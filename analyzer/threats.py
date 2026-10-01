"""Incremental, passive network threat detection from packet metadata.

No traffic is transmitted and encrypted application payloads are never decoded.
A detector's score is evidence strength unless a calibrated model is loaded.
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import statistics
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

import dpkt

from analyzer.infer.loader import load_task
from analyzer.parse.reader import PacketRecord, stream

CLASSES = ("ddos", "beaconing", "dga", "dns_tunneling", "encrypted_malware",
           "port_scan", "data_exfiltration")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((value.count(c) / len(value)) * math.log2(value.count(c) / len(value))
                for c in set(value))


def dns_name_features(name: str, queries_30s: int = 0) -> dict[str, float]:
    """Lexical DNS features used by live packets and domain-list imports."""
    label = name.lower().rstrip(".").split(".")[0]
    bigrams = [label[i:i + 2] for i in range(max(0, len(label) - 1))]
    return {"label_len": float(len(label)), "entropy": _entropy(label),
            "bigram_diversity": len(set(bigrams)) / max(1, len(bigrams)),
            "digit_ratio": sum(c.isdigit() for c in label) / max(1, len(label)),
            "name_len": float(len(name)), "qps": queries_30s / 30.0}


def _flow_key(pkt: PacketRecord) -> tuple:
    left = (pkt.src, pkt.sport or 0)
    right = (pkt.dst, pkt.dport or 0)
    return (min(left, right), max(left, right), pkt.ip_proto)


def _flow_id(key: tuple) -> str:
    return hashlib.sha256(repr(key).encode()).hexdigest()[:20]


def _dns(pkt: PacketRecord) -> tuple[str | None, int | None, int | None]:
    if pkt.ip_proto != 17 or not ({pkt.sport, pkt.dport} & {53}):
        return None, None, None
    try:
        msg = dpkt.dns.DNS(pkt.payload)
        if msg.qd:
            return (msg.qd[0].name.lower().rstrip("."),
                    msg.rcode if msg.qr else None, msg.qd[0].type)
    except (dpkt.dpkt.UnpackError, ValueError, IndexError):
        pass
    return None, None, None


def _tls_metadata(pkt: PacketRecord) -> dict[str, float]:
    if pkt.ip_proto == 6 and pkt.payload[:1] == b"\x16" and len(pkt.payload) > 10:
        data = pkt.payload
        out = {"tls": 1.0, "quic": 0.0,
               "tls_version": float(int.from_bytes(data[1:3], "big")),
               "handshake_len": float(len(data)), "quic_version": 0.0,
               "cipher_count": 0.0,
               "sni_length": 0.0, "extension_count": 0.0}
        # Parse only a complete, plaintext ClientHello; never inspect app data.
        if data[5] == 1 and len(data) >= 45:
            try:
                pos = 5 + 4 + 2 + 32
                session_len = data[pos]
                pos += 1 + session_len
                cipher_bytes = int.from_bytes(data[pos:pos + 2], "big")
                out["cipher_count"] = cipher_bytes / 2
                pos += 2 + cipher_bytes
                pos += 1 + data[pos]  # compression methods
                end = min(len(data), pos + 2 + int.from_bytes(data[pos:pos + 2], "big"))
                pos += 2
                while pos + 4 <= end:
                    ext_type = int.from_bytes(data[pos:pos + 2], "big")
                    ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
                    ext = data[pos + 4:pos + 4 + ext_len]
                    out["extension_count"] += 1
                    if ext_type == 0 and len(ext) >= 5:
                        out["sni_length"] = float(int.from_bytes(ext[3:5], "big"))
                    pos += 4 + ext_len
            except (IndexError, ValueError):
                pass
        return out
    # QUIC long header and fixed bit. Only public header fields are read.
    if pkt.ip_proto == 17 and pkt.payload and pkt.payload[0] & 0xC0 == 0xC0 and len(pkt.payload) >= 6:
        return {"tls": 0.0, "quic": 1.0, "tls_version": 0.0,
                "cipher_count": 0.0, "sni_length": 0.0, "extension_count": 0.0,
                "quic_version": float(int.from_bytes(pkt.payload[1:5], "big")),
                "handshake_len": float(len(pkt.payload))}
    return {}


@dataclass
class Alert:
    id: str
    timestamp: float
    flow_id: str
    threat_class: str
    severity: str
    confidence: float
    evidence: dict
    source: str
    model_version: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Flow:
    key: tuple
    last_seen: float
    packets: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    syns: int = 0
    metadata: dict[str, float] = field(default_factory=dict)


class ThreatEngine:
    """Bounded state keyed by bidirectional flow and rolling event windows."""

    def __init__(self, source: str = "replay", internal_cidrs: Iterable[str] | None = None,
                 models_dir: Path | str | None = None,
                 feature_sink: Callable[[str, PacketRecord, dict[str, float]], None] | None = None) -> None:
        self.source = source
        spec = internal_cidrs or os.environ.get("CS_INTERNAL_CIDRS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",")
        self.internal = tuple(ipaddress.ip_network(x.strip()) for x in spec if x.strip())
        self.models_dir = str(models_dir or os.environ.get("CS_MODELS_DIR", "models"))
        self.flows: dict[tuple, Flow] = {}
        self.to_dest: dict[str, deque[tuple[float, str, int, int]]] = defaultdict(deque)
        self.from_src: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)
        self.dns_events: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self.beacon_times: dict[tuple, deque[float]] = defaultdict(lambda: deque(maxlen=12))
        self.emitted: dict[tuple[str, str], float] = {}
        self.feature_sink = feature_sink
        self.packet_count = 0
        self.drop_count = 0

    def _inside(self, address: str) -> bool:
        try:
            return any(ipaddress.ip_address(address) in network for network in self.internal)
        except ValueError:
            return False

    def _model_score(self, name: str, features: dict[str, float]) -> tuple[float | None, str]:
        pack = load_task(name, self.models_dir)
        if not pack:
            return None, "heuristic-v1"
        model, _cal, _q, order = pack
        if not order or not all(k in features for k in order):
            return None, "heuristic-v1"
        try:
            import pandas as pd
            probs = model.predict_proba(pd.DataFrame([[features[k] for k in order]], columns=order))[0]
            classes = list(model.classes_)
            idx = classes.index(1) if 1 in classes else classes.index(True)
            version = model.__dict__.get("_cs_version", "trained")
            return float(probs[idx]), f"{name}-{version}"
        except (ValueError, TypeError, IndexError, AttributeError):
            return None, "heuristic-v1"

    def _alert(self, pkt: PacketRecord, threat: str, confidence: float, evidence: dict,
               version: str = "heuristic-v1", severity: str = "medium",
               dedup_id: str | None = None) -> Alert | None:
        flow_id = _flow_id(_flow_key(pkt))
        key = (dedup_id or flow_id, threat)
        if pkt.ts - self.emitted.get(key, float("-inf")) < 30:
            return None
        self.emitted[key] = pkt.ts
        digest = hashlib.sha256(f"{flow_id}:{threat}:{int(pkt.ts)}".encode()).hexdigest()[:24]
        return Alert(f"al_{digest}", pkt.ts, flow_id, threat, severity,
                     round(min(1.0, max(0.0, confidence)), 4), evidence, self.source, version)

    @staticmethod
    def _trim(events: deque, cutoff: float) -> None:
        while events and events[0][0] < cutoff:
            events.popleft()

    def ingest(self, pkt: PacketRecord) -> list[Alert]:
        self.packet_count += 1
        now = pkt.ts
        key = _flow_key(pkt)
        flow = self.flows.get(key)
        if flow is None:
            flow = self.flows[key] = Flow(key, now)
        flow.last_seen = now
        flow.packets += 1
        size = pkt.length or len(pkt.payload)
        if self._inside(pkt.src) and not self._inside(pkt.dst):
            flow.bytes_out += size
        elif self._inside(pkt.dst) and not self._inside(pkt.src):
            flow.bytes_in += size
        if pkt.tcp_flags & dpkt.tcp.TH_SYN and not pkt.tcp_flags & dpkt.tcp.TH_ACK:
            flow.syns += 1
        handshake = _tls_metadata(pkt)
        flow.metadata.update(handshake)
        handshake_features = {
            "interval_mean": 0.0, "interval_cv": 1.0, "observations": 1.0,
            **{name: float(handshake.get(name, 0.0)) for name in (
                "tls", "quic", "tls_version", "quic_version", "handshake_len",
                "cipher_count", "sni_length", "extension_count")}}
        if handshake and self.feature_sink:
            self.feature_sink("encrypted_malware", pkt, handshake_features)
        found: list[Alert] = []
        if handshake:
            p_malware, version = self._model_score("encrypted_malware", handshake_features)
            if p_malware is not None and p_malware >= 0.9:
                alert = self._alert(pkt, "encrypted_malware", p_malware,
                                    {"reason": "encrypted handshake metadata",
                                     "tls": bool(handshake.get("tls")),
                                     "quic": bool(handshake.get("quic")),
                                     "handshake_bytes": len(pkt.payload)}, version)
                if alert:
                    found.append(alert)

        dest = self.to_dest[pkt.dst]
        dest.append((now, pkt.src, pkt.tcp_flags, pkt.ip_proto or 0))
        self._trim(dest, now - 1)
        syn_sources = {src for _, src, flags, proto in dest
                       if proto == 6 and flags & dpkt.tcp.TH_SYN and not flags & dpkt.tcp.TH_ACK}
        udp_sources = {src for _, src, _, proto in dest if proto == 17}
        if len(dest) >= 100 and (len(syn_sources) >= 5 or len(udp_sources) >= 5):
            source_counts = Counter(src for _, src, _, _ in dest)
            source_entropy = -sum((count / len(dest)) * math.log2(count / len(dest))
                                  for count in source_counts.values())
            subtype = "syn_flood" if len(syn_sources) >= 5 else "udp_flood_or_reflection"
            alert = self._alert(pkt, "ddos", min(0.99, len(dest) / 200),
                                {"packets_1s": len(dest), "syn_sources": len(syn_sources),
                                 "udp_sources": len(udp_sources),
                                 "source_entropy": round(source_entropy, 3),
                                 "subtype": subtype, "destination": pkt.dst},
                                severity="high", dedup_id=f"dst:{pkt.dst}")
            if alert:
                found.append(alert)

        src_events = self.from_src[pkt.src]
        src_events.append((now, pkt.dst, pkt.dport or 0))
        self._trim(src_events, now - 10)
        targets = {(d, p) for _, d, p in src_events if p}
        if len(targets) >= 10:
            alert = self._alert(pkt, "port_scan", min(0.99, len(targets) / 30),
                                {"distinct_targets_10s": len(targets), "source": pkt.src})
            if alert:
                found.append(alert)

        name, rcode, qtype = _dns(pkt)
        if name:
            host_dns = self.dns_events[pkt.src]
            host_dns.append((now, name))
            self._trim(host_dns, now - 30)
            label = name.split(".")[0]
            ent = _entropy(label)
            dns_features = dns_name_features(name, len(host_dns))
            if self.feature_sink:
                self.feature_sink("dga", pkt, dns_features)
            p_dga, version = self._model_score("dga", dns_features)
            if p_dga is None:
                p_dga = min(0.9, ent / 5) if len(label) >= 18 and ent >= 3.5 else 0.0
            if p_dga >= 0.75:
                alert = self._alert(pkt, "dga", p_dga,
                                    {"query": name, "label_entropy": round(ent, 3),
                                     "label_length": len(label), "rcode": rcode}, version)
                if alert:
                    found.append(alert)
            tunnel_features = {"name_len": float(len(name)), "entropy": ent,
                               "queries_30s": float(len(host_dns)),
                               "qtype": float(qtype or 0)}
            if self.feature_sink:
                self.feature_sink("dns_tunneling", pkt, tunnel_features)
            p_tunnel, version = self._model_score("dns_tunneling", tunnel_features)
            if p_tunnel is None:
                p_tunnel = 0.82 if len(name) >= 65 and ent >= 3.4 and len(host_dns) >= 3 else 0.0
            if p_tunnel >= 0.75:
                alert = self._alert(pkt, "dns_tunneling", p_tunnel,
                                    {"query": name, "query_length": len(name),
                                     "queries_30s": len(host_dns), "qtype": qtype}, version, "high")
                if alert:
                    found.append(alert)

        if self._inside(pkt.src) and not self._inside(pkt.dst) and flow.bytes_out > 1_000_000:
            ratio = flow.bytes_out / max(flow.bytes_in, 1)
            if ratio >= 10:
                alert = self._alert(pkt, "data_exfiltration", min(0.95, ratio / 40),
                                    {"bytes_out": flow.bytes_out, "bytes_in": flow.bytes_in,
                                     "out_in_ratio": round(ratio, 2)}, severity="high")
                if alert:
                    found.append(alert)

        if flow.packets == 1 and self._inside(pkt.src) and not self._inside(pkt.dst):
            pair = (pkt.src, pkt.dst, pkt.dport or 0, pkt.ip_proto)
            times = self.beacon_times[pair]
            times.append(now)
            if len(times) >= 2 and self.feature_sink:
                observed_gaps = [b - a for a, b in zip(times, list(times)[1:])]
                observed_mean = statistics.mean(observed_gaps)
                self.feature_sink("beaconing", pkt, {
                    "interval_mean": observed_mean,
                    "interval_cv": statistics.pstdev(observed_gaps) / observed_mean
                    if observed_mean > 0 else 1.0,
                    "observations": float(len(times))})
            if len(times) >= 4:
                gaps = [b - a for a, b in zip(times, list(times)[1:])]
                mean = statistics.mean(gaps)
                cv = statistics.pstdev(gaps) / mean if mean > 0 else 1.0
                features = {"interval_mean": mean, "interval_cv": cv,
                            "observations": float(len(times))}
                if self.feature_sink:
                    self.feature_sink("beaconing", pkt, features)
                p_beacon, version = self._model_score("beaconing", features)
                if p_beacon is None:
                    p_beacon = 0.85 if mean >= 2 and cv <= 0.15 else 0.0
                if p_beacon >= 0.75:
                    alert = self._alert(pkt, "beaconing", p_beacon,
                                        {"interval_mean_s": round(mean, 2),
                                         "interval_cv": round(cv, 3), "observations": len(times)},
                                        version)
                    if alert:
                        found.append(alert)
                    if flow.metadata.get("tls") or flow.metadata.get("quic"):
                        malware_features = {**features, **{name: float(flow.metadata.get(name, 0.0))
                            for name in ("tls", "quic", "handshake_len",
                                         "cipher_count", "sni_length", "extension_count")}}
                        if self.feature_sink:
                            self.feature_sink("encrypted_malware", pkt, malware_features)
                        p_malware, m_version = self._model_score(
                            "encrypted_malware", malware_features)
                        if p_malware is None:
                            p_malware, m_version = 0.75, "heuristic-v1"
                        if p_malware >= 0.75:
                            alert = self._alert(pkt, "encrypted_malware", p_malware,
                                                {"reason": "periodic encrypted connection",
                                                 "tls": bool(flow.metadata.get("tls")),
                                                 "quic": bool(flow.metadata.get("quic")),
                                                 "interval_cv": round(cv, 3)}, m_version)
                            if alert:
                                found.append(alert)

        if self.packet_count % 1024 == 0:
            self.expire(now)
        return found

    def expire(self, now: float) -> None:
        for key in [k for k, v in self.flows.items() if v.last_seen < now - 60]:
            del self.flows[key]
        for mapping, age in ((self.to_dest, 2), (self.from_src, 11), (self.dns_events, 31)):
            for key, events in list(mapping.items()):
                self._trim(events, now - age)
                if not events:
                    del mapping[key]
        for key, times in list(self.beacon_times.items()):
            while times and times[0] < now - 3600:
                times.popleft()
            if not times:
                del self.beacon_times[key]
        for key, ts in list(self.emitted.items()):
            if ts < now - 60:
                del self.emitted[key]

    def replay(self, path: Path) -> Iterable[Alert]:
        for pkt in stream(path):
            yield from self.ingest(pkt)
