"""Behavioral checks for incremental passive alerting."""
from __future__ import annotations

import dpkt

from analyzer.parse.reader import PacketRecord
from analyzer.threats import ThreatEngine


def packet(ts, src="10.1.1.1", dst="8.8.8.8", proto=6, sport=1000, dport=443,
           length=100, payload=b"", flags=0):
    return PacketRecord(ts, src, dst, proto, sport, dport, payload, 4,
                        length=length, tcp_flags=flags)


def test_ddos_and_scan_have_evidence_and_deduplicate():
    engine = ThreatEngine()
    alerts = []
    for n in range(110):
        alerts += engine.ingest(packet(n / 200, f"10.0.0.{n % 20 + 1}", "1.2.3.4",
                                       dport=80, flags=dpkt.tcp.TH_SYN))
    ddos = [a for a in alerts if a.threat_class == "ddos"]
    assert len(ddos) == 1
    assert ddos[0].evidence["syn_sources"] >= 5
    assert 0 <= ddos[0].confidence <= 1
    scans = []
    for n in range(11):
        scans += engine.ingest(packet(2 + n / 20, dport=100 + n))
    assert any(a.threat_class == "port_scan" and
               a.evidence["distinct_targets_10s"] >= 10 for a in scans)


def test_dns_dga_tunneling_and_exfiltration():
    engine = ThreatEngine()
    alerts = []
    label = "aj3k9v7m2n8p4q6r1s5t"
    for n in range(3):
        query = f"{label}{n}{label}{n}{label}.example.org"
        payload = bytes(dpkt.dns.DNS(id=n, qd=[dpkt.dns.DNS.Q(name=query)]))
        alerts += engine.ingest(packet(1 + n, proto=17, dport=53, payload=payload))
    assert any(a.threat_class == "dga" for a in alerts)
    assert any(a.threat_class == "dns_tunneling" for a in alerts)
    alerts += engine.ingest(packet(5, length=1_100_000))
    assert any(a.threat_class == "data_exfiltration" for a in alerts)


def test_periodic_encrypted_connections_are_suspicious():
    engine = ThreatEngine()
    alerts = []
    for n in range(4):
        alerts += engine.ingest(packet(10 + n * 5, sport=1000 + n,
                                       payload=b"\x16\x03\x03" + b"x" * 20))
    assert {a.threat_class for a in alerts} >= {"beaconing", "encrypted_malware"}
    assert all(a.model_version == "heuristic-v1" for a in alerts)
