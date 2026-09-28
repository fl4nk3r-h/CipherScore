"""Streaming pcap/pcapng reader (mvp.md §3.3).

"The pipeline streams packets with `dpkt` for speed and uses Scapy only to
decode IKE payloads." Streaming keeps ~200 MB captures in the seconds-to-a-few-
minutes range and respects the 500 MB upload cap behavior (§13).
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import dpkt


@dataclass
class PacketRecord:
    ts: float
    src: str
    dst: str
    ip_proto: int | None      # 50 ESP, 51 AH, 17 UDP, ...
    sport: int | None
    dport: int | None
    payload: bytes            # protocol payload (ESP body / UDP body)
    ip_version: int
    inner_src: str | None = None  # for tunneled/decapsulated views if available
    inner_dst: str | None = None


def _inet_str(addr: bytes, version: int) -> str:
    return ".".join(str(b) for b in addr) if version == 4 else \
        ":".join(f"{b:02x}" for b in addr)


def stream(pcap_path: Path) -> Iterator[PacketRecord]:
    """Yield PacketRecord for each packet; never loads the file into memory."""
    with open(pcap_path, "rb") as fh:
        try:
            reader = dpkt.pcapng.Reader(fh)
        except ValueError:
            fh.seek(0)
            reader = dpkt.pcap.Reader(fh)

        datalink = reader.datalink() if hasattr(reader, "datalink") else 1
        for ts, buf in reader:
            # DLT_RAW (101/12/14), DLT_IPV4 (228), DLT_IPV6 (229): the buffer is
            # the bare IP packet (common for tcpdump -i any / crafted captures).
            if datalink in (101, 12, 14, 228, 229):
                ip_bytes = buf
                version = ip_bytes[0] >> 4 if ip_bytes else 0
                if version == 4:
                    ip = dpkt.ip.IP(ip_bytes)
                elif version == 6:
                    ip = dpkt.ip6.IP6(ip_bytes)
                else:
                    continue
            else:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            version = 4 if isinstance(ip, dpkt.ip.IP) else 6
            # dpkt IPv6 exposes the next-header as .nxt (not .p)
            proto = getattr(ip, "p", None)
            if version == 6:
                proto = getattr(ip, "nxt", proto)
            sport = dport = None
            payload = b""
            if version == 6 and proto in (50, 51) and getattr(ip, "all_extension_headers", None):
                # dpkt treats ESP/AH as an IPv6 extension header; its bytes()
                # already include the trailing data (do not double-count).
                ext = ip.all_extension_headers[-1]
                payload = bytes(ext)
            elif proto == 17 and isinstance(ip.data, dpkt.udp.UDP):
                sport, dport = ip.data.sport, ip.data.dport
                payload = bytes(ip.data.data)
            elif proto in (50, 51):
                payload = bytes(ip.data)
            yield PacketRecord(
                ts=float(ts),
                src=_inet_str(ip.src, version),
                dst=_inet_str(ip.dst, version),
                ip_proto=proto,
                sport=sport,
                dport=dport,
                payload=payload,
                ip_version=version,
            )


def total_packets(pcap_path: Path) -> int:
    return sum(1 for _ in stream(pcap_path))


def pcap_global_header_ok(path: Path) -> bool:
    magic = path.read_bytes()[:4]
    return magic in (
        struct.pack("<I", 0xA1B2C3D4), struct.pack(">I", 0xA1B2C3D4),
        struct.pack("<I", 0xA1B23C4D), struct.pack(">I", 0xA1B23C4D),
        b"\x0a\x0d\x0d\x0a",  # pcapng
    )
