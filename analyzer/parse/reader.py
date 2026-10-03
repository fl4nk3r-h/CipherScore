"""Streaming pcap/pcapng reader (mvp.md §3.3).

"The pipeline streams packets with `dpkt` for speed and uses Scapy only to
decode IKE payloads." Streaming keeps ~200 MB captures in the seconds-to-a-few-
minutes range and respects the 500 MB upload cap behavior (§13).
"""
from __future__ import annotations

import ipaddress
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
    length: int = 0
    tcp_flags: int = 0
    ttl: int | None = None


def _inet_str(addr: bytes, version: int) -> str:
    return str(ipaddress.ip_address(addr))


def _ipv6_from_ethernet(frame: bytes) -> bytes | None:
    """Return an Ethernet frame's IPv6 bytes, including through VLAN tags."""
    if len(frame) < 14:
        return None
    eth_type = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    while eth_type in (0x8100, 0x88A8, 0x9100):
        if len(frame) < offset + 4:
            return None
        eth_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    return frame[offset:] if eth_type == 0x86DD else None


def _ipv6_fragment(ts: float, ip_bytes: bytes) -> PacketRecord:
    """Decode the Fragment header without dpkt's ESP extension-header bug.

    Only the first fragment contains the ESP/AH or transport header. Later
    fragments are kept as protocol 44 so demux doesn't count them as complete
    protected packets.
    """
    payload_len = struct.unpack_from("!H", ip_bytes, 4)[0]
    end = min(len(ip_bytes), 40 + payload_len) if payload_len else len(ip_bytes)
    next_header = ip_bytes[40]
    offset = struct.unpack_from("!H", ip_bytes, 42)[0] >> 3
    fragment_data = ip_bytes[48:end]
    proto = next_header if offset == 0 else 44
    sport = dport = None
    tcp_flags = 0
    payload = fragment_data
    if offset == 0 and next_header == 17 and len(fragment_data) >= 8:
        sport, dport = struct.unpack_from("!HH", fragment_data)
        payload = fragment_data[8:]
    elif offset == 0 and next_header == 6 and len(fragment_data) >= 20:
        sport, dport = struct.unpack_from("!HH", fragment_data)
        tcp_flags = fragment_data[13]
        payload = fragment_data[(fragment_data[12] >> 4) * 4:]
    return PacketRecord(
        ts=float(ts),
        src=_inet_str(ip_bytes[8:24], 6),
        dst=_inet_str(ip_bytes[24:40], 6),
        ip_proto=proto,
        sport=sport,
        dport=dport,
        payload=payload,
        ip_version=6,
        length=end,
        tcp_flags=tcp_flags,
        ttl=ip_bytes[7],
    )


def stream(pcap_path: Path) -> Iterator[PacketRecord]:
    """Yield PacketRecord for each packet without loading the capture."""
    with open(pcap_path, "rb") as fh:
        yield from stream_file(fh)


def stream_file(fh) -> Iterator[PacketRecord]:
    """Read a PCAP/PCAPNG file object, including a live tcpdump pipe."""
    if hasattr(fh, "peek"):
        magic = fh.peek(4)[:4]
    else:
        magic = fh.read(4)
        fh.seek(-4, 1)
    reader = dpkt.pcapng.Reader(fh) if magic == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(fh)

    datalink = reader.datalink() if hasattr(reader, "datalink") else 1
    raw_datalink = datalink in (101, 12, 14, 228, 229)
    for ts, buf in reader:
        if raw_datalink:
            ip6_bytes = buf if buf and buf[0] >> 4 == 6 else None
        else:
            ip6_bytes = _ipv6_from_ethernet(buf)
        if ip6_bytes is not None and len(ip6_bytes) >= 48 and ip6_bytes[6] == 44:
            yield _ipv6_fragment(ts, ip6_bytes)
            continue
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
        tcp_flags = 0
        if version == 6 and proto in (50, 51) and getattr(ip, "all_extension_headers", None):
            # dpkt treats ESP/AH as an IPv6 extension header; its bytes()
            # already include the trailing data (do not double-count).
            ext = ip.all_extension_headers[-1]
            payload = bytes(ext)
        elif proto == 17 and isinstance(ip.data, dpkt.udp.UDP):
            sport, dport = ip.data.sport, ip.data.dport
            payload = bytes(ip.data.data)
        elif proto == 6 and isinstance(ip.data, dpkt.tcp.TCP):
            sport, dport = ip.data.sport, ip.data.dport
            tcp_flags = ip.data.flags
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
            length=len(ip),
            tcp_flags=tcp_flags,
            ttl=getattr(ip, "ttl", getattr(ip, "hlim", None)),
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
