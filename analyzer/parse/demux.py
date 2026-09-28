"""Protocol demux (mvp.md §3.3, Step 1).

| Signal              | Detection                                                   |
|---------------------|-------------------------------------------------------------|
| ESP                 | IP protocol 50 (IPv4) / Next Header 50 (IPv6)               |
| AH                  | IP protocol 51                                              |
| IKE                 | UDP/500, or UDP/4500 with the 4-byte non-ESP marker 0x00000000 |
| ESP-in-UDP (NAT-T)  | UDP/4500 whose first 4 bytes are non-zero (the SPI)          |
"""
from __future__ import annotations

from collections.abc import Iterable

from analyzer.parse.reader import PacketRecord

IKE_PORT = 500
NATT_PORT = 4500
NON_ESP_MARKER = b"\x00\x00\x00\x00"


class ProtocolClass:
    ESP = "esp"
    AH = "ah"
    IKE = "ike"
    ESP_IN_UDP = "esp_in_udp"   # NAT-T
    OTHER = "other"


def classify_packet(pkt: PacketRecord) -> str:
    if pkt.ip_proto == 50:
        return ProtocolClass.ESP
    if pkt.ip_proto == 51:
        return ProtocolClass.AH
    if pkt.ip_proto == 17 and pkt.dport == IKE_PORT or pkt.ip_proto == 17 and pkt.sport == IKE_PORT:
        return ProtocolClass.IKE
    if pkt.ip_proto == 17 and (pkt.dport == NATT_PORT or pkt.sport == NATT_PORT):
        if pkt.payload[:4] == NON_ESP_MARKER:
            return ProtocolClass.IKE              # IKE behind the non-ESP marker
        return ProtocolClass.ESP_IN_UDP           # first 4 bytes non-zero: the SPI
    return ProtocolClass.OTHER


def classify(packets: Iterable[PacketRecord]) -> dict[str, list[PacketRecord]]:
    """Bucket packets by protocol class."""
    buckets: dict[str, list[PacketRecord]] = {
        ProtocolClass.ESP: [], ProtocolClass.AH: [], ProtocolClass.IKE: [],
        ProtocolClass.ESP_IN_UDP: [], ProtocolClass.OTHER: [],
    }
    for pkt in packets:
        buckets[classify_packet(pkt)].append(pkt)
    return buckets
