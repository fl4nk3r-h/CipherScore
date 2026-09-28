"""ESP header parse (mvp.md §3.3, Step 3).

ESP bytes 0-3 are the SPI, bytes 4-7 the sequence number. These reveal SA
identity, replay behavior, and rekeys (a new SPI appears).
"""
from __future__ import annotations

from dataclasses import dataclass

from analyzer.parse.reader import PacketRecord


@dataclass
class ESPRecord:
    spi: int
    seq: int
    length: int          # full ESP packet length
    ts: float
    src: str
    dst: str
    udp_encapsulated: bool


def parse_esp(pkt: PacketRecord, udp_encapsulated: bool = False) -> ESPRecord | None:
    body = pkt.payload
    if len(body) < 8:
        return None
    return ESPRecord(
        spi=int.from_bytes(body[0:4], "big"),
        seq=int.from_bytes(body[4:8], "big"),
        length=len(body) + (20 if pkt.ip_version == 4 else 40),  # + outer IP header
        ts=pkt.ts,
        src=pkt.src,
        dst=pkt.dst,
        udp_encapsulated=udp_encapsulated,
    )
