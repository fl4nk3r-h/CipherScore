"""AH header parse (mvp.md §3.3 signal: IP protocol 51; profile p16 is AH-only).

AH (RFC 4302) is authenticated-only: no confidentiality. The MVP parses it so
the demux and posture engine can report the AH SA and its integrity algorithm.
"""
from __future__ import annotations

from dataclasses import dataclass

from analyzer.parse.reader import PacketRecord


@dataclass
class AHRecord:
    spi: int
    seq: int
    next_header: int
    icv_len: int


def parse_ah(pkt: PacketRecord) -> AHRecord | None:
    body = pkt.payload
    if len(body) < 12:
        return None
    nh = body[0]
    len_field = body[1]           # in 4-byte words minus 2
    icv_len = (len_field + 2) * 4 - 12
    spi = int.from_bytes(body[4:8], "big")
    seq = int.from_bytes(body[8:12], "big")
    return AHRecord(spi=spi, seq=seq, next_header=nh, icv_len=icv_len)
