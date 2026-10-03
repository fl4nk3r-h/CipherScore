"""IPv6 fragmentation around ESP must not crash packet streaming."""
from __future__ import annotations

import ipaddress
import struct

import dpkt

from analyzer.parse import demux, reader


def _frame(offset: int, more: bool, data: bytes) -> bytes:
    src = ipaddress.IPv6Address("fd30::2").packed
    dst = ipaddress.IPv6Address("fd30::3").packed
    frag = struct.pack("!BBHI", 50, 0, (offset << 3) | int(more), 1234)
    ip6 = struct.pack("!IHBB16s16s", 0x60000000, len(frag) + len(data),
                      44, 64, src, dst) + frag + data
    return b"\xff" * 6 + b"\x00" * 6 + b"\x86\xdd" + ip6


def test_esp_first_fragment_and_remainder(tmp_path):
    pcap = tmp_path / "fragmented.pcap"
    spi_and_seq = struct.pack("!II", 0x12345678, 1)
    with pcap.open("wb") as stream:
        writer = dpkt.pcap.Writer(stream)
        writer.writepkt(_frame(0, True, spi_and_seq + b"a" * 24), ts=1)
        writer.writepkt(_frame(4, False, b"b" * 16), ts=2)
        writer.close()

    packets = list(reader.stream(pcap))
    assert len(packets) == 2
    assert packets[0].ip_proto == 50
    assert packets[0].payload.startswith(spi_and_seq)
    assert packets[0].src == "fd30::2"
    assert packets[0].length == 40 + 8 + 32
    assert demux.classify_packet(packets[0]) == demux.ProtocolClass.ESP
    assert packets[1].ip_proto == 44
    assert demux.classify_packet(packets[1]) == demux.ProtocolClass.OTHER
