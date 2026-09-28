"""SA tracker tests (mvp.md §3.3 Step 3): SPI grouping, rekey linking,
lifetimes, replay checks."""
from __future__ import annotations

from analyzer.parse.esp import ESPRecord
from analyzer.parse.sa_tracker import build, replay_window_inferred, spi_lifetime_s


def _rec(spi: int, seq: int, ts: float) -> ESPRecord:
    return ESPRecord(spi=spi, seq=seq, length=104, ts=ts, src="a", dst="b",
                     udp_encapsulated=False)


def test_groups_packets_by_spi():
    res = build([_rec(1, 1, 0.0), _rec(1, 2, 0.1), _rec(2, 1, 0.2)], {})
    assert set(res.sas) == {1, 2}
    assert res.sas[1].packet_count == 2


def test_rekey_link_new_spi_same_peers():
    res = build([_rec(0xAA, 1, 0.0), _rec(0xAA, 2, 5.0), _rec(0xBB, 1, 6.0)], {})
    assert res.sas[0xBB].rekey_of == 0xAA


def test_spi_lifetime():
    res = build([_rec(7, 1, 10.0), _rec(7, 2, 15.5)], {})
    assert spi_lifetime_s(res.sas[7]) == 5.5


def test_replay_resets_detected():
    # seq resets from a huge value to 1 without an SPI change
    res = build([_rec(9, 4000000000, 0.0), _rec(9, 1, 0.1)], {})
    assert res.sas[9].replay_resets == 1
    assert replay_window_inferred(res.sas[9]) == 0
