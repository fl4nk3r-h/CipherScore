"""ESP structural hypothesis tests (mvp.md §3.3 Step 3)."""
from __future__ import annotations

from analyzer.features.esp_structure import StructureResult, _consistent, analyze
from analyzer.parse.esp import ESPRecord


def _rec(length: int, natt: bool = False) -> ESPRecord:
    return ESPRecord(spi=1, seq=1, length=length, ts=0.0, src="a", dst="b",
                     udp_encapsulated=natt)


def test_cbc_consistency_formula():
    # body = length - 20; header 8 + IV 16 + icv; payload must pad to 16-byte blocks.
    # payload 48 -> length = 20 + 8 + 16 + 48 + 12 = 104
    assert _consistent("CBC", 12, 104, natt=False)
    assert not _consistent("CBC", 12, 105, natt=False)


def test_gcm_consistency_formula():
    # GCM: body - 8 - IV 8 - pad 4 - icv >= 0 and ct 16-byte aligned
    assert _consistent("GCM", 16, 40 + 8 + 8 + 32 + 4 + 16, natt=False, ip_version=6)
    assert not _consistent("GCM", 16, 30, natt=False, ip_version=6)
    # non-aligned plaintext fails
    assert not _consistent("GCM", 12, 40 + 8 + 8 + 30 + 4 + 12, natt=False, ip_version=6)


def test_analyze_picks_dominant_hypothesis():
    recs = [_rec(104) for _ in range(10)]           # CBC/ICV12 wins
    res = analyze(recs)
    assert isinstance(res, StructureResult)
    assert res.cipher_mode == "CBC"
    assert res.icv_len == 12
    assert res.consistency == 1.0
    assert res.key_size_hint is None                # key size is never a structure output


def test_analyze_empty():
    res = analyze([])
    assert res.cipher_mode is None and res.consistency == 0.0


def test_size_offsets_include_histogram():
    recs = [_rec(100), _rec(120), _rec(140)]
    off = analyze(recs)
    _ = off
    from analyzer.features.esp_structure import size_offsets
    stats = size_offsets(recs)
    assert {"min_len", "p50_len", "mean_len", "std_len"} <= set(stats)
    assert stats["min_len"] == 100
