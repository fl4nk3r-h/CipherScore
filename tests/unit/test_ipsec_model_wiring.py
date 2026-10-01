"""The analysis path uses all model heads but stays honest without artifacts."""
from __future__ import annotations

from analyzer.features.esp_structure import StructureResult
from analyzer.infer.ensemble import infer_sa
from analyzer.parse.sa_tracker import SATrack, TrackerResult


def test_rekey_dependent_heads_unknown_without_rekey(tmp_path):
    track = SATrack(spi=42, peers=["10.0.0.1", "10.0.0.2"], packet_count=30)
    structure = StructureResult(cipher_mode="CBC", icv_len=12, consistency=0.8)
    evidence = infer_sa(track, structure, TrackerResult({42: track}, []),
                        models_dir=tmp_path, offsets={"min_len": 100},
                        windows=[{"features": {"n_packets": 30}}])
    assert evidence.pfs.value is None and evidence.pfs.tag == "unknown"
    assert evidence.dh_group.value is None and evidence.dh_group.tag == "unknown"
    assert evidence.traffic is None
    assert evidence.enc.value == "CBC"
