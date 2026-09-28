"""Manifest contract tests (mvp.md §3.2 + capture/schemas/manifest.schema.json).

The manifest is the ground-truth contract between Person A (capture) and
Person B (analyzer) — its shape is pinned by the spec and validated here.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

from capture.manifest import build_manifest, write_from_session_dir

SCHEMA = json.loads(
    (Path(__file__).resolve().parent.parent.parent / "capture" / "schemas"
     / "manifest.schema.json").read_text())

LABELS = {
    "ike_version": 2, "mode": "tunnel", "enc": "AES-GCM-16", "key_bits": 256,
    "integ": "AEAD", "dh_group": 20, "pfs": True, "nat_t": False,
    "child_rekey_s": 600, "replay_window": 64,
}


def test_manifest_matches_spec_example_shape():
    m = build_manifest("p07-voip-0003", "p07", "voip", ["fd30::2", "fd30::3"],
                       LABELS, pcap="p07-voip-0003.pcapng",
                       keys="p07-voip-0003.keys/",
                       start="2026-09-28T10:14:02Z", end="2026-09-28T10:16:02Z")
    # Field-for-field identical to the §3.2 example
    assert list(m) == ["session_id", "profile", "traffic_type", "start", "end",
                       "gateways", "labels", "pcap", "keys"]
    assert m["labels"] == LABELS
    jsonschema.validate(m, SCHEMA)


def test_manifest_labels_block_requires_all_ten_fields():
    bad = dict(LABELS)
    del bad["replay_window"]
    m = build_manifest("p03-web-0001", "p03", "web", ["172.30.0.2"],
                       bad, pcap="x.pcapng", keys="x.keys/")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(m, SCHEMA)


def test_manifest_rejects_unknown_traffic_type():
    m = build_manifest("p01-x-0001", "p01", "streaming", ["172.30.0.2"],
                       LABELS, pcap="x.pcapng", keys="x.keys/")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(m, SCHEMA)


def test_write_from_session_dir_uses_sidecar_timestamps(tmp_path):
    d = tmp_path / "p07-voip-0003"
    d.mkdir()
    (d / "started_at").write_text("1790590442")   # fixed epoch -> 2026-09-28T10:14:02Z
    (d / "ended_at").write_text("1790590562")
    out = write_from_session_dir("p07-voip-0003", "p07", "voip",
                                 ["fd30::2", "fd30::3"], LABELS,
                                 sessions_dir=tmp_path)
    m = json.loads(out.read_text())
    assert m["start"] == "2026-09-28T10:14:02Z"   # deterministic, from sidecar
    assert m["end"] == "2026-09-28T10:16:02Z"
    assert m["pcap"] == "p07-voip-0003.pcapng"
    jsonschema.validate(m, SCHEMA)
