"""Old manifests are skipped only when their capture contains useful evidence."""

import json

from analyzer.parse.reader import PacketRecord
from lab.runner.orchestrate import _existing_capture_valid


def test_existing_capture_requires_ike_and_twenty_esp(tmp_path, monkeypatch):
    from analyzer.parse import reader

    capture = tmp_path / "session.pcapng"
    capture.write_bytes(b"placeholder")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"session_id": "s1", "pcap": capture.name}))
    esp = PacketRecord(0, "a", "b", 50, None, None, b"esp", 4)
    ike = PacketRecord(0, "a", "b", 17, 500, 500, b"ike", 4)
    profile = {"esp_proposal": "aes128cbc-sha256"}

    monkeypatch.setattr(reader, "stream", lambda _path: iter([ike, *([esp] * 20)]))
    assert _existing_capture_valid(manifest, profile, "s1")

    monkeypatch.setattr(reader, "stream", lambda _path: iter([esp] * 20))
    assert not _existing_capture_valid(manifest, profile, "s1")
