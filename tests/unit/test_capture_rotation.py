"""Rotated bulk captures must retain the initial IKE exchange."""
from __future__ import annotations

import dpkt

from capture import capture


def test_stop_merges_all_rotated_parts(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(capture, "_tcpdump_alive", lambda pid: True)
    monkeypatch.setattr(capture.os, "kill", lambda pid, sig: None)
    session = tmp_path / "p04-bulk-probe"
    session.mkdir()
    (session / "tcpdump.pid").write_text("123")
    (session / "started_at").write_text("42")
    for index in (0, 1):
        suffix = "" if index == 0 else str(index)
        with (session / f"session_42.pcapng{suffix}").open("wb") as stream:
            writer = dpkt.pcap.Writer(stream)
            writer.writepkt(bytes([index]) * 60, ts=index + 1)
            writer.close()

    # The mocked process has exited by the time stop waits for it.
    states = iter((True, False))
    monkeypatch.setattr(capture, "_tcpdump_alive", lambda pid: next(states))
    capture.stop("p04-bulk-probe")

    with (session / "p04-bulk-probe.pcapng").open("rb") as stream:
        packets = list(dpkt.pcapng.Reader(stream))
    assert len(packets) == 2
    assert packets[0][1] == bytes([0]) * 60
    assert packets[1][1] == bytes([1]) * 60
    assert not list(session.glob("session_*.pcapng*"))
