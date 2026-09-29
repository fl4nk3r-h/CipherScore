from __future__ import annotations

import os
import time
from io import StringIO

import pytest

from capture import live
from capture.live import LiveCaptureError, LiveCapturer, capture_command, runtime_dir


def test_runtime_dir_uses_data_dir_argument(tmp_path):
    assert runtime_dir(tmp_path) == tmp_path / "sessions" / "_live"


def test_latest_window_ignores_currently_written_file(tmp_path):
    capturer = LiveCapturer(data_dir=tmp_path)
    completed = capturer.runtime_dir / "live_completed.pcapng"
    current = capturer.runtime_dir / "live_current.pcapng"
    completed.touch()
    current.touch()
    old = time.time() - 11
    os.utime(completed, (old, old))

    assert capturer.latest_window() == completed


def test_capture_command_prefers_dumpcap(tmp_path, monkeypatch):
    monkeypatch.setattr(live.shutil, "which", lambda name: "/usr/bin/dumpcap")

    command = capture_command("wlo1", tmp_path)

    assert command == [
        "dumpcap", "-i", "wlo1", "-b", "duration:10", "-b", "files:3",
        "-w", str(tmp_path / "live.pcapng"),
    ]


def test_capture_command_falls_back_to_tcpdump(tmp_path, monkeypatch):
    monkeypatch.setattr(live.shutil, "which", lambda name: None)

    command = capture_command("eth0", tmp_path)

    assert command[:8] == ["tcpdump", "-i", "eth0", "-U", "-G", "10", "-W", "3"]


def test_start_rejects_an_immediately_failing_tcpdump(tmp_path, monkeypatch):
    class FailedProcess:
        stderr = StringIO("tcpdump: wlo1: You don't have permission")

        def poll(self):
            return 1

    monkeypatch.setattr(live.subprocess, "Popen", lambda *args, **kwargs: FailedProcess())
    monkeypatch.setattr(live.time, "sleep", lambda _: None)

    with pytest.raises(LiveCaptureError, match="don't have permission"):
        LiveCapturer(interface="wlo1", data_dir=tmp_path).start()
