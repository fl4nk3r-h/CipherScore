"""Rolling 10 s window capture for live mode (mvp.md §0, §1 "Analysis input",
§4 screen 9).

The API starts/stops this via POST /live/start and /live/stop; every 10 s the
most recent window is handed to the analyzer as if it were a tiny pcap, and
predictions stream back over /live/events (SSE).

Requires NET_RAW/NET_ADMIN; live mode is disabled by default
(CS_LIVE_ENABLED=false, mvp.md §13).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

WINDOW_S = 10


class LiveCaptureError(RuntimeError):
    """Raised when tcpdump cannot start a live capture."""


def runtime_dir(data_dir: Path | str | None = None) -> Path:
    """Return the live-capture directory under the configured runtime data.

    The capture container maps its session volume at ``/sessions``, whereas a
    locally run API must write under ``CS_DATA_DIR``. Resolve this at runtime
    rather than import time so test and process environment overrides work.
    """
    base = Path(data_dir) if data_dir is not None else Path(
        os.environ.get("CS_DATA_DIR", "./data"))
    return base / "sessions" / "_live"


def capture_command(interface: str, output_dir: Path) -> list[str]:
    """Build a rotating capture command, preferring capability-enabled dumpcap.

    Linux distributions commonly grant ``dumpcap`` narrowly scoped packet
    capture capabilities for members of the ``wireshark`` group, while a
    normal user cannot run ``tcpdump`` directly. Keep tcpdump as the container
    and minimal-host fallback.
    """
    if shutil.which("dumpcap"):
        return [
            "dumpcap", "-i", interface,
            "-b", f"duration:{WINDOW_S}",
            "-b", "files:3",
            "-w", str(output_dir / "live.pcapng"),
        ]
    return [
        "tcpdump", "-i", interface, "-U", "-G", str(WINDOW_S),
        "-W", "3", "-w", str(output_dir / "live_%s.pcapng"),
    ]


class LiveCapturer:
    def __init__(self, interface: str = "eth0", data_dir: Path | str | None = None) -> None:
        self.interface = interface
        self.proc: subprocess.Popen | None = None
        self.runtime_dir = runtime_dir(data_dir)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)

    def start(self) -> None:
        if self.proc:
            return
        self.proc = subprocess.Popen(
            capture_command(self.interface, self.runtime_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        # Capture tools report insufficient privileges from their child
        # process, not as a Popen exception. Give them a brief startup window
        # so the API can surface a useful error instead of claiming success.
        time.sleep(0.1)
        if self.proc.poll() is not None:
            stderr = self.proc.stderr.read().strip() if self.proc.stderr else ""
            self.proc = None
            raise LiveCaptureError(stderr or "tcpdump exited during startup")

    def stop(self) -> None:
        if self.proc:
            self.proc.terminate()
            self.proc = None

    def latest_window(self) -> Path | None:
        """Snapshot the last 10 s of traffic as a standalone pcapng window."""
        # ``tcpdump -G`` begins the next file at each boundary. Only return a
        # file old enough to be a closed 10-second window, never the file that
        # tcpdump is currently writing.
        cutoff = time.time() - WINDOW_S
        windows = [path for path in self.runtime_dir.glob("live_*.pcapng")
                   if path.stat().st_mtime <= cutoff]
        return max(windows, key=lambda path: path.stat().st_mtime) if windows else None


def window_seconds() -> int:
    """Live mode uses 10 s rolling windows on one interface (mvp.md §0)."""
    return WINDOW_S
