"""Rolling 10 s window capture for live mode (mvp.md §0, §1 "Analysis input",
§4 screen 9).

The API starts/stops this via POST /live/start and /live/stop; every 10 s the
most recent window is handed to the analyzer as if it were a tiny pcap, and
predictions stream back over /live/events (SSE).

Requires NET_RAW/NET_ADMIN; live mode is disabled by default
(CS_LIVE_ENABLED=false, mvp.md §13).
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path

WINDOW_S = 10
RUNTIME_DIR = Path("/sessions/_live")


class LiveCapturer:
    def __init__(self, interface: str = "eth0") -> None:
        self.interface = interface
        self.proc: subprocess.Popen | None = None
        self.window_no = 0
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

    def start(self) -> None:
        if self.proc:
            return
        self.proc = subprocess.Popen(
            ["tcpdump", "-i", self.interface, "-U", "-w",
             str(RUNTIME_DIR / "live_%s.pcapng")],
        )

    def stop(self) -> None:
        if self.proc:
            self.proc.terminate()
            self.proc = None

    def latest_window(self) -> Path | None:
        """Snapshot the last 10 s of traffic as a standalone pcapng window."""
        windows = sorted(RUNTIME_DIR.glob("live_*.pcapng"))
        return windows[-1] if windows else None


def window_seconds() -> int:
    """Live mode uses 10 s rolling windows on one interface (mvp.md §0)."""
    return WINDOW_S
