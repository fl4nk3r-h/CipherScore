"""tcpdump session capture (mvp.md §3.2).

A tcpdump sidecar on the lab bridge writes rotating captures per session:
`tcpdump -C 100 -w session_%s.pcapng` for each session.

CLI:
    python3 capture.py start <session_id> [interface]
    python3 capture.py stop  <session_id>

The stop command waits for the tcpdump child to exit so the final pcap is
flushed, then renames the last rotated file to the canonical
`<session_id>.pcapng` named in the manifest (§3.2).
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

SESSIONS_DIR = Path("/sessions")


def _session_dir(session_id: str) -> Path:
    d = SESSIONS_DIR / session_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def start(session_id: str, interface: str = "eth0") -> int:
    out = _session_dir(session_id)
    stamp = int(time.time())
    # Stamp-based names: some tcpdump builds do not expand %s in -w; rotations
    # (-C 100) append 1,2,3… which the stop glob below still picks up.
    # -Z root: tcpdump's default privilege drop cannot create files in the
    # root-owned bind-mounted /sessions (writes nothing, exits silently).
    cmd = ["tcpdump", "-i", interface, "-C", "100", "-Z", "root", "-w",
           str(out / f"session_{stamp}.pcapng")]
    proc = subprocess.Popen(cmd)
    (out / "tcpdump.pid").write_text(str(proc.pid))
    (out / "started_at").write_text(str(stamp))
    print(f"[capture] {session_id}: tcpdump pid={proc.pid} on {interface}")
    return 0


def _tcpdump_alive(pid: int) -> bool:
    """True if pid exists AND is still tcpdump (guards against pid reuse:
    signaling a recycled pid once killed our own exec'd python -> exit 137)."""
    try:
        return "tcpdump" in Path(f"/proc/{pid}/comm").read_text()
    except OSError:
        return False


def stop(session_id: str) -> int:
    out = _session_dir(session_id)
    pid_file = out / "tcpdump.pid"
    if not pid_file.exists():
        # Idempotent: a double-stop (e.g. two runners racing on one session)
        # must not fail the sweep.
        print(f"[capture] {session_id}: no running tcpdump", file=sys.stderr)
        return 0
    pid = int(pid_file.read_text().strip())
    if not _tcpdump_alive(pid):
        print(f"[capture] {session_id}: pid {pid} is not tcpdump (stale)")
        pid_file.unlink(missing_ok=True)
        return 0
    # SIGINT lets tcpdump flush buffers and write the pcap trailer cleanly.
    # The container image has no `kill` binary, so signal via os.kill.
    try:
        os.kill(pid, signal.SIGINT)
    except ProcessLookupError:
        pass

    # Wait for the process to actually exit so the final pcap is flushed.
    for _ in range(50):                       # up to ~5 s
        if not _tcpdump_alive(pid):
            break
        time.sleep(0.1)
    else:
        # Re-validate before the fallback kill: the pid may have been recycled
        # between the check above and now.
        if _tcpdump_alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            time.sleep(0.2)

    started = (out / "started_at").read_text().strip()
    (out / "ended_at").write_text(str(int(time.time())))

    # Canonical artifact name per §3.2: <session_id>.pcapng. The newest/largest
    # rotated file wins — a stale canonical from an aborted run must not mask
    # the fresh capture.
    rotated = sorted(out.glob("session_*"))
    canonical = out / f"{session_id}.pcapng"
    if rotated:
        largest = max(rotated, key=lambda p: p.stat().st_size)
        largest.replace(canonical)
        for extra in rotated:
            extra.unlink(missing_ok=True)
    pid_file.unlink(missing_ok=True)
    print(f"[capture] {session_id}: stopped (started {started})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_start = sub.add_parser("start")
    p_start.add_argument("session_id")
    p_start.add_argument("--interface", default="eth0")
    p_stop = sub.add_parser("stop")
    p_stop.add_argument("session_id")
    args = ap.parse_args()
    if args.cmd == "start":
        return start(args.session_id, args.interface)
    return stop(args.session_id)


if __name__ == "__main__":
    raise SystemExit(main())
