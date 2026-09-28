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
    # -C 100: rotate every 100 MB; -w session_%s: timestamped files (mvp.md §3.2).
    cmd = ["tcpdump", "-i", interface, "-C", "100", "-w",
           str(out / "session_%s.pcapng")]
    proc = subprocess.Popen(cmd)
    (out / "tcpdump.pid").write_text(str(proc.pid))
    (out / "started_at").write_text(str(stamp))
    print(f"[capture] {session_id}: tcpdump pid={proc.pid} on {interface}")
    return 0


def stop(session_id: str) -> int:
    out = _session_dir(session_id)
    pid_file = out / "tcpdump.pid"
    if not pid_file.exists():
        print(f"[capture] {session_id}: no running tcpdump", file=sys.stderr)
        return 1
    pid = int(pid_file.read_text().strip())
    # SIGINT lets tcpdump flush buffers and write the pcap trailer cleanly.
    subprocess.run(["kill", "-INT", str(pid)], check=False)

    # Wait for the process to actually exit so the final pcap is flushed.
    for _ in range(50):                       # up to ~5 s
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        subprocess.run(["kill", "-9", str(pid)], check=False)

    started = (out / "started_at").read_text().strip()
    (out / "ended_at").write_text(str(int(time.time())))

    # Canonical artifact name per §3.2: <session_id>.pcapng
    rotated = sorted(out.glob("session_*.pcapng"))
    canonical = out / f"{session_id}.pcapng"
    if rotated and not canonical.exists():
        largest = max(rotated, key=lambda p: p.stat().st_size)
        largest.replace(canonical)
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
