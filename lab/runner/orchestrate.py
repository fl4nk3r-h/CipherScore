"""Session orchestration (repo.md §2, mvp.md §3.1-3.2).

For each (profile, traffic_type): bring the SA up, tell the capture sidecar to
start, dispatch the traffic generator, stop capture, tear the SA down. The
capture container writes the pcapng, manifest.json, and save-keys output.
"""
from __future__ import annotations

import fcntl
import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_REQUIRED_CONTAINERS = ("gw-a", "gw-b", "client-a", "server-b",
                        "lab-bridge-tap", "capture")

# Bounded waits: swanctl --initiate blocks forever without --timeout when the
# peer never answers, which wedged the whole session loop (repo.md §2).
SWANCTL_TIMEOUT_S = 60
DOCKER_TIMEOUT_S = 300

DURATION_DEFAULT_S = 120

GENERATOR_CMD = {
    "icmp": ["bash", "/traffic/icmp.sh", "{server}", "{dur}"],
    "web": ["python3", "/traffic/web.py", "http://{server}", "{dur}"],
    "email": ["bash", "/traffic/email.sh", "{server}", "{dur}"],
    "voip": ["sipp", "-sf", "/traffic/voip/uac.xml", "-rtp_payload",
             "{server}", "-m", "1", "-d", "{dur}000"],
    "video": ["bash", "/traffic/video.sh", "{server}", "{dur}"],
    "messaging": ["python3", "/traffic/messaging/bot.py", "{server}", "8080", "{dur}"],
    "bulk": ["bash", "/traffic/bulk.sh", "{server}", "{dur}"],
}

SERVER_BY_FAMILY = {"ipv4": "10.2.0.10", "ipv6": "fd02::10"}


def _sh(cmd: list[str], check: bool = True,
        timeout: int = DOCKER_TIMEOUT_S) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, check=check, text=True, capture_output=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[lab] command timed out after {timeout}s: {' '.join(cmd)}",
              file=sys.stderr)
        raise
    except subprocess.CalledProcessError as e:
        print(f"[lab] command failed (exit {e.returncode}): {' '.join(cmd)}\n{e.stderr}",
              file=sys.stderr)
        raise


def _runner_lock() -> int:
    """Advisory exclusive lock so two sweeps can't interleave (a previous
    double-run leaked duplicate tcpdumps, clobbered pcaps, and raced
    capture.py stop into self-kill exit 137). Returns the lock fd."""
    lock_path = _REPO_ROOT / "data" / ".lab-runner.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        print("[lab] another sweep is already running — refusing to start "
              "a concurrent one", file=sys.stderr)
        raise SystemExit(1)
    return fd


def _write_manifest(session_id: str, profile: dict[str, Any],
                    traffic_type: str, out_root: str) -> pathlib.Path | None:
    """Write manifest.json from the sidecar's recorded start/end (mvp.md §3.2).

    GET /lab/sessions, the analysis API (lab_session_id resolution) and the
    Grafana session panels all key off this file; capture.py stop does not
    write it (it only records started_at/ended_at), so the runner must.
    """
    session_dir = _REPO_ROOT / out_root / session_id
    pcap = session_dir / f"{session_id}.pcapng"
    if not pcap.exists():
        print(f"[lab] session {session_id}: no capture produced, skipping manifest",
              file=sys.stderr)
        return None
    started = session_dir / "started_at"
    ended = session_dir / "ended_at"
    manifest = {
        "session_id": session_id,
        "profile": profile["id"],
        "traffic_type": traffic_type,
        "start": (started.read_text().strip() if started.exists()
                  else str(int(time.time()))),
        "end": (ended.read_text().strip() if ended.exists()
                else str(int(time.time()))),
        "gateways": ["172.30.0.2", "172.30.0.3"],
        "labels": {
            "ike_version": profile["ike_version"],
            "mode": profile["mode"],
            "ip_family": profile["ip_family"],
            "nat_t": profile["nat_t"],
            "ike_proposal": profile["ike_proposal"],
            "esp_proposal": profile["esp_proposal"],
            "pfs": profile["pfs"],
            "traffic_type": traffic_type,
        },
        "pcap": f"{session_id}.pcapng",
        "keys": f"{session_id}.keys/",
    }
    path = session_dir / "manifest.json"
    try:
        path.write_text(json.dumps(manifest, indent=2))
    except PermissionError:
        # Legacy session dirs are root-owned (created by the capture sidecar);
        # write through the container, which runs as root.
        _write_manifest_via_container(session_id, json.dumps(manifest, indent=2))
    return path


def _write_manifest_via_container(session_id: str, payload: str) -> None:
    subprocess.run(
        ["docker", "exec", "-i", "capture", "/bin/sh", "-c",
         f"cat > /sessions/{session_id}/manifest.json"],
        input=payload, text=True, capture_output=True, check=False,
    )


def _container_running(name: str) -> bool:
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                       capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() == "true"


def ensure_stack() -> None:
    """Bring up the lab stack + capture sidecar if any piece is missing."""
    missing = [n for n in _REQUIRED_CONTAINERS if not _container_running(n)]
    if not missing:
        return
    print(f"[lab] missing: {', '.join(missing)} — starting stack")
    _sh(["docker", "compose", "-f", str(_REPO_ROOT / "docker-compose.lab.yml"),
         "up", "-d"])
    _sh(["docker", "compose", "-f", str(_REPO_ROOT / "docker-compose.yml"),
         "up", "-d", "capture"])


def parse_duration(spec: str) -> int:
    return int(spec[:-1]) * {"s": 1, "m": 60, "h": 3600}[spec[-1]]


def run_sessions(profiles: list[dict[str, Any]], traffic: list[str] | None,
                 out_root: str = "data/sessions") -> None:
    lock_fd = _runner_lock()
    try:
        ensure_stack()
        for profile in profiles:
            wanted = traffic or profile["traffic"]
            for tt in wanted:
                if tt not in profile["traffic"]:
                    continue
                # One failing session must not abort the whole sweep.
                try:
                    _run_one(profile, tt, out_root)
                except (subprocess.SubprocessError, OSError) as e:
                    print(f"[lab] session {profile['id']}-{tt}-0001 failed, "
                          f"continuing: {e}", file=sys.stderr)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _run_one(profile: dict[str, Any], tt: str, out_root: str) -> None:
    session_id = f"{profile['id']}-{tt}-0001"
    # Pre-create as the invoking user so manifest cleanup/writes work
    # without root (the capture sidecar writes as root inside it).
    (_REPO_ROOT / out_root / session_id).mkdir(parents=True, exist_ok=True)
    print(f"[lab] session {session_id}: initiating SA…")
    # --child is explicit: start_action=start alone has proven unreliable
    # on this image, and without a CHILD_SA the capture is plaintext.
    _sh(["docker", "exec", "gw-a", "swanctl", "--initiate",
         "--child", f"{profile['id']}-child", "--ike", profile["id"],
         "--timeout", str(SWANCTL_TIMEOUT_S)], check=False)
    print(f"[lab] session {session_id}: SA up")
    _sh(["docker", "exec", "capture", "python3", "/app/capture.py",
         "start", session_id])
    dur = parse_duration(profile["duration_per_traffic"])
    cmd = [c.format(server=SERVER_BY_FAMILY[profile["ip_family"]],
                    dur=dur) for c in GENERATOR_CMD[tt]]
    # Generators run with check=False, so surface their stderr — a crashing
    # generator otherwise leaves an empty capture with no clue why.
    r = _sh(["docker", "exec", "client-a", *cmd], check=False)
    if r.returncode != 0 and (r.stderr or "").strip():
        print(f"[lab] {tt} generator exited {r.returncode}: "
              f"{r.stderr.strip()[:400]}", file=sys.stderr)
    _sh(["docker", "exec", "capture", "python3", "/app/capture.py",
         "stop", session_id])
    _write_manifest(session_id, profile, tt, out_root)
    print(f"[lab] session {session_id}: capture stopped, manifest written")
    _sh(["docker", "exec", "gw-a", "swanctl", "--terminate", "--ike",
         profile["id"], "--timeout", str(SWANCTL_TIMEOUT_S)], check=False)
