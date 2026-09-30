"""Session orchestration (repo.md §2, mvp.md §3.1-3.2).

For each (profile, traffic_type): bring the SA up, tell the capture sidecar to
start, dispatch the traffic generator, stop capture, tear the SA down. The
capture container writes the pcapng, manifest.json, and save-keys output.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys
from typing import Any

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_REQUIRED_CONTAINERS = ("gw-a", "gw-b", "client-a", "server-b",
                        "lab-bridge-tap", "capture")

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


def _sh(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, check=check, text=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"[lab] command failed (exit {e.returncode}): {' '.join(cmd)}\n{e.stderr}",
              file=sys.stderr)
        raise


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
    ensure_stack()
    for profile in profiles:
        wanted = traffic or profile["traffic"]
        for tt in wanted:
            if tt not in profile["traffic"]:
                continue
            session_id = f"{profile['id']}-{tt}-0001"
            print(f"[lab] session {session_id}: initiating SA…")
            _sh(["docker", "exec", "gw-a", "swanctl", "--initiate", "--ike",
                 profile["id"]], check=False)
            print(f"[lab] session {session_id}: SA up")
            _sh(["docker", "exec", "capture", "python3", "/app/capture.py",
                 "start", session_id])
            dur = parse_duration(profile["duration_per_traffic"])
            cmd = [c.format(server=SERVER_BY_FAMILY[profile["ip_family"]],
                            dur=dur) for c in GENERATOR_CMD[tt]]
            _sh(["docker", "exec", "client-a", *cmd], check=False)
            _sh(["docker", "exec", "capture", "python3", "/app/capture.py",
                 "stop", session_id])
            print(f"[lab] session {session_id}: capture stopped, manifest written")
            _sh(["docker", "exec", "gw-a", "swanctl", "--terminate", "--ike",
                 profile["id"]], check=False)
