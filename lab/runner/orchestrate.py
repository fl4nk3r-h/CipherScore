"""Session orchestration (repo.md §2, mvp.md §3.1-3.2).

For each (profile, traffic_type): bring the SA up, tell the capture sidecar to
start, dispatch the traffic generator, stop capture, tear the SA down. The
capture container writes the pcapng, manifest.json, and save-keys output.
"""
from __future__ import annotations

import subprocess
from typing import Any

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
    return subprocess.run(cmd, check=check, text=True, capture_output=True)


def parse_duration(spec: str) -> int:
    return int(spec[:-1]) * {"s": 1, "m": 60, "h": 3600}[spec[-1]]


def run_sessions(profiles: list[dict[str, Any]], traffic: list[str] | None,
                 out_root: str = "data/sessions") -> None:
    for profile in profiles:
        wanted = traffic or profile["traffic"]
        for tt in wanted:
            if tt not in profile["traffic"]:
                continue
            session_id = f"{profile['id']}-{tt}-0001"
            print(f"[lab] session {session_id}: SA up")
            _sh(["docker", "exec", "gw-a", "swanctl", "--initiate", "--ike",
                 profile["id"]], check=False)
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
