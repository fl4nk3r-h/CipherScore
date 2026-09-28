"""Baseline (non-VPN) captures (mvp.md §3.2).

A baseline capture of the same traffic types is recorded **with IPsec
disabled**. It trains and validates the "IPsec present / absent" decision and
shows the metadata that encryption removes.

Workflow:
    1. Tear the SA down (swanctl --terminate) or run on a lab without SAs.
    2. Start tcpdump as in capture.py, tagged session id `<profile>-<traffic>-baseNNNN`.
    3. Run the identical generator for the identical duration.
    4. Stop, write the manifest with labels: {"ipsec_present": false}.
"""
from __future__ import annotations

import subprocess

from capture import capture


def run_baseline(profile: str, traffic_type: str, duration_s: int,
                 generator_cmd: list[str], interface: str = "eth0") -> str:
    # Ensure no SA is up so traffic flows in the clear.
    subprocess.run(["docker", "exec", "gw-a", "swanctl", "--terminate", "--ike", profile],
                   check=False, capture_output=True)
    session_id = f"{profile}-{traffic_type}-baseline"
    capture.start(session_id, interface)
    subprocess.run(generator_cmd, check=False)
    capture.stop(session_id)
    return session_id
