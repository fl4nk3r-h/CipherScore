"""Session verification (repo.md §2): `swanctl --list-sas` checks + ESP presence.

Exit criterion of milestone M-A (mvp.md §9): `swanctl --list-sas` shows installed
SAs and ESP is visible in the pcap.
"""
from __future__ import annotations

import subprocess


def list_sas() -> str:
    out = subprocess.run(
        ["docker", "exec", "gw-a", "swanctl", "--list-sas"],
        text=True, capture_output=True, check=False,
    )
    return out.stdout


def sa_installed(profile_id: str) -> bool:
    return profile_id in list_sas()


def esp_present_in_pcap(pcap_path: str) -> bool:
    """True when at least one ESP packet (IP proto 50) appears in the capture."""
    out = subprocess.run(
        ["tcpdump", "-r", pcap_path, "-c", "1", "ip[9]==50 or ip6[6]==50"],
        text=True, capture_output=True, check=False,
    )
    return out.returncode == 0 and bool(out.stdout.strip())
