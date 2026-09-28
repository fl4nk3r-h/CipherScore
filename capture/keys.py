"""save-keys collection (mvp.md §3.2).

strongSwan's save-keys plugin (charon.plugins.save-keys.esp = yes, ike = yes)
writes Wireshark-compatible `esp_sa` and `ikev2_decryption_table` files. Those
files decrypt the lab captures offline to verify inner-traffic labels. **The
analyzer itself never uses them.**

This module copies them from the gateway container into the session's keys/
directory, per session.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

SESSIONS_DIR = Path("/sessions")
KEY_FILES = ["esp_sa", "ikev2_decryption_table"]


def collect(session_id: str, gateway: str = "gw-a") -> Path:
    out = SESSIONS_DIR / session_id / "keys"
    out.mkdir(parents=True, exist_ok=True)
    for name in KEY_FILES:
        res = subprocess.run(
            ["docker", "cp", f"{gateway}:/var/run/{name}", str(out / name)],
            check=False, capture_output=True, text=True,
        )
        if res.returncode != 0:
            print(f"[keys] warning: {name} not found on {gateway}: {res.stderr}")
    return out


def verify_decrypts(pcap: Path, keys_dir: Path) -> bool:
    """Label-verification hook: tshark decrypts the capture with the key files.

    Used by scripts/sanity_check.py to confirm the traffic label; never part of
    the analysis path (mvp.md §3.2).
    """
    esp_sa = keys_dir / "esp_sa"
    if not esp_sa.exists() or not pcap.exists():
        return False
    res = subprocess.run(
        ["tshark", "-r", str(pcap), "-o", f"uat:esp_sa_files:{esp_sa}",
         "-c", "1"],
        capture_output=True, text=True, check=False,
    )
    return res.returncode == 0
