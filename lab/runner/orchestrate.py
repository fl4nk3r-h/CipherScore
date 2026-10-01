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
import re
import subprocess
import sys
import time
from collections.abc import Callable
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
        timeout: int = DOCKER_TIMEOUT_S, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, check=check, text=True, capture_output=True,
                              timeout=timeout, env=env)
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
                    traffic_type: str, out_root: str, sa_state: str = "") -> pathlib.Path | None:
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
    esp = profile["esp_proposal"].lower()
    cipher = "AES-GCM-16" if "gcm" in esp else "AES-CBC" if "cbc" in esp else "AH"
    match = re.search(r"aes(128|256)", esp)
    dh_names = {"modp1024": 2, "modp2048": 14, "modp3072": 15,
                "modp4096": 16, "ecp256": 19, "ecp384": 20, "ecp521": 21,
                "curve25519": 31}
    dh_group = next((group for name, group in dh_names.items()
                     if name in profile["ike_proposal"]), None)
    integ = ("AEAD" if "gcm" in esp else next(
        (token for token in esp.split("-") if token.startswith("sha")), "unknown"))
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
            "enc": cipher,
            "key_bits": int(match.group(1)) if match else None,
            "integ": integ,
            "dh_group": dh_group,
            "child_rekey_s": parse_duration(profile["child_rekey_time"]),
            "replay_window": profile["replay_window"],
            "traffic_type": traffic_type,
        },
        "pcap": f"{session_id}.pcapng",
        "keys": f"{session_id}.keys/",
        "sa_state": sa_state,
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
        input=payload, text=True, capture_output=True, check=True,
    )


def _container_running(name: str) -> bool:
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                       capture_output=True, text=True, check=False)
    return r.returncode == 0 and r.stdout.strip() == "true"


def _capture_compose(*args: str) -> list[str]:
    return ["docker", "compose", "-f", str(_REPO_ROOT / "docker-compose.yml"), *args]


def _lab_compose(*args: str) -> list[str]:
    return ["docker", "compose", "-f", str(_REPO_ROOT / "docker-compose.lab.yml"), *args]


def ensure_stack(profile_id: str = "p01") -> None:
    """Bring up missing lab services and bind capture to the current gw-a."""
    missing_lab = [name for name in _REQUIRED_CONTAINERS if name != "capture"
                   and not _container_running(name)]
    capture_running = _container_running("capture")
    if not missing_lab and capture_running:
        return
    missing = [*missing_lab, *([] if capture_running else ["capture"])]
    print(f"[lab] missing: {', '.join(missing)} — starting stack")
    if missing_lab:
        # A running capture sidecar shares gw-a's namespace. Stop it before
        # Compose may replace the gateway, then rebind it to the new ID.
        if capture_running:
            _sh(_capture_compose("stop", "capture"))
        _sh(_lab_compose("up", "-d"),
            env={**os.environ, "LAB_PROFILE": profile_id})
    # Compose `start` reuses an old container:<gateway-id> namespace and fails
    # after gw-a was recreated. Recreate the sidecar every time it is missing
    # or the lab stack changed.
    _sh(_capture_compose("up", "-d", "--force-recreate", "capture"))


def activate_profile(profile_id: str) -> None:
    """Recreate gateways and rebind capture when the selected profile changes."""
    current = _sh(["docker", "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}",
                   "gw-a"], check=False).stdout
    if f"LAB_PROFILE={profile_id}" in current:
        return
    if _container_running("capture"):
        _sh(_capture_compose("stop", "capture"))
    _sh(_lab_compose("up", "-d", "--force-recreate", "gw-a", "gw-b"),
        env={**os.environ, "LAB_PROFILE": profile_id})
    _sh(_capture_compose("up", "-d", "--force-recreate", "capture"))


def parse_duration(spec: str) -> int:
    return int(spec[:-1]) * {"s": 1, "m": 60, "h": 3600}[spec[-1]]


def run_sessions(profiles: list[dict[str, Any]], traffic: list[str] | None,
                 out_root: str = "data/sessions", repetitions: int = 1,
                 on_progress: Callable[[dict[str, Any]], None] | None = None) -> dict[str, int]:
    """Run selected sessions and publish durable progress after each step."""
    tasks = []
    for profile in profiles:
        for traffic_type in (traffic or profile["traffic"]):
            if traffic_type not in profile["traffic"]:
                continue
            for repetition in range(1, repetitions + 1):
                session_id = f"{profile['id']}-{traffic_type}-{repetition:04d}"
                manifest = _REPO_ROOT / out_root / session_id / "manifest.json"
                tasks.append((profile, traffic_type, session_id, manifest))
    total = len(tasks)
    counts = {"total": total, "processed": 0, "completed": 0, "skipped": 0, "failed": 0}
    # Traffic generators have a declared duration. Add setup/teardown time per
    # uncaptured session; this remains an estimate, especially during Docker startup.
    remaining = sum(parse_duration(profile["duration_per_traffic"]) + 45
                    for profile, _, _, manifest in tasks if not manifest.exists())

    def report(phase: str, current_session: str | None = None) -> None:
        if on_progress:
            on_progress({**counts, "status": "running", "phase": phase,
                         "current_session": current_session,
                         "eta_seconds": max(0, round(remaining))})

    lock_fd = _runner_lock()
    try:
        report("Preparing Lab stack")
        ensure_stack(profiles[0]["id"] if profiles else "p01")
        for profile in profiles:
            report(f"Configuring profile {profile['id']}")
            activate_profile(profile["id"])
            for task_profile, traffic_type, session_id, manifest in tasks:
                if task_profile is not profile:
                    continue
                if manifest.exists():
                    print(f"[lab] session {session_id} already valid; skipping", flush=True)
                    counts["skipped"] += 1
                    counts["processed"] += 1
                    report(f"Skipped existing session {session_id}")
                    continue
                report(f"Capturing {session_id}", session_id)
                try:
                    _run_one(profile, traffic_type, out_root, session_id)
                except (subprocess.SubprocessError, OSError, ValueError) as exc:
                    print(f"[lab] session {session_id} failed, continuing: {exc}",
                          file=sys.stderr, flush=True)
                    counts["failed"] += 1
                    if on_progress:
                        on_progress({"last_error": f"{session_id}: {exc}"})
                else:
                    counts["completed"] += 1
                counts["processed"] += 1
                expected = parse_duration(profile["duration_per_traffic"]) + 45
                remaining = max(0, remaining - expected)
                report(f"Finished {session_id}")
        return counts
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _run_one(profile: dict[str, Any], tt: str, out_root: str, session_id: str) -> None:
    session_dir = _REPO_ROOT / out_root / session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    _sh(["docker", "exec", "capture", "python3", "/app/capture.py", "start", session_id])
    sa_state = ""
    try:
        if profile["ike_version"] == 1:
            initiation = _sh(["docker", "exec", "gw-a", "ipsec", "up", profile["id"]],
                             check=False)
        else:
            initiation = _sh(["docker", "exec", "gw-a", "swanctl", "--initiate",
                              "--child", f"{profile['id']}-child", "--ike", profile["id"],
                              "--timeout", str(SWANCTL_TIMEOUT_S)], check=False)
        if initiation.returncode != 0:
            raise ValueError(f"SA initiation failed: {initiation.stderr[:200]}")
        dur = parse_duration(profile["duration_per_traffic"])
        cmd = [c.format(server=SERVER_BY_FAMILY[profile["ip_family"]], dur=dur)
               for c in GENERATOR_CMD[tt]]
        traffic_result = _sh(["docker", "exec", "client-a", *cmd], check=False)
        if traffic_result.returncode != 0:
            raise ValueError(f"{tt} generator failed: {traffic_result.stderr[:200]}")
        if profile["ike_version"] == 2:
            sa_state = _sh(["docker", "exec", "gw-a", "swanctl", "--list-sas"],
                           check=False).stdout
            rekey = _sh(["docker", "exec", "gw-a", "swanctl", "--rekey", "--child",
                         f"{profile['id']}-child"], check=False)
            if rekey.returncode != 0:
                raise ValueError(f"CHILD_SA rekey failed: {rekey.stderr[:200]}")
        else:
            sa_state = _sh(["docker", "exec", "gw-a", "ipsec", "statusall"],
                           check=False).stdout
        _sh(["docker", "exec", "client-a", "bash", "/traffic/icmp.sh",
             SERVER_BY_FAMILY[profile["ip_family"]], "5"], check=False)
    finally:
        _sh(["docker", "exec", "capture", "python3", "/app/capture.py", "stop",
             session_id], check=False)
        if profile["ike_version"] == 1:
            _sh(["docker", "exec", "gw-a", "ipsec", "down", profile["id"]], check=False)
        else:
            _sh(["docker", "exec", "gw-a", "swanctl", "--terminate", "--ike",
                 profile["id"], "--timeout", str(SWANCTL_TIMEOUT_S)], check=False)
    from analyzer.parse import demux, reader
    capture = session_dir / f"{session_id}.pcapng"
    buckets = demux.classify(reader.stream(capture))
    esp_count = len(buckets[demux.ProtocolClass.ESP]) + len(buckets[demux.ProtocolClass.ESP_IN_UDP])
    ah_count = len(buckets[demux.ProtocolClass.AH])
    protected = ah_count if profile["esp_proposal"].startswith("ah-") else esp_count
    expected_mode = profile["mode"].upper()
    expected_cipher = "AES_GCM" if "gcm" in profile["esp_proposal"] else "AES_CBC"
    state_matches = (profile["id"] in sa_state and expected_mode in sa_state.upper()
                     and (expected_cipher in sa_state.upper() or
                          profile["esp_proposal"].startswith("ah-")))
    if protected < 20 or not buckets[demux.ProtocolClass.IKE] or not state_matches:
        raise ValueError(f"invalid capture: {esp_count} ESP, {ah_count} AH, "
                         f"{len(buckets[demux.ProtocolClass.IKE])} IKE packets")
    _write_manifest(session_id, profile, tt, out_root, sa_state)
    print(f"[lab] valid session {session_id}: {protected} protected packets")
