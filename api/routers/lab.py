"""Lab endpoints (mvp.md §5, screen 8).

| GET  /lab/profiles  | List profiles |
| POST /lab/runs      | {profile_ids, traffic_types}. Starts a lab run |
| GET  /lab/sessions  | Sessions + ground truth |
"""
from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException

from analyzer import config
from analyzer.lab_evidence import normalize_labels, parse_legacy_state
from api import db
from api.lab_run_status import read_status, update_status
from api.repositories import analyses_repo

_REPO_ROOT = Path(__file__).resolve().parents[2]

router = APIRouter(prefix="/lab", tags=["lab"])

# Env-overridable so the API container sees the shipped profiles (api/Dockerfile).
PROFILES_DIR = config.LAB_PROFILES_DIR


@router.get("/profiles")
def list_profiles() -> list[dict]:
    profiles = []
    for p in sorted(PROFILES_DIR.glob("p*.yaml")):
        spec = yaml.safe_load(p.read_text())
        profiles.append({"id": spec["id"], "file": p.name, "spec": spec})
    return profiles


_ACTIVE = {"queued", "running"}
_PROCESSES: dict[str, subprocess.Popen] = {}


def _status_path() -> Path:
    return config.DATA_DIR / "lab-runs" / "current.json"


def _runner_busy() -> bool:
    """Also detect sweeps started directly from the command line."""
    path = _REPO_ROOT / "data" / ".lab-runner.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False
    finally:
        os.close(fd)


def _alive(run: dict) -> bool:
    pid = run.get("pid")
    if not isinstance(pid, int):
        return False
    process = _PROCESSES.get(run.get("run_id"))
    if process is not None:
        return process.poll() is None
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def _current_status() -> dict | None:
    path = _status_path()
    run = read_status(path)
    if run and run.get("status") in _ACTIVE and not _alive(run) and (
        run.get("pid") is not None or time.time() - run.get("started_at", 0) > 10
    ):
        # A crash or killed subprocess may never get to write its final state.
        run = update_status(path, status="failed", phase="Lab runner stopped",
                            error="The Lab runner exited before reporting completion. Check the server log.",
                            current_session=None, eta_seconds=0, finished_at=time.time())
    if run and run.get("status") not in _ACTIVE:
        _PROCESSES.pop(run.get("run_id"), None)
    if run and run.get("status") in _ACTIVE:
        run = dict(run)
        if run.get("eta_seconds") is not None:
            run["eta_seconds"] = max(0, round(run["eta_seconds"] -
                                               (time.time() - run["updated_at"])))
    return run


@router.get("/runs/current")
def current_run() -> dict | None:
    return _current_status()


@router.post("/runs", status_code=202)
def start_run(body: dict) -> dict:
    profile_ids = body.get("profile_ids")
    traffic_types = body.get("traffic_types") or ["icmp"]
    available = {profile["id"]: profile for profile in list_profiles()}
    if not isinstance(profile_ids, list) or not profile_ids or any(
        not isinstance(pid, str) or pid not in available for pid in profile_ids
    ):
        raise HTTPException(422, "Select one or more valid Lab profiles")
    supported_traffic = {item for profile in available.values()
                         for item in profile["spec"]["traffic"]}
    if not isinstance(traffic_types, list) or not traffic_types or any(
        not isinstance(tt, str) or tt not in supported_traffic for tt in traffic_types
    ):
        raise HTTPException(422, "Select valid traffic types")
    if not any(tt in available[pid]["spec"]["traffic"]
               for pid in profile_ids for tt in traffic_types):
        raise HTTPException(422, "Selected profiles do not support the requested traffic")

    if importlib.util.find_spec("lab.runner") is None:
        raise HTTPException(503, "Lab runner is unavailable in this API environment")

    path = _status_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    submit_fd = os.open(path.parent / ".submit.lock", os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(submit_fd, fcntl.LOCK_EX)
        current = _current_status()
        if (current and current.get("status") in _ACTIVE) or _runner_busy():
            raise HTTPException(409, "A Lab sweep is already running")
        run_id = f"lab_{uuid.uuid4().hex[:8]}"
        update_status(path, run_id=run_id, status="queued", phase="Waiting for Lab runner",
                      profile_ids=profile_ids, traffic_types=traffic_types,
                      total=0, processed=0, completed=0, skipped=0, failed=0,
                      current_session=None, eta_seconds=None, started_at=time.time(),
                      finished_at=None, error=None, last_error=None, pid=None)
        log_path = path.parent / f"{run_id}.log"
        command = [sys.executable, "-m", "lab.runner", "run", "--profiles",
                   ",".join(profile_ids), "--traffic", ",".join(traffic_types),
                   "--status-file", str(path.resolve())]
        try:
            with log_path.open("w") as log:
                process = subprocess.Popen(command, cwd=_REPO_ROOT, stdout=log,
                                           stderr=subprocess.STDOUT, start_new_session=True)
            _PROCESSES[run_id] = process
            run = update_status(path, pid=process.pid)
        except OSError as exc:
            update_status(path, status="failed", phase="Could not start Lab runner",
                          error=str(exc), finished_at=time.time())
            raise HTTPException(503, f"Could not start Lab runner: {exc}") from exc
        return run
    finally:
        fcntl.flock(submit_fd, fcntl.LOCK_UN)
        os.close(submit_fd)


def _value(value):
    """Extract a tagged inference value without treating unknowns as evidence."""
    if isinstance(value, dict) and value.get("tag") != "unknown":
        return value.get("value")
    return None


def _comparable(field: str, value):
    if not isinstance(value, str):
        return value
    value = value.casefold().replace("_", "-")
    if field == "enc":
        if "gcm" in value:
            return "gcm"
        if "cbc" in value:
            return "cbc"
    if field == "integ":
        if "*" in value or value.startswith("icv-"):
            return None
        if value == "aead":
            return value
        for digest in ("sha512", "sha384", "sha256", "sha1", "md5"):
            if digest in value.replace("sha2-", "sha"):
                return digest
    if field == "ike_version":
        return value.removeprefix("ikev")
    return value


def _accuracy(analysis: dict, labels: dict, traffic_type: str) -> dict:
    result = {"analysis_id": analysis["id"], "status": analysis["status"],
              "predicted": {}, "match": {}, "match_rate": None,
              "matched": 0, "compared": 0, "missing": 0, "eligible": 0}
    if analysis["status"] != "completed":
        return result
    sas = analyses_repo.sas(analysis["id"])
    if not sas:
        return result
    fields = ("ike_version", "mode", "enc", "key_bits", "integ", "dh_group", "pfs", "nat_t")
    # A capture may contain several inbound/outbound CHILD_SAs. Use the SA
    # with the most available evidence, independent of the ground truth.
    sa = max(sas, key=lambda item: sum(_value(item.get(field)) is not None
                                       for field in fields) + int(bool(
                                           (item.get("traffic") or {}).get("top"))))
    predicted = {field: _value(sa.get(field)) for field in fields}
    predicted["traffic"] = (sa.get("traffic") or {}).get("top")
    result["predicted"] = predicted
    for field in (*fields, "traffic"):
        expected = traffic_type if field == "traffic" else labels.get(field)
        actual = predicted.get(field)
        if expected is None:
            result["match"][field] = None
            continue
        result["eligible"] += 1
        if actual is None or _comparable(field, actual) is None:
            result["match"][field] = None
            result["missing"] += 1
            continue
        matched = _comparable(field, expected) == _comparable(field, actual)
        result["match"][field] = matched
        result["compared"] += 1
        result["matched"] += int(matched)
    if result["eligible"]:
        result["match_rate"] = result["matched"] / result["eligible"]
    return result


def _verification(manifest: dict, analysis: dict | None, labels: dict) -> dict:
    """Gateway values require an exact CHILD_SA SPI join to the saved PCAP."""
    fields = {field: {"value": None, "source": "unavailable", "match": None}
              for field in ("mode", "enc", "key_bits", "integ", "pfs", "dh_group")}
    evidence = manifest.get("gateway_evidence") or {}
    if evidence:
        children = evidence.get("after", []) + evidence.get("before", [])
        source = "gateway_vici"
    else:
        children = parse_legacy_state(manifest.get("sa_state") or "")
        source = "legacy_sa_state"
        for field in ("pfs", "dh_group"):
            value = labels.get(field)
            if value is not None:
                fields[field] = {"value": value, "source": "configured", "match": None}
    if analysis and analysis["status"] == "completed":
        spis = {sa.get("spi", "").lower() for sa in analyses_repo.sas(analysis["id"])}
        matched_children = [child for child in children
                            if spis.intersection(child.get("spis", []))]
        # Multiple distinct children in a capture are ambiguous for a single
        # session-level value. They must agree; ordering cannot decide it.
        for field in ("mode", "enc", "key_bits", "integ"):
            values = {child.get(field) for child in matched_children if child.get(field) is not None}
            if len(values) == 1:
                value = values.pop()
                fields[field] = {"value": value, "source": source,
                                 "match": _comparable(field, value) == _comparable(field, labels.get(field))
                                 if labels.get(field) is not None else None}
        rekey = evidence.get("rekey") or {}
        if rekey.get("status") == "observed":
            child = rekey.get("child") or {}
            if spis.intersection(child.get("spis", [])):
                for field, value in (("pfs", child.get("dh_group") is not None),
                                     ("dh_group", child.get("dh_group"))):
                    if value is not None:
                        fields[field] = {"value": value, "source": "gateway_vici_rekey",
                                         "match": _comparable(field, value) == _comparable(field, labels.get(field))
                                         if labels.get(field) is not None else None}
    eligible = sum(labels.get(field) is not None for field in fields)
    compared = sum(item["match"] is not None for item in fields.values())
    matched = sum(item["match"] is True for item in fields.values())
    return {"fields": fields, "eligible": eligible, "compared": compared,
            "matched": matched}


@router.get("/sessions")
def list_sessions() -> list[dict]:
    sessions_root = config.SESSIONS_DIR
    rejected_path = _REPO_ROOT / "dataset" / "rejected.json"
    rejected = {}
    if rejected_path.exists():
        try:
            rejected = {item["session_id"]: item["reason"]
                        for item in json.loads(rejected_path.read_text())}
        except (OSError, ValueError, KeyError, TypeError):
            rejected = {}
    conn = db.connect()
    try:
        analyses = {row["capture_id"]: dict(row) for row in conn.execute(
            "SELECT * FROM analysis ORDER BY created, id")}
    finally:
        conn.close()
    out = []
    for manifest_path in sorted(sessions_root.glob("*/manifest.json")):
        m = json.loads(manifest_path.read_text())
        analysis = analyses.get(m["session_id"])
        labels = normalize_labels(m["labels"])
        out.append({
            "session_id": m["session_id"],
            "profile": m["profile"],
            "traffic_type": m["traffic_type"],
            "labels": labels,
            "pcap": m["pcap"],
            "capture_issue": (rejected.get(m["session_id"])
                              if rejected_path.exists() and
                              manifest_path.stat().st_mtime <= rejected_path.stat().st_mtime
                              else None),
            "accuracy": _accuracy(analysis, labels, m["traffic_type"]) if analysis else None,
            "verification": _verification(m, analysis, labels),
        })
    return out
