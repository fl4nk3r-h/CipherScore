"""Lab endpoints (mvp.md §5, screen 8).

| GET  /lab/profiles  | List profiles |
| POST /lab/runs      | {profile_ids, traffic_types}. Starts a lab run |
| GET  /lab/sessions  | Sessions + ground truth |
"""
from __future__ import annotations

import json
import pathlib
import uuid

import yaml
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/lab", tags=["lab"])

PROFILES_DIR = pathlib.Path("lab/profiles")


@router.get("/profiles")
def list_profiles() -> list[dict]:
    profiles = []
    for p in sorted(PROFILES_DIR.glob("p*.yaml")):
        spec = yaml.safe_load(p.read_text())
        profiles.append({"id": spec["id"], "file": p.name, "spec": spec})
    return profiles


@router.post("/runs")
def start_run(body: dict) -> dict:
    profile_ids = body.get("profile_ids", [])
    traffic_types = body.get("traffic_types", [])
    if not profile_ids:
        raise HTTPException(422, "profile_ids required")
    # Delegates to the M1 runner; sessions appear under data/sessions/.
    import subprocess
    subprocess.Popen(
        ["python", "-m", "lab.runner", "run", "--profiles",
         ",".join(profile_ids), "--traffic", ",".join(traffic_types or ["icmp"])])
    return {"run_id": f"lab_{uuid.uuid4().hex[:8]}", "status": "started"}


@router.get("/sessions")
def list_sessions() -> list[dict]:
    sessions_root = pathlib.Path("data/sessions")
    out = []
    for manifest_path in sorted(sessions_root.glob("*/manifest.json")):
        m = json.loads(manifest_path.read_text())
        out.append({
            "session_id": m["session_id"],
            "profile": m["profile"],
            "traffic_type": m["traffic_type"],
            "labels": m["labels"],
            "pcap": m["pcap"],
        })
    return out
