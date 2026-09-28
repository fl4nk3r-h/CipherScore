"""Analysis endpoints (mvp.md §5).

| POST /analyses            | {capture_id | lab_session_id, rule_pack}. Starts a job -> analysis_id |
| GET  /analyses/{id}       | Status + summary (score, risk, confidence) |
| GET  /analyses/{id}/sas   | SA table with inference tags |
| GET  /analyses/{id}/traffic | Traffic classification + histograms |
| GET  /analyses/{id}/findings | Findings with evidence |
| GET  /analyses/{id}/threat-matrix | 5 x 5 matrix |
| GET  /analyses/{id}/events | SSE progress stream |
"""
from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from api import db, events, jobs
from api.repositories import analyses_repo

router = APIRouter(prefix="/analyses", tags=["analyses"])


@router.post("")
def start_analysis(body: dict) -> dict:
    capture_id = body.get("capture_id")
    lab_session_id = body.get("lab_session_id")
    rule_pack = body.get("rule_pack", "ipsec-baseline")
    conn = db.connect()
    try:
        pcap_path = None
        if capture_id:
            row = conn.execute("SELECT path FROM capture WHERE id = ?",
                               (capture_id,)).fetchone()
            if not row:
                raise HTTPException(404, "capture not found")
            pcap_path = row["path"]
        elif lab_session_id:
            row = conn.execute(
                "SELECT path FROM capture WHERE id LIKE 'sess_' || ?",
                (lab_session_id,)).fetchone()
            if not row:
                raise HTTPException(404, "lab session capture not found")
            pcap_path = row["path"]
        else:
            raise HTTPException(422, "capture_id or lab_session_id required")
    finally:
        conn.close()

    analysis_id = f"an_{uuid.uuid4().hex[:8]}"
    analyses_repo.create(analysis_id, capture_id or lab_session_id, rule_pack)
    jobs.submit(analysis_id, __import__("pathlib").Path(pcap_path), rule_pack,
                on_done=lambda: analyses_repo.refresh_summary(analysis_id))
    return {"analysis_id": analysis_id, "status": "queued"}


@router.get("/{analysis_id}")
def get_analysis(analysis_id: str):
    summary = analyses_repo.summary(analysis_id)
    if summary is None:
        raise HTTPException(404, "analysis not found")
    return summary


@router.get("/{analysis_id}/sas")
def get_sas(analysis_id: str):
    return JSONResponse(analyses_repo.sas(analysis_id))


@router.get("/{analysis_id}/traffic")
def get_traffic(analysis_id: str):
    return JSONResponse(analyses_repo.traffic(analysis_id))


@router.get("/{analysis_id}/findings")
def get_findings(analysis_id: str):
    return JSONResponse(analyses_repo.findings(analysis_id))


@router.get("/{analysis_id}/threat-matrix")
def get_threat_matrix(analysis_id: str):
    return JSONResponse(analyses_repo.threat_matrix(analysis_id))


@router.get("/{analysis_id}/events")
def stream_events(analysis_id: str):
    q = jobs.subscribe(analysis_id)
    return events.sse_response(events.queue_to_sse(q))
_ = json
