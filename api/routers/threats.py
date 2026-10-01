"""Passive threat replay, mirror capture, history, and alert events."""
from __future__ import annotations

import asyncio
import json
import queue
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import APIRouter, HTTPException

from analyzer.parse.reader import stream_file
from analyzer.threats import Alert, ThreatEngine
from api import db, events
from api.settings import settings

router = APIRouter(prefix="/threats", tags=["threats"])
_worker = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cs-threat")
_subscribers: list[queue.Queue] = []
_lock = threading.Lock()
_live_process: subprocess.Popen | None = None
_live_stop = threading.Event()


def _publish(message: dict) -> None:
    with _lock:
        for subscriber in _subscribers:
            try:
                subscriber.put_nowait(message)
            except queue.Full:
                try:
                    subscriber.get_nowait()
                except queue.Empty:
                    pass
                subscriber.put_nowait(message)


def _save(alert: Alert) -> None:
    conn = db.connect()
    try:
        conn.execute("INSERT OR IGNORE INTO threat_alert VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (alert.id, alert.timestamp, alert.flow_id, alert.threat_class,
                      alert.severity, alert.confidence, json.dumps(alert.evidence),
                      alert.source, alert.model_version))
        conn.commit()
    finally:
        conn.close()
    _publish({"event": "alert", "alert": alert.as_dict()})


def _run_replay(run_id: str, path: Path) -> None:
    try:
        engine = ThreatEngine(source=f"replay:{run_id}")
        for alert in engine.replay(path):
            _save(alert)
        _publish({"event": "completed", "run_id": run_id,
                  "packets": engine.packet_count, "drops": engine.drop_count})
    except Exception as exc:  # noqa: BLE001 — background job must report failures
        _publish({"event": "failed", "run_id": run_id, "error": str(exc)})


@router.post("/replay")
def replay(body: dict) -> dict:
    capture_id = body.get("capture_id")
    if not capture_id:
        raise HTTPException(422, "capture_id required")
    conn = db.connect()
    try:
        row = conn.execute("SELECT path FROM capture WHERE id = ?", (capture_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(404, "capture not found")
    path = Path(row["path"])
    if not path.is_file():
        raise HTTPException(404, "capture file missing")
    run_id = f"tr_{uuid.uuid4().hex[:12]}"
    _worker.submit(_run_replay, run_id, path)
    return {"run_id": run_id, "status": "queued"}


@router.get("/alerts")
def alerts(limit: int = 100, threat_class: str | None = None) -> list[dict]:
    limit = max(1, min(limit, 500))
    conn = db.connect()
    try:
        if threat_class:
            rows = conn.execute(
                "SELECT * FROM threat_alert WHERE threat_class = ? ORDER BY timestamp DESC LIMIT ?",
                (threat_class, limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM threat_alert ORDER BY timestamp DESC LIMIT ?",
                                (limit,)).fetchall()
        return [dict(row) | {"evidence": json.loads(row["evidence"])} for row in rows]
    finally:
        conn.close()


@router.get("/events")
def alert_events():
    subscriber: queue.Queue = queue.Queue(maxsize=1000)
    with _lock:
        _subscribers.append(subscriber)

    async def gen():
        try:
            while True:
                try:
                    item = await asyncio.to_thread(subscriber.get, True, 1)
                except queue.Empty:
                    yield {"event": "ping", "data": ""}
                    continue
                yield {"event": item["event"], "data": json.dumps(item)}
        finally:
            with _lock:
                if subscriber in _subscribers:
                    _subscribers.remove(subscriber)

    return events.sse_response(gen())


def _run_live(process: subprocess.Popen) -> None:
    engine = ThreatEngine(source="mirror")
    try:
        assert process.stdout is not None
        for pkt in stream_file(process.stdout):
            if _live_stop.is_set():
                break
            for alert in engine.ingest(pkt):
                _save(alert)
    except Exception as exc:  # noqa: BLE001 — capture thread must report failures
        _publish({"event": "failed", "source": "mirror", "error": str(exc)})
    finally:
        process.terminate()
        _publish({"event": "stopped", "source": "mirror",
                  "packets": engine.packet_count, "drops": engine.drop_count})


@router.post("/live/start")
def start_live() -> dict:
    global _live_process
    if not settings.live_enabled:
        raise HTTPException(403, "live mode disabled")
    if _live_process and _live_process.poll() is None:
        return {"status": "running", "interface": settings.live_interface}
    _live_stop.clear()
    try:
        _live_process = subprocess.Popen(
            ["tcpdump", "-i", settings.live_interface, "-U", "-w", "-"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise HTTPException(503, f"capture unavailable: {exc}") from exc
    time.sleep(0.1)
    if _live_process.poll() is not None:
        error = _live_process.stderr.read().decode(errors="replace") if _live_process.stderr else ""
        _live_process = None
        raise HTTPException(503, error.strip() or "capture exited during startup")
    _worker.submit(_run_live, _live_process)
    return {"status": "running", "interface": settings.live_interface}


@router.post("/live/stop")
def stop_live() -> dict:
    global _live_process
    _live_stop.set()
    if _live_process:
        _live_process.terminate()
        _live_process = None
    return {"status": "stopped"}
