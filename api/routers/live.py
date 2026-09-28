"""Live mode (mvp.md §5, screen 9).

| POST /live/start · /live/stop | Live mode on a configured interface |
| GET  /live/events             | SSE stream of window predictions |

Rolling 10 s windows (§0); requires NET_RAW/NET_ADMIN and is disabled by
default via CS_LIVE_ENABLED=false (§13).
"""
from __future__ import annotations

import asyncio
import queue

from fastapi import APIRouter, HTTPException

from api import events
from api.settings import settings

router = APIRouter(prefix="/live", tags=["live"])

_live_state = {"capturer": None, "q": queue.Queue()}


@router.post("/start")
def start_live() -> dict:
    if not settings.live_enabled:
        raise HTTPException(403, "live mode disabled (CS_LIVE_ENABLED=false)")
    from capture.live import LiveCapturer
    cap = LiveCapturer(settings.live_interface)
    cap.start()
    _live_state["capturer"] = cap
    return {"status": "started", "window_s": 10, "interface": settings.live_interface}


@router.post("/stop")
def stop_live() -> dict:
    cap = _live_state["capturer"]
    if cap:
        cap.stop()
        _live_state["capturer"] = None
    return {"status": "stopped"}


@router.get("/events")
def live_events():
    async def gen():
        while _live_state["capturer"] is not None:
            window = _live_state["capturer"].latest_window()
            if window is not None:
                # Analyzer runs the same pipeline on each 10 s window; predictions evolve.
                from analyzer import pipeline
                result = pipeline.run_analysis(window, out_dir=None)
                yield {"event": "window", "data": result.model_dump_json(
                    include={"analysis_id", "status", "posture"})}
            await asyncio.sleep(10)
        yield {"event": "closed", "data": "{}"}
    return events.sse_response(gen())
