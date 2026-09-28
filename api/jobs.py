"""ThreadPoolExecutor job runner + progress bus (repo.md §7).

"At prototype scale a capture of about 200 MB finishes in seconds to a few
minutes, so a separate queue broker is unnecessary. The job interface stays
the same, so Celery/RQ can replace it later." (mvp.md §2.1)

Progress events follow the §8 sequence: parsed 0.30 → features 0.50 →
inferred 0.70 → assessed 0.85 → completed 1.0, published on the SSE bus.
"""
from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from analyzer import pipeline

EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cs-analysis")
_subscribers: dict[str, list[queue.Queue]] = {}
_lock = threading.Lock()


def subscribe(analysis_id: str) -> queue.Queue:
    q: queue.Queue = queue.Queue()
    with _lock:
        _subscribers.setdefault(analysis_id, []).append(q)
    return q


def unsubscribe(analysis_id: str, q: queue.Queue) -> None:
    with _lock:
        subs = _subscribers.get(analysis_id, [])
        if q in subs:
            subs.remove(q)


def _publish(analysis_id: str, message: dict) -> None:
    with _lock:
        for q in _subscribers.get(analysis_id, []):
            q.put(message)


def submit(analysis_id: str, pcap_path: Path, rule_pack: str,
           on_done: Callable[[], None] | None = None) -> None:
    def progress(stage: str, frac: float) -> None:
        _publish(analysis_id, {"event": "progress", "stage": stage, "frac": frac})
        if stage == "completed":
            _publish(analysis_id, {"event": "completed", "analysis_id": analysis_id})

    def run() -> None:
        try:
            pipeline.run_analysis(pcap_path, rule_pack=rule_pack,
                                  on_progress=progress, out_dir=None,
                                  analysis_id=analysis_id)
        except Exception as exc:  # noqa: BLE001 — job isolation: any failure must surface on the stream
            _publish(analysis_id, {"event": "failed", "error": str(exc)})
        finally:
            if on_done:
                on_done()

    EXECUTOR.submit(run)
