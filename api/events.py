"""SSE helpers (repo.md §7): /analyses/{id}/events and /live/events streams."""
from __future__ import annotations

import asyncio
import json
import queue

from sse_starlette.sse import EventSourceResponse


def sse_response(gen) -> EventSourceResponse:
    return EventSourceResponse(gen)


async def queue_to_sse(q: queue.Queue, poll_interval: float = 0.2):
    """Adapt a blocking progress queue into an async SSE generator."""
    loop = asyncio.get_running_loop()
    while True:
        try:
            message = await loop.run_in_executor(None, q.get, True, poll_interval)
        except queue.Empty:
            yield {"event": "ping", "data": ""}
            continue
        yield {"event": message.get("event", "message"),
               "data": json.dumps(message)}
        if message.get("event") in ("completed", "failed"):
            return
