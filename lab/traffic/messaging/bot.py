"""WhatsApp-like messaging generator (mvp.md §3.1).

A WebSocket chat bot that exchanges text messages, images, and voice notes with
the chat server on server-b, using the size and timing distributions from
timing_profile.json (which reproduce the public WhatsApp traffic datasets' profile).

Usage: bot.py <server_host> <port> <duration_seconds>
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import random
import sys
import time

import websockets

PROFILE_PATH = pathlib.Path(__file__).with_name("timing_profile.json")


def load_profile() -> dict:
    if PROFILE_PATH.exists():
        return json.loads(PROFILE_PATH.read_text())
    return {
        "text": {"size_bytes": [40, 400], "interval_s": [1.0, 8.0]},
        "image": {"size_bytes": [20_000, 400_000], "interval_s": [20.0, 90.0]},
        "voice": {"size_bytes": [8_000, 120_000], "interval_s": [30.0, 120.0]},
    }


def payload(kind: str, rng: random.Random, spec: dict) -> bytes:
    lo, hi = spec["size_bytes"]
    n = rng.randint(int(lo), int(hi))
    header = f"{kind}:{n}:".encode()
    return header + os.urandom(max(0, n - len(header)))


async def run(host: str, port: int, duration: int) -> None:
    profile = load_profile()
    rng = random.Random()
    end = time.monotonic() + duration
    async with websockets.connect(f"ws://{host}:{port}") as ws:
        while time.monotonic() < end:
            for kind in ("text", "image", "voice"):
                lo, hi = profile[kind]["interval_s"]
                await asyncio.sleep(rng.uniform(float(lo), float(hi)) / len(profile))
                msg = payload(kind, rng, profile[kind])
                await ws.send(msg)
                try:
                    await asyncio.wait_for(ws.recv(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass
                if time.monotonic() >= end:
                    return


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1], int(sys.argv[2]), int(sys.argv[3])))
