"""WebSocket chat server for the messaging traffic class (mvp.md §3.1).

Reproduces a WhatsApp-like service: small text messages, occasional image and
voice-note payloads. Size and timing characteristics are driven by
lab/traffic/messaging/timing_profile.json.
"""
from __future__ import annotations

import argparse
import asyncio

import websockets  # installed in the server image


async def handler(ws) -> None:
    async for message in ws:
        # Echo pattern is enough to create realistic bidirectional traffic;
        # payload sizes come from the bot, timing from its jittered schedule.
        await ws.send(message)


async def main(port: int) -> None:
    async with websockets.serve(handler, None, port):
        await asyncio.Future()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    asyncio.run(main(args.port))
