"""Run one SIP call while sending G.711 PCMU RTP for the call duration."""
from __future__ import annotations

import socket
import struct
import subprocess
import sys
import time


def main(server: str, client: str, duration: int) -> None:
    command = ["sipp", server, "-sf", "/traffic/voip/uac.xml",
               "-rtp_payload", "0", "-m", "1", "-nostdin", "-i", client,
               "-mi", client, "-d", str(duration * 1000),
               "-timeout", f"{duration + 30}s"]
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    media_port = 7000 if family == socket.AF_INET6 else 6000
    with socket.socket(family, socket.SOCK_DGRAM) as media:
        media.bind((client, 6000))
        call = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(1)
            deadline = time.monotonic() + max(0, duration - 1)
            sequence = 0
            timestamp = 0
            while time.monotonic() < deadline and call.poll() is None:
                # RFC 3550 header, static payload type 0 (PCMU), 20 ms at 8 kHz.
                header = struct.pack("!BBHII", 0x80, 0, sequence, timestamp, 0x43495048)
                media.sendto(header + b"\xff" * 160, (server, media_port))
                sequence = (sequence + 1) & 0xffff
                timestamp = (timestamp + 160) & 0xffffffff
                time.sleep(0.02)
            _, errors = call.communicate(timeout=duration + 30)
            if call.returncode:
                raise RuntimeError(f"SIPp exited {call.returncode}: {errors[-1000:]}")
        finally:
            if call.poll() is None:
                call.kill()
                call.communicate()


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]))
