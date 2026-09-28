"""Flow window features (mvp.md §3.3, Step 3): one FlowWindow per 5 s window of
each SA for the traffic classifier.

Flow statistics per window: packet size mean/std/percentiles, IAT stats, burst
counts, up/down byte ratio, packets/s, and the first 32 packet sizes and
directions.
"""
from __future__ import annotations

from itertools import pairwise

from analyzer import config
from analyzer.parse.esp import ESPRecord


def extract(sa_packets: list[ESPRecord], sa_id: str) -> list[dict]:
    if not sa_packets:
        return []
    sa_packets = sorted(sa_packets, key=lambda p: p.ts)
    t_start = sa_packets[0].ts
    windows: list[dict] = []

    win: list[ESPRecord] = []

    def flush() -> None:
        nonlocal win
        if not win:
            return
        lens = [p.length for p in win]
        iats = [b.ts - a.ts for a, b in pairwise(win)]
        up = sum(p.length for p in win if p.src == sa_packets[0].src)
        down = sum(p.length for p in win) - up
        # Bursts: runs of packets with IAT < 20 ms.
        bursts = 0
        in_burst = False
        for gap in iats:
            if gap < 0.02:
                in_burst = True
            elif in_burst:
                bursts += 1
                in_burst = False
        mean = sum(lens) / len(lens)
        std = (sum((x - mean) ** 2 for x in lens) / len(lens)) ** 0.5
        srt = sorted(lens)
        head = list(lens[: config.PACKET_SIZE_HEAD])
        dirs = [1 if p.src == sa_packets[0].src else 0 for p in win[: config.PACKET_SIZE_HEAD]]
        duration = max(win[-1].ts - win[0].ts, 1e-6)
        windows.append({
            "sa_id": sa_id,
            "t0": win[0].ts - t_start,
            "features": {
                "n_packets": float(len(win)),
                "len_mean": mean,
                "len_std": std,
                "len_p10": float(srt[int(0.10 * (len(srt) - 1))]),
                "len_p50": float(srt[len(srt) // 2]),
                "len_p90": float(srt[int(0.90 * (len(srt) - 1))]),
                "iat_mean": (sum(iats) / len(iats)) if iats else 0.0,
                "iat_std": (sum((g - (sum(iats) / len(iats))) ** 2 for g in iats) / len(iats)) ** 0.5
                if iats else 0.0,
                "bursts": float(bursts),
                "updown_ratio": (up / down) if down else float("inf"),
                "packets_per_s": len(win) / duration,
            },
            "head_sizes": head,
            "head_dirs": dirs,
            "pred": None,
            "p": None,
        })
        win = []

    for p in sa_packets:
        if win and p.ts - win[0].ts >= config.FLOW_WINDOW_SECONDS:
            flush()
        win.append(p)
    flush()
    return windows
