"""Measure single-process passive threat throughput with deterministic flows."""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import time

from analyzer.parse.reader import PacketRecord
from analyzer.threats import ThreatEngine


def run(flows: int = 20_000) -> dict:
    engine = ThreatEngine(source="benchmark")
    latencies = []
    start = time.perf_counter()
    for n in range(flows):
        pkt = PacketRecord(ts=float(n) / 1000, src=f"10.1.{n // 256 % 256}.{n % 256}",
                           dst="203.0.113.20", ip_proto=6, sport=20000 + n % 30000,
                           dport=443, payload=b"", ip_version=4, length=80)
        before = time.perf_counter()
        engine.ingest(pkt)
        latencies.append(time.perf_counter() - before)
    elapsed = time.perf_counter() - start
    return {"flows": flows, "seconds": round(elapsed, 3),
            "flows_per_second": round(flows / elapsed),
            "p95_processing_ms": round(statistics.quantiles(latencies, n=100)[94] * 1000, 3),
            "target_1000_flows_per_second_met": flows / elapsed >= 1000,
            "packet_drops": engine.drop_count, "python": platform.python_version(),
            "machine": platform.machine(), "processor": platform.processor()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--flows", type=int, default=20_000)
    args = parser.parse_args()
    print(json.dumps(run(args.flows), indent=2))
