"""Extract production threat features from exactly labeled PCAP intervals.

JSONL rows need pcap, scenario_id, task, binary label, src_ip, and optional
dst_ip/start_ts/end_ts. Mixed captures must use flow and time scoped labels.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import pandas as pd

from analyzer.threats import ThreatEngine

TASKS = {"beaconing", "dga", "dns_tunneling", "encrypted_malware"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(manifest_path: Path, out_dir: Path) -> dict:
    rows: dict[str, list[dict]] = defaultdict(list)
    by_pcap: dict[Path, list[dict]] = defaultdict(list)
    provenance = []
    for line in manifest_path.read_text().splitlines():
        if not line.strip():
            continue
        spec = json.loads(line)
        if (spec.get("task") not in TASKS or spec.get("label") not in (0, 1)
                or not spec.get("src_ip") or not spec.get("scenario_id")):
            raise ValueError("task, binary label, scenario_id, and src_ip are required")
        pcap = Path(spec["pcap"])
        if not pcap.is_file():
            raise FileNotFoundError(pcap)
        by_pcap[pcap].append(spec)

    for pcap, specs in by_pcap.items():
        digest = sha256_file(pcap)
        lookup: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for spec in specs:
            lookup[(spec["task"], spec["src_ip"])].append(spec)
            provenance.append({"scenario_id": spec["scenario_id"], "task": spec["task"],
                               "pcap": str(pcap), "sha256": digest,
                               "source": spec.get("source", "unrecorded")})

        def collect(feature_task, packet, features, lookup=lookup, digest=digest):
            for spec in lookup.get((feature_task, packet.src), ()):
                if spec.get("dst_ip") and packet.dst != spec["dst_ip"]:
                    continue
                if not (spec.get("start_ts", float("-inf")) <= packet.ts <=
                        spec.get("end_ts", float("inf"))):
                    continue
                rows[feature_task].append({"scenario_id": spec["scenario_id"],
                                           "label": int(spec["label"]),
                                           "capture_sha256": digest, **features})

        engine = ThreatEngine(source="training", feature_sink=collect)
        for _ in engine.replay(pcap):
            pass
    out_dir.mkdir(parents=True, exist_ok=True)
    counts = {}
    for task, values in rows.items():
        pd.DataFrame(values).to_parquet(out_dir / f"{task}.parquet", index=False)
        counts[task] = len(values)
    (out_dir / "provenance.json").write_text(json.dumps(provenance, indent=2))
    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--out", type=Path, default=Path("dataset/threats"))
    args = parser.parse_args()
    print(json.dumps(build(args.manifest, args.out), indent=2))
