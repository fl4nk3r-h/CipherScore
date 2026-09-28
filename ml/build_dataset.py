"""Build dataset (repo.md §5): sessions/ -> dataset/features/*.parquet + labels.csv.

Reuses the analyzer's parsers so training features match inference features
exactly (mvp.md §3.3 output contract: SAEvidence + FlowWindow as Parquet).
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from analyzer.features import esp_structure, flow_windows, store
from analyzer.parse import demux, ike, reader, sa_tracker


def build(sessions_root: Path, out_dir: Path) -> None:
    rows_sa: list[dict] = []
    rows_windows: list[dict] = []
    labels: list[dict] = []

    for manifest_path in sorted(sessions_root.glob("*/manifest.json")):
        manifest = json.loads(manifest_path.read_text())
        pcap = manifest_path.parent / manifest["pcap"]
        if not pcap.exists():
            continue

        buckets = demux.classify(reader.stream(pcap))
        ike_sessions: dict[tuple, ike.IKESession] = {}
        for pkt in buckets[demux.ProtocolClass.IKE]:
            ike.parse_ike_message(pkt, ike_sessions)
        esp = []
        for pkt in buckets[demux.ProtocolClass.ESP]:
            from analyzer.parse.esp import parse_esp
            rec = parse_esp(pkt)
            if rec:
                esp.append(rec)
        for pkt in buckets[demux.ProtocolClass.ESP_IN_UDP]:
            from analyzer.parse.esp import parse_esp
            rec = parse_esp(pkt, udp_encapsulated=True)
            if rec:
                esp.append(rec)
        tracker = sa_tracker.build(esp, ike_sessions)

        for spi in tracker.sas:   # values unused here; keys() would hide the loop pair
            recs = [r for r in esp if r.spi == spi]
            struct = esp_structure.analyze(recs)
            rows_sa.append({
                "session_id": manifest["session_id"],
                "profile": manifest["profile"],
                "spi": f"0x{spi:08x}",
                "cipher_mode": struct.cipher_mode,
                "icv_len": struct.icv_len,
                "consistency": struct.consistency,
                **esp_structure.size_offsets(recs),
            })
            for w in flow_windows.extract(recs, sa_id=f"0x{spi:08x}"):
                rows_windows.append({
                    "session_id": manifest["session_id"],
                    "profile": manifest["profile"],
                    "traffic_type": manifest["traffic_type"],
                    **w,
                })

        labels.append({
            "session_id": manifest["session_id"],
            "profile": manifest["profile"],
            "traffic_type": manifest["traffic_type"],
            **manifest["labels"],
        })

    out_dir.mkdir(parents=True, exist_ok=True)
    store.write_sa_evidence(rows_sa, out_dir / "features" / "sa_evidence.parquet")
    store.write_flow_windows(rows_windows, out_dir / "features" / "flow_windows.parquet")

    labels_path = out_dir / "labels.csv"
    if labels:
        with open(labels_path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=sorted(labels[0]))
            writer.writeheader()
            writer.writerows(labels)
    print(f"[build_dataset] {len(rows_sa)} SA rows, {len(rows_windows)} windows, "
          f"{len(labels)} sessions -> {out_dir}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=Path, default=Path("data/sessions"))
    ap.add_argument("--out", type=Path, default=Path("dataset"))
    args = ap.parse_args()
    build(args.sessions, args.out)
