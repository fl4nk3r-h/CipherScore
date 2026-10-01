"""Build verified IPsec SA and flow-window training tables from lab sessions."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from analyzer.features import esp_structure, flow_windows, store
from analyzer.infer.features import sa_features, traffic_features
from analyzer.parse import demux, ike, reader, sa_tracker
from analyzer.parse.esp import parse_esp
from ml.build_threat_dataset import sha256_file

DH_NAMES = {"modp1024": 2, "modp2048": 14, "modp3072": 15, "modp4096": 16,
            "ecp256": 19, "ecp384": 20, "ecp521": 21, "curve25519": 31}


def proposal_labels(manifest: dict) -> dict:
    labels = manifest["labels"]
    esp = labels.get("esp_proposal", "").lower()
    cipher = "GCM" if "gcm" in esp else "CBC" if "cbc" in esp else None
    integ = "AEAD" if cipher == "GCM" else next(
        (token for token in esp.split("-") if token.startswith("sha")), None)
    dh = next((value for name, value in DH_NAMES.items() if name in esp), None)
    return {"mode": labels.get("mode"), "cipher": cipher,
            "integ": integ, "pfs": labels.get("pfs"), "dh_group": dh,
            "traffic": manifest["traffic_type"]}


def build(sessions_root: Path, out_dir: Path) -> dict:
    rows_sa: list[dict] = []
    rows_windows: list[dict] = []
    labels: list[dict] = []
    rejected: list[dict] = []
    provenance: list[dict] = []

    for manifest_path in sorted(sessions_root.glob("*/manifest.json")):
        manifest = json.loads(manifest_path.read_text())
        pcap = manifest_path.parent / manifest["pcap"]
        if not pcap.exists():
            rejected.append({"session_id": manifest["session_id"], "reason": "missing pcap"})
            continue
        buckets = demux.classify(reader.stream(pcap))
        ike_packets = buckets[demux.ProtocolClass.IKE]
        esp_records = [rec for pkt in buckets[demux.ProtocolClass.ESP]
                       if (rec := parse_esp(pkt))]
        esp_records += [rec for pkt in buckets[demux.ProtocolClass.ESP_IN_UDP]
                        if (rec := parse_esp(pkt, udp_encapsulated=True))]
        if len(esp_records) < 20 or not ike_packets:
            rejected.append({"session_id": manifest["session_id"],
                             "reason": f"{len(esp_records)} ESP, {len(ike_packets)} IKE"})
            continue
        ike_sessions: dict[tuple, ike.IKESession] = {}
        for pkt in ike_packets:
            ike.parse_ike_message(pkt, ike_sessions)
        tracker = sa_tracker.build(esp_records, ike_sessions)
        if not tracker.sas:
            rejected.append({"session_id": manifest["session_id"], "reason": "no SAs"})
            continue
        truth = proposal_labels(manifest)
        labels.append({"session_id": manifest["session_id"],
                       "profile": manifest["profile"], **truth})
        provenance.append({"session_id": manifest["session_id"], "path": str(pcap),
                           "sha256": sha256_file(pcap),
                           "source": "strongswan-lab", "esp_packets": len(esp_records),
                           "ike_packets": len(ike_packets)})
        for spi, track in tracker.sas.items():
            recs = [r for r in esp_records if r.spi == spi]
            struct = esp_structure.analyze(recs)
            features = sa_features(track, struct, esp_structure.size_offsets(recs),
                                   tracker.ike_sessions)
            rows_sa.append({"session_id": manifest["session_id"],
                            "profile": manifest["profile"], "spi": f"0x{spi:08x}",
                            **features, **truth})
            for window in flow_windows.extract(recs, sa_id=f"0x{spi:08x}"):
                rows_windows.append({"session_id": manifest["session_id"],
                                     "profile": manifest["profile"], "spi": f"0x{spi:08x}",
                                     "t0": window["t0"], **traffic_features(window),
                                     "traffic": truth["traffic"]})

    out_dir.mkdir(parents=True, exist_ok=True)
    if rows_sa:
        store.write_sa_evidence(rows_sa, out_dir / "features" / "sa_evidence.parquet")
    if rows_windows:
        store.write_flow_windows(rows_windows, out_dir / "features" / "flow_windows.parquet")
    if labels:
        with (out_dir / "labels.csv").open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(labels[0]))
            writer.writeheader()
            writer.writerows(labels)
    (out_dir / "provenance.json").write_text(json.dumps(provenance, indent=2))
    (out_dir / "rejected.json").write_text(json.dumps(rejected, indent=2))
    summary = {"sessions": len(labels), "sa_rows": len(rows_sa),
               "windows": len(rows_windows), "rejected": len(rejected)}
    print(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=Path, default=Path("data/sessions"))
    ap.add_argument("--out", type=Path, default=Path("dataset"))
    args = ap.parse_args()
    build(args.sessions, args.out)
