"""Session manifest writer (mvp.md §3.2).

Each session gets a manifest.json carrying the session id, profile, traffic
type, start/end times, gateways, the full ground-truth label block, the pcap
name, and the save-keys directory. Schema: capture/schemas/manifest.schema.json.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

SESSIONS_DIR = Path("/sessions")


def build_manifest(session_id: str, profile: str, traffic_type: str,
                   gateways: list[str], labels: dict,
                   pcap: str, keys: str) -> dict:
    return {
        "session_id": session_id,
        "profile": profile,
        "traffic_type": traffic_type,
        "start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "gateways": gateways,
        "labels": labels,
        "pcap": pcap,
        "keys": keys,
    }


def write_manifest(session_dir: Path, manifest: dict) -> Path:
    path = session_dir / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2))
    return path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("session_id")
    ap.add_argument("--profile", required=True)
    ap.add_argument("--traffic", required=True)
    ap.add_argument("--gateways", nargs="+", required=True)
    ap.add_argument("--labels", required=True, help="JSON file with the label block")
    args = ap.parse_args()
    d = SESSIONS_DIR / args.session_id
    labels = json.loads(Path(args.labels).read_text())
    manifest = build_manifest(
        args.session_id, args.profile, args.traffic, args.gateways, labels,
        pcap=f"{args.session_id}.pcapng", keys=f"{args.session_id}.keys/",
    )
    # Rename the last rotated capture to the canonical session name.
    out = write_manifest(d, manifest)
    print(f"[manifest] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
