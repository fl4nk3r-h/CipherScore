"""Session manifest writer (mvp.md §3.2).

Each session gets a manifest.json carrying the session id, profile, traffic
type, start/end times, gateways, the full ground-truth label block, the pcap
name, and the save-keys directory. Schema: capture/schemas/manifest.schema.json.

Start/end come from the capture sidecar's started_at/ended_at files — real
times, not fabricated ones.
"""
from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

SESSIONS_DIR = Path("/sessions")


def _iso(ts: str | float | None) -> str:
    if ts is None:
        return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return datetime.fromtimestamp(float(ts), tz=UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def build_manifest(session_id: str, profile: str, traffic_type: str,
                   gateways: list[str], labels: dict,
                   pcap: str, keys: str,
                   start: str | None = None, end: str | None = None) -> dict:
    return {
        "session_id": session_id,
        "profile": profile,
        "traffic_type": traffic_type,
        "start": start or _iso(None),
        "end": end or _iso(None),
        "gateways": gateways,
        "labels": labels,
        "pcap": pcap,
        "keys": keys,
    }


def write_manifest(session_dir: Path, manifest: dict) -> Path:
    path = session_dir / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2))
    return path


def write_from_session_dir(session_id: str, profile: str, traffic_type: str,
                           gateways: list[str], labels: dict,
                           sessions_dir: Path = SESSIONS_DIR) -> Path:
    """Write the manifest using the sidecar's recorded start/end times."""
    d = sessions_dir / session_id
    start = _iso((d / "started_at").read_text().strip())
    ended = d / "ended_at"
    end = _iso(ended.read_text().strip()) if ended.exists() else _iso(None)
    manifest = build_manifest(
        session_id, profile, traffic_type, gateways, labels,
        pcap=f"{session_id}.pcapng", keys=f"{session_id}.keys/",
        start=start, end=end,
    )
    return write_manifest(d, manifest)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("session_id")
    ap.add_argument("--profile", required=True)
    ap.add_argument("--traffic", required=True)
    ap.add_argument("--gateways", nargs="+", required=True)
    ap.add_argument("--labels", required=True, help="JSON file with the label block")
    ap.add_argument("--sessions-dir", default=str(SESSIONS_DIR))
    args = ap.parse_args()
    labels = json.loads(Path(args.labels).read_text())
    out = write_from_session_dir(args.session_id, args.profile, args.traffic,
                                 args.gateways, labels, Path(args.sessions_dir))
    print(f"[manifest] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
