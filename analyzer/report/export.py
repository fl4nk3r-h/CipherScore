"""Machine-readable exports (repo.md §4; mvp.md §3.6): `report.json` and
`findings.csv`."""
from __future__ import annotations

import csv
import json
from pathlib import Path


def export_report_json(context: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.json"
    path.write_text(json.dumps(context, indent=2, default=str))
    return path


def export_findings_csv(context: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "findings.csv"
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["rule_id", "title", "category", "severity",
                         "likelihood", "confidence", "refs", "fix"])
        for f in context.get("findings", []):
            writer.writerow([f["rule_id"], f["title"], f["category"], f["severity"],
                             f["likelihood"], f["confidence"],
                             "; ".join(f.get("refs", [])), f.get("fix", "")])
    return path
