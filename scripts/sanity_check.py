"""Ground truth vs prediction over all lab sessions (repo.md §9; mvp.md §4
screen 8 "accuracy proof" and §9 milestone M-C: deterministic fields match
ground truth on 100 % of lab sessions)."""
from __future__ import annotations

import json
from pathlib import Path

SESSIONS = Path("data/sessions")
COMPARABLE_FIELDS = ["ike_version", "mode", "enc", "key_bits", "integ",
                     "dh_group", "pfs", "nat_t"]


def main() -> None:
    total = matches = 0
    per_field = {f: [0, 0] for f in COMPARABLE_FIELDS}
    for manifest_path in sorted(SESSIONS.glob("*/manifest.json")):
        manifest = json.loads(manifest_path.read_text())
        report = SESSIONS / manifest["session_id"] / "analysis" / "report.json"
        if not report.exists():
            continue
        context = json.loads(report.read_text())
        for sa in context.get("sas", []):
            for field in COMPARABLE_FIELDS:
                pred = sa.get(field)
                if not pred or pred.get("tag") == "unknown":
                    continue
                truth = manifest["labels"].get(field)
                total += 1
                per_field[field][1] += 1
                if str(pred["value"]).lower() == str(truth).lower():
                    matches += 1
                    per_field[field][0] += 1

    print(f"[sanity] deterministic-field match: {matches}/{total}")
    for field, (hit, seen) in per_field.items():
        if seen:
            print(f"  {field}: {hit}/{seen} = {hit / seen:.1%}")
    if total == 0:
        print("[sanity] no analyzed sessions found; run analyses first")


if __name__ == "__main__":
    main()
