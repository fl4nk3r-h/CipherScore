"""Load 3 pre-analyzed captures for the offline demo (repo.md §9; mvp.md §9
milestone M-F: the demo runs without manual fixes)."""
from __future__ import annotations

import shutil
from pathlib import Path

DEMO = Path("data/demo")
SESSIONS = Path("data/sessions")
REPORTS = Path("data/reports")

# Three demo captures: weak (p03), strong (p07), and a baseline.
DEMO_SETS = ["p03-voip-demo", "p07-voip-demo", "p01-web-demo"]


def main() -> None:
    if not DEMO.exists():
        print(f"[seed] no {DEMO} directory; generate demo captures from the lab first")
        return

    for session_id in DEMO_SETS:
        src = DEMO / session_id
        if not src.exists():
            print(f"[seed] missing {src}; skipping")
            continue
        dst = SESSIONS / session_id
        dst.mkdir(parents=True, exist_ok=True)
        for item in src.glob("*.pcapng"):
            shutil.copy(item, dst / item.name)
        manifest = src / "manifest.json"
        if manifest.exists():
            shutil.copy(manifest, dst / "manifest.json")
        report = src / "report.json"
        if report.exists():
            out = REPORTS / f"demo-{session_id}"
            out.mkdir(parents=True, exist_ok=True)
            shutil.copy(report, out / "report.json")
        print(f"[seed] seeded {session_id}")

    print("[seed] done; open http://localhost:3000 (make demo also starts the stack)")
