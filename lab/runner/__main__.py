"""`python -m lab.runner run --profiles p01,p07` (repo.md §2).

Loads profiles, validates them against lab/profiles/_schema.json, and drives
orchestrate.py through one session per (profile, traffic type) pair.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

from lab.runner import orchestrate, render

PROFILES_DIR = pathlib.Path(__file__).resolve().parent.parent / "profiles"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="lab.runner")
    sub = ap.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="run profiles and capture labeled sessions")
    run_p.add_argument("--profiles", default="all",
                       help="comma-separated profile ids or 'all'")
    run_p.add_argument("--traffic", default="icmp,web",
                       help="comma-separated traffic types")
    run_p.add_argument("--matrix", default=None,
                       help="path to matrix.yaml for full sweeps")
    run_p.add_argument("--out", default="data/sessions",
                       help="session output root (capture side writes here)")

    args = ap.parse_args(argv)
    if args.cmd == "run":
        profile_ids = render.select_profiles(PROFILES_DIR, args.profiles)
        if args.matrix:
            import yaml
            matrix = yaml.safe_load(pathlib.Path(args.matrix).read_text())
            selected = matrix.get("profiles", "all")
            profile_ids = render.select_profiles(PROFILES_DIR, ",".join(selected) if isinstance(selected, list) else selected)
            traffic = matrix.get("traffic", [])
            repetitions = int(matrix.get("defaults", {}).get("repetitions", 1))
        else:
            traffic = args.traffic.split(",")
            repetitions = 1
        orchestrate.run_sessions(profile_ids, traffic, out_root=args.out, repetitions=repetitions)
    return 0


if __name__ == "__main__":
    sys.exit(main())
