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
        traffic = args.traffic.split(",") if not args.matrix else None
        orchestrate.run_sessions(profile_ids, traffic, out_root=args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
