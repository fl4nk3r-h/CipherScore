"""CLI (repo.md §4): `cipherscope analyze capture.pcapng --out report/`.

Same pipeline as the API uses; useful for `make analyze PCAP=path`.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from analyzer import pipeline


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cipherscope")
    sub = ap.add_subparsers(dest="cmd", required=True)
    an = sub.add_parser("analyze", help="analyze a pcap/pcapng offline")
    an.add_argument("pcap", type=pathlib.Path)
    an.add_argument("--out", type=pathlib.Path, default=pathlib.Path("data/reports"))
    an.add_argument("--rule-pack", default="ipsec-baseline")
    args = ap.parse_args(argv)

    result = pipeline.run_analysis(args.pcap, rule_pack=args.rule_pack)

    out_dir = args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(
        json.dumps(result.model_dump(mode="json"), indent=2, default=str))
    print(f"analysis {result.analysis_id}: status={result.status} "
          f"score={result.posture.security_score if result.posture else '?'} "
          f"risk={result.posture.risk_score if result.posture else '?'}")
    print(f"reports in {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
