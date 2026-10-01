"""Import labeled domain lists into the DGA training contract.

CSV columns: domain,label,scenario_id. Keep malware-family and benign collection
batches in separate scenario IDs so splits cannot leak repeated domain patterns.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from analyzer.threats import dns_name_features


def import_csv(source: Path, out: Path) -> int:
    rows = pd.read_csv(source, usecols=["domain", "label", "scenario_id"])
    if not rows["label"].isin([0, 1]).all():
        raise ValueError("label must be 0 or 1")
    seen = rows.groupby("domain")["label"].nunique()
    if (seen > 1).any():
        raise ValueError("conflicting labels for the same domain")
    rows = rows.drop_duplicates("domain")
    features = pd.DataFrame([dns_name_features(name) for name in rows["domain"].astype(str)])
    result = pd.concat([rows[["label", "scenario_id"]].reset_index(drop=True), features], axis=1)
    out.parent.mkdir(parents=True, exist_ok=True)
    result.to_parquet(out, index=False)
    return len(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--out", type=Path, default=Path("dataset/threats/dga.parquet"))
    args = parser.parse_args()
    print(import_csv(args.source, args.out))
