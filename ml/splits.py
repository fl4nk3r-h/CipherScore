"""Write four profile-disjoint train, probability, conformal, and test splits."""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from sklearn.model_selection import GroupKFold


def make_splits(features_parquet: Path, out_dir: Path, n_splits: int = 5) -> None:
    frame = pd.read_parquet(features_parquet)
    if frame["profile"].nunique() < n_splits or n_splits < 5:
        raise ValueError("need at least five distinct profiles and folds")
    folds = [held for _, held in GroupKFold(n_splits=n_splits).split(
        frame, groups=frame["profile"])]
    parts = {"test": folds[0], "conformal": folds[1], "calib": folds[2],
             "train": [index for fold in folds[3:] for index in fold]}
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, indices in parts.items():
        sessions = sorted(map(str, frame.iloc[indices]["session_id"].unique()))
        (out_dir / f"{name}.txt").write_text("\n".join(sessions) + "\n")
    print("[splits] " + " ".join(f"{name}={len(indices)} rows"
                                 for name, indices in parts.items()))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", type=Path, default=Path("dataset/features/sa_evidence.parquet"))
    ap.add_argument("--out", type=Path, default=Path("dataset/splits"))
    args = ap.parse_args()
    make_splits(args.features, args.out)
