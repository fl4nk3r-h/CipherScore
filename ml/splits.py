"""Profile-grouped splits (repo.md §5; mvp.md §3.4 step 2).

"Use a **profile-grouped** split (GroupKFold by `profile`) so the test set
holds configurations the model never seen." Writes train.txt / calib.txt /
test.txt of session_ids, grouped by profile.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from sklearn.model_selection import GroupKFold


def make_splits(features_parquet: Path, out_dir: Path,
                n_splits: int = 5, alpha: float = 0.1) -> None:
    df = pd.read_parquet(features_parquet)
    groups = df["profile"]
    gkf = GroupKFold(n_splits=n_splits)
    train_idx, test_idx = next(gkf.split(df, groups=groups))

    train = df.iloc[train_idx]
    test = df.iloc[test_idx]
    # Carve the calibration fold out of train (held-out for conformal q-hat).
    calib = train.groupby("profile").sample(frac=alpha + 0.1, random_state=0)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "train.txt").write_text("\n".join(train["session_id"].unique()))
    (out_dir / "calib.txt").write_text("\n".join(calib["session_id"].unique()))
    (out_dir / "test.txt").write_text("\n".join(test["session_id"].unique()))
    print(f"[splits] train={train['session_id'].nunique()} "
          f"calib={calib['session_id'].nunique()} test={test['session_id'].nunique()}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", type=Path, default=Path("dataset/features/flow_windows.parquet"))
    ap.add_argument("--out", type=Path, default=Path("dataset/splits"))
    args = ap.parse_args()
    make_splits(args.features, args.out)
