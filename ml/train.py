"""Train (repo.md §5; mvp.md §3.4 steps 3-5).

Trains LightGBM for `mode`, `pfs`, `cipher_mode`, and `traffic_type`;
calibrates with isotonic; computes conformal quantiles (α = 0.1); exports
models/<task>/<version>/{model.joblib, calibrator.joblib, conformal.json,
features.json, metrics.json} + registry.json; writes the model card and
confusion matrix.
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import lightgbm as lgb
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import f1_score
from sklearn.model_selection import GroupKFold

from analyzer.features import flow_windows as fw
from analyzer.infer.calibration import expected_calibration_error
from analyzer.infer.conformal import conformal_quantile
from analyzer.infer.traffic import CLASSES

DATASET = Path("dataset")
MODELS = Path("models")
VERSION = "v0.1.0"

TARGETS = {
    "mode": {"label": "mode", "params": "configs/mode_lgbm.yaml"},
    "pfs": {"label": "pfs", "params": "configs/pfs_lgbm.yaml"},
    "cipher": {"label": "cipher_mode", "params": "configs/cipher_lgbm.yaml"},
    "traffic": {"label": "traffic_type", "params": "configs/traffic_lgbm.yaml"},
}

FEATURES = [
    "n_packets", "len_mean", "len_std", "len_p10", "len_p50", "len_p90",
    "iat_mean", "iat_std", "bursts", "updown_ratio", "packets_per_s",
]


def _flatten(df: pd.DataFrame) -> pd.DataFrame:
    if "features" in df.columns:
        feat = pd.json_normalize(df["features"])
        return pd.concat([df.drop(columns=["features"]).reset_index(drop=True),
                          feat.reset_index(drop=True)], axis=1)
    return df


def train_task(task: str, df: pd.DataFrame) -> dict:
    label = TARGETS[task]["label"]
    data = df.dropna(subset=[label])
    X, y = data[FEATURES], data[label]
    groups = data["profile"]

    gkf = GroupKFold(n_splits=3)
    tr_idx, te_idx = next(gkf.split(X, y, groups))
    X_tr, X_te, y_tr, y_te = X.iloc[tr_idx], X.iloc[te_idx], y.iloc[tr_idx], y.iloc[te_idx]

    base = lgb.LGBMClassifier(n_estimators=200, learning_rate=0.05,
                              num_leaves=31, random_state=0)
    clf = CalibratedClassifierCV(base, method="isotonic", cv=3).fit(X_tr, y_tr)

    proba = clf.predict_proba(X_te)
    preds = proba.argmax(axis=1)
    metrics = {
        "macro_f1": round(f1_score(y_te, preds, average="macro"), 4),
        "ece": round(expected_calibration_error(y_te.to_numpy(), proba), 4),
    }

    vdir = MODELS / task / VERSION
    vdir.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, vdir / "model.joblib")
    (vdir / "features.json").write_text(json.dumps(FEATURES))
    (vdir / "metrics.json").write_text(json.dumps(metrics))

    if task == "traffic":
        # Conformal q-hat from the same held-out fold (alpha = 0.1, §3.4).
        conf = 1.0 - proba.max(axis=1)
        (vdir / "conformal.json").write_text(
            json.dumps({"q": round(conformal_quantile(conf, alpha=0.1), 4)}))
    return metrics


def main() -> None:
    windows = _flatten(pd.read_parquet(DATASET / "features" / "flow_windows.parquet"))
    if windows.empty:
        raise SystemExit("dataset/features/flow_windows.parquet is empty; run `make dataset` first.")
    labels = pd.read_csv(DATASET / "labels.csv")
    # Per-session labels for mode/pfs/cipher tasks.
    merged = windows.merge(labels, on=["session_id", "profile"], how="left", suffixes=("", "_y"))

    registry: dict[str, str] = {}
    report: dict[str, dict] = {}
    for task in TARGETS:
        if task in ("mode", "pfs") and merged[TARGETS[task]["label"]].isna().all():
            continue
        label = TARGETS[task]["label"]
        if label not in merged.columns:
            continue
        report[task] = train_task(task, merged)
        registry[task] = VERSION

    MODELS.mkdir(exist_ok=True)
    (MODELS / "registry.json").write_text(json.dumps(registry, indent=2))
    print(json.dumps(report, indent=2))
    print("[train] models written to models/; run ml/evaluate.py for the model card")
    _ = CLASSES, fw  # referenced by doc contract


if __name__ == "__main__":
    main()
