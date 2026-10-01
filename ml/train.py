"""Train and calibrate six IPsec heads with profile-disjoint folds."""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import StratifiedGroupKFold

from analyzer.infer.calibration import expected_calibration_error
from analyzer.infer.features import SA_FEATURES, TRAFFIC_FEATURES

DATASET = Path("dataset/features")
MODELS = Path("models")
VERSION = "v0.2.0"
MIN_F1 = {"mode": 0.90, "cipher": 0.95, "integ": 0.95,
          "pfs": 0.90, "dh_group": 0.80, "traffic": 0.80}
TARGETS = {"mode": ("mode", SA_FEATURES), "cipher": ("cipher", SA_FEATURES),
           "integ": ("integ", SA_FEATURES), "pfs": ("pfs", SA_FEATURES),
           "dh_group": ("dh_group", SA_FEATURES), "traffic": ("traffic", TRAFFIC_FEATURES)}


def _split(data: pd.DataFrame, target: str):
    if data["profile"].nunique() < 5:
        raise ValueError("need at least five distinct profiles for disjoint folds")
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=43)
    folds = [held for _, held in cv.split(data, data[target], groups=data["profile"])]
    train_idx = np.concatenate(folds[3:])
    return (data.iloc[train_idx], data.iloc[folds[2]],
            data.iloc[folds[1]], data.iloc[folds[0]])


def _ece(y, proba, classes) -> float:
    indices = np.array([list(classes).index(value) for value in y])
    return expected_calibration_error(indices, proba)


def train_task(task: str, data: pd.DataFrame) -> dict:
    target, columns = TARGETS[task]
    data = data.dropna(subset=[target]).copy()
    if task in ("pfs", "dh_group"):
        data = data[data["rekey_count"] > 0]
    if len(data) < 100 or data[target].nunique() < 2:
        raise ValueError(f"{task}: need >=100 rows and >=2 classes; got {len(data)} rows")
    train, cal, conformal, test = _split(data, target)
    if min(train[target].nunique(), cal[target].nunique(),
           conformal[target].nunique(), test[target].nunique()) < 2:
        raise ValueError(f"{task}: each disjoint split must contain >=2 classes")
    base = lgb.LGBMClassifier(n_estimators=200, learning_rate=0.05,
                              num_leaves=15, random_state=43, verbosity=-1)
    base.fit(train[columns], train[target])
    calibrated = CalibratedClassifierCV(FrozenEstimator(base), method="isotonic")
    calibrated.fit(cal[columns], cal[target])
    proba = calibrated.predict_proba(test[columns])
    predictions = calibrated.classes_[proba.argmax(axis=1)]
    # Conformal quantile uses a fourth, disjoint profile fold.
    cal_proba = calibrated.predict_proba(conformal[columns])
    class_index = {value: i for i, value in enumerate(calibrated.classes_)}
    scores = np.array([1 - cal_proba[i, class_index[value]]
                       for i, value in enumerate(conformal[target])])
    q = float(np.quantile(scores, min(1, np.ceil((len(scores) + 1) * 0.9) / len(scores)),
                          method="higher"))
    metrics = {"accuracy": round(accuracy_score(test[target], predictions), 4),
               "macro_f1": round(f1_score(test[target], predictions, average="macro"), 4),
               "ece": round(_ece(test[target], proba, calibrated.classes_), 4),
               "train_rows": len(train), "cal_rows": len(cal), "conformal_rows": len(conformal),
               "test_rows": len(test),
               "train_profiles": sorted(map(str, train["profile"].unique())),
               "cal_profiles": sorted(map(str, cal["profile"].unique())),
               "conformal_profiles": sorted(map(str, conformal["profile"].unique())),
               "test_profiles": sorted(map(str, test["profile"].unique()))}
    test_indices = np.array([class_index[value] for value in test[target]])
    metrics["conformal_coverage"] = round(float(np.mean(
        proba[np.arange(len(test)), test_indices] >= 1 - q)), 4)
    metrics["promoted"] = (metrics["macro_f1"] >= MIN_F1[task]
                           and metrics["ece"] <= 0.08
                           and metrics["conformal_coverage"] >= 0.85)
    if not metrics["promoted"]:
        return metrics
    vdir = MODELS / task / VERSION
    vdir.mkdir(parents=True, exist_ok=True)
    calibrated._cs_version = VERSION
    joblib.dump(calibrated, vdir / "model.joblib")
    (vdir / "features.json").write_text(json.dumps(columns))
    (vdir / "conformal.json").write_text(json.dumps({"q": q, "alpha": 0.1}))
    (vdir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    return metrics


def main() -> None:
    tables = {"sa": pd.read_parquet(DATASET / "sa_evidence.parquet"),
              "traffic": pd.read_parquet(DATASET / "flow_windows.parquet")}
    registry = json.loads((MODELS / "registry.json").read_text())
    report = {}
    for task in TARGETS:
        try:
            report[task] = train_task(task, tables["traffic" if task == "traffic" else "sa"])
            if report[task]["promoted"]:
                registry[task] = VERSION
        except ValueError as exc:
            report[task] = {"status": "not_trained", "reason": str(exc)}
    (MODELS / "registry.json").write_text(json.dumps(registry, indent=2))
    (Path("ml/reports") / "training.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
