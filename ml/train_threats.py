"""Calibrated binary threat models with scenario-disjoint test gates."""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold

from analyzer.infer.calibration import expected_calibration_error

DATA = Path("dataset/threats")
MODELS = Path("models")
VERSION = "v0.1.0"
FEATURES = {
    "beaconing": ["interval_mean", "interval_cv", "observations"],
    "dga": ["label_len", "entropy", "bigram_diversity",
            "digit_ratio", "name_len"],
    "dns_tunneling": ["name_len", "entropy", "queries_30s", "qtype"],
    "encrypted_malware": ["interval_mean", "interval_cv", "observations",
                          "tls", "quic", "tls_version", "quic_version",
                          "handshake_len", "cipher_count",
                          "sni_length", "extension_count"],
}


def train_task(task: str, frame: pd.DataFrame) -> dict:
    columns = FEATURES[task]
    data = frame.dropna(subset=columns + ["label", "scenario_id"])
    if len(data) < 200 or data["scenario_id"].nunique() < 5:
        raise ValueError("need >=200 labeled rows from >=5 scenarios")
    data = data.copy()
    data["label"] = data["label"].astype(int)
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=52)
    folds = [test for _, test in cv.split(data, data["label"], data["scenario_id"])]
    train = data.iloc[np.concatenate(folds[3:])]
    cal, conf, test = (data.iloc[folds[i]] for i in (2, 1, 0))
    if any(part["label"].nunique() < 2 for part in (train, cal, conf, test)):
        raise ValueError("all scenario-disjoint splits must contain both labels")
    base = lgb.LGBMClassifier(n_estimators=200, learning_rate=0.05, num_leaves=15,
                              random_state=52, verbosity=-1)
    base.fit(train[columns], train["label"])
    model = CalibratedClassifierCV(FrozenEstimator(base), method="isotonic")
    model.fit(cal[columns], cal["label"])
    proba = model.predict_proba(test[columns])[:, list(model.classes_).index(1)]
    predicted = proba >= 0.75
    metrics = {"precision": float(precision_score(test["label"], predicted, zero_division=0)),
               "recall": float(recall_score(test["label"], predicted, zero_division=0)),
               "f1": float(f1_score(test["label"], predicted, zero_division=0)),
               "pr_auc": float(average_precision_score(test["label"], proba)),
               "ece": float(expected_calibration_error(test["label"].to_numpy(),
                                                       model.predict_proba(test[columns]))),
               "test_scenarios": sorted(map(str, test["scenario_id"].unique())),
               "rows": len(data)}
    # A model that fails the held-out gate is recorded but never served.
    metrics["promoted"] = (metrics["f1"] >= 0.7 and metrics["pr_auc"] >= 0.75
                           and metrics["ece"] <= 0.1)
    if metrics["promoted"]:
        model._cs_version = VERSION
        target = MODELS / task / VERSION
        target.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, target / "model.joblib")
        (target / "features.json").write_text(json.dumps(columns))
        scores = 1 - model.predict_proba(conf[columns])[np.arange(len(conf)),
                                                        conf["label"].to_numpy()]
        q = float(np.quantile(scores, min(1, np.ceil((len(scores) + 1) * 0.9) / len(scores)),
                              method="higher"))
        (target / "conformal.json").write_text(json.dumps({"q": q, "alpha": 0.1}))
        (target / "metrics.json").write_text(json.dumps(metrics, indent=2))
    return metrics


def main() -> None:
    registry_path = MODELS / "registry.json"
    registry = json.loads(registry_path.read_text()) if registry_path.exists() else {}
    results = {}
    for task in FEATURES:
        path = DATA / f"{task}.parquet"
        try:
            if not path.exists():
                raise ValueError("dataset missing")
            results[task] = train_task(task, pd.read_parquet(path))
            if results[task]["promoted"]:
                registry[task] = VERSION
        except ValueError as exc:
            results[task] = {"status": "not_trained", "reason": str(exc)}
    MODELS.mkdir(exist_ok=True)
    registry_path.write_text(json.dumps(registry, indent=2))
    Path("ml/reports/threat_training.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
