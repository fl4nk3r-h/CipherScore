"""Model loader (repo.md §4): loads models/*.joblib by version.

models/registry.json maps task -> version; each version dir carries model.joblib,
calibrator.joblib, conformal.json (q-hat for α=0.1), features.json (ordered
feature list, guards against drift), and metrics.json (repo.md §6).
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import joblib


def _registry_path(models_dir: Path) -> Path:
    return models_dir / "registry.json"


@lru_cache(maxsize=8)
def load_task(task: str, models_dir_str: str):
    """Returns (model, calibrator, conformal_q, feature_order) or None."""
    models_dir = Path(models_dir_str)
    registry = json.loads(_registry_path(models_dir).read_text()) \
        if _registry_path(models_dir).exists() else {}
    version = registry.get(task)
    if not version:
        return None
    vdir = models_dir / task / version
    model = joblib.load(vdir / "model.joblib")
    calibrator = joblib.load(vdir / "calibrator.joblib") \
        if (vdir / "calibrator.joblib").exists() else None
    conformal = json.loads((vdir / "conformal.json").read_text()) \
        if (vdir / "conformal.json").exists() else None
    features = json.loads((vdir / "features.json").read_text()) \
        if (vdir / "features.json").exists() else None
    return model, calibrator, conformal, features


def feature_order_matches(features: dict, order: list[str] | None) -> bool:
    if order is None:
        return True
    return all(k in features for k in order)
