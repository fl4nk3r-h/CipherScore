"""Model loader (repo.md §4): loads models/*.joblib by version.

models/registry.json maps task -> version; each version dir carries model.joblib,
calibrator.joblib, conformal.json (q-hat for α=0.1), features.json (ordered
feature list, guards against drift), and metrics.json (repo.md §6).

With no registry entry (or no ML deps installed) `load_task` returns None and
the ensemble degrades to rules-only inference with honest tags — the fallback
promised by models/README.md and mvp.md §3.4.
"""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)


@lru_cache(maxsize=8)
def load_task(task: str, models_dir_str: str):
    """Returns (model, calibrator, conformal_q, feature_order) or None.

    Never raises for missing models/deps: absence is a normal, honest state
    ("unknown" tags), not an error.
    """
    models_dir = Path(models_dir_str)
    registry_path = models_dir / "registry.json"
    registry = json.loads(registry_path.read_text()) if registry_path.exists() else {}
    version = registry.get(task)
    if not version:
        return None
    vdir = models_dir / task / version
    if not (vdir / "model.joblib").exists():
        return None
    try:
        import joblib  # lazy: ML stack is optional at inference time
    except ImportError:
        logger.warning("task %r registered but joblib unavailable; skipping", task)
        return None

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
