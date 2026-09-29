"""M4 Classifier Ensemble: shared serving types and head machinery.

Implements the LLD §1.2 `Prediction` / `FeatureAttribution` domain types, the
§6.5 serving contract (`InferenceRequest` / `InferenceResponse`), and a
`HeadModel` base that loads a calibrated artifact from
`models/<task>/<version>/` (repo.md §6) and turns its probabilities into a
split-conformal prediction set with the LLD §6.3 confidence.

ML dependencies are imported lazily. With no artifact (or no `joblib` /
`lightgbm` installed) a head still answers, but with `value=None` and
confidence `0.0` instead of guessing — the same honest fallback used by
`analyzer/infer/loader.py`.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, ClassVar, Literal
from uuid import UUID

from pydantic import BaseModel, Field

Source = Literal["observed", "inferred", "key_assisted", "active_probe"]
Attribute = Literal[
    "ipsec_protocol", "ike_version", "mode", "encryption_family",
    "encryption_key_bits", "integrity_alg", "dh_group", "pfs",
    "sa_lifetime_s", "replay_window", "traffic_class", "nat_t",
]


class FeatureAttribution(BaseModel):
    feature: str
    importance: float


class Prediction(BaseModel):
    attribute: Attribute
    value: str | int | bool | None
    source: Source
    confidence: float                    # 0..1, conformal-derived
    prediction_set: list[str] = Field(default_factory=list)   # conformal set at alpha
    alpha: float = 0.05
    model_version: str | None = None
    explanation: list[FeatureAttribution] = Field(default_factory=list)   # top-k SHAP


class InferenceRequest(BaseModel):
    tunnel_id: UUID
    child_sa_id: UUID | None = None
    features: dict[str, float] = Field(default_factory=dict)          # tabular
    tokens: list[tuple[int, int, int]] | None = None                  # sequence
    heads: list[str] = Field(default_factory=list)                    # which heads to run


class InferenceResponse(BaseModel):
    predictions: list[Prediction] = Field(default_factory=list)
    latency_ms: float = 0.0
    model_versions: dict[str, str] = Field(default_factory=dict)


def default_models_dir() -> Path:
    """Artifact root, overridable with `CS_MODELS_DIR` (repo.md §11)."""
    return Path(os.environ.get("CS_MODELS_DIR", "models"))


def load_registry(models_dir: str | Path) -> dict[str, Any]:
    """Read `models/registry.json`; an absent/corrupt file means no trained models."""
    path = Path(models_dir) / "registry.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def resolve_version(models_dir: str | Path, task: str) -> str | None:
    version = load_registry(models_dir).get(task)
    return str(version) if version else None


def conformal_set(proba: list[float], qhat: float) -> list[int]:
    """APS-style split-conformal set (LLD §6.3): classes in descending
    probability until their cumulative mass reaches ``1 - qhat``."""
    order = sorted(range(len(proba)), key=lambda i: proba[i], reverse=True)
    chosen: list[int] = []
    total = 0.0
    for idx in order:
        chosen.append(idx)
        total += float(proba[idx])
        if total >= 1.0 - float(qhat):
            break
    return chosen


def conformal_confidence(top_p: float, set_size: int) -> float:
    """LLD §6.3: ``p(top)`` when the set is a singleton, else ``p(top) / |C|``."""
    if set_size <= 1:
        return float(top_p)
    return float(top_p) / float(set_size)


class HeadModel:
    """Base for one M4 head (LLD §6.1).

    Subclasses set ``attribute``, ``task`` (the registry key / artifact folder)
    and the default ``classes``. A trained artifact overrides ``classes`` from
    the estimator's own ``classes_`` so label order can never drift.
    """

    attribute: Attribute
    task: str
    classes: ClassVar[list[Any]] = []
    source: Source = "inferred"
    alpha: float = 0.05
    top_k_explanations: int = 10

    def __init__(self, models_dir: str | Path | None = None,
                 version: str | None = None,
                 model_path: str | Path | None = None,
                 model: Any | None = None) -> None:
        self.models_dir = Path(models_dir) if models_dir else default_models_dir()
        self.version = version or resolve_version(self.models_dir, self.task)
        self.model_version = (f"{self.task}-{self.version}" if self.version
                              else f"{self.task}-untrained")
        self.is_initialized = model is not None
        self._model = model
        self._calibrator = None
        self._qhat = 0.1
        self._feature_order: list[str] | None = None
        self._feature_importances: list[float] | None = None
        if model is None:
            self._load(model_path)
        self._resolve_classes()
        if self._feature_importances is None:
            self._feature_importances = self._extract_importances()

    # -- artifact loading -------------------------------------------------
    def _artifact_dir(self, model_path: str | Path | None = None) -> Path | None:
        if model_path:
            path = Path(model_path)
            return path if path.is_dir() else path.parent
        if not self.version:
            return None
        return self.models_dir / self.task / self.version

    def _load(self, model_path: str | Path | None = None) -> None:
        vdir = self._artifact_dir(model_path)
        if vdir is None:
            return
        if model_path and Path(model_path).is_file():
            model_file = Path(model_path)
        else:
            model_file = vdir / "model.joblib"
        if not model_file.exists():
            return
        try:
            import joblib
        except ImportError:
            return
        self._model = joblib.load(model_file)
        self.is_initialized = True

        calibrator_file = vdir / "calibrator.joblib"
        if calibrator_file.exists():
            self._calibrator = joblib.load(calibrator_file)
        conformal_file = vdir / "conformal.json"
        if conformal_file.exists():
            self._qhat = float(json.loads(conformal_file.read_text()).get("q", self._qhat))
        features_file = vdir / "features.json"
        if features_file.exists():
            self._feature_order = [str(name) for name in json.loads(features_file.read_text())]
        self._feature_importances = self._extract_importances()

    def _tree_estimator(self) -> Any:
        """Return the fitted tree estimator behind a calibrated wrapper.

        `ml/train.py` persists the `CalibratedClassifierCV` itself, so the
        underlying LightGBM model lives in `calibrated_classifiers_[i].estimator`
        (a template `.estimator` on the wrapper is unfitted and unusable for
        SHAP / feature importances).
        """
        model = self._model
        wrappers = getattr(model, "calibrated_classifiers_", None)
        if wrappers:
            return getattr(wrappers[0], "estimator", model)
        return getattr(model, "estimator", None) or model

    def _extract_importances(self) -> list[float] | None:
        importances = getattr(self._tree_estimator(), "feature_importances_", None)
        if importances is None:
            return None
        try:
            return [float(value) for value in importances]
        except (TypeError, ValueError):
            return None

    def _resolve_classes(self) -> None:
        classes = getattr(self._model, "classes_", None) if self._model is not None else None
        if classes is not None:
            self.classes = list(classes)

    # -- inference --------------------------------------------------------
    def _vector(self, features: dict[str, float]) -> list[float]:
        if self._feature_order:
            return [float(features.get(name, 0.0)) for name in self._feature_order]
        return [float(value) for value in features.values()]

    def _proba(self, features: dict[str, float]) -> list[float] | None:
        if self._model is None:
            return None
        try:
            proba = self._model.predict_proba([self._vector(features)])[0]
        except (AttributeError, TypeError, ValueError):
            return None
        return [float(p) for p in proba]

    def predict(self, features: dict[str, float]) -> InferenceResponse:
        start = time.perf_counter()
        proba = self._proba(features)
        if not proba:
            prediction = Prediction(
                attribute=self.attribute, value=None, source=self.source,
                confidence=0.0, prediction_set=[], alpha=self.alpha,
                model_version=self.model_version,
            )
        else:
            top = max(range(len(proba)), key=lambda i: proba[i])
            set_idx = conformal_set(proba, self._qhat)
            top_p = self._calibrate(proba[top])
            prediction = Prediction(
                attribute=self.attribute,
                value=self._label(top),
                source=self.source,
                confidence=round(conformal_confidence(top_p, len(set_idx)), 4),
                prediction_set=[str(self._label(i)) for i in set_idx],
                alpha=self.alpha,
                model_version=self.model_version,
                explanation=self._explain(features),
            )
        latency = (time.perf_counter() - start) * 1000.0
        return InferenceResponse(
            predictions=[prediction],
            latency_ms=round(latency, 3),
            model_versions={self.task: self.model_version},
        )

    def _calibrate(self, p: float) -> float:
        """Apply a separately stored binary isotonic calibrator if present."""
        if self._calibrator is None:
            return float(p)
        try:
            return float(self._calibrator.predict([float(p)])[0])
        except (AttributeError, TypeError, ValueError):
            return float(p)

    def _label(self, idx: int) -> Any:
        if idx < len(self.classes):
            value = self.classes[idx]
            if hasattr(value, "item"):       # numpy scalars -> python scalars
                value = value.item()
            if isinstance(value, (bool, int, float, str)):
                return value
            return str(value)
        return str(idx)

    def _explain(self, features: dict[str, float],
                 k: int | None = None) -> list[FeatureAttribution]:
        """Top-k attributions (LLD §6.4).

        TreeSHAP is preferred for the GBDT heads; when ``shap`` is not installed
        (or the estimator is not tree-explainable) we fall back to the model's
        global ``feature_importances_`` so a prediction is never left
        unexplained by accident. Both need ``features.json`` for feature names.
        """
        if not self._feature_order:
            return []
        k = k or self.top_k_explanations
        local = self._shap_explanation(features)
        if local is not None:
            return local[:k]
        if not self._feature_importances:
            return []
        pairs = sorted(zip(self._feature_order, self._feature_importances),
                       key=lambda pair: abs(pair[1]), reverse=True)
        return [FeatureAttribution(feature=name, importance=float(importance))
                for name, importance in pairs[:k]]

    def _shap_explanation(self, features: dict[str, float]) -> list[FeatureAttribution] | None:
        if self._model is None:
            return None
        try:
            import numpy as np
            import shap
        except ImportError:
            return None
        try:
            estimator = self._tree_estimator()
            explainer = shap.TreeExplainer(estimator)
            raw = explainer.shap_values([self._vector(features)])
            if isinstance(raw, list):
                stacked = np.stack([np.asarray(part, dtype=float) for part in raw], axis=-1)
            else:
                stacked = np.asarray(raw, dtype=float)
            flat = np.abs(stacked).reshape(-1, len(self._feature_order)).mean(axis=0)
        except Exception:  # noqa: BLE001 — shap/estimator edge cases -> fall back to importances
            return None
        values = flat.tolist()
        if len(values) != len(self._feature_order):
            return None
        pairs = sorted(zip(self._feature_order, values),
                       key=lambda pair: abs(pair[1]), reverse=True)
        return [FeatureAttribution(feature=name, importance=float(importance))
                for name, importance in pairs]
