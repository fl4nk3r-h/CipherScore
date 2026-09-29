"""M4 Classifier Ensemble serving package (LLD §1.2, §6).

Public surface:

* domain types — :class:`Prediction`, :class:`FeatureAttribution`
* serving contract — :class:`InferenceRequest`, :class:`InferenceResponse`
* heads — :class:`ModeModel`, :class:`PfsModel`, :class:`CipherModel`,
  :class:`TrafficModel`
* facade — :class:`Ensemble`
"""
from __future__ import annotations

from .base import (
    Attribute,
    FeatureAttribution,
    HeadModel,
    InferenceRequest,
    InferenceResponse,
    Prediction,
    Source,
    conformal_confidence,
    conformal_set,
    default_models_dir,
    load_registry,
    resolve_version,
)
from .cipher import CipherModel, EncFamilyModel
from .ensemble import HEADS, Ensemble
from .mode import ModeModel
from .pfs import PfsModel
from .traffic import TrafficClassModel, TrafficModel

__all__ = [
    "HEADS",
    "Attribute",
    "CipherModel",
    "EncFamilyModel",
    "Ensemble",
    "FeatureAttribution",
    "HeadModel",
    "InferenceRequest",
    "InferenceResponse",
    "ModeModel",
    "PfsModel",
    "Prediction",
    "Source",
    "TrafficClassModel",
    "TrafficModel",
    "conformal_confidence",
    "conformal_set",
    "default_models_dir",
    "load_registry",
    "resolve_version",
]
