"""M4 Classifier Ensemble (LLD §6): run the registered heads and return the
§6.5 serving response.

Each head loads its own calibrated artifact from ``models/<task>/<version>/``;
a head with no registry entry (or no ML stack installed) contributes an
"unknown" prediction instead of guessing, exactly as `analyzer/infer` does.
"""
from __future__ import annotations

import time
from pathlib import Path

from .base import (
    InferenceRequest,
    InferenceResponse,
    default_models_dir,
)
from .cipher import CipherModel
from .mode import ModeModel
from .pfs import PfsModel
from .traffic import TrafficModel

HEADS: dict[str, type] = {
    "mode": ModeModel,
    "pfs": PfsModel,
    "cipher": CipherModel,
    "traffic": TrafficModel,
}


class Ensemble:
    """Serving facade over the M4 heads (LLD §6.5)."""

    def __init__(self, models_dir: str | Path | None = None,
                 heads: list[str] | None = None) -> None:
        self.models_dir = Path(models_dir) if models_dir else default_models_dir()
        names = list(heads) if heads else list(HEADS)
        self.heads = {name: HEADS[name](self.models_dir)
                      for name in names if name in HEADS}

    def predict(self, request: InferenceRequest) -> InferenceResponse:
        start = time.perf_counter()
        predictions = []
        versions: dict[str, str] = {}
        names = request.heads or list(self.heads)
        for name in names:
            head = self.heads.get(name)
            if head is None:
                continue
            response = head.predict(request.features)
            predictions.extend(response.predictions)
            versions.update(response.model_versions)
        latency = (time.perf_counter() - start) * 1000.0
        return InferenceResponse(
            predictions=predictions,
            latency_ms=round(latency, 3),
            model_versions=versions,
        )

    def model_versions(self) -> dict[str, str]:
        return {name: head.model_version for name, head in self.heads.items()}
