"""Isotonic calibration wrappers (mvp.md §3.4 training loop, step 4):
"Calibrate with CalibratedClassifierCV(method='isotonic')" — ECE target ≤ 0.08."""
from __future__ import annotations

import numpy as np
from sklearn.calibration import CalibratedClassifierCV


def calibrate(model, X_cal, y_cal, cv: str = "prefit") -> CalibratedClassifierCV:
    return CalibratedClassifierCV(model, method="isotonic", cv=cv).fit(X_cal, y_cal)


def expected_calibration_error(y_true, probs, n_bins: int = 15) -> float:
    """ECE for the calibration target in §3.4 (ECE ≤ 0.08)."""
    confidences = probs.max(axis=1)
    predictions = probs.argmax(axis=1)
    accuracies = (predictions == np.asarray(y_true)).astype(float)
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for lo, hi in zip(bins, bins[1:]):
        mask = (confidences > lo) & (confidences <= hi)
        if mask.any():
            ece += mask.mean() * abs(accuracies[mask].mean() - confidences[mask].mean())
    return float(ece)
