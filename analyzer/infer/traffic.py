"""Traffic type inside ESP (mvp.md §3.4 table).

Method: LightGBM multi-class on `FlowWindow`, aggregated per SA with majority
vote and mean probability. Confidence: isotonic-calibrated probability +
split-conformal prediction set (α = 0.1).

MVP acceptance (§3.4): macro-F1 ≥ 0.80 per SA, ≥ 0.70 per 5 s window,
ECE ≤ 0.08. Classes (§1.1): icmp, web, email, voip, video, messaging, bulk.
"""
from __future__ import annotations

from collections import Counter

from analyzer.models import TrafficPrediction

CLASSES = ["icmp", "web", "email", "voip", "video", "messaging", "bulk"]


def predict_window(features: dict[str, float], model=None,
                   calibrator=None) -> tuple[str | None, float | None]:
    """Predict one window. Falls back to None/unknown without a trained model."""
    if model is None:
        return None, None
    proba = model.predict_proba([list(features.values())])[0]
    idx = int(proba.argmax())
    p = float(proba[idx])
    if calibrator is not None:
        p = float(calibrator.predict([p])[0])
    return CLASSES[idx], p


def aggregate_sa(window_preds: list[tuple[str | None, float | None]],
                 conformal_q: dict[str, float] | None = None) -> TrafficPrediction | None:
    """Majority vote + mean probability per SA, with a conformal set."""
    valid = [(c, p) for c, p in window_preds if c is not None and p is not None]
    if not valid:
        return None
    counts = Counter(c for c, _ in valid)
    top, _ = counts.most_common(1)[0]
    mean_p = sum(p for c, p in valid if c == top) / max(1, sum(1 for c, _ in valid if c == top))

    conformal_set = [top]
    if conformal_q:
        # Split-conformal: include classes whose mean proba clears (1 - q) margin.
        for cls in CLASSES:
            if cls == top:
                continue
            vals = [p for c, p in valid if c == cls]
            if vals and (sum(vals) / len(vals)) >= 1.0 - conformal_q.get("q", 0.1):
                conformal_set.append(cls)
    return TrafficPrediction(top=top, p=round(mean_p, 4), conformal_set=conformal_set)
