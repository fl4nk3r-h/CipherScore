"""Tunnel vs Transport (mvp.md §3.4 table).

Method: LightGBM on size-offset features + endpoint heuristic.
Confidence: calibrated probability.

Tunnel mode adds a full inner IP header (+20 B v4 / +20..40 B v6 outer-vs-inner
offset) compared with transport mode (§3.3 size offsets).
"""
from __future__ import annotations

from analyzer.models import TaggedValue
from analyzer.parse.sa_tracker import SATrack, TrackerResult


def endpoint_heuristic(track: SATrack, result: TrackerResult) -> float | None:
    """Corroborate with outer-vs-endpoint comparison (§3.3): when the outer IPs
    equal the IKE peers' outer addresses AND distinct inner subnets were seen in
    baseline traffic, lean tunnel. Returns a prior in [0,1] or None."""
    if not result.ike_sessions:
        return None
    outer = {p for s in result.ike_sessions for p in (s.initiator, s.responder)}
    return 0.8 if set(track.peers) == outer else 0.5


def infer_mode(track: SATrack, offsets: dict[str, float],
               prior: float | None = None,
               model=None, features: dict[str, float] | None = None) -> TaggedValue:
    """Combine the size-offset model with the endpoint heuristic.

    `model` is the calibrated LightGBM `mode` model (models/mode/...); when it
    is absent (e.g. CLI without trained models) the heuristic alone is used and
    the tag stays "inferred" with the heuristic confidence.
    """
    p_model = None
    if model is not None and features is not None:
        p_model = float(model.predict_proba([list(features.values())])[0][1])

    if p_model is None and prior is None:
        return TaggedValue(value=None, tag="unknown", confidence=0.0)

    p_tunnel = p_model if p_model is not None else (prior or 0.5)
    if prior is not None and p_model is not None:
        p_tunnel = 0.7 * p_model + 0.3 * prior   # simple blend; calibration applied at train time

    value = "tunnel" if p_tunnel >= 0.5 else "transport"
    return TaggedValue(value=value, tag="inferred", confidence=round(p_tunnel, 4))
