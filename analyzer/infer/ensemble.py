"""Fuse observable IKE/ESP facts with versioned IPsec model predictions."""
from __future__ import annotations

import uuid
from pathlib import Path

from analyzer import config
from analyzer.features.esp_structure import StructureResult
from analyzer.infer import cipher, mode, rules_based, traffic
from analyzer.infer.features import sa_features, traffic_features
from analyzer.models import SAEvidence, TaggedValue, TrafficPrediction
from analyzer.parse.sa_tracker import SATrack, TrackerResult
from models import Ensemble, InferenceRequest


def _tag(prediction) -> TaggedValue:
    if prediction.value is None:
        return TaggedValue(value=None, tag="unknown", confidence=0.0)
    return TaggedValue(value=prediction.value, tag="inferred",
                       confidence=prediction.confidence)


def infer_sa(track: SATrack, struct: StructureResult, tracker: TrackerResult,
             windows_preds: list[tuple[str | None, float | None]] | None = None,
             models_dir: Path | None = None,
             offsets: dict[str, float] | None = None,
             ike_enc_chosen: str | None = None,
             windows: list[dict] | None = None) -> SAEvidence:
    models_dir = models_dir or config.MODELS_DIR
    offsets = offsets or {}
    features = sa_features(track, struct, offsets, tracker.ike_sessions)
    service = Ensemble(models_dir=models_dir)
    request = InferenceRequest(tunnel_id=uuid.uuid4(), features=features,
                               heads=["mode", "cipher", "integ", "pfs", "dh_group"])
    preds = {p.attribute: p for p in service.predict(request).predictions}
    rekey_seen = features["rekey_count"] > 0

    mode_value = _tag(preds["mode"])
    if mode_value.value is None:
        mode_value = mode.infer_mode(track, offsets, prior=mode.endpoint_heuristic(track, tracker))
    enc_value = _tag(preds["encryption_family"])
    if enc_value.value is None:
        enc_value = cipher.cipher_mode(struct)
    integ_value = _tag(preds["integrity_alg"])
    if integ_value.value is None:
        integ_value = cipher.integrity(struct)

    sa = SAEvidence(
        spi=f"0x{track.spi:08x}", peers=track.peers,
        nat_t=rules_based.nat_t(any(s.nat_detection_seen for s in tracker.ike_sessions),
                                track.udp_encapsulated),
        mode=mode_value, enc=enc_value, integ=integ_value,
        key_size=cipher.key_size(ike_enc_chosen),
        pfs=_tag(preds["pfs"]) if rekey_seen else TaggedValue(
            value=None, tag="unknown", confidence=0.0),
        dh_group=_tag(preds["dh_group"]) if rekey_seen else TaggedValue(
            value=None, tag="unknown", confidence=0.0),
    )

    if windows:
        traffic_head = service.heads["traffic"]
        window_results = [traffic_head.predict(traffic_features(w)).predictions[0]
                          for w in windows]
        valid = [p for p in window_results if p.value is not None]
        if valid:
            votes = [(str(p.value), p.confidence) for p in valid]
            aggregated = traffic.aggregate_sa(votes)
            if aggregated:
                prediction_set = sorted({label for p in valid for label in p.prediction_set})
                sa.traffic = TrafficPrediction(top=aggregated.top, p=aggregated.p,
                                               conformal_set=prediction_set)
    elif windows_preds:
        sa.traffic = traffic.aggregate_sa(windows_preds)
    return sa
