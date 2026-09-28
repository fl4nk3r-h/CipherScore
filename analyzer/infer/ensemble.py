"""Ensemble (repo.md §4): merges rules + ML into tagged Inference objects
(mvp.md §3.4). The report tells the analyst which statements are observed,
which are inferred, and which are unknown (§3.4 "Why this is credible")."""
from __future__ import annotations

from pathlib import Path

from analyzer import config
from analyzer.features.esp_structure import StructureResult
from analyzer.infer import cipher, loader, mode, pfs, rules_based, traffic
from analyzer.models import SAEvidence
from analyzer.parse.sa_tracker import SATrack, TrackerResult


def infer_sa(track: SATrack, struct: StructureResult, tracker: TrackerResult,
             windows_preds: list[tuple[str | None, float | None]],
             models_dir: Path | None = None,
             offsets: dict[str, float] | None = None,
             ike_enc_chosen: str | None = None) -> SAEvidence:
    models_dir = models_dir or config.MODELS_DIR
    offsets = offsets or {}

    mode_pack = loader.load_task("mode", str(models_dir))
    pfs_pack = loader.load_task("pfs", str(models_dir))
    cipher_pack = loader.load_task("cipher", str(models_dir))
    traffic_pack = loader.load_task("traffic", str(models_dir))

    prior = mode.endpoint_heuristic(track, tracker)

    sa = SAEvidence(
        spi=f"0x{track.spi:08x}",
        peers=track.peers,
        nat_t=rules_based.nat_t(
            any(s.nat_detection_seen for s in tracker.ike_sessions),
            track.udp_encapsulated),
        mode=mode.infer_mode(
            track, offsets,
            prior=prior,
            model=mode_pack[0] if mode_pack else None,
            features=offsets or None,
        ),
        enc=cipher.cipher_mode(
            struct,
            model=cipher_pack[0] if cipher_pack else None,
            features={"len_mean": offsets.get("mean_len", 0.0)} if cipher_pack else None,
        ),
        integ=cipher.integrity(struct),
        key_size=cipher.key_size(
            ike_enc_chosen,
            model=cipher_pack[0] if cipher_pack else None,
            features={"len_mean": offsets.get("mean_len", 0.0)} if cipher_pack else None,
        ),
        pfs=pfs.infer_pfs(
            tracker.ike_sessions,
            model=pfs_pack[0] if pfs_pack else None,
            features=None,
        ),
    )
    if traffic_pack and windows_preds:
        model, calibrator, _conformal_q, _order = traffic_pack
        preds = [traffic.predict_window({"n_packets": 0}, model, calibrator)
                 for _ in windows_preds]
    else:
        preds = windows_preds
    sa.traffic = traffic.aggregate_sa(
        preds, conformal_q=traffic_pack[2] if traffic_pack else None)
    return sa
