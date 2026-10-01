"""Feature vectors shared by IPsec training and runtime inference."""
from __future__ import annotations

from analyzer.features.esp_structure import StructureResult
from analyzer.parse.ike import IKESession
from analyzer.parse.sa_tracker import SATrack

SA_FEATURES = ["packet_count", "min_len", "p10_len", "p50_len", "p90_len",
               "mean_len", "std_len", "cbc_consistency", "icv_len",
               "natt", "ip_v6", "rekey_count", "rekey_len_min", "rekey_len_mean"]
TRAFFIC_FEATURES = ["n_packets", "len_mean", "len_std", "len_p10", "len_p50",
                    "len_p90", "iat_mean", "iat_std", "bursts", "updown_ratio",
                    "packets_per_s"]


def sa_features(track: SATrack, struct: StructureResult, offsets: dict[str, float],
                sessions: list[IKESession]) -> dict[str, float]:
    lengths = [size for sess in sessions for size in sess.rekey_lengths]
    values = {name: float(offsets.get(name, 0.0)) for name in SA_FEATURES}
    values.update(packet_count=float(track.packet_count),
                  cbc_consistency=float(struct.consistency),
                  icv_len=float(struct.icv_len or 0),
                  natt=float(track.udp_encapsulated),
                  ip_v6=float(any(":" in peer for peer in track.peers)),
                  rekey_count=float(len(lengths)),
                  rekey_len_min=float(min(lengths)) if lengths else 0.0,
                  rekey_len_mean=float(sum(lengths) / len(lengths)) if lengths else 0.0)
    return values


def traffic_features(window: dict) -> dict[str, float]:
    raw = window.get("features", window)
    out = {name: float(raw.get(name, 0.0)) for name in TRAFFIC_FEATURES}
    if not __import__("math").isfinite(out["updown_ratio"]):
        out["updown_ratio"] = 1000.0
    return out
