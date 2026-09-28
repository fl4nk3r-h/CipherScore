"""ESP structural inference (mvp.md §3.3, Step 3).

`esp_len mod 16` after subtracting the header, a candidate IV, and a candidate
ICV. Hypotheses: {CBC: IV 16, block 16} and {GCM: IV 8, pad 4} × ICV
{12, 16, 24, 32}. The winner reveals cipher mode (CBC vs GCM) and ICV length,
which gives the integrity algorithm.
"""
from __future__ import annotations

from dataclasses import dataclass

from analyzer import config
from analyzer.parse.esp import ESPRecord


@dataclass
class StructureResult:
    cipher_mode: str | None        # "CBC" | "GCM"
    icv_len: int | None
    consistency: float             # fraction of packets consistent with the winner
    key_size_hint: None = None     # key size is NOT observable from ESP bytes (§3.3)


def _consistent(mode: str, icv_len: int, length: int, natt: bool,
                ip_version: int = 4) -> bool:
    # ESPRecord.length already includes the outer IP header (20 v4 / 40 v6).
    outer = 20 if ip_version == 4 else 40
    body = length - outer
    if natt:
        body -= 8                                            # minus UDP header
    if mode == "CBC":
        # header 8 + IV 16, then ciphertext padded to the 16-byte block, + ICV.
        payload = body - 8 - config.CBC_IV_LEN - icv_len
        return payload > 0 and payload % config.CBC_BLOCK == 0
    # GCM: header 8 + IV 8 + cipher + pad 4 (incl. next header) + ICV; the
    # plaintext (an IP datagram) is 16-byte aligned in tunnel mode (TFC off).
    payload = body - 8 - config.GCM_IV_LEN - config.GCM_PAD - icv_len
    return payload >= 0 and payload % config.CBC_BLOCK == 0


def analyze(sa_packets: list[ESPRecord]) -> StructureResult:
    if not sa_packets:
        return StructureResult(cipher_mode=None, icv_len=None, consistency=0.0)
    natt = any(p.udp_encapsulated for p in sa_packets)
    ip_version = 6 if sa_packets and sa_packets[0].src.count(":") else 4
    # Deterministic selection: highest consistency fraction wins; ties go to CBC
    # (the more constrained hypothesis: strict 16-byte IV + block alignment), then
    # to the smallest consistent ICV (parsimony).
    best: tuple[float, int, str, int] | None = None   # (frac, mode_rank, mode, icv)
    for cand_mode in ("CBC", "GCM"):
        mode_rank = 0 if cand_mode == "CBC" else 1
        for icv in config.CANDIDATE_ICV_LENS:
            hits = sum(1 for p in sa_packets
                       if _consistent(cand_mode, icv, p.length, natt, ip_version))
            frac = hits / len(sa_packets)
            if best is None or (frac, -mode_rank, -icv) > (best[0], -best[1], -best[3]):
                best = (frac, mode_rank, cand_mode, icv)
    assert best is not None
    frac, _rank, mode, icv = best
    return StructureResult(
        cipher_mode=mode,   # winner even below 95%; confidence carries the doubt
        icv_len=icv,
        consistency=frac,
    )


def size_offsets(sa_packets: list[ESPRecord]) -> dict[str, float]:
    """Minimum ESP length and size histogram per SA (mvp.md §3.3).

    Tunnel mode adds a full inner IP header (+20 B v4 / +40 B v6) compared with
    transport mode — this offset feeds the mode classifier.
    """
    if not sa_packets:
        return {}
    lens = sorted(p.length for p in sa_packets)
    mean = sum(lens) / len(lens)
    var = sum((x - mean) ** 2 for x in lens) / len(lens)
    return {
        "min_len": float(lens[0]),
        "p10_len": float(lens[int(0.10 * (len(lens) - 1))]),
        "p50_len": float(lens[len(lens) // 2]),
        "p90_len": float(lens[int(0.90 * (len(lens) - 1))]),
        "mean_len": mean,
        "std_len": var ** 0.5,
    }
