"""PFS on/off (mvp.md §3.4 table).

Method: rule on CREATE_CHILD_SA size + LightGBM.
Confidence: calibrated probability; **"unknown" if no rekey was captured**.

The CHILD_SA proposal travels inside encrypted IKE_AUTH, so the ESP parameters
are inferred from packet structure; the presence of a KE payload inside
CREATE_CHILD_SA makes it noticeably larger -> PFS on (§3.3).
"""
from __future__ import annotations

from analyzer.models import TaggedValue
from analyzer.parse import ike_constants as C
from analyzer.parse.ike import IKESession

# Typical IKE_AUTH / CREATE_CHILD_SA message sizes; a KE payload adds the DH
# public value (e.g. +256 B for MODP-2048, +64 B for ECP-256) plus overhead.
KE_SIZES = C.KE_SIZE_BY_DH


def create_child_sa_ke_present(sessions: list[IKESession]) -> bool | None:
    """True/False when a CREATE_CHILD_SA with/without KE was observed;
    None when no rekey was captured (PFS unknown, §3.4 & §13)."""
    ccs = [s for s in sessions if 36 in s.exchanges]
    if not ccs:
        return None
    for s in ccs:
        if s.ke_size and s.ke_size >= min(KE_SIZES.values()):
            return True
    return False


def infer_pfs(sessions: list[IKESession], model=None,
              features: dict[str, float] | None = None) -> TaggedValue:
    ke = create_child_sa_ke_present(sessions)
    if ke is None:
        # mvp.md §13: the report says "unknown: capture longer than the rekey interval".
        return TaggedValue(value=None, tag="unknown", confidence=0.0)

    p_pfs = 0.92 if ke else 0.08          # deterministic size rule with margin
    if model is not None and features is not None:
        p_model = float(model.predict_proba([list(features.values())])[0][1])
        p_pfs = 0.5 * p_pfs + 0.5 * p_model
    return TaggedValue(value=bool(ke), tag="inferred", confidence=round(p_pfs, 4))
