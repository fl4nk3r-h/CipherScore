"""Metadata exposure (repo.md §4; mvp.md §3.5 "Metadata exposure" category).

- Transport mode exposes real endpoints.
- IKEv1 Aggressive Mode identity leak.
- No TFC padding, so packet sizes reveal the application: **the confidence of
  the M4 traffic classifier IS the exposure measure.**
"""
from __future__ import annotations

from analyzer.models import SAEvidence, TaggedValue


def assess(sa: SAEvidence) -> dict:
    exposure: dict[str, object] = {}

    def val(field) -> object:
        v = getattr(sa, field, None)
        return v.value if isinstance(v, TaggedValue) else None

    if val("mode") == "transport":
        exposure["endpoints"] = {
            "leak": "real endpoints visible (transport mode)",
            "peers": sa.peers,
        }
    if val("ike_version") == 1:
        exposure["ikev1_aggressive"] = "possible identity in cleartext (Aggressive Mode)"
    if sa.traffic:
        exposure["traffic_fingerprint"] = {
            "note": "no TFC padding: packet sizes reveal the application",
            "class": sa.traffic.top,
            "confidence_is_exposure": sa.traffic.p,
            "conformal_set": sa.traffic.conformal_set,
        }
    return exposure
