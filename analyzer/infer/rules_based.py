"""Deterministic inferences (mvp.md §3.4 table).

| IPsec present        | Rule: ESP/AH/IKE demux        | 1.0 when observed          |
| IKE version          | Rule: header parse            | 1.0 when IKE observed, else unknown |
| IKE SA enc/integ/DH  | Rule: SA_INIT transform parse | 1.0 when SA_INIT observed  |
"""
from __future__ import annotations

from analyzer.models import TaggedValue
from analyzer.parse.ike import IKESession, summarize_session


def ipsec_present(protocol_buckets: dict[str, int]) -> TaggedValue:
    seen = (protocol_buckets.get("esp", 0) + protocol_buckets.get("ah", 0)
            + protocol_buckets.get("esp_in_udp", 0) + protocol_buckets.get("ike", 0))
    return TaggedValue(value=seen > 0, tag="observed", confidence=1.0) if seen else \
        TaggedValue(value=False, tag="observed", confidence=1.0)


def ike_version(sessions: list[IKESession]) -> TaggedValue:
    if not sessions:
        return TaggedValue(value=None, tag="unknown", confidence=0.0)
    versions = {s.version for s in sessions}
    return TaggedValue(value=versions.pop() if len(versions) == 1 else None,
                       tag="observed", confidence=1.0)


def ike_sa_suite(sessions: list[IKESession]) -> dict[str, TaggedValue]:
    """Parse the SA_INIT transforms. The responder's SA_INIT carries the single
    selected proposal; until it is observed, the offered set is reported."""
    out: dict[str, TaggedValue] = {}
    if not sessions:
        return out
    summary = summarize_session(sessions[0])
    for key in ("enc_chosen", "integ_offered", "dh_offered"):
        val = summary.get(key)
        if key == "enc_chosen" and val:
            out["enc"] = TaggedValue(value=val, tag="observed", confidence=1.0)
        elif key == "integ_offered" and val:
            out["integ"] = TaggedValue(value=val[0] if isinstance(val, list) and val else None,
                                       tag="observed", confidence=1.0)
        elif key == "dh_offered" and val:
            out["dh_group"] = TaggedValue(value=val[0] if isinstance(val, list) and val else None,
                                          tag="observed", confidence=1.0)
    if summary.get("ke_size") is not None:
        out["ke_size"] = TaggedValue(value=summary["ke_size"], tag="observed", confidence=1.0)
    return out


def nat_t(session_nat_hint: bool, udp_esp_seen: bool) -> TaggedValue:
    return TaggedValue(value=session_nat_hint or udp_esp_seen,
                       tag="observed" if (session_nat_hint or udp_esp_seen) else "unknown",
                       confidence=1.0 if (session_nat_hint or udp_esp_seen) else 0.0)


def aggressive_mode(sessions: list[IKESession]) -> TaggedValue:
    """IKEv1 Aggressive Mode exposes the identity in cleartext (§3.3)."""
    val = any(s.aggressive_mode for s in sessions)
    return TaggedValue(value=val, tag="observed" if sessions else "unknown",
                       confidence=1.0 if sessions else 0.0)
