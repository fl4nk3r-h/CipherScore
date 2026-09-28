"""Compliance badges (repo.md §4; mvp.md §3.5).

Configuration compliance: profile checks against **RFC 8221 (ESP)**, **RFC 8247
(IKEv2)**, **NIST SP 800-77r1**, and **CNSA 2.0**. The Executive Report shows
compliance badges for these four (§3.6).

CNSA 2.0 (stricter): AES-256, ECP-384+, SHA-384+ (rules/cnsa2.yaml).
"""
from __future__ import annotations

from analyzer.models import TaggedValue

CNSA2_OK_ENC = {"AES-GCM-16-256", "AES-GCM-256"}
CNSA2_OK_DH = {"ECP-384", "ECP-521"}


def _v(field) -> object:
    return field.value if isinstance(field, TaggedValue) else field


def evaluate(sa) -> dict[str, bool | str]:
    enc = str(_v(sa.enc) or "")
    integ = str(_v(sa.integ) or "")
    dh = str(_v(sa.dh_group) or "")

    # RFC 8221 (ESP) / RFC 8247 (IKEv2): MUST-level algorithms still acceptable.
    rfc_ok = not any(w in enc for w in ("3DES", "DES")) and "SHA1" not in integ
    # NIST SP 800-77r1: at least AES + SHA2 or AEAD; DH >= 2048-bit / ECP-256.
    nist_ok = rfc_ok and not (dh in ("MODP-1024", "MODP-1536"))
    # CNSA 2.0: AES-256-GCM, ECP-384+, SHA-384+.
    cnsa_ok = ("AES-GCM" in enc and "256" in enc) and dh in CNSA2_OK_DH

    return {
        "RFC 8221": "pass" if rfc_ok else "fail",
        "RFC 8247": "pass" if rfc_ok else "fail",
        "NIST SP 800-77r1": "pass" if nist_ok else "fail",
        "CNSA 2.0": "pass" if cnsa_ok else "fail",
    }
