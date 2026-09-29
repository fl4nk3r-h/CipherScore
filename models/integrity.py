"""`integ` head — ESP integrity / ICV family (LLD §6.1).

LightGBM over the §5.2 length-residue features, conditional on the cipher
family (CBC packets carry an HMAC ICV; AEAD packets do not). Classes follow the
ICV lengths in LLD §5.2 / the mvp.md §3.4 table. The MVP computes this
deterministically in `analyzer/infer/cipher.py`; this head exists so the
full-platform ensemble can add the learned fallback.
"""
from __future__ import annotations

from typing import ClassVar

from .base import HeadModel


class IntegrityModel(HeadModel):
    attribute = "integrity_alg"
    task = "integ"
    classes: ClassVar[list] = ["sha1_96", "sha256_128", "sha384_192", "sha512_256", "none(aead)"]
