"""`enc_family` head — ESP cipher family (LLD §6.1).

LightGBM (multiclass) over the §5.2 length-residue features
(`frac_zero_mod16_icv*`, `frac_zero_mod4_gcm`, `len_gcd`, `min_len`,
`len_entropy`). Backed by the MVP `cipher` artifact (repo.md §6), so the
registry key and artifact folder are both `cipher`.
"""
from __future__ import annotations

from typing import ClassVar

from .base import HeadModel


class CipherModel(HeadModel):
    attribute = "encryption_family"
    task = "cipher"
    classes: ClassVar[list] = ["aes-cbc", "aes-gcm", "other"]


# LLD §6.1 names this head `enc_family`.
EncFamilyModel = CipherModel
