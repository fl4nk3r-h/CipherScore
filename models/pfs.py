"""`pfs` head — Perfect Forward Secrecy on/off (LLD §6.1).

LightGBM plus the §5.3 encrypted-rekey side-channel (`rekey_count`,
`rekey_delta_bytes[]`, `rekey_interval_s[]`, `pfs_candidate_group`,
`pfs_match_error`). The MVP labels the target as a boolean, so the classes are
``False``/``True`` and are read back from the estimator's ``classes_``.
"""
from __future__ import annotations

from typing import ClassVar

from .base import HeadModel


class PfsModel(HeadModel):
    attribute = "pfs"
    task = "pfs"
    classes: ClassVar[list] = [False, True]
