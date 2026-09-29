"""`dh_group` head — Diffie-Hellman group of encrypted rekeys (LLD §6.1).

Nearest-match against the LLD §4.3 KE-length table plus a LightGBM correction,
using the §5.3 rekey side-channel features (`rekey_delta_bytes[]`,
`pfs_candidate_group`, `pfs_match_error`). The MVP reads the IKE_SA group from
the cleartext SA_INIT in `analyzer/parse/ike.py`; this head is the learned
counterpart for CHILD_SA rekeys.
"""
from __future__ import annotations

from typing import ClassVar

from .base import HeadModel


class DhGroupModel(HeadModel):
    attribute = "dh_group"
    task = "dh_group"
    classes: ClassVar[list] = [2, 14, 15, 16, 19, 20, 21, 31, "pq_hybrid"]
