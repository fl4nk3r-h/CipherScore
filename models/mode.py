"""`mode` head — Tunnel vs Transport (LLD §6.1).

LightGBM (binary) over the §5.4 features: `outer_eq_inner_hint`,
`min_esp_payload_len`, `distinct_peer_ratio`, `ttl_outer`,
`ike_notify_use_transport`, `spi_count_per_pair`. Confidence is the calibrated
probability turned into a conformal set by :class:`models.base.HeadModel`.
"""
from __future__ import annotations

from typing import ClassVar

from .base import HeadModel


class ModeModel(HeadModel):
    attribute = "mode"
    task = "mode"
    classes: ClassVar[list] = ["transport", "tunnel"]
