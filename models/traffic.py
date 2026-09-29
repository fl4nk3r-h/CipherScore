"""`traffic_class` head — traffic type inside ESP (LLD §6.1).

LightGBM multi-class over the §5.5 aggregate features (size/IAT moments,
burst counts, up/down byte ratio, packets per second, FFT periodicity peak),
with the seven classes from mvp.md §1.1. Split-conformal sets come from the
`conformal.json` q-hat written at train time (α = 0.1, §3.4 step 4).
"""
from __future__ import annotations

from typing import ClassVar

from .base import HeadModel


class TrafficModel(HeadModel):
    attribute = "traffic_class"
    task = "traffic"
    classes: ClassVar[list] = ["icmp", "web", "email", "voip", "video", "messaging", "bulk"]


# LLD §6.1 names this head `traffic_class`.
TrafficClassModel = TrafficModel
