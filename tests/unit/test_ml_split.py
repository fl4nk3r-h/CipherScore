"""Profile splits must preserve independent calibration and evaluation."""

import pandas as pd
import pytest

from ml.train import _split


def test_split_search_finds_class_diverse_disjoint_profiles():
    frame = pd.DataFrame([
        {"profile": f"p{i:02d}", "label": label}
        for i in range(1, 11)
        for label in ("CBC", "GCM")
        for _ in range(3)
    ])
    parts = _split(frame, "label")
    groups = [set(part.profile) for part in parts]
    assert all(set(part.label) == {"CBC", "GCM"} for part in parts)
    assert len(set.union(*groups)) == 10
    assert sum(map(len, groups)) == 10


def test_split_reports_insufficient_profile_diversity():
    frame = pd.DataFrame([
        {"profile": f"p{i:02d}", "label": "GCM" if i == 5 else "CBC"}
        for i in range(1, 6)
    ])
    with pytest.raises(ValueError, match="profiles per class"):
        _split(frame, "label")


def test_split_can_allocate_four_minority_profiles_across_holdouts():
    frame = pd.DataFrame([
        {"profile": f"p{i:02d}", "label": "GCM" if i <= 4 else "CBC"}
        for i in range(1, 10)
        for _ in range(3)
    ])
    parts = _split(frame, "label")
    assert all(set(part.label) == {"CBC", "GCM"} for part in parts)
    groups = [set(part.profile) for part in parts]
    assert sum(map(len, groups)) == 9
    assert len(set.union(*groups)) == 9
