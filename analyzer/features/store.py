"""Parquet writer/reader (repo.md §4): SAEvidence and FlowWindow tables."""
from __future__ import annotations

from pathlib import Path

import pandas as pd


def write_flow_windows(windows: list[dict], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(windows).to_parquet(path, index=False)
    return path


def write_sa_evidence(rows: list[dict], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_parquet(path, index=False)
    return path


def read_table(path: Path) -> pd.DataFrame:
    return pd.read_parquet(path)
