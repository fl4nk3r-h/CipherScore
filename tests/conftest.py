"""Shared fixtures (repo.md §9 tests/)."""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
RULES_DIR = ROOT / "rules"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def rules_dir() -> Path:
    return RULES_DIR


@pytest.fixture
def pcaps_dir() -> Path:
    return FIXTURES / "pcaps"


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"
