"""Pydantic settings from env (repo.md §7); names match docker-compose.yml §11.

Read live from `os.environ` on every access so test harnesses (and containers)
can override `CS_*` at process runtime, not just import time.
"""
from __future__ import annotations

import os
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


class Settings:
    """Dynamic view over the CS_* environment variables."""

    @property
    def data_dir(self) -> Path:
        return Path(_env("CS_DATA_DIR", "./data"))

    @property
    def models_dir(self) -> Path:
        return Path(_env("CS_MODELS_DIR", "./models"))

    @property
    def rules_dir(self) -> Path:
        return Path(_env("CS_RULES_DIR", "./rules"))

    @property
    def max_upload_mb(self) -> int:
        return int(_env("CS_MAX_UPLOAD_MB", "500"))   # §13: 500 MB upload cap

    @property
    def live_enabled(self) -> bool:
        return _env("CS_LIVE_ENABLED", "false").lower() in ("1", "true", "yes")

    @property
    def live_interface(self) -> str:
        return _env("CS_LIVE_INTERFACE", "eth0")


settings = Settings()
