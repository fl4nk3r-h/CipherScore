"""Pydantic settings from env (repo.md §7); names match docker-compose.yml §11."""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    data_dir: Path = Path("./data")
    models_dir: Path = Path("./models")
    rules_dir: Path = Path("./rules")
    max_upload_mb: int = 500          # §13: 500 MB upload cap in the MVP
    live_enabled: bool = False        # §13: disabled by default
    live_interface: str = "eth0"

    class Config:
        env_prefix = "CS_"
        env_file = ".env"


settings = Settings()
