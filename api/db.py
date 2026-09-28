"""SQLite engine + migrations on startup (repo.md §7). Tables per mvp.md §6."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from api.settings import settings

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def connect() -> sqlite3.Connection:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.data_dir / "cipherscope.sqlite3")
    conn.row_factory = sqlite3.Row
    return conn


def migrate() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA_PATH.read_text())
        conn.commit()
    finally:
        conn.close()
