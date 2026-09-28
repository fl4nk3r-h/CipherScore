"""Captures repository (repo.md §7). All SQL parameterized."""
from __future__ import annotations

from api import db


def get(capture_id: str) -> dict | None:
    conn = db.connect()
    try:
        row = conn.execute("SELECT * FROM capture WHERE id = ?", (capture_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def create(capture_id: str, path: str, size: int, sha256: str) -> None:
    conn = db.connect()
    try:
        conn.execute(
            "INSERT INTO capture (id, path, bytes, sha256) VALUES (?, ?, ?, ?)",
            (capture_id, path, size, sha256))
        conn.commit()
    finally:
        conn.close()
