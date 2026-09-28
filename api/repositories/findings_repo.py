"""Findings repository (repo.md §7)."""
from __future__ import annotations

import json

from api import db


def by_rule(rule_id: str) -> list[dict]:
    conn = db.connect()
    try:
        return [dict(r) | {"evidence": json.loads(r["evidence"])} for r in conn.execute(
            "SELECT * FROM finding WHERE rule_id = ?", (rule_id,))]
    finally:
        conn.close()


def by_analysis_severity(analysis_id: str, severity: str) -> list[dict]:
    conn = db.connect()
    try:
        return [dict(r) | {"evidence": json.loads(r["evidence"])} for r in conn.execute(
            "SELECT * FROM finding WHERE analysis_id = ? AND severity = ?",
            (analysis_id, severity))]
    finally:
        conn.close()
