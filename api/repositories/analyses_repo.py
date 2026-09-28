"""Analyses repository (repo.md §7): reads the analyzer's outputs for the API.

All SQL parameterized. Summary shape matches the mvp.md §5 sample response.
"""
from __future__ import annotations

import json
import uuid

from analyzer import config
from api import db


def create(analysis_id: str, capture_id: str, rule_pack: str) -> None:
    conn = db.connect()
    try:
        conn.execute(
            "INSERT INTO analysis (id, capture_id, status) VALUES (?, ?, 'queued')",
            (analysis_id, capture_id))
        conn.commit()
    finally:
        conn.close()


def _report_dir(analysis_id: str):
    return config.REPORTS_DIR / analysis_id


def refresh_summary(analysis_id: str) -> None:
    """Pull the completed AnalysisResult (report.json) into the analysis row."""
    path = _report_dir(analysis_id) / "report.json"
    if not path.exists():
        return
    context = json.loads(path.read_text())
    conn = db.connect()
    try:
        conn.execute(
            "UPDATE analysis SET status='completed', score=?, risk=?, confidence=? "
            "WHERE id=?",
            (context.get("security_score"), context.get("risk_score"),
             context.get("ai_confidence"), analysis_id))

        for sa in context.get("sas", []):
            sa_id = f"{analysis_id}-{sa['spi']}"
            conn.execute(
                "INSERT OR REPLACE INTO sa (id, analysis_id, spi, peers, params) "
                "VALUES (?, ?, ?, ?, ?)",
                (sa_id, analysis_id, sa["spi"], json.dumps(sa.get("peers", [])),
                 json.dumps(sa)))
        for f in context.get("findings", []):
            conn.execute(
                "INSERT OR REPLACE INTO finding (id, analysis_id, rule_id, severity, "
                "likelihood, confidence, evidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (f"{analysis_id}-{f['rule_id']}-{uuid.uuid4().hex[:4]}", analysis_id,
                 f["rule_id"], f["severity"], f["likelihood"], f["confidence"],
                 json.dumps(f.get("evidence", {}))))
        conn.commit()
    finally:
        conn.close()


def summary(analysis_id: str) -> dict | None:
    conn = db.connect()
    try:
        row = conn.execute("SELECT * FROM analysis WHERE id = ?", (analysis_id,)).fetchone()
        if not row:
            return None
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in conn.execute(
                "SELECT severity, COUNT(*) n FROM finding WHERE analysis_id = ? "
                "GROUP BY severity", (analysis_id,)):
            if f["severity"] in sev:
                sev[f["severity"]] = f["n"]
        top = [f["rule_id"] for f in conn.execute(
            "SELECT rule_id FROM finding WHERE analysis_id = ? AND severity IN "
            "('critical','high') LIMIT 5", (analysis_id,))]
        return {
            "analysis_id": analysis_id,
            "status": row["status"],
            "security_score": row["score"],
            "grade": _grade(row["score"]) if row["score"] is not None else None,
            "risk_score": row["risk"],
            "ai_confidence": row["confidence"],
            "sa_count": conn.execute(
                "SELECT COUNT(*) n FROM sa WHERE analysis_id = ?",
                (analysis_id,)).fetchone()["n"],
            "findings": sev,
            "top_findings": top,
        }
    finally:
        conn.close()


def _grade(score: float) -> str:
    return ("A" if score >= 90 else "B" if score >= 80 else
            "C" if score >= 70 else "D" if score >= 55 else "E")


def sas(analysis_id: str) -> list[dict]:
    conn = db.connect()
    try:
        return [dict(json.loads(r["params"])) for r in conn.execute(
            "SELECT params FROM sa WHERE analysis_id = ?", (analysis_id,))]
    finally:
        conn.close()


def traffic(analysis_id: str) -> list[dict]:
    conn = db.connect()
    try:
        return [dict(r) for r in conn.execute(
            "SELECT fw.pred, fw.p, fw.t0, fw.features FROM flow_window fw "
            "JOIN sa ON sa.id = fw.sa_id WHERE sa.analysis_id = ?", (analysis_id,))]
    finally:
        conn.close()


def findings(analysis_id: str) -> list[dict]:
    conn = db.connect()
    try:
        return [dict(r) | {"evidence": json.loads(r["evidence"])} for r in conn.execute(
            "SELECT * FROM finding WHERE analysis_id = ?", (analysis_id,))]
    finally:
        conn.close()


def threat_matrix(analysis_id: str) -> list[list[dict]]:
    """5 x 5 grid of likelihood bucket x severity (mvp.md §3.5)."""
    sevs = ["info", "low", "medium", "high", "critical"]
    grid = [[{"likelihood_bucket": b, "impact": s, "findings": []}
             for s in sevs] for b in range(1, 6)]
    for f in findings(analysis_id):
        b = min(5, max(1, int(f["likelihood"] * 5) + (1 if f["likelihood"] > 0 else 1)))
        col = sevs.index(f["severity"]) if f["severity"] in sevs else 0
        grid[b - 1][col]["findings"].append({"rule_id": f["rule_id"],
                                             "evidence": f["evidence"]})
    return grid
