"""Analyses repository (repo.md §7): reads the analyzer's outputs for the API.

All SQL parameterized. Summary shape matches the mvp.md §5 sample response.
"""
from __future__ import annotations

import json
import uuid

import yaml

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
        return _summary(conn, row)
    finally:
        conn.close()


def list_recent(limit: int = 50) -> list[dict]:
    """Newest-first summaries for the Overview screen (mvp.md §4 screen 1).

    Each item carries `created`, `capture_id`, and structured `top_findings`
    (rule_id, title, severity, count) so the dashboard can render the trend,
    the recent-analyses table, and top findings across captures from one call.
    """
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT * FROM analysis ORDER BY created DESC, id DESC LIMIT ?",
            (limit,)).fetchall()
        titles = _rule_titles() if rows else {}
        out = []
        for row in rows:
            item = _summary(conn, row)
            item["created"] = row["created"]
            item["capture_id"] = row["capture_id"]
            item["top_findings"] = _top_findings(conn, row["id"], titles)
            out.append(item)
        return out
    finally:
        conn.close()


def _summary(conn, row) -> dict:
    analysis_id = row["id"]
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in conn.execute(
            "SELECT severity, COUNT(*) n FROM finding WHERE analysis_id = ? "
            "GROUP BY severity", (analysis_id,)):
        if f["severity"] in sev:
            sev[f["severity"]] = f["n"]
    top = [f'{t["rule_id"]} {t["title"]}' if t["title"] != t["rule_id"]
           else t["rule_id"]
           for t in _top_findings(conn, analysis_id)]
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


def _rule_titles() -> dict[str, str]:
    """rule_id -> title from the plain-YAML rule pack (mvp.md §3.5)."""
    titles: dict[str, str] = {}
    for pack in sorted(config.RULES_DIR.glob("*.yaml")):
        try:
            rules = yaml.safe_load(pack.read_text())
        except yaml.YAMLError:
            continue
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if isinstance(rule, dict) and rule.get("id"):
                titles[str(rule["id"])] = str(rule.get("title") or rule["id"])
    return titles


def _top_findings(conn, analysis_id: str, titles: dict[str, str] | None = None,
                  limit: int = 5) -> list[dict]:
    """Most severe/most frequent findings of one analysis, with titles.

    The rule pack is read lazily (only when findings exist) so live-polling the
    summary of a running analysis does not touch the filesystem.
    """
    rows = conn.execute(
        "SELECT rule_id, severity, COUNT(*) n FROM finding WHERE analysis_id = ? "
        "GROUP BY rule_id, severity "
        "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, n DESC LIMIT ?",
        (analysis_id, limit)).fetchall()
    if not rows:
        return []
    if titles is None:
        titles = _rule_titles()
    return [{"rule_id": r["rule_id"],
             "title": titles.get(r["rule_id"]) or r["rule_id"],
             "severity": r["severity"],
             "count": r["n"]} for r in rows]



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
        b = min(5, max(1, int(f["likelihood"] * 5) + 1))
        col = sevs.index(f["severity"]) if f["severity"] in sevs else 0
        grid[b - 1][col]["findings"].append({"rule_id": f["rule_id"],
                                             "evidence": f["evidence"]})
    return grid
