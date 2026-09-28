"""Scoring tests (mvp.md §3.5): Risk and Security Score formulas, grade bands,
confidence weighting."""
from __future__ import annotations

from analyzer.models import Finding
from analyzer.posture.matrix import bucket, build
from analyzer.posture.score import compute


def _f(rule_id: str, severity: str, likelihood: float, confidence: float) -> Finding:
    return Finding(rule_id=rule_id, title=rule_id, category="test",
                   severity=severity, likelihood=likelihood, confidence=confidence,
                   evidence={}, refs=[], fix="")


def test_low_confidence_cannot_inflate_risk():
    # critical, likelihood 0.9, but evidence confidence ~ 0 -> risk ~ 0
    findings = [_f("X-001", "critical", 0.9, 0.01)]
    posture = compute(findings, ai_confidence=0.01)
    assert posture.risk_score < 1.0
    assert posture.security_score >= 90


def test_full_confidence_critical_drops_score():
    findings = [_f("X-001", "critical", 1.0, 1.0)]
    posture = compute(findings, ai_confidence=1.0)
    assert posture.risk_score == 10.0
    assert posture.security_score == 0


def test_demo_scores():
    # p03 (weak): several strong findings -> ~40 (grade E); p07 (strong): ~90 (grade A)
    p03 = compute([
        _f("CRYPTO-001", "high", 0.7, 1.0),
        _f("CRYPTO-003", "medium", 0.6, 0.98),
        _f("PFS-001", "medium", 0.5, 0.88),
        _f("REPLAY-001", "high", 0.8, 1.0),
        _f("META-003", "medium", 0.6, 0.9),
    ])
    assert p03.security_score < 60
    assert p03.grade in ("D", "E")

    p07 = compute([
        _f("COMP-001", "low", 0.5, 1.0),
        _f("META-003", "medium", 0.6, 0.9),
    ])
    assert p07.security_score >= 85
    assert p07.grade in ("A", "B")


def test_threat_matrix_buckets():
    findings = [_f("A", "high", 0.55, 1.0), _f("B", "critical", 0.9, 1.0)]
    grid = build(findings)
    assert len(grid) == 5 and all(len(row) == 5 for row in grid)
    hits = [c for row in grid for c in row if c["findings"]]
    assert len(hits) == 2
    assert bucket(0.55) == 3
    assert bucket(0.9) == 5
