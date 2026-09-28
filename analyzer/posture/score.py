"""Scoring (mvp.md §3.5, simplified from LLD §7).

Risk = sum over findings of w_sev(f) * L_f * C_f
Security Score = max(0, 100 - 100 * Risk / Risk_max)

Severity weights: {info: 0, low: 1, medium: 3, high: 6, critical: 10}.
L_f is the rule's likelihood; C_f is the AI confidence of the evidence that
triggered the finding. **Low-confidence evidence therefore cannot inflate
risk.** Grade bands: A >= 90, B >= 80, C >= 70, D >= 55, E < 55 (demo script
§10 uses ~40 -> grade E for p03 and ~90 -> grade A for p07).
"""
from __future__ import annotations

from analyzer.models import Finding, Posture

SEVERITY_WEIGHTS = {"info": 0, "low": 1, "medium": 3, "high": 6, "critical": 10}


def compute(findings: list[Finding], ai_confidence: float = 0.0) -> Posture:
    risk = sum(SEVERITY_WEIGHTS[f.severity] * f.likelihood * f.confidence for f in findings)
    risk_max = sum(SEVERITY_WEIGHTS[max((f.severity for f in findings),
                                        key=lambda s: SEVERITY_WEIGHTS[s],
                                        default="info")] * 1.0 * 1.0
                   for _ in findings) if findings else 1.0
    risk_max = max(risk_max, 1.0)
    security_score = int(max(0, 100 - 100 * risk / risk_max))
    grade = ("A" if security_score >= 90 else
             "B" if security_score >= 80 else
             "C" if security_score >= 70 else
             "D" if security_score >= 55 else "E")
    return Posture(
        risk_score=round(risk, 2),
        security_score=security_score,
        grade=grade,
        ai_confidence=round(ai_confidence, 4),
        threat_matrix=[],
    )
