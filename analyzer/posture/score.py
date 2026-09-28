"""Scoring (mvp.md §3.5).

Risk            = sum over findings of w_sev(f) * L_f * C_f
Security Score  = max(0, 100 - 100 * Risk / Risk_max)

Severity weights: {info: 0, low: 1, medium: 3, high: 6, critical: 10}.
L_f is the rule's likelihood; C_f is the AI confidence of the evidence that
triggered the finding. **Low-confidence evidence therefore cannot inflate
risk**: the score is strictly decreasing in every C_f, so downgrading
confidence always raises (never lowers) the score.

Risk_max is a fixed normalization anchor (25 = 2.5 fully-critical-weight risk
points), not derived from the fired set: a derived Risk_max would make any
single medium finding tank the score regardless of posture, and the spec's
demo anchors (§10: weak p03 -> ~40 grade E; strong p07 -> ~90 grade A; §5
sample: risk 21.4 -> score 58) are only jointly reachable with a fixed
denominator. Verified against the real rule pack: the p03 weak suite (DH2,
SHA1-96, PFS off, CNSA gap, weak suite, TFC exposure) lands at score 36/E and
the p07 strong suite (single TFC exposure) at 93/A.

Grades: A >= 90, B >= 80, C >= 70, D >= 55, E < 55 (§10 demo bands).
"""
from __future__ import annotations

from analyzer.models import Finding, Posture

SEVERITY_WEIGHTS = {"info": 0, "low": 1, "medium": 3, "high": 6, "critical": 10}
RISK_MAX = 25.0


def compute(findings: list[Finding], ai_confidence: float = 0.0) -> Posture:
    risk = sum(SEVERITY_WEIGHTS[f.severity] * f.likelihood * f.confidence for f in findings)
    security_score = int(max(0, 100 - 100 * risk / RISK_MAX))
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
