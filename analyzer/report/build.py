"""Assemble report context from an analysis (repo.md §4)."""
from __future__ import annotations

from analyzer.models import AnalysisResult, Finding


def build_context(result: AnalysisResult) -> dict:
    findings: list[Finding] = result.findings
    posture = result.posture
    counts = {s: sum(1 for f in findings if f.severity == s)
              for s in ("critical", "high", "medium", "low", "info")}
    top = sorted(findings, key=lambda f: (f.severity != "critical",
                                          f.severity != "high",
                                          -f.likelihood * f.confidence))[:5]
    return {
        "analysis_id": result.analysis_id,
        "security_score": posture.security_score if posture else None,
        "grade": posture.grade if posture else None,
        "risk_score": posture.risk_score if posture else None,
        "ai_confidence": posture.ai_confidence if posture else None,
        "severity_counts": counts,
        "top_findings": [{"id": f.rule_id, "title": f.title,
                          "fix": f.fix, "refs": f.refs} for f in top],
        "threat_matrix": posture.threat_matrix if posture else [],
        "sas": [sa.model_dump(mode="json") for sa in
                (result.inferences.sas if result.inferences else [])],
        "findings": [f.model_dump(mode="json") for f in findings],
    }
