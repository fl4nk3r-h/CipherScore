"""Threat Matrix (mvp.md §3.5): findings placed on a 5 x 5 grid of likelihood
bucket x impact (severity). Each cell links to its findings and their evidence."""
from __future__ import annotations

from analyzer.models import Finding

SEVERITIES = ["info", "low", "medium", "high", "critical"]   # impact axis


def bucket(likelihood: float) -> int:
    """Map likelihood [0,1] to bucket 1..5."""
    return min(5, max(1, int(likelihood * 5) + 1))


def build(findings: list[Finding]) -> list[list[dict]]:
    """5x5 grid; cells hold their findings' ids, titles, and evidence."""
    grid: list[list[dict]] = [
        [{"likelihood_bucket": b, "impact": s, "findings": []} for s in SEVERITIES]
        for b in range(1, 6)
    ]
    for f in findings:
        b = bucket(f.likelihood)
        col = SEVERITIES.index(f.severity)
        grid[b - 1][col]["findings"].append(
            {"rule_id": f.rule_id, "title": f.title, "evidence": f.evidence})
    return grid
