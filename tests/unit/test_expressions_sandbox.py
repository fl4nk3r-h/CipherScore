"""Sandbox evaluator tests (repo.md §4): no eval(); whitelisted operators."""
from __future__ import annotations

import pytest

from analyzer.posture import expressions


def test_membership_expression():
    assert expressions.evaluate("sa.dh_group in [1, 2, 5]", {"sa": {"dh_group": 2}})
    assert not expressions.evaluate("sa.dh_group in [1, 2, 5]", {"sa": {"dh_group": 14}})


def test_boolean_and_not():
    ctx = {"sa": {"pfs": False, "mode": "transport"}}
    assert expressions.evaluate("not sa.pfs and sa.mode == 'transport'", ctx)


def test_comparisons():
    ctx = {"sa": {"rekey_interval_s": 90000, "traffic_confidence": 0.87}}
    assert expressions.evaluate("sa.rekey_interval_s > 28800", ctx)
    assert expressions.evaluate("sa.traffic_confidence >= 0.7", ctx)


@pytest.mark.parametrize("expr", [
    "__import__('os')",
    "(lambda: 1)()",
    "sa.__class__",
    "open('/etc/passwd')",
    "[].append(1)",
    "sa.x.y.z",
])
def test_dangerous_expressions_rejected(expr):
    with pytest.raises(ValueError):
        expressions.evaluate(expr, {"sa": {"x": {}}})


def test_unknown_name_rejected():
    with pytest.raises(ValueError):
        expressions.evaluate("evil in [1]", {"sa": {}})
