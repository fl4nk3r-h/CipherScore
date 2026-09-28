"""Sandboxed evaluator (repo.md §4): no eval(); whitelisted operators.

Rule conditions like "sa.dh_group in [1, 2, 5]" (mvp.md §3.5) are evaluated
against the SA context with a restricted AST walk. YAML booleans parse as
Python True/False; the lowercase YAML spellings (true/false/null) are accepted
as names too.
"""
from __future__ import annotations

import ast
import operator as op

_ALLOWED_BINOPS = {
    ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul,
    ast.Div: op.truediv, ast.Mod: op.mod,
}
_ALLOWED_CMPOPS = {
    ast.Eq: op.eq, ast.NotEq: op.ne, ast.Lt: op.lt, ast.LtE: op.le,
    ast.Gt: op.gt, ast.GtE: op.ge, ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}
_ALLOWED_UNARY = {ast.Not: op.not_, ast.USub: op.neg}
_MAX_NODES = 200


def _eval(node: ast.AST, ctx: dict) -> object:
    if isinstance(node, ast.Expression):
        return _eval(node.body, ctx)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float, str, bool, type(None))):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in ctx:
            return ctx[node.id]
        if node.id in ("true", "True"):
            return True
        if node.id in ("false", "False"):
            return False
        if node.id in ("null", "none", "None"):
            return None
        raise ValueError(f"unknown name: {node.id}")
    if isinstance(node, ast.Attribute):
        base = _eval(node.value, ctx)
        if isinstance(base, dict) and node.attr in base:
            return base[node.attr]
        raise ValueError(f"unknown attribute: {node.attr}")
    if isinstance(node, ast.List):
        return [_eval(e, ctx) for e in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_eval(e, ctx) for e in node.elts)
    if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_BINOPS:
        return _ALLOWED_BINOPS[type(node.op)](_eval(node.left, ctx), _eval(node.right, ctx))
    if isinstance(node, ast.BoolOp):
        vals = [_eval(v, ctx) for v in node.values]
        return all(vals) if isinstance(node.op, ast.And) else any(vals)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_UNARY:
        return _ALLOWED_UNARY[type(node.op)](_eval(node.operand, ctx))
    if isinstance(node, ast.Compare):
        left = _eval(node.left, ctx)
        for cmp_op, comparator in zip(node.ops, node.comparators):
            if type(cmp_op) not in _ALLOWED_CMPOPS:
                raise ValueError(f"operator not allowed: {type(cmp_op).__name__}")
            right = _eval(comparator, ctx)
            # Unknown evidence (None) must never satisfy a rule: treat any
            # failed/undefined comparison as non-firing (mvp.md §3.4).
            if left is None or right is None:
                return False
            if type(cmp_op) in (ast.In, ast.NotIn):
                if not _ALLOWED_CMPOPS[type(cmp_op)](left, right):
                    return False
            else:
                try:
                    if not _ALLOWED_CMPOPS[type(cmp_op)](left, right):
                        return False
                except TypeError:
                    return False
            left = right
        return True
    raise ValueError(f"node not allowed: {type(node).__name__}")


def evaluate(expression: str, sa_context: dict) -> bool:
    """Evaluate a rule `when:` expression safely. Raises on anything disallowed."""
    tree = ast.parse(expression, mode="eval")
    if sum(1 for _ in ast.walk(tree)) > _MAX_NODES:
        raise ValueError("expression too complex")
    return bool(_eval(tree, sa_context))
