"""Rule engine tests (mvp.md §3.5): pack loading, firing, confidence weighting."""
from __future__ import annotations

import pytest

from analyzer.models import SAEvidence, TaggedValue
from analyzer.posture.rule_engine import evaluate, load_pack


def _sa(**fields) -> SAEvidence:
    sa = SAEvidence(spi="0xc3a1f00d", peers=["172.30.0.2", "172.30.0.3"])
    for k, v in fields.items():
        setattr(sa, k, v)
    return sa


def test_load_pack_requires_fields(rules_dir):
    pack = load_pack(rules_dir, "ipsec-baseline")
    assert any(r["id"] == "CRYPTO-001" for r in pack)
    assert any(r["id"] == "PFS-001" for r in pack)


def test_weak_dh_fires_crypto_001(rules_dir):
    sa = _sa(dh_group=TaggedValue(value="MODP-1024", tag="observed", confidence=1.0),
             pfs=TaggedValue(value=False, tag="inferred", confidence=0.88))
    findings = evaluate(type("I", (), {"sas": [sa]})(), rules_dir, "ipsec-baseline")
    ids = {f.rule_id for f in findings}
    assert "CRYPTO-001" in ids
    assert "PFS-001" in ids


def test_unknown_values_do_not_fire(rules_dir):
    sa = _sa(dh_group=TaggedValue(value=None, tag="unknown", confidence=0.0))
    findings = evaluate(type("I", (), {"sas": [sa]})(), rules_dir, "ipsec-baseline")
    assert all(f.rule_id != "CRYPTO-001" for f in findings)


def test_finding_confidence_is_evidence_confidence(rules_dir):
    sa = _sa(dh_group=TaggedValue(value="MODP-1024", tag="observed", confidence=1.0))
    findings = evaluate(type("I", (), {"sas": [sa]})(), rules_dir, "ipsec-baseline")
    crypto = next(f for f in findings if f.rule_id == "CRYPTO-001")
    assert crypto.confidence == 1.0


def test_severity_scale_matches_spec(rules_dir):
    pack = load_pack(rules_dir, "ipsec-baseline")
    allowed = {"info", "low", "medium", "high", "critical"}
    assert all(r["severity"] in allowed for r in pack)


def test_weights_match_spec():
    from analyzer.posture.score import SEVERITY_WEIGHTS
    assert SEVERITY_WEIGHTS == {"info": 0, "low": 1, "medium": 3, "high": 6, "critical": 10}


def test_sandbox_blocks_eval(rules_dir):
    from analyzer.posture import expressions
    with pytest.raises(Exception):
        expressions.evaluate("__import__('os').system('id')", {"sa": {}})
