"""Rule engine (repo.md §4): loads the YAML pack and evaluates safe expressions
against the SA context (mvp.md §3.5).

The rule pack is plain YAML (rules/ipsec-baseline.yaml), so reviewers can read
and change it. Severity: info | low | medium | high | critical.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from analyzer.models import Finding, Severity
from analyzer.posture import expressions


def load_pack(rules_dir: Path, pack: str = "ipsec-baseline") -> list[dict]:
    path = rules_dir / f"{pack}.yaml"
    rules = yaml.safe_load(path.read_text())
    required = {"id", "title", "category", "when", "severity", "likelihood", "refs", "fix"}
    for r in rules:
        missing = required - set(r)
        if missing:
            raise ValueError(f"rule {r.get('id', '?')}: missing fields {sorted(missing)}")
    return rules


def _sa_context(sa) -> dict:
    """Flatten a SAEvidence into the `sa.*` context rules expect."""
    def val(field):
        v = getattr(sa, field, None)
        return v.value if isinstance(v, TaggedValue) else v

    return {
        "dh_group": val("dh_group"),
        "pfs": val("pfs"),
        "mode": val("mode"),
        "enc": val("enc"),
        "key_bits": val("key_bits"),
        "integ": val("integ"),
        "nat_t": val("nat_t"),
        "replay_window": val("replay_window"),
        "esn": val("esn"),
        "rekey_interval_s": val("rekey_interval_s"),
        "traffic_confidence": sa.traffic.p if sa.traffic else 0.0,
        "ike_version": val("ike_version"),
    }


def evaluate(inferences, rules_dir: Path,
             pack: str = "ipsec-baseline") -> list[Finding]:
    """Run every rule against every SA. `confidence` on the Finding is the AI
    confidence of the evidence that triggered it (mvp.md §3.5 scoring)."""
    findings: list[Finding] = []
    for rule in load_pack(rules_dir, pack):
        targets = getattr(inferences, "sas", None) or []
        for sa in targets:
            ctx = _sa_context(sa)
            try:
                hit = expressions.evaluate(rule["when"], {"sa": ctx})
            except ValueError:
                hit = False   # a rule over unknown values simply doesn't fire
            if hit:
                findings.append(Finding(
                    rule_id=rule["id"],
                    title=rule["title"],
                    category=rule["category"],
                    severity=Severity(rule["severity"]),
                    likelihood=float(rule["likelihood"]),
                    confidence=_evidence_confidence(sa, rule),
                    evidence={"spi": sa.spi, "when": rule["when"], "context": ctx},
                    refs=list(rule["refs"]),
                    fix=rule["fix"],
                ))
    return findings


def _evidence_confidence(sa, rule: dict) -> float:
    """Confidence of the evidence that triggered the finding: the minimum
    confidence among the SA fields referenced by the rule's `when` (§3.5)."""
    confs: list[float] = []
    for field in ("dh_group", "pfs", "mode", "enc", "key_bits", "integ",
                  "nat_t", "replay_window", "esn", "rekey_interval_s",
                  "ike_version"):
        v = getattr(sa, field, None)
        if isinstance(v, TaggedValue) and v.tag != "unknown":
            if field in rule["when"]:
                confs.append(v.confidence)
    if sa.traffic and "traffic" in rule["when"]:
        confs.append(sa.traffic.p)
    return round(min(confs), 4) if confs else 0.5
