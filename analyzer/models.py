"""Pydantic domain models (repo.md §4).

Tags follow mvp.md §3.4: every output statement is "observed", "inferred", or
"unknown", with an AI confidence. Low-confidence evidence can never inflate risk.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Tag = Literal["observed", "inferred", "unknown"]
Severity = Literal["info", "low", "medium", "high", "critical"]


class TaggedValue(BaseModel):
    value: Any
    tag: Tag
    confidence: float = Field(ge=0.0, le=1.0)


class TrafficPrediction(BaseModel):
    top: str
    p: float
    conformal_set: list[str]


class SAEvidence(BaseModel):
    """One record per security association (mvp.md §3.3), stored as Parquet."""

    spi: str
    peers: list[str]
    ike_version: TaggedValue | None = None
    mode: TaggedValue | None = None
    enc: TaggedValue | None = None          # e.g. AES-CBC / AES-GCM-16
    key_bits: TaggedValue | None = None     # 128 / 256; cannot be observed from ESP bytes
    integ: TaggedValue | None = None        # e.g. HMAC-SHA1-96 / AEAD
    dh_group: TaggedValue | None = None
    pfs: TaggedValue | None = None
    nat_t: TaggedValue | None = None
    rekey_interval_s: TaggedValue | None = None
    replay_window: TaggedValue | None = None
    esn: TaggedValue | None = None
    traffic: TrafficPrediction | None = None


class FlowWindow(BaseModel):
    """One 5 s feature window of one SA (mvp.md §3.3), stored as Parquet."""

    sa_id: str
    t0: float
    features: dict[str, float]
    pred: str | None = None
    p: float | None = None


class InferenceSet(BaseModel):
    ike_version: TaggedValue | None = None
    ike_suite: dict[str, TaggedValue] = Field(default_factory=dict)  # enc/prf/integ/dh
    sas: list[SAEvidence] = Field(default_factory=list)


class Finding(BaseModel):
    rule_id: str
    title: str
    category: str
    severity: Severity
    likelihood: float
    confidence: float          # AI confidence of the evidence that triggered it
    evidence: dict[str, Any]   # packet numbers, fields, features
    refs: list[str] = Field(default_factory=list)
    fix: str = ""


class Posture(BaseModel):
    risk_score: float
    security_score: int
    grade: str
    ai_confidence: float
    threat_matrix: list[list[dict[str, Any]]]
    compliance: dict[str, Any] = Field(default_factory=dict)


class ReportPaths(BaseModel):
    executive_pdf: str | None = None
    technical_pdf: str | None = None
    report_json: str | None = None
    findings_csv: str | None = None


class AnalysisResult(BaseModel):
    analysis_id: str
    status: Literal["queued", "running", "completed", "failed"] = "queued"
    inferences: InferenceSet | None = None
    findings: list[Finding] = Field(default_factory=list)
    posture: Posture | None = None
    reports: ReportPaths | None = None
