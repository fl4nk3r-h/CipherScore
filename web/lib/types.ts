// Mirrors analyzer/models.py (repo.md §8 lib/types.ts).
export type Tag = "observed" | "inferred" | "unknown";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface TaggedValue {
  value: unknown;
  tag: Tag;
  confidence: number;
}

export interface TrafficPrediction {
  top: string;
  p: number;
  conformal_set: string[];
}

export interface SAEvidence {
  spi: string;
  peers: string[];
  ike_version?: TaggedValue;
  mode?: TaggedValue;
  enc?: TaggedValue;
  key_bits?: TaggedValue;
  integ?: TaggedValue;
  dh_group?: TaggedValue;
  pfs?: TaggedValue;
  nat_t?: TaggedValue;
  rekey_interval_s?: TaggedValue;
  replay_window?: TaggedValue;
  esn?: TaggedValue;
  traffic?: TrafficPrediction;
}

export interface Finding {
  rule_id: string;
  title: string;
  category: string;
  severity: Severity;
  likelihood: number;
  confidence: number;
  evidence: Record<string, unknown>;
  refs: string[];
  fix: string;
}

export interface Summary {
  analysis_id: string;
  status: "queued" | "running" | "completed" | "failed";
  security_score: number | null;
  grade: string | null;
  risk_score: number | null;
  ai_confidence: number | null;
  sa_count: number;
  findings: Record<string, number>;
  top_findings: string[];
}

export interface MatrixCell {
  likelihood_bucket: number;
  impact: Severity;
  findings: { rule_id: string; title?: string; evidence?: unknown }[];
}
