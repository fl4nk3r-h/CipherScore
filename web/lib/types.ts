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

export interface TopFinding {
  rule_id: string;
  title: string;
  severity: Severity;
  count: number;
}

export interface AnalysisListItem {
  analysis_id: string;
  status: Summary["status"];
  security_score: number | null;
  grade: string | null;
  risk_score: number | null;
  ai_confidence: number | null;
  sa_count: number;
  findings: Record<string, number>;
  top_findings: TopFinding[];
  created: string;
  capture_id: string;
}

export interface OverviewData {
  analyses: AnalysisListItem[];
}

export interface TrafficWindow {
  pred: string | null;
  p: number | null;
  t0: number;
  features?: Record<string, number>;
}

export interface LiveWindow {
  analysis_id: string;
  t0?: number;
  pred?: string | null;
  posture?: {
    security_score?: number | null;
    risk_score?: number | null;
  };
}

export interface LabProfile {
  id: string;
  file?: string;
  spec?: {
    mode?: string;
    ip_family?: string;
    esp_proposal?: string;
    traffic?: string[];
  };
}

export type GroundTruthLabels = Record<string, string | number | boolean | null>;

export interface SessionAccuracy {
  analysis_id: string;
  status: Summary["status"];
  predicted: Record<string, string | number | boolean | null>;
  match: Record<string, boolean | null>;
  match_rate: number | null;
  matched: number;
  compared: number;
  missing: number;
}

export interface LabSession {
  session_id: string;
  profile: string;
  traffic_type: string;
  labels: GroundTruthLabels;
  pcap: string;
  accuracy?: SessionAccuracy | null;
}

export interface ReportContext {
  analysis_id: string;
  security_score: number | null;
  grade: string | null;
  risk_score: number | null;
  ai_confidence: number | null;
  severity_counts: Record<string, number>;
  top_findings: { id: string; title: string; fix: string; refs: string[] }[];
  sas?: unknown[];
  findings?: unknown[];
}
