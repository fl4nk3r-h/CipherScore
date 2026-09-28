-- Tables from mvp.md §6 (data model). All access uses parameterized queries (repo.md §7).
CREATE TABLE IF NOT EXISTS capture (
  id TEXT PRIMARY KEY,
  path TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  created TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS analysis (
  id TEXT PRIMARY KEY,
  capture_id TEXT NOT NULL REFERENCES capture(id),
  status TEXT NOT NULL DEFAULT 'queued',   -- queued | running | completed | failed
  score REAL,
  risk REAL,
  confidence REAL,
  created TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sa (
  id TEXT PRIMARY KEY,
  analysis_id TEXT NOT NULL REFERENCES analysis(id),
  spi TEXT NOT NULL,
  peers TEXT NOT NULL,          -- JSON list
  params TEXT NOT NULL          -- JSON: tagged values (observed/inferred/unknown + confidence)
);

CREATE TABLE IF NOT EXISTS flow_window (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sa_id TEXT NOT NULL REFERENCES sa(id),
  t0 REAL NOT NULL,
  features TEXT NOT NULL,       -- JSON
  pred TEXT,
  p REAL
);

CREATE TABLE IF NOT EXISTS finding (
  id TEXT PRIMARY KEY,
  analysis_id TEXT NOT NULL REFERENCES analysis(id),
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  likelihood REAL NOT NULL,
  confidence REAL NOT NULL,
  evidence TEXT NOT NULL        -- JSON
);

CREATE TABLE IF NOT EXISTS rule (
  id TEXT PRIMARY KEY,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  refs TEXT NOT NULL            -- JSON list
);

CREATE TABLE IF NOT EXISTS profile (
  id TEXT PRIMARY KEY,
  spec TEXT NOT NULL            -- JSON profile spec
);

CREATE TABLE IF NOT EXISTS lab_session (
  id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL REFERENCES profile(id),
  traffic_type TEXT NOT NULL,
  labels TEXT NOT NULL          -- JSON ground truth
);

CREATE INDEX IF NOT EXISTS idx_analysis_capture ON analysis(capture_id);
CREATE INDEX IF NOT EXISTS idx_sa_analysis ON sa(analysis_id);
CREATE INDEX IF NOT EXISTS idx_finding_analysis ON finding(analysis_id);
