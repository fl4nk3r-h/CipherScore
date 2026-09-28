# agent.md — `api/` (FastAPI REST + SSE service)

**Source of truth: `docs/mvp.md` §2.1, §5 (API surface), §6 (data model), §8 (flow); layout per `docs/repo.md` §7, §11. Nothing here adds, removes, or reinterprets an MVP requirement.**

## Mission

Expose the MVP's minimal API surface and run analysis jobs, with **no analysis logic here**: every router calls `analyzer.pipeline` or a repository (repo.md §7).

## What this folder must do (from mvp.md)

**Implement exactly this subset (§5), base URL `http://localhost:8000/api/v1`:**

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/captures` | Upload PCAP (multipart). Returns `capture_id` |
| `POST` | `/analyses` | `{capture_id \| lab_session_id, rule_pack}`. Starts a job and returns `analysis_id` |
| `GET` | `/analyses/{id}` | Status + summary (score, risk, confidence) |
| `GET` | `/analyses/{id}/sas` | SA table with inference tags |
| `GET` | `/analyses/{id}/traffic` | Traffic classification + histograms |
| `GET` | `/analyses/{id}/findings` | Findings with evidence |
| `GET` | `/analyses/{id}/threat-matrix` | 5 × 5 matrix |
| `GET` | `/analyses/{id}/reports/{executive\|technical}.pdf` | Download report |
| `GET` | `/analyses/{id}/events` | SSE progress stream |
| `GET` | `/lab/profiles` | List profiles |
| `POST` | `/lab/runs` | `{profile_ids, traffic_types}`. Starts a lab run |
| `GET` | `/lab/sessions` | Sessions + ground truth |
| `POST` | `/live/start` · `/live/stop` | Live mode on a configured interface |
| `GET` | `/live/events` | SSE stream of window predictions |

**Summary response shape (§5 sample):** `analysis_id`, `status`, `security_score`, `grade`, `risk_score`, `ai_confidence`, `sa_count`, `findings` counts by severity, `top_findings`.

**SA record shape (§5 sample):** every parameter is `{value, tag: observed|inferred|unknown, confidence}`; traffic adds `top`, `p`, `conformal_set`.

**Job model (§2.1):** run analysis jobs in a `ThreadPoolExecutor` — a ~200 MB capture finishes in seconds to a few minutes; keep the job interface the same so Celery/RQ can replace it later. Progress events follow the §8 sequence (parsed 0.30 → features 0.50 → inferred 0.70 → assessed 0.85 → completed 1.0) over the SSE stream.

**Live mode (§0, §9 step 8, §13):** rolling 10 s windows on one interface streamed over SSE; disabled by default (`CS_LIVE_ENABLED=false`); the container gets `NET_RAW`/`NET_ADMIN` only for live mode.

## Inputs

- Uploaded PCAPs (multipart, streamed; **500 MB cap**, §13), lab session ids, rule pack names.
- Environment: `CS_DATA_DIR`, `CS_MODELS_DIR`, `CS_RULES_DIR`, `CS_MAX_UPLOAD_MB`, `CS_LIVE_ENABLED` (repo.md §11).

## Outputs

- JSON per the §5 shapes; PDFs from the analyzer; SSE event streams; SQLite tables of mvp.md §6 (`capture`, `analysis`, `sa`, `flow_window`, `finding`, `rule`, `profile`, `lab_session`).

## Security invariants (repo.md §7 — mandatory)

- All SQL uses **parameterized queries**.
- Uploaded file names are **never** used as paths: store as `data/uploads/<sha256>.pcapng`.
- The API contains no analysis logic; import `analyzer.pipeline` / repositories only.

## Boundaries (do not do)

- No parsing/inference/scoring/reporting code in this folder.
- No auth/RBAC/SSO — single analyst for the MVP (deferred, §1.2).
- No Postgres/TimescaleDB or object storage — SQLite + local disk (deferred, §1.2).
- Don't extend the API surface beyond §5 without an MVP spec change.
