# agent.md — `tests/` (cross-module tests + reference PCAPs)

**Owners: shared** — fixture data + golden ground truth: Person A; unit/API/e2e suites: Person B (see [docs/team_split.md](../docs/team_split.md)).

**Source of truth: `docs/mvp.md` §3.3, §3.4, §3.5, §9 (milestones), §14 (definition of done); layout per `docs/repo.md` §9. Nothing here adds, removes, or reinterprets an MVP requirement.**

## Mission

Prove the MVP does what §14 demands: "`pytest` passes: parser golden tests on reference PCAPs, rule tests, scoring tests, API tests."

## What this folder must do (from mvp.md)

1. **Parser golden tests** (`integration/test_pipeline_golden.py`) on small reference captures with expected JSON (§3.3):
   - `ikev2_sa_init_aes256gcm_ecp384.pcapng` — ENCR 20 AES-GCM-16, DH 20 ECP-384, KE size 96 B.
   - `ikev1_main_mode_3des_modp1024.pcapng` — IKEv1 Main Mode, weak suite.
   - `esp_cbc_sha1_tunnel_v4.pcapng` — CBC hypothesis (IV 16, block 16), ICV 12, tunnel size offset.
   - `esp_gcm_transport_v6.pcapng` — GCM hypothesis (IV 8, pad 4), ICV 16, transport offsets.
   - `natt_esp_in_udp.pcapng` — UDP/4500 non-ESP marker vs ESP-in-UDP demux.
   Milestone M-C exit criterion (§9): deterministic fields match ground truth on **100 %** of lab sessions.
2. **Rule tests** (`test_rule_engine.py`) — the §3.5 example rules (`CRYPTO-001` DH in [1,2,5]; `PFS-001` pfs == false), all-8-category coverage, unknown values must not fire, severity scale `info|low|medium|high|critical`.
3. **Scoring tests** (`test_score.py`) — exact formulas: `Risk = Σ w_sev·L_f·C_f`, `Score = max(0, 100 − 100·Risk/Risk_max)`, weights `{info:0, low:1, medium:3, high:6, critical:10}`; **low-confidence evidence cannot inflate risk**; demo bands (p03 → ~40/E, p07 → ~90/A); 5×5 matrix bucketing.
4. **Sandbox tests** (`test_expressions_sandbox.py`) — no `eval()`, whitelisted operators only (repo.md §4).
5. **API tests** (`integration/test_api.py`) — upload → analysis → report via TestClient; uploaded files stored as `<sha256>.pcapng` (never original names); live mode 403 while `CS_LIVE_ENABLED=false` (§13).
6. **E2E** (`e2e/dashboard.spec.ts`, Playwright) — the §14 dashboard criterion: upload produces score, SAs, findings, matrix, and both PDFs.
7. **ML gate** (via `make train`/`make eval`, exercised in CI): §3.4 targets on held-out profiles — cipher ≥ 95 %, mode ≥ 90 %, PFS ≥ 90 % (rekey captured), traffic macro-F1 ≥ 0.80/SA and ≥ 0.70/window, ECE ≤ 0.08.

## Inputs

- Fixture PCAPs (< 1 MB) + `expected/*.json` (regeneration policy in `fixtures/pcaps/README.md`; ground truth always from the session manifest, never from the analyzer).
- `rules/` packs; the analyzer package; the FastAPI app.

## Outputs

- Passing pytest suites (`make test` = ruff + pytest unit + integration), Playwright run (`make e2e`).

## Boundaries (do not do)

- Never generate expected values with the analyzer under test — that would be circular (§0: "accuracy is measured, not claimed").
- No live-network or docker-required tests in the default suite; lab-dependent checks belong to `scripts/sanity_check.py` and the demo (§10).
- Fixtures stay < 1 MB each (repo.md §9).
