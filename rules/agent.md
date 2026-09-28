# agent.md — `rules/` (M5 rule packs)

**Owner: Person B** (see [docs/team_split.md](../docs/team_split.md)).

**Source of truth: `docs/mvp.md` §1.1(d), §3.5 (categories, example rules, scoring), §12, §13; layout per `docs/repo.md` §9. Nothing here adds, removes, or reinterprets an MVP requirement.**

## Mission

Hold the plain-YAML security rule packs that drive the Posture Engine — "so reviewers can read and change it" (§3.5).

## What this folder must do (from mvp.md)

1. **Provide the default pack** `ipsec-baseline.yaml` covering **all 8 assessment categories** (§1.1(d), §3.5):
   - **Cryptographic strength** — 3DES/DES present · AES-128 vs 256 against the chosen policy · HMAC-SHA1-96 integrity.
   - **Configuration compliance** — checks against **RFC 8221 (ESP)**, **RFC 8247 (IKEv2)**, **NIST SP 800-77r1**, **CNSA 2.0**.
   - **SA parameters** — lifetime too long · ESN off on high-rate SAs · Aggressive Mode.
   - **Key lifetime** — CHILD_SA rekey over 8 h · IKE SA over 24 h · no rekey observed on a long session.
   - **Replay protection** — sequence numbers repeat or reset without an SPI change · replay window 0 inferred.
   - **Forward secrecy** — PFS off · weak DH group used for PFS.
   - **Cipher suite strength** — suite graded A–F from its combined algorithms.
   - **Metadata exposure** — transport mode exposes real endpoints · IKEv1 Aggressive Mode identity leak · no TFC padding (the M4 traffic classifier confidence **is** the exposure measure).
2. **Keep the rule schema fixed (§3.5):** `id`, `title`, `category`, `when`, `severity` (`info|low|medium|high|critical`), `likelihood` (0–1), `refs`, `fix`. The two example rules must remain faithful: `CRYPTO-001` "Weak DH group in use" fires on `sa.dh_group in [1, 2, 5]` (high, 0.7, RFC 8247 §2.4 + NIST §5); `PFS-001` "Perfect Forward Secrecy disabled for CHILD_SA" fires on `sa.pfs == false` (medium, 0.5, NIST §4.2).
3. **Provide the stricter pack** `cnsa2.yaml` (AES-256, ECP-384, SHA-384+) per repo.md §9, plus `categories.yaml` (names, descriptions, and the weights `w = {info: 0, low: 1, medium: 3, high: 6, critical: 10}`) and `references.yaml` (RFC 7296/4302/4303/3948/4106/8221/8247/9370, NIST SP 800-77r1, CNSA 2.0 — §15).
4. **Score correctly through the engine (§3.5):** `Risk = Σ w_sev(f)·L_f·C_f`, `Security Score = max(0, 100 − 100·Risk/Risk_max)`. `C_f` is the AI confidence of the triggering evidence, so **rule severity/likelihood values are inputs to a confidence-weighted score** — low-confidence evidence cannot inflate risk.

## Inputs

- SA context produced by M4 (`sa.dh_group`, `sa.pfs`, `sa.mode`, `sa.enc`, `sa.key_bits`, `sa.integ`, `sa.nat_t`, `sa.replay_window`, `sa.esn`, `sa.rekey_interval_s`, `sa.ike_version`, `sa.traffic_confidence`). Unknown values must **not** make a rule fire.

## Outputs

- Findings consumed by `analyzer/posture/` (rule_engine, score, matrix, compliance badges) and rendered in both reports (§3.6) and the dashboard findings screen (§4 screen 6).

## Functionality / interfaces

- Rule expressions are evaluated by `analyzer/posture/expressions.py` in a **sandboxed evaluator (no `eval()`, whitelisted operators)** — write `when:` expressions only in that subset (e.g. `sa.dh_group in [1, 2, 5]`).
- Packs are selected by name: `ipsec-baseline` (default) and `cnsa2` (repo.md §9).

## Boundaries (do not do)

- Don't encode ML logic in rules — confidence comes from M4 evidence, not from rules (§3.5).
- Don't add assessment categories (the problem statement fixes 8) or change the severity scale.
- No vendor config ingestion — out of scope for the MVP (§1.2); the MVP assesses from traffic.
- PQ readiness is flagged informationally only; generating PQ traffic is deferred (§1.2).
