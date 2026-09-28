# agent.md — `analyzer/` (M3 Evidence Fusion · M4 Classifier Ensemble · M5 Posture Engine · M6 Report Studio)

**Owner: Person B** (see [docs/team_split.md](../docs/team_split.md)).

**Source of truth: `docs/mvp.md` §1.1(c)–(e), §3.3, §3.4, §3.5, §3.6, §5, §8, §12, §13. Nothing here adds, removes, or reinterprets an MVP requirement.**

This package holds **all the analysis logic** and knows nothing about HTTP; the API and CLI both import it (repo.md §4). Output language is fixed: every statement in a result is tagged **observed / inferred / unknown** with an **AI confidence** (§3.4).

---

## `parse/` — M3 Evidence Fusion: parsing

**Mission.** Turn a pcap/pcapng into protocol-level evidence. The pipeline **streams packets with dpkt for speed**; **Scapy is only for IKE decoding** (§3.3).

**Step 1 — Protocol demux (fixed table, §3.3):**

| Signal | Detection |
|---|---|
| ESP | IP protocol 50 (IPv4) / Next Header 50 (IPv6) |
| AH | IP protocol 51 |
| IKE | UDP/500, or UDP/4500 with the 4-byte non-ESP marker `0x00000000` |
| ESP-in-UDP (NAT-T) | UDP/4500 whose first 4 bytes are non-zero (the SPI) |

**Step 2 — IKE parsing (deterministic, high confidence, §3.3):**
- **IKE version** from the header version byte (major 1 or 2) and exchange type (IKEv2: 34 IKE_SA_INIT, 35 IKE_AUTH, 36 CREATE_CHILD_SA, 37 INFORMATIONAL; IKEv1: 2 Main Mode, 4 Aggressive, 32 Quick Mode).
- **IKE SA proposal offered and chosen.** SA payload transforms: Type 1 ENCR (12 AES-CBC, 20 AES-GCM-16, 28 ChaCha20-Poly1305, 3 3DES) with Key Length attribute 14; Type 2 PRF; Type 3 INTEG (2 SHA1-96, 12 SHA2-256-128, 13 SHA2-384-192, 14 SHA2-512-256); Type 4 DH (2, 5, 14, 15, 16, 19, 20, 21, 31). **The responder's SA_INIT carries the single selected proposal.**
- **KE payload size** as a cross-check of the DH group (256 bytes for MODP-2048, 64 bytes for ECP-256).
- **Vendor ID and NOTIFY payloads** such as NAT_DETECTION_* → indicates NAT-T.
- **IKEv1 Aggressive Mode** exposes the identity in cleartext → flagged as metadata exposure.

**Step 3 — ESP structural inference (the CHILD_SA proposal is inside encrypted IKE_AUTH, so ESP parameters are inferred from packet structure, §3.3):**

| Feature | How computed | Reveals |
|---|---|---|
| `spi`, `seq` | ESP bytes 0–3 and 4–7 | SA identity, replay behavior, rekey (new SPI appears) |
| `esp_len mod 16` minus header/IV/ICV candidates | hypotheses {CBC: IV 16, block 16} and {GCM: IV 8, pad 4} × ICV {12, 16, 24, 32} | Cipher mode (CBC vs GCM) and ICV length → integrity algorithm |
| Minimum ESP length and size histogram | per SA | Tunnel adds a full inner IP header (+20 B v4 / +40 B v6) vs transport |
| Outer vs communicating endpoints | outer IPs vs inner subnets in baseline + NAT-T hints | Tunnel vs transport corroboration |
| Sequence gaps / resets | per SPI | Replay window behavior, ESN usage |
| SPI lifetime | first→last packet per SPI + spacing of CREATE_CHILD_SA | Effective key lifetime and rekey interval |
| CREATE_CHILD_SA message size | a KE payload makes it noticeably larger | **PFS on/off** |
| Flow statistics | size mean/std/percentiles, IAT stats, burst counts, up/down byte ratio, packets/s, first 32 packet sizes and directions | Traffic type inside ESP |

**Inputs:** a pcap/pcapng path (uploaded file or lab session capture; 500 MB upload cap upstream). **Outputs:** `SAEvidence` records per SA and `FlowWindow` vectors per 5 s window per SA, stored as **Parquet** (§3.3).

---

## `infer/` — M4 Classifier Ensemble

**Mission.** Combine **rules where the protocol is readable** with **ML where it is encrypted**; every output carries a confidence (§3.4).

| Target | Method | Confidence source |
|---|---|---|
| IPsec present | Rule: ESP/AH/IKE demux | 1.0 when observed |
| IKE version | Rule: header parse | 1.0 when IKE observed, else "unknown" |
| IKE SA enc/integ/DH | Rule: SA_INIT transform parse | 1.0 when SA_INIT observed |
| ESP cipher mode (CBC/GCM) | Hypothesis test on length alignment + LightGBM fallback | Fraction of packets consistent with the winning hypothesis, then calibrated |
| ESP integrity / ICV length | Same hypothesis test | Same |
| ESP key size (128/256) | **Cannot be observed from ESP bytes.** Inferred from the IKE SA choice (same-suite prior) and the profile-trained model | Lower confidence, shown explicitly |
| Tunnel vs Transport | LightGBM on size-offset features + endpoint heuristic | Calibrated probability |
| PFS on/off | Rule on CREATE_CHILD_SA size + LightGBM | Calibrated probability; **"unknown" if no rekey was captured** |
| Traffic type in ESP | LightGBM multi-class on `FlowWindow`, aggregated per SA with majority vote and mean probability | Isotonic-calibrated probability + split-conformal prediction set |

**Credibility contract (§3.4):** when evidence can't support an answer, say **"unknown"** instead of guessing. The report marks which statements are **observed**, **inferred**, **unknown**.

**Accuracy targets (checked on held-out profiles, §3.4):** IPsec / IKE version / IKE SA transforms ≥ 99 % (deterministic) · ESP cipher mode ≥ 95 % · ICV length / integrity family ≥ 95 % · Tunnel vs Transport ≥ 90 % · PFS ≥ 90 % when a rekey was captured · traffic (7 classes) macro-F1 ≥ 0.80 per SA and ≥ 0.70 per 5 s window · **ECE ≤ 0.08**.

**Models:** load from `models/` by version (`registry.json` → `model.joblib`, `calibrator.joblib`, `conformal.json` q̂ for α = 0.1, `features.json` ordering guard, `metrics.json`).

**Risk-reduction rules from §13:** key size is never presented as observed; missing rekey → "unknown: capture longer than the rekey interval".

---

## `posture/` — M5 Posture Engine

**Mission.** Assess security posture from inferences with a readable YAML rule pack mapped to **RFC 8221, RFC 8247, NIST SP 800-77r1, CNSA 2.0** (§3.5).

**All 8 categories required by the problem (§1.1(d) and §3.5):** cryptographic strength (3DES/DES present · AES-128 vs 256 against policy · HMAC-SHA1-96) · configuration compliance (RFC 8221 ESP, RFC 8247 IKEv2, NIST SP 800-77r1, CNSA 2.0) · SA parameters (lifetime too long · ESN off on high-rate SAs · Aggressive Mode) · key lifetime (CHILD_SA rekey > 8 h, IKE SA > 24 h, or no rekey observed on a long session) · replay protection (seq repeat/reset without SPI change; replay window 0 inferred) · forward secrecy (PFS off; weak DH for PFS) · cipher suite strength (graded A–F) · metadata exposure (transport mode exposes real endpoints · IKEv1 Aggressive identity leak · no TFC padding so sizes reveal the application — **the M4 traffic confidence IS the exposure measure**).

**Scoring (exact formulas, §3.5):**
`Risk = Σ w_sev(f) · L_f · C_f`, `Security Score = max(0, 100 − 100·Risk/Risk_max)`,
weights `w = {info: 0, low: 1, medium: 3, high: 6, critical: 10}`; `L_f` = rule likelihood, `C_f` = AI confidence of the triggering evidence. **Low-confidence evidence cannot inflate risk.** Grade expectations from the demo: p03 ≈ 40 → E, p07 ≈ 90 → A (§10).

**Threat Matrix:** findings on a **5 × 5 grid** of likelihood bucket × impact (severity); each cell links findings and their evidence packets (§3.5).

**Rule engine safety:** evaluate rule `when:` expressions in a sandbox — no `eval()`, whitelisted operators only (repo.md §4). A rule over an unknown value must not fire.

---

## `report/` — M6 Report Studio

**Mission.** Produce the two PDF reports plus machine-readable exports (§3.6):

| Report | Audience | Contents |
|---|---|---|
| **Executive** (2 pages) | Management | Security Score gauge, grade, top 5 risks in plain language, Threat Matrix, compliance badges (RFC 8221/8247, NIST, CNSA), recommended actions ranked by impact |
| **Technical** (8–20 pages) | Analysts | Per-SA parameter table with Observed/Inferred/Unknown tags + confidence · IKE exchange timeline · rekey/lifetime chart · traffic-type breakdown with conformal sets · all findings with evidence (packet numbers, fields) · remediation config snippets for strongSwan · model card and limitations |

HTML via **Jinja2**, PDF via **WeasyPrint**; exports `report.json` and `findings.csv`.

---

## Pipeline entry point (`pipeline.py`, §8 sequence and repo.md §4 skeleton)

`run_analysis(pcap, rule_pack)` → progress events at fixed fractions: **parsed 0.30 → features 0.50 → inferred 0.70 → assessed 0.85 → completed 1.0** (matches the SSE stream the dashboard consumes in §8).

## Inputs / outputs (folder level)

- **Inputs:** pcap/pcapng path; rule pack name (`ipsec-baseline` default; `cnsa2.yaml` stricter); `models/` artifacts; `rules/` YAML.
- **Outputs:** `AnalysisResult` with `InferenceSet` (SA table, tagged), `Finding[]`, `Posture` (risk, score, grade, confidence, matrix), PDFs + `report.json` + `findings.csv`, Parquet features.

## Boundaries (do not do)

- No HTTP, no DB access, no upload handling — `api/` wraps this package (repo.md §4).
- Never use lab save-keys/decryption in the analysis path (§3.2).
- Never present key size as observed; never guess when the tag should be unknown (§3.4, §13).
- No active probing of the target: analysis is passive only (§12 row "Passive (no probing of production)").
- Deep sequence models are out of scope for the MVP (§1.2): gradient boosting on flow statistics is the baseline.
