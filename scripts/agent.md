# agent.md — `scripts/` (helper scripts: demo, packaging, sanity checks)

**Owners: split** — `sanity_check.py` + `package_dataset.sh`: Person A; `demo.sh` + `seed_demo_data.py`: Person B (see [docs/team_split.md](../docs/team_split.md)).

**Source of truth: `docs/mvp.md` §4 (screen 8), §9 (milestone M-F), §10 (demo script), §14 (definition of done); layout per `docs/repo.md` §9. Nothing here adds, removes, or reinterprets an MVP requirement.**

## Mission

Provide the operator entry points that make the MVP demonstrable and releasable: the §10 demo sequence, dataset packaging, the accuracy sanity check, and offline demo seeding.

## What this folder must do (from mvp.md)

1. **`demo.sh` — run the §10 demo sequence exactly:**
   1. Show the problem: raw ESP capture in Wireshark shows only SPIs and sequence numbers.
   2. Show the lab: pick profiles **p03 (weak)** and **p07 (strong)**; run **VoIP + Web** on both.
   3. Analyze: upload the resulting PCAPs or click "analyze session"; the progress stream shows parse → infer → assess → report.
   4. Weak tunnel (p03): **score ≈ 40, grade E**; findings: DH group 2, SHA1-96, PFS off; traffic panel predicts **VoIP at 0.9 confidence** though every packet is encrypted (the metadata exposure finding).
   5. Strong tunnel (p07): **score ≈ 90, grade A**; remaining findings: lack of PQ readiness (info) and traffic still classifiable (recommendation: TFC padding).
   6. Ground truth vs prediction on the Lab screen: per-field match rate.
   7. Reports: Executive PDF (plain language), Technical PDF (evidence to packet numbers).
   8. Live mode: start a VoIP call through the tunnel; predictions update every 10 s.

   Exit criterion (§9, M-F): the demo script runs **without manual fixes**.
2. **`sanity_check.py`** — ground truth vs prediction over **all** lab sessions (screen 8's accuracy proof; §9 M-C: deterministic fields match ground truth on 100 % of lab sessions). Unknown predictions are excluded, never guessed.
3. **`package_dataset.sh`** — zips the dataset for release (§7 deliverable).
4. **`seed_demo_data.py`** — loads **3 pre-analyzed captures** for the offline demo (`make demo`).

## Inputs

- Lab sessions under `data/sessions/` (pcapng + manifest.json), analysis outputs under `data/reports/`, optional `data/demo/` pre-analyzed sets.

## Outputs

- Demo runs (lab, analyses, seeded dashboard), sanity report to stdout, `dist/cipherscope-dataset.zip`.

## Boundaries (do not do)

- No analysis logic here — call the analyzer CLI/pipeline; scripts only orchestrate (repo.md §9).
- Demo numbers (≈40/E, ≈90/A) come from the scoring model, not hardcoded into outputs (§10).
- No cloud services; everything runs on the local stack (§0).
