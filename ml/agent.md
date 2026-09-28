# agent.md — `ml/` (offline training and evaluation for M4)

**Source of truth: `docs/mvp.md` §3.4 (training loop, targets), §7 (dataset), §13 (risks); layout per `docs/repo.md` §5. Nothing here adds, removes, or reinterprets an MVP requirement.**

## Mission

Train and calibrate the four MVP models — `mode`, `pfs`, `cipher_mode`, `traffic_type` — from the labeled dataset, meeting the §3.4 accuracy targets on **held-out profiles**, and produce the model card.

## What this folder must do (from mvp.md)

**Training loop (§3.4), exactly five steps:**
1. Load feature Parquet + `labels.csv`.
2. **Profile-grouped split** (`GroupKFold` by `profile`) — the test set holds configurations the model never saw.
3. Train LightGBM for `mode`, `pfs`, `cipher_mode`, `traffic_type`.
4. Calibrate with `CalibratedClassifierCV(method="isotonic")` and compute conformal quantiles on a held-out calibration fold (**α = 0.1**).
5. Export `models/*.joblib`, `model_card.md`, and a confusion matrix PNG.

**Accuracy targets to verify (§3.4, on held-out profiles):**
- IPsec / IKE version / IKE SA transforms ≥ 99 % (deterministic — these come from rules, not from `ml/`)
- ESP cipher mode (CBC vs GCM) ≥ 95 %
- ICV length / integrity family ≥ 95 %
- Tunnel vs Transport ≥ 90 %
- PFS on/off (when a rekey is captured) ≥ 90 %
- Traffic type in ESP (7 classes) macro-F1 ≥ 0.80 per SA, ≥ 0.70 per 5 s window
- Calibration: **ECE ≤ 0.08**

**Overfitting mitigations (§13):** profile-grouped splits · jittered generators · public datasets for testing (ISCX VPN-nonVPN 2016, CIC — §7).

## Inputs

- `dataset/features/sa_evidence.parquet` + `dataset/features/flow_windows.parquet` (the §3.3 feature contract: one SAEvidence per SA, one FlowWindow per 5 s window per SA).
- `dataset/labels.csv` (ground truth per session, from the capture manifests).
- `dataset/splits/{train,calib,test}.txt` (profile-grouped).
- Hyperparameters in `ml/configs/*.yaml`.

## Outputs

- `models/<task>/<version>/{model.joblib, calibrator.joblib, conformal.json (q̂ for α=0.1), features.json, metrics.json}` + `models/registry.json` (repo.md §6 layout).
- `ml/reports/model_card.md` (intended use, data, metrics, limitations) and `ml/reports/figures/` (confusion matrices, reliability diagram).

## Functionality / interfaces

- `make dataset` → `ml/build_dataset.py` (sessions → features + labels; uses analyzer parsers so training and inference features match exactly).
- `make train` → `ml/train.py`; `make eval` → `ml/evaluate.py`.
- `ml/splits.py` writes the profile-grouped splits.

## Boundaries (do not do)

- No inference-time logic — runtime behavior lives in `analyzer/infer/` (rules + model loading); keep feature computation identical on both sides (§3.3).
- No deep sequence models (1D-CNN / Transformer) — explicitly deferred to the full platform (§1.2); gradient boosting on flow statistics is the MVP baseline.
- Don't weaken the split: never train and test on the same profile (§3.4 step 2).
- Key size and no-rekey PFS must remain "low-confidence inferred"/"unknown" cases in evaluation reporting (§13).
