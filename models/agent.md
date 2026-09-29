# agent.md — `models/` (M4 Classifier Ensemble: artifacts + serving package)

**Owner: Person A** (see [docs/team_split.md](../docs/team_split.md); `ml/agent.md` names the same owner for the training side).

**Source of truth: `docs/mvp.md` §3.4 (methods, confidence, targets), §6 (data model), §13 (risks); `docs/repo.md` §6 (artifact layout); `docs/LOW_LEVEL_DESIGN.md` §1.2 and §6 (domain types, heads, calibration, serving contract); `docs/MODULES.md` M4. Nothing here adds, removes, or reinterprets an MVP requirement.**

## Mission

Hold the versioned model artifacts written by `make train` (repo.md §6) **and** the in-process M4 serving package that turns those artifacts into tagged `Prediction` objects with calibrated confidence, conformal sets, and SHAP attributions (LLD §6).

## What this folder must do (from mvp.md / LLD)

**Artifact layout (repo.md §6).** `registry.json` maps each task to a version; each version directory holds `model.joblib`, `calibrator.joblib`, `conformal.json` (q̂ for α = 0.1), `features.json` (ordered feature list, drift guard), and `metrics.json`.

**Serving package (LLD §1.2, §6).**

| Module | Provides |
|---|---|
| `base.py` | `Prediction`, `FeatureAttribution` (LLD §1.2); `InferenceRequest` / `InferenceResponse` (LLD §6.5); `HeadModel` loader + conformal/confidence logic |
| `mode.py` | `mode` head — Tunnel vs Transport |
| `cipher.py` | `enc_family` head — AES-CBC / AES-GCM / other |
| `integrity.py` | `integ` head — ICV / integrity family |
| `pfs.py` | `pfs` head — PFS on/off |
| `dh_group.py` | `dh_group` head — DH group of encrypted rekeys |
| `traffic.py` | `traffic_class` head — 7 traffic classes |
| `ensemble.py` | `Ensemble.predict(req)` facade over the heads (LLD §6.5) |

**Heads map to the LLD §6.1 table**, whose primary sources are the §5.2–§5.5 features produced by M3. The four MVP-trained tasks are `mode`, `pfs`, `cipher`, `traffic` (§3.4); `integ` and `dh_group` have no MVP artifact and therefore answer `value=None`, confidence `0.0` until trained.

**Confidence is conformal (LLD §6.3):** the prediction set is the cumulative-probability set at `1 − q̂`; `confidence = p̂(top)` when the set is a singleton, else `p̂(top) / |Ĉ|`. Findings inherit the **minimum** confidence of the predictions they depend on (that rule lives in `analyzer/`, not here).

**Explainability (LLD §6.4):** TreeSHAP over the underlying tree estimator fills `Prediction.explanation` (top-k); when `shap` is unavailable the model's global `feature_importances_` is used instead so a prediction is never silently unexplained.

## Inputs

- `models/registry.json` + `<task>/<version>/` artifacts written by `ml/train.py` (repo.md §6).
- Feature vectors from M3 (§5.2–§5.5); optional token sequences for the deferred Tier-3 model.
- Environment: `CS_MODELS_DIR` (defaults to `models/`, repo.md §11).

## Outputs

- `Prediction` objects (`value`, `prediction_set`, `confidence`, `alpha`, `model_version`, `explanation`) and an `InferenceResponse` (`predictions`, `latency_ms`, `model_versions`).

## Honesty contract (mvp.md §3.4, §13 — mandatory)

- **Never present an unobserved value as observed.** The serving package only emits `source="inferred"`; Tier-1 observations are tagged in `analyzer/infer/rules_based.py`.
- **Never guess.** With no registry entry, no artifact, or no ML stack installed, a head returns `value=None` with confidence `0.0` — the same fallback as `analyzer/infer/loader.py`. Key size and no-rekey PFS stay low-confidence/unknown (§13).
- The package is read-only over artifacts: it never trains, and it never reads lab `save-keys` output (§3.2).

## Boundaries (do not do)

- No parsing, feature extraction, rule evaluation, scoring, or reporting — those live in `analyzer/` and `ml/`.
- No HTTP/DB access: the API imports this package, not the other way around (repo.md §4, api/agent.md).
- No deep sequence models in the MVP path (§1.2); the `tokens` field is reserved for the full-platform Tier-3 head.
- The MVP artifact format is `joblib` (repo.md §6). The LLD §6.1/MODULES M4 ONNX `model_bundle` and MAPIE calibrators are full-platform; do not claim them as MVP capabilities.

See [docs/models.md](../docs/models.md) for the implementation details and verification record.
