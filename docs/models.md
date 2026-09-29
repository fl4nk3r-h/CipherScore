# `models/` — M4 Classifier Ensemble: implementation notes

**Status:** implemented (MVP subset). **Companion to** [LOW_LEVEL_DESIGN.md](./LOW_LEVEL_DESIGN.md) §1.2/§6, [MODULES.md](./MODULES.md) M4, [mvp.md](./mvp.md) §3.4/§6/§13, and [repo.md](./repo.md) §6.

This document records **how the `models/` serving package is built**, so a reader can map every doc requirement to a file and a function. It does not restate the requirements and does not extend the MVP surface. The folder's contract is in [`../models/agent.md`](../models/agent.md); the artifact layout is owned by repo.md §6.

---

## 1. Two responsibilities in one folder

| Responsibility | Owner | Files |
|---|---|---|
| **Versioned artifacts** written by `make train` | `ml/train.py` | `registry.json`, `<task>/<version>/…` |
| **In-process serving** used by the analysis engine | `models/` | `base.py`, `mode.py`, `cipher.py`, `integrity.py`, `pfs.py`, `dh_group.py`, `traffic.py`, `ensemble.py` |

The serving package is a thin, dependency-light layer over the artifacts. It never trains and never parses; it only loads a calibrated estimator, orders features, and converts probabilities into the documented `Prediction` shape.

---

## 2. Module map

| File | Public names | Purpose |
|---|---|---|
| `base.py` | `Source`, `Attribute`, `FeatureAttribution`, `Prediction`, `InferenceRequest`, `InferenceResponse`, `HeadModel`, `default_models_dir`, `load_registry`, `resolve_version`, `conformal_set`, `conformal_confidence` | Domain types (LLD §1.2), serving contract (LLD §6.5), artifact loader, conformal/confidence math, SHAP explainability |
| `mode.py` | `ModeModel` | `mode` head (Tunnel/Transport) |
| `cipher.py` | `CipherModel`, `EncFamilyModel` | `enc_family` head (AES-CBC/AES-GCM/other); task key `cipher` |
| `integrity.py` | `IntegrityModel` | `integ` head (ICV family) |
| `pfs.py` | `PfsModel` | `pfs` head (boolean) |
| `dh_group.py` | `DhGroupModel` | `dh_group` head (nearest-match + GBDT) |
| `traffic.py` | `TrafficModel`, `TrafficClassModel` | `traffic_class` head (7 classes) |
| `ensemble.py` | `HEADS`, `Ensemble` | LLD §6.5 facade over the heads |

`HEADS` is keyed by the registry/task name (`mode`, `cipher`, `integ`, `pfs`, `dh_group`, `traffic`) so `InferenceRequest.heads` and `Ensemble(heads=[...])` select heads by the same names used in `registry.json`.

---

## 3. Serving flow

```text
InferenceRequest(tunnel_id, features, heads, tokens)
        │
        ▼
Ensemble.predict(req)
        │  for each requested head
        ▼
HeadModel.predict(features)
        │  1. _vector()        order features by features.json (drift guard)
        │  2. _proba()         model.predict_proba -> [p0..pn]
        │  3. conformal_set()  cumulative mass >= 1 - qhat
        │  4. _calibrate()     optional separate binary calibrator
        │  5. confidence       p(top) or p(top)/|C|
        │  6. _explain()       TreeSHAP, else feature_importances_
        ▼
Prediction(attribute, value, source="inferred", confidence,
           prediction_set, alpha, model_version, explanation)
        │
        ▼
InferenceResponse(predictions, latency_ms, model_versions)
```

`InferenceRequest`/`InferenceResponse` are exactly LLD §6.5. `tokens` is carried for the deferred Tier-3 sequence head and is unused by the MVP tabular heads.

---

## 4. Artifact contract (repo.md §6)

```
models/
├── registry.json                 # {"mode": "v0.1.0", "pfs": "v0.1.0", ...}
└── <task>/<version>/
    ├── model.joblib              # CalibratedClassifierCV (ml/train.py dumps the calibrated model)
    ├── calibrator.joblib         # optional separate binary isotonic calibrator
    ├── conformal.json            # {"q": q-hat} for alpha = 0.1
    ├── features.json             # ordered feature names (drift guard)
    └── metrics.json              # macro_f1, ece, ...
```

Loading rules in `HeadModel`:

1. `registry.json` → version for `task`; no entry ⇒ **not trained**.
2. `model.joblib` must exist; otherwise **not trained**.
3. `joblib` is imported **lazily**; if the ML stack is absent the head still exists but reports unknown.
4. `features.json` fixes the feature order passed to `predict_proba`; missing features default to `0.0`.
5. `classes_` is read from the estimator so label order can never drift; the subclass list is only a default.
6. `conformal.json` sets q̂ (default `0.1`).

Because `ml/train.py` persists the `CalibratedClassifierCV` itself, the underlying LightGBM model is resolved through `HeadModel._tree_estimator()` (`calibrated_classifiers_[i].estimator`) for SHAP and feature importances.

---

## 5. Confidence and conformal sets (LLD §6.3)

- **Prediction set** (`conformal_set`): sort classes by probability and add them until the cumulative mass reaches `1 − q̂` (APS-style). A confident model yields a singleton.
- **Confidence** (`conformal_confidence`): `p̂(top)` if `|Ĉ| == 1`, else `p̂(top) / |Ĉ|`.
- **Calibration:** if a separate `calibrator.joblib` exists it is applied to the top probability before the confidence is computed. In the MVP `ml/train.py` writes the calibrated estimator as `model.joblib`, so the separate calibrator is usually absent.
- **Finding-level confidence** is the minimum confidence over the predictions a finding depends on; that aggregation lives in `analyzer/posture`, not in this package (mvp.md §3.5).

---

## 6. Explainability (LLD §6.4)

`HeadModel._explain(features)` returns the top-k `FeatureAttribution` list stored on `Prediction.explanation`:

1. **Preferred:** `shap.TreeExplainer` over the fitted tree estimator. Per-class SHAP values are stacked, absolute values are averaged over classes, and the result is sorted by magnitude. This covers the GBDT heads (the MVP path).
2. **Fallback:** the estimator's global `feature_importances_` (also sorted). This keeps `explanation` populated when `shap` is not installed.
3. Feature names come from `features.json`; with no feature order there is nothing to name, so `explanation` is empty.

Integrated Gradients for the Tier-3 Transformer is full-platform only (deferred, mvp.md §1.2).

---

## 7. Honest fallback

The package mirrors `analyzer/infer/loader.py`: absence of a model is a normal state, not an error.

| Situation | Result |
|---|---|
| No `registry.json` entry | `value=None`, `confidence=0.0`, `prediction_set=[]`, `model_version="<task>-untrained"` |
| `model.joblib` missing | same |
| `joblib`/`lightgbm` not installed | same |
| `predict_proba` raises | same |
| No `conformal.json` | q̂ defaults to `0.1` |
| No `features.json` | features passed in insertion order; no named SHAP |

This is what lets the ensemble run before `make train` and keeps tags honest (mvp.md §3.4 "say unknown instead of guessing").

---

## 8. Usage

```python
import uuid
from models import Ensemble, InferenceRequest

ensemble = Ensemble()                       # reads CS_MODELS_DIR / models/
response = ensemble.predict(InferenceRequest(
    tunnel_id=uuid.uuid4(),
    features={"outer_eq_inner_hint": 1.0, "min_esp_payload_len": 60, "ttl_outer": 64},
    heads=["mode", "pfs"],                  # empty => all registered heads
))
for prediction in response.predictions:
    print(prediction.attribute, prediction.value,
          prediction.confidence, prediction.prediction_set)
```

`Ensemble.model_versions()` returns the loaded version per head (the API exposes this via `GET /version`, repo.md §7).

---

## 9. MVP vs full platform

| Doc requirement | MVP implementation | Full-platform note |
|---|---|---|
| LLD §6.1 heads | `mode`, `enc_family`, `integ`, `pfs`, `dh_group`, `traffic_class` present | `integ`/`dh_group` await training; MVP computes them deterministically in `analyzer/infer` |
| LLD §6.5 serving | `InferenceRequest`/`InferenceResponse` | identical |
| LLD §6.3 calibration | split-conformal + confidence formula | MVP uses LightGBM isotonic + `conformal.json`; full platform uses MAPIE (MODULES M4) |
| LLD §6.4 explainability | TreeSHAP with importance fallback | Integrated Gradients for the Transformer is deferred (§1.2) |
| LLD §6.1 traffic head | LightGBM on `FlowWindow` | Transformer + logistic stacking is deferred (§1.2) |
| Artifacts | `joblib` (repo.md §6) | ONNX `model_bundle_vX.Y.Z.tar` with cosign (MODULES M4) |

---

## 10. Verification record

Checked against the docs and exercised locally:

- `ruff check models/` — clean.
- **Head contract:** injected-model and artifact-loaded predictions return the documented `Prediction` fields; `pfs` returns a boolean value with string `prediction_set`; `prediction_set` respects q̂.
- **Artifact loading:** `registry.json` → `<task>/<version>/` resolution; `features.json` ordering; `conformal.json` q̂; `model_version` propagation.
- **Ensemble:** all six heads run; unregistered heads return `value=None`/`confidence=0.0`; `model_versions` aggregates.
- **Real artifacts:** a calibrated LightGBM model (`CalibratedClassifierCV`) trained and persisted exactly as `ml/train.py` does, then served through `ModeModel` and `TrafficModel`; TreeSHAP produced named attributions; the non-tree fallback path returned global importances.

Not covered by these checks (full-platform, deferred): Transformer/Tier-3 sequence path, MAPIE calibrators, ONNX bundles, Integrated Gradients.
