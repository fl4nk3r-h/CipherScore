# Model serving and training contract

CipherScope defines six IPsec heads: `mode`, `cipher`, `integ`, `pfs`, `dh_group`, and `traffic`. `models.Ensemble` serves them in-process, and `analyzer/infer/ensemble.py` calls that same facade during analysis. The traffic head receives actual five-second flow windows. SA and traffic feature names and ordering come from `analyzer/infer/features.py`, which is also used by `ml.build_dataset`.

Four learned passive threat tasks share the artifact loader: `beaconing`, `dga`, `dns_tunneling`, and `encrypted_malware`. DDoS, scanning, and non-DNS outbound-volume exfiltration use rules. The checked-in `models/registry.json` has ten null values: **none is a trained, promoted model**. The threat engine marks its interim detector scores `heuristic-v1`.

## Artifact layout

```text
models/
├── registry.json
└── <task>/<version>/
    ├── model.joblib       # fitted estimator with isotonic probability calibration
    ├── features.json      # ordered inference feature names
    ├── conformal.json     # q for alpha=0.1
    └── metrics.json       # held-out results and split information
```

A legacy separate `calibrator.joblib` can be loaded if present, but the current trainer writes calibration inside `model.joblib`. `HeadModel` reads `classes_` from the fitted estimator, passes a DataFrame with the exact feature order to `predict_proba`, and returns `value=None` and confidence 0 if an artifact or required feature is absent. Its conformal set uses the score `1 − p(true)`; eligible labels satisfy `p(label) ≥ 1 − q`. Explainability uses TreeSHAP when available, then fitted tree feature importances if present.

PFS and CHILD_SA DH require captured rekey evidence even if a model is registered. An ordinary ESP stream cannot reveal its key size. The analyzer may report separately tagged observable facts or rule-based mode/cipher/integrity assessments; these are not trained model outputs.

## Promotion and status

`make dataset` verifies lab captures, derives production feature vectors, and records hashes and rejected sessions. `make train` fits the six IPsec heads using distinct profile folds for fitting, probability calibration, conformal calibration, and held-out testing. It registers only heads meeting macro F1, expected calibration error, and conformal coverage gates. `make eval` writes [the model card](../ml/reports/model_card.md) and [metric summary](../ml/reports/metrics_eval.json). `make threat-train` fits four binary threat models on scenario-disjoint folds and requires held-out F1, PR-AUC, and calibration gates.

Two valid p01 smoke captures currently give 8 SA rows and 14 windows; they are insufficient for training or testing across profiles. The six-head training report is [here](../ml/reports/training.json). Threat training data has not been imported. See [the data and operating guide](threat_training.md) for source datasets, labels, and known validation limits.
