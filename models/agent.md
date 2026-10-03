# `models/` serving contract

This folder contains six IPsec serving heads and the registry for their artifacts and four optional learned threat detectors. See [the model contract](../docs/models.md) and [training guide](../docs/threat_training.md). Check `registry.json` for current promoted versions.

The artifact format is `<task>/<version>/{model.joblib,features.json,conformal.json,metrics.json}`. `model.joblib` includes the fitted probability calibrator. The serving facade preserves ordered features, estimator class indices, prediction tags, confidence, and conformal sets. A missing registry entry, artifact, or required feature yields an unknown IPsec prediction. PFS and CHILD_SA DH also require captured rekey evidence in the analyzer. The threat engine labels fallback scores `heuristic-v1`.

Serving is read-only. It does not parse traffic, train, probe, decrypt, or inspect lab keys. Model training belongs in `ml/`; observable and rule-based IPsec inferences belong in `analyzer/infer/`.
