# Versioned inference artifacts

`registry.json` lists the promoted version for each of the six IPsec and four learned threat tasks. Every entry is currently `null`: the available captures cannot support held-out training. The IPsec `models.Ensemble` facade and analyzer load the same artifact contract. A promoted version contains `model.joblib` (including its probability calibrator), `features.json` (ordered serving features), `conformal.json`, and `metrics.json`. Missing artifacts yield `unknown` for model-only IPsec attributes; the threat engine marks its fallback scores as `heuristic-v1`.

The training steps and dataset requirements are in [the guide](../docs/threat_training.md).
