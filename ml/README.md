# Training and evaluation

See [the collection and threat training guide](../docs/threat_training.md) for data sources, labels, commands, and current model status.

`make dataset`, `make train`, and `make eval` extract production IPsec features, train all six heads on disjoint profile folds, and write metrics and a model card. `ml.build_threat_dataset` and `ml.import_domains` prepare threat features; `make threat-train` trains four calibrated threat models. Artifact promotion is gated by held-out metrics. The checked-in registry has no trained versions.
