# Training and evaluation

See [the collection and threat training guide](../docs/threat_training.md) for data sources, labels, commands, and current model status.

`make train` rebuilds production IPsec features from saved Lab sessions and trains all six heads on disjoint profile folds; `make eval` writes metrics and a model card. `make train-cached` retrains from the existing Parquet snapshot without rescanning PCAPs. `make dataset` can also be run independently to inspect accepted and rejected captures. `ml.build_threat_dataset` and `ml.import_domains` prepare threat features; `make threat-train` trains four calibrated threat models. Artifact promotion is gated by held-out metrics.
