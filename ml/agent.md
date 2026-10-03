# `ml/` training contract

Use [the current data and training guide](../docs/threat_training.md) and [model contract](../docs/models.md) for implemented behavior. The older [MVP specification](../docs/mvp.md) describes target requirements.

`ml.build_dataset` accepts only usable strongSwan sessions, extracts the same features served at inference, and writes Parquet, labels, provenance hashes, and rejection reasons. `ml.train` targets all six IPsec heads (`mode`, `cipher`, `integ`, `pfs`, `dh_group`, `traffic`). It uses profile-disjoint fitting, probability calibration, conformal calibration, and testing. PFS and CHILD_SA DH rows require rekey evidence. Promote only after held-out metrics pass. `ml.evaluate` writes the model card and metric summary.

`ml.build_threat_dataset` accepts scoped JSONL capture labels and re-extracts features through the production threat engine. `ml.import_domains` converts labeled DGA CSV data to production lexical features. `ml.train_threats` trains beaconing, DGA, DNS tunnelling, and suspicious encrypted-session models with scenario-disjoint folds. Source datasets and their label limits are listed in the guide. Rules handle DDoS, scanning, and outbound-volume exfiltration.

Only heads that pass the quality gates may enter the registry. No training data may leak from a test profile, host, or scenario into fitting or either calibration fold.
