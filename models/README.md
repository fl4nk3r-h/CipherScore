# models/ — versioned artifacts (repo.md §6)

Populated by `make train`. `registry.json` maps each task to a version:

```
models/
├── registry.json                      # { "traffic": "v0.3.0", "mode": "v0.2.1", ... }
├── traffic/<version>/
│   ├── model.joblib
│   ├── calibrator.joblib
│   ├── conformal.json                 # q-hat for alpha = 0.1
│   ├── features.json                  # ordered feature list (guards against drift)
│   └── metrics.json
└── mode/..., pfs/..., cipher/...
```

`analyzer/infer/loader.py` refuses to guess: with no registry entry the
ensemble falls back to rules-only inference and tags stay honest (mvp.md §3.4).

## Serving package (M4)

This folder also contains the in-process **M4 classifier ensemble** that turns
the artifacts above into tagged `Prediction` objects (LLD §1.2, §6):

```
models/
├── base.py        # Prediction, InferenceRequest/Response, HeadModel, conformal math, SHAP
├── mode.py        # mode head          (tunnel | transport)
├── cipher.py      # enc_family head    (aes-cbc | aes-gcm | other)
├── integrity.py   # integ head         (ICV family)
├── pfs.py         # pfs head           (on | off)
├── dh_group.py    # dh_group head      (DH group of encrypted rekeys)
├── traffic.py     # traffic_class head (7 classes)
└── ensemble.py    # Ensemble.predict(req) facade
```

```python
from models import Ensemble, InferenceRequest

response = Ensemble().predict(InferenceRequest(tunnel_id=..., features={...}))
```

A head with no registry entry (or no `joblib`/`lightgbm` installed) returns
`value=None` and confidence `0.0` instead of guessing — the same honest
fallback as `analyzer/infer/loader.py`. See [`agent.md`](./agent.md) for the
folder contract and [`../docs/models.md`](../docs/models.md) for the
implementation notes and verification record.

