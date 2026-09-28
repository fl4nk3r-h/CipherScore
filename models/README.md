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
