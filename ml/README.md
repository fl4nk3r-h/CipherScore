# ml/ — training and evaluation (M4 offline)

Rebuild all models from `dataset/` (mvp.md §3.4 training loop):

```bash
make dataset      # ml/build_dataset.py -> dataset/features/*.parquet + labels.csv
make train        # ml/train.py -> models/*.joblib + calibrators + conformal + model card
make eval         # ml/evaluate.py -> metrics, figures, model_card.md update
```

Training loop (mvp.md §3.4):
1. Load feature Parquet + `labels.csv`.
2. **Profile-grouped split** (GroupKFold by `profile`) — the test set holds configurations the model never saw.
3. Train LightGBM for `mode`, `pfs`, `cipher_mode`, `traffic_type`.
4. Calibrate with `CalibratedClassifierCV(method="isotonic")`; conformal quantiles on a held-out calibration fold (α = 0.1).
5. Export `models/*.joblib`, `model_card.md`, confusion matrix PNG.

Accuracy targets and the ECE ≤ 0.08 gate: mvp.md §3.4.
