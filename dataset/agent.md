# agent.md — `dataset/` (dataset deliverable)

**Owner: Person A** (see [docs/team_split.md](../docs/team_split.md)).

**Source of truth: `docs/mvp.md` §3.2 (labels/keys), §3.4 (splits), §7 (dataset spec), §13 (limitations). Layout per `docs/repo.md` §9. Nothing here adds, removes, or reinterprets an MVP requirement.**

## Mission

Package the labeled PCAP set, extracted features, and `labels.csv`, published with the repo (§0 "Dataset" row, §7).

## What this folder must do (from mvp.md)

Exact layout and content (§7):

```
dataset/
├── README.md               # collection method, license, schema, class balance
├── labels.csv              # session_id, profile, traffic_type, all ground-truth labels
├── pcaps/                  # <profile>-<traffic>-<n>.pcapng (Git LFS or release asset)
├── keys/                   # save-keys output, for label verification only
├── features/
│   ├── sa_evidence.parquet
│   └── flow_windows.parquet
└── splits/
    ├── train.txt  calib.txt  test.txt   # grouped by profile
```

- **Target volume:** ≥ 16 profiles × 7 traffic types × 5 repetitions ≈ **560 sessions**, about **5–15 GB** of PCAP, **> 100 k labeled flow windows** (§7).
- **Ground truth:** labels come from the session manifests (§3.2) — the analyzer never consumes `keys/` for analysis; they exist **for label verification only**.
- **Baseline captures** of the same traffic with IPsec disabled are part of the story: they train/validate "IPsec present / absent" and show the metadata encryption removes (§3.2).
- **Splits are profile-grouped** so the test set holds configurations the model never saw (§3.4 step 2).
- **Optional additions:** public captures (ISCX VPN-nonVPN 2016, CIC datasets) for extra testing (§7, §12).
- **README must state limitations** (§13): WhatsApp-like generator rather than real WhatsApp (plus optional real-phone validation session), lab-overfitting mitigations, and that key size / missing-rekey PFS remain inferred/unknown cases.

## Inputs

- `data/sessions/<session_id>/` outputs from M2: pcapng + `manifest.json` + `keys/`.
- `lab/profiles/*.yaml` (for reproducing collection) and `lab/matrix.yaml` (sweep definition).

## Outputs

- The §7 tree above; produced by `make dataset` (`ml/build_dataset.py`) and packaged by `scripts/package_dataset.sh`.

## Boundaries (do not do)

- Don't mix features computed with different window sizes (5 s windows are the §3.3 contract).
- Don't publish keys together with a claim of privacy for the pcaps — keys decrypt them; that is their purpose.
- Don't relabel: labels must equal the profile that produced the session (verified against save-keys decryption, §3.2).
