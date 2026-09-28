# CipherScope MVP: Repository Structure

> This is the repository layout for the **MVP prototype** in [mvp.md](./mvp.md). It is a trimmed version of the full monorepo in [REPO_STRUCTURE.md](./REPO_STRUCTURE.md). The folder names are the same, so the MVP can grow into the full platform without a restructure.

Repository name: `cipherscope-mvp`

---

## 1. Top-level layout

```
cipherscope-mvp/
├── README.md                  # Quick start, demo steps, screenshots
├── LICENSE
├── Makefile                   # Every workflow as one command (see §10)
├── docker-compose.yml         # api + web + capture
├── docker-compose.lab.yml     # strongSwan gateways, clients, servers
├── .env.example               # Ports, paths, feature flags (no secrets needed)
├── pyproject.toml             # Python workspace (uv / pip) + ruff + pytest config
├── .github/workflows/ci.yml   # Lint, unit tests, parser golden tests, web build
│
├── lab/                       # M1 LabForge: VPN testbed generation
├── capture/                   # M2 CaptureMesh: capture + labeling
├── analyzer/                  # M3 + M4 + M5 + M6: the core Python package
├── ml/                        # Training, evaluation, model cards
├── api/                       # FastAPI service wrapping analyzer/
├── web/                       # Next.js 16 dashboard
├── rules/                     # YAML security rule packs
├── dataset/                   # Dataset deliverable (LFS / release asset)
├── models/                    # Trained model artifacts (versioned)
├── data/                      # Runtime storage: uploads, sqlite, reports (git-ignored)
├── tests/                     # Cross-module tests + reference PCAPs
├── scripts/                   # Helper scripts (demo, packaging, sanity checks)
└── docs/                      # mvp.md, repo.md, architecture, API, model card
```

| Folder | Module | Language | Runs in container |
|---|---|---|---|
| `lab/` | M1 LabForge | YAML, Jinja2, Bash, Python | `lab-*` |
| `capture/` | M2 CaptureMesh | Python, tcpdump | `capture` |
| `analyzer/` | M3 Evidence Fusion, M4 Classifier, M5 Posture, M6 Reports | Python | `api` |
| `ml/` | Offline training for M4 | Python | host or `api` image |
| `api/` | REST + SSE service | Python (FastAPI) | `api` |
| `web/` | Dashboard | TypeScript (Next.js) | `web` |
| `rules/` | M5 rule packs | YAML | mounted into `api` |

---

## 2. `lab/`: VPN testbed (M1 LabForge)

```
lab/
├── README.md                          # Topology, adding profiles, troubleshooting
├── profiles/                          # One YAML per VPN configuration
│   ├── _schema.json                   # JSON Schema that validates every profile
│   ├── p01-t-aes128cbc-sha256-modp2048-pfs-v4.yaml
│   ├── p02-x-aes128cbc-sha256-modp2048-nopfs-v4.yaml
│   ├── p03-t-aes256cbc-sha1-modp1024-nopfs-v4.yaml   # deliberately weak
│   ├── ...                                            # p04 – p15
│   └── p16-x-ah-sha256-modp2048-pfs-v4.yaml           # optional AH
├── matrix.yaml                        # Which profiles × traffic × repetitions to run
├── templates/
│   ├── swanctl.conf.j2                # strongSwan connection template
│   ├── strongswan.conf.j2             # Enables save-keys, logging
│   └── ipsec.conf.ikev1.j2            # Legacy template for IKEv1 profiles
├── images/
│   ├── gateway/Dockerfile             # strongSwan 5.9+ (charon + swanctl + save-keys)
│   ├── client/Dockerfile              # Traffic generators (Chromium, SIPp, ffmpeg, swaks, iperf3)
│   └── server/Dockerfile              # Nginx (web + HLS), Postfix/Dovecot, SIPp UAS, chat server
├── traffic/                           # One generator per traffic class
│   ├── icmp.sh
│   ├── web.py                         # Playwright headless browsing script
│   ├── email.sh                       # swaks SMTP + IMAP fetch, attachment sizes varied
│   ├── voip/
│   │   ├── uac.xml                    # SIPp caller scenario
│   │   ├── uas.xml                    # SIPp callee scenario
│   │   └── media/                     # G.711 / Opus RTP pcaps
│   ├── video.sh                       # ffmpeg HLS pull at several bitrates
│   ├── messaging/
│   │   ├── bot.py                     # WhatsApp-like WebSocket chat bot
│   │   └── timing_profile.json        # Message size/timing distributions
│   └── bulk.sh                        # iperf3 / scp
├── runner/
│   ├── __main__.py                    # `python -m lab.runner run --profiles p01,p07`
│   ├── render.py                      # profile YAML → swanctl.conf
│   ├── orchestrate.py                 # bring up SA, start capture, run traffic, tear down
│   └── verify.py                      # swanctl --list-sas checks, ESP presence check
└── network/
    └── bridges.yaml                   # Dual-stack subnets (172.30.0.0/24, fd30::/64, inner nets)
```

**Naming convention for profiles:** `pNN-<mode>-<cipher><integ>-<dh>-<pfs>-<ipfamily>.yaml`, where `t` is tunnel and `x` is transport.

---

## 3. `capture/`: capture and labeling (M2 CaptureMesh)

```
capture/
├── Dockerfile                         # tcpdump + Python helper
├── capture.py                         # Start/stop tcpdump per session, file rotation
├── manifest.py                        # Writes manifest.json with ground-truth labels
├── keys.py                            # Collects strongSwan save-keys output per session
├── baseline.py                        # Records the same traffic with IPsec disabled
├── live.py                            # Rolling 10 s window capture for live mode
└── schemas/
    └── manifest.schema.json
```

Output per session (written to `data/sessions/<session_id>/`):

```
p07-voip-0003/
├── p07-voip-0003.pcapng
├── manifest.json
└── keys/
    ├── esp_sa
    └── ikev2_decryption_table
```

---

## 4. `analyzer/`: core Python package (M3–M6)

This package holds all the logic and knows nothing about HTTP. The API and CLI both import it.

```
analyzer/
├── __init__.py
├── cli.py                             # `cipherscope analyze capture.pcapng --out report/`
├── config.py                          # Paths, thresholds, feature window size
├── models.py                          # Pydantic domain models: SAEvidence, FlowWindow, Inference, Finding, Report
│
├── parse/                             # M3 Evidence Fusion: parsing
│   ├── reader.py                      # Streaming pcap/pcapng reader (dpkt)
│   ├── demux.py                       # ESP / AH / IKE / NAT-T / other
│   ├── ike.py                         # IKEv1 + IKEv2 header, SA/transform, KE, Notify, Vendor ID
│   ├── ike_constants.py               # Transform IDs, DH groups, exchange types
│   ├── esp.py                         # SPI, seq, length, direction
│   ├── ah.py                          # AH header parse (optional profile)
│   └── sa_tracker.py                  # Groups packets by SPI, links rekeys, lifetimes, replay checks
│
├── features/                          # M3 Evidence Fusion: features
│   ├── esp_structure.py               # CBC/GCM + ICV hypothesis tests, size offsets
│   ├── flow_windows.py                # 5 s window statistics for the traffic classifier
│   └── store.py                       # Parquet writer/reader
│
├── infer/                             # M4 Classifier Ensemble
│   ├── ensemble.py                    # Merges rules + ML into tagged Inference objects
│   ├── rules_based.py                 # Deterministic inferences (IKE version, IKE SA suite)
│   ├── mode.py                        # Tunnel vs Transport
│   ├── pfs.py                         # PFS from CREATE_CHILD_SA size + model
│   ├── cipher.py                      # ESP cipher mode, ICV, key-size prior
│   ├── traffic.py                     # Traffic type per window + per SA aggregation
│   ├── calibration.py                 # Isotonic calibration wrappers
│   ├── conformal.py                   # Split-conformal prediction sets
│   └── loader.py                      # Loads models/*.joblib by version
│
├── posture/                           # M5 Posture Engine
│   ├── rule_engine.py                 # Loads YAML, evaluates safe expressions against SA context
│   ├── expressions.py                 # Sandboxed evaluator (no eval(); whitelisted operators)
│   ├── score.py                       # Risk, Security Score, grade
│   ├── matrix.py                      # 5 × 5 threat matrix
│   ├── compliance.py                  # RFC 8221 / 8247 / NIST / CNSA badge calculation
│   └── exposure.py                    # Metadata exposure from classifier confidence + mode
│
├── report/                            # M6 Report Studio
│   ├── build.py                       # Assemble report context from analysis
│   ├── render.py                      # Jinja2 → HTML → WeasyPrint PDF
│   ├── export.py                      # report.json, findings.csv
│   ├── remediation.py                 # strongSwan config snippets per finding
│   └── templates/
│       ├── base.html.j2
│       ├── executive.html.j2
│       ├── technical.html.j2
│       ├── partials/                  # score gauge, matrix, SA table, charts
│       └── report.css
│
└── pipeline.py                        # parse → features → infer → posture → report (one entry point)
```

**Core entry point** (`analyzer/pipeline.py`):

```python
def run_analysis(pcap_path: Path, rule_pack: str = "ipsec-baseline",
                 on_progress: Callable[[str, float], None] = noop) -> AnalysisResult:
    packets = reader.stream(pcap_path)
    sas, ike_msgs = sa_tracker.build(demux.classify(packets))
    on_progress("parsed", 0.30)

    windows = flow_windows.extract(sas)
    structure = esp_structure.analyze(sas)
    on_progress("features", 0.50)

    inferences = ensemble.infer(sas, ike_msgs, structure, windows)
    on_progress("inferred", 0.70)

    findings = rule_engine.evaluate(inferences, rule_pack)
    posture = score.compute(findings)
    on_progress("assessed", 0.85)

    reports = report.render.all(inferences, findings, posture)
    on_progress("completed", 1.0)
    return AnalysisResult(inferences, findings, posture, reports)
```

---

## 5. `ml/`: training and evaluation (M4 offline)

```
ml/
├── README.md                          # How to rebuild models from dataset/
├── build_dataset.py                   # sessions/ → dataset/features/*.parquet + labels.csv
├── splits.py                          # GroupKFold by profile → dataset/splits/
├── train.py                           # Trains mode / pfs / cipher / traffic models
├── evaluate.py                        # Accuracy, macro-F1, ECE, confusion matrices
├── configs/
│   ├── traffic_lgbm.yaml              # Hyperparameters
│   ├── mode_lgbm.yaml
│   ├── pfs_lgbm.yaml
│   └── cipher_lgbm.yaml
├── notebooks/
│   ├── 01_eda.ipynb                   # Feature distributions per traffic class
│   └── 02_error_analysis.ipynb
└── reports/
    ├── model_card.md                  # Intended use, data, metrics, limitations
    └── figures/                       # confusion_traffic.png, reliability_diagram.png
```

---

## 6. `models/`: versioned artifacts

```
models/
├── registry.json                      # { "traffic": "v0.3.0", "mode": "v0.2.1", ... }
├── traffic/v0.3.0/
│   ├── model.joblib
│   ├── calibrator.joblib
│   ├── conformal.json                 # q̂ for α = 0.1
│   ├── features.json                  # Ordered feature list (guards against drift)
│   └── metrics.json
├── mode/v0.2.1/...
├── pfs/v0.2.0/...
└── cipher/v0.2.0/...
```

---

## 7. `api/`: FastAPI service

```
api/
├── Dockerfile
├── main.py                            # App factory, CORS, routers, lifespan (load models)
├── settings.py                        # Pydantic settings from env
├── db.py                              # SQLite engine + migrations on startup
├── schema.sql                         # Tables from mvp.md §6
├── jobs.py                            # ThreadPoolExecutor job runner + progress bus
├── events.py                          # SSE helpers
├── routers/
│   ├── captures.py                    # POST /captures (streamed upload, size cap, sha256)
│   ├── analyses.py                    # POST/GET /analyses, /sas, /traffic, /findings, /threat-matrix
│   ├── reports.py                     # GET /analyses/{id}/reports/{kind}.pdf
│   ├── lab.py                         # /lab/profiles, /lab/runs, /lab/sessions
│   ├── live.py                        # /live/start, /live/stop, /live/events
│   └── health.py                      # /healthz, /version (model versions)
└── repositories/
    ├── captures_repo.py
    ├── analyses_repo.py
    └── findings_repo.py
```

The API contains no analysis logic. Every router calls `analyzer.pipeline` or a repository. All SQL uses parameterized queries, and uploaded file names are never used as paths: files are stored under `data/uploads/<sha256>.pcapng`.

---

## 8. `web/`: Next.js 16 dashboard

```
web/
├── package.json
├── next.config.mjs
├── app/
│   ├── layout.tsx
│   ├── page.tsx                       # Overview
│   ├── analyses/
│   │   ├── new/page.tsx               # Upload / lab session / live start
│   │   └── [id]/
│   │       ├── layout.tsx             # Tabs: Summary · SAs · Traffic · Findings · Reports
│   │       ├── page.tsx               # Summary (score, risk, confidence, matrix)
│   │       ├── sas/page.tsx
│   │       ├── traffic/page.tsx
│   │       ├── findings/page.tsx
│   │       └── reports/page.tsx
│   ├── lab/page.tsx                   # Profiles, runs, ground truth vs predicted
│   └── live/page.tsx                  # SSE live predictions
├── components/
│   ├── score-gauge.tsx
│   ├── threat-matrix.tsx
│   ├── confidence-badge.tsx           # Observed / Inferred / Unknown + %
│   ├── sa-table.tsx
│   ├── traffic-donut.tsx
│   ├── histogram-chart.tsx
│   ├── exposure-panel.tsx
│   ├── findings-list.tsx
│   ├── evidence-drawer.tsx
│   ├── upload-dropzone.tsx
│   ├── progress-stream.tsx
│   └── ui/                            # shadcn/ui components
├── lib/
│   ├── api.ts                         # Typed fetchers for the API
│   ├── types.ts                       # Mirrors analyzer/models.py
│   └── use-sse.ts                     # EventSource hook
└── hooks/
    └── use-analysis.ts                # SWR hooks per resource
```

---

## 9. `rules/`, `dataset/`, `tests/`, `scripts/`, `docs/`

```
rules/
├── ipsec-baseline.yaml                # Default pack (all 8 assessment categories)
├── cnsa2.yaml                         # Stricter pack: AES-256, ECP-384, SHA-384+
├── categories.yaml                    # Category names, descriptions, weights
└── references.yaml                    # RFC / NIST / CNSA citations used in reports

dataset/
├── README.md                          # Collection method, class balance, license, limitations
├── labels.csv
├── pcaps/                             # Git LFS / GitHub release asset
├── keys/
├── features/{sa_evidence,flow_windows}.parquet
└── splits/{train,calib,test}.txt

tests/
├── conftest.py
├── fixtures/pcaps/                    # Small reference captures (< 1 MB each) with expected JSON
│   ├── ikev2_sa_init_aes256gcm_ecp384.pcapng
│   ├── ikev1_main_mode_3des_modp1024.pcapng
│   ├── esp_cbc_sha1_tunnel_v4.pcapng
│   ├── esp_gcm_transport_v6.pcapng
│   ├── natt_esp_in_udp.pcapng
│   └── expected/*.json
├── unit/
│   ├── test_ike_parser.py
│   ├── test_esp_structure.py
│   ├── test_sa_tracker.py
│   ├── test_rule_engine.py
│   ├── test_expressions_sandbox.py
│   └── test_score.py
├── integration/
│   ├── test_pipeline_golden.py        # Every fixture pcap → expected inferences
│   └── test_api.py                    # Upload → analysis → report via TestClient
└── e2e/
    └── dashboard.spec.ts              # Playwright: upload flow renders score and report

scripts/
├── demo.sh                            # Runs the mvp.md §10 demo sequence
├── package_dataset.sh                 # Zips dataset for release
├── sanity_check.py                    # Ground truth vs prediction over all lab sessions
└── seed_demo_data.py                  # Loads 3 pre-analyzed captures for offline demo

docs/
├── mvp.md                             # MVP specification
├── repo.md                            # This file
├── api.md                             # MVP subset of the API reference
├── model_card.md → ../ml/reports/model_card.md
└── demo_video_script.md
```

---

## 10. Makefile targets

| Target | What it does |
|---|---|
| `make setup` | Install Python deps (`uv sync`), web deps (`pnpm i`), pull images |
| `make lab-up` / `make lab-down` | Start/stop the strongSwan lab (`docker-compose.lab.yml`) |
| `make lab-run PROFILES=p01,p07 TRAFFIC=voip,web` | Run the selected profiles and capture labeled sessions |
| `make lab-all` | Run `lab/matrix.yaml` (every profile × every traffic type × repetitions) |
| `make dataset` | Build Parquet features, `labels.csv`, and grouped splits |
| `make train` | Train and calibrate all models into `models/` |
| `make eval` | Metrics + figures + update `model_card.md` |
| `make up` / `make down` | Start/stop `api` + `web` + `capture` |
| `make analyze PCAP=path` | CLI analysis without the dashboard |
| `make test` | ruff + pytest (unit + integration) |
| `make e2e` | Playwright dashboard test |
| `make demo` | Seed demo data and open the dashboard |

---

## 11. `docker-compose.yml` (MVP services)

```yaml
services:
  api:
    build: ./api
    ports: ["8000:8000"]
    volumes:
      - ./data:/data
      - ./models:/models:ro
      - ./rules:/rules:ro
    environment:
      CS_DATA_DIR: /data
      CS_MODELS_DIR: /models
      CS_RULES_DIR: /rules
      CS_MAX_UPLOAD_MB: "500"
      CS_LIVE_ENABLED: "false"
    # cap_add: [NET_RAW, NET_ADMIN]   # uncomment only for live mode

  web:
    build: ./web
    ports: ["3000:3000"]
    environment:
      NEXT_PUBLIC_API_URL: http://localhost:8000/api/v1
    depends_on: [api]

  capture:
    build: ./capture
    network_mode: "container:lab-bridge-tap"   # attaches to the lab bridge
    cap_add: [NET_RAW, NET_ADMIN]
    volumes:
      - ./data/sessions:/sessions
```

---

## 12. Dependencies

**Python (`pyproject.toml`)**

| Package | Used for |
|---|---|
| `fastapi`, `uvicorn`, `sse-starlette`, `python-multipart` | API, SSE, uploads |
| `pydantic` | Domain models + settings |
| `dpkt`, `scapy` | Streaming pcap parsing, IKE decoding |
| `numpy`, `pandas`, `pyarrow` | Features, Parquet |
| `lightgbm`, `scikit-learn`, `joblib` | Models, calibration, persistence |
| `pyyaml`, `jinja2` | Rules, profiles, templates |
| `weasyprint` | PDF reports |
| `playwright` | Web traffic generator (lab only) |
| `pytest`, `ruff`, `httpx` | Tests, lint, API tests |

**Web (`web/package.json`)**: `next@16`, `react@19`, `swr`, `recharts`, `lucide-react`, `tailwindcss`, shadcn/ui components.

**Lab images**: `strongswan` (5.9+ with `save-keys`), `tcpdump`, `sipp`, `ffmpeg`, `nginx`, `postfix`, `dovecot`, `swaks`, `iperf3`, `chromium`.

---

## 13. Mapping repo to problem statement

| Problem statement part | Primary folders |
|---|---|
| (a) VPN Testbed Generation | `lab/profiles`, `lab/templates`, `lab/traffic`, `lab/runner` |
| (b) Traffic Capture | `capture/`, `data/sessions/`, `dataset/pcaps` |
| (c) AI-Based Protocol Identification | `analyzer/parse`, `analyzer/features`, `analyzer/infer`, `ml/`, `models/` |
| (d) Security Assessment | `analyzer/posture`, `rules/` |
| (e) Scores, reports, matrix, confidence | `analyzer/posture/score.py`, `analyzer/posture/matrix.py`, `analyzer/report`, `web/` |
| Deliverables | `web/` (dashboard), `analyzer/` + `models/` (AI engine), `analyzer/report` (report), `scripts/demo.sh` (video), `docs/` (documentation), `dataset/` (dataset) |

---

## 14. Growing from MVP to full platform

| MVP piece | Full-platform replacement (see REPO_STRUCTURE.md) |
|---|---|
| `api/jobs.py` thread pool | `services/worker` with a queue broker |
| SQLite in `data/` | Postgres + TimescaleDB, object storage for PCAPs |
| `capture/` single sidecar | `services/sensor` distributed agents streaming features |
| LightGBM models | Adds sequence models under `ml/models/` |
| Single analyst | `services/auth` with RBAC |

The package boundaries (`parse` → `features` → `infer` → `posture` → `report`) stay the same, so every MVP module is reused unchanged.
