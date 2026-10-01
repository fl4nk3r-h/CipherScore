# CipherScope run sequence

This page describes the implemented workflows. The [MVP specification](mvp.md) and [repository design](repo.md) also include planned components; use this page for current commands.

## Local IPsec analysis

From the repository root, install Python and dashboard dependencies:

```bash
uv sync --extra dev
cd web && pnpm install && cd ..
```

Start the API and dashboard in separate terminals:

```bash
uv run uvicorn api.main:app --reload --port 8000
```

```bash
cd web
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1 pnpm dev
```

Open `http://localhost:3000`. Upload a PCAP through the New Analysis screen or call `POST /api/v1/captures`, then `POST /api/v1/analyses` with the returned `capture_id`. Follow `GET /api/v1/analyses/{id}/events`, then fetch summary, SAs, traffic, findings, or reports. API startup migrates SQLite and loads any registered models. All checked-in registry entries are currently null, so model-only values stay unknown; rules and observable IKE/ESP evidence still work.

`make up` is not currently a full dashboard deployment: `docker-compose.yml` refers to `web/Dockerfile`, which is absent. The API Docker image builds, and `cd web && pnpm build` compiles the dashboard. Compose publishes the API at port 8010 if running that service alone; use `NEXT_PUBLIC_API_URL=http://localhost:8010/api/v1` for a local dashboard against it.

## Passive threat replay and mirror

The `/threats` dashboard page uploads a PCAP and queues replay automatically. The API sequence is `POST /captures` → `POST /threats/replay` with `{"capture_id":"..."}` → `GET /threats/alerts` or subscribe to `GET /threats/events`. Replay and mirror pass parsed packets through the same incremental detector. Alerts are stored in SQLite and repeated alerts from the same flow or destination are suppressed for a 30-second interval.

For a local mirror, set `CS_INTERNAL_CIDRS`, `CS_LIVE_ENABLED=true`, and `CS_LIVE_INTERFACE` to an interface that receives copied traffic, then call `POST /threats/live/start`. Call `/threats/live/stop` to stop it. `tcpdump` and interface capture privileges are required. A Docker container needs both capture capability and access to the mirror's network namespace. The older `/live/*` routes are for IPsec rolling-window analysis and do not feed `/threats` alerts.

The detectors use no decryption and send no traffic across the monitored link. DDoS, scanning, and directional-volume exfiltration use rules; beaconing, DGA, DNS tunnelling, and suspicious encrypted sessions use heuristics until calibrated models are promoted. `heuristic-v1` scores are not calibrated probabilities.

## StrongSwan data and model training

```bash
make lab-all
make dataset
make train
make eval
```

`make lab-all` uses `lab/matrix.yaml` to select profiles, traffic, and repetitions. The runner skips already valid session IDs, captures IKE plus protected traffic, triggers CHILD_SA rekey, and writes a manifest only after capture and negotiated SA checks. `make dataset` writes shared serving/training features plus labels, SHA-256 provenance, and rejected-session reasons. `make train` attempts six IPsec heads using disjoint profile folds for fitting, probability calibration, conformal calibration, and testing. It promotes only heads that pass held-out gates.

**Current outcome:** 30 older sessions were rejected for insufficient packets. Two new p01 captures produced 8 SA rows and 14 traffic windows, all from one profile. The trainer ran and left all six IPsec heads untrained. See [the model card](../ml/reports/model_card.md) and [training report](../ml/reports/training.json). Collect more valid, class-diverse profiles before relying on learned IPsec predictions.

For learned threat detectors, prepare labeled capture intervals with `python -m ml.build_threat_dataset manifest.jsonl` or labeled DGA domains with `python -m ml.import_domains domains.csv`, then run `make threat-train`. Dataset sources, manifest fields, split policy, and limits are in [the training guide](threat_training.md). The threat registry also remains untrained.

## Verification

`make test` runs Ruff and the unit/integration suite; the last run passed 68 tests. `cd web && pnpm build` passed. The API Docker image built. A 10,000-flow detector-only smoke benchmark reached 13,055 flows/s and 0.086 ms p95 processing per record, with zero reported drops. This does not measure PCAP decode, SQLite persistence, OS capture loss, or evidence-to-alert delay. The sustained 1,000 flows/s and five-second end-to-end targets remain unverified.
