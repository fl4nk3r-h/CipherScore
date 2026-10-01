# CipherScope API reference

The local Python API defaults to `http://localhost:8000/api/v1`. Docker Compose publishes it at `http://localhost:8010/api/v1`; the dashboard uses that published port. Interactive OpenAPI documentation is at `/docs` on the same host and port.

## Existing IPsec analysis

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/captures` | Upload a PCAP or PCAPNG as multipart `file`; returns `capture_id` |
| `POST` | `/analyses` | Start analysis with `capture_id` or `lab_session_id`, optional `rule_pack`; returns `analysis_id` |
| `GET` | `/analyses` | List recent analyses |
| `GET` | `/analyses/{id}` | Status and summary |
| `GET` | `/analyses/{id}/sas` | SA evidence and inference tags |
| `GET` | `/analyses/{id}/traffic` | Traffic windows and classifications |
| `GET` | `/analyses/{id}/findings` | Posture findings |
| `GET` | `/analyses/{id}/threat-matrix` | Posture risk matrix; distinct from passive threat alerts |
| `GET` | `/analyses/{id}/reports/{filename}` | `executive.pdf`, `technical.pdf`, `report.json`, or `findings.csv` |
| `GET` | `/analyses/{id}/events` | SSE analysis progress |
| `GET` | `/lab/profiles` | Lab profiles |
| `POST` | `/lab/runs` | Start lab runner with `profile_ids` and `traffic_types` |
| `GET` | `/lab/sessions` | Captured lab manifests |
| `GET` | `/healthz`, `/version` | Health and model registry |

Without promoted models, observable IPsec facts and rule-based inferences still appear. PFS and CHILD_SA DH return `unknown` when the capture has no rekey evidence. Do not treat a configured proposal as an observed encrypted transform.

## Passive threats

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/threats/replay` | Queue replay of an uploaded `capture_id`; returns `run_id` |
| `GET` | `/threats/alerts` | Recent persisted alerts; optional `limit` (1–500) and `threat_class` |
| `GET` | `/threats/events` | SSE `alert`, `completed`, `failed`, `stopped`, and heartbeat events |
| `POST` | `/threats/live/start` | Start incremental capture from configured mirror interface |
| `POST` | `/threats/live/stop` | Stop that capture |

Upload with `POST /captures`, then replay with `POST /threats/replay` and `{"capture_id":"cap_..."}`. Each alert has `id`, Unix `timestamp`, `flow_id`, `threat_class`, `severity`, `confidence`, `evidence`, `source`, and `model_version`. The classes are `ddos`, `port_scan`, `data_exfiltration`, `beaconing`, `dga`, `dns_tunneling`, and `encrypted_malware`. The last class indicates suspicion from public TLS/QUIC metadata, not known encrypted payload content. `model_version="heuristic-v1"` identifies a heuristic score rather than calibrated model probability.

Set `CS_INTERNAL_CIDRS` for direction-based evidence. Live mode also needs `CS_LIVE_ENABLED=true`, a visible `CS_LIVE_INTERFACE`, `tcpdump`, and capture privileges. The older `/live/*` routes remain the separate IPsec rolling-window workflow and do not publish threat alerts. Uploads are limited to 500 MB by default. See [collection and training](threat_training.md) for data requirements and validation limits.
