# Passive threat detection and training

## Current status

The IPsec analyzer and passive threat workflow share the repository but have separate inputs, models, and reports. `/api/v1/threats` accepts uploaded PCAP replay, a configured mirror interface, alert history, and server-sent alert events. Both replay and mirror call `ThreatEngine.ingest` for each parsed packet. The ingest path transmits no packets. TLS results describe suspicious public handshake metadata; they do not establish the contents of encrypted traffic.

**The checked-in registry has no promoted model versions.** IPsec inference uses observable rules where possible and returns `unknown` for PFS and CHILD_SA DH when rekey evidence is absent. Beaconing, DGA, DNS tunnelling and encrypted-session detectors use clearly marked heuristics until independently evaluated, calibrated artifacts are promoted. DDoS, scanning and outbound-volume exfiltration use rules. The old local lab captures are unsuitable for training: 30 manifests were inspected, 30 captures were rejected by the new extraction gate. Two new p01 smoke sessions produced 8 SA rows and 14 traffic windows. Both are from one profile and cannot support profile-disjoint training.

## Collect and train IPsec models

1. Start Docker and run `make lab-all`. The matrix selects profiles, traffic types, and repetitions. Valid sessions contain an IKE exchange, at least 20 protected packets, a negotiated SA record, and an attempted CHILD_SA rekey. Existing valid session IDs are skipped on subsequent runs.
2. Run `make dataset`. `ml.build_dataset` scans the PCAPs, rejects empty captures, and writes `dataset/features/sa_evidence.parquet`, `flow_windows.parquet`, `labels.csv`, `provenance.json` with SHA-256 hashes, and `rejected.json`. It extracts the same ordered features used in serving. PFS and DH training rows require observed rekey evidence.
3. Run `make train && make eval`. Six heads (`mode`, `cipher`, `integ`, `pfs`, `dh_group`, `traffic`) use profile-disjoint training, probability calibration, conformal calibration, and test folds. The registry changes only for heads meeting held-out macro F1, calibration, and coverage gates. The model card and per-head metrics record the outcome. Profile labels must be checked against negotiated SA state before promoting a capture.

The 16-profile lab matrix gives a useful start, but some rare classes occur in only one profile. Add independent profile variants and repetitions to support every class in each split; otherwise the trainer correctly leaves that head untrained. Do not use generated packets with random ciphertext as proof of IPsec configuration inference.

## Threat data

Extract features through `ml.build_threat_dataset` from a JSONL label manifest. Each line needs `pcap`, `scenario_id`, `task`, `label` (0 or 1), and `src_ip`; use `dst_ip`, `start_ts`, and `end_ts` to scope mixed captures. For example:

```json
{"pcap":"/data/captures/scenario-01.pcap","scenario_id":"host01-day01","task":"beaconing","label":1,"src_ip":"10.1.2.3","dst_ip":"203.0.113.7","start_ts":1790000000,"end_ts":1790003600,"source":"CTU-13"}
```

Run `python -m ml.build_threat_dataset labels.jsonl`. The builder records source hashes and writes one Parquet per modeled task. For labeled domain lists, supply `domain,label,scenario_id` CSV columns to `python -m ml.import_domains domains.csv`; the importer uses the same lexical features as live DNS. `make threat-train` uses scenario-disjoint folds and promotes only models passing held-out F1, PR-AUC and calibration gates. Keep captures or domains from the same host, malware family, or generated profile in one scenario group.

Suggested primary sources and their limits:

| Detection | Source | Use |
|---|---|---|
| SYN/UDP floods and reflection | [CIC-DDoS2019](https://www.unb.ca/cic/datasets/ddos-2019.html) | Replay and rule thresholds |
| Scanning and benign control | [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | Replay and false-positive checks |
| Beaconing | [CTU-13](https://www.stratosphereips.org/datasets) | Botnet flows; verify actual periodicity in each labeled interval |
| DGA | [UMUDGA](https://github.com/Cyberdefence-Lab-Murcia/UMUDGA) | Lexical labels; add independent benign domains |
| DNS tunnelling | [CIC-Bell-DNS-EXF-2021](https://www.unb.ca/cic/datasets/dns-exf-2021.html) | DNS exfiltration and benign control |
| Suspicious encrypted TLS/QUIC | [TQH-C2](https://zenodo.org/records/21436858) | Labeled public handshake and flow metadata |
| Non-DNS exfiltration | Controlled outbound-volume captures | The above DNS dataset does not establish general file exfiltration |

[ISCXVPN2016](https://www.unb.ca/cic/datasets/vpn.html) uses OpenVPN. It cannot label IPsec mode, cipher, PFS, or DH group. Store dataset license, original URL, capture hash, scenario/host split assignment, and label mapping with every imported set. Dataset downloads are not included in this repository.

## Operate and verify

Set `CS_INTERNAL_CIDRS` to the monitored internal networks. For a local process, set `CS_LIVE_ENABLED=true` and `CS_LIVE_INTERFACE` to a receive-only mirror or tap interface visible to `tcpdump`, then call `POST /api/v1/threats/live/start`; call `/live/stop` to end capture. The Docker API requires `NET_RAW` and a network namespace that actually sees the mirrored packets. Merely choosing its container `eth0` will not expose traffic from another bridge port. Replay starts with a previously uploaded capture ID via `POST /api/v1/threats/replay` and `{"capture_id":"..."}`. `GET /alerts` returns persisted events; `GET /events` streams SSE. The dashboard is at `/threats`.

`make threat-benchmark` measures the single-process detector with synthetic packet records. A 10,000-flow smoke run on x86_64/Python 3.12.3 reached 13,055 flows/s, 0 reported drops, and 0.086 ms p95 processing per record. This excludes PCAP decoding, SQLite writes, the OS capture buffer, and network delivery, so it does **not** establish the requested sustained end-to-end 1,000 flows/s and five-second alert-delay target. Validate those with labeled replay and live mirrored traffic on the deployment host before claiming the service target. Beaconing must first accumulate several connections, so its alert delay also includes its observation window.
