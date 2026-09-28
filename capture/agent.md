# agent.md — `capture/` (M2 CaptureMesh: traffic capture and labeling)

**Source of truth: `docs/mvp.md` §0, §1.1(b), §3.2, §9, §13. Nothing here adds, removes, or reinterprets an MVP requirement.**

## Mission

Capture lab traffic per session and label it with ground truth, so the analyzer's accuracy can be measured against the profile that produced the capture.

## What this folder must do (from mvp.md)

1. **Rotating tcpdump per session** (§3.2): a tcpdump sidecar on the lab bridge writes
   `-C 100 -w session_%s.pcapng` for each session (rotate at 100 MB, timestamped files).
2. **Collect save-keys output per session** (§3.2): strongSwan's save-keys plugin
   (`charon.plugins.save-keys.esp = yes`, `ike = yes`) writes Wireshark-compatible `esp_sa` and
   `ikev2_decryption_table` files. Those files decrypt the lab captures **offline to verify
   inner-traffic labels**. The analyzer itself never uses them.
3. **Write a manifest per session** (§3.2) with exactly this shape:
   ```json
   {
     "session_id": "p07-voip-0003",
     "profile": "p07",
     "traffic_type": "voip",
     "start": "2026-09-28T10:14:02Z",
     "end": "2026-09-28T10:16:02Z",
     "gateways": ["fd30::2", "fd30::3"],
     "labels": {
       "ike_version": 2, "mode": "tunnel", "enc": "AES-GCM-16", "key_bits": 256,
       "integ": "AEAD", "dh_group": 20, "pfs": true, "nat_t": false,
       "child_rekey_s": 600, "replay_window": 64
     },
     "pcap": "p07-voip-0003.pcapng",
     "keys": "p07-voip-0003.keys/"
   }
   ```
   Label values come from the profile that ran (lab/profiles) — no guesswork.
4. **Baseline (non-VPN) captures** (§3.2): record the same traffic types **with IPsec disabled**.
   The baseline trains and validates the "IPsec present / absent" decision and shows the metadata
   that encryption removes.
5. **Live mode capture** (§0, §4 screen 9): rolling **10 s** windows on **one interface**, feeding
   the analyzer repeatedly for evolving predictions streamed over SSE.
6. **Deliverable support** (§1.1(b), §9, §14): session outputs feed the dataset deliverable
   (pcaps + keys + labels) and the demo; decrypting in Wireshark must confirm the label for every
   traffic type (milestone M-B exit criterion).

## Inputs

- A `start`/`stop` command per session from `lab/runner/orchestrate.py` (session id, interface).
- The session's profile (for label values: ike_version, mode, enc, key_bits, integ, dh_group, pfs,
  nat_t, child_rekey_s, replay_window).
- The gateway containers (save-keys files under `/var/run`).
- Baseline runs: a generator command + duration, with SAs torn down first.

## Outputs

Per session, under `data/sessions/<session_id>/` (repo.md §3):

```
p07-voip-0003/
├── p07-voip-0003.pcapng
├── manifest.json
└── keys/
    ├── esp_sa
    └── ikev2_decryption_table
```

## Functionality / interfaces

- `capture.py start <session_id> [--interface]` / `capture.py stop <session_id>` — tcpdump lifecycle.
- `manifest.py` — writes manifest.json (schema: `schemas/manifest.schema.json`).
- `keys.py` — copies `esp_sa` + `ikev2_decryption_table` into `keys/`; exposes a
  Wireshark/tshark-based decrypt check used by `scripts/sanity_check.py` for ground-truth
  verification only.
- `baseline.py` — same traffic, IPsec off, labeled `ipsec_present: false`.
- `live.py` — 10 s rolling-window capture for the Live screen; runs only when live mode is enabled.
- Runs as the `capture` container: `network_mode: "container:lab-bridge-tap"`,
  `cap_add: [NET_RAW, NET_ADMIN]`, sessions volume mounted at `/sessions` (repo.md §11).

## Boundaries (do not do)

- No parsing, inference, scoring, or reporting — the analyzer never imports anything from here.
- Never feed save-keys material into analysis results; keys are for label verification only (§3.2).
- No cloud or remote sensors — one tcpdump sidecar on one host is the MVP (§1.2 defers multi-sensor/Kafka).
- Don't alter traffic selection: the runner decides profiles and traffic types; capture only records.
