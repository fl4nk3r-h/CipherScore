# agent.md — `lab/` (M1 LabForge: VPN testbed generation)

**Owner: Person A** (see [docs/team_split.md](../docs/team_split.md)).

**Source of truth: `docs/mvp.md` §0, §1.1, §3.1, §3.2, §9, §13. Nothing in this file adds, removes, or reinterprets an MVP requirement.**

## Mission

Generate IPsec VPNs and labeled traffic for every variation the MVP requires, so that every capture has ground truth and the analyzer's accuracy is **measured, not claimed** (mvp.md §0 "What viable means here", item 3).

## What this folder must do (from mvp.md)

1. **Build the two topologies** (§3.1):
   - Tunnel mode — site-to-site: `client-a ── gw-a ═══ IPsec ═══ gw-b ── server-b`
     (`10.1.0.10/172.30.0.2 ═ 172.30.0.3/10.2.0.10`, `fd01::10/fd30::2 ═ fd30::3/fd02::10`).
     Inner hosts differ from the gateways.
   - Transport mode — host to host: `host-a ═══ IPsec ═══ host-b` (`172.30.0.2 ═ 172.30.0.3`, `fd30::2 ═ fd30::3`).
2. **Render the 16-profile matrix exactly as specified** (§3.1 table; the profiles in `profiles/`):

   | ID | IKE | Mode | IP | ESP cipher | Integrity | DH | PFS | Notes |
   |---|---|---|---|---|---|---|---|---|
   | p01 | v2 | Tunnel | v4 | AES-128-CBC | SHA2-256-128 | 14 | On | Baseline good |
   | p02 | v2 | Transport | v4 | AES-128-CBC | SHA2-256-128 | 14 | Off | PFS off |
   | p03 | v2 | Tunnel | v4 | AES-256-CBC | SHA1-96 | 2 | Off | Deliberately weak |
   | p04 | v2 | Transport | v6 | AES-256-CBC | SHA2-256-128 | 19 | On | |
   | p05 | v2 | Tunnel | v4 | AES-128-GCM-16 | (AEAD) | 19 | On | |
   | p06 | v2 | Transport | v4 | AES-128-GCM-16 | (AEAD) | 14 | Off | |
   | p07 | v2 | Tunnel | v6 | AES-256-GCM-16 | (AEAD) | 20 | On | CNSA-style |
   | p08 | v2 | Transport | v6 | AES-256-GCM-16 | (AEAD) | 31 | On | Curve25519 |
   | p09 | v2 | Tunnel | v6 | AES-128-CBC | SHA1-96 | 14 | Off | |
   | p10 | v2 | Tunnel | v4 | AES-256-GCM-16 | (AEAD) | 14 | On | NAT-T (UDP/4500) |
   | p11 | v2 | Transport | v4 | AES-256-CBC | SHA2-512-256 | 20 | On | |
   | p12 | v2 | Tunnel | v4 | AES-128-CBC | SHA2-256-128 | 5 | Off | Legacy DH |
   | p13 | v1 | Tunnel | v4 | AES-128-CBC | SHA1-96 | 2 | Off | IKEv1 Main Mode, weak |
   | p14 | v1 | Transport | v4 | AES-256-CBC | SHA2-256-128 | 14 | On | IKEv1 |
   | p15 | v2 | Tunnel | v4 | AES-256-CBC | SHA2-256-128 | 14 | On | Long lifetime (24 h), replay window 0 |
   | p16 | v2 | Transport | v4 | AH only | SHA2-256-128 | 14 | On | Optional AH profile |

   This satisfies §1.1(a) entirely: Tunnel and Transport · AES-128-CBC / AES-256-CBC with
   HMAC-SHA1-96 / HMAC-SHA2-256-128 · AES-128-GCM-16 / AES-256-GCM-16 · DH groups 2, 14, 19, 20, 31
   (plus legacy 5 from the spec's matrix) · PFS on/off · IPv4 and IPv6 · IKEv2 (IKEv1 in 2 legacy
   profiles) · NAT-T on/off.
3. **Run the 7 traffic types** (§3.1 table; §1.1 "Traffic types"): ICMP (`ping`/`ping6`, sizes and
   intervals varied), Web browsing (headless Chromium via Playwright against a local mirror +
   optional NAT internet), E-mail (`swaks` SMTP to Postfix; IMAP pull from Dovecot; attachments
   10 KB–5 MB), VoIP (`SIPp` scenarios with RTP media, G.711/Opus pcaps), Video streaming (`ffmpeg`
   to Nginx HLS at 480p–1080p), Messaging (WhatsApp-like WebSocket chat bot with text, images, and
   voice notes using the timing profile of public WhatsApp datasets — real WhatsApp can't be
   scripted; optionally route a real phone through gw-a for validation), Bulk (`iperf3`/`scp`,
   negative/control class).
4. **Render profiles into strongSwan config with Jinja2** (§3.1): `swanctl.conf` mapping is fixed —
   `version`, `proposals`, `rekey_time`, PSK auth with ids `gw-a`/`gw-b`, child `mode`,
   `esp_proposals`, `rekey_time`, `replay_window`, and traffic selectors `local_ts`/`remote_ts`
   (`fd01::/64 ↔ fd02::/64` for v6, `10.1.0.0/24 ↔ 10.2.0.0/24` for v4). IKEv1 profiles render
   through the legacy ipsec.conf template. A DH group at the end of `esp_proposal` means PFS on.
5. **Support sweeps** (§3.1, §7): sweeping duration, packet sizes, and random seeds turns
   16 profiles × 7 traffic types into **>110 labeled sessions per run**; the dataset target is
   **≥ 560 sessions** (16 × 7 × 5 repetitions), 5–15 GB PCAP, >100 k labeled flow windows.
6. **Make rekeys capturable** (§3.1, §13): p07 uses `child_rekey_time: 10m` "short on purpose so
   rekeys appear in captures"; p15 uses 24 h to produce the legitimate "PFS unknown" case.

## Inputs

- A profile YAML per run (fields and semantics in §3.1; validated by `profiles/_schema.json`).
- `matrix.yaml` selecting profiles × traffic × repetitions.
- `network/bridges.yaml` subnets (172.30.0.0/24, fd30::/64, inner nets 10.1/10.2, fd01::/fd02::).
- The Docker lab stack (`docker-compose.lab.yml`): strongSwan gateways with `save-keys`,
  traffic-generator client, service server (Nginx web+HLS, Postfix, Dovecot, SIPp UAS, chat server).

## Outputs

- Installed SAs: `swanctl --list-sas` shows them (milestone M-A exit criterion, §9).
- Per session, under `data/sessions/<session_id>/` (written by the M2 capture sidecar):
  `pcapng`, `manifest.json` with ground-truth labels (the exact schema is in §3.2), and
  `keys/` from strongSwan save-keys.
- ESP visible in the pcaps; decryption with the key files confirms every traffic label
  (milestone M-B exit criterion, §9).

## Functionality / interfaces

- `python -m lab.runner run --profiles p01,p07 [--traffic voip,web] [--matrix lab/matrix.yaml]`
- `render.py`: profile YAML → swanctl.conf/ipsec.conf (Jinja2 templates; template content is fixed by §3.1's example).
- `orchestrate.py`: bring SA up → start capture → run generator → stop capture → tear down.
- `verify.py`: `swanctl --list-sas` check + ESP presence check.
- Make targets consumed: `make lab-up`, `make lab-run PROFILES=… TRAFFIC=…`, `make lab-all` (repo.md §10).

## Boundaries (do not do)

- No analysis, inference, scoring, or reporting — that is `analyzer/` (§2 component split).
- No capture implementation — `capture/` owns tcpdump, manifests, keys.
- The analyzer must never consume the save-keys files; they exist only to decrypt lab captures
  offline for label verification (§3.2).
- No cloud services; the demo runs offline on one 8 GB host (§0).
- Don't add ciphers/DH groups/traffic types beyond §1.1/§3.1, and don't drop any of them.
- Post-quantum hybrid testbed profiles are explicitly deferred (§1.2); rules only flag PQ
  non-readiness.
