# lab/ — M1 LabForge: VPN testbed generation

Builds IPsec VPNs from YAML profiles and generates labeled traffic (mvp.md §3.1).

## Topology

- **Tunnel mode**: `client-a(10.1.0.10/fd01::10) ── gw-a(172.30.0.2/fd30::2) ═══ IPsec ═══ gw-b(172.30.0.3/fd30::3) ── server-b(10.2.0.10/fd02::10)` — site-to-site, inner hosts differ from gateways.
- **Transport mode**: `host-a(172.30.0.2/fd30::2) ═══ IPsec ═══ host-b(172.30.0.3/fd30::3)`.

Addressing: `lab/network/bridges.yaml`.

## Profiles

One YAML per configuration, validated by `profiles/_schema.json`, named
`pNN-<mode>-<cipher><integ>-<dh>-<pfs>-<ipfamily>.yaml` (`t` = tunnel, `x` = transport).
The 16 base profiles cover: Tunnel/Transport · AES-128/256-CBC with HMAC-SHA1-96 /
HMAC-SHA2-256-128 · AES-128/256-GCM-16 · DH groups 2, 5, 14, 19, 20, 31 · PFS on/off ·
IPv4/IPv6 · IKEv2 (IKEv1 in p13/p14) · NAT-T (p10) · AH-only (p16) ·
long lifetime + replay window 0 (p15). Field meanings and the p07 example are in
mvp.md §3.1 — do not add or rename fields without updating `_schema.json`.

## Traffic generators

`icmp.sh`, `web.py` (Playwright), `email.sh` (swaks + IMAP), `voip/` (SIPp +
RTP media), `video.sh` (ffmpeg → HLS), `messaging/bot.py` (WhatsApp-like
WebSocket bot + timing_profile.json), `bulk.sh` (iperf3/scp, negative control).

## Run

```bash
make lab-up
make lab-run PROFILES=p01,p07 TRAFFIC=voip,web
make lab-all          # full matrix.yaml sweep
```

Sessions land in `data/sessions/<session_id>/` written by the capture sidecar.

## Troubleshooting

- No ESP in pcap → check `lab/runner/verify.py` and `swanctl --list-sas` on gw-a.
- SA not installed → the rendered config is in the gateway container at `/etc/swanctl/swanctl.conf`;
  re-render with `python -m lab.runner render --profiles pNN` output for inspection.
- IKEv1 profiles (p13/p14) use `ipsec.conf`, not swanctl.
- Messaging: real WhatsApp cannot be scripted; the bot reproduces public-dataset
  size/timing characteristics (see mvp.md §3.1 and §13).
