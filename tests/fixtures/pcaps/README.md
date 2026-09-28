# Reference PCAP fixtures (< 1 MB each) with expected JSON (repo.md §9)

| File | Covers |
|---|---|
| `ikev2_sa_init_aes256gcm_ecp384.pcapng` | IKEv2 SA_INIT: ENCR 20 (AES-GCM-16), DH 20 (ECP-384), KE size 96 B |
| `ikev1_main_mode_3des_modp1024.pcapng` | IKEv1 Main Mode (exchange 2), 3DES, MODP-1024 (weak) |
| `esp_cbc_sha1_tunnel_v4.pcapng` | ESP structural: CBC IV 16 / block 16, ICV 12 (SHA1-96), tunnel size offset |
| `esp_gcm_transport_v6.pcapng` | GCM IV 8 / pad 4, ICV 16, transport-mode offsets, IPv6 |
| `natt_esp_in_udp.pcapng` | UDP/4500: ESP-in-UDP with non-zero SPI + IKE behind the 0x00000000 marker |

`expected/*.json` hold the golden inferences (§5 sample SA record shape) that
`tests/integration/test_pipeline_golden.py` asserts against.

**Regenerate** fixtures from lab sessions (`make lab-run PROFILES=p01,p07 ...`,
trim to < 1 MB with `tcpdump -w - -C 1` or `editcap`), then refresh the
`expected/` JSON after **reviewing** the diff — ground truth comes from the
session manifest, never from the analyzer.
