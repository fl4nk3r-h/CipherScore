# CipherScope IPsec model card

## Intended use

Passive IPsec SA and encrypted traffic classification. Predictions are evidence, not proof.

## Training and validation

Lab PCAPs require IKE plus at least 20 ESP packets. Profiles are disjoint across
fitting, probability calibration, conformal calibration, and testing.

| Head | Version | Macro F1 | ECE | Coverage |
|---|---|---:|---:|---:|
| mode | untrained | 0.4832 | 0.3423 | 0.9727 |
| cipher | untrained | 0.2147 | 0.4824 | 1.0 |
| integ | untrained | — | — | — |
| pfs | untrained | 0.5911 | 0.3949 | 0.6019 |
| dh_group | untrained | — | — | — |
| traffic | v0.2.0 | 0.9181 | 0.0424 | 0.8546 |

## Limits

Key size cannot be read from ESP bytes. PFS and CHILD_SA DH are unknown
without a captured rekey. Lab-only training may not generalize to other VPNs.
