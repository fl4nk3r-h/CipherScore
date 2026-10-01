# CipherScope IPsec model card

## Intended use

Passive IPsec SA and encrypted traffic classification. Predictions are evidence, not proof.

## Training and validation

Lab PCAPs require IKE plus at least 20 ESP packets. Profiles are disjoint across
fitting, probability calibration, conformal calibration, and testing.

| Head | Version | Macro F1 | ECE | Coverage |
|---|---|---:|---:|---:|
| mode | untrained | — | — | — |
| cipher | untrained | — | — | — |
| integ | untrained | — | — | — |
| pfs | untrained | — | — | — |
| dh_group | untrained | — | — | — |
| traffic | untrained | — | — | — |

## Limits

Key size cannot be read from ESP bytes. PFS and CHILD_SA DH are unknown
without a captured rekey. Lab-only training may not generalize to other VPNs.
