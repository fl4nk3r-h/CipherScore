#!/bin/bash
# Gateway entrypoint: renders configs from the profile dir, starts charon, waits for teardown.
set -euo pipefail

ROLE="${LAB_ROLE:?LAB_ROLE must be gw-a or gw-b}"
PROFILES_DIR="${LAB_PROFILES_DIR:-/profiles}"
OUT_DIR="${LAB_OUT_DIR:-/out}"

mkdir -p "$OUT_DIR" /etc/swanctl

# Render swanctl.conf (IKEv2) or ipsec.conf (IKEv1) for the selected profile.
python3 /render.py --role "$ROLE" --profiles "$PROFILES_DIR" --out /etc/swanctl

# Start the IKE daemon; save-keys writes /var/run/esp_sa and ikev2_decryption_table.
/usr/lib/ipsec/charon > /var/log/charon-stdout.log 2>&1 &
sleep 2
swanctl --load-conns --file /etc/swanctl/swanctl.conf || true
swanctl --load-secrets || true

# IKEv1 profiles additionally load the stroke-based config.
if [ -f /etc/ipsec.conf ]; then
  ipsec start || true
  ipsec rereadsecrets || true
  ipsec update || true
fi

# The runner brings the SA up and tears the stack down when the session ends.
tail -f /var/log/charon.log /var/log/charon-stdout.log & wait
