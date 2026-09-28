#!/bin/bash
# ICMP traffic generator (mvp.md §3.1): ping/ping6 with sizes and intervals varied.
# Usage: icmp.sh <server_ip> <duration_seconds>
set -euo pipefail
SERVER="${1:?server ip required}"
DURATION="${2:-120}"
END=$((SECONDS + DURATION))

if [[ "$SERVER" == *:* ]]; then
  PING="ping6"
else
  PING="ping"
fi

i=0
while [ $SECONDS -lt $END ]; do
  # Sizes sweep small control packets through ~1400B payloads; intervals 0.1-1.0s.
  SIZE=$((64 + (i * 173) % 1408))
  GAP=$(python3 -c "print(round(0.1 + ($i % 10) * 0.1, 2))")
  "$PING" -c 4 -s "$SIZE" -i "$GAP" "$SERVER" || true
  i=$((i + 1))
done
