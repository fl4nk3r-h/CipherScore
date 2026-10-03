#!/bin/bash
# Bulk transfer generator (mvp.md §3.1): iperf3 / scp. Serves as the negative /
# control class for the traffic classifier (large, smooth, throughput-dominated).
# Usage: bulk.sh <server_ip> <duration_seconds>
set -euo pipefail
SERVER="${1:?server ip required}"
SCP_HOST="$SERVER"
[[ "$SERVER" == *:* ]] && SCP_HOST="[$SERVER]"
DURATION="${2:-120}"
END=$((SECONDS + DURATION))

while [ $SECONDS -lt $END ]; do
  iperf3 -c "$SERVER" -t 20 -P 2 -b 1M
  # Isolated lab account carries the SSH copy leg of the bulk workload.
  dd if=/dev/urandom of=/tmp/bulk.bin bs=1M count=8 status=none
  SSHPASS=labpass sshpass -e scp -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null /tmp/bulk.bin "labuser@${SCP_HOST}:/tmp/"
  sleep 2
done
