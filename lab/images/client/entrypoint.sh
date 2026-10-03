#!/bin/bash
# client-a entrypoint: waits for the lab bridge, then executes a generator command
# dispatched by lab/runner/orchestrate.py (docker exec client-a /entrypoint.sh <cmd>).
set -euo pipefail

# Inner addressing (mvp.md §3.1 topology): client-a sits behind gw-a on 10.1.0.0/24
# and reaches server-b (10.2.0.10 behind gw-b) through the IPsec tunnel.
# The route pins src 10.1.0.10: without it, pings use the 172.30.0.10 bridge
# address, miss the tunnel's 10.1/24<->10.2/24 traffic selectors, and ride the
# shared bridge in cleartext.
ip addr add 10.1.0.10/24 dev lo 2>/dev/null || true
ip -6 addr add fd01::10/64 dev lo 2>/dev/null || true
ip route replace 10.2.0.0/24 via 172.30.0.2 src 10.1.0.10 2>/dev/null || true
ip route replace fd02::/64 via fd30::2 src fd01::10 2>/dev/null || true
# rp_filter would drop ESP-decapsulated inner traffic on the strict default.
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f" 2>/dev/null || true; done

# Wait for basic reachability of the server side.
for i in $(seq 1 30); do
  ping -c1 -W1 172.30.0.3 >/dev/null 2>&1 && break
  sleep 1
done

if [ "$#" -eq 0 ]; then
  echo "client-a idle; runner dispatches generators via: docker exec client-a /entrypoint.sh <generator>"
  sleep infinity
else
  exec "$@"
fi
