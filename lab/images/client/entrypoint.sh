#!/bin/bash
# client-a entrypoint: waits for the lab bridge, then executes a generator command
# dispatched by lab/runner/orchestrate.py (docker exec client-a /entrypoint.sh <cmd>).
set -euo pipefail

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
