#!/bin/bash
# Video streaming generator (mvp.md §3.1): client pulls HLS segments from the Nginx
# mirror at 480p-1080p, producing the characteristic segment burst pattern.
# Usage: video.sh <server_host> <duration_seconds>
set -euo pipefail
SERVER="${1:?server host required}"
URL_HOST="$SERVER"
[[ "$SERVER" == *:* ]] && URL_HOST="[$SERVER]"
DURATION="${2:-120}"
END=$((SECONDS + DURATION))

BITRATES=("480p" "720p" "1080p")   # quality ladder names for logging only
i=0
while [ $SECONDS -lt $END ]; do
  BR="${BITRATES[$((i % 3))]}"
  echo "[video] pulling HLS ladder ($BR) from $SERVER ..."
  ffmpeg -re -loglevel error \
         -i "http://$URL_HOST/hls/stream.m3u8" \
         -t 20 -f null - || true
  i=$((i + 1))
done
