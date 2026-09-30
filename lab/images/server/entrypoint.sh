#!/bin/bash
# server-b entrypoint: starts every service the traffic generators talk to (mvp.md §3.1).
set -euo pipefail

# Inner addressing (mvp.md §3.1 topology): server-b sits behind gw-b on 10.2.0.0/24
# and answers traffic arriving from the 10.1.0.0/24 side through the tunnel.
# src pinning mirrors client-a (see its entrypoint) so replies take the tunnel.
ip addr add 10.2.0.10/24 dev lo 2>/dev/null || true
ip route replace 10.1.0.0/24 via 172.30.0.3 src 10.2.0.10 2>/dev/null || true
ip route replace fd01::/64 via fd30::3 src fd02::10 2>/dev/null || true
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f" 2>/dev/null || true; done

mkdir -p /var/www/hls

# Web mirror + HLS video segments (video streaming generator pulls these).
nginx

# E-mail: SMTP (Postfix) + IMAP (Dovecot).
service postfix start || postfix start
service dovecot start || true

# VoIP: SIPp UAS answers the UAC scenario from lab/traffic/voip/.
if [ -f /opt/uas.xml ]; then
  sipp -sf /opt/uas.xml -m 10000 -i 172.30.0.3 -p 5060 >/var/log/sipp-uas.log 2>&1 &
fi

# Messaging: WebSocket chat server backing the WhatsApp-like bot.
python3 /opt/chat_server.py --port 8080 >/var/log/chat.log 2>&1 &

# Keep HLS segments fresh so the client always has 480p-1080p content to pull.
while true; do
  ffmpeg -re -f lavfi -i testsrc=size=1280x720:rate=30 \
         -f lavfi -i sine=frequency=440 \
         -c:v libx264 -preset veryfast -g 48 -sc_threshold 0 \
         -c:a aac -f hls -hls_time 4 -hls_list_size 6 \
         /var/www/hls/stream.m3u8 >/dev/null 2>&1 || sleep 5
done
