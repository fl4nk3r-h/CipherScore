#!/bin/bash
# server-b entrypoint: starts every service the traffic generators talk to (mvp.md §3.1).
set -euo pipefail

# Inner addressing (mvp.md §3.1 topology): server-b sits behind gw-b on 10.2.0.0/24
# and answers traffic arriving from the 10.1.0.0/24 side through the tunnel.
# src pinning mirrors client-a (see its entrypoint) so replies take the tunnel.
if [ "${TRANSPORT_HOST:-0}" = 1 ]; then
  SIP_IP4=172.30.0.3
  SIP_IP6=fd30::3
else
  SIP_IP4=10.2.0.10
  SIP_IP6=fd02::10
  ip addr add 10.2.0.10/24 dev lo 2>/dev/null || true
  ip -6 addr add fd02::10/64 dev lo 2>/dev/null || true
  ip route replace 10.1.0.0/24 via 172.30.0.3 src 10.2.0.10 2>/dev/null || true
  ip route replace fd01::/64 via fd30::3 src fd02::10 2>/dev/null || true
  for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f" 2>/dev/null || true; done
fi

mkdir -p /var/www/hls

# Web mirror + HLS video segments (video streaming generator pulls these).
nginx

# E-mail: SMTP (Postfix) + IMAP (Dovecot).
# Local mailbox for the test account; Postfix delivers to its Maildir.
id labuser >/dev/null 2>&1 || useradd -m -s /bin/bash labuser
printf 'labuser:labpass\n' | chpasswd
postconf -e 'home_mailbox = Maildir/'
postconf -e 'mydestination = server-b, localhost'
printf 'mail_location = maildir:~/Maildir\ndisable_plaintext_auth = no\n' > /etc/dovecot/conf.d/99-lab-mail.conf
mkdir -p /home/labuser/Maildir/{cur,new,tmp}
chown -R labuser:labuser /home/labuser/Maildir
service postfix start || postfix start
service dovecot start || true
mkdir -p /run/sshd
printf 'PasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/99-lab.conf
service ssh start

# VoIP: SIPp UAS answers the UAC scenario from lab/traffic/voip/.
if [ -f /opt/uas.xml ]; then
  sipp -sf /opt/uas.xml -m 10000 -i "$SIP_IP4" -p 5060 -rtp_echo -nostdin >/var/log/sipp-uas.log 2>&1 &
  sipp -sf /opt/uas.xml -m 10000 -i "$SIP_IP6" -p 5060 -mp 7000 -rtp_echo -nostdin >/var/log/sipp-uas-v6.log 2>&1 &
fi

# Bulk-transfer endpoint.
iperf3 -s -D

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
