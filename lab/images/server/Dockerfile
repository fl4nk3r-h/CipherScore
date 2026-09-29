# server-b services (repo.md §2): Nginx (web + HLS), Postfix/Dovecot (SMTP/IMAP),
# SIPp UAS (VoIP callee), and the WebSocket chat server (messaging).
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx postfix dovecot-imapd \
    sip-tester ffmpeg \
    python3 python3-pip \
    iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m pip install --no-cache-dir --break-system-packages websockets

COPY hls/ /var/www/hls/
COPY chat_server.py /opt/chat_server.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 25 143 5060/udp 8080
ENTRYPOINT ["/entrypoint.sh"]
