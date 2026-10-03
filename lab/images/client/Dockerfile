# Traffic generator client (client-a / host-a). Provides every generator in mvp.md §3.1:
# ICMP (ping), Web (headless Chromium via Playwright), E-mail (swaks), VoIP (SIPp),
# Video (ffmpeg), Messaging (WebSocket bot), Bulk (iperf3/scp).
FROM debian:12-slim

# Debian 12: SIPp is packaged as `sip-tester` (provides the sipp binary).
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip curl ca-certificates \
    chromium \
    iputils-ping iproute2 \
    swaks libio-socket-inet6-perl netbase \
    sip-tester \
    ffmpeg \
    iperf3 openssh-client sshpass \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m pip install --no-cache-dir --break-system-packages playwright websockets

# Playwright driver bundle; chromium from Debian is used as the browser executable.
ENV PLAYWRIGHT_BROWSERS_PATH=/usr/bin
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE=/usr/bin/chromium

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
