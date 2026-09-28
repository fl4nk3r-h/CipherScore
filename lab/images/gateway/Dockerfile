# strongSwan 5.9+ gateway (charon + swanctl + save-keys) for the CipherScope lab.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan strongswan-swanctl strongswan-plugins \
    tcpdump iputils-ping iproute2 python3 jinja2 \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
