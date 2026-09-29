# strongSwan gateway (charon + swanctl) for the CipherScope lab.
# Debian 12 ships strongSwan 5.9.8 (>= 5.9 per mvp.md §3.1).
#
# NOTE on save-keys (mvp.md §3.2): Debian does not package the save-keys plugin
# as a standalone .so in these repos; it is compiled with
# `--enable-save-keys` (strongswan-plugin-save-keys exists only in some
# downstreams). The entrypoint therefore enables it if the plugin file is
# present and otherwise records an explicit warning in the session keys/
# directory, so M-B label verification (Wireshark decrypt) degrades loudly,
# never silently.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan strongswan-swanctl strongswan-libcharon \
    libcharon-extra-plugins libstrongswan-extra-plugins \
    libstrongswan-standard-plugins \
    tcpdump iputils-ping iproute2 python3 python3-pip \
 && python3 -m pip install --no-cache-dir --break-system-packages jinja2 pyyaml \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY render.py /render.py
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
