# M2 CaptureMesh sidecar (repo.md §3): tcpdump + Python helper.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump python3 python3-pip tshark \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m pip install --no-cache-dir pyyaml jsonschema

COPY capture.py manifest.py keys.py baseline.py live.py /app/
COPY schemas/ /app/schemas/
WORKDIR /sessions

ENTRYPOINT ["python3", "/app/capture.py"]
