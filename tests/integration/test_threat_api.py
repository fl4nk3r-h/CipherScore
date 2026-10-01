"""PCAP replay reaches persisted threat alerts through the public API."""
from __future__ import annotations

import io
import socket
import time

import dpkt
from fastapi.testclient import TestClient

from api import db
from api.main import create_app


def _ddos_pcap() -> bytes:
    output = io.BytesIO()
    writer = dpkt.pcap.Writer(output)
    for n in range(110):
        tcp = dpkt.tcp.TCP(sport=30000 + n, dport=80, flags=dpkt.tcp.TH_SYN)
        ip = dpkt.ip.IP(src=socket.inet_aton(f"10.0.0.{n % 20 + 1}"),
                        dst=socket.inet_aton("1.2.3.4"), p=6, ttl=64, data=tcp)
        eth = dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
        writer.writepkt(bytes(eth), ts=100 + n / 200)
    return output.getvalue()


def test_replay_persists_deduplicated_alert(tmp_path, monkeypatch):
    monkeypatch.setenv("CS_DATA_DIR", str(tmp_path))
    db.migrate()
    client = TestClient(create_app())
    uploaded = client.post("/api/v1/captures", files={"file": ("ddos.pcap", _ddos_pcap())})
    assert uploaded.status_code == 200
    capture_id = uploaded.json()["capture_id"]
    started = client.post("/api/v1/threats/replay", json={"capture_id": capture_id})
    assert started.status_code == 200
    for _ in range(100):
        alerts = client.get("/api/v1/threats/alerts").json()
        if alerts:
            break
        time.sleep(0.02)
    assert len([a for a in alerts if a["threat_class"] == "ddos"]) == 1
    alert = alerts[0]
    assert alert["flow_id"] and alert["evidence"]["destination"] == "1.2.3.4"
    assert alert["source"].startswith("replay:")
    assert client.post("/api/v1/threats/replay", json={"capture_id": "missing"}).status_code == 404


def test_replay_and_pipe_ingest_produce_the_same_alerts(tmp_path):
    from analyzer.parse.reader import stream_file
    from analyzer.threats import ThreatEngine

    capture = tmp_path / "same.pcap"
    capture.write_bytes(_ddos_pcap())
    replayed = [alert.as_dict() for alert in ThreatEngine(source="same").replay(capture)]
    live_engine = ThreatEngine(source="same")
    piped = [alert.as_dict() for packet in stream_file(io.BytesIO(capture.read_bytes()))
             for alert in live_engine.ingest(packet)]
    assert replayed == piped
    assert len([alert for alert in piped if alert["threat_class"] == "ddos"]) == 1
