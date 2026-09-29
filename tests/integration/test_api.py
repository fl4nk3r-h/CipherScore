"""API integration test (repo.md §9): upload → analysis → report via TestClient."""
from __future__ import annotations

import struct

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CS_DATA_DIR", str(tmp_path))
    from api import db
    from api.main import create_app
    db.migrate()
    return TestClient(create_app())


def _minimal_pcap() -> bytes:
    """pcap header + one Ethernet/IPv4/UDP packet (no ESP content)."""
    pcap_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    eth_ip_udp = (
        bytes(14)                                          # ethernet
        + struct.pack(">BBHHHBBH", 0x45, 0, 28, 0, 0, 64, 17, 0)  # IPv4
        + bytes(8) + bytes(4) + bytes(6)                   # src, dst, udp
    )
    record_header = struct.pack("<IIII", 0, 0, len(eth_ip_udp), len(eth_ip_udp))
    return pcap_header + record_header + eth_ip_udp


def test_health(client):
    assert client.get("/api/v1/healthz").json() == {"status": "ok"}


def test_upload_and_analyze_flow(client, tmp_path):
    pcap = _minimal_pcap()
    res = client.post("/api/v1/captures",
                      files={"file": ("tiny.pcapng", pcap, "application/octet-stream")})
    assert res.status_code == 200, res.text
    capture_id = res.json()["capture_id"]

    # Stored under sha256 name, not the original filename (repo.md §7 invariant).
    uploads = list((tmp_path / "uploads").glob("*.pcapng"))
    assert uploads and all(u.name != "tiny.pcapng" for u in uploads)

    res = client.post("/api/v1/analyses", json={"capture_id": capture_id})
    assert res.status_code == 200
    analysis_id = res.json()["analysis_id"]
    assert res.json()["status"] == "queued"

    res = client.get(f"/api/v1/analyses/{analysis_id}")
    assert res.status_code == 200


def test_unknown_capture_404(client):
    res = client.post("/api/v1/analyses", json={"capture_id": "nope"})
    assert res.status_code == 404


def test_live_disabled_by_default(client):
    res = client.post("/api/v1/live/start")
    assert res.status_code == 403   # CS_LIVE_ENABLED=false (mvp.md §13)


def test_live_uses_configured_data_dir(client, tmp_path, monkeypatch):
    monkeypatch.setenv("CS_LIVE_ENABLED", "true")
    from capture import live

    seen: dict[str, object] = {}

    class FakeCapturer:
        def __init__(self, interface, data_dir):
            seen["interface"] = interface
            seen["data_dir"] = data_dir

        def start(self):
            seen["started"] = True

        def stop(self):
            seen["stopped"] = True

    monkeypatch.setattr(live, "LiveCapturer", FakeCapturer)
    res = client.post("/api/v1/live/start")

    assert res.status_code == 200, res.text
    assert seen == {"interface": "eth0", "data_dir": tmp_path, "started": True}
    client.post("/api/v1/live/stop")


def test_live_permission_error_is_service_unavailable(client, monkeypatch):
    monkeypatch.setenv("CS_LIVE_ENABLED", "true")
    from capture import live

    class DeniedCapturer:
        def __init__(self, interface, data_dir):
            raise PermissionError("permission denied")

    monkeypatch.setattr(live, "LiveCapturer", DeniedCapturer)
    res = client.post("/api/v1/live/start")

    assert res.status_code == 503
    assert "NET_RAW/NET_ADMIN" in res.json()["detail"]


def test_live_capture_error_is_service_unavailable(client, monkeypatch):
    monkeypatch.setenv("CS_LIVE_ENABLED", "true")
    from capture import live

    class FailedCapturer:
        def __init__(self, interface, data_dir):
            pass

        def start(self):
            raise live.LiveCaptureError("tcpdump denied capture")

    monkeypatch.setattr(live, "LiveCapturer", FailedCapturer)
    res = client.post("/api/v1/live/start")

    assert res.status_code == 503
    assert "tcpdump" in res.json()["detail"]
