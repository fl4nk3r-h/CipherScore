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


def test_reports_serve_all_artifacts(client, tmp_path, monkeypatch):
    """The reports router serves PDFs, report.json and findings.csv (mvp.md §5).

    Regression: only {kind}.pdf was routed, so the Reports screen got 404 for
    report.json and 405 for HEAD probes (web/lib/api.ts headExists), rendering
    every report as "missing".
    """
    from analyzer import config

    # config.REPORTS_DIR is bound at import time; point it at the test dir.
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path / "reports")
    aid = "an_test1234"
    report_dir = tmp_path / "reports" / aid
    report_dir.mkdir(parents=True)
    (report_dir / "report.json").write_text("{\"security_score\": 96}")
    (report_dir / "findings.csv").write_text("rule_id\ntest\n")
    (report_dir / "executive.pdf").write_bytes(b"%PDF-1.7 fake")
    (report_dir / "technical.pdf").write_bytes(b"%PDF-1.7 fake")

    base = f"/api/v1/analyses/{aid}/reports"
    res = client.get(f"{base}/report.json")
    assert res.status_code == 200
    assert res.json() == {"security_score": 96}

    res = client.get(f"{base}/findings.csv")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")

    res = client.get(f"{base}/executive.pdf")
    assert res.status_code == 200
    assert res.content.startswith(b"%PDF")

    # HEAD must succeed: the web client uses it for the ready/missing badges.
    for artifact in ("executive.pdf", "technical.pdf", "report.json", "findings.csv"):
        res = client.head(f"{base}/{artifact}")
        assert res.status_code == 200, (artifact, res.status_code)


def test_reports_unknown_kind_and_missing_files_404(client):
    base = "/api/v1/analyses/an_nope/reports"
    assert client.get(f"{base}/executive.docx").status_code == 404
    assert client.get(f"{base}/executive.pdf").status_code == 404
    assert client.head(f"{base}/report.json").status_code == 404


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


def test_lab_sessions_include_latest_analysis_accuracy(client, tmp_path, monkeypatch):
    import json
    from analyzer import config
    from api import db

    sessions_dir = tmp_path / "sessions"
    monkeypatch.setattr(config, "SESSIONS_DIR", sessions_dir)
    session_dir = sessions_dir / "session-1"
    session_dir.mkdir(parents=True)
    (session_dir / "manifest.json").write_text(json.dumps({
        "session_id": "session-1", "profile": "p01", "traffic_type": "web",
        "labels": {"mode": "tunnel", "enc": "AES-GCM-16"}, "pcap": "capture.pcapng",
    }))
    conn = db.connect()
    try:
        conn.execute("INSERT INTO analysis (id, capture_id, status) VALUES (?, ?, ?)",
                     ("an_test", "session-1", "completed"))
        conn.execute("INSERT INTO sa (id, analysis_id, spi, peers, params) VALUES (?, ?, ?, ?, ?)",
                     ("an_test-0x01", "an_test", "0x01", "[]", json.dumps({
                         "spi": "0x01", "mode": {"value": "tunnel", "tag": "observed"},
                         "enc": {"value": "AES-CBC", "tag": "inferred"},
                         "traffic": {"top": "web", "p": 0.9},
                     })))
        conn.execute("INSERT INTO flow_window (sa_id, t0, features, pred, p) VALUES (?, ?, ?, ?, ?)",
                     ("an_test-0x01", 0.0, json.dumps({"len_mean": 120.0}), "web", 0.9))
        conn.commit()
    finally:
        conn.close()

    sessions = client.get("/api/v1/lab/sessions").json()
    assert len(sessions) == 1
    accuracy = sessions[0]["accuracy"]
    assert accuracy["status"] == "completed"
    assert accuracy["matched"] == 2
    assert accuracy["compared"] == 3
    assert accuracy["match"]["enc"] is False
    assert client.get("/api/v1/analyses/an_test/traffic").json() == [
        {"pred": "web", "p": 0.9, "t0": 0.0, "features": {"len_mean": 120.0}}
    ]
