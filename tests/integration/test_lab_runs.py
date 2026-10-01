"""Lab run API reports the child process and rejects duplicate sweeps."""
from __future__ import annotations

from fastapi.testclient import TestClient

from analyzer import config
from api.lab_run_status import update_status
from api.main import create_app
from api.routers import lab


def test_run_status_and_duplicate_rejection(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(lab, "_runner_busy", lambda: False)
    lab._PROCESSES.clear()

    class FakeProcess:
        pid = 12345
        exited = False

        def __init__(self, *args, **kwargs):
            self.command = args[0]

        def poll(self):
            return 1 if self.exited else None

    monkeypatch.setattr(lab.subprocess, "Popen", FakeProcess)
    client = TestClient(create_app())
    payload = {"profile_ids": ["p03"], "traffic_types": ["voip", "web"]}
    first = client.post("/api/v1/lab/runs", json=payload)
    assert first.status_code == 202, first.text
    run_id = first.json()["run_id"]
    assert first.json()["status"] == "queued"
    assert client.post("/api/v1/lab/runs", json=payload).status_code == 409

    update_status(lab._status_path(), status="running", phase="Capturing p03-web-0001",
                  total=2, processed=1, skipped=1, current_session="p03-web-0001",
                  eta_seconds=165)
    current = client.get("/api/v1/lab/runs/current")
    assert current.status_code == 200
    assert current.json()["run_id"] == run_id
    assert current.json()["processed"] == 1
    assert 0 <= current.json()["eta_seconds"] <= 165

    lab._PROCESSES[run_id].exited = True
    stopped = client.get("/api/v1/lab/runs/current")
    assert stopped.json()["status"] == "failed"
    assert "exited" in stopped.json()["error"]
    lab._PROCESSES.clear()


def test_run_rejects_invalid_selection(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    client = TestClient(create_app())
    assert client.post("/api/v1/lab/runs", json={"profile_ids": ["invalid"]}).status_code == 422
    assert client.get("/api/v1/lab/runs/current").json() is None
