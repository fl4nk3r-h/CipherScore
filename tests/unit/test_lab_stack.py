"""The capture sidecar must follow the current gateway network namespace."""
from __future__ import annotations

from types import SimpleNamespace

from lab.runner import orchestrate


def test_missing_capture_is_recreated_without_restarting_gateways(monkeypatch):
    calls = []
    monkeypatch.setattr(orchestrate, "_container_running", lambda name: name != "capture")
    monkeypatch.setattr(orchestrate, "_sh", lambda command, **kwargs: calls.append(command))

    orchestrate.ensure_stack("p03")

    assert calls == [orchestrate._capture_compose("up", "-d", "--force-recreate", "capture")]


def test_profile_change_stops_capture_before_gateway_recreate(monkeypatch):
    calls = []
    monkeypatch.setattr(orchestrate, "_container_running", lambda name: True)

    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(stdout="LAB_PROFILE=p01\n")

    monkeypatch.setattr(orchestrate, "_sh", run)

    orchestrate.activate_profile("p07")

    assert calls[1:] == [
        orchestrate._capture_compose("stop", "capture"),
        orchestrate._lab_compose("up", "-d", "--force-recreate", "gw-a", "gw-b"),
        orchestrate._capture_compose("up", "-d", "--force-recreate", "capture"),
    ]


def test_missing_gateway_stops_capture_before_rebinding(monkeypatch):
    calls = []
    monkeypatch.setattr(orchestrate, "_container_running", lambda name: name != "gw-a")
    monkeypatch.setattr(orchestrate, "_sh", lambda command, **kwargs: calls.append(command))

    orchestrate.ensure_stack("p03")

    assert calls == [
        orchestrate._capture_compose("stop", "capture"),
        orchestrate._lab_compose("up", "-d"),
        orchestrate._capture_compose("up", "-d", "--force-recreate", "capture"),
    ]


def test_run_sessions_reports_processed_skipped_and_completed(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrate, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(orchestrate, "ensure_stack", lambda profile: None)
    monkeypatch.setattr(orchestrate, "activate_profile", lambda profile: None)
    monkeypatch.setattr(orchestrate, "_run_one", lambda *args: None)
    profile = {"id": "p03", "traffic": ["voip", "web"], "duration_per_traffic": "2m"}
    existing = tmp_path / "data/sessions/p03-voip-0001/manifest.json"
    existing.parent.mkdir(parents=True)
    existing.write_text("{}")
    events = []

    counts = orchestrate.run_sessions([profile], ["voip", "web"], on_progress=events.append)

    assert counts == {"total": 2, "processed": 2, "completed": 1, "skipped": 1, "failed": 0}
    assert any(event.get("current_session") == "p03-web-0001" for event in events)
    assert events[-1]["eta_seconds"] == 0


def test_cli_writes_terminal_run_status(tmp_path, monkeypatch):
    from api.lab_run_status import read_status
    from lab.runner import __main__ as cli

    monkeypatch.setattr(cli.render, "select_profiles", lambda *_: [{"id": "p03"}])

    def fake_run(*args, **kwargs):
        kwargs["on_progress"]({"status": "running", "phase": "Capturing p03-web-0001",
                               "total": 1, "processed": 0, "eta_seconds": 165})
        return {"total": 1, "processed": 1, "completed": 1, "skipped": 0, "failed": 0}

    monkeypatch.setattr(cli.orchestrate, "run_sessions", fake_run)
    path = tmp_path / "run.json"
    assert cli.main(["run", "--profiles", "p03", "--status-file", str(path)]) == 0
    state = read_status(path)
    assert state["status"] == "completed"
    assert state["processed"] == 1
    assert state["eta_seconds"] == 0
    assert state["finished_at"] >= state["started_at"]
