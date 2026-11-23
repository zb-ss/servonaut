"""Settings can use the updater's local status without starting a worker."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from servonaut.updates import status


@pytest.fixture
def pipx_home(tmp_path, monkeypatch):
    anchor = tmp_path / "pipx" / "venvs" / "servonaut"
    anchor.mkdir(parents=True)
    (anchor / status.PIPX_METADATA).write_text("{}")
    monkeypatch.setattr(status.sys, "prefix", str(anchor))
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    monkeypatch.setattr(status, "get_version", lambda: "2.34.0")
    return anchor


def test_fresh_pipx_reports_up_to_date_without_creating_state(pipx_home):
    actual = status.read_update_status()
    assert actual == status.UpdateStatus(
        "up_to_date", "2.34.0", "pipx", "stable", channel_selectable=True,
    )
    assert not status.storage_for(pipx_home).exists()


def test_read_json_checks_a_limit_even_for_valid_json(tmp_path):
    path = tmp_path / "state.json"
    payload = '{"current": "example"}'
    path.write_text(payload)
    assert status.read_json(path, maximum_bytes=len(payload)) == {"current": "example"}
    with pytest.raises(status.InvalidUpdateState, match="size limit"):
        status.read_json(path, maximum_bytes=len(payload) - 1)


def test_unmanaged_runtime_returns_its_kind(monkeypatch):
    monkeypatch.setattr(status, "locate_install", lambda: None)
    runtime = SimpleNamespace(product_version="2.34.0", kind=SimpleNamespace(value="packaged-desktop"))
    assert status.read_update_status(runtime) == status.UpdateStatus(
        "managed_elsewhere", "2.34.0", "packaged-desktop", "stable",
    )
    assert status.set_update_channel("rc", runtime) is False
    assert status.postpone_update("2.35.0", runtime) is False


def test_settings_preserve_config_and_queue_recheck(pipx_home):
    directory = status.storage_for(pipx_home)
    with status.update_gate(directory, 1):
        status.write_json(directory / "preferences.json", {"health_timeout": 7})
        status.write_json(directory / "state.json", {"checked_at": 100, "current": "generation"})
    assert status.set_update_channel("rc")
    assert status.read_json(directory / "preferences.json") == {"health_timeout": 7, "channel": "rc"}
    assert status.read_json(directory / "state.json") == {"checked_at": 0, "current": "generation"}
    assert status.read_update_status().channel == "rc"


def test_first_postpone_is_capped_and_cannot_be_reused(pipx_home, monkeypatch):
    directory = status.storage_for(pipx_home)
    with status.update_gate(directory, 1):
        status.write_json(directory / "preferences.json", {"postpone_max_seconds": 100_000})
        status.write_json(directory / "state.json", {"offered": "2.35.0", "status": "ready"})
    monkeypatch.setattr(status.time, "time", lambda: 100.0)
    assert status.postpone_update("2.34.1") is False
    assert status.read_update_status().can_postpone
    assert status.postpone_update("2.35.0")
    assert status.read_update_status().postponed_until == 86_500
    monkeypatch.setattr(status.time, "time", lambda: 86_501.0)
    assert status.read_update_status().postponed_until is None
    assert status.postpone_update("2.35.0") is False


def test_old_sessions_and_server_floor_are_independent_of_ready_state(pipx_home):
    directory = status.storage_for(pipx_home)
    with status.update_gate(directory, 1):
        status.write_json(directory / "state.json", {
            "status": "ready", "offered": "2.35.0",
            "policy": {"mode": "enforce", "minimum_version": "2.34.1"},
        })
        status.write_json(directory / "leases.json", {
            "123": {"role": "mcp", "version": "2.33.0"},
            "456": {"role": "cli", "version": "2.35.0"},
        })
    actual = status.read_update_status()
    assert actual.state == "ready"
    assert actual.target_version == "2.35.0"
    assert actual.old_sessions == ("mcp",)
    assert actual.required_minimum == "2.34.1"


def test_generation_reads_its_launchers_update_state(pipx_home, monkeypatch):
    generation = "1" * 32
    directory = status.storage_for(pipx_home)
    prefix = directory / "generations" / generation
    prefix.mkdir(parents=True)
    status.write_json(prefix / status.MARKER_NAME, {"anchor": str(pipx_home), "generation": generation})
    status.write_json(directory / "preferences.json", {"channel": "rc"})
    monkeypatch.setattr(status.sys, "prefix", str(prefix))
    assert status.read_update_status().channel == "rc"


def test_unreadable_state_keeps_settings_open(pipx_home):
    directory = status.storage_for(pipx_home)
    directory.mkdir(parents=True)
    (directory / "state.json").write_text("broken JSON")
    actual = status.read_update_status()
    assert actual.state == "failed"
    assert actual.last_failure == "Update status is unavailable."
