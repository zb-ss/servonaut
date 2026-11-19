"""Focused safeguards for update notice, launcher health, and manual checks."""

import errno
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from servonaut import entry
from servonaut.updates import builder, state, status
from servonaut.updates.generations import directory_for
from servonaut.updates.layout import UpdateLayout
from tests.test_update_followup import _ready, _spec, route
from tests.test_update_review import ACTIVE_VERSION, CURRENT, OLD, READY, TARGET, VERSION, install


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["failed", "rolled_back", "up_to_date"])
async def test_hidden_offer_does_not_count_as_presented(monkeypatch, name):
    from servonaut.app import ServonautApp

    snapshots = [status.UpdateStatus(name, VERSION, "pipx", "stable", TARGET)]
    monkeypatch.setattr(status, "read_update_status", lambda _runtime: snapshots[0])
    notices, marks = [], []

    def mark(version):
        marks.append(version)
        return True

    monkeypatch.setattr(status, "mark_update_presented", mark)
    app = SimpleNamespace(runtime_layout=None, _show_update_button=lambda _version: None,
                          notify=lambda message, **_kwargs: notices.append(message))
    await ServonautApp._show_generation_update(app)
    assert notices == []
    assert marks == []

    snapshots[0] = status.UpdateStatus("ready", VERSION, "pipx", "stable", TARGET)
    await ServonautApp._show_generation_update(app)
    assert len(notices) == 1
    assert marks == [TARGET]


def test_metadata_rewrite_cannot_reactivate_a_completed_manual_pin(install, route):
    store, _ = install
    _spec(store, f"servonaut[mcp]=={VERSION}")
    assert route("--mcp") == "launcher"
    journal = store.read("state.json")
    assert journal["pin"] == {"version": VERSION, "from": ACTIVE_VERSION}
    _ready(store, journal)
    journal["generations"][READY]["verified_at"] = time.time()
    store.write("state.json", journal)
    assert route("--mcp") == READY

    metadata = store.root / "pipx_metadata.json"
    contents = json.loads(metadata.read_text())
    original = metadata.stat().st_mtime_ns
    contents["injected_packages"] = {"sample": {"package_or_url": "example-package"}}
    metadata.write_text(json.dumps(contents))
    os.utime(metadata, ns=(original + 1_000_000_000,) * 2)
    assert route("--mcp") == READY
    assert "pin" not in store.read("state.json")


def _lease(pid, launched_at, *, started=False):
    return {
        "id": f"{pid:032x}", "birth": "identity", "generation": CURRENT, "role": "mcp",
        "version": ACTIVE_VERSION, "launched_at": launched_at, "started": started,
    }


def test_live_acknowledged_session_vetoes_startup_demotion(install, route, monkeypatch):
    store, _ = install
    monkeypatch.setattr(state, "birth", lambda pid: "identity" if pid == 8000 else None)
    now = time.time()
    leases = {"8000": _lease(8000, now - 1200, started=True),
              "8001": _lease(8001, now - 4), "8002": _lease(8002, now - 2)}
    store.write("leases.json", leases)
    assert route("--mcp") == CURRENT
    assert store.read("state.json")["generations"][CURRENT]["health"] == "healthy"


def test_recent_acknowledgement_resets_preceding_failed_attempts(install, route, monkeypatch):
    store, _ = install
    monkeypatch.setattr(state, "birth", lambda _pid: None)
    now = time.time()
    confirmed = _lease(8000, now - 120)
    failures = {"8001": _lease(8001, now - 20), "8002": _lease(8002, now - 10)}
    store.write("leases.json", {"8000": confirmed, **failures})
    store.acknowledge(confirmed["id"])
    assert route("--mcp") == CURRENT
    assert all(pid not in store.read("leases.json") for pid in failures)


@pytest.mark.parametrize("flag", ["--help", "--version", "--update"])
def test_installed_entry_acknowledges_an_inherited_lease_on_all_routes(
    install, monkeypatch, flag,
):
    store, _ = install
    generation = directory_for(store, CURRENT)
    monkeypatch.setattr(sys, "prefix", str(generation))
    lease = _lease(os.getpid(), time.time())
    monkeypatch.setenv("_SERVONAUT_UPDATE_LEASE_ID", lease["id"])
    store.write("leases.json", {str(os.getpid()): lease})
    seen = []
    marker = store.directory / "acks" / lease["id"]
    monkeypatch.setattr(entry, "_dispatch", lambda: seen.append(marker.is_file()))
    entry._route([flag])
    assert seen == [True]


@pytest.mark.parametrize("error", [errno.ENOMEM, errno.ETXTBSY, errno.EAGAIN, errno.EMFILE])
def test_transient_exec_failure_falls_back_without_demoting(install, monkeypatch, error):
    store, _ = install
    seen = []

    def execute(path, *_args):
        seen.append(Path(path).parent.parent.name)
        if len(seen) == 1:
            raise OSError(error, "fixture transient failure")
        raise SystemExit(0)

    monkeypatch.setattr(entry, "_run_generation", execute)
    with pytest.raises(SystemExit) as result:
        entry._route(["--mcp"])
    assert result.value.code == 0
    assert seen == [CURRENT, OLD]
    journal = store.read("state.json")
    assert journal["current"] == CURRENT
    assert journal["generations"][CURRENT]["health"] == "healthy"


@pytest.mark.parametrize(("case", "expected"), [
    ("held_gate", "busy"), ("existing_worker", "busy"), ("skip", "skipped"),
    ("spawn_error", "failed"), ("starts", "queued"),
])
def test_forced_check_reports_the_actual_outcome(install, monkeypatch, case, expected):
    store, _ = install
    if case == "held_gate":
        store.write("preferences.json", {"admission_timeout": 0.01})
        with store.gate():
            assert builder.queue_update_check(store, VERSION) == expected
        return
    if case == "skip":
        monkeypatch.setenv("SERVONAUT_SKIP_AUTO_APPLY", "1")
    elif case == "spawn_error":
        def fail(*_args, **_kwargs):
            raise OSError(errno.ENOMEM, "fixture unavailable process")
        monkeypatch.setattr(builder, "schedule", fail)
    elif case == "starts":
        monkeypatch.setattr(builder, "schedule",
                            lambda *_args, **_kwargs: SimpleNamespace(wait=lambda: 0))
    else:
        monkeypatch.setattr(builder, "schedule", lambda *_args, **_kwargs: None)
    assert builder.queue_update_check(store, VERSION) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("result", ["queued", "busy", "skipped", "failed"])
async def test_settings_receives_the_discovery_outcome(install, monkeypatch, result):
    from servonaut.app import ServonautApp

    store, _ = install
    monkeypatch.setattr(UpdateLayout, "detect", lambda: UpdateLayout(store, CURRENT))
    snapshot = status.UpdateStatus("up_to_date", ACTIVE_VERSION, "pipx", "stable")
    monkeypatch.setattr(status, "read_update_status", lambda _runtime: snapshot)
    monkeypatch.setattr(builder, "queue_update_check", lambda *_args: result)
    jobs = []
    app = SimpleNamespace(runtime_layout=None, run_worker=lambda job, **_kwargs: jobs.append(job))
    observed = await ServonautApp.request_update_check(app)
    for job in jobs:
        job.close()
    assert observed == result
    assert jobs == []
