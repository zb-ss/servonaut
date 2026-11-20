"""Tests for acknowledgement concurrency, promotion eligibility and updater recovery."""

import errno
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace

import pytest

from servonaut import entry
from servonaut.updates import builder, index, launch, profile, state
from servonaut.updates.generations import directory_for, evacuate_unused
from servonaut.updates.layout import python_for
from servonaut.updates.status import ADMISSION_DEFAULT, UpdateBusy
from tests.test_update_review import (
    ACTIVE_VERSION, CURRENT, OLD, READY, TARGET, VERSION, _initialize, install,
)


@pytest.fixture
def route(monkeypatch):
    executed = []

    def dispatch():
        executed.append("launcher")

    def run_generation(path, *_arguments):
        executed.append(Path(path).parent.parent.name)
        raise SystemExit(0)

    monkeypatch.setattr(entry, "_dispatch", dispatch)
    monkeypatch.setattr(entry, "_run_generation", run_generation)

    def run(*args):
        try:
            entry._route(list(args))
        except SystemExit as error:
            assert error.code == 0
        return executed[-1]

    return run


def _ready(store, journal, **changes):
    now = time.time()
    _initialize(store, journal, READY, TARGET)
    journal["generations"][READY]["verified_at"] = now - 600
    journal.update(ready=READY, offered=TARGET, offered_at=now - 2, presented_at=now - 1)
    journal.update(changes)
    store.write("state.json", journal)


@pytest.mark.parametrize("code", [1, 2])
def test_command_exit_status_never_demotes_healthy_generation(install, monkeypatch, code):
    store, _ = install
    monkeypatch.setattr(sys, "prefix", str(directory_for(store, CURRENT)))

    def fail():
        raise SystemExit(code)

    monkeypatch.setattr(entry, "_dispatch", fail)
    for _attempt in range(3):
        with pytest.raises(SystemExit) as error:
            entry._route(["--no-such-flag"])
        assert error.value.code == code
    updated = store.read("state.json")
    assert updated["current"] == CURRENT
    assert updated["generations"][CURRENT]["health"] == "healthy"


def test_twenty_acknowledgements_succeed_while_gate_is_held(install, route, monkeypatch):
    store, _ = install
    owners = range(8000, 8020)
    monkeypatch.setattr(state, "birth", lambda _pid: None)
    timestamp = time.time()
    rows = {
        str(pid): {"id": f"{pid:032x}", "role": "mcp", "generation": CURRENT,
                   "version": ACTIVE_VERSION, "started": False, "launched_at": timestamp}
        for pid in owners
    }
    store.write("leases.json", rows)
    barrier = Barrier(len(owners))

    def confirm(pid):
        barrier.wait(timeout=5)
        token = rows[str(pid)]["id"]
        try:
            if hasattr(state.InstallState, "discard_lease"):
                store.acknowledge(token)
            else:
                store.acknowledge("mcp", CURRENT, ACTIVE_VERSION, str(pid))
        except UpdateBusy:
            return False
        return True

    with store.gate(), ThreadPoolExecutor(max_workers=len(owners)) as pool:
        acknowledged = list(pool.map(confirm, owners))
    assert all(acknowledged)
    assert route("--mcp") == CURRENT
    assert not any((store.directory / "acks").iterdir())


@pytest.mark.parametrize("barrier", ["postponed", "unpresented", "pinned"])
def test_ineligible_stale_stage_never_checks_index(install, route, monkeypatch, barrier):
    store, journal = install
    if barrier == "postponed":
        changes = {"postponed": {TARGET: time.time() + 600}}
    elif barrier == "unpresented":
        changes = {"presented_at": 0}
    else:
        changes = {"pin": {"version": VERSION, "from": TARGET}}
    _ready(store, journal, **changes)
    calls = []

    def check(*_args):
        calls.append(True)
        time.sleep(0.2)

    monkeypatch.setattr(launch, "_verify", check)
    started = time.monotonic()
    assert route("--mcp") == ("launcher" if barrier == "pinned" else CURRENT)
    assert not calls
    assert time.monotonic() - started < 0.18


def test_unreachable_stale_stage_checks_only_once_per_window(install, route, monkeypatch):
    store, journal = install
    _ready(store, journal)
    calls, queued = [], []

    def offline(*_args):
        calls.append(True)
        time.sleep(0.2)

    monkeypatch.setattr(launch, "_verify", offline)
    monkeypatch.setattr(launch, "schedule", lambda *_args: queued.append(True))
    assert route("--mcp") == CURRENT
    started = time.monotonic()
    assert route("--mcp") == CURRENT
    assert time.monotonic() - started < 0.18
    assert calls == [True]
    assert queued
    record = store.read("state.json")["generations"][READY]
    assert record["last_validation_attempt_at"] > record["verified_at"]


def test_hourly_worker_drops_a_withdrawn_ready_copy_even_if_fresh(install, monkeypatch):
    store, journal = install
    _ready(store, journal)
    journal["generations"][READY]["verified_at"] = time.time()
    store.write("state.json", journal)
    monkeypatch.setattr(launch, "_verify", lambda *_args: False)
    launch.refresh_ready(store)
    updated = store.read("state.json")
    assert "ready" not in updated
    assert updated["status"] == "failed"
    assert updated["current"] == CURRENT


@pytest.mark.parametrize("expired_by", ["age", "reboot"])
def test_quarantine_allows_collection_again(install, monkeypatch, expired_by):
    store, journal = install
    unused = "4" * 32
    _initialize(store, journal, unused, VERSION)
    journal["generations"][unused]["health"] = "failed"
    prefs = state.Preferences()
    now = time.time()
    journal["unknown_leases"] = {"boot": "original", "since": now}
    monkeypatch.setattr(state, "boot_identity", lambda: "original", raising=False)
    assert not evacuate_unused(store, journal, prefs)
    if expired_by == "reboot":
        monkeypatch.setattr(state, "boot_identity", lambda: "new")
    else:
        journal["unknown_leases"]["since"] = now - 8 * 24 * 3600
    assert evacuate_unused(store, journal, prefs)
    assert "unknown_leases" not in journal
    assert not directory_for(store, unused).exists()


def _spec(store, requirement):
    (store.root / "pipx_metadata.json").write_text(json.dumps({
        "main_package": {"package_or_url": requirement},
    }))


def test_normal_pipx_stable_upgrade_keeps_a_newer_rc(install, route, monkeypatch):
    store, journal = install
    journal["generations"][CURRENT]["version"] = "2.41.0rc2"
    journal["last_launcher_version"] = "2.40.0"
    store.write("state.json", journal)
    store.write("preferences.json", {"channel": "rc"})
    monkeypatch.setattr("servonaut.get_version", lambda: "2.40.1")
    _spec(store, "servonaut")
    assert route("--mcp") == CURRENT
    assert "pin" not in store.read("state.json")


@pytest.mark.parametrize("operator", ["==", "==="])
def test_exact_install_pins_an_unchanged_launcher_only_once(install, route, operator):
    store, journal = install
    _spec(store, f"servonaut[mcp]{operator}{VERSION}")
    assert route("--mcp") == "launcher"
    updated = store.read("state.json")
    assert updated["pin"] == {"version": VERSION, "from": ACTIVE_VERSION}
    _ready(store, updated)
    updated["generations"][READY]["verified_at"] = time.time()
    store.write("state.json", updated)
    assert route("--mcp") == READY
    assert route("--mcp") == READY
    assert "pin" not in store.read("state.json")


@pytest.mark.parametrize("exact", [True, False])
def test_downgrade_is_pinned_without_an_active_generation(install, route, exact):
    store, journal = install
    journal.pop("current")
    journal.pop("previous")
    journal["last_launcher_version"] = ACTIVE_VERSION
    store.write("state.json", journal)
    _spec(store, f"servonaut=={VERSION}" if exact else "servonaut")
    assert route("--mcp") == "launcher"
    assert store.read("state.json")["pin"] == {"version": VERSION, "from": ACTIVE_VERSION}


def test_exact_install_prevents_an_existing_ready_copy_from_switching(install, route, monkeypatch):
    store, journal = install
    journal.pop("current")
    journal.pop("previous")
    _ready(store, journal)
    journal["generations"][READY]["verified_at"] = time.time()
    store.write("state.json", journal)
    _spec(store, f"servonaut=={VERSION}")
    monkeypatch.setattr(launch, "_verify", lambda *_args: pytest.fail("Pinned target was checked"))
    assert route("--mcp") == "launcher"
    assert store.read("state.json")["pin"] == {"version": VERSION, "from": TARGET}


@pytest.mark.parametrize("location", ["recorded", "user", "shared"])
def test_pipx_discovery_without_path(install, monkeypatch, location):
    store, _ = install
    _spec(store, "servonaut")
    monkeypatch.setattr("shutil.which", lambda _name: None)
    recorded = None
    if location == "shared":
        executable = python_for(store.root.parent.parent / "shared")
    elif location == "user":
        executable = Path.home() / ".local" / "bin" / ("pipx.exe" if os.name == "nt" else "pipx")
    else:
        executable = Path.home() / "tools" / "pipx"
        recorded = [str(executable)]
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.touch()
    observed = []

    def check(command, **_kwargs):
        observed.append(command)
        return str(store.root.parent)

    monkeypatch.setattr(profile.subprocess, "check_output", check)
    monkeypatch.setattr(profile, "_usual_locations",
                        lambda: (executable,) if location == "user" else (), raising=False)
    if hasattr(profile.Profile, "pipx_command"):
        profile.load_profile(store.root, 1, recorded)
    else:
        profile.load_profile(store.root, 1)
    prefix = [str(executable), "-m", "pipx"] if location == "shared" else [str(executable)]
    assert observed == [[*prefix, "environment", "--value", "PIPX_LOCAL_VENVS"]]


def test_missing_pipx_preserves_offer_and_throttles(install):
    store, journal = install
    _ready(store, journal, status="ready", builder={"token": "builder"}, checked_at=time.time())
    now = time.time()
    builder._failed(store, "builder", None, profile.PipxUnavailable("pipx unavailable to caller"))
    updated = store.read("state.json")
    assert updated["status"] == "ready"
    assert updated["ready"] == READY and updated["offered"] == TARGET
    assert updated["checked_at"] > 0
    assert now < updated["check_failure"]["retry_at"] <= now + 3601
    assert "failure" not in updated


@pytest.mark.parametrize(("configured_cap", "expected_cap"), [
    (None, 3600), (10800, 10800), (59, 3600), (86401, 3600), (10**400, 3600),
])
def test_check_failures_cap_separately_from_build_failures(install, configured_cap, expected_cap):
    store, journal = install
    store.write("preferences.json", {
        "retry_base_seconds": 14400, "check_retry_max_seconds": configured_cap,
    })
    journal["builder"] = {"token": "first"}
    store.write("state.json", journal)
    start = time.time()
    builder._failed(store, "first", None, TimeoutError("offline"))
    updated = store.read("state.json")
    assert expected_cap <= updated["failure"]["retry_at"] - start <= expected_cap + 1
    updated["builder"] = {"token": "second"}
    store.write("state.json", updated)
    builder._failed(store, "second", TARGET, TimeoutError("failed build"))
    assert store.read("state.json")["failure"]["retry_at"] - start >= 14400


def test_start_lock_timeout_runs_the_unmanaged_launcher(install, route):
    store, _ = install
    assert ADMISSION_DEFAULT == 3
    store.write("preferences.json", {"admission_timeout": 0.02})
    with store.gate():
        started = time.monotonic()
        assert route("--mcp") == "launcher"
        assert time.monotonic() - started < 0.4


def test_application_exit_waits_at_most_one_second_for_gate(install, monkeypatch):
    store, _ = install
    store.write("preferences.json", {"admission_timeout": 1.2})
    monkeypatch.setattr(sys, "prefix", str(directory_for(store, CURRENT)))
    monkeypatch.setattr(entry, "_dispatch", lambda: None)
    lease_id = "a" * 32
    store.write("leases.json", {str(os.getpid()): {
        "id": lease_id, "role": "cli", "generation": CURRENT, "version": ACTIVE_VERSION,
        "started": False, "launched_at": time.time(),
    }})
    monkeypatch.setenv("_SERVONAUT_UPDATE_LEASE_ID", lease_id)
    with store.gate():
        started = time.monotonic()
        entry._route(["--mcp"])
        assert time.monotonic() - started < 1.15
    assert store.read("leases.json")[str(os.getpid())]["id"] == lease_id


def test_exec_fallback_releases_the_failed_generation_lease(install, monkeypatch):
    store, _ = install
    seen = []

    def execute(_console, _arguments, _worker, *_lease):
        record = store.read("leases.json")[str(os.getpid())]
        seen.append(record["generation"])
        if len(seen) == 1:
            raise OSError(errno.ENOEXEC, "unusable executable")
        raise SystemExit(0)

    monkeypatch.setattr(entry, "_run_generation", execute)
    with pytest.raises(SystemExit):
        entry._route(["--mcp"])
    assert seen == [CURRENT, OLD]


def test_forced_check_uses_anchor_and_bypasses_interval(install, monkeypatch):
    store, journal = install
    journal["checked_at"] = time.time()
    journal["check_failure"] = {"retry_at": time.time() + 5000}
    store.write("state.json", journal)
    from tests.test_update_review import _SCHEDULE

    monkeypatch.setattr(builder, "schedule", _SCHEDULE)
    started = []

    def spawn(command, **kwargs):
        started.append((command, kwargs))
        return SimpleNamespace(pid=os.getpid(), wait=lambda: 0)

    monkeypatch.setattr(builder.subprocess, "Popen", spawn)
    builder.queue_update_check(store, ACTIVE_VERSION)
    command, options = started[0]
    assert command[0] == str(python_for(store.root))
    assert command[-1] == VERSION
    assert options["cwd"] == store.directory
    assert options["stdin"] == builder.subprocess.DEVNULL
    assert store.read("state.json")["builder"]["pid"] == os.getpid()


@pytest.mark.parametrize("blocked", ["skip", "gate"])
def test_forced_check_respects_skip_and_gate(install, monkeypatch, blocked):
    store, _ = install
    store.write("preferences.json", {"admission_timeout": 0.01})
    monkeypatch.setattr(builder, "schedule", lambda *_a, **_kw: pytest.fail("Discovery was started"))
    original = (store.directory / "state.json").read_bytes()
    if blocked == "skip":
        monkeypatch.setenv("SERVONAUT_SKIP_AUTO_APPLY", "1")
        builder.queue_update_check(store, ACTIVE_VERSION)
    else:
        with store.gate():
            builder.queue_update_check(store, ACTIVE_VERSION)
    assert (store.directory / "state.json").read_bytes() == original


@pytest.mark.asyncio
@pytest.mark.parametrize("managed_elsewhere", [True, False])
async def test_public_update_check_returns_after_queuing(install, managed_elsewhere, monkeypatch):
    from servonaut.app import ServonautApp
    from servonaut.updates import layout, status

    store, _ = install
    layout_result = layout.UpdateLayout(store, CURRENT)
    snapshot = status.UpdateStatus(
        "managed_elsewhere" if managed_elsewhere else "up_to_date",
        ACTIVE_VERSION, "pipx", "stable",
    )
    monkeypatch.setattr(layout.UpdateLayout, "detect", lambda: layout_result)
    monkeypatch.setattr(status, "read_update_status", lambda _runtime: snapshot)
    work, calls = [], []
    def queue(install, version):
        calls.append((install, version))
        return "queued"

    monkeypatch.setattr(builder, "queue_update_check", queue)

    async def legacy_check():
        calls.append("legacy")

    app = SimpleNamespace(runtime_layout=None, _check_legacy_update=legacy_check,
                          run_worker=lambda job, **_kwargs: work.append(job))
    assert await ServonautApp.request_update_check(app) == "queued"
    if managed_elsewhere:
        assert len(work) == 1
        assert calls == []
        await work[0]
        assert calls == ["legacy"]
    else:
        assert work == []
        assert calls == [(store, ACTIVE_VERSION)]


@pytest.mark.asyncio
async def test_generation_toast_reports_preparing_and_ready(monkeypatch):
    from servonaut.app import ServonautApp
    from servonaut.updates import status

    current = ["building"]
    seen = []
    monkeypatch.setattr(status, "read_update_status", lambda _runtime: status.UpdateStatus(
        current[0], VERSION, "pipx", "stable", TARGET,
    ))
    monkeypatch.setattr(status, "mark_update_presented", lambda _version: True)
    app = SimpleNamespace(runtime_layout=None, _show_update_button=lambda _version: None,
                          notify=lambda message, **options: seen.append((message, options["markup"])))
    await ServonautApp._show_generation_update(app)
    current[0] = "ready"
    await ServonautApp._show_generation_update(app)
    await ServonautApp._show_generation_update(app)
    assert seen == [
        (f"Servonaut {TARGET} is being prepared", False),
        (f"{TARGET} is ready · starts the next time you open Servonaut", False),
    ]


@pytest.mark.asyncio
async def test_public_manual_upgrade_routes_to_the_pipx_anchor(install, monkeypatch):
    from servonaut import app
    from servonaut.updates import layout

    store, _ = install
    installed = layout.UpdateLayout(store, CURRENT)
    monkeypatch.setattr(layout.UpdateLayout, "detect", lambda: installed)
    called = []

    def upgrade(command, **options):
        called.append((command, options["cwd"]))
        return SimpleNamespace(returncode=0, stdout="Updated successfully\n")

    monkeypatch.setattr(app.subprocess, "run", upgrade)
    result = await app.ServonautApp().run_requested_upgrade()
    assert result == (True, "Updated successfully")
    assert called == [([str(installed.launcher), "--update"], store.root)]
