"""Regressions for update ownership, state display and Settings actions."""
import asyncio
import os
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from textual.widgets import Button, Static

from servonaut.runtime import DistributionKind
from servonaut.services.update_service import UpdateService
from servonaut.updates import status
from servonaut.updates.layout import python_for
from servonaut.updates.state import InstallState
from servonaut.widgets.busy_indicator import BusyIndicator
from tests.test_settings_updates_panel import (
    _UpdatesHost, _fake_runtime, _reset_identity, _seed_pipx_files, _wait_updates_panel, pipx_env,
)
from tests._async_bounds import wait_until


pytestmark = pytest.mark.asyncio
TARGET = "2.35.0"


def text(panel, widget):
    return str(panel.query_one(widget, Static).render())




async def test_channel_save_contention_keeps_ui_responsive_and_dirty(tmp_path, pipx_env, monkeypatch):
    directory = _seed_pipx_files(pipx_env, preferences={"channel": "stable", "admission_timeout": 0.18})
    waits = []
    ui_thread = threading.get_ident()

    def observe_sleep(seconds):
        waits.append((threading.get_ident(), seconds))
        time.sleep(seconds)

    monkeypatch.setattr(status, "time", SimpleNamespace(
        time=time.time, monotonic=time.monotonic, sleep=observe_sleep,
    ))
    app = _UpdatesHost(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert await pilot.click("#updates_channel_rc")
        await wait_until(panel.is_dirty)
        with status.update_gate(directory, 1.0):
            assert await pilot.click("#save_updates")
            await wait_until(lambda: any("Couldn't save" in msg for msg, _ in app.notifications))
        assert waits and all(tid != ui_thread for tid, _ in waits)
        assert sum(duration for _, duration in waits) >= 0.14
        assert "Couldn't save the update channel right now. Try again." in text(panel, "#status_updates")
        assert any(
            msg == "Couldn't save the update channel right now. Try again." and settings["markup"] is False
            for msg, settings in app.notifications
        )
        assert panel.is_dirty()


async def test_detached_check_renders_ready_offer_when_the_worker_finishes(tmp_path, pipx_env):
    _seed_pipx_files(
        pipx_env, state={"status": "up_to_date"}, preferences={"status_poll_seconds": 0.10},
    )
    app = _UpdatesHost(tmp_path)
    app.request_update_check = AsyncMock(return_value="queued")
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert await pilot.click("#updates_btn_check")
        await wait_until(lambda: not panel._busy and app.request_update_check.await_count == 1)
        assert "Checking for updates" in text(panel, "#updates_status_primary")
        assert "Up to date" not in text(panel, "#updates_status_primary")
        _seed_pipx_files(pipx_env, state={"status": "ready", "offered": TARGET})
        await wait_until(lambda: f"{TARGET} is ready" in text(panel, "#updates_status_primary"))
        assert panel.query_one("#updates_btn_postpone", Button).display


@pytest.mark.parametrize("state_name", ["offered", "ready"])
async def test_postponed_offer_gives_only_the_deferred_start(tmp_path, pipx_env, state_name):
    deadline = time.time() + 3600
    _seed_pipx_files(pipx_env, state={
        "status": state_name, "offered": TARGET, "postponed": {TARGET: deadline},
    })
    app = _UpdatesHost(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        primary, secondary = (
            text(panel, "#updates_status_primary"), text(panel, "#updates_status_secondary")
        )
        assert "Postponed until" in secondary
        assert "installs at the next start after that" in secondary
        assert "starts the next time you open Servonaut" not in primary
        assert "will install in the background" not in primary
        assert ", installs at the next start after that" in secondary
        assert panel.query_one("#updates_btn_postpone", Button).display is False


async def test_out_of_range_postpone_is_ignored_and_renders(tmp_path, pipx_env):
    _seed_pipx_files(pipx_env, state={
        "status": "ready", "offered": TARGET, "postponed": {TARGET: 10 ** 35},
    })
    app = _UpdatesHost(tmp_path)
    assert status.read_update_status(app.runtime_layout).postponed_until is None
    from servonaut.screens.settings.panels.updates import format_postponed_until
    assert format_postponed_until(10 ** 35) == ""
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert f"{TARGET} is ready" in text(panel, "#updates_status_primary")


async def test_demo_details_use_display_redaction(tmp_path, pipx_env, monkeypatch):
    marker = "/home/user/private-update.log"
    _seed_pipx_files(pipx_env, state={
        "status": "failed", "offered": TARGET, "failure": {"message": f"See {marker} for details [red]"},
    })
    app = _UpdatesHost(tmp_path, demo_mode=True)
    monkeypatch.setattr(app, "redact_display_text", lambda s: s.replace(marker, "/home/user/update.log"))
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert await pilot.click("#updates_link_details")
        await wait_until(lambda: panel.query_one("#updates_failure_details", Static).display)
        assert marker not in text(panel, "#updates_failure_details")
        assert "/home/user/update.log" in text(panel, "#updates_failure_details")
        assert "[red]" in text(panel, "#updates_failure_details")


async def test_arabic_letter_mark_is_removed_from_version_text(tmp_path, pipx_env):
    mark = "\u061c"
    _seed_pipx_files(pipx_env, state={
        "status": "ready", "offered": f"2.{mark}35.0[red]",
    })
    app = _UpdatesHost(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert mark not in text(panel, "#updates_status_primary")
        assert "[red]" in text(panel, "#updates_status_primary")
        assert not panel.query_one("#updates_link_release_notes").display


async def test_pip_update_now_keeps_package_and_network_queries_off_ui_thread(tmp_path, monkeypatch):
    ui_thread = threading.get_ident()
    calls = []

    def observe_version():
        calls.append(("version", threading.get_ident()))
        return "2.34.0" if len(calls) == 1 else "2.35.0"

    def observe_check():
        calls.append(("network", threading.get_ident()))
        return TARGET

    async def communicate():
        return b"", b""

    runtime = _fake_runtime(DistributionKind.PIP)
    service = UpdateService(runtime=runtime)
    monkeypatch.setattr(service, "installed_version_external", observe_version)
    monkeypatch.setattr(service, "check_for_update", observe_check)
    monkeypatch.setattr(service, "_installed_package_version", lambda: "2.34.0")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=SimpleNamespace(
        returncode=0, communicate=communicate,
    )))
    app = _UpdatesHost(tmp_path, runtime=runtime, update_service=service)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        panel._status = status.UpdateStatus("managed_elsewhere", "2.34.0", "pip", "stable", required_minimum=TARGET)
        panel._render_status()
        button = panel.query_one("#updates_btn_update", Button)
        assert button.display
        button.press()
        await wait_until(lambda: len(calls) == 3 and not panel._busy)
        assert [operation for operation, _ in calls] == ["version", "network", "version"]
        assert all(thread != ui_thread for _, thread in calls)


async def test_ready_release_above_pin_threshold_can_be_postponed(tmp_path, pipx_env):
    target = "2.36.0"
    generation = "a" * 32
    current_state = {
        "status": "ready", "offered": target, "offered_at": time.time() - 50,
        "presented_at": time.time() - 10, "ready": generation,
        "generations": {generation: {"version": target, "health": "healthy"}},
        "pin": {"version": "2.34.0", "from": TARGET},
    }
    directory = _seed_pipx_files(pipx_env, state=current_state)
    generation_path = directory / "generations" / generation
    python = python_for(generation_path)
    python.parent.mkdir(parents=True)
    python.touch()
    python.chmod(0o755)
    status.write_json(generation_path / status.MARKER_NAME, {
        "anchor": str(pipx_env), "generation": generation,
    })
    app = _UpdatesHost(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert panel._status.can_postpone
        assert f"{target} is ready" in text(panel, "#updates_status_primary")
        assert panel.query_one("#updates_btn_postpone", Button).display


async def test_stable_channel_reports_prepared_rc_will_be_skipped(tmp_path, pipx_env):
    current, target = "2.35.0rc1", "2.35.0rc2"
    generation = "a" * 32
    current_state = {
        "status": "ready", "offered": target, "offered_at": time.time() - 50,
        "presented_at": time.time() - 10, "ready": generation,
        "generations": {generation: {"version": target}},
    }
    _seed_pipx_files(pipx_env, state=current_state, preferences={"channel": "rc"})
    runtime = _fake_runtime(DistributionKind.PIPX, version=current)
    app = _UpdatesHost(tmp_path, runtime=runtime)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert await pilot.click("#updates_channel_stable")
        await wait_until(panel.is_dirty)
        assert "no downgrade" in text(panel, "#updates_channel_note")
        assert await pilot.click("#save_updates")
        await wait_until(lambda: not panel.is_dirty())
        prefs = InstallState(pipx_env).preferences()
        assert prefs.channel == "stable"
        primary = text(panel, "#updates_status_primary")
        assert f"{target} was prepared for Release candidates" in primary
        assert "won't be used on the Stable channel" in primary
        assert not panel.query_one("#updates_btn_postpone", Button).display


async def test_session_note_uses_older_lease_version_and_excludes_current_sessions(tmp_path, pipx_env):
    _seed_pipx_files(
        pipx_env,
        state={
            "status": "ready", "offered": TARGET, "current": "a" * 32,
            "generations": {"a" * 32: {"version": "2.33.1"}},
        },
        leases={
            "101": {"role": "mcp", "version": "2.33.0", "started": True},
            "102": {"role": "cli", "version": "2.33.1", "started": True},
            "103": {"role": "relay", "version": "2.34.0", "started": True},
            str(os.getpid()): {"role": "tui", "version": "2.33.0", "started": True},
        },
    )
    app = _UpdatesHost(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        note = text(panel, "#updates_status_secondary")
        assert "1 MCP server keeps 2.33.0" in note
        assert panel._status.old_sessions == ("mcp",)


async def test_presentation_is_retried_on_next_render_after_failed_write(tmp_path, pipx_env, monkeypatch):
    directory = _seed_pipx_files(pipx_env, state={"status": "up_to_date"})
    marker_calls = []

    real_marker = status.mark_update_presented

    def marker(version):
        marker_calls.append(version)
        return len(marker_calls) > 1 and real_marker(version)

    monkeypatch.setattr(status, "mark_update_presented", marker)
    app = _UpdatesHost(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        _seed_pipx_files(pipx_env, state={"status": "ready", "offered": TARGET})
        panel._status = await asyncio.to_thread(status.read_update_status, app.runtime_layout)
        panel._render_status()
        await wait_until(lambda: marker_calls == [TARGET])
        await wait_until(lambda: not any(
            worker.group == "updates_present" and not worker.is_finished for worker in app.workers
        ))
        panel._render_status()
        await wait_until(lambda: "presented_at" in status.read_json(directory / "state.json"))
        assert marker_calls == [TARGET, TARGET]


async def test_app_upgrade_remains_single_flight_across_panel_teardown(
    tmp_path, pipx_env, monkeypatch,
):
    from servonaut import app as app_module
    from servonaut.updates.layout import UpdateLayout

    _seed_pipx_files(pipx_env, state={
        "status": "failed", "offered": TARGET, "failure": {"message": "The update build failed."},
    })
    app = _UpdatesHost(tmp_path)
    layout = SimpleNamespace(
        generation="a" * 32, store=InstallState(pipx_env), launcher=pipx_env / "bin" / "servonaut",
    )
    monkeypatch.setattr(UpdateLayout, "detect", staticmethod(lambda: layout))
    active = set()
    calls = []
    release = threading.Event()

    def simulate_package_process(command, **kwargs):
        assert command[-1] == "--update"
        tid = threading.get_ident()
        active.add(tid)
        calls.append(tid)
        try:
            release.wait(8)
            return SimpleNamespace(returncode=0, stdout="Updated")
        finally:
            active.remove(tid)

    monkeypatch.setattr(app_module, "subprocess", SimpleNamespace(
        run=simulate_package_process, SubprocessError=RuntimeError,
    ))
    try:
        async with app.run_test(size=(160, 50)) as pilot:
            panel = await _wait_updates_panel(app, pilot)
            panel.query_one("#updates_btn_try", Button).press()
            await wait_until(lambda: len(active) == 1)
            await app.pop_screen()
            await wait_until(lambda: not panel.is_attached)
            assert len(active) == 1
            app.open_settings_screen("updates")
            new_panel = await _wait_updates_panel(app, pilot)
            assert new_panel is not panel
            assert new_panel.query_one("#updates_busy", BusyIndicator).is_active
            assert new_panel.query_one("#updates_btn_try", Button).disabled
            assert await app.run_requested_upgrade() == (False, "An update is already running.")
            assert len(calls) == 1
            release.set()
            await wait_until(lambda: not active and not app._update_in_progress)
            await wait_until(lambda: not new_panel.query_one("#updates_btn_try", Button).disabled)
    finally:
        release.set()
