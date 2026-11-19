"""Settings → Updates panel snapshots at 160x50 and 100x30."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Button, RadioButton

from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)
from servonaut.screens.settings.panels.updates import UpdatesPanel
from servonaut.updates import status as updates_status

from . import _harness

_SNAPSHOT_VERSION = "2.34.0"


def _pipx_runtime(home: Path) -> RuntimeLayout:
    return RuntimeLayout(
        kind=DistributionKind.PIPX,
        product_version=_SNAPSHOT_VERSION,
        build_revision=None,
        resource_root=home,
        executable_root=home,
        data_root=home / ".servonaut",
        executable=home / "servonaut",
        python_executable=home / "python",
        path_console=None,
        console_helper=None,
        desktop_child=None,
        package_management=PackageManagementCapability(
            PackageManagementKind.PIPX, ("pipx",), True,
        ),
        is_frozen=False,
    )


def _seed_state(home: Path, monkeypatch: pytest.MonkeyPatch, scenario: str) -> RuntimeLayout:
    anchor = home / "pipx" / "venvs" / "servonaut"
    anchor.mkdir(parents=True, exist_ok=True)
    (anchor / updates_status.PIPX_METADATA).write_text("{}", encoding="utf-8")
    monkeypatch.setattr(updates_status.sys, "prefix", str(anchor))
    monkeypatch.setattr(updates_status, "get_version", lambda: _SNAPSHOT_VERSION)
    directory = updates_status.storage_for(anchor)
    with updates_status.update_gate(directory, 2.0):
        updates_status.write_json(directory / "preferences.json", {"channel": "stable"})
        if scenario == "up_to_date":
            updates_status.write_json(directory / "state.json", {"status": "up_to_date"})
        elif scenario == "update_ready":
            updates_status.write_json(
                directory / "state.json",
                {"status": "ready", "offered": "2.35.0"},
            )
            updates_status.write_json(
                directory / "leases.json",
                {"101": {"role": "mcp", "version": _SNAPSHOT_VERSION}},
            )
        elif scenario == "server_minimum":
            updates_status.write_json(
                directory / "state.json",
                {
                    "status": "up_to_date",
                    "policy": {"mode": "enforce", "minimum_version": "2.35.0"},
                },
            )
        elif scenario == "pinned":
            updates_status.write_json(
                directory / "state.json",
                {
                    "status": "up_to_date",
                    "pin": {"version": _SNAPSHOT_VERSION, "from": "2.35.0"},
                },
            )
    return _pipx_runtime(home)


def _geometry_check(size: str) -> Any:
    def check(pilot: Any) -> None:
        panel = pilot.app.screen._current_panel()
        assert isinstance(panel, UpdatesPanel)
        panel_body = panel.query_one(".panel-body", VerticalScroll)
        status_body = panel.query_one("#updates_status_body", Vertical)
        status_actions = panel.query_one("#updates_status_actions", Vertical)
        save_btn = panel.query_one("#save_updates", Button)

        assert pilot.app.screen.region.contains_region(save_btn.region)
        assert pilot.app.get_widget_at(*save_btn.region.center)[0] is save_btn
        for selector in ("#updates_channel_stable", "#updates_channel_rc"):
            btn = panel.query_one(selector, RadioButton)
            assert btn.region.width > 0 and btn.region.height > 0
            assert btn.region.right <= panel_body.content_region.right

        if size == "160x50":
            assert not panel.has_class("-narrow")
            assert status_actions.region.x >= status_body.region.right
        else:
            assert panel.has_class("-narrow")
            assert status_actions.region.y >= status_body.region.bottom

    return check


@pytest.mark.parametrize("scenario", ["up_to_date", "update_ready", "server_minimum", "pinned"])
@pytest.mark.parametrize("size", ["160x50", "100x30"])
def test_settings_updates_panel(
    screen_snapshot: Any,
    empty_home: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
    size: str,
) -> None:
    runtime = _seed_state(empty_home, monkeypatch, scenario)

    # Keep the snapshot deterministic: the background update poller would
    # otherwise race with opening Settings and mutate the sidebar/toast state.
    async def _no_bg_update_check(_self: Any) -> None:
        return None

    monkeypatch.setattr(_harness.SnapshotApp, "_check_for_update", _no_bg_update_check)

    async def before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        pilot.app.runtime_layout = runtime
        pilot.app.workspace_state.navigation_visible = False
        pilot.app.open_settings_screen("updates")
        screen = await _harness.wait_for_screen(pilot, "SettingsScreen")
        await _harness.wait_until(
            pilot,
            lambda: isinstance(screen._current_panel(), UpdatesPanel)
            and screen._current_panel()._loaded
            and not screen._current_panel()._settling,
            f"the updates panel ({scenario}) to settle",
        )
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(
        _harness.SnapshotApp(),
        _harness.SIZES[size],
        before,
        check=_geometry_check(size),
    )
