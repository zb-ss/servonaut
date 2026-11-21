"""Settings → Updates panel snapshots at 160x50 and 100x30."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Button, RadioButton, RadioSet, Static

from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)
from servonaut.screens.settings.panels import updates as updates_mod
from servonaut.screens.settings.panels.updates import UpdatesPanel
from servonaut.services.apt_runtime import AptBuildIdentity, AptChange, AptUpgradeState
from servonaut.services.client_identity import reset_client_identity_for_tests
from servonaut.updates import status as updates_status
from servonaut.updates.apt import (
    APT_UPGRADE_COMMAND,
    AptInstallStatus,
    reset_apt_status_cache_for_tests,
    seed_apt_status_cache_for_tests,
)

from . import _harness

_SNAPSHOT_VERSION = "2.34.0"
_APT_RUNTIME_STATES = {
    "apt_restart": AptUpgradeState(AptChange.RESTART_REQUIRED, AptBuildIdentity("2.35.0rc10", "fixture", 2, (1, 2))),
    "apt_deferred": AptUpgradeState(AptChange.DEFERRED),
    "apt_removed": AptUpgradeState(AptChange.REMOVED),
}


@pytest.fixture(autouse=True)
def _reset_apt_snapshot_state() -> Any:
    reset_client_identity_for_tests()
    reset_apt_status_cache_for_tests()
    yield
    reset_client_identity_for_tests()
    reset_apt_status_cache_for_tests()


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


def _apt_desktop_runtime(home: Path) -> RuntimeLayout:
    root = home / "opt" / "servonaut"
    return RuntimeLayout(
        kind=DistributionKind.PACKAGED_DESKTOP,
        product_version=_SNAPSHOT_VERSION,
        build_revision=None,
        resource_root=root,
        executable_root=root,
        data_root=home / ".servonaut",
        executable=root / "servonaut-desktop",
        python_executable=None,
        path_console=None,
        console_helper=None,
        desktop_child=None,
        package_management=PackageManagementCapability(
            PackageManagementKind.UNSUPPORTED, (), False,
        ),
        is_frozen=True,
    )


def _seed_state(home: Path, monkeypatch: pytest.MonkeyPatch, scenario: str) -> RuntimeLayout:
    if scenario.startswith("apt_"):
        runtime = _apt_desktop_runtime(home)
        apt_status = AptInstallStatus(
            managed=True,
            suite="stable",
            suites=("stable",),
            dpkg_owned=True,
            architecture="amd64",
            checked=True,
        )
        monkeypatch.setattr(updates_status, "locate_install", lambda _prefix=None: None)
        monkeypatch.setattr(updates_status, "get_version", lambda: _SNAPSHOT_VERSION)
        monkeypatch.setattr(updates_mod.sys, "platform", "linux")
        monkeypatch.setattr(updates_mod, "refresh_apt_status", lambda _rt, **_kw: apt_status)
        seed_apt_status_cache_for_tests(apt_status, runtime=runtime, platform_name="linux")
        return runtime

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
                {"101": {"role": "mcp", "version": "2.33.0"}},
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


def _geometry_check(size: str, scenario: str) -> Any:
    def check(pilot: Any) -> None:
        panel = pilot.app.screen._current_panel()
        assert isinstance(panel, UpdatesPanel)
        panel_body = panel.query_one(".panel-body", VerticalScroll)
        status_body = panel.query_one("#updates_status_body", Vertical)
        status_actions = panel.query_one("#updates_status_actions", Vertical)
        save_btn = panel.query_one("#save_updates", Button)

        assert pilot.app.screen.region.contains_region(save_btn.region)
        assert pilot.app.get_widget_at(*save_btn.region.center)[0] is save_btn

        if scenario in _APT_RUNTIME_STATES:
            expected = {
                "apt_restart": "Servonaut was updated by apt. Restart to use version 2.35.0rc10.",
                "apt_deferred": "Waiting for the Servonaut package to finish configuring.",
                "apt_removed": "The Servonaut package was removed.",
            }
            primary = panel.query_one("#updates_status_primary", Static)
            assert str(primary.render()) == expected[scenario]
            assert panel_body.content_region.contains_region(primary.region)
            restart = panel.query_one("#updates_btn_restart", Button)
            assert restart.display is (scenario == "apt_restart")
            if restart.display:
                assert panel_body.content_region.contains_region(restart.region)
            return

        if scenario == "apt_managed":
            assert not status_actions.display
            for selector in (
                "#updates_btn_check",
                "#updates_btn_postpone",
                "#updates_btn_try",
                "#updates_btn_update",
            ):
                assert panel.query_one(selector, Button).display is False
            assert panel.query_one("#updates_channel_title", Static).display is False
            assert panel.query_one("#updates_channel_radio", RadioSet).display is False
            assert save_btn.disabled is True
            assert "Updates are managed by apt." == str(
                panel.query_one("#updates_status_primary", Static).render()
            )
            assert "To update now, run:" == str(
                panel.query_one("#updates_status_secondary", Static).render()
            )
            cmd = panel.query_one("#updates_status_command", Static)
            assert cmd.display is True
            assert str(cmd.render()) == APT_UPGRADE_COMMAND
            assert cmd.region.height == 1
            summary = panel.query_one("#updates_channel_apt_summary", Static)
            note = panel.query_one("#updates_channel_note", Static)
            assert summary.display is True
            assert str(summary.render()) == "Release channel: stable (set in your APT source)"
            assert note.display is True
            assert str(note.render()) == "Servonaut does not modify APT configuration."
            assert panel_body.content_region.contains_region(summary.region)
            assert panel_body.content_region.contains_region(note.region)
            if size == "160x50":
                assert not panel.has_class("-narrow")
            else:
                assert panel.has_class("-narrow")
            return

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


@pytest.mark.parametrize(
    "scenario", ["up_to_date", "update_ready", "server_minimum", "pinned", "apt_managed", *_APT_RUNTIME_STATES],
)
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
        if scenario in _APT_RUNTIME_STATES:
            pilot.app.apt_upgrade_state = _APT_RUNTIME_STATES[scenario]
        pilot.app.workspace_state.navigation_visible = False
        pilot.app.open_settings_screen("updates")
        screen = await _harness.wait_for_screen(pilot, "SettingsScreen")
        await _harness.wait_until(
            pilot,
            lambda: isinstance(screen._current_panel(), UpdatesPanel)
            and screen._current_panel()._loaded
            and not screen._current_panel()._settling
            and not screen._current_panel()._checking_apt,
            f"the updates panel ({scenario}) to settle",
        )
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(
        _harness.SnapshotApp(),
        _harness.SIZES[size],
        before,
        check=_geometry_check(size, scenario),
    )
