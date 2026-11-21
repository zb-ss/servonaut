"""Unit and headless pilot tests for Settings → Updates (UpdatesPanel)."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import threading
import time
from types import SimpleNamespace
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual import events
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Button, RadioButton, RadioSet, Static, Switch

from e2e.harness import markup_guard
from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)
from servonaut.screens.settings.panels.updates import (
    UpdatesPanel,
    describe_install_kind,
    format_checked_ago,
    format_old_sessions,
    format_postponed_until,
    format_server_minimum_hint,
    release_notes_url,
)
from servonaut.screens.settings.shell import SettingsScreen
from servonaut.services.client_identity import (
    configure_client_identity,
    get_client_identity,
    reset_client_identity_for_tests,
)
from servonaut.services.update_service import UpdateCheckResult
from servonaut.services.version_policy import DEFAULT_UPDATE_URL, VersionPolicy
from servonaut.updates import layout as _updates_layout  # noqa: F401 — bind locate_install before monkeypatches
from servonaut.updates import status as updates_status
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.widgets.link_button import LinkButton
from tests._async_bounds import wait_until


# ---------------------------------------------------------------------------
# Fixtures & host
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_identity() -> Any:
    reset_client_identity_for_tests()
    yield
    reset_client_identity_for_tests()


@pytest.fixture
def pipx_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create a real isolated pipx anchor and point servonaut.updates.status at it."""
    anchor = tmp_path / "pipx" / "venvs" / "servonaut"
    anchor.mkdir(parents=True)
    (anchor / updates_status.PIPX_METADATA).write_text("{}", encoding="utf-8")
    monkeypatch.setattr(updates_status.sys, "prefix", str(anchor))
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    monkeypatch.setattr(updates_status, "get_version", lambda: "2.34.0")
    return anchor


@pytest.fixture
def generation_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Create an isolated generation venv under a pipx anchor's update storage."""
    anchor = tmp_path / "pipx" / "venvs" / "servonaut"
    anchor.mkdir(parents=True)
    (anchor / updates_status.PIPX_METADATA).write_text("{}", encoding="utf-8")
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    generation_id = "a" * 32
    gen_root = updates_status.storage_for(anchor) / "generations" / generation_id
    gen_root.mkdir(parents=True)
    (gen_root / updates_status.MARKER_NAME).write_text(
        json.dumps({"anchor": str(anchor), "generation": generation_id}),
        encoding="utf-8",
    )
    monkeypatch.setattr(updates_status.sys, "prefix", str(gen_root))
    monkeypatch.setattr(updates_status, "get_version", lambda: "2.34.0")
    return anchor, gen_root


def _seed_pipx_files(
    anchor: Path,
    *,
    state: Optional[dict[str, Any]] = None,
    preferences: Optional[dict[str, Any]] = None,
    leases: Optional[dict[str, Any]] = None,
) -> Path:
    directory = updates_status.storage_for(anchor)
    with updates_status.update_gate(directory, 2.0):
        if state is not None:
            updates_status.write_json(directory / "state.json", state)
        if preferences is not None:
            updates_status.write_json(directory / "preferences.json", preferences)
        if leases is not None:
            updates_status.write_json(directory / "leases.json", leases)
    return directory


def _fake_runtime(kind: DistributionKind, *, version: str = "2.34.0") -> RuntimeLayout:
    if kind is DistributionKind.PIPX:
        cap = PackageManagementCapability(PackageManagementKind.PIPX, ("pipx",), True)
    elif kind is DistributionKind.PIP:
        cap = PackageManagementCapability(PackageManagementKind.PIP, ("python", "-m", "pip"), True)
    elif kind is DistributionKind.SOURCE:
        cap = PackageManagementCapability(PackageManagementKind.PIP, ("python", "-m", "pip"), False)
    else:
        cap = PackageManagementCapability(PackageManagementKind.UNSUPPORTED, (), False)
    return RuntimeLayout(
        kind=kind,
        product_version=version,
        build_revision=None,
        resource_root=Path("/tmp"),
        executable_root=Path("/tmp"),
        data_root=Path("/tmp"),
        executable=Path("/tmp/servonaut"),
        python_executable=None if kind in {DistributionKind.FROZEN_CLI, DistributionKind.PACKAGED_DESKTOP} else Path("/tmp/python"),
        path_console=None,
        console_helper=None,
        desktop_child=None,
        package_management=cap,
        is_frozen=kind in {DistributionKind.FROZEN_CLI, DistributionKind.PACKAGED_DESKTOP},
    )


class _UpdatesHost(ServonautApp):
    """Minimal ServonautApp host opening Settings directly on the Updates panel."""

    def __init__(
        self,
        tmp_path: Path,
        *,
        runtime: Optional[RuntimeLayout] = None,
        update_service: Optional[Any] = None,
        policy_client: Optional[Any] = None,
        navigation_visible: bool = False,
        demo_mode: bool = False,
    ) -> None:
        super().__init__()
        manager = ConfigManager(config_path=tmp_path / "config.json")
        manager.save(AppConfig())
        manager.load()
        self.config_manager = manager
        self.workspace_state.navigation_visible = navigation_visible
        self.demo_mode = demo_mode
        self.runtime_layout = runtime or _fake_runtime(DistributionKind.PIPX, version="2.34.0")
        self.update_service = update_service or SimpleNamespace(
            runtime=self.runtime_layout,
            current_version=self.runtime_layout.product_version,
            last_check_result=UpdateCheckResult.UP_TO_DATE,
            update_status=None,
            target_artifact=None,
            check_for_update=MagicMock(return_value=None),
            run_upgrade=AsyncMock(return_value=(True, "Updated cleanly.")),
        )
        self.version_policy_client = policy_client or SimpleNamespace(
            cached=MagicMock(return_value=None),
            fetch=AsyncMock(return_value=None),
        )
        self.auth_service = SimpleNamespace(
            is_authenticated=False,
            has_feature=MagicMock(return_value=False),
            cached_version_policy=MagicMock(return_value=None),
        )
        self.opened_urls: list[str] = []
        self.notifications: list[tuple[str, dict[str, Any]]] = []

    def open_url(self, url: str, *, new_tab: bool = True) -> None:
        self.opened_urls.append(url)

    def notify(self, message: str, *args: Any, **kwargs: Any) -> None:
        self.notifications.append((str(message), dict(kwargs)))
        super().notify(message, *args, **kwargs)

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        self.push_screen(SettingsScreen("updates"))

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()


async def _wait_updates_panel(app: _UpdatesHost, pilot: Any) -> UpdatesPanel:
    await pilot.pause()
    await wait_until(lambda: isinstance(app.screen, SettingsScreen))
    await wait_until(lambda: isinstance(app.screen._current_panel(), UpdatesPanel))
    panel = app.screen._current_panel()
    assert isinstance(panel, UpdatesPanel)
    await wait_until(lambda: panel._loaded and not panel._settling and not panel._checking_apt)
    await pilot.pause()
    return panel


# ---------------------------------------------------------------------------
# Pure helper tests
# ---------------------------------------------------------------------------


def test_describe_install_kind_variants() -> None:
    assert describe_install_kind("pipx") == "installed with pipx"
    assert describe_install_kind("pip") == "installed with pip"
    assert describe_install_kind("source") == "source checkout"
    assert describe_install_kind("frozen-cli") == "standalone build"
    assert describe_install_kind("apt") == "installed from the Servonaut APT repository"
    assert describe_install_kind("packaged-desktop", platform_name="darwin") == "macOS app"
    assert describe_install_kind("packaged-desktop", platform_name="win32") == "desktop app"
    assert describe_install_kind(
        "packaged-desktop", platform_name="linux", apt_managed=False,
    ) == "Linux desktop app"
    assert describe_install_kind(
        "packaged-desktop", platform_name="linux", apt_managed=True,
    ) == "installed from the Servonaut APT repository"


def test_format_checked_ago_ranges() -> None:
    assert format_checked_ago(1000.0, now=1025.0) == "just now"
    assert format_checked_ago(1000.0, now=1180.0) == "3 min ago"
    assert format_checked_ago(1000.0, now=4600.0) == "1 hr ago"
    assert format_checked_ago(1000.0, now=8200.0) == "2 hrs ago"
    assert format_checked_ago(1000.0, now=90000.0) == "1 day ago"
    assert format_checked_ago(1000.0, now=261000.0) == "3 days ago"


def test_format_old_sessions_variants_and_sanitization() -> None:
    assert format_old_sessions((), "2.34.0") == ""
    assert (
        format_old_sessions(("mcp",), "2.34.0")
        == "1 MCP server keeps 2.34.0 until your agent restarts it"
    )
    assert (
        format_old_sessions(("mcp", "mcp"), "2.34.0")
        == "2 MCP servers keep 2.34.0 until your agents restart them"
    )
    assert (
        format_old_sessions(("cli", "mcp"), "2.34.0")
        == "2 sessions (1 CLI session, 1 MCP server) keep 2.34.0 until they restart"
    )
    sanitized = format_old_sessions(("mcp\x1b[31m",), "2.34.0\u202e")
    assert "\x1b" not in sanitized
    assert "\u202e" not in sanitized


def test_format_server_minimum_hint_prefers_policy_hints_and_uses_only_upgrade() -> None:
    assert format_server_minimum_hint("pipx") == "pipx upgrade servonaut"
    assert format_server_minimum_hint("pip") == "pip install --upgrade servonaut"
    apt_hint = format_server_minimum_hint("apt", platform_name="linux")
    assert apt_hint == "sudo apt update && sudo apt install --only-upgrade servonaut"
    assert "apt upgrade servonaut" not in apt_hint
    assert (
        format_server_minimum_hint("packaged-desktop", platform_name="linux", apt_managed=False)
        == DEFAULT_UPDATE_URL
    )
    assert (
        format_server_minimum_hint("packaged-desktop", platform_name="darwin")
        == DEFAULT_UPDATE_URL
    )
    assert "source checkout" in format_server_minimum_hint("source")

    policy = VersionPolicy(
        mode="enforce",
        minimum_version="2.35.0",
        update_hints={"pipx": "pipx upgrade servonaut --force\x1b[31m"},
    )
    hint = format_server_minimum_hint("pipx", policy=policy)
    assert hint == "pipx upgrade servonaut --force[31m"
    assert "\x1b" not in hint


def test_release_notes_url_validation() -> None:
    assert release_notes_url("2.35.0") == "https://github.com/zb-ss/servonaut/releases/tag/v2.35.0"
    assert release_notes_url("2.35.0rc1") == "https://github.com/zb-ss/servonaut/releases/tag/v2.35.0rc1"
    assert release_notes_url("not-a-version") is None


# ---------------------------------------------------------------------------
# State 1 — up to date (pipx) + no auto-update on/off toggle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_state_1_up_to_date_pipx_and_no_auto_update_switch(
    tmp_path: Path, pipx_env: Path,
) -> None:
    app = _UpdatesHost(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert "2.34.0  ·  installed with pipx" == str(
            panel.query_one("#updates_installed_value", Static).render()
        )
        assert "Up to date" in str(panel.query_one("#updates_status_primary", Static).render())
        assert panel.query_one("#updates_btn_check", Button).display is True
        assert panel.query_one("#updates_btn_postpone", Button).display is False
        assert panel.query_one("#updates_btn_try", Button).display is False
        assert panel.query_one("#updates_btn_update", Button).display is False
        # Approved design: no on/off switch for stable auto-update.
        assert list(panel.query(Switch)) == []
        assert panel.query_one("#updates_auto_note", Static).display is True
        assert panel.query_one("#updates_channel_radio", RadioSet).disabled is False
        assert not panel.has_unsaved_changes()


# ---------------------------------------------------------------------------
# State 2 — update ready + old sessions + one-shot postpone + mark_presented
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_state_2_ready_old_sessions_release_notes_and_one_shot_postpone(
    tmp_path: Path, pipx_env: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = _seed_pipx_files(
        pipx_env,
        state={"status": "ready", "offered": "2.35.0"},
        leases={
            "101": {"role": "mcp", "version": "2.33.0"},
            "102": {"role": "cli", "version": "2.35.0"},
        },
    )
    monkeypatch.setattr(updates_status.time, "time", lambda: 1_763_600_000.0)
    real_mark = updates_status.mark_update_presented
    presented: list[str] = []

    def spy_mark(version: str) -> bool:
        presented.append(version)
        return real_mark(version)

    monkeypatch.setattr(updates_status, "mark_update_presented", spy_mark)

    app = _UpdatesHost(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        primary = str(panel.query_one("#updates_status_primary", Static).render())
        secondary = str(panel.query_one("#updates_status_secondary", Static).render())
        assert "2.35.0 is ready" in primary
        assert "starts the next time you open Servonaut" in primary
        assert "1 MCP server keeps 2.33.0 until your agent restarts it" in secondary

        notes_link = panel.query_one("#updates_link_release_notes", LinkButton)
        assert notes_link.display is True
        assert "What's new in 2.35.0" in str(notes_link.label)
        assert await pilot.click("#updates_link_release_notes")
        await pilot.pause()
        assert app.opened_urls == ["https://github.com/zb-ss/servonaut/releases/tag/v2.35.0"]

        # Real 1-arg mark_update_presented called once and persisted presented_at.
        await wait_until(
            lambda: len(presented) == 1
            and "presented_at" in json.loads((directory / "state.json").read_text(encoding="utf-8"))
        )
        assert presented == ["2.35.0"]

        postpone_btn = panel.query_one("#updates_btn_postpone", Button)
        assert postpone_btn.display is True
        assert await pilot.click("#updates_btn_postpone")
        await wait_until(lambda: not panel._busy and not postpone_btn.display)

        # Persisted in real state.json, button gone, postponed copy shown.
        saved_state = json.loads((directory / "state.json").read_text(encoding="utf-8"))
        assert "2.35.0" in saved_state["postponed"]
        assert saved_state["presented_at"] == 1_763_600_000.0
        expected_when = format_postponed_until(saved_state["postponed"]["2.35.0"])
        updated_secondary = str(panel.query_one("#updates_status_secondary", Static).render())
        assert f"Postponed until {expected_when}, installs at the next start after that" in updated_secondary
        assert panel.query_one("#updates_btn_postpone", Button).display is False
        # Still called only once after re-render.
        assert len(presented) == 1


@pytest.mark.asyncio
async def test_state_2_building_does_not_mark_presented_and_handles_missing_helper(
    tmp_path: Path, pipx_env: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(updates_status, "mark_update_presented")
    _seed_pipx_files(pipx_env, state={"status": "building", "offered": "2.35.0"})
    app = _UpdatesHost(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert "Preparing 2.35.0 in the background" in str(
            panel.query_one("#updates_status_primary", Static).render()
        )
        assert panel.query_one("#updates_btn_postpone", Button).display is True


# ---------------------------------------------------------------------------
# State 3 — update failed / rolled back + escaped details + Try now
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_state_3_rolled_back_details_escaped_and_try_now(
    tmp_path: Path, pipx_env: Path,
) -> None:
    hostile_failure = "Health check failed: [bold red]bad-tag[/bold red]\x1b[31m"
    _seed_pipx_files(
        pipx_env,
        state={
            "status": "rolled_back",
            "offered": "2.35.0",
            "failure": {"message": hostile_failure},
        },
    )
    run_upgrade = AsyncMock(return_value=(True, "Updated v2.34.0 → v2.35.0."))
    service = SimpleNamespace(
        runtime=_fake_runtime(DistributionKind.PIPX, version="2.34.0"),
        current_version="2.34.0",
        last_check_result=None,
        update_status=None,
        target_artifact=None,
        check_for_update=MagicMock(return_value=None),
        run_upgrade=run_upgrade,
    )
    app = _UpdatesHost(tmp_path, update_service=service)
    with markup_guard.watch() as guard:
        async with app.run_test(size=(160, 50)) as pilot:
            panel = await _wait_updates_panel(app, pilot)
            primary = str(panel.query_one("#updates_status_primary", Static).render())
            secondary = str(panel.query_one("#updates_status_secondary", Static).render())
            assert "The update to 2.35.0 did not start correctly, so Servonaut kept 2.34.0." == primary
            assert "It will try again at a later start." == secondary
            assert panel.query_one("#updates_btn_try", Button).display is True

            details_link = panel.query_one("#updates_link_details", LinkButton)
            details_box = panel.query_one("#updates_failure_details", Static)
            assert details_link.display is True
            assert details_box.display is False

            assert await pilot.click("#updates_link_details")
            await pilot.pause()
            assert details_box.display is True
            rendered_details = str(details_box.render())
            assert "[bold red]bad-tag[/bold red]" in rendered_details
            assert "\x1b" not in rendered_details
            assert "Hide details" in str(details_link.label)

            assert await pilot.click("#updates_btn_try")
            await wait_until(lambda: run_upgrade.await_count == 1 and not panel._busy)
            assert any("Updated v2.34.0" in msg for msg, _ in app.notifications)
    assert guard.findings == []


# ---------------------------------------------------------------------------
# State 4 — server minimum required
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_state_4_server_minimum_shows_required_copy_and_update_now(
    tmp_path: Path, pipx_env: Path,
) -> None:
    _seed_pipx_files(
        pipx_env,
        state={
            "status": "up_to_date",
            "policy": {"mode": "enforce", "minimum_version": "2.35.0"},
        },
    )
    run_upgrade = AsyncMock(return_value=(True, "Updated v2.34.0 → v2.35.0."))
    service = SimpleNamespace(
        runtime=_fake_runtime(DistributionKind.PIPX, version="2.34.0"),
        current_version="2.34.0",
        last_check_result=None,
        update_status=None,
        target_artifact=None,
        check_for_update=MagicMock(return_value=None),
        run_upgrade=run_upgrade,
    )
    app = _UpdatesHost(tmp_path, update_service=service)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        primary = str(panel.query_one("#updates_status_primary", Static).render())
        secondary = str(panel.query_one("#updates_status_secondary", Static).render())
        assert "servonaut.dev needs 2.35.0 or later for team, vault and AI features." == primary
        assert "Local features keep working.  Update: pipx upgrade servonaut" == secondary
        assert panel.query_one("#updates_btn_update", Button).display is True
        assert await pilot.click("#updates_btn_update")
        await wait_until(lambda: run_upgrade.await_count == 1 and not panel._busy)


# ---------------------------------------------------------------------------
# State 5 — managed elsewhere variants
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind, platform_name, apt_managed, expected_installed, expected_primary, expected_secondary, expected_command",
    [
        (
            DistributionKind.PACKAGED_DESKTOP,
            "linux",
            True,
            "installed from the Servonaut APT repository",
            "Updates are managed by apt.",
            "To update now, run:",
            "sudo apt update && sudo apt install --only-upgrade servonaut",
        ),
        (
            DistributionKind.SOURCE,
            "linux",
            False,
            "source checkout",
            "source checkout",
            "Update your checkout",
            "",
        ),
        (
            DistributionKind.PIP,
            "linux",
            False,
            "installed with pip",
            "Updates are installed with pip.",
            "pip install --upgrade servonaut",
            "",
        ),
    ],
)
async def test_state_5_managed_elsewhere_variants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: DistributionKind,
    platform_name: str,
    apt_managed: bool,
    expected_installed: str,
    expected_primary: str,
    expected_secondary: str,
    expected_command: str,
) -> None:
    import servonaut.screens.settings.panels.updates as updates_mod
    from servonaut.updates.apt import AptInstallStatus

    monkeypatch.setattr(updates_status, "locate_install", lambda _prefix=None: None)
    monkeypatch.setattr(updates_mod.sys, "platform", platform_name)
    monkeypatch.setattr(
        updates_mod,
        "refresh_apt_status",
        lambda _rt, **_kw: AptInstallStatus(
            managed=apt_managed,
            suite="stable" if apt_managed else None,
            suites=("stable",) if apt_managed else (),
            dpkg_owned=apt_managed,
            architecture="amd64" if apt_managed else None,
            checked=True,
        ),
    )
    app = _UpdatesHost(tmp_path, runtime=_fake_runtime(kind, version="2.34.0"))
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        installed_text = str(panel.query_one("#updates_installed_value", Static).render())
        primary_text = str(panel.query_one("#updates_status_primary", Static).render())
        secondary_text = str(panel.query_one("#updates_status_secondary", Static).render())
        command_widget = panel.query_one("#updates_status_command", Static)
        assert expected_installed in installed_text
        assert expected_primary in primary_text
        assert expected_secondary in secondary_text
        assert "apt upgrade servonaut" not in secondary_text
        if expected_command:
            assert command_widget.display is True
            assert str(command_widget.render()) == expected_command
            assert "`" not in str(command_widget.render())
            assert panel.query_one("#updates_channel_radio", RadioSet).display is False
            assert panel.query_one("#updates_channel_apt_summary", Static).display is True
        else:
            assert command_widget.display is False
            assert panel.query_one("#updates_channel_radio", RadioSet).display is True
            assert panel.query_one("#updates_channel_radio", RadioSet).disabled is True
        assert panel.query_one("#save_updates", Button).disabled is True


@pytest.mark.asyncio
@pytest.mark.parametrize("suite", ["stable", "candidate"])
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_apt_managed_desktop_shows_channel_summary_copyable_command_and_fits_100x30(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suite: str, size: tuple[int, int],
) -> None:
    import servonaut.screens.settings.panels.updates as updates_mod
    from servonaut.updates.apt import APT_UPGRADE_COMMAND, AptInstallStatus

    monkeypatch.setattr(updates_status, "locate_install", lambda _prefix=None: None)
    monkeypatch.setattr(updates_mod.sys, "platform", "linux")
    monkeypatch.setattr(
        updates_mod,
        "refresh_apt_status",
        lambda _rt, **_kw: AptInstallStatus(
            managed=True,
            suite=suite,
            suites=(suite,),
            dpkg_owned=True,
            architecture="amd64",
            checked=True,
        ),
    )
    runtime = _fake_runtime(DistributionKind.PACKAGED_DESKTOP, version="2.34.0")
    app = _UpdatesHost(tmp_path, runtime=runtime)
    async with app.run_test(size=size) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert "2.34.0  ·  installed from the Servonaut APT repository" == str(
            panel.query_one("#updates_installed_value", Static).render()
        )
        assert "Updates are managed by apt." == str(
            panel.query_one("#updates_status_primary", Static).render()
        )
        secondary = str(panel.query_one("#updates_status_secondary", Static).render())
        assert secondary == "To update now, run:"
        assert "APT suite" not in secondary

        command_widget = panel.query_one("#updates_status_command", Static)
        assert command_widget.display is True
        assert str(command_widget.render()) == APT_UPGRADE_COMMAND
        assert "`" not in str(command_widget.render())
        # Copyable command fits on one single line without mid-command wrapping even at 100x30.
        assert command_widget.region.height == 1

        for selector in (
            "#updates_btn_check",
            "#updates_btn_postpone",
            "#updates_btn_try",
            "#updates_btn_update",
        ):
            assert panel.query_one(selector, Button).display is False
        assert panel.query_one("#updates_status_actions", Vertical).display is False
        assert panel.query_one("#updates_link_download", LinkButton).display is False
        assert panel.query_one("#updates_link_release_notes", LinkButton).display is False

        # Radio set replaced by one-line channel summary; note stays visible without scrolling at 100x30.
        assert panel.query_one("#updates_channel_title", Static).display is False
        assert panel.query_one("#updates_channel_radio", RadioSet).display is False
        summary = panel.query_one("#updates_channel_apt_summary", Static)
        assert summary.display is True
        assert str(summary.render()) == f"Release channel: {suite} (set in your APT source)"
        note = panel.query_one("#updates_channel_note", Static)
        assert note.display is True
        assert str(note.render()) == "Servonaut does not modify APT configuration."
        assert panel.query_one("#save_updates", Button).disabled is True

        panel_body = panel.query_one(".panel-body", VerticalScroll)
        assert panel_body.content_region.contains_region(summary.region)
        assert panel_body.content_region.contains_region(note.region)


@pytest.mark.asyncio
async def test_apt_probe_runs_off_ui_thread_showing_cached_status_and_busy_indicator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import servonaut.screens.settings.panels.updates as updates_mod
    from servonaut.updates.apt import (
        APT_UPGRADE_COMMAND,
        AptInstallStatus,
        seed_apt_status_cache_for_tests,
    )

    monkeypatch.setattr(updates_status, "locate_install", lambda _prefix=None: None)
    monkeypatch.setattr(updates_mod.sys, "platform", "linux")
    runtime = _fake_runtime(DistributionKind.PACKAGED_DESKTOP, version="2.34.0")
    # Seed a prior cached status (e.g. from startup) so the panel renders it
    # immediately alongside a loading indicator while re-checking off the UI thread.
    seed_apt_status_cache_for_tests(
        AptInstallStatus(
            managed=True,
            suite="stable",
            suites=("stable",),
            dpkg_owned=True,
            architecture="amd64",
            checked=True,
        ),
        runtime=runtime,
        platform_name="linux",
    )

    ui_thread = threading.get_ident()
    probe_threads: list[int] = []
    started = threading.Event()
    release = threading.Event()

    def slow_refresh(_rt: Any, **_kw: Any) -> AptInstallStatus:
        probe_threads.append(threading.get_ident())
        started.set()
        release.wait(timeout=5.0)
        return AptInstallStatus(
            managed=True,
            suite="candidate",
            suites=("candidate",),
            dpkg_owned=True,
            architecture="amd64",
            checked=True,
        )

    monkeypatch.setattr(updates_mod, "refresh_apt_status", slow_refresh)
    app = _UpdatesHost(tmp_path, runtime=runtime)
    try:
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            await wait_until(lambda: isinstance(app.screen, SettingsScreen))
            await wait_until(lambda: isinstance(app.screen._current_panel(), UpdatesPanel))
            panel = app.screen._current_panel()
            assert isinstance(panel, UpdatesPanel)

            # Wait until the worker is blocked in slow_refresh.
            await wait_until(lambda: started.is_set() and panel._checking_apt)
            busy = panel.query_one("#updates_busy", BusyIndicator)
            await wait_until(lambda: busy.is_active)
            # Cached result is already visible while the fresh check is in flight.
            assert "Updates are managed by apt." == str(
                panel.query_one("#updates_status_primary", Static).render()
            )
            assert "Release channel: stable (set in your APT source)" == str(
                panel.query_one("#updates_channel_apt_summary", Static).render()
            )
            assert probe_threads and all(tid != ui_thread for tid in probe_threads)

            release.set()
            await wait_until(lambda: not panel._checking_apt and not busy.is_active)
            assert "Release channel: candidate (set in your APT source)" == str(
                panel.query_one("#updates_channel_apt_summary", Static).render()
            )
            assert str(panel.query_one("#updates_status_command", Static).render()) == APT_UPGRADE_COMMAND
    finally:
        release.set()


@pytest.mark.asyncio
async def test_apt_panel_wires_real_refresh_apt_status_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise UpdatesPanel against the real refresh_apt_status pipeline (temp files + fake dpkg)."""
    import servonaut.screens.settings.panels.updates as updates_mod
    from servonaut.updates import apt as apt_mod
    from servonaut.updates.apt import APT_UPGRADE_COMMAND, AptDetectionConfig, DpkgCommandResult

    root = tmp_path / "opt" / "servonaut"
    root.mkdir(parents=True)
    exe = root / "servonaut-desktop"
    exe.write_bytes(b"#!/bin/sh\n")
    marker = root / "servonaut-runtime.json"
    marker.write_text('{"distribution_kind": "packaged-desktop"}\n', encoding="utf-8")
    keyring = tmp_path / "keyrings" / "servonaut.gpg"
    keyring.parent.mkdir(parents=True)
    keyring.write_bytes(b"key-bytes")
    sources_d = tmp_path / "etc" / "apt" / "sources.list.d"
    sources_d.mkdir(parents=True)
    (sources_d / "servonaut.sources").write_text(
        "Types: deb\n"
        "URIs: https://releases.servonaut.dev/apt/\n"
        "Suites: stable\n"
        "Components: main\n"
        "Architectures: amd64\n"
        f"Signed-By: {keyring}\n",
        encoding="utf-8",
    )
    dpkg_status = tmp_path / "var" / "lib" / "dpkg" / "status"
    dpkg_status.parent.mkdir(parents=True)
    dpkg_status.write_text("Package: servonaut\n", encoding="utf-8")

    def fake_runner(argv: Any, _timeout: float) -> DpkgCommandResult:
        if "-W" in argv:
            return DpkgCommandResult(returncode=0, stdout="ii\tamd64\t2.34.0-1\n")
        return DpkgCommandResult(
            returncode=0,
            stdout=f"servonaut: {exe.resolve()}\nservonaut: {marker.resolve()}\n",
        )

    cfg = AptDetectionConfig(
        packaged_prefixes=(tmp_path,),
        sources_list_path=tmp_path / "etc" / "apt" / "sources.list",
        sources_list_d_path=sources_d,
        dpkg_status_path=dpkg_status,
        require_root_owned=False,
        dpkg_runner=fake_runner,
    )
    real_refresh = apt_mod.refresh_apt_status
    monkeypatch.setattr(updates_status, "locate_install", lambda _prefix=None: None)
    monkeypatch.setattr(updates_mod.sys, "platform", "linux")
    monkeypatch.setattr(
        updates_mod,
        "refresh_apt_status",
        lambda rt, **_kw: real_refresh(rt, platform_name="linux", config=cfg),
    )

    runtime = RuntimeLayout(
        kind=DistributionKind.PACKAGED_DESKTOP,
        product_version="2.34.0",
        build_revision=None,
        resource_root=root,
        executable_root=root,
        data_root=tmp_path / "data",
        executable=exe,
        python_executable=None,
        path_console=None,
        console_helper=None,
        desktop_child=None,
        package_management=PackageManagementCapability(PackageManagementKind.UNSUPPORTED, (), False),
        is_frozen=True,
    )
    app = _UpdatesHost(tmp_path, runtime=runtime)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert str(panel.query_one("#updates_status_primary", Static).render()) == "Updates are managed by apt."
        assert str(panel.query_one("#updates_status_command", Static).render()) == APT_UPGRADE_COMMAND
        assert str(panel.query_one("#updates_channel_apt_summary", Static).render()) == (
            "Release channel: stable (set in your APT source)"
        )
        assert str(panel.query_one("#updates_channel_note", Static).render()) == (
            "Servonaut does not modify APT configuration."
        )


@pytest.mark.asyncio
async def test_apt_transient_refresh_failure_preserves_cached_suite_in_channel_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import servonaut.screens.settings.panels.updates as updates_mod
    from servonaut.updates.apt import (
        APT_UPGRADE_COMMAND,
        AptInstallStatus,
        seed_apt_status_cache_for_tests,
    )

    monkeypatch.setattr(updates_status, "locate_install", lambda _prefix=None: None)
    monkeypatch.setattr(updates_mod.sys, "platform", "linux")
    runtime = _fake_runtime(DistributionKind.PACKAGED_DESKTOP, version="2.34.0")
    cached_good = AptInstallStatus(
        managed=True,
        suite="stable",
        suites=("stable",),
        dpkg_owned=True,
        architecture="amd64",
        checked=True,
    )
    seed_apt_status_cache_for_tests(cached_good, runtime=runtime, platform_name="linux")

    # Simulate a transient failure (unchecked negative) on refresh while the cache
    # still holds the last good APT suite.
    monkeypatch.setattr(
        updates_mod,
        "refresh_apt_status",
        lambda _rt, **_kw: AptInstallStatus(managed=False, checked=False),
    )
    app = _UpdatesHost(tmp_path, runtime=runtime)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert str(panel.query_one("#updates_status_primary", Static).render()) == "Updates are managed by apt."
        assert str(panel.query_one("#updates_status_command", Static).render()) == APT_UPGRADE_COMMAND
        assert str(panel.query_one("#updates_channel_apt_summary", Static).render()) == (
            "Release channel: stable (set in your APT source)"
        )
        # Also verify _effective_apt_suite directly if _apt_status itself is unchecked.
        panel._apt_status = AptInstallStatus(managed=False, checked=False)
        panel._render_status()
        assert str(panel.query_one("#updates_channel_apt_summary", Static).render()) == (
            "Release channel: stable (set in your APT source)"
        )


@pytest.mark.asyncio
async def test_apt_managed_server_minimum_426_shows_apt_command_and_hides_update_and_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import servonaut.screens.settings.panels.updates as updates_mod
    from servonaut.updates.apt import APT_UPGRADE_COMMAND, AptInstallStatus

    monkeypatch.setattr(updates_status, "locate_install", lambda _prefix=None: None)
    monkeypatch.setattr(updates_mod.sys, "platform", "linux")
    monkeypatch.setattr(
        updates_mod,
        "refresh_apt_status",
        lambda _rt, **_kw: AptInstallStatus(
            managed=True,
            suite="stable",
            suites=("stable",),
            dpkg_owned=True,
            architecture="amd64",
            checked=True,
        ),
    )
    runtime = _fake_runtime(DistributionKind.PACKAGED_DESKTOP, version="2.34.0")
    policy = VersionPolicy(mode="enforce", minimum_version="2.35.0")
    policy_client = SimpleNamespace(
        cached=MagicMock(return_value=policy),
        fetch=AsyncMock(return_value=policy),
    )
    app = _UpdatesHost(tmp_path, runtime=runtime, policy_client=policy_client)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        primary = str(panel.query_one("#updates_status_primary", Static).render())
        secondary = str(panel.query_one("#updates_status_secondary", Static).render())
        command = panel.query_one("#updates_status_command", Static)
        assert "servonaut.dev needs 2.35.0 or later for team, vault and AI features." == primary
        assert "Local features keep working. To update now, run:" == secondary
        assert command.display is True
        assert str(command.render()) == APT_UPGRADE_COMMAND
        assert panel.query_one("#updates_btn_update", Button).display is False
        assert panel.query_one("#updates_btn_check", Button).display is False
        assert panel.query_one("#updates_link_download", LinkButton).display is False
        assert panel.query_one("#updates_channel_radio", RadioSet).display is False
        assert panel.query_one("#updates_channel_apt_summary", Static).display is True
        assert panel.query_one("#save_updates", Button).disabled is True


@pytest.mark.asyncio
async def test_standalone_linux_deb_without_apt_source_falls_back_to_download_guidance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import servonaut.screens.settings.panels.updates as updates_mod
    from servonaut.updates.apt import AptInstallStatus

    monkeypatch.setattr(updates_status, "locate_install", lambda _prefix=None: None)
    monkeypatch.setattr(updates_mod.sys, "platform", "linux")
    monkeypatch.setattr(
        updates_mod,
        "refresh_apt_status",
        lambda _rt, **_kw: AptInstallStatus(
            managed=False,
            dpkg_owned=True,
            architecture="amd64",
            checked=True,
        ),
    )
    runtime = _fake_runtime(DistributionKind.PACKAGED_DESKTOP, version="2.34.0")
    app = _UpdatesHost(tmp_path, runtime=runtime)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert "2.34.0  ·  Linux desktop app" == str(
            panel.query_one("#updates_installed_value", Static).render()
        )
        assert "Up to date" in str(panel.query_one("#updates_status_primary", Static).render())
        assert "servonaut.dev/download" in str(
            panel.query_one("#updates_status_secondary", Static).render()
        )
        assert panel.query_one("#updates_btn_check", Button).display is True


@pytest.mark.asyncio
async def test_state_5_macos_desktop_shows_download_and_install_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import servonaut.screens.settings.panels.updates as updates_mod

    monkeypatch.setattr(updates_status, "locate_install", lambda _prefix=None: None)
    monkeypatch.setattr(updates_mod.sys, "platform", "darwin")
    runtime = _fake_runtime(DistributionKind.PACKAGED_DESKTOP, version="2.34.0")
    service = SimpleNamespace(
        runtime=runtime,
        current_version="2.34.0",
        last_check_result=UpdateCheckResult.UPDATE_AVAILABLE,
        update_status="Update available: v2.35.0",
        target_artifact=None,
        check_for_update=MagicMock(return_value="2.35.0"),
        run_upgrade=AsyncMock(return_value=(True, "Downloaded.")),
    )
    app = _UpdatesHost(tmp_path, runtime=runtime, update_service=service)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert "macOS app" in str(panel.query_one("#updates_installed_value", Static).render())
        assert panel.query_one("#updates_btn_check", Button).display is True

        assert await pilot.click("#updates_btn_check")
        await wait_until(lambda: not panel._busy and panel._discovered_version == "2.35.0")

        assert "2.35.0 is available" in str(panel.query_one("#updates_status_primary", Static).render())
        download_link = panel.query_one("#updates_link_download", LinkButton)
        assert download_link.display is True
        assert await pilot.click("#updates_link_download")
        await pilot.pause()
        assert app.opened_urls == [DEFAULT_UPDATE_URL]


# ---------------------------------------------------------------------------
# Channel radio dirty / discard / save + no-downgrade note
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_channel_radio_dirty_discard_and_save_persists_to_preferences(
    tmp_path: Path, pipx_env: Path,
) -> None:
    directory = _seed_pipx_files(
        pipx_env,
        state={"status": "up_to_date", "checked_at": 12345},
        preferences={"channel": "stable", "health_timeout": 9},
    )
    app = _UpdatesHost(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert not panel.has_unsaved_changes()

        # Select Release candidates -> dirty.
        assert await pilot.click("#updates_channel_rc")
        await wait_until(lambda: panel.has_unsaved_changes())
        assert "unsaved" in str(panel.query_one("#dirty_updates", Static).render())

        # Discard reverts back to Stable.
        panel.discard()
        await wait_until(lambda: not panel.has_unsaved_changes())
        assert panel.current_values() == {"channel": "stable"}

        # Select Release candidates again and Save through the dock.
        assert await pilot.click("#updates_channel_rc")
        await wait_until(lambda: panel.has_unsaved_changes())
        assert await pilot.click("#save_updates")
        await wait_until(lambda: not panel.has_unsaved_changes())

        prefs = json.loads((directory / "preferences.json").read_text(encoding="utf-8"))
        state = json.loads((directory / "state.json").read_text(encoding="utf-8"))
        assert prefs == {"channel": "rc", "health_timeout": 9}
        assert state["checked_at"] == 0
        assert get_client_identity().channel == "rc"


@pytest.mark.asyncio
async def test_switching_rc_to_stable_on_prerelease_shows_no_downgrade_note(
    tmp_path: Path, pipx_env: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(updates_status, "get_version", lambda: "2.35.0rc1")
    _seed_pipx_files(pipx_env, preferences={"channel": "rc"})
    app = _UpdatesHost(
        tmp_path,
        runtime=_fake_runtime(DistributionKind.PIPX, version="2.35.0rc1"),
    )
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        note = panel.query_one("#updates_channel_note", Static)
        assert note.display is False

        assert await pilot.click("#updates_channel_stable")
        await wait_until(lambda: note.display)
        assert "no downgrade" in str(note.render()).lower()


# ---------------------------------------------------------------------------
# Check now: loading indicator in-flight + completion + policy floor refresh
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_now_shows_busy_indicator_and_updates_on_completion(
    tmp_path: Path, pipx_env: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from servonaut.updates import builder as updates_builder

    started = threading.Event()
    release = threading.Event()
    queued: list[tuple[Path, str]] = []

    def slow_queue_check(store: Any, installed_version: str) -> str:
        queued.append((store.root, installed_version))
        started.set()
        release.wait(timeout=5.0)
        with store.gate():
            store.write("state.json", {"status": "up_to_date", "checked_at": time.time()})
        return "queued"

    monkeypatch.setattr(updates_builder, "queue_update_check", slow_queue_check)
    legacy_check = MagicMock(return_value=None)
    service = SimpleNamespace(
        runtime=_fake_runtime(DistributionKind.PIPX, version="2.34.0"),
        current_version="2.34.0",
        last_check_result=UpdateCheckResult.UP_TO_DATE,
        update_status=None,
        target_artifact=None,
        check_for_update=legacy_check,
        run_upgrade=AsyncMock(return_value=(True, "ok")),
    )
    policy_client = SimpleNamespace(
        cached=MagicMock(return_value=None),
        fetch=AsyncMock(return_value=VersionPolicy(mode="off")),
    )
    app = _UpdatesHost(tmp_path, update_service=service, policy_client=policy_client)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        busy = panel.query_one("#updates_busy", BusyIndicator)
        check_btn = panel.query_one("#updates_btn_check", Button)
        assert not busy.is_active

        assert await pilot.click("#updates_btn_check")
        await wait_until(lambda: started.is_set() and busy.is_active)
        assert busy.has_class("-active")
        assert check_btn.disabled is True

        release.set()
        await wait_until(lambda: not busy.is_active and not panel._busy)
        assert check_btn.disabled is False
        assert "checked just now" in str(panel.query_one("#updates_status_primary", Static).render())
        assert queued == [(pipx_env.resolve(), "2.34.0")]
        legacy_check.assert_not_called()
        policy_client.fetch.assert_awaited_once_with(force_refresh=True)
        assert app.notifications == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outcome, expected_toast, expected_severity",
    [
        ("busy", "An update check is already running.", "information"),
        ("failed", "Couldn't start an update check.", "error"),
    ],
)
async def test_check_now_non_queued_outcomes_show_markup_safe_toast(
    tmp_path: Path,
    pipx_env: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
    expected_toast: str,
    expected_severity: str,
) -> None:
    from servonaut.updates import builder as updates_builder

    monkeypatch.setattr(updates_builder, "queue_update_check", lambda _store, _ver: outcome)
    app = _UpdatesHost(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert await pilot.click("#updates_btn_check")
        await wait_until(lambda: not panel._busy and len(app.notifications) == 1)

        msg, kwargs = app.notifications[-1]
        assert msg == expected_toast
        assert kwargs.get("severity") == expected_severity
        assert kwargs.get("markup") is False
        assert "checked just now" not in str(
            panel.query_one("#updates_status_primary", Static).render()
        )


@pytest.mark.asyncio
async def test_check_now_skipped_outcome_shows_markup_safe_toast(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import servonaut.screens.settings.panels.updates as updates_mod

    monkeypatch.setenv("SERVONAUT_SKIP_AUTO_APPLY", "1")
    monkeypatch.setattr(updates_status, "locate_install", lambda _prefix=None: None)
    monkeypatch.setattr(updates_mod.sys, "platform", "darwin")
    runtime = _fake_runtime(DistributionKind.PACKAGED_DESKTOP, version="2.34.0")
    app = _UpdatesHost(tmp_path, runtime=runtime)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert await pilot.click("#updates_btn_check")
        await wait_until(lambda: not panel._busy and len(app.notifications) == 1)

        msg, kwargs = app.notifications[-1]
        assert msg == "Automatic updates are turned off for this session."
        assert kwargs.get("severity") == "information"
        assert kwargs.get("markup") is False
        assert "checked just now" not in str(
            panel.query_one("#updates_status_primary", Static).render()
        )


# ---------------------------------------------------------------------------
# Generation-install routing (app hooks vs legacy UpdateService)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generation_install_try_now_routes_via_app_and_never_calls_legacy_upgrade(
    tmp_path: Path,
    generation_env: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from servonaut.updates.layout import console_for

    anchor, _gen_root = generation_env
    _seed_pipx_files(
        anchor,
        state={
            "status": "rolled_back",
            "offered": "2.35.0",
            "failure": {"message": "Startup probe failed."},
        },
    )
    invoked: list[tuple[list[str], Path]] = []

    def fake_subprocess_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        invoked.append((list(cmd), Path(kwargs["cwd"])))
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="Updated Servonaut to 2.35.0\n", stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)
    legacy_upgrade = AsyncMock(return_value=(True, "legacy should not run"))
    service = SimpleNamespace(
        runtime=_fake_runtime(DistributionKind.PIPX, version="2.34.0"),
        current_version="2.34.0",
        last_check_result=None,
        update_status=None,
        target_artifact=None,
        check_for_update=MagicMock(return_value=None),
        run_upgrade=legacy_upgrade,
    )
    app = _UpdatesHost(tmp_path, update_service=service)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert panel.query_one("#updates_btn_try", Button).display is True
        assert await pilot.click("#updates_btn_try")
        await wait_until(lambda: len(invoked) == 1 and not panel._busy)

        expected_launcher = str(console_for(anchor.resolve()))
        assert invoked == [([expected_launcher, "--update"], anchor.resolve())]
        legacy_upgrade.assert_not_awaited()
        assert any("Updated Servonaut to 2.35.0" in msg for msg, _ in app.notifications)


@pytest.mark.asyncio
async def test_generation_install_update_now_routes_via_app_and_never_calls_legacy_upgrade(
    tmp_path: Path,
    generation_env: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from servonaut.updates.layout import console_for

    anchor, _gen_root = generation_env
    _seed_pipx_files(
        anchor,
        state={
            "status": "up_to_date",
            "policy": {"mode": "enforce", "minimum_version": "2.35.0"},
        },
    )
    invoked: list[tuple[list[str], Path]] = []

    def fake_subprocess_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        invoked.append((list(cmd), Path(kwargs["cwd"])))
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="Upgraded via launcher\n", stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)
    legacy_upgrade = AsyncMock(return_value=(True, "legacy should not run"))
    service = SimpleNamespace(
        runtime=_fake_runtime(DistributionKind.PIPX, version="2.34.0"),
        current_version="2.34.0",
        last_check_result=None,
        update_status=None,
        target_artifact=None,
        check_for_update=MagicMock(return_value=None),
        run_upgrade=legacy_upgrade,
    )
    app = _UpdatesHost(tmp_path, update_service=service)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert panel.query_one("#updates_btn_update", Button).display is True
        assert await pilot.click("#updates_btn_update")
        await wait_until(lambda: len(invoked) == 1 and not panel._busy)

        expected_launcher = str(console_for(anchor.resolve()))
        assert invoked == [([expected_launcher, "--update"], anchor.resolve())]
        legacy_upgrade.assert_not_awaited()
        assert any("Upgraded via launcher" in msg for msg, _ in app.notifications)


@pytest.mark.asyncio
async def test_generation_install_check_now_queues_check_and_re_reads_status(
    tmp_path: Path,
    generation_env: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from servonaut.updates import builder as updates_builder

    anchor, _gen_root = generation_env
    _seed_pipx_files(anchor, state={"status": "up_to_date"})
    queued: list[str] = []

    def fake_queue_check(store: Any, installed_version: str) -> str:
        queued.append(installed_version)
        with store.gate():
            store.write("state.json", {"status": "ready", "offered": "2.35.0"})
        return "queued"

    monkeypatch.setattr(updates_builder, "queue_update_check", fake_queue_check)
    legacy_check = MagicMock(return_value="9.9.9")
    service = SimpleNamespace(
        runtime=_fake_runtime(DistributionKind.PIPX, version="2.34.0"),
        current_version="2.34.0",
        last_check_result=UpdateCheckResult.UP_TO_DATE,
        update_status=None,
        target_artifact=None,
        check_for_update=legacy_check,
        run_upgrade=AsyncMock(return_value=(True, "ok")),
    )
    app = _UpdatesHost(tmp_path, update_service=service)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert await pilot.click("#updates_btn_check")
        await wait_until(
            lambda: not panel._busy
            and "2.35.0 is ready" in str(panel.query_one("#updates_status_primary", Static).render())
        )
        assert queued == ["2.34.0"]
        legacy_check.assert_not_called()


@pytest.mark.asyncio
async def test_frozen_desktop_keeps_direct_service_download_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import servonaut.screens.settings.panels.updates as updates_mod

    monkeypatch.setattr(updates_status, "locate_install", lambda _prefix=None: None)
    monkeypatch.setattr(updates_mod.sys, "platform", "darwin")
    runtime = _fake_runtime(DistributionKind.PACKAGED_DESKTOP, version="2.34.0")
    frozen_upgrade = AsyncMock(return_value=(True, "Downloaded verified installer."))
    service = SimpleNamespace(
        runtime=runtime,
        current_version="2.34.0",
        last_check_result=UpdateCheckResult.UPDATE_AVAILABLE,
        update_status="Update available: v2.35.0",
        target_artifact=SimpleNamespace(url="https://servonaut.dev/download"),
        check_for_update=MagicMock(return_value="2.35.0"),
        run_upgrade=frozen_upgrade,
    )
    app = _UpdatesHost(tmp_path, runtime=runtime, update_service=service)
    app_runner = AsyncMock(return_value=(True, "app runner should not handle frozen download"))
    monkeypatch.setattr(app, "run_requested_upgrade", app_runner)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert await pilot.click("#updates_btn_check")
        await wait_until(lambda: not panel._busy and panel._discovered_version == "2.35.0")
        assert await pilot.click("#updates_link_download")
        await wait_until(lambda: frozen_upgrade.await_count == 1 and not panel._busy)
        app_runner.assert_not_awaited()
        assert any("Downloaded verified installer." in msg for msg, _ in app.notifications)


# ---------------------------------------------------------------------------
# Responsive geometry (160x50 vs 100x30), Demo mode, open_settings_screen
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_layout_wide_side_by_side_and_narrow_stacked_with_no_clipping(
    tmp_path: Path, pipx_env: Path,
) -> None:
    _seed_pipx_files(
        pipx_env,
        state={"status": "ready", "offered": "2.35.0"},
        leases={"1": {"role": "mcp", "version": "2.34.0"}},
    )

    # Wide (160x50): status body and actions sit side-by-side.
    wide_app = _UpdatesHost(tmp_path)
    async with wide_app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(wide_app, pilot)
        body = panel.query_one("#updates_status_body", Vertical)
        actions = panel.query_one("#updates_status_actions", Vertical)
        postpone = panel.query_one("#updates_btn_postpone", Button)
        save_btn = panel.query_one("#save_updates", Button)
        assert actions.region.x >= body.region.right
        assert wide_app.screen.region.contains_region(postpone.region)
        assert wide_app.get_widget_at(*postpone.region.center)[0] is postpone
        assert wide_app.screen.region.contains_region(save_btn.region)

    # Narrow (100x30): labels, status copy, and action button stack vertically.
    narrow_app = _UpdatesHost(tmp_path)
    async with narrow_app.run_test(size=(100, 30)) as pilot:
        panel = await _wait_updates_panel(narrow_app, pilot)
        assert panel.has_class("-narrow")
        installed_row = panel.query_one("#updates_installed_row")
        installed_label = installed_row.query_one(".updates-label")
        installed_val = panel.query_one("#updates_installed_value")
        assert installed_val.region.y >= installed_label.region.bottom

        status_body = panel.query_one("#updates_status_body", Vertical)
        status_actions = panel.query_one("#updates_status_actions", Vertical)
        assert status_actions.region.y >= status_body.region.bottom

        panel_body = panel.query_one(".panel-body", VerticalScroll)
        for selector in ("#updates_channel_stable", "#updates_channel_rc"):
            radio_btn = panel.query_one(selector, RadioButton)
            assert radio_btn.region.width > 0 and radio_btn.region.height > 0
            assert radio_btn.region.right <= panel_body.content_region.right

        save_btn = panel.query_one("#save_updates", Button)
        assert narrow_app.screen.region.contains_region(save_btn.region)
        assert narrow_app.get_widget_at(*save_btn.region.center)[0] is save_btn


@pytest.mark.asyncio
async def test_demo_mode_keeps_version_and_install_kind_visible(
    tmp_path: Path, pipx_env: Path,
) -> None:
    app = _UpdatesHost(tmp_path, demo_mode=True)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        assert "2.34.0  ·  installed with pipx" == str(
            panel.query_one("#updates_installed_value", Static).render()
        )
        assert panel.DEMO_REDACTED_FIELDS == {}


@pytest.mark.asyncio
async def test_open_settings_screen_opens_updates_panel_directly(
    tmp_path: Path, pipx_env: Path,
) -> None:
    app = _UpdatesHost(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        await _wait_updates_panel(app, pilot)
        app.open_settings_screen("general")
        await wait_until(lambda: app.screen._active_id == "general")
        app.open_settings_screen("updates")
        await wait_until(lambda: app.screen._active_id == "updates")
        assert isinstance(app.screen._current_panel(), UpdatesPanel)


# ---------------------------------------------------------------------------
# Pinned by manual install (real state.json pin + neutral/escaped display)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pinned_version_from_real_state_json_is_neutral_without_postpone(
    tmp_path: Path, pipx_env: Path,
) -> None:
    _seed_pipx_files(
        pipx_env,
        state={
            "status": "ready",
            "offered": "2.35.0",
            "pin": {"version": "2.34.0", "from": "2.35.0"},
        },
    )
    app = _UpdatesHost(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        primary = panel.query_one("#updates_status_primary", Static)
        text = str(primary.render())
        assert "Pinned to 2.34.0 by a manual install" in text
        assert "newer than 2.35.0" in text
        assert not primary.has_class("-error")
        assert not primary.has_class("-warning")
        assert panel.query_one("#updates_btn_postpone", Button).display is False
        assert panel.query_one("#updates_btn_check", Button).display is True


@pytest.mark.asyncio
async def test_pinned_version_without_threshold_shows_generic_resume_copy(
    tmp_path: Path, pipx_env: Path,
) -> None:
    _seed_pipx_files(
        pipx_env,
        state={
            "status": "up_to_date",
            "pin": {"version": "2.34.0"},
        },
    )
    app = _UpdatesHost(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _wait_updates_panel(app, pilot)
        primary = panel.query_one("#updates_status_primary", Static)
        text = str(primary.render())
        assert "Pinned to 2.34.0 by a manual install" in text
        assert "automatic updates resume when a newer release is out" in text
        assert not primary.has_class("-error")
        assert not primary.has_class("-warning")
        assert panel.query_one("#updates_btn_postpone", Button).display is False
        assert panel.query_one("#updates_btn_check", Button).display is True


@pytest.mark.asyncio
async def test_pinned_version_with_threshold_is_neutral_and_escaped(
    tmp_path: Path, pipx_env: Path,
) -> None:
    _seed_pipx_files(
        pipx_env,
        state={
            "status": "failed",
            "offered": "2.35.0",
            "failure": {"message": "ignored while pinned"},
            "pin": {"version": "2.34.0\x1b[31m", "from": "2.35.0[bold]"},
        },
    )
    app = _UpdatesHost(tmp_path)
    with markup_guard.watch() as guard:
        async with app.run_test(size=(160, 50)) as pilot:
            panel = await _wait_updates_panel(app, pilot)
            primary = panel.query_one("#updates_status_primary", Static)
            text = str(primary.render())
            assert "Pinned to 2.34.0[31m by a manual install" in text
            assert "\x1b" not in text
            assert "newer than 2.35.0[bold]" in text
            assert not primary.has_class("-error")
            assert not primary.has_class("-warning")
            assert panel.query_one("#updates_btn_postpone", Button).display is False
            assert panel.query_one("#updates_btn_try", Button).display is False
    assert guard.findings == []
