"""Screenshot tests: the main screens, drawn by the real app and stylesheet.

Each test drives :class:`_harness.SnapshotApp` to one state and compares the
rendered terminal with the SVG stored under ``__snapshots__``. A layout or
styling change shows up as a failed comparison; ``pytest --update-snapshots``
accepts the new rendering (see CONTRIBUTING.md).

Every screen is captured at two terminal sizes.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

import pytest
from textual.widgets import Button, DataTable, Select

from servonaut.screens.settings.registry import PANELS

from . import _harness

Scenario = Callable[[Any], Awaitable[None]]

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))

# Typed into the command palette; it matches a single command.
_PALETTE_QUERY = "settings"


def _run(scenario: Scenario) -> Callable[[Any], Awaitable[None]]:
    """Wrap *scenario*: start from a loaded fleet, finish with steady cursors."""

    async def run_before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        await scenario(pilot)
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    return run_before


def _capture(screen_snapshot: Any, size: str, scenario: Scenario, *, demo: bool = False) -> None:
    screen_snapshot(_harness.SnapshotApp(demo=demo), _harness.SIZES[size], _run(scenario))


async def _navigate(pilot: Any, nav_id: str, screen: str) -> Any:
    """Press a sidebar entry, as a click on it would, and wait for *screen*."""
    pilot.app.screen.query_one(f"#{nav_id}", Button).press()
    return await _harness.wait_for_screen(pilot, screen)


async def _open_focus_server(pilot: Any, key: str, screen: str) -> Any:
    """Select the seeded server in the fleet table and press *key*."""
    return await _open_server(pilot, _harness.FOCUS_SERVER["name"], key, screen)


async def _open_server(pilot: Any, name: str, key: str, screen: str) -> Any:
    """Select the server called *name* in the fleet table and press *key*."""
    await _harness.select_fleet_row(pilot, name)
    await pilot.press(key)
    return await _harness.wait_for_screen(pilot, screen)


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


async def _fleet(pilot: Any) -> None:
    del pilot


async def _fleet_memory_banner(pilot: Any) -> None:
    """No server has memory yet: the fleet shows its one-line memory hint."""
    app = pilot.app
    app.memory_service.list_all = lambda: []
    app.screen._sync_memory_banner()
    banner = app.screen.query_one("#memory_discover_banner")
    await _harness.wait_until(pilot, lambda: banner.display, "the memory hint")


async def _fleet_search(pilot: Any) -> None:
    await pilot.press("slash", *"web")
    table = pilot.app.screen.query_one("InstanceTable")
    await _harness.wait_until(pilot, lambda: table.row_count == 1, "the filtered fleet")


def _server_actions_of(name: str) -> Scenario:
    async def scenario(pilot: Any) -> None:
        screen = await _open_server(pilot, name, "o", "ServerActionsScreen")
        # The screen focuses its first action as it opens, which may or may not
        # scroll the action rail past its first heading, depending on timing.
        # Start from the top of the rail, as the screen is laid out.
        screen.query_one("#action_buttons").scroll_home(animate=False, immediate=True)

    return scenario


_server_actions = _server_actions_of(_harness.FOCUS_SERVER["name"])


async def _memory(pilot: Any) -> None:
    screen = await _open_focus_server(pilot, "m", "MemoryScreen")
    table = screen.query_one("#memory-table", DataTable)
    await _harness.wait_until(pilot, lambda: table.row_count > 0, "the memory table")


def _settings(panel_id: str) -> Scenario:
    async def scenario(pilot: Any) -> None:
        pilot.app.open_settings_screen(panel_id)
        screen = await _harness.wait_for_screen(pilot, "SettingsScreen")
        await _harness.wait_until(
            pilot,
            lambda: screen.query_one(f"#panel_{panel_id}").display,
            f"the {panel_id} settings panel",
        )

    return scenario


async def _power_prompt(pilot: Any) -> None:
    screen = await _navigate(pilot, "nav_aws_manage", "AWSManagerScreen")
    table = screen.query_one("#aws_mgr_table", DataTable)
    await _harness.wait_until(
        pilot, lambda: table.row_count == len(_harness.AWS_ROWS), "the EC2 table"
    )
    table.focus()
    table.move_cursor(row=0)  # app-1, running
    await pilot.pause()
    await pilot.press("t")
    await _harness.wait_for_screen(pilot, "PowerActionConfirmModal")


async def _dialog_over_fleet(pilot: Any) -> None:
    from servonaut.screens.confirm_action import ConfirmActionScreen

    await _harness.select_fleet_row(pilot, "web-1")
    pilot.app.push_screen(
        ConfirmActionScreen(
            title="Reinstall server",
            description="Reinstall [bold]web-1[/bold] from its base image?",
            consequences=["Every file on the server is erased"],
            confirm_text="web-1",
            action_label="Reinstall",
        )
    )
    await _harness.wait_for_screen(pilot, "ConfirmActionScreen")


async def _help(pilot: Any) -> None:
    # From the fleet table: in the search box, "?" is typed as text.
    await _harness.select_fleet_row(pilot, _harness.FOCUS_SERVER["name"])
    await pilot.press("question_mark")
    await _harness.wait_for_screen(pilot, "HelpScreen")


async def _command_palette(pilot: Any) -> None:
    from textual.command import CommandList, CommandPalette

    await pilot.press("ctrl+p")
    screen = await _harness.wait_for_screen(pilot, "CommandPalette")
    await pilot.press(*_PALETTE_QUERY)
    commands = screen.query_one(CommandList)

    def search_finished() -> bool:
        searching = any(
            worker.group == CommandPalette._GATHER_COMMANDS_GROUP and not worker.is_finished
            for worker in pilot.app.workers
        )
        return not searching and commands.option_count > 0

    await _harness.wait_until(pilot, search_finished, "the command palette search")


async def _custom_servers(pilot: Any) -> None:
    await _navigate(pilot, "nav_custom_servers", "CustomServersScreen")


async def _ip_ban(pilot: Any) -> None:
    await _navigate(pilot, "nav_ip_ban", "IPBanScreen")


async def _ip_ban_configured(pilot: Any) -> None:
    from servonaut.config.schema import IPBanConfig

    pilot.app.config_manager.get().ip_ban_configs.append(
        IPBanConfig(name="edge-waf", method="waf", region="us-east-1")
    )
    await _navigate(pilot, "nav_ip_ban", "IPBanScreen")


async def _cloudtrail(pilot: Any) -> None:
    await _navigate(pilot, "nav_cloudtrail", "CloudTrailBrowserScreen")


async def _cloudwatch(pilot: Any) -> None:
    await _navigate(pilot, "nav_cloudwatch", "CloudWatchBrowserScreen")


async def _cloudwatch_top_ips(pilot: Any) -> None:
    app = pilot.app

    async def log_groups(prefix: str = "", region: str = "") -> list:
        del prefix, region
        return [{"name": _harness.CLOUDWATCH_GROUP}]

    async def log_events(**_kwargs: Any) -> list:
        return _harness.cloudwatch_events()

    app.cloudwatch_service.list_log_groups = log_groups
    app.cloudwatch_service.get_log_events = log_events
    screen = await _navigate(pilot, "nav_cloudwatch", "CloudWatchBrowserScreen")
    screen.query_one("#cw_select_region", Select).value = _harness.CLOUDWATCH_REGION
    groups = screen.query_one("#cw_select_log_group", Select)
    await _harness.wait_until(
        pilot, lambda: groups.prompt == "Select log group", "the log group list"
    )
    groups.value = _harness.CLOUDWATCH_GROUP
    await pilot.pause()
    screen.action_fetch()
    ips = screen.query_one("#cloudwatch_ips_table", DataTable)
    await _harness.wait_until(pilot, lambda: ips.row_count > 0, "the Top IPs table")
    ips.focus()
    app.clear_notifications()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@sizes
def test_fleet_table(screen_snapshot, size: str) -> None:
    """The fleet table with AWS, custom, OVH and Hetzner servers."""
    _capture(screen_snapshot, size, _fleet)


@sizes
def test_fleet_memory_banner(screen_snapshot, size: str) -> None:
    """The memory hint takes one row, so the fleet keeps its rows."""
    _capture(screen_snapshot, size, _fleet_memory_banner)


@sizes
def test_fleet_search(screen_snapshot, size: str) -> None:
    """The fleet filtered from the search box; the footer keeps the shortcuts, greyed."""
    _capture(screen_snapshot, size, _fleet_search)


@sizes
def test_fleet_table_demo_mode(screen_snapshot, size: str) -> None:
    """The same fleet with demo mode on: every identifier is a stand-in."""
    _capture(screen_snapshot, size, _fleet, demo=True)


def _capture_multi_account(
    screen_snapshot: Any, size: str, scenario: Scenario, *, demo: bool = False,
) -> None:
    async def run_before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot, rows=_harness.MULTI_ACCOUNT_FLEET_SIZE)
        await scenario(pilot)
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(
        _harness.MultiAccountSnapshotApp(demo=demo), _harness.SIZES[size], run_before,
    )


@sizes
def test_fleet_table_two_hetzner_projects(screen_snapshot, size: str) -> None:
    """A provider with two accounts lists its servers as account/name."""
    _capture_multi_account(screen_snapshot, size, _fleet)


@sizes
def test_fleet_table_two_hetzner_projects_demo_mode(screen_snapshot, size: str) -> None:
    """Demo mode also stands in for the account label."""
    _capture_multi_account(screen_snapshot, size, _fleet, demo=True)


@sizes
def test_server_actions(screen_snapshot, size: str) -> None:
    """The actions screen of an AWS server with cached memory."""
    _capture(screen_snapshot, size, _server_actions)


@sizes
def test_server_actions_custom_server(screen_snapshot, size: str) -> None:
    """The actions screen of a custom server with no memory yet."""
    _capture(screen_snapshot, size, _server_actions_of(_harness.CUSTOM_SERVERS[0].name))


@sizes
def test_server_actions_ovh(screen_snapshot, size: str) -> None:
    """The actions screen of an OVH VPS, with its extra maintenance actions."""
    _capture(screen_snapshot, size, _server_actions_of(_harness.OVH_ROWS[0]["name"]))


@sizes
def test_settings_general(screen_snapshot, size: str) -> None:
    """Settings, General panel."""
    _capture(screen_snapshot, size, _settings("general"))


@sizes
def test_settings_hetzner(screen_snapshot, size: str) -> None:
    """Settings, Hetzner Cloud panel."""
    _capture(screen_snapshot, size, _settings("hetzner"))


# The other Settings panels, at the narrow size, where each label sits above
# its field. Left out: panels whose content depends on the machine running
# the tests (whether the Bitwarden CLI or the voice packages are installed).
_MACHINE_DEPENDENT_PANELS = {"bw_ssh", "voice"}
_NARROW_PANELS = [
    spec.id
    for spec in PANELS
    if spec.id not in {"general", "hetzner"} | _MACHINE_DEPENDENT_PANELS
]


@pytest.mark.parametrize("panel_id", _NARROW_PANELS)
def test_settings_panel_narrow(screen_snapshot, panel_id: str) -> None:
    """A Settings panel on the narrow terminal."""
    _capture(screen_snapshot, "100x30", _settings(panel_id))


@sizes
def test_server_memory(screen_snapshot, size: str) -> None:
    """The memory screen of a server with four cached modules."""
    _capture(screen_snapshot, size, _memory)


@sizes
def test_power_action_prompt(screen_snapshot, size: str) -> None:
    """The yes/no question before stopping an EC2 instance."""
    _capture(screen_snapshot, size, _power_prompt)


@sizes
def test_dialog_over_fleet(screen_snapshot, size: str) -> None:
    """A confirmation dialog dims the fleet table behind it instead of hiding it."""
    _capture(screen_snapshot, size, _dialog_over_fleet)


@sizes
def test_help(screen_snapshot, size: str) -> None:
    """The keyboard help screen."""
    _capture(screen_snapshot, size, _help)


@sizes
def test_command_palette(screen_snapshot, size: str) -> None:
    """The command palette, filtered by a query."""
    _capture(screen_snapshot, size, _command_palette)


@sizes
def test_custom_servers(screen_snapshot, size: str) -> None:
    """The custom servers screen with one server."""
    _capture(screen_snapshot, size, _custom_servers)


@sizes
def test_ip_ban(screen_snapshot, size: str) -> None:
    """The IP ban manager with nothing configured: a hint points to Settings."""
    _capture(screen_snapshot, size, _ip_ban)


def test_ip_ban_configured(screen_snapshot) -> None:
    """The IP ban manager once a ban method exists: no hint."""
    _capture(screen_snapshot, "100x30", _ip_ban_configured)


@sizes
def test_cloudtrail_empty(screen_snapshot, size: str) -> None:
    """The CloudTrail browser before a fetch: every filter reads on one line."""
    _capture(screen_snapshot, size, _cloudtrail)


@sizes
def test_cloudwatch_empty(screen_snapshot, size: str) -> None:
    """The CloudWatch browser before a log group is chosen."""
    _capture(screen_snapshot, size, _cloudwatch)


@sizes
def test_cloudwatch_top_ips(screen_snapshot, size: str) -> None:
    """The CloudWatch browser after fetching WAF logs, Top IPs focused."""
    _capture(screen_snapshot, size, _cloudwatch_top_ips)
