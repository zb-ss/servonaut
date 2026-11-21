"""Journey: client-version gate behavior in the TUI (enforce vs log mode).

Under ``mode="enforce"`` with a server minimum newer than the running client:
- the local fleet still loads and stays usable;
- the in-process relay stops on HTTP 426, never retries, and flips the
  sidebar indicator to ``○ update required`` (not ``session expired``);
- clicking the indicator shows ``Local: update_required`` and the required
  version on ``RelayStatusScreen``;
- Teams lists the user's teams, then selecting a team shows the
  update-required guidance for its details;
- opening Settings → Updates renders the enforced server-minimum state
  naming the required version and noting that local features keep working.

Under ``mode="log"`` with the same minimum, the relay connects and Teams
loads normally with zero HTTP 426 responses.
"""

from __future__ import annotations

import pytest
from textual.content import Content
from textual.widgets import Button, Static

from e2e.harness import fleet
from e2e.harness.session_seed import seed_relay_config, seed_session
from servonaut.screens.settings.panels.updates import UpdatesPanel
from servonaut.services.version_policy import parse_client_signal

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

CONNECTED = "● connected"
UPDATE_REQUIRED = "○ update required"
MINIMUM_VERSION = "99.0.0"
TEAM_PATH = "/api/v1/teams/ops"


def _seed(seed, fake_cloud) -> None:
    seed_relay_config(seed, heartbeat_interval=1)
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)


def _indicator(t):
    from servonaut.widgets.relay_indicator import RelayIndicator

    return t.on_screen(RelayIndicator)


def _indicator_text(t) -> str:
    return Content.from_markup(str(_indicator(t).render())).plain


async def _view_ops(t) -> None:
    await t.nav("nav_teams")
    await t.wait_for_screen("TeamManagementScreen")
    rows = await t.wait_until(lambda: t.table_rows("#teams_table"), desc="teams listed")
    assert rows == [["Ops", "owner", "2"]]
    await t.click("#btn_view_team")


@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_unavailable_vault_warning_matches_the_sidebar(tui, seed, fake_cloud, monkeypatch, size):
    from servonaut.services.api_client import APIError
    from servonaut.services.vault.command_service import VaultCommandService

    async def unavailable(_service):
        raise APIError(code="service_unavailable", message="Vault unavailable", status=503)

    fake_cloud.configure(plan="teams", mcp_connections=1)
    _seed(seed, fake_cloud)
    monkeypatch.setattr(VaultCommandService, "discover", unavailable)

    async with tui(size=size) as t:
        await t.wait_for_toast(r"^Vault is unavailable\. Restart Servonaut to retry\.$")
        await t.wait_for_text("Vault is unavailable.", "Restart Servonaut")
        await t.show_navigation()
        assert not t.nav_reachable("nav_vault")
        assert not t.nav_reachable("nav_ca")


@pytest.mark.parametrize("size, via_palette", [((160, 50), False), ((100, 30), True)])
async def test_enforced_vault_remains_reachable_and_explains_update(tui, seed, fake_cloud, size, via_palette):
    fake_cloud.configure(plan="teams", mcp_connections=0)
    fake_cloud.set_client_version_policy(mode="enforce", minimum_version=MINIMUM_VERSION)
    _seed(seed, fake_cloud)

    async with tui(size=size) as t:
        await t.show_navigation()
        await t.wait_until(lambda: t.nav_reachable("nav_vault"), desc="Vault navigation after the gate refusal")
        await t.wait_for_toast(rf"^This version of Servonaut.*Update to {MINIMUM_VERSION}")
        assert not t.nav_reachable("nav_ca")
        if via_palette:
            await t.palette("Go to Vault", choose="Go to Vault")
        else:
            await t.nav("nav_vault")
        await t.wait_for_screen("VaultScreen")
        await t.wait_for_text("Update required", screen_only=True)
        status = t.on_screen("#vault_status", Static)

        def drawn_status() -> str:
            x, y, width, height = status.region
            lines = t.rendered_text().splitlines()[y:y + height]
            return " ".join(" ".join(line[x:x + width].split()) for line in lines)

        await t.wait_until(
            lambda: "reinstall" in drawn_status(),
            desc="the complete update instructions rendered in the Vault card",
        )
        rendered = drawn_status()
        assert f"Update to {MINIMUM_VERSION}" in rendered
        assert "update your source checkout and reinstall" in rendered
        assert not t.on_screen("#vault_workspace").display
        assert all(t.on_screen(f"#vault_{action}", Button).disabled for action in ("setup", "recover", "create"))
        assert fake_cloud.statuses("/api/v1/vault/identity/me") == [426, 426]
        assert all("Vault background access needs attention" not in text for _, text in t.toasts())

        fake_cloud.set_client_version_policy(mode="log", minimum_version=MINIMUM_VERSION)
        await t.press("r")
        await t.wait_until(
            lambda: t.app.vault_available and not t.app.vault_update_required,
            desc="Vault discovery resumes after refresh",
        )
        assert t.nav_reachable("nav_ca")
        assert not t.screen.has_class("-update-required")


async def test_enforce_mode_blocks_cloud_and_relay_while_local_fleet_and_updates_panel_work(
    tui, seed, fake_cloud,
):
    fake_cloud.configure(
        plan="teams",
        client_version_mode="enforce",
        client_minimum_version=MINIMUM_VERSION,
    )
    _seed(seed, fake_cloud)

    async with tui() as t:
        # Local fleet loads immediately despite enforced server minimum.
        await t.wait_for_text(fleet.APP_1.name, fleet.DB_1.name, fleet.EDGE_1.name)

        # In-process relay hits 426, stops, and flips the sidebar indicator.
        await t.wait_until(
            lambda: _indicator_text(t) == UPDATE_REQUIRED,
            desc="relay indicator shows update required",
        )
        assert not fake_cloud.relay.subscriptions(live=True)
        assert fake_cloud.requests("/api/oauth/refresh") == []
        cli_426 = [
            req for req in fake_cloud.requests()
            if req["path"].startswith("/api/cli/") and req["status"] == 426
        ]
        assert 1 <= len(cli_426) <= 2, cli_426
        assert all(parse_client_signal(req["client_header"])[2] == "relay" for req in cli_426)

        # Clicking the indicator opens RelayStatusScreen with the 426 reason.
        await t.click(_indicator(t))
        await t.wait_for_screen("RelayStatusScreen")
        await t.wait_for_text("update_required", MINIMUM_VERSION)

        await _view_ops(t)
        await t.wait_for_toast(rf"too old.*{MINIMUM_VERSION}")
        list_statuses = fake_cloud.statuses("/api/v1/teams")
        assert list_statuses and set(list_statuses) == {200}
        (team_request,) = fake_cloud.requests(TEAM_PATH)
        assert team_request["status"] == 426
        assert parse_client_signal(team_request["client_header"])[2] == "cli"

        # Settings → Updates displays the enforced server-minimum state.
        await t.nav("nav_settings")
        await t.wait_for_screen("SettingsScreen")
        await t.click("#navbtn_updates")
        await t.wait_until(
            lambda: isinstance(t.screen._current_panel(), UpdatesPanel)
            and t.screen._current_panel()._loaded
            and not t.screen._current_panel()._settling,
            desc="Updates panel loaded",
        )
        await t.wait_for_text(
            f"servonaut.dev needs {MINIMUM_VERSION} or later for team, vault and AI features.",
            "Local features keep working.",
        )
        assert 426 in fake_cloud.statuses("/api/v1/vault/identity/me")
        assert all(
            "Vault background access needs attention" not in message
            for _, message in t.toasts()
        )

        # Returning to the fleet confirms local views remain fully usable.
        await t.nav("nav_list")
        await t.wait_for_screen("InstanceListScreen")
        await t.wait_for_text(fleet.APP_1.name, fleet.DB_1.name, fleet.EDGE_1.name)
        assert _indicator_text(t) == UPDATE_REQUIRED


async def test_log_mode_keeps_relay_and_teams_working(tui, seed, fake_cloud):
    fake_cloud.configure(
        plan="teams",
        client_version_mode="log",
        client_minimum_version=MINIMUM_VERSION,
    )
    _seed(seed, fake_cloud)

    async with tui() as t:
        await t.wait_until(
            lambda: _indicator_text(t) == CONNECTED,
            desc="relay indicator shows connected in log mode",
        )

        await _view_ops(t)
        await t.wait_until(
            lambda: "Your role: owner" in str(t.on_screen("#team_header", Static).render()),
            desc="team details loaded",
        )
        (team_request,) = fake_cloud.requests(TEAM_PATH)
        assert team_request["status"] == 200 and team_request["below_minimum"] is True
        assert parse_client_signal(team_request["client_header"])[2] == "cli"
        list_requests = fake_cloud.requests("/api/v1/teams")
        assert list_requests and all("below_minimum" not in request for request in list_requests)
        (relay_request,) = fake_cloud.requests("/api/cli/mercure-token")
        assert relay_request["status"] == 200 and relay_request["below_minimum"] is True
        assert parse_client_signal(relay_request["client_header"])[2] == "relay"
        assert not any(req["status"] == 426 for req in fake_cloud.requests())

        # Settings → Updates does not show the enforced server-minimum warning in log mode.
        await t.nav("nav_settings")
        await t.wait_for_screen("SettingsScreen")
        await t.click("#navbtn_updates")
        await t.wait_until(
            lambda: isinstance(t.screen._current_panel(), UpdatesPanel)
            and t.screen._current_panel()._loaded
            and not t.screen._current_panel()._settling,
            desc="Updates panel loaded",
        )
        primary = str(t.on_screen("#updates_status_primary", Static).render())
        assert f"needs {MINIMUM_VERSION}" not in primary
