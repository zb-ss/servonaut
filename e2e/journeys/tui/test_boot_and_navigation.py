"""Journey: start the TUI and move around it.

Covers first launch with an empty home, launch with a seeded fleet, a tour of
every sidebar destination a signed-out user can reach (at a roomy and a
small terminal size), the entries hidden until sign-in, the command palette,
the help screen, returning to the root screen and quitting.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.pilot import DEFAULT_SIZE, SMALL_SIZE

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

# Where each sidebar entry leads. Built from what a user sees, not from the
# sidebar's own lookup table, so a mismatch between the two is caught.
DESTINATIONS = {
    "nav_list": "InstanceListScreen",
    "nav_custom_servers": "CustomServersScreen",
    "nav_keys": "KeyManagementScreen",
    "nav_memory": "FleetMemoryScreen",
    "nav_memory_sync": "MemorySyncSetupScreen",
    "nav_secrets": "SecretsScreen",
    "nav_bw_vault": "BwVaultManagerScreen",
    "nav_findings": "FindingsScreen",
    "nav_settings": "SettingsScreen",
    "nav_aws_manage": "AWSManagerScreen",
    "nav_aws_s3": "ObjectStorageScreen",
    "nav_cloudwatch": "CloudWatchBrowserScreen",
    "nav_ip_ban": "IPBanScreen",
    "nav_cloudtrail": "CloudTrailBrowserScreen",
    "nav_login": "LoginScreen",
    "nav_bug_report": "BugReportScreen",
}

# Hidden from a signed-out user: they need an account (and a plan) first.
HIDDEN_WHEN_SIGNED_OUT = ("nav_sync_config", "nav_teams", "nav_drift", "nav_memory_export")
# Provider sections stay hidden until that provider is configured.
HIDDEN_WITHOUT_PROVIDERS = (
    "nav_ovh_manage",
    "nav_ovh_dns",
    "nav_ovh_s3",
    "nav_hetzner_manage",
    "nav_hetzner_s3",
)


def _seed_fleet(seed) -> None:
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)


async def test_first_launch_with_an_empty_home(tui, seed, fake_cloud):
    async with tui() as t:
        # First launch writes a config with the relay pointed at the API the
        # app was started against.
        await t.wait_until(lambda: seed.config_path.is_file(), desc="config created")
        assert seed.read_config()["relay"]["base_url"] == fake_cloud.url
        # No cache and no reachable AWS: the fleet stays empty, the failure
        # is reported, and the app keeps running.
        await t.wait_for_toast(r"AWS refresh failed", severity="warning")
        assert t.table_rows("InstanceTable") == []
        assert t.screen_name() == "InstanceListScreen"
        # The update check asked the (fake) package index and found nothing newer.
        await t.wait_until(
            lambda: fake_cloud.requests("/pypi/servonaut/json"), desc="update check request"
        )
        await t.settle()
        assert not t.nav_reachable("nav_update")
        assert not any("Update available" in message for _, message in t.toasts())


async def test_seeded_home_shows_the_fleet_at_once(tui, seed):
    _seed_fleet(seed)
    async with tui() as t:
        rows = await t.wait_until(lambda: t.table_rows("InstanceTable"), desc="fleet rows")
        names = [row[1] for row in rows]
        assert names == [host.name for host in fleet.AWS_FLEET]
        screen_text = t.rendered_text()
        assert all(name in screen_text for name in names)
        assert fleet.EDGE_1.public_ip in screen_text
        # A fresh cache means no background refresh was needed.
        await t.settle()
        assert not any("Refreshing" in message for _, message in t.toasts())


@pytest.mark.parametrize("size", [DEFAULT_SIZE, SMALL_SIZE], ids=["160x50", "80x24"])
async def test_sidebar_tour_reaches_every_destination(tui, seed, size):
    _seed_fleet(seed)
    async with tui(size=size) as t:
        for nav_id in HIDDEN_WHEN_SIGNED_OUT + HIDDEN_WITHOUT_PROVIDERS:
            assert not t.nav_reachable(nav_id), f"{nav_id} should be hidden"

        for nav_id, screen_name in DESTINATIONS.items():
            await t.nav(nav_id)
            if nav_id == "nav_bug_report":
                # Reporting a bug starts with a consent prompt; declining it
                # closes the report again.
                await t.wait_for_screen("BugReportConsentModal")
                await t.press("escape")
                await t.wait_for_toast("Bug report cancelled")
                await t.wait_until(
                    lambda: "BugReportScreen" not in t.stack_names(), desc="report closed"
                )
            else:
                await t.wait_for_screen(screen_name)
                await t.settle()
            # Every full screen keeps the sidebar, so the tour can go on.
            assert t.nav_reachable("nav_list"), f"no way back from {screen_name}"

        await t.nav("nav_list")
        await t.wait_for_screen("InstanceListScreen")


async def test_palette_reaches_screens_and_respects_sign_in_gates(tui, seed):
    _seed_fleet(seed)
    async with tui() as t:
        await t.palette("Go to Custom Servers")
        await t.wait_for_screen("CustomServersScreen")

        # Teams needs a Teams subscription: the user is told and stays put.
        await t.palette("Go to Teams")
        await t.wait_for_toast("Team management requires a Teams subscription")
        assert t.screen_name() == "CustomServersScreen"

        # Config snapshots need an account: the user is sent to sign in.
        await t.palette("Go to Sync Config")
        await t.wait_for_toast("Sign in to manage config snapshots")
        await t.wait_for_screen("LoginScreen")


async def test_help_back_to_root_and_quit(tui, seed):
    _seed_fleet(seed)
    async with tui() as t:
        # The search box has focus at start-up, so move to the fleet first,
        # as a user would, before using single-key shortcuts.
        await t.focus_instance_table()
        await t.press("question_mark")
        await t.wait_for_screen("HelpScreen")
        await t.press("escape")
        await t.wait_for_screen("InstanceListScreen")

        # Leaving a top-level screen returns to the fleet, never to nothing.
        await t.palette("Go to SSH Keys")
        await t.wait_for_screen("KeyManagementScreen")
        await t.press("escape")
        await t.wait_for_screen("InstanceListScreen")

        await t.focus_instance_table()
        await t.press("q")
        await t.wait_until(lambda: t.app.return_code is not None, desc="app exit")
        assert t.app.return_code == 0
