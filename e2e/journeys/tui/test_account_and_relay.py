"""Journey: sign in from the TUI and live with the session and the relay.

Signing in on the Account screen starts the in-process relay listener; the
sidebar indicator turns to "connected" and account-only entries appear. A
stale access token is refreshed transparently (the Teams screen still
loads), a revoked session flips the indicator to "session expired" and one
click leads back to sign-in, and signing out revokes the session and stops
the relay. The relay status screen shows the local and the service's view
and can stop and restart the listener. ``servonaut connect --force-bg``
takes the relay over from a running TUI.
"""

from __future__ import annotations

import asyncio
import os
import re

import pytest
from rich.text import Text

from e2e.harness import fleet
from e2e.harness.session_seed import read_session, seed_relay_config, seed_session
from e2e.harness.fake_cloud.state import USER_CODE

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

CONNECTED = "● connected"
DISCONNECTED = "○ disconnected"
SESSION_EXPIRED = "○ session expired"
ACCOUNT_ONLY = "nav_sync_config"


def _seed(seed, fake_cloud, *, signed_in: bool = True, heartbeat_interval=None) -> None:
    seed_relay_config(seed, heartbeat_interval=heartbeat_interval)
    seed.cache(fleet.cache_rows(), fresh=True)
    if signed_in:
        seed_session(seed.home, fake_cloud)


def _indicator(t):
    from servonaut.widgets.relay_indicator import RelayIndicator

    return t.on_screen(RelayIndicator)


def _indicator_text(t) -> str:
    return Text.from_markup(str(_indicator(t).render())).plain


async def _relay_shows(t, label: str) -> None:
    await t.wait_until(lambda: _indicator_text(t) == label, desc=f"relay indicator {label!r}")


def _fleet_column(t, key: str) -> dict[str, str]:
    """One column of the fleet table, by instance name."""
    from servonaut.widgets.instance_table import InstanceTable

    table = t.on_screen(InstanceTable)
    name_at, value_at = table.get_column_index("name"), table.get_column_index(key)
    return {row[name_at]: row[value_at] for row in t.table_rows(InstanceTable)}


def _live(fake_cloud) -> list[dict]:
    return fake_cloud.relay.subscriptions(live=True)


async def _sign_in(t) -> None:
    """Run the device flow from the Account screen, as a user would."""
    await t.click("#btn_login")
    await t.wait_until(lambda: f"Code: {USER_CODE}" in t.rendered_text(), desc="user code shown")
    await t.wait_for_toast("Logged in successfully!")


async def test_login_starts_the_relay_and_unlocks_account_features(tui, seed, fake_cloud):
    _seed(seed, fake_cloud, signed_in=False)
    async with tui() as t:
        assert not t.nav_reachable(ACCOUNT_ONLY)
        await t.nav("nav_login")
        await t.wait_for_screen("LoginScreen")
        await _sign_in(t)

        await t.wait_for_toast("Connecting to Servonaut relay")
        await _relay_shows(t, CONNECTED)
        # "Connected" follows the first heartbeat; the subscription is made
        # alongside it.
        user_id = fake_cloud.entitlements()["user_id"]
        topics = [f"/cli/{user_id}/commands", f"/cli/{user_id}/ai-tool-calls"]
        await t.wait_until(
            lambda: [s["topics"] for s in _live(fake_cloud)] == [topics],
            desc="subscription to both topics",
        )
        handshake = fake_cloud.relay.heartbeats()[0]
        assert handshake["type"] == "cli.handshake"
        assert "aws" in handshake["providers_configured"]

        session = read_session(seed.home)
        assert session["plan"] == "solo" and session["user_id"] == user_id
        assert (seed.home / ".servonaut" / "auth.json").stat().st_mode & 0o777 == 0o600

        # A fresh screen's sidebar reflects the account: Sync Config appears,
        # Teams stays hidden on a Solo plan.
        await t.nav("nav_list")
        await t.wait_for_screen("InstanceListScreen")
        assert t.nav_reachable(ACCOUNT_ONLY)
        assert not t.nav_reachable("nav_teams")
        assert _indicator_text(t) == CONNECTED


async def test_revoked_session_leads_back_to_sign_in(tui, seed, fake_cloud):
    _seed(seed, fake_cloud, heartbeat_interval=1)
    async with tui() as t:
        await _relay_shows(t, CONNECTED)

        fake_cloud.revoke_session()
        await t.wait_for_toast("Servonaut session expired", severity="warning")
        await _relay_shows(t, SESSION_EXPIRED)
        await t.wait_until(lambda: not _live(fake_cloud), desc="relay unsubscribed")

        # Clicking the indicator goes straight to sign-in.
        await t.click(_indicator(t))
        await t.wait_for_screen("LoginScreen")
        assert t.is_reachable(t.on_screen("#btn_login"))
        await _sign_in(t)
        await _relay_shows(t, CONNECTED)
        # The new sign-in is a new token pair, saved to disk.
        assert read_session(seed.home)["refresh_token"] == fake_cloud.tokens()[1]


async def test_stale_token_is_refreshed_and_the_request_retried(tui, seed, fake_cloud):
    fake_cloud.configure(plan="teams", mcp_connections=0)
    _seed(seed, fake_cloud)
    first_refresh_token = fake_cloud.tokens()[1]
    async with tui() as t:
        await t.wait_for_toast("MCP relay disabled by your plan")
        # A Teams plan shows the Teams entry.
        assert t.nav_reachable("nav_teams")
        # Let the start-up requests (a team lookup, then the team and
        # personal secret-store configs) finish before the token goes stale.
        await t.wait_until(
            lambda: fake_cloud.requests("/api/v1/me/instances")
            and fake_cloud.requests("/api/v1/teams")
            and fake_cloud.requests("/api/v1/teams/ops/secrets-config")
            and fake_cloud.requests("/api/v1/me/secrets-config"),
            desc="start-up requests",
        )
        before = len(fake_cloud.requests("/api/v1/teams"))

        fake_cloud.expire_access_token()
        await t.nav("nav_teams")
        await t.wait_for_screen("TeamManagementScreen")
        rows = await t.wait_until(lambda: t.table_rows("#teams_table"), desc="teams listed")
        assert rows == [["Ops", "owner", "2"]]

        teams = [r["status"] for r in fake_cloud.requests("/api/v1/teams")[before:]]
        assert teams == [401, 200]
        assert [r["status"] for r in fake_cloud.requests("/api/oauth/refresh")] == [200]
        # The refresh token rotated and the new pair replaced the old on disk.
        saved = read_session(seed.home)
        assert saved["refresh_token"] == fake_cloud.tokens()[1] != first_refresh_token
        assert saved["access_token"] == fake_cloud.tokens()[0]


async def test_logout_revokes_the_session_and_stops_the_relay(tui, seed, fake_cloud):
    _seed(seed, fake_cloud)
    async with tui() as t:
        await _relay_shows(t, CONNECTED)
        await t.nav("nav_login")
        await t.wait_for_screen("LoginScreen")
        await t.click("#btn_logout")
        await t.wait_for_toast("Logged out.")

        assert read_session(seed.home) is None
        assert len(fake_cloud.requests("/api/oauth/revoke")) == 1
        await t.wait_until(lambda: not _live(fake_cloud), desc="relay unsubscribed")
        await _relay_shows(t, DISCONNECTED)
        assert t.is_reachable(t.on_screen("#btn_login"))

        await t.nav("nav_list")
        await t.wait_for_screen("InstanceListScreen")
        assert not t.nav_reachable(ACCOUNT_ONLY)


async def test_relay_status_screen_stops_and_restarts(tui, seed, fake_cloud):
    _seed(seed, fake_cloud)
    async with tui() as t:
        await _relay_shows(t, CONNECTED)
        client_id = fake_cloud.relay.heartbeats()[0]["client_id"]

        await t.click(_indicator(t))
        await t.wait_for_screen("RelayStatusScreen")
        await t.wait_until(
            lambda: "Backend: connected" in t.rendered_text(), desc="the service's view"
        )
        text = t.rendered_text()
        assert f"Local: connected — lock owner: tui (PID {os.getpid()})" in text
        assert client_id in text

        stopped = _live(fake_cloud)[0]["number"]
        await t.press("s")
        await t.wait_for_toast("Relay stopped")
        await t.wait_until(lambda: t.screen_name() != "RelayStatusScreen", desc="screen closed")
        await _relay_shows(t, DISCONNECTED)
        await t.wait_until(lambda: not _live(fake_cloud), desc="relay unsubscribed")

        await t.click(_indicator(t))
        await t.wait_for_screen("RelayStatusScreen")
        await t.wait_until(lambda: "Local: stopped" in t.rendered_text(), desc="local view")
        await t.press("r")
        await t.wait_for_toast("Relay restart requested")
        await _relay_shows(t, CONNECTED)
        await t.wait_until(
            lambda: [s["number"] > stopped for s in _live(fake_cloud)] == [True],
            desc="one new subscription replacing the stopped one",
        )


async def test_force_bg_takes_the_relay_over_from_the_tui(
    tui, seed, fake_cloud, relay, e2e_ctx
):
    _seed(seed, fake_cloud)
    async with tui() as t:
        await _relay_shows(t, CONNECTED)
        tui_client = fake_cloud.relay.heartbeats()[0]["client_id"]
        connect = relay(e2e_ctx.sandbox)  # the same home as the TUI
        held = f"A TUI session is already holding the relay connection (PID {os.getpid()})"

        # Plain start-up forms refuse while the TUI holds the relay.
        background = await asyncio.to_thread(connect.run, "--bg")
        assert held in background.stdout, background.describe()
        foreground = await asyncio.to_thread(connect.run)
        assert foreground.returncode == 2 and held in foreground.stdout

        # --force-bg asks the TUI to let go, waits for its answer, then starts.
        handover = await asyncio.to_thread(connect.run, "--force-bg")
        assert handover.returncode == 0, handover.describe()
        match = re.search(r"started in background \(PID (\d+)\)", handover.stdout)
        assert match, handover.describe()
        pid = int(match.group(1))

        await _relay_shows(t, DISCONNECTED)
        # The background listener heartbeats once it holds the relay lock.
        await t.wait_until(
            lambda: any(h["client_id"] != tui_client for h in fake_cloud.relay.heartbeats()),
            desc="the background listener's heartbeat",
        )
        assert connect.lock_owner() == {"pid": pid, "mode": "bg"}
        await t.wait_until(lambda: len(_live(fake_cloud)) == 1, desc="one subscription")

        # Restarting the relay in the TUI now defers to the background listener.
        await t.click(_indicator(t))
        await t.wait_for_screen("RelayStatusScreen")
        await t.press("r")
        await _relay_shows(t, "● external listener")


async def test_ssh_verify_results_show_in_the_fleet(tui, seed, fake_cloud):
    fake_cloud.account.set_verify_status("aws", fleet.APP_1.instance_id, "verified")
    fake_cloud.account.set_verify_status("aws", fleet.DB_1.instance_id, "auth_failed")
    _seed(seed, fake_cloud)
    async with tui() as t:
        def ssh_column():
            return _fleet_column(t, "ssh")

        await t.wait_until(
            lambda: "verified" in ssh_column().get(fleet.APP_1.name, ""), desc="verify badges"
        )
        badges = ssh_column()
        assert "✓ verified" in badges[fleet.APP_1.name]
        assert "✗ auth failed" in badges[fleet.DB_1.name]
        assert "verified" not in badges[fleet.EDGE_1.name]
        assert "failed" not in badges[fleet.EDGE_1.name]
