"""Journey: a team member finds the team's shared servers in the server list.

Signed in as a member of the team Ops, the user opens the TUI. Besides their
own servers, the list holds the team's server-1 ("Team Ops", state
"shared"). One of their own servers the team shares too, app-1, is listed
once, marked "· shared". Searching "shared" finds both; opening server-1
shows it as the team's server. When the team stops sharing server-1, a
refresh takes it off the list; signed out, the list holds only the user's
own servers and nothing asks the team service.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.session_seed import seed_session

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

TEAM = {"slug": "ops", "name": "Ops", "role": "member", "member_count": 2}
SERVER_1 = {
    "id": "srv-1", "name": "server-1", "hostname": "server-1.example.com", "port": 22,
    "login_user": "deploy", "status": "active",
}
# The team's copy of the user's own app-1.
APP_1_SHARED = {
    "id": "srv-2", "name": "app-1-team", "hostname": "app-1.example.com", "port": 22,
    "instance_id": fleet.APP_1.instance_id, "status": "active",
}
OWN = sorted(host.name for host in fleet.AWS_FLEET)


def _seed(seed, fake_cloud, *, signed_in: bool = True) -> None:
    fake_cloud.configure(plan="teams")
    fake_cloud.account.configure(teams=[TEAM], shared_servers={"ops": [SERVER_1, APP_1_SHARED]})
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    if signed_in:
        seed_session(seed.home, fake_cloud)


def _rows(t) -> dict[str, list[str]]:
    """The fleet table's rows by their Name cell."""
    return {row[1]: row for row in t.table_rows("InstanceTable")}


def _column(t, key: str) -> int:
    from servonaut.widgets.instance_table import InstanceTable

    return t.on_screen(InstanceTable).get_column_index(key)


async def test_a_member_finds_the_team_servers_in_the_server_list(tui, seed, fake_cloud):
    _seed(seed, fake_cloud)
    async with tui() as t:
        await t.wait_until(lambda: "server-1" in _rows(t), desc="the team's server listed")
        rows = _rows(t)
        assert rows["server-1"][_column(t, "provider")] == "Team Ops"
        assert rows["server-1"][_column(t, "state")] == "shared"
        assert rows["server-1"][_column(t, "public_ip")] == "server-1.example.com"
        # app-1 is listed once, as the user's own server, marked as shared.
        assert sorted(rows) == sorted(
            ["server-1", *(f"{name} · shared" if name == "app-1" else name for name in OWN)]
        )
        assert "app-1-team" not in rows

        # "shared" finds the team's server and the own server it shares too.
        await t.fill("#search_input", "shared")
        await t.wait_until(
            lambda: sorted(_rows(t)) == ["app-1 · shared", "server-1"], desc="shared servers found",
        )
        await t.fill("#search_input", "")
        await t.wait_until(lambda: len(_rows(t)) == len(OWN) + 1, desc="every server back")

        # Opening server-1 shows it as the team's server.
        await t.select_instance("server-1")
        await t.press("enter")
        await t.wait_for_screen("ServerActionsScreen")
        info = str(t.on_screen("#server_info").visual)
        assert "Team server: server-1" in info
        assert "Team: Ops" in info
        assert "Login: deploy" in info
        await t.press("escape")
        await t.wait_for_screen("InstanceListScreen")

        # The team stops sharing server-1: a refresh takes it off the list.
        fake_cloud.account.configure(shared_servers={"ops": [APP_1_SHARED]})
        await t.focus_instance_table()
        await t.press("r")
        await t.wait_until(lambda: "server-1" not in _rows(t), desc="server-1 gone")
        assert "app-1 · shared" in _rows(t)


async def test_signed_out_the_list_holds_only_the_own_servers(tui, seed, fake_cloud):
    _seed(seed, fake_cloud, signed_in=False)
    async with tui() as t:
        await t.wait_until(lambda: sorted(_rows(t)) == OWN, desc="own servers listed")
        await t.settle()
        assert sorted(_rows(t)) == OWN
        assert fake_cloud.requests("/api/v1/teams") == []
