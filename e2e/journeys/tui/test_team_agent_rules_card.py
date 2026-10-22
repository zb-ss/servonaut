"""Journey: a member reads what agents may do on the team's servers, on the Teams screen.

Signed in as a member of the team Ops, the user opens Teams and views Ops.
The last card, "What agents may do here", shows the rules Ops's owners and
admins set, as this Servonaut verified them: the level of each role, the
user's own role, a server with its own levels (by name), the command lists,
and the rules' version with when they were fetched and until when they hold.

When the team service stops sending signed rules, viewing the team again
fetches them again, and the card says that agents now run at the readonly
level on Ops's servers, owners included, and why.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.fake_cloud import routes_agent_rules as served
from e2e.harness.session_seed import seed_session
from e2e.harness.team_agent_rules import ENV_FILES, SERVER_1, SLUG, member_of_ops

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

RULES = {
    "role_levels": {"member": "readonly"},
    "servers": {SERVER_1["id"]: {"role_levels": {"member": "standard"}}},
    "command_allowlist": ["uptime", "df"],
    "command_blocklist": [ENV_FILES],
}


def _card(t) -> list[str]:
    """The card's lines, without their styling (it may be scrolled out of view)."""
    return str(t.on_screen("#agent_rules_body").visual).splitlines()


async def _view_ops(t) -> None:
    await t.wait_until(lambda: t.table_rows("#teams_table") == [["Ops", "member", "2"]], desc="Ops listed")
    await t.click("#btn_view_team")


async def test_a_member_sees_the_rules_and_when_they_fall_back(tui, seed, fake_cloud):
    member_of_ops(fake_cloud)
    fake_cloud.configure(mcp_connections=0)
    fake_cloud.agent_rules.set_rules(SLUG, RULES, version=7)
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)
    async with tui() as t:
        await t.nav("nav_teams")
        await t.wait_for_screen("TeamManagementScreen")
        await _view_ops(t)
        await t.wait_until(lambda: _card(t)[-1].startswith("Version 7 · last refreshed "), desc="the rules")
        *lines, times = _card(t)
        assert lines == [
            "Agents on this team's shared servers run at these levels. "
            "Your own MCP settings can only make these stricter.",
            "Owner: standard · Admin: standard · Member: readonly · Viewer: readonly",
            "Your role: member (readonly)",
            "Per server:",
            "  server-1: Member standard",
            "Allowed commands at the standard level: uptime, df",
            f"Blocked patterns the team adds to Servonaut's own: {ENV_FILES}",
        ]
        assert " · valid until " in times

        # The service stops signing the rules: viewing the team fetches them again.
        fake_cloud.agent_rules.serve(SLUG, served.UNSIGNED)
        await _view_ops(t)
        fallback = (
            "Agents run at the readonly level on this team's shared servers, owners "
            "included, because the team service sent no signed agent rules."
        )
        await t.wait_until(lambda: _card(t)[0] == fallback, desc="the readonly fallback")
        assert _card(t)[1].startswith("Version 7 · last refreshed ")
        assert [row["serving"] for row in fake_cloud.agent_rules.served(SLUG)][-1] == served.UNSIGNED
