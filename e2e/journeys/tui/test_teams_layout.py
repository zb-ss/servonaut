"""Journey: viewing a team on the Teams screen.

Each card on the Teams screen is as tall as its contents, so View Team shows
the team's members right below the team list: every member row and the
member buttons are in view without scrolling, in a wide and a narrow
terminal. In a narrow terminal the five member buttons wrap onto a second
row instead of running off the edge.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.pilot import DEFAULT_SIZE
from e2e.harness.session_seed import seed_relay_config, seed_session

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

NARROW = (100, 30)
MEMBER_BUTTONS = ("#btn_invite", "#btn_change_role", "#btn_resend", "#btn_copy_url", "#btn_remove")
MEMBERS = [
    {"invitation_email": f"{name}@example.com", "role": role, "is_accepted": True}
    for name, role in (("owner", "owner"), ("lead", "admin"), ("dev-1", "member"), ("dev-2", "member"))
]
TEAM = {"slug": "ops", "name": "Ops", "role": "owner", "member_count": len(MEMBERS), "members": MEMBERS}


def _seed(seed, fake_cloud) -> None:
    fake_cloud.configure(plan="teams", mcp_connections=0)
    fake_cloud.account.configure(teams=[TEAM])
    seed_relay_config(seed)
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)


@pytest.mark.parametrize("size", [DEFAULT_SIZE, NARROW], ids=["160x50", "100x30"])
async def test_view_team_shows_every_member_in_view(tui, seed, fake_cloud, size):
    _seed(seed, fake_cloud)
    async with tui(size=size) as t:
        await t.nav("nav_teams")
        await t.wait_for_screen("TeamManagementScreen")
        await t.wait_until(lambda: t.table_rows("#teams_table"), desc="teams listed")
        await t.click("#btn_view_team")
        members = t.on_screen("#members_table")
        await t.wait_until(lambda: members.row_count == len(MEMBERS), desc="members listed")
        await t.settle()

        viewport = t.on_screen("#team_management_container").region
        # The header and every member row are drawn, and all of it is in view.
        assert members.region.height == len(MEMBERS) + 1, members.region
        assert members.region.bottom <= viewport.bottom, (members.region, viewport)
        row = t.on_screen("#member_actions_row").region
        for selector in MEMBER_BUTTONS:
            button = t.on_screen(selector).region
            assert button.width and row.x <= button.x and button.right <= row.right, (selector, button, row)
            assert button.bottom <= viewport.bottom, (selector, button, viewport)
