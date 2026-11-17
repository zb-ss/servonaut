"""Journey: viewing a team on the Teams screen.

Native Tab reveals the complete member table and then the member-action
grid within the scrolling workspace, in wide and narrow terminals. Every
member and action must be fully painted and reachable without activating
an action or changing the selected member.
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


async def _tab_to(t, target) -> None:
    assert target in t.screen.focus_chain, f"{target!r} must remain keyboard reachable"
    for _ in range(len(t.screen.focus_chain) + 1):
        if target.has_focus:
            break
        await t.press("tab")
    assert target.has_focus, t.focused_id()
    await t.settle()


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

        initial_rows = t.table_rows("#members_table")
        initial_cursor = members.cursor_coordinate
        assert [row[0] for row in initial_rows] == [member["invitation_email"] for member in MEMBERS]

        # The table has a reserved viewport; native focus must expose its
        # header and every seeded member, including the final two rows.
        await _tab_to(t, members)
        workspace = t.on_screen("#team_management_container")
        body_view = workspace.scrollable_content_region
        assert members.region.height >= len(MEMBERS) + 1, members.region
        assert body_view.contains_region(members.region), (members.region, body_view)
        painted = t.rendered_text()
        assert all(member["invitation_email"] in painted for member in MEMBERS)

        # The narrow layout may scroll between the table and its actions;
        # the entire action grid must still fit in its native focus pose.
        await _tab_to(t, t.on_screen("#btn_remove"))
        body_view = workspace.scrollable_content_region
        painted = t.rendered_text()
        row = t.on_screen("#member_actions_row").region
        for selector in MEMBER_BUTTONS:
            target = t.on_screen(selector)
            button = target.region
            assert button.width and row.x <= button.x and button.right <= row.right, (selector, button, row)
            assert button.height == 3 and body_view.contains_region(button), (selector, button, body_view)
            assert all(
                t.app.get_widget_at(x, y)[0] is target
                for y in range(button.y, button.bottom)
                for x in range(button.x, button.right)
            ), selector
            assert target.label.plain in painted, selector
        assert t.table_rows("#members_table") == initial_rows
        assert members.cursor_coordinate == initial_cursor
