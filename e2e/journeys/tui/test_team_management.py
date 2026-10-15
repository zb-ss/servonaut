"""Journey: a team owner manages members and shared servers on the Teams screen.

On the Teams plan, owning a team, the user opens Teams, views the team and
invites a colleague by e-mail as a member. The pending row shows when the
invitation expires; the owner resends it and copies its accept URL. They
make the colleague an admin; inviting the same address again is refused
with the service's own reason. Once the colleague accepts (in their browser,
a FakeCloud control here) the row turns active, and the owner removes them
after typing their address to confirm. Finally the owner shares one of
their servers with the team, and it joins the team's shared servers.

Every change goes through the service's team API, and the screen shows what
the service answers, so the journey checks both.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.fake_cloud.wire import expected
from e2e.harness.session_seed import seed_session

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

TEAM = "Example team"
OWNER_EMAIL = "owner@example.com"
COLLEAGUE_ID = 4243
COLLEAGUE = "colleague@example.com"
OWNER_ROW = [OWNER_EMAIL, "owner", "Active"]


def _seed(seed, fake_cloud) -> str:
    fake_cloud.configure(plan="teams", mcp_connections=0)
    fake_cloud.account.configure(teams=[])
    slug = fake_cloud.account.create_team(name=TEAM, owner_user_id=4242)["slug"]
    fake_cloud.add_user(COLLEAGUE_ID, email=COLLEAGUE, name="Colleague")
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)
    return slug


async def _open_team(t) -> None:
    await t.nav("nav_teams")
    await t.wait_for_screen("TeamManagementScreen")
    await t.wait_until(lambda: t.table_rows("#teams_table") == [[TEAM, "owner", "1"]], desc="team listed")
    await t.click("#btn_view_team")
    # The team's sections open below the teams table, out of view until scrolled to.
    await t.wait_until(lambda: _text(t, "#team_header") == f"Team: {TEAM}\nSeats: 1 / 5", desc="team header")


def _text(t, selector: str) -> str:
    """What a Static says, without its markup (it may be scrolled out of view)."""
    return str(t.on_screen(selector).visual)


async def _members(t, *rows: list[str]) -> None:
    wanted = [OWNER_ROW, *rows]
    await t.wait_until(lambda: t.table_rows("#members_table") == wanted, desc=f"members {wanted}")


async def _screen_idle(t) -> None:
    """Wait for the screen's own work (a change and the reload after it) to finish.

    The screen reloads the team after every change, which redraws the members
    table with its cursor back on the first row.
    """
    screen = t.screen
    await t.wait_until(
        lambda: not any(w.node is screen and not w.is_finished for w in t.app.workers),
        desc="team screen idle",
    )


async def _pick_member(t, row: int) -> None:
    """Move the members table's cursor to *row* with the keyboard."""
    await _screen_idle(t)
    table = t.on_screen("#members_table")
    if not table.has_focus:
        table.focus()  # as tabbing to it would
        await t.wait_until(lambda: table.has_focus, desc="members table focus")
    for _ in range(table.row_count + 1):
        if table.cursor_row == row:
            break
        await t.press("down" if table.cursor_row < row else "up")
    await t.wait_until(lambda: table.cursor_row == row, desc=f"cursor on member row {row}")


async def _press(t, selector: str) -> None:
    """Press a button from the keyboard (focus it, then enter).

    The action rows end at the right edge, where notifications stack up: a
    pointer click there can land on a toast instead.
    """
    button = await t.wait_for_widget(selector)
    assert t.is_reachable(button), f"{selector} is hidden"
    button.focus()
    await t.wait_until(lambda: button.has_focus, desc=f"focus on {selector}")
    await t.press("enter")


async def _choose(t, selector: str, label: str) -> None:
    """Pick the option labelled *label* in a dropdown the form focused, by keyboard."""
    from textual.widgets import OptionList, Select

    select = t.on_screen(selector, Select)
    await t.wait_until(lambda: select.has_focus, desc=f"{selector} focused")
    await t.press("enter")
    await t.wait_until(lambda: select.expanded, desc=f"{selector} open")
    overlay = select.query_one(OptionList)

    def highlighted() -> str:
        index = overlay.highlighted
        return "" if index is None else str(overlay.get_option_at_index(index).prompt)

    for _ in range(overlay.option_count + 1):
        if highlighted() == label:
            break
        await t.press("down")
        await t.settle(1)
    assert highlighted() == label, f"{label!r} is not offered by {selector}"
    await t.press("enter")
    await t.wait_until(lambda: not select.expanded and select.value is not None, desc=f"{selector} closed")


async def test_owner_invites_promotes_removes_and_shares(tui, seed, fake_cloud):
    slug = _seed(seed, fake_cloud)
    members = f"/api/v1/teams/{slug}/members"
    async with tui() as t:
        await _open_team(t)
        await _members(t)

        # Invite the colleague as a member.
        await _press(t, "#btn_invite")
        await t.fill("#input_invite_email", COLLEAGUE)
        await _press(t, "#btn_send_invite")
        await t.wait_for_toast(rf"^Invite sent to {COLLEAGUE}\.$", severity="information")
        await _members(t, [COLLEAGUE, "member", "Invited (expires in 6d)"])
        [invited] = fake_cloud.requests(members, "POST")
        assert invited["body"] == {"email": COLLEAGUE, "role": "member"} and invited["status"] == 201
        pending = fake_cloud.account.members(slug)[1]

        # Resend the invitation, then copy its accept URL.
        await _pick_member(t, 1)
        await _press(t, "#btn_resend")
        await t.wait_for_toast(rf"^Invite resent to {COLLEAGUE}\.$")
        assert [r["status"] for r in fake_cloud.requests(f"{members}/{pending['id']}/resend")] == [200]
        await _pick_member(t, 1)
        await _press(t, "#btn_copy_url")
        await t.wait_for_toast(rf"^Accept URL for {COLLEAGUE} copied to clipboard\.$")
        assert t.app.clipboard == f"{fake_cloud.url}{pending['accept_url']}"

        # Make the colleague an admin.
        await _pick_member(t, 1)
        await _press(t, "#btn_change_role")
        await t.wait_until(lambda: _text(t, "#change_role_header") == f"Change Role: {COLLEAGUE}",
                           desc="change-role form for the colleague")
        await _choose(t, "#select_change_role", "Admin")
        await _press(t, "#btn_save_role")
        await t.wait_for_toast(rf"^{COLLEAGUE} is now Admin\.$")
        await _members(t, [COLLEAGUE, "admin", "Invited (expires in 6d)"])

        # Inviting the same address again is refused with the service's reason.
        await _press(t, "#btn_invite")
        await t.fill("#input_invite_email", COLLEAGUE)
        await _press(t, "#btn_send_invite")
        await t.wait_for_toast(rf"^Failed to invite member: {COLLEAGUE} is already a member or invited\.$",
                               severity="error")
        await _press(t, "#btn_cancel_invite")

        # The colleague accepts in their browser; viewing the team again shows it.
        fake_cloud.accept_invitation(COLLEAGUE)
        await t.click("#btn_view_team")
        await _members(t, [COLLEAGUE, "admin", "Active"])
        await _pick_member(t, 1)
        await _press(t, "#btn_copy_url")
        await t.wait_for_toast(r"^This member has already accepted\.$", severity="warning")

        # Remove the colleague, confirming with their address.
        await _press(t, "#btn_remove")
        await t.wait_for_screen("ConfirmActionScreen")
        await t.fill("#confirm_input", COLLEAGUE)
        await t.click("#btn_confirm")
        await t.wait_for_toast(rf"^Removed {COLLEAGUE}\.$")
        await _members(t)
        assert [r["status"] for r in fake_cloud.requests(f"{members}/{pending['id']}", "DELETE")] == [200]
        assert fake_cloud.account.team_members(slug) == [
            {"user_id": 4242, "email": OWNER_EMAIL, "name": "Team owner", "role": "owner",
             "joined_at": fake_cloud.account.members(slug)[0]["accepted_at"]}
        ]

        # Share app-1 (the first server offered) with the team.
        servers_before = t.table_rows("#servers_table")
        await _press(t, "#btn_share")
        await t.wait_until(lambda: t.on_screen("#share_server_form").display, desc="share form open")
        await t.fill("#input_share_username", "deploy")
        await _press(t, "#btn_confirm_share")
        await t.wait_for_toast(rf"^Server '{fleet.APP_1.name}' shared with team\.$")
        await t.wait_until(
            lambda: t.table_rows("#servers_table") == [
                *servers_before, [fleet.APP_1.name, fleet.APP_1.private_ip, fleet.APP_1.region],
            ],
            desc="app-1 among the shared servers",
        )
        [shared] = [row for row in fake_cloud.account.shared_servers(slug) if row["name"] == fleet.APP_1.name]
        assert (shared["hostname"], shared["instance_id"], shared["username"]) == (
            fleet.APP_1.private_ip, fleet.APP_1.instance_id, "deploy",
        )

    fake_cloud.assert_no_unexpected_errors(
        *expected("no secret store on file"),
        ("POST", members, 409),
    )
