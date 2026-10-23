"""Journey: a team owner manages members and shared servers on the Teams screen.

On the Teams plan, owning a team, the user opens Teams, views the team and
invites a colleague by e-mail as a member. The pending row shows when the
invitation expires; the owner resends it and copies its accept URL. They
make the colleague an admin; inviting the same address again is refused
with the service's own reason. Once the colleague accepts (in their browser,
a FakeCloud control here) the row turns active, and the owner removes them
after typing their address to confirm. Finally the owner shares one of
their servers with the team, and it joins the team's shared servers.

A second journey checks what leaves for the team only after the owner says
so. Share All lists every server it would share and sends nothing when the
owner backs out; shared again with one server ticked, only that one goes.
Pushing the config offers each custom server unticked and lists the
connection profiles that go with it; the push carries the one server the
owner ticked, and pulling it back applies cleanly.

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


def _seed(seed, fake_cloud, **config) -> str:
    fake_cloud.configure(plan="teams", mcp_connections=0)
    fake_cloud.account.configure(teams=[])
    slug = fake_cloud.account.create_team(name=TEAM, owner_user_id=4242)["slug"]
    fake_cloud.add_user(COLLEAGUE_ID, email=COLLEAGUE, name="Colleague")
    seed.config(**config)
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


TEAM_BOX = ("team-box", "10.0.5.1")
PRIVATE_BOX = ("private-box", "10.0.5.2")


def _aligned(rows) -> list[str]:
    """Rows as the lists show them: names padded to the longest, then the address."""
    width = max(len(name) for name, _address in rows)
    return [f"{name.ljust(width)}  {address}" for name, address in rows]


def _labels(listing) -> list[str]:
    return [str(listing.get_option_at_index(i).prompt) for i in range(listing.option_count)]


async def test_servers_leave_for_the_team_only_when_the_owner_confirms(tui, seed, fake_cloud):
    from servonaut.config.schema import ConnectionProfile, CustomServer

    slug = _seed(
        seed, fake_cloud,
        custom_servers=[
            CustomServer(name=TEAM_BOX[0], host=TEAM_BOX[1], username="deploy", ssh_key="~/.ssh/team_box"),
            CustomServer(name=PRIVATE_BOX[0], host=PRIVATE_BOX[1]),
        ],
        connection_profiles=[
            ConnectionProfile(name=fleet.BASTION_PROFILE, bastion_host=fleet.BASTION_1.public_ip,
                              bastion_user=fleet.BASTION_USER),
        ],
    )
    servers_url = f"/api/v1/teams/{slug}/servers"
    configs_url = f"/api/v1/teams/{slug}/configs"
    servers = [
        (fleet.APP_1.name, fleet.APP_1.private_ip),
        (fleet.DB_1.name, fleet.DB_1.private_ip),
        (fleet.BASTION_1.name, fleet.BASTION_1.public_ip),
        (fleet.EDGE_1.name, fleet.EDGE_1.public_ip),
        TEAM_BOX,
        PRIVATE_BOX,
    ]
    offered = _aligned(servers)
    async with tui() as t:
        await _open_team(t)
        await _screen_idle(t)

        # Share All lists every server it would share; backing out sends nothing.
        await _press(t, "#btn_share_all")
        await t.wait_for_screen("ShareServersConfirmModal")
        listing = t.on_screen("#share_confirm_list")
        await t.wait_until(lambda: _labels(listing) == offered, desc="every server offered")
        assert sorted(listing.selected) == list(range(len(offered)))
        assert _text(t, "#share_confirm_title") == f"Share servers with {TEAM}?"
        # The team's own shared server is in the list too, and is not offered again.
        assert _text(t, "#share_confirm_skipped") == "Not listed: 1 server already shared."
        await t.wait_until(lambda: t.focused_id() == "share_confirm_cancel", desc="Cancel focused")
        await t.press("escape")
        await t.wait_for_screen("TeamManagementScreen")
        await t.settle()
        assert fake_cloud.requests(servers_url, "POST") == []

        # Shared again with only the first server ticked: only that one goes.
        await _press(t, "#btn_share_all")
        await t.wait_for_screen("ShareServersConfirmModal")
        listing = t.on_screen("#share_confirm_list")
        await t.wait_until(lambda: listing.option_count == len(offered), desc="servers offered again")
        await _press(t, "#share_confirm_none")
        await t.press("tab")
        await t.wait_until(lambda: t.focused_id() == "share_confirm_list", desc="list focused")
        await t.press("space")
        share = t.on_screen("#share_confirm_share")
        await t.wait_until(lambda: str(share.label) == "Share 1 server", desc="one server ticked")
        await _press(t, "#share_confirm_share")
        await t.wait_for_toast(
            rf"^Share All: Shared 1, left out {len(offered) - 1}, skipped 1 already shared\.$"
        )
        [posted] = fake_cloud.requests(servers_url, "POST")
        assert (posted["body"]["name"], posted["body"]["hostname"]) == (fleet.APP_1.name, fleet.APP_1.private_ip)
        await _screen_idle(t)

        # Push config: every custom server offered unticked, the profiles listed.
        await _press(t, "#btn_push_config")
        picker = t.on_screen("#push_config_servers")
        await t.wait_until(lambda: picker.has_focus, desc="custom-server picker focused")
        # The whole form is brought into view, down to its Push button.
        viewport = t.on_screen("#team_management_container").region
        push = t.on_screen("#btn_confirm_push_config")
        await t.wait_until(
            lambda: viewport.y <= t.on_screen("#push_config_form").region.y
            and push.region.height and push.region.bottom <= viewport.bottom,
            desc="push form in view",
        )
        assert _labels(picker) == _aligned([TEAM_BOX, PRIVATE_BOX])
        assert picker.selected == []
        assert _text(t, "#push_config_profiles") == (
            "Connection profiles — all of them are shared\n"
            f"  • {fleet.BASTION_PROFILE}  bastion {fleet.BASTION_USER}@{fleet.BASTION_1.public_ip}"
        )
        await t.press("space")
        await t.wait_until(
            lambda: _text(t, "#push_config_preview").startswith("Will share: 1 of 2 custom servers,"),
            desc="preview counts the ticked server",
        )
        await t.fill("#input_push_description", "Team box only")
        await _press(t, "#btn_confirm_push_config")
        await t.wait_for_toast(r"^Pushed config version 1\.$")
        [pushed] = fake_cloud.requests(configs_url, "POST")
        sent = pushed["body"]["config_data"]
        assert [(s["name"], s["host"], s["ssh_key"]) for s in sent["custom_servers"]] == [(*TEAM_BOX, "")]
        assert [p["name"] for p in sent["connection_profiles"]] == [fleet.BASTION_PROFILE]
        await _screen_idle(t)

        # Pulling the partial push back applies cleanly.
        await _press(t, "#btn_pull_config")
        await t.wait_until(lambda: "Custom Servers: 2 → 1" in _text(t, "#pull_config_preview"),
                           desc="pull preview")
        await _press(t, "#btn_confirm_pull_config")
        await t.wait_for_toast(r"^Team config applied\.")
        saved = seed.read_config()
        assert [(s["name"], s["host"], s["ssh_key"]) for s in saved["custom_servers"]] == [(*TEAM_BOX, "")]
        assert [p["name"] for p in saved["connection_profiles"]] == [fleet.BASTION_PROFILE]

    fake_cloud.assert_no_unexpected_errors(*expected("no secret store on file"))
