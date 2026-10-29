"""Self-tests for several people and managed teams in FakeCloud.

Team journeys prove what a member or an owner can do, which only means
something if the fake keeps people and roles apart the way the service does:

* an added user's token is answered for that user (entitlements, ``/me``,
  refresh, sign-out), while the scenario's account behaves exactly as before;
* a device-flow sign-in completes as an added user only when one was named;
* a managed team follows the rules the CLI documents, through the product's
  own ``TeamService``: invitations with an accept URL, resend, role changes,
  removal, shared servers, and the refusals (status and code) for what an
  owner, admin or member may not do;
* accepting an invitation makes the user a member who sees the team through
  their own role.
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from e2e.harness.fake_cloud.state import ACCESS_TOKEN

pytestmark = [pytest.mark.e2e_pr]

OWNER_ID = 4242
MEMBER_ID = 4243
MEMBER_EMAIL = "member@example.com"
SECOND_ID = 4244
SECOND_EMAIL = "second@example.com"


def _client(fake_cloud) -> httpx.Client:
    return httpx.Client(base_url=fake_cloud.url, timeout=10)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _teams_as(token: str):
    """The product's TeamService, signed in with *token*."""
    from servonaut.services.api_client import APIClient
    from servonaut.services.team_service import TeamService

    async def no_refresh() -> bool:
        return False

    return TeamService(APIClient(SimpleNamespace(access_token=token, refresh_token=no_refresh)))


def test_an_added_user_is_answered_as_themselves(fake_cloud):
    default_access, _ = fake_cloud.tokens()
    before = fake_cloud.entitlements()
    fake_cloud.add_user(MEMBER_ID, email=MEMBER_EMAIL, name="Member")
    member_access, member_refresh = fake_cloud.user_tokens(MEMBER_ID)
    assert member_access.startswith(ACCESS_TOKEN) and member_access != default_access

    with _client(fake_cloud) as client:
        mine = client.get("/api/entitlements", headers=_bearer(default_access)).json()
        theirs = client.get("/api/entitlements", headers=_bearer(member_access)).json()
        assert mine == before == fake_cloud.entitlements()
        assert (mine["user_id"], mine["email"]) == (OWNER_ID, "")
        assert (theirs["user_id"], theirs["plan"], theirs["email"]) == (MEMBER_ID, "teams", MEMBER_EMAIL)
        assert theirs == fake_cloud.entitlements(MEMBER_ID)
        assert client.get("/api/v1/me", headers=_bearer(member_access)).json() == {"user_id": MEMBER_ID}
        assert client.get("/api/v1/me", headers=_bearer(default_access)).json() == {"user_id": OWNER_ID}

        # Refresh rotates the added user's own pair; signing out ends only theirs.
        rotated = client.post("/api/oauth/refresh", json={"refresh_token": member_refresh}).json()
        assert rotated["user_id"] == MEMBER_ID and rotated["access_token"] == fake_cloud.user_tokens(MEMBER_ID)[0]
        assert client.get("/api/v1/me", headers=_bearer(member_access)).status_code == 401
        client.post("/api/oauth/revoke", json={"token": rotated["access_token"]})
        assert client.get("/api/v1/me", headers=_bearer(rotated["access_token"])).status_code == 401
        assert client.get("/api/v1/me", headers=_bearer(default_access)).status_code == 200

    # The request log names the added user of each request a current token made.
    me = fake_cloud.requests("/api/v1/me")
    assert [(entry.get("user_id"), entry["status"]) for entry in me] == [
        (MEMBER_ID, 200), (None, 200), (None, 401), (None, 401), (None, 200),
    ]
    with pytest.raises(ValueError):
        fake_cloud.add_user(OWNER_ID, email="again@example.com")


def test_a_device_sign_in_completes_as_the_user_who_approved_it(fake_cloud):
    fake_cloud.add_user(MEMBER_ID, email=MEMBER_EMAIL)
    with _client(fake_cloud) as client:
        def sign_in() -> dict:
            code = client.post("/api/oauth/device", json={}).json()["device_code"]
            return client.post("/api/oauth/token", json={"device_code": code}).json()

        assert sign_in()["user_id"] == OWNER_ID
        fake_cloud.sign_in_next_as(MEMBER_ID)
        member = sign_in()
        assert (member["user_id"], member["plan"], member["email"]) == (MEMBER_ID, "teams", MEMBER_EMAIL)
        assert member["access_token"] == fake_cloud.user_tokens(MEMBER_ID)[0]
        # Only the next sign-in was the member's.
        assert sign_in()["user_id"] == OWNER_ID
    with pytest.raises(KeyError):
        fake_cloud.sign_in_next_as(SECOND_ID)


@pytest.mark.asyncio
async def test_a_managed_team_follows_the_documented_member_rules(fake_cloud):
    from servonaut.services.api_client import APIError

    fake_cloud.add_user(MEMBER_ID, email=MEMBER_EMAIL, name="Member")
    fake_cloud.add_user(SECOND_ID, email=SECOND_EMAIL, name="Second")
    fake_cloud.account.configure(teams=[])  # no scenario rows beside the managed team
    created = fake_cloud.account.create_team(name="Example team", owner_user_id=OWNER_ID, max_seats=3)
    slug = created["slug"]
    owner = _teams_as(fake_cloud.tokens()[0])
    member = _teams_as(fake_cloud.user_tokens(MEMBER_ID)[0])
    second = _teams_as(fake_cloud.user_tokens(SECOND_ID)[0])

    assert await owner.list_teams() == [
        {"id": created["id"], "slug": slug, "name": "Example team", "role": "owner", "member_count": 1}
    ]
    assert await member.list_teams() == []

    invited = await owner.invite_member(slug, MEMBER_EMAIL, "member")
    assert invited["email_sent"] is True and invited["is_accepted"] is False
    assert invited["accept_url"].startswith(f"{fake_cloud.url}/invite/")
    detail = await owner.get_team(slug)
    assert (detail["role"], detail["max_seats"]) == ("owner", 3)
    assert [(m["invitation_email"], m["role"], m["is_accepted"]) for m in detail["members"]] == [
        ("owner@example.com", "owner", True), (MEMBER_EMAIL, "member", False),
    ]
    pending = detail["members"][1]
    assert pending["accept_url"] == invited["accept_url"] and pending["invitation_expires_at"]
    resent = await owner.resend_invite(slug, str(pending["id"]))
    assert resent["accept_url"] == invited["accept_url"] and resent["email_sent"] is True

    async def refused(call, status: int, code: str) -> None:
        with pytest.raises(APIError) as caught:
            await call
        assert (caught.value.status, caught.value.code) == (status, code), caught.value.message

    await refused(owner.invite_member(slug, "owner2@example.com", "owner"), 400, "invalid_role")
    await refused(owner.invite_member(slug, "not-an-address", "member"), 400, "invalid_email")
    await refused(owner.invite_member(slug, MEMBER_EMAIL, "viewer"), 409, "already_member")
    await refused(owner.update_role(slug, "999", "viewer"), 404, "not_found")
    await refused(owner.get_team("no-such-team"), 404, "not_found")
    await refused(member.invite_member(slug, SECOND_EMAIL, "member"), 404, "not_found")
    owner_row = detail["members"][0]
    await refused(owner.update_role(slug, str(owner_row["id"]), "admin"), 400, "owner_role_immutable")
    await refused(owner.remove_member(slug, str(owner_row["id"])), 400, "owner_not_removable")

    # Accepting (the browser step) makes the invitee a member, in their own role.
    accepted = fake_cloud.accept_invitation(MEMBER_EMAIL)
    assert (accepted["team"], accepted["is_accepted"], accepted["user"]["id"]) == (slug, True, MEMBER_ID)
    assert [t["role"] for t in await member.list_teams()] == ["member"]
    as_member = await member.get_team(slug)
    assert as_member["role"] == "member"
    await refused(member.invite_member(slug, SECOND_EMAIL, "member"), 403, "forbidden")
    await refused(member.push_server(slug, {"name": "x", "hostname": "10.0.0.9"}), 403, "forbidden")
    with pytest.raises(KeyError):
        fake_cloud.accept_invitation(MEMBER_EMAIL)

    # An admin manages members, but only the owner makes or demotes admins.
    await owner.update_role(slug, str(pending["id"]), "admin")
    admin = member
    await refused(admin.invite_member(slug, SECOND_EMAIL, "admin"), 403, "forbidden")
    second_invite = await admin.invite_member(slug, SECOND_EMAIL, "viewer")
    hidden = await second.list_teams()
    assert hidden == []
    await refused(admin.update_role(slug, str(pending["id"]), "member"), 403, "forbidden")
    fake_cloud.accept_invitation(SECOND_EMAIL)
    viewer_view = await second.get_team(slug)
    assert all("accept_url" not in row for row in viewer_view["members"])
    await refused(owner.invite_member(slug, "fourth@example.com", "member"), 422, "seat_limit_reached")

    # Shared servers: managers add and remove the canonical record by id.
    shared = await admin.push_server(slug, {"name": "web-9", "hostname": "10.0.0.9", "port": 2222})
    assert (shared["name"], shared["hostname"], shared["port"]) == ("web-9", "10.0.0.9", 2222)
    assert "web-9" in [row["name"] for row in await second.list_shared_servers(slug)]
    await refused(owner.push_server(slug, {"name": "web-10", "hostname": "10.0.0.9", "port": 2222}), 409, "already_shared")
    await refused(owner.push_server(slug, {"name": "web-10"}), 422, "validation_failed")
    await refused(owner.remove_shared_server(slug, "web-9"), 404, "not_found")
    await owner.remove_shared_server(slug, shared["id"])
    await refused(owner.remove_shared_server(slug, shared["id"]), 404, "not_found")

    # Removing a member takes the team away from them.
    await owner.remove_member(slug, str(second_invite["id"]))
    assert await second.list_teams() == []
    await refused(second.get_team(slug), 404, "not_found")

    # A team without seats (no Teams subscription) refuses invitations with 402.
    lapsed = fake_cloud.account.create_team(name="Lapsed", owner_user_id=SECOND_ID, max_seats=0)
    await refused(second.invite_member(lapsed["slug"], "x@example.com", "member"), 402, "subscription_inactive")


@pytest.mark.asyncio
async def test_creating_a_team_needs_the_teams_plan_and_no_owned_team(fake_cloud):
    from servonaut.services.api_client import APIError

    fake_cloud.add_user(MEMBER_ID, email=MEMBER_EMAIL, plan="solo")
    fake_cloud.add_user(SECOND_ID, email=SECOND_EMAIL)
    with pytest.raises(APIError) as solo:
        await _teams_as(fake_cloud.user_tokens(MEMBER_ID)[0]).create_team("Mine")
    assert (solo.value.status, solo.value.code) == (403, "forbidden")

    creator = _teams_as(fake_cloud.user_tokens(SECOND_ID)[0])
    made = await creator.create_team("Second Team")
    assert (made["slug"], made["role"], made["member_count"]) == ("second-team", "owner", 1)
    detail = await creator.get_team("second-team")
    assert [(m["invitation_email"], m["role"]) for m in detail["members"]] == [(SECOND_EMAIL, "owner")]
    with pytest.raises(APIError) as again:
        await creator.create_team("Another")
    assert again.value.status == 403 and "already own" in again.value.message
