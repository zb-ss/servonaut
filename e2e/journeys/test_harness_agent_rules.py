"""Self-tests for the team agent rules in FakeCloud.

The agent-rules journeys prove what a member's Servonaut does with what the
service sends, which only means something if the fake sends what the service
does. Each answer is checked with the product's own verifier
(``TeamPolicyStore.apply_response``):

* a member reads the signed format 1 defaults at version 0 from both policy
  routes; a non-member gets 404, a request without a token 401;
* a save follows the service's rules: owners and admins only, merging and
  replacing as documented, invalid input refused with an ``errors`` map,
  ``dangerous`` and the owner's own level for the owner alone, the signed
  rules the effective ones, and a version that rises with every change of
  the signed rules and never goes down;
* each way of serving (unsigned, tampered with, an untrusted key,
  unavailable, a replayed copy) is what the product refuses, for the reason
  that way stands for.
"""

from __future__ import annotations

import json
import time

import httpx
import pytest

from e2e.harness.fake_cloud import routes_agent_rules as fake
from e2e.harness.team_agent_rules import (
    ADMIN_ID,
    ENV_FILES,
    OWNER_ID,
    SERVER_1,
    SLUG,
    TEAM_ID,
    member_of_ops,
    ops_with_people,
    save_policy,
)

pytestmark = [pytest.mark.e2e_pr]

OUTSIDER_ID = 4399


def _get(fake_cloud, path: str = f"/api/v1/teams/{SLUG}/policy", token=None) -> httpx.Response:
    if token is None:
        token, _ = fake_cloud.tokens()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    with httpx.Client(base_url=fake_cloud.url, timeout=10) as client:
        return client.get(path, headers=headers)


def _store(journey, name: str = "verifier"):
    """A fresh product verifier, its state file inside the journey's directory."""
    from servonaut.services.team_policy import TeamPolicyStore

    return TeamPolicyStore(journey.directory / name / "team_policy.json")


def _verified(store, response: httpx.Response):
    """What the product makes of *response* (a GET of Ops's policy)."""
    return store.apply_response(
        {"slug": SLUG, "id": TEAM_ID}, response.json(), server_date=response.headers.get("Date"),
    )


def _signed_rules(fake_cloud) -> dict:
    """The effective rules Ops's policy carries now, once the product verified them."""
    from servonaut.services.team_policy import current_api_origin, verify_envelope

    response = _get(fake_cloud)
    assert response.status_code == 200
    policy = verify_envelope(
        response.json()["data"]["agent_rules_signed"], origin=current_api_origin(), team_id=TEAM_ID,
    )
    return json.loads(policy.canonical_rules)


def test_a_member_reads_the_signed_defaults(fake_cloud, journey):
    from servonaut.services.team_policy import format_1_default_agent_rules

    # Format 1 fixes the defaults: the fake serves the product's own.
    assert fake.default_agent_rules() == format_1_default_agent_rules()
    member_of_ops(fake_cloud)
    fake_cloud.add_user(OUTSIDER_ID, email="outsider@example.com")
    for path in (f"/api/v1/teams/{SLUG}/policy", f"/api/v1/teams/{SLUG}/mcp-policy"):
        response = _get(fake_cloud, path)
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["agent_rules"] is None and data["agent_rules_version"] == 0
        status = _verified(_store(journey, path.rsplit("/", 1)[-1]), response)
        assert status.problem is None and status.version == 0
        assert status.rules.role_levels == fake.default_agent_rules()["role_levels"]

    outsider, _ = fake_cloud.user_tokens(OUTSIDER_ID)
    assert _get(fake_cloud, token=outsider).status_code == 404
    assert _get(fake_cloud, token="").status_code == 401
    assert [row["version"] for row in fake_cloud.agent_rules.served(SLUG)] == [0, 0]


def test_only_owners_and_admins_save_and_admins_cannot_touch_the_owner(fake_cloud):
    ops_with_people(fake_cloud)
    access, _ = fake_cloud.tokens()
    with httpx.Client(base_url=fake_cloud.url, timeout=10) as client:
        refused = client.put(
            f"/api/v1/teams/{SLUG}/mcp-policy", json={"agent_rules": {}},
            headers={"Authorization": f"Bearer {access}"},
        )
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "forbidden"

    before = int(time.time() * 1000)
    saved = save_policy(fake_cloud, {"agent_rules": {"role_levels": {"member": "readonly"}}}, user_id=ADMIN_ID)
    assert saved.status_code == 200
    version = fake_cloud.agent_rules.version(SLUG)
    assert version >= before and saved.json()["data"]["agent_rules_version"] == version
    assert saved.json()["data"]["agent_rules"] == {"role_levels": {"member": "readonly"}}
    assert _signed_rules(fake_cloud)["role_levels"] == {
        "owner": "standard", "admin": "standard", "member": "readonly", "viewer": "readonly",
    }

    # Saving what is already in force changes nothing, so the version stays.
    assert save_policy(fake_cloud, {"agent_rules": {"role_levels": {"viewer": "readonly"}}},
                       user_id=ADMIN_ID).status_code == 200
    assert fake_cloud.agent_rules.version(SLUG) == version

    for body in (
        {"agent_rules": {"role_levels": {"owner": "readonly"}}},
        {"agent_rules": {"servers": {SERVER_1["id"]: {"role_levels": {"owner": "readonly"}}}}},
        {"agent_rules": {"role_levels": {"admin": "dangerous"}}},
        {"allow_dangerous_ai_tools": True},
    ):
        answer = save_policy(fake_cloud, body, user_id=ADMIN_ID)
        assert answer.status_code == 403, body
        assert answer.json()["error"]["code"] == "forbidden"
    assert fake_cloud.agent_rules.version(SLUG) == version

    # The owner changes their own level too; an admin may then save it unchanged.
    assert save_policy(fake_cloud, {"agent_rules": {"role_levels": {"owner": "readonly"}}},
                       user_id=OWNER_ID).status_code == 200
    assert save_policy(fake_cloud, {"agent_rules": {"role_levels": {"owner": "readonly", "admin": "readonly"}}},
                       user_id=ADMIN_ID).status_code == 200
    assert fake_cloud.agent_rules.version(SLUG) > version


def test_saves_merge_replace_and_reset_and_refuse_what_is_invalid(fake_cloud):
    ops_with_people(fake_cloud)
    server = SERVER_1["id"]
    assert save_policy(fake_cloud, {"agent_rules": {
        "servers": {server: {"role_levels": {"member": "readonly"}}},
        "command_allowlist": ["uptime", "df"],
        "command_blocklist": [ENV_FILES],
    }}, user_id=ADMIN_ID).status_code == 200
    assert save_policy(fake_cloud, {"agent_rules": {"role_levels": {"viewer": "readonly"},
                                                    "command_allowlist": ["uptime"]}},
                       user_id=ADMIN_ID).status_code == 200
    rules = _signed_rules(fake_cloud)
    assert rules["servers"] == {server: {"role_levels": {"member": "readonly"}}}
    assert rules["command_allowlist"] == ["uptime"] and rules["command_blocklist"] == [ENV_FILES]

    invalid = {
        "agent_rules.colour": {"agent_rules": {"colour": "blue"}},
        "agent_rules.role_levels.guest": {"agent_rules": {"role_levels": {"guest": "readonly"}}},
        "agent_rules.role_levels.member": {"agent_rules": {"role_levels": {"member": "root"}}},
        "agent_rules.servers.srv-404": {"agent_rules": {"servers": {"srv-404": {"role_levels": {}}}}},
        "agent_rules.command_allowlist": {"agent_rules": {"command_allowlist": ["ls -la"]}},
        "agent_rules.command_blocklist": {"agent_rules": {"command_blocklist": [""]}},
        "max_sessions": {"max_sessions": 3},
    }
    version = fake_cloud.agent_rules.version(SLUG)
    for field, body in invalid.items():
        answer = save_policy(fake_cloud, body, user_id=ADMIN_ID)
        assert answer.status_code == 400, body
        assert field in answer.json()["errors"], answer.json()
    assert fake_cloud.agent_rules.version(SLUG) == version

    # A key set to null goes back to its default; agent_rules null resets them all.
    assert save_policy(fake_cloud, {"agent_rules": {"command_allowlist": None}},
                       user_id=ADMIN_ID).status_code == 200
    assert _signed_rules(fake_cloud)["command_allowlist"] is None
    assert save_policy(fake_cloud, {"agent_rules": None}, user_id=ADMIN_ID).status_code == 200
    assert _signed_rules(fake_cloud) == fake.default_agent_rules()
    # Back to the defaults, yet never back to version 0.
    assert fake_cloud.agent_rules.version(SLUG) > version


def test_only_the_owner_sets_dangerous_and_only_while_it_is_allowed(fake_cloud):
    ops_with_people(fake_cloud)
    dangerous_admins = {"agent_rules": {"role_levels": {"admin": "dangerous"}}}
    refused = save_policy(fake_cloud, dangerous_admins, user_id=OWNER_ID)
    assert refused.status_code == 400 and "agent_rules" in refused.json()["errors"]

    allowed = {"allow_dangerous_ai_tools": True, **dangerous_admins}
    assert save_policy(fake_cloud, allowed, user_id=OWNER_ID).status_code == 200
    assert _signed_rules(fake_cloud)["role_levels"]["admin"] == "dangerous"
    version = fake_cloud.agent_rules.version(SLUG)
    # What is already dangerous an admin may save unchanged (a load-and-save round trip).
    assert save_policy(fake_cloud, dangerous_admins, user_id=ADMIN_ID).status_code == 200

    # Switching dangerous tools off lowers the signed level, as a new version.
    assert save_policy(fake_cloud, {"allow_dangerous_ai_tools": False}, user_id=OWNER_ID).status_code == 200
    assert _signed_rules(fake_cloud)["role_levels"]["admin"] == "standard"
    assert fake_cloud.agent_rules.version(SLUG) > version


@pytest.mark.parametrize(
    ("how", "problem"),
    [
        (fake.SIGNED, None),
        (fake.UNSIGNED, "missing"),
        (fake.TAMPERED, "bad_signature"),
        (fake.UNKNOWN_KEY, "unknown_key"),
    ],
)
def test_each_way_of_serving_is_refused_for_its_own_reason(fake_cloud, journey, how, problem):
    member_of_ops(fake_cloud)
    fake_cloud.agent_rules.set_rules(SLUG, {"command_blocklist": [ENV_FILES]})
    fake_cloud.agent_rules.serve(SLUG, how)
    response = _get(fake_cloud)
    assert response.status_code == 200
    status = _verified(_store(journey), response)
    assert (status.problem.code if status.problem else None) == problem
    assert fake_cloud.agent_rules.served(SLUG) == [{"version": 1, "serving": how, "status": 200}]


def test_an_unavailable_policy_answers_503(fake_cloud):
    member_of_ops(fake_cloud)
    fake_cloud.agent_rules.serve(SLUG, fake.UNAVAILABLE)
    assert _get(fake_cloud).status_code == 503
    assert fake_cloud.agent_rules.served(SLUG) == [{"version": None, "serving": fake.UNAVAILABLE, "status": 503}]


def test_a_replay_serves_an_earlier_copy_unchanged(fake_cloud, journey):
    member_of_ops(fake_cloud)
    store = _store(journey)
    fake_cloud.agent_rules.set_rules(SLUG, None, version=1)
    first = _get(fake_cloud)
    assert _verified(store, first).problem is None
    fake_cloud.agent_rules.set_rules(SLUG, {"command_blocklist": [ENV_FILES]})
    assert _verified(store, _get(fake_cloud)).version == 2

    fake_cloud.agent_rules.replay(SLUG, 1)
    replayed = _get(fake_cloud)
    assert replayed.json()["data"]["agent_rules_signed"] == first.json()["data"]["agent_rules_signed"]
    assert _verified(store, replayed).problem.code == "replayed"
    with pytest.raises(KeyError):
        fake_cloud.agent_rules.replay(SLUG, 7)
