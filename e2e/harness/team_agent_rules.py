"""Teams with agent rules, for journeys: who is in them, and saves as the website makes them.

:func:`member_of_ops` makes the scenario's account a member of the team Ops
(a scenario row) that shares ``server-1``; :func:`ops_with_people` builds the
same team with people in it (an owner and an admin beside the account, a
member), for journeys where someone else changes the rules.
:func:`save_policy` saves a team's policy the way the website's Policies tab
does: ``PUT /api/v1/teams/{slug}/mcp-policy`` as that person. The rules a
team saved earlier, and how FakeCloud serves them, are set on
``fake_cloud.agent_rules`` (see ``routes_agent_rules.py``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

SLUG = "ops"
TEAM_ID = "team-ops"
TEAM_NAME = "Ops"
SERVER_1 = {
    "id": "srv-1", "name": "server-1", "hostname": "server-1.example.com", "port": 22,
    "login_user": "deploy", "username": "deploy", "status": "active",
}
# How an agent names server-1 through the team.
SERVER_1_REF = f"{SLUG}/{SERVER_1['name']}"
OWNER_ID = 4301
OWNER_EMAIL = "owner@example.com"
ADMIN_ID = 4302
ADMIN_EMAIL = "admin@example.com"
MEMBER_EMAIL = "member@example.com"
# The pattern Ops's rules add to the built-in blocklist: no agent reads an app's .env.
ENV_FILES = r"\.env\b"


def member_of_ops(fake_cloud: Any, *, role: str = "member") -> None:
    """The account is in the team Ops with *role*; Ops shares server-1."""
    fake_cloud.configure(plan="teams")
    fake_cloud.account.configure(
        teams=[{"id": TEAM_ID, "slug": SLUG, "name": TEAM_NAME, "role": role, "member_count": 2}],
        shared_servers={SLUG: [dict(SERVER_1)]},
    )


def ops_with_people(fake_cloud: Any) -> None:
    """Ops with an owner and an admin (added users) and the account as a member."""
    fake_cloud.configure(plan="teams")
    fake_cloud.account.configure(teams=[], shared_servers={SLUG: [dict(SERVER_1)]})
    fake_cloud.add_user(OWNER_ID, email=OWNER_EMAIL, name="Team owner")
    fake_cloud.add_user(ADMIN_ID, email=ADMIN_EMAIL, name="Team admin")
    fake_cloud.account.create_team(
        name=TEAM_NAME, slug=SLUG, team_id=TEAM_ID, owner_user_id=OWNER_ID,
        owner_email=OWNER_EMAIL, owner_name="Team owner",
    )
    fake_cloud.account.join_team(SLUG, user_id=ADMIN_ID, role="admin", email=ADMIN_EMAIL)
    account = fake_cloud.entitlements()["user_id"]
    fake_cloud.account.join_team(SLUG, user_id=account, role="member", email=MEMBER_EMAIL)


def save_policy(fake_cloud: Any, body: dict[str, Any], *, user_id: int, slug: str = SLUG) -> httpx.Response:
    """Save *body* as team *slug*'s policy, as the added user *user_id* on the website."""
    access, _ = fake_cloud.user_tokens(user_id)
    with httpx.Client(base_url=fake_cloud.url, timeout=10) as client:
        return client.put(
            f"/api/v1/teams/{slug}/mcp-policy", json=body,
            headers={"Authorization": f"Bearer {access}"},
        )


def audit_rows(home: Path, tool: str) -> list[dict[str, Any]]:
    """The MCP audit rows of *tool* in *home*, oldest first."""
    path = home / ".servonaut" / "mcp_audit.jsonl"
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return [row for row in rows if row.get("tool") == tool]
