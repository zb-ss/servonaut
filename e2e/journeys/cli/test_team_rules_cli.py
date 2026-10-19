"""Journey: ``servonaut team rules`` shows what a team lets agents do, from the command line.

Signed in as a member of the team Ops, ``servonaut team rules ops`` fetches
Ops's signed rules, checks them and prints what applies on this machine now:
the level of each role and of the user's own, a server with its own levels,
the command lists, and the version. ``--json`` gives the same as data, and
the team can be named by its name too. When the service sends no signed
rules, the command prints the readonly fallback and why, and still exits 0:
that is what applies. A team the user is not in exits 1.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness.fake_cloud import routes_agent_rules as served
from e2e.harness.team_agent_rules import ENV_FILES, SERVER_1, SLUG, member_of_ops

pytestmark = [pytest.mark.e2e_pr]

RULES = {
    "servers": {SERVER_1["id"]: {"role_levels": {"member": "readonly"}}},
    "command_blocklist": [ENV_FILES],
}


def test_team_rules_from_the_command_line(fake_cloud, cli, account_home):
    member_of_ops(fake_cloud)
    fake_cloud.agent_rules.set_rules(SLUG, RULES, version=3)
    home = account_home("cli-team-rules")

    shown = cli(home, "team", "rules", SLUG)
    assert shown.returncode == 0, shown.describe()
    lines = shown.stdout.splitlines()
    assert lines[0] == f"What agents may do here (team {SLUG})"
    assert "Owner: standard · Admin: standard · Member: standard · Viewer: readonly" in lines
    assert "Your role: member (standard)" in lines
    assert "  server-1: Member readonly" in lines
    assert "Allowed commands at the standard level: Servonaut's built-in list" in lines
    assert f"Blocked patterns the team adds to Servonaut's own: {ENV_FILES}" in lines
    assert lines[-1].startswith("Version 3 · last refreshed ")

    as_json = cli(home, "team", "rules", "Ops", "--json")
    assert as_json.returncode == 0, as_json.describe()
    view = json.loads(as_json.stdout)
    assert (view["team"], view["in_force"], view["version"], view["your_level"]) == (SLUG, True, 3, "standard")
    assert view["servers"] == [
        {"id": SERVER_1["id"], "name": "server-1", "role_levels": {"member": "readonly"}},
    ]
    assert view["command_allowlist"] is None and view["command_blocklist"] == [ENV_FILES]

    fake_cloud.agent_rules.serve(SLUG, served.UNSIGNED)
    fallback = cli(home, "team", "rules", SLUG)
    assert fallback.returncode == 0, fallback.describe()
    assert fallback.stdout.splitlines()[1] == (
        "Agents run at the readonly level on this team's shared servers, owners "
        "included, because the team service sent no signed agent rules."
    )

    other = cli(home, "team", "rules", "dev-team")
    assert other.returncode == 1
    assert "You are not in a team called dev-team." in other.stderr
