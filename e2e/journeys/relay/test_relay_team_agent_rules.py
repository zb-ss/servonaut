"""Journey: the hosted AI's tool calls relayed to a member's machine follow the team's rules.

A member of the team Ops runs ``servonaut connect``, with the dangerous AI
tools unlocked and the listener set to approve them without a prompt. The
hosted AI (on the web or in another session) sends tool calls for Ops's
server-1 to this machine. The listener runs them under Ops's rules: a
command matching a pattern Ops blocks is refused before anything reaches the
server, and the AI is told why; an allowed command runs. Every refusal is in
the audit trail with the reason ``team_rule``.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.bootstrap import Sandbox
from e2e.harness.relay_events import tool_call_event, wait_for_tool_result, wait_until_connected
from e2e.harness.session_seed import grant_dangerous_ai_tools, seed_session
from e2e.harness.team_agent_rules import (
    ENV_FILES,
    SERVER_1,
    SLUG,
    audit_rows,
    member_of_ops,
)

pytestmark = [pytest.mark.e2e_pr]

READ_ENV = "cat /srv/app/.env"
UPTIME = " 10:00:00 up 3 days\n"


def _member_home(journey, fake_cloud) -> Sandbox:
    """A member's home whose listener approves the dangerous AI tools without asking."""
    from e2e.harness.seed import HomeSeeder

    sandbox = journey.new_sandbox("relay-team-rules")
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
    relay = seeder.build_config().relay
    relay.ai_tool_auto_approve = "dangerous"
    seeder.config(relay=relay)
    seeder.cache(fleet.cache_rows(), fresh=True)
    grant_dangerous_ai_tools(seed_session(sandbox.home, fake_cloud))
    return sandbox


def test_relayed_tool_calls_run_under_the_team_rules(journey, fake_cloud, relay):
    member_of_ops(fake_cloud)
    fake_cloud.agent_rules.set_rules(SLUG, {"command_blocklist": [ENV_FILES]})
    journey.shims.when("ssh", r"server-1\.example\.com.*uptime", stdout=UPTIME)
    home = _member_home(journey, fake_cloud)
    listener = relay(home).start()
    user_id = wait_until_connected(fake_cloud, listener)

    def ask(tool_call_id: str, command: str) -> dict:
        fake_cloud.relay.publish(tool_call_event(
            tool_call_id, user_id, "run_command",
            {"instance_id": SERVER_1["name"], "command": command}, guard_level="dangerous",
        ), topic="ai-tool-calls")
        return wait_for_tool_result(fake_cloud, tool_call_id, listener)

    refused = ask("tc-env", READ_ENV)
    assert refused["status"] == "error", refused
    assert refused["result"] == (
        "Blocked: on team Ops's shared servers your agents run at the standard level "
        f"(set by the team), and '{READ_ENV}' is refused there: it matches the blocked "
        f"pattern {ENV_FILES}."
    )
    ran = ask("tc-uptime", "uptime")
    assert ran["status"] == "ok", ran
    assert "up 3 days" in ran["result"]

    [ssh] = journey.shims.calls("ssh")
    assert ssh.argv[-1].endswith("uptime")
    reasons = {row["tool_call_id"]: row["reason"] for row in audit_rows(home.home, "run_command")
               if row.get("source") == "ai_chat"}
    assert reasons["tc-env"] == "team_rule"
    assert listener.interrupt() in (0, 130)
    assert "Traceback" not in listener.output()
