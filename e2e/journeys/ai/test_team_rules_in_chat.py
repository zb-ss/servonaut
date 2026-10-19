"""Journey: a team's agent rules bind the AI chat, whichever model is behind it.

Signed in as a member of the team Ops, the user chats with their own model
(a local Ollama). When the model asks to run commands on Ops's server-1, the
tools run under Ops's rules: the command matching a pattern Ops blocks is
refused before anything reaches the server, and the model is told why; the
allowed one runs. The rules live in Servonaut's tools, not in the model, so
the provider makes no difference.
"""

from __future__ import annotations

import pytest

from e2e.harness.ai_chat import open_chat, seed_byo, send, wait_for_reply
from e2e.harness.fake_ai import reply, tool_call
from e2e.harness.team_agent_rules import (
    ENV_FILES,
    SERVER_1_REF,
    SLUG,
    audit_rows,
    member_of_ops,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

READ_ENV = "cat /srv/app/.env"
ANSWER = "server-1 has been up for 3 days; the team does not let me read its .env file."


async def test_your_own_model_runs_under_the_team_rules(tui, seed, fake_cloud, fake_ai, journey):
    member_of_ops(fake_cloud)
    fake_cloud.agent_rules.set_rules(SLUG, {"command_blocklist": [ENV_FILES]})
    seed_byo(seed, fake_cloud, "ollama", fake_ai.url, signed_in=True, with_key=False, preferred=True)
    journey.shims.when("ssh", r"server-1\.example\.com.*uptime", stdout=" 10:00:00 up 3 days\n")
    fake_ai.script(
        "ollama",
        tool_call("run_command", instance_id=SERVER_1_REF, command=READ_ENV),
        tool_call("run_command", instance_id=SERVER_1_REF, command="uptime"),
        reply(ANSWER),
    )
    async with tui() as t:
        await open_chat(t)
        await send(t, "What is in server-1's .env file, and how long has it been up?")
        assert (await wait_for_reply(t))[-1] == ANSWER

    _, after_env, after_uptime = fake_ai.requests("ollama")
    assert after_env["body"]["messages"][-1]["content"] == (
        "Blocked: on team Ops's shared servers your agents run at the standard level "
        f"(set by the team), and '{READ_ENV}' is refused there: it matches the blocked "
        f"pattern {ENV_FILES}."
    )
    assert "up 3 days" in after_uptime["body"]["messages"][-1]["content"]
    [ssh] = journey.shims.calls("ssh")
    assert ssh.argv[-1].endswith("uptime")
    refusals = [row for row in audit_rows(seed.home, "run_command") if row.get("reason") == "team_rule"]
    assert [row["args"]["command"] for row in refusals] == [READ_ENV]
