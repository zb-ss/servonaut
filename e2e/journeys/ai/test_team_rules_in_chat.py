"""Journey: a team's agent rules bind the AI chat, whichever model is behind it.

Signed in as a member of the team Ops, the user chats with their own model
(a local Ollama). When the model asks to run commands on Ops's server-1, the
tools run under Ops's rules: the command matching a pattern Ops blocks is
refused before anything reaches the server, and the model is told why; the
allowed one runs. The rules live in Servonaut's tools, not in the model, so
the provider makes no difference.

With Servonaut AI the same should hold for the tool calls the service sends
to the chat: the user confirms the command (typing RUN), and it is still the
AI's command, so Ops's rule refuses it and the service is told why. Today
that call does not get as far as the rule: Servonaut AI in the TUI cannot
find a team's shared server at all (a known bug, recorded below), so nothing
reaches the server either way.
"""

from __future__ import annotations

import pytest

from e2e.harness.ai_chat import open_chat, seed_byo, seed_hosted, send, wait_for_reply
from e2e.harness.fake_ai import reply, tool_call
from e2e.harness.fake_cloud.chat_script import ChatTurn, token, usage
from e2e.harness.fake_cloud.chat_script import tool_call as hosted_tool_call
from e2e.harness.known_bugs import ProductBug, known_bug
from e2e.harness.team_agent_rules import (
    ENV_FILES,
    SERVER_1,
    SERVER_1_REF,
    SLUG,
    audit_rows,
    member_of_ops,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

READ_ENV = "cat /srv/app/.env"
ANSWER = "server-1 has been up for 3 days; the team does not let me read its .env file."
REFUSED = (
    "Blocked: on team Ops's shared servers your agents run at the standard level "
    f"(set by the team), and '{READ_ENV}' is refused there: it matches the blocked "
    f"pattern {ENV_FILES}."
)


def _team_refusals(home) -> list[dict]:
    return [row for row in audit_rows(home, "run_command") if row.get("reason") == "team_rule"]


class TeamServerNotFound(ProductBug):
    """Servonaut AI's tool call in the TUI does not find the team's shared server."""


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
    assert after_env["body"]["messages"][-1]["content"] == REFUSED
    assert "up 3 days" in after_uptime["body"]["messages"][-1]["content"]
    [ssh] = journey.shims.calls("ssh")
    assert ssh.argv[-1].endswith("uptime")
    assert [row["args"]["command"] for row in _team_refusals(seed.home)] == [READ_ENV]


@known_bug(
    "the TUI runs Servonaut AI's tool calls without the team server lookup, so a team's "
    "shared server is not found and the call ends before the team's rules are applied",
    raises=TeamServerNotFound,
)
async def test_servonaut_ai_runs_under_the_team_rules_even_once_you_confirm(
    tui, seed, fake_cloud, journey,
):
    member_of_ops(fake_cloud)
    fake_cloud.agent_rules.set_rules(SLUG, {"command_blocklist": [ENV_FILES]})
    seed_hosted(seed, fake_cloud, dangerous_tools=True)
    fake_cloud.ai.script(ChatTurn.of(
        token("Checking."),
        hosted_tool_call(
            "tc-env", "run_command", {"instance_id": SERVER_1["name"], "command": READ_ENV},
            guard_level="dangerous",
        ),
        token(" Done."),
        usage(),
    ))
    async with tui() as t:
        await open_chat(t)
        await send(t, "Show me server-1's .env file")
        await t.wait_for_screen("DangerousToolConfirmModal")
        await t.wait_until(lambda: t.focused_id() == "dangerous_confirm_input", desc="input")
        await t.type("RUN")
        await t.press("enter")
        assert (await wait_for_reply(t))[-1] == "Checking. Done."
        [posted] = await t.wait_until(
            lambda: fake_cloud.ai.tool_results("tc-env"), desc="the tool result",
        )

    assert journey.shims.calls("ssh") == []
    if posted["result"] == f"Instance not found: {SERVER_1['name']}":
        raise TeamServerNotFound(posted["result"])
    assert posted["status"] == "error" and posted["result"] == REFUSED
    [row] = [row for row in _team_refusals(seed.home) if row.get("source") == "ai_chat"]
    assert row["tool_call_id"] == "tc-env"
