"""Journey: the hosted AI asks before it acts, and never on its own say-so.

When the hosted model wants a tool run on the user's machine, the chat
panel sizes the prompt by the tool's guard level:

* read-only tools run at once (see the hosted-chat journeys);
* standard tools wait for a yes/no;
* dangerous tools (running commands, deploys) need ``RUN`` typed out, and
  only an account with the dangerous-tools entitlement is asked at all.
  Without it they are refused before any prompt.

A prompt left unanswered expires after ``ai_provider.tool_confirm_timeout_seconds``
(50 s by default, before the service stops waiting): it closes, the tool
never runs, and the service is told so.

The level the service sends is only a hint: the client's own table is the
floor, so a service that labels a tool lower still gets the prompt the
tool deserves. Labels are read trimmed and lower-cased; one the client does
not know counts as standard. Every decision lands in the audit trail tagged
as coming from the AI chat, with the conversation and the tool call it
belongs to, and every raised level gets its own row that keeps the label
exactly as the service sent it.
"""

from __future__ import annotations

from typing import Optional

import pytest

from e2e.harness import fleet
from e2e.harness.ai_chat import (
    audit_rows,
    open_chat,
    plain,
    seed_hosted,
    send,
    wait_for_reply,
    web_1_server,
)
from e2e.harness.fake_cloud.chat_script import ChatTurn, token, tool_call, usage

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

WEB_1 = fleet.WEB_1
UPTIME = " 10:00:00 up 3 days,  load average: 0.10\n"
NOTE = {"instance_id": WEB_1.name, "title": "Disk nearly full", "body": "/var is at 91%."}
UPTIME_ON_WEB_1 = {"instance_id": WEB_1.name, "command": "uptime"}
NO_ENTITLEMENT = "Dangerous tools require allow_dangerous_ai_tools."


def _turn(tool_call_id: str, tool: str, args: dict, guard_level: Optional[str]) -> ChatTurn:
    return ChatTurn.of(
        token("On it."),
        tool_call(tool_call_id, tool, args, guard_level=guard_level),
        token(" Done."),
        usage(),
    )


def _seed(seed, fake_cloud, journey, **kwargs):
    seed_hosted(seed, fake_cloud, custom_servers=[web_1_server()], **kwargs)
    journey.shims.when("ssh", rf"{WEB_1.username}@{WEB_1.host} .*uptime", stdout=UPTIME)


async def _posted(t, fake_cloud, tool_call_id: str) -> dict:
    rows = await t.wait_until(
        lambda: fake_cloud.ai.tool_results(tool_call_id), desc=f"tool result {tool_call_id}"
    )
    return rows[0]


def _audit(seed, tool_call_id: str) -> list[dict]:
    return [r for r in audit_rows(seed.home, source="ai_chat") if r["tool_call_id"] == tool_call_id]


def _trail(rows: list[dict]) -> list[tuple]:
    """Each row as (reason, label the service sent, level after that step)."""
    return [(r["reason"], r.get("server_tier"), r.get("effective_tier")) for r in rows]


# The rows a raised level writes: (reason, server_tier, effective_tier).
def _client_floor(sent: str, to: str) -> tuple:
    return ("client_guard_escalation", sent, to)


def _name_floor(sent: str) -> tuple:
    return ("dangerous_floor_escalation", sent, "dangerous")


REFUSED = ("dangerous_disallowed_client_side", None, None)
DECLINED = ("user_declined", None, None)


async def test_standard_tool_waits_for_yes_or_no(tui, seed, fake_cloud, journey):
    _seed(seed, fake_cloud, journey)
    fake_cloud.ai.script(
        _turn("tc-note-1", "remember_server_finding", NOTE, "standard"),
        _turn("tc-note-2", "remember_server_finding", NOTE, "standard"),
    )
    async with tui() as t:
        await open_chat(t)
        await send(t, "Remember that the disk is nearly full")
        prompt = await t.wait_for_screen("ToolConfirmModal")
        assert plain(prompt.query_one("#tool_confirm_title")) == "remember_server_finding"
        assert "title: Disk nearly full" in plain(prompt.query_one("#tool_confirm_args"))
        # The service is still waiting on the answer.
        assert fake_cloud.ai.tool_results() == []
        await t.press("y")
        assert (await wait_for_reply(t))[-1] == "On it. Done."
        approved = await _posted(t, fake_cloud, "tc-note-1")
        assert approved["status"] == "ok"
        conversation_id = fake_cloud.ai.chats()[0]["conversation_id"]
        assert approved["conversation_id"] == conversation_id
        [row] = _audit(seed, "tc-note-1")
        assert row["allowed"] is True and row["guard_level"] == "standard"
        assert row["conversation_id"] == conversation_id

        await send(t, "And again")
        await t.wait_for_screen("ToolConfirmModal")
        await t.press("n")
        await wait_for_reply(t)
        declined = await _posted(t, fake_cloud, "tc-note-2")
        assert declined["status"] == "denied" and declined["result"] == "User declined."
        [row] = _audit(seed, "tc-note-2")
        assert row["allowed"] is False and row["reason"] == "user_declined"


async def test_dangerous_tool_needs_run_typed_out(tui, seed, fake_cloud, journey):
    _seed(seed, fake_cloud, journey, dangerous_tools=True)
    fake_cloud.ai.script(_turn("tc-run-1", "run_command", UPTIME_ON_WEB_1, "dangerous"))
    async with tui() as t:
        await open_chat(t)
        await send(t, "How long has web-1 been up?")
        prompt = await t.wait_for_screen("DangerousToolConfirmModal")
        assert plain(prompt.query_one("#dangerous_confirm_title")) == "Dangerous tool: run_command"
        await t.wait_until(lambda: t.focused_id() == "dangerous_confirm_input", desc="input")

        # Anything but the exact word keeps the prompt open.
        await t.type("run")
        await t.press("enter")
        error = prompt.query_one("#dangerous_confirm_error")
        await t.wait_until(lambda: "exactly" in plain(error), desc="the re-prompt")
        assert t.screen_name() == "DangerousToolConfirmModal"
        assert journey.shims.calls("ssh") == []

        await t.press("backspace", "backspace", "backspace")
        await t.type("RUN")
        await t.press("enter")
        assert (await wait_for_reply(t))[-1] == "On it. Done."
        posted = await _posted(t, fake_cloud, "tc-run-1")
        assert posted["status"] == "ok" and "up 3 days" in posted["result"]
        [ssh] = journey.shims.calls("ssh")
        assert f"{WEB_1.username}@{WEB_1.host}" in ssh.argv and str(WEB_1.port) in ssh.argv
        [row] = _audit(seed, "tc-run-1")
        assert row["allowed"] is True and row["guard_level"] == "dangerous"


@pytest.mark.parametrize(
    ("tool", "label", "trail"),
    [
        ("run_command", "dangerous", [REFUSED]),
        ("deploy", "dangerous", [REFUSED]),
        # Read trimmed and lower-cased: no coercion, nothing to raise.
        ("deploy", " Dangerous ", [REFUSED]),
        # Labelled lower by the service, or not at all: still dangerous.
        ("deploy", "readonly", [_client_floor("readonly", "dangerous"), REFUSED]),
        ("deploy", None, [_client_floor("", "dangerous"), REFUSED]),
        (
            "run_command",
            "readonly",
            [_client_floor("readonly", "standard"), _name_floor("readonly"), REFUSED],
        ),
    ],
    ids=[
        "command",
        "deploy",
        "deploy-label-spaced-and-capitalised",
        "deploy-labelled-readonly",
        "deploy-unlabelled",
        "command-labelled-readonly",
    ],
)
async def test_dangerous_tools_are_refused_without_the_entitlement(
    tui, seed, fake_cloud, journey, tool, label, trail
):
    _seed(seed, fake_cloud, journey)
    fake_cloud.ai.script(_turn("tc-refused", tool, UPTIME_ON_WEB_1, label))
    async with tui() as t:
        await open_chat(t)
        await send(t, "Do it")
        # The service waits for this answer, and nobody presses a key: had a
        # prompt been shown, the answer would never come.
        posted = await _posted(t, fake_cloud, "tc-refused")
        assert posted["status"] == "denied" and posted["result"] == NO_ENTITLEMENT
        assert (await wait_for_reply(t))[-1] == "On it. Done."
        assert t.stack_names()[-1] == "InstanceListScreen"
        assert journey.shims.calls("ssh") == []
        rows = _audit(seed, "tc-refused")
        assert _trail(rows) == trail
        assert rows[-1]["allowed"] is False and rows[-1]["guard_level"] == "dangerous"


async def test_the_service_cannot_lower_a_tools_guard_level(tui, seed, fake_cloud, journey):
    _seed(seed, fake_cloud, journey, dangerous_tools=True)
    fake_cloud.ai.script(
        _turn("tc-low-1", "remember_server_finding", NOTE, "readonly"),
        _turn("tc-low-2", "run_command", UPTIME_ON_WEB_1, "readonly"),
        _turn("tc-low-3", "remember_server_finding", NOTE, "root"),
    )
    async with tui() as t:
        await open_chat(t)
        # Labelled read-only, but saving a finding is a standard tool.
        await send(t, "Note it")
        await t.wait_for_screen("ToolConfirmModal")
        await t.press("n")
        await wait_for_reply(t)
        rows = _audit(seed, "tc-low-1")
        assert _trail(rows) == [_client_floor("readonly", "standard"), DECLINED]
        assert rows[0]["client_tier"] == "standard" and rows[-1]["guard_level"] == "standard"

        # Labelled read-only, but running a command is dangerous: the client
        # table makes it standard, the name floor makes it dangerous.
        await send(t, "Check uptime")
        await t.wait_for_screen("DangerousToolConfirmModal")
        await t.press("escape")
        await wait_for_reply(t)
        assert (await _posted(t, fake_cloud, "tc-low-2"))["status"] == "denied"
        rows = _audit(seed, "tc-low-2")
        assert _trail(rows) == [
            _client_floor("readonly", "standard"), _name_floor("readonly"), DECLINED,
        ]
        assert rows[-1]["guard_level"] == "dangerous"

        # A label the client does not know counts as standard: still asked.
        await send(t, "Note it again")
        await t.wait_for_screen("ToolConfirmModal")
        await t.press("n")
        await wait_for_reply(t)
        assert _trail(_audit(seed, "tc-low-3")) == [
            ("unknown_guard_level", "root", "standard"), DECLINED,
        ]
        assert journey.shims.calls("ssh") == []


async def test_an_unanswered_prompt_expires_and_the_tool_never_runs(
    tui, seed, fake_cloud, journey
):
    from servonaut.config.schema import AIProviderConfig

    deadline = AIProviderConfig(tool_confirm_timeout_seconds=1.0)
    _seed(seed, fake_cloud, journey, dangerous_tools=True, ai_provider=deadline)
    fake_cloud.ai.script(_turn("tc-late", "run_command", UPTIME_ON_WEB_1, "dangerous"))
    async with tui() as t:
        await open_chat(t)
        await send(t, "How long has web-1 been up?")
        # The prompt is open for 1 s only, so check that it opened rather
        # than catching it on screen.
        await t.wait_for_screen_opened("DangerousToolConfirmModal")
        # Nobody answers: the prompt closes on its own and the service is
        # told the tool did not run.
        posted = await _posted(t, fake_cloud, "tc-late")
        assert posted["status"] == "error"
        assert posted["result"] == (
            "The confirmation prompt for run_command was not answered within 1 s, "
            "so the tool was not run."
        )
        await t.wait_until(
            lambda: t.screen_name() != "DangerousToolConfirmModal", desc="the prompt to close"
        )
        assert (await wait_for_reply(t))[-1] == "On it. Done."
        assert journey.shims.calls("ssh") == []
        rows = _audit(seed, "tc-late")
        assert [row["reason"] for row in rows] == ["confirm_timeout"]
        assert rows[0]["allowed"] is False and rows[0]["guard_level"] == "dangerous"
