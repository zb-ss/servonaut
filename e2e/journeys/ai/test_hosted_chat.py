"""Journey: chat with the hosted Servonaut AI through every recorded stream.

A signed-in subscriber opens the chat panel (F2) and sends a message. The
(fake) service answers with one of the SSE scenarios recorded in
``tests/fixtures/sse``, and the panel must end in the state the user should
see: the streamed reply, tool rows, the stats bar badges, a toast or banner
for caps and errors, or the top-up offer. The same holds when the service
refuses the request before any stream opens, when the user closes the panel
mid-stream, and when the model's text contains Rich markup (shown as typed,
never interpreted). Whatever happens, nothing crashes and the input takes
the next message.

A silent stream is given up after ``ai_provider.stream_silence_timeout_seconds``
(35 s by default, against a ping every 15 s). Journeys that need it set 3 s
and space the recorded frames 0.5 s apart, so the 90-second ping-only stream
takes under four seconds and still outlasts the limit. Time spent answering
a tool prompt does not count as silence.
"""

from __future__ import annotations

import importlib
import inspect

import pytest

from e2e.harness.ai_chat import (
    audit_rows,
    banner,
    bubbles,
    busy,
    open_chat,
    plain,
    replies,
    seed_hosted,
    send,
    stats,
    stays_false,
    wait_for_literal_toast,
    wait_for_reply,
    web_1_server,
)
from e2e.harness.fake_cloud.chat_script import (
    ChatTurn,
    error,
    fixture_names,
    token,
    tool_call,
    tool_result,
    usage,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

SILENCE_LIMIT_SECONDS = 3.0
PING_GAP_SECONDS = 0.5
LOST_CONTACT = "Lost contact with the AI server — send your message again."


@pytest.fixture
def short_silence_limit(monkeypatch):
    """AI settings with a 3 s stream silence limit.

    The product clamps the setting to 20 s and up; the journeys lower that
    floor so a silent stream is noticed in seconds.
    """
    from servonaut.config.schema import AIProviderConfig
    from servonaut.services import ai_sse

    monkeypatch.setattr(ai_sse, "SSE_SILENCE_MIN_S", 1.0)
    return AIProviderConfig(stream_silence_timeout_seconds=SILENCE_LIMIT_SECONDS)


def _chat(fake_cloud, index: int = 0) -> dict:
    chats = fake_cloud.ai.chats()
    return chats[index] if len(chats) > index else {}


async def _ended(t, fake_cloud, index: int = 0) -> str:
    """Wait until the service side of chat *index* is over; how it ended."""
    await t.wait_until(
        lambda: _chat(fake_cloud, index).get("ended", "open") != "open",
        desc=f"chat {index} to end on the service side",
    )
    return _chat(fake_cloud, index)["ended"]


async def _still_usable(t, fake_cloud) -> None:
    """The panel takes the next message and shows its reply."""
    fake_cloud.ai.script(ChatTurn.of(token("Still here."), usage()))
    await send(t, "ping")
    assert (await wait_for_reply(t))[-1] == "Still here."


# fixture -> (reply the user ends up with, stats bar text, toast)
STREAMS = {
    "tokens_only": (
        "Hello world, how are you?", ["Model: gemini-2-flash-002", "Tokens: 120"], None
    ),
    "fallback_used": ("Working...", ["via backup vendor"], None),
    "soft_cap": ("Hello world, how are you?", ["downgraded to faster model"], None),
    "wall_clock_120s": (
        "Working on it...",
        [],
        "wall_clock_cap_exceeded: Turn took longer than 120s; partial response above.",
    ),
    "tool_round_limit_5": (
        "Let me check that",
        [],
        "tool_round_limit: Reached MAX_TOOL_ROUNDS=5; partial response above.",
    ),
    "error_rate_limited": (None, [], "Rate limited — try again in 12 s."),
}
# The other recorded streams, and the journey (module:function) that replays
# each; the last test checks both lists against the fixture files.
COVERED_ELSEWHERE = {
    "tool_round_one": "test_hosted_chat:test_tool_round_runs_the_tool_and_answers_the_service",
    "error_quota_exhausted": "test_topup:_out_of_tokens",
    "mid_stream_silence": (
        "test_hosted_chat:test_silence_mid_stream_is_reported_and_the_chat_recovers"
    ),
    "cancelled_mid_stream": "test_hosted_chat:test_closing_the_panel_cancels_the_stream",
    "ping_only_90s": "test_hosted_chat:test_ping_only_stream_keeps_the_connection_alive",
}


@pytest.mark.parametrize("name", sorted(STREAMS))
async def test_stream_ends_in_the_state_the_user_should_see(tui, seed, fake_cloud, name):
    reply, badges, toast = STREAMS[name]
    seed_hosted(seed, fake_cloud)
    fake_cloud.ai.script(ChatTurn.fixture(name))
    async with tui() as t:
        await open_chat(t)
        await send(t, "How is the fleet?")
        shown = await wait_for_reply(t)
        assert await _ended(t, fake_cloud) == "completed"

        assert shown == ([reply] if reply else [])
        for badge in badges:
            assert badge in stats(t)
        if toast:
            await wait_for_literal_toast(t, toast)
        assert banner(t) == ""
        body = _chat(fake_cloud)["body"]
        assert body["messages"][-1] == {"role": "user", "content": "How is the fleet?"}
        assert body["stream"] is True and body["allow_tools"] is True
        # No round cap configured: the service's own default applies.
        assert "max_tool_rounds" not in body
        await _still_usable(t, fake_cloud)


async def test_tool_round_runs_the_tool_and_answers_the_service(tui, seed, fake_cloud):
    seed_hosted(seed, fake_cloud, chat_max_tool_rounds=4)
    fake_cloud.ai.script(ChatTurn.fixture("tool_round_one"))
    async with tui() as t:
        await open_chat(t)
        await send(t, "Why is nginx failing?")
        shown = await wait_for_reply(t)
        assert await _ended(t, fake_cloud) == "completed"

        assert shown == ["Let me check the logs.The errors point to upstream timeout."]
        assert ("tool", "Tool result tc_abc123 (ok)\n50 lines tailed") in bubbles(t)
        assert "Tokens: 5,042" in stats(t)
        # A read-only tool runs without asking; its outcome went back to the
        # service on the conversation the stream announced.
        assert t.stack_names()[-1] == "InstanceListScreen"
        [posted] = fake_cloud.ai.tool_results("tc_abc123")
        conversation_id = _chat(fake_cloud)["conversation_id"]
        assert posted["conversation_id"] == conversation_id
        [row] = audit_rows(seed.home, source="ai_chat")
        assert row["tool"] == "tail_log" and row["guard_level"] == "readonly"
        assert row["tool_call_id"] == "tc_abc123" and row["conversation_id"] == conversation_id
        assert row["status"] == posted["status"]

        # The configured cap on tool rounds goes with each request, and a
        # change (as the AI Chat settings save it) applies to the next one.
        assert _chat(fake_cloud)["body"]["max_tool_rounds"] == 4
        t.app.config_manager.update(chat_max_tool_rounds=2)
        await _still_usable(t, fake_cloud)
        assert _chat(fake_cloud, 1)["body"]["max_tool_rounds"] == 2


async def test_ping_only_stream_keeps_the_connection_alive(
    tui, seed, fake_cloud, short_silence_limit
):
    seed_hosted(seed, fake_cloud, ai_provider=short_silence_limit)
    fake_cloud.ai.script(ChatTurn.fixture("ping_only_90s", gap=PING_GAP_SECONDS))
    async with tui() as t:
        await open_chat(t)
        await send(t, "Anything?")
        # Longer than the watchdog in total, but never silent for that long.
        assert await wait_for_reply(t) == ["(no response)"]
        assert await _ended(t, fake_cloud) == "completed"
        assert banner(t) == ""
        await _still_usable(t, fake_cloud)


async def test_silence_mid_stream_is_reported_and_the_chat_recovers(
    tui, seed, fake_cloud, short_silence_limit
):
    seed_hosted(seed, fake_cloud, ai_provider=short_silence_limit)
    fake_cloud.ai.script(ChatTurn.fixture("mid_stream_silence", stall_after=5))
    async with tui() as t:
        await open_chat(t)
        await send(t, "Count to five")
        await t.wait_until(lambda: not busy(t), desc="the silence limit to end the turn")
        # The client gave up on the silent stream and closed it.
        assert await _ended(t, fake_cloud) == "stalled:client_left"
        assert banner(t) == LOST_CONTACT
        assert replies(t) == []
        await _still_usable(t, fake_cloud)


async def test_a_slow_answer_to_a_tool_prompt_keeps_the_turn(
    tui, seed, fake_cloud, short_silence_limit
):
    seed_hosted(
        seed, fake_cloud, custom_servers=[web_1_server()], ai_provider=short_silence_limit
    )
    fake_cloud.ai.script(
        ChatTurn.of(
            token("Saving it."),
            tool_call(
                "tc-slow", "remember_server_finding",
                {"instance_id": "web-1", "title": "Disk", "body": "Nearly full."},
                guard_level="standard",
            ),
            token(" Saved."),
            usage(),
            ping_every=PING_GAP_SECONDS,
        )
    )
    async with tui() as t:
        await open_chat(t)
        await send(t, "Remember the disk")
        await t.wait_for_screen("ToolConfirmModal")
        # The user reads the prompt for longer than the silence limit (but
        # well inside the 50 s confirmation deadline) while the service
        # keeps the stream alive with pings.
        needed = int(SILENCE_LIMIT_SECONDS / PING_GAP_SECONDS) + 2
        await t.wait_until(
            lambda: _chat(fake_cloud).get("pings", 0) >= needed, desc="pings during the prompt"
        )
        assert t.screen_name() == "ToolConfirmModal"
        await t.press("y")
        await t.wait_until(lambda: not busy(t), desc="the turn to finish")
        assert fake_cloud.ai.tool_results("tc-slow")[0]["status"] == "ok"
        assert banner(t) == ""
        assert replies(t) == ["Saving it. Saved."]


async def test_closing_the_panel_cancels_the_stream(tui, seed, fake_cloud):
    seed_hosted(seed, fake_cloud)
    fake_cloud.ai.script(ChatTurn.fixture("cancelled_mid_stream", hold_open=True))
    async with tui() as t:
        chat = await open_chat(t)
        await send(t, "Count slowly")
        await t.wait_until(
            lambda: any(
                kind == "thinking" and text.endswith("onetwothreefourfive")
                for kind, text in bubbles(t)
            ),
            desc="the streamed text so far",
        )
        await t.click(chat.query_one("#btn-chat-close"))
        await t.wait_until(lambda: not t.find("#chat-panel"), desc="panel closed")
        assert await _ended(t, fake_cloud) == "held:client_left"

        # Reopening resumes the conversation with a usable input.
        await open_chat(t)
        assert not busy(t)
        await _still_usable(t, fake_cloud)


async def test_markup_in_streamed_content_is_shown_literally(tui, seed, fake_cloud):
    """Every string the service sends is shown as typed. Each carries an
    unbalanced ``[/]``, which raises if anything interprets it as markup."""
    seed_hosted(seed, fake_cloud, custom_servers=[web_1_server()])
    streamed = "Use [bold]sudo[/bold] [/] or [link=https://example.invalid]this[/link]"
    odd_tool = "odd[b]tool[/]"
    fake_cloud.ai.script(
        ChatTurn.of(
            token("Use [bold]sudo[/bold] [/]"),
            token(" or [link=https://example.invalid]this[/link]"),
            tool_call(
                "tc-markup", "remember_server_finding",
                {"instance_id": "web-1", "title": "[b]Disk[/b] [/]", "body": "[red]full[/red]"},
                guard_level="standard",
            ),
            tool_result("tc-markup", "[red]declined[/red] by [b]you[/b] [/]", status="denied"),
            tool_call("tc-odd", odd_tool, {}, guard_level="readonly"),
            error("tool_round_limit", "[b]stop[/b] here [/]"),
            usage(),
        )
    )
    async with tui() as t:
        await open_chat(t)
        await send(t, "Help")
        # The stream pauses on the confirm prompt with the text so far on
        # screen, brackets intact, and the prompt shows the arguments as sent.
        prompt = await t.wait_for_screen("ToolConfirmModal")
        assert any(kind == "thinking" and streamed in text for kind, text in bubbles(t))
        assert plain(prompt.query_one("#tool_confirm_args")) == (
            "instance_id: web-1\ntitle: [b]Disk[/b] [/]\nbody: [red]full[/red]"
        )
        await t.press("n")
        # An unknown tool is asked about too, under its literal name, and
        # then reported as not available here.
        await t.wait_until(
            lambda: t.screen_name() == "ToolConfirmModal"
            and plain(t.screen.query_one("#tool_confirm_title")) == odd_tool,
            desc="the prompt for the unknown tool",
        )
        await t.press("y")
        await wait_for_literal_toast(
            t, f"Skipped tool: {odd_tool} — not available in this CLI build.",
            severity="warning",
        )
        await wait_for_reply(t)

        assert replies(t) == [streamed]
        rows = [text for kind, text in bubbles(t) if kind == "tool"]
        assert rows == [
            "Tool result tc-markup (denied)\n[red]declined[/red] by [b]you[/b] [/]",
            f"⊘ Skipped tool {odd_tool} — Tool {odd_tool!r} is not available in this CLI build.",
        ]
        await wait_for_literal_toast(t, "tool_round_limit: [b]stop[/b] here [/]")
        assert fake_cloud.ai.tool_results("tc-odd")[0]["status"] == "error"


REFUSED = "Refused by the service [b]now[/b] [/]."


@pytest.mark.parametrize(
    ("status", "code", "details", "outcome"),
    [
        (429, "rate_limited", {"retry_after": 7}, "toast:Rate limited — try again in 7 s."),
        (
            429,
            "rate_limited",
            {},
            "toast:Rate limited — wait a moment, then try again.",
        ),
        (402, "quota_exhausted", {}, "screen:AITopUpModal"),
        (409, "e2e_unknown_code", {}, f"toast:{REFUSED}"),
    ],
    ids=["rate-limited", "rate-limited-no-wait-given", "out-of-tokens", "unknown-code"],
)
async def test_refusal_before_the_stream_opens(
    tui, seed, fake_cloud, status, code, details, outcome
):
    seed_hosted(seed, fake_cloud)
    fake_cloud.ai.script(ChatTurn.refused(status, code, REFUSED, **details))
    async with tui() as t:
        await open_chat(t)
        await send(t, "Hello")
        kind, expected = outcome.split(":", 1)
        if kind == "toast":
            await wait_for_literal_toast(t, expected)
        else:
            await t.wait_for_screen(expected)
            await t.press("escape")
        assert await wait_for_reply(t) == []
        assert _chat(fake_cloud)["ended"] == f"refused:{status}"
        await _still_usable(t, fake_cloud)


async def test_a_rate_limited_turn_is_not_retried_behind_the_users_back(
    tui, seed, fake_cloud
):
    """The toast says when to try again, and nothing is re-sent meanwhile:
    re-sending a turn could repeat tool calls the service already ran."""
    seed_hosted(seed, fake_cloud)
    fake_cloud.ai.script(
        ChatTurn.of(error("rate_limited", "Slow down.", retry_after=2)),
        ChatTurn.of(token("Answered."), usage()),
    )
    async with tui() as t:
        await open_chat(t)
        await send(t, "Hello")
        await wait_for_literal_toast(t, "Rate limited — try again in 2 s.", severity="warning")
        assert await wait_for_reply(t) == []
        # A second past the wait the service asked for: still one request.
        assert await stays_false(t, lambda: len(fake_cloud.ai.chats()) > 1, seconds=3)
        # The user sends again, and only now is the next turn used.
        await send(t, "Hello again")
        assert await wait_for_reply(t) == ["Answered."]
        assert len(fake_cloud.ai.chats()) == 2


async def test_every_recorded_stream_has_a_journey():
    assert sorted([*STREAMS, *COVERED_ELSEWHERE]) == fixture_names()
    for name, where in COVERED_ELSEWHERE.items():
        module_name, function = where.split(":")
        module = importlib.import_module(f"e2e.journeys.ai.{module_name}")
        source = inspect.getsource(getattr(module, function))
        assert f'ChatTurn.fixture("{name}"' in source, f"{where} does not replay {name}"
