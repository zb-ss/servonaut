"""Journey: the hosted AI pauses a turn while its tools run here.

The chat asks the service to split its turns. When a model round ends with
tools to run on the user's machine, a service that supports it sends the
tool calls, then ``turn_suspended``, and closes the stream: nothing waits on
the user's answer server-side. Once the results are posted the client
continues the turn (``POST /api/ai/chat/continue``) and the reply streams on
as one turn.

* When the service says up front that it pauses, the tool prompts wait for
  the pause, so they can stay open for the service's whole window instead
  of the shorter ``ai_provider.tool_confirm_timeout_seconds``.
* A service that does not say so gets each tool call answered as it
  arrives, as before, and is still continued if it pauses.
* A continue refused while the service is busy is asked again within the
  window; a turn the service stopped waiting for is reported, never sent
  again (that would repeat its tools).
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.ai_chat import (
    open_chat,
    seed_hosted,
    send,
    stays_false,
    wait_for_literal_toast,
    wait_for_reply,
    web_1_server,
)
from e2e.harness.fake_cloud.chat_script import (
    ChatTurn,
    token,
    tool_call,
    tool_result,
    turn_suspended,
    usage,
)
from e2e.harness.fake_cloud.routes_ai import CHAT_PATH, CONTINUE_PATH

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

WEB_1 = fleet.WEB_1
NOTE = {"instance_id": WEB_1.name, "title": "Disk nearly full", "body": "/var is at 91%."}
LOST = "The AI service stopped waiting for this turn's tools. Send your message again."


def _paused(*, says_it_pauses: bool) -> ChatTurn:
    return ChatTurn.of(
        token("On it."),
        tool_call("tc-note", "remember_server_finding", NOTE, guard_level="standard"),
        turn_suspended("cont-1", ["tc-note"]),
        says_it_pauses=says_it_pauses,
    )


def _rest() -> ChatTurn:
    # The continued stream opens with the conversation frame too.
    return ChatTurn.of(
        tool_result("tc-note", "Saved."), token(" Done."), usage(), says_it_pauses=True,
    )


def _seed(seed, fake_cloud, **config):
    from servonaut.config.schema import AIProviderConfig

    # A prompt limit far below the service's window: a paused turn's prompt
    # must not be held to it.
    limit = AIProviderConfig(tool_confirm_timeout_seconds=1.0)
    seed_hosted(seed, fake_cloud, custom_servers=[web_1_server()], ai_provider=limit, **config)


def _requests(fake_cloud) -> list[tuple[str, str]]:
    return [(c["path"], c["ended"]) for c in fake_cloud.ai.chats()]


async def test_a_paused_turn_frees_the_service_while_the_user_decides(tui, seed, fake_cloud):
    _seed(seed, fake_cloud)
    fake_cloud.ai.script(_paused(says_it_pauses=True), _rest())
    async with tui() as t:
        await open_chat(t)
        await send(t, "Remember that the disk is nearly full")
        await t.wait_for_screen("ToolConfirmModal")
        assert fake_cloud.ai.chats()[0]["body"]["split_turns"] is True
        # The service's stream is already closed while the user decides.
        await t.wait_until(
            lambda: _requests(fake_cloud) == [(CHAT_PATH, "completed")],
            desc="the paused stream to close",
        )
        # The prompt outlasts the 1 s limit: the service's window decides.
        assert await stays_false(
            t, lambda: t.screen_name() != "ToolConfirmModal", seconds=2.0,
        )
        assert fake_cloud.ai.tool_results() == []

        await t.press("y")

        assert (await wait_for_reply(t))[-1] == "On it. Done."
        [posted] = fake_cloud.ai.tool_results("tc-note")
        assert posted["status"] == "ok"
        chat, cont = fake_cloud.ai.chats()
        assert (cont["path"], cont["body"]) == (CONTINUE_PATH, {"continuation_id": "cont-1"})
        assert posted["conversation_id"] == chat["conversation_id"] == cont["conversation_id"]


async def test_a_service_that_does_not_announce_pauses_is_still_continued(
    tui, seed, fake_cloud
):
    _seed(seed, fake_cloud)
    fake_cloud.ai.script(_paused(says_it_pauses=False), _rest())
    async with tui() as t:
        await open_chat(t)
        await send(t, "Remember that the disk is nearly full")
        # Answered as it arrives, under the configured limit.
        await t.wait_for_screen("ToolConfirmModal")
        await t.press("y")

        assert (await wait_for_reply(t))[-1] == "On it. Done."
        assert fake_cloud.ai.tool_results("tc-note")[0]["status"] == "ok"
        assert _requests(fake_cloud) == [(CHAT_PATH, "completed"), (CONTINUE_PATH, "completed")]


async def test_a_busy_service_is_asked_again_within_the_window(tui, seed, fake_cloud):
    _seed(seed, fake_cloud)
    fake_cloud.ai.script(
        _paused(says_it_pauses=True),
        ChatTurn.refused(503, "server_busy", "Busy, try again shortly.", retry_after=1),
        _rest(),
    )
    async with tui() as t:
        await open_chat(t)
        await send(t, "Remember that the disk is nearly full")
        await t.wait_for_screen("ToolConfirmModal")
        await t.press("y")

        assert (await wait_for_reply(t))[-1] == "On it. Done."
        assert _requests(fake_cloud) == [
            (CHAT_PATH, "completed"),
            (CONTINUE_PATH, "refused:503"),
            (CONTINUE_PATH, "completed"),
        ]


async def test_a_turn_the_service_stopped_waiting_for_is_not_sent_again(
    tui, seed, fake_cloud
):
    # The second turn of a conversation, paused before any text streamed:
    # exactly when a 404 would otherwise read as a stale conversation and
    # resend the turn, repeating its tools.
    _seed(seed, fake_cloud)
    fake_cloud.ai.script(
        ChatTurn.of(token("Hello."), usage()),
        ChatTurn.of(
            tool_call("tc-note", "remember_server_finding", NOTE, guard_level="standard"),
            turn_suspended("cont-1", ["tc-note"]),
            says_it_pauses=True,
        ),
        ChatTurn.refused(404, "continuation_not_found", "No such paused turn."),
    )
    async with tui() as t:
        await open_chat(t)
        await send(t, "Hi")
        assert (await wait_for_reply(t))[-1] == "Hello."
        await send(t, "Remember that the disk is nearly full")
        await t.wait_for_screen("ToolConfirmModal")
        await t.press("y")

        await wait_for_literal_toast(t, LOST, severity="warning")
        await wait_for_reply(t)
        assert await stays_false(t, lambda: len(fake_cloud.ai.chats()) > 3, seconds=1.0)
        assert _requests(fake_cloud) == [
            (CHAT_PATH, "completed"),
            (CHAT_PATH, "completed"),
            (CONTINUE_PATH, "refused:404"),
        ]
        assert fake_cloud.ai.chats()[1]["body"]["conversation_id"]
        assert len(fake_cloud.ai.tool_results("tc-note")) == 1
