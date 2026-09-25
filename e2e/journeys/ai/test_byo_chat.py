"""Journey: chat with your own AI provider (OpenAI, Anthropic or Ollama).

A subscriber who also has their own provider configured opens the chat and
is asked once which one to use. Keeping their own provider saves that
choice; the next question goes to the provider's own API (a local stand-in
reached through the provider base-URL setting) with that provider's key, sent
the way its API expects: a Bearer token for OpenAI and Ollama Cloud,
``x-api-key`` for Anthropic, nothing for a local Ollama. The stand-in refuses
any request its real API would refuse. Switching to Servonaut AI sends the
chat to the service instead.

When the model asks for a read-only tool, the CLI runs it itself and sends
the result back to the model, which then answers. This chat never shows a
confirm prompt: its guard level decides instead, the stats bar names that
level, and a change to it applies to the next call. The model is only offered
the tools that level allows (the dangerous ones are never on its menu), and
commands are limited to allowlisted read-only ones; anything else is
refused before it reaches a server. A provider error ends up in the chat,
not in a crash.

These providers answer in one piece (the product does not stream them), so
the reply appears when the turn is complete.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import fleet
from e2e.harness.ai_chat import (
    busy,
    open_chat,
    plain,
    seed_byo,
    send,
    stats,
    wait_for_reply,
    web_1_server,
)
from e2e.harness.fake_ai import failure, reply, tool_call
from e2e.harness.fake_cloud.chat_script import ChatTurn

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

PROVIDER_LABELS = {"openai": "OpenAI", "anthropic": "Anthropic", "ollama": "Ollama"}
# (provider, key configured, the auth headers its requests must carry)
SETUPS = {
    "openai": ("openai", True, ["authorization"]),
    "anthropic": ("anthropic", True, ["x-api-key"]),
    "ollama-local": ("ollama", False, []),
    "ollama-cloud": ("ollama", True, ["authorization"]),
}
ANSWER = "Three servers are running: app-1, bastion-1 and edge-1."
# Dangerous-tier tools the chat could otherwise offer the model.
DANGEROUS_TOOLS = {"block_ip", "ip_ban_set", "waf_rate_rule_set"}


def _assert_well_formed(fake_ai, provider: str, auth_headers: list[str]) -> None:
    """Every request was one the real API accepts, carrying only its own auth header."""
    for request in fake_ai.requests():
        assert request["provider"] == provider, request
        assert request["problem"] is None, request["problem"]
        assert request["auth_ok"] and request["auth_headers"] == auth_headers, request


def _offered_tools(body: dict) -> set[str]:
    names = set()
    for tool in body.get("tools") or []:
        names.add(tool.get("name") or tool.get("function", {}).get("name"))
    return names


async def _pick_own_provider(t, provider: str, fake_ai) -> None:
    modal = t.screen
    existing = plain(modal.query_one("#ai_picker_existing"))
    if provider == "ollama":
        assert existing == f"Currently configured: Ollama @ {fake_ai.url.split('//', 1)[1]}"
    else:
        assert existing == f"Currently configured: {PROVIDER_LABELS[provider]}"
    assert plain(modal.query_one("#btn_pick_existing")) == f"Keep {PROVIDER_LABELS[provider]}"
    await t.click("#btn_pick_existing")
    await t.wait_for_toast(f"Provider preference set to {provider}.")
    # The prompt closes and the input has the focus.
    await t.wait_until(lambda: t.focused_id() == "chat-input", desc="chat input focused")


@pytest.mark.parametrize("setup", sorted(SETUPS))
async def test_first_run_pick_then_a_tool_round_with_your_own_provider(
    tui, seed, fake_cloud, fake_ai, setup
):
    provider, with_key, auth_headers = SETUPS[setup]
    seed_byo(seed, fake_cloud, provider, fake_ai.url, signed_in=True, with_key=with_key)
    fake_ai.script(provider, tool_call("list_instances"), reply(ANSWER))
    async with tui() as t:
        await open_chat(t, prompt="AIProviderFirstRunModal")
        await _pick_own_provider(t, provider, fake_ai)
        assert seed.read_config()["ai_provider"]["provider_preference"] == provider

        await send(t, "Which servers are running?")
        assert await wait_for_reply(t) == [ANSWER]
        # No prompt for a read-only tool: the turn finished on its own.
        assert t.stack_names()[-1] == "InstanceListScreen"

        first, second = fake_ai.requests(provider)
        _assert_well_formed(fake_ai, provider, auth_headers)
        assert "Which servers are running?" in json.dumps(first["body"])
        offered = _offered_tools(first["body"])
        assert "list_instances" in offered and not offered & DANGEROUS_TOOLS
        # The tool ran locally and its output went back to the model.
        fed_back = json.dumps(second["body"]["messages"][-1])
        for host in fleet.AWS_FLEET:
            assert host.name in fed_back
        assert "Messages: 2" in stats(t)
        assert fake_cloud.ai.chats() == []


async def test_without_a_subscription_the_provider_is_used_directly(
    tui, seed, fake_cloud, fake_ai
):
    seed_byo(seed, fake_cloud, "openai", fake_ai.url, signed_in=False)
    fake_ai.script("openai", reply("Hello from your own model."))
    async with tui() as t:
        await open_chat(t)
        await send(t, "Hello")
        assert await wait_for_reply(t) == ["Hello from your own model."]
        assert t.stack_names()[-1] == "InstanceListScreen"
        _assert_well_formed(fake_ai, "openai", ["authorization"])


@pytest.mark.parametrize("setup", sorted(SETUPS))
async def test_provider_errors_are_shown_in_the_chat(tui, seed, fake_cloud, fake_ai, setup):
    provider, with_key, auth_headers = SETUPS[setup]
    label = PROVIDER_LABELS[provider]
    seed_byo(seed, fake_cloud, provider, fake_ai.url, signed_in=False, with_key=with_key)
    fake_ai.script(provider, failure(429, "Rate limit reached for requests"))
    async with tui() as t:
        await open_chat(t)
        await send(t, "Hello")
        assert await wait_for_reply(t) == [
            f"Error: {label} API error (429): Rate limit reached for requests"
        ]
        # The next message goes through.
        fake_ai.script(provider, reply("Back again."))
        await send(t, "Hello again")
        assert (await wait_for_reply(t))[-1] == "Back again."
        assert not busy(t)
        _assert_well_formed(fake_ai, provider, auth_headers)


async def test_switching_to_servonaut_ai_routes_the_chat_to_the_service(
    tui, seed, fake_cloud, fake_ai
):
    seed_byo(seed, fake_cloud, "openai", fake_ai.url, signed_in=True)
    fake_cloud.ai.script(ChatTurn.fixture("tokens_only"))
    async with tui() as t:
        await open_chat(t, prompt="AIProviderFirstRunModal")
        await t.click("#btn_pick_servonaut")
        await t.wait_for_toast("Provider preference set to servonaut.")
        await t.wait_until(lambda: t.focused_id() == "chat-input", desc="chat input focused")
        assert seed.read_config()["ai_provider"]["provider_preference"] == "servonaut"

        await send(t, "Hello")
        assert await wait_for_reply(t) == ["Hello world, how are you?"]
        assert len(fake_cloud.ai.chats()) == 1 and fake_ai.requests() == []


async def test_commands_from_your_own_model_stay_read_only(
    tui, seed, fake_cloud, fake_ai, journey
):
    """The chat's guard level (standard) lets the model run allowlisted,
    read-only commands without a prompt and refuses anything else before it
    reaches the server."""
    seed_byo(
        seed, fake_cloud, "openai", fake_ai.url, signed_in=False,
        custom_servers=[web_1_server()],
    )
    web_1 = fleet.WEB_1
    journey.shims.when("ssh", rf"{web_1.username}@{web_1.host} .*uptime", stdout=" up 3 days\n")
    fake_ai.script(
        "openai",
        tool_call("run_command", instance_id=web_1.name, command="uptime"),
        tool_call("run_command", instance_id=web_1.name, command="systemctl restart app"),
        reply("web-1 has been up for 3 days; I may not restart services."),
    )
    async with tui() as t:
        await open_chat(t)
        await send(t, "How is web-1?")
        assert (await wait_for_reply(t))[-1].startswith("web-1 has been up for 3 days")
        assert t.stack_names()[-1] == "InstanceListScreen"

        [ssh] = journey.shims.calls("ssh")
        assert ssh.argv[-1].endswith("uptime")
        _, after_uptime, after_restart = fake_ai.requests("openai")
        assert "up 3 days" in after_uptime["body"]["messages"][-1]["content"]
        assert after_restart["body"]["messages"][-1]["content"].startswith("Blocked:")


async def test_the_tool_level_is_shown_and_a_change_applies_to_the_next_call(
    tui, seed, fake_cloud, fake_ai, journey
):
    """The stats bar names the level this chat's tools run at. Lowering it
    (as the AI Chat settings save it) applies to the next turn, without a
    restart: the model is no longer offered commands, and one it asks for
    anyway is refused before it reaches the server."""
    seed_byo(
        seed, fake_cloud, "openai", fake_ai.url, signed_in=False,
        custom_servers=[web_1_server()],
    )
    web_1 = fleet.WEB_1
    journey.shims.when("ssh", rf"{web_1.username}@{web_1.host} .*uptime", stdout=" up 3 days\n")
    uptime = tool_call("run_command", instance_id=web_1.name, command="uptime")
    fake_ai.script("openai", uptime, reply("Up 3 days."), uptime, reply("Not allowed now."))
    async with tui() as t:
        await open_chat(t)
        await send(t, "How long has web-1 been up?")
        assert (await wait_for_reply(t))[-1] == "Up 3 days."
        assert "Tools: standard" in stats(t)
        assert "Tool execution requires Servonaut AI." not in stats(t)
        assert len(journey.shims.calls("ssh")) == 1

        t.app.config_manager.update(chat_tool_guard_level="readonly")
        await send(t, "And now?")
        assert (await wait_for_reply(t))[-1] == "Not allowed now."
        assert "Tools: read-only" in stats(t)
        _, _, ask, refused = fake_ai.requests("openai")
        assert "run_command" not in _offered_tools(ask["body"])
        assert refused["body"]["messages"][-1]["content"].startswith("Blocked:")
        assert len(journey.shims.calls("ssh")) == 1
