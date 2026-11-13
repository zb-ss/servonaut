"""``ssh_exec_readonly`` only runs without asking when the command is read-only."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.models.relay_messages import CommandResponse
from servonaut.services.ai_tool_bridge import AIToolBridge, ToolCall


def run(coro):
    return asyncio.run(coro)


def _bridge(*, confirm=True, dangerous=True, allowlist: Any = "default"):
    relay = MagicMock()
    relay.execute = AsyncMock(
        side_effect=lambda req: CommandResponse(
            request_id=req.id, status="success", output="done",
        )
    )
    audit = MagicMock()
    confirm_mock = AsyncMock(return_value=confirm)
    auth = MagicMock()
    auth.has_dangerous_ai_tools = dangerous
    getter = None if allowlist == "default" else (lambda: allowlist)
    bridge = AIToolBridge(
        api_client=MagicMock(),
        relay_executors=relay,
        mcp_audit=audit,
        confirm_callback=confirm_mock,
        auth_service=auth,
        readonly_commands=getter,
    )
    return bridge, relay, audit, confirm_mock


def _call(command: Any, tool: str = "ssh_exec_readonly", guard: str = "readonly"):
    args: Dict[str, Any] = {"instance_id": "web-1"}
    if command is not None:
        args["command"] = command
    return ToolCall(
        tool_call_id="tc-1", tool=tool, args=args,
        guard_level=guard, conversation_id="conv-1",  # type: ignore[arg-type]
    )


def _rows(audit) -> List[tuple]:
    return [(c.args[4], c.kwargs) for c in audit.log.call_args_list]


def _sent(relay) -> str:
    return relay.execute.await_args.args[0].payload["command"]


def test_allowlisted_command_runs_without_a_prompt():
    bridge, relay, audit, confirm = _bridge()
    result = run(bridge.handle_tool_call(_call("uptime")))
    assert result.status == "ok"
    confirm.assert_not_called()
    assert _sent(relay) == "uptime"
    reason, extras = _rows(audit)[-1]
    assert reason == "ok" and extras["readonly_check"] == "allowlisted"


NOT_READ_ONLY = [
    "ls; id", "ls && id", "ls || id", "ls | sh", "ls | xargs rm", "ls `id`",
    "ls $(id)", "ls ${HOME}", "ls > /tmp/x", "cat < /etc/passwd", "ls 2>&1",
    "ls\nid", "sudo ls", "sudo -u root ls", "FOO=1 ls", "env ls",
    "find / -exec id ;", "find / -delete", "sort -o /tmp/x f", "'ls;id'",
    "rm -f x", "systemctl status nginx", 'ls "unbalanced',
]


@pytest.mark.parametrize("command", NOT_READ_ONLY)
def test_command_outside_the_list_asks_at_the_run_command_level(command):
    bridge, relay, _audit, confirm = _bridge(confirm=False)
    result = run(bridge.handle_tool_call(_call(command)))
    assert result.status == "denied"
    confirm.assert_awaited_once()
    asked = confirm.await_args.args[0]
    assert asked.guard_level == "dangerous"
    assert asked.confirm_note
    relay.execute.assert_not_called()


def test_approved_command_outside_the_list_runs_as_written():
    bridge, relay, audit, confirm = _bridge(confirm=True)
    result = run(bridge.handle_tool_call(_call("ls; id")))
    assert result.status == "ok"
    confirm.assert_awaited_once()
    assert _sent(relay) == "ls; id"
    rows = dict((reason, extras) for reason, extras in _rows(audit))
    assert rows["readonly_command_not_allowlisted"]["check_reason"]
    assert rows["readonly_command_not_allowlisted"]["effective_tier"] == "dangerous"
    assert rows["ok"]["readonly_check"] == "approved"


def test_declined_row_records_the_check():
    bridge, _relay, audit, _confirm = _bridge(confirm=False)
    run(bridge.handle_tool_call(_call("ls; id")))
    reason, extras = _rows(audit)[-1]
    assert reason == "user_declined"
    assert extras["guard_level"] == "dangerous"
    assert extras["readonly_check"] == "needs_approval"


def test_without_the_dangerous_entitlement_it_is_refused_with_the_reason():
    bridge, relay, audit, confirm = _bridge(dangerous=False)
    result = run(bridge.handle_tool_call(_call("ls; id")))
    assert result.status == "denied"
    assert "read-only command list" in result.result
    assert "dangerous tools are not enabled" in result.result
    confirm.assert_not_called()
    relay.execute.assert_not_called()
    assert _rows(audit)[-1][0] == "readonly_command_dangerous_disallowed"


@pytest.mark.parametrize("command", [None, "", "   ", 5, ["ls"]])
def test_missing_or_non_string_command_is_an_error(command):
    bridge, relay, audit, confirm = _bridge()
    call = _call(command)
    if command is None:
        pass
    else:
        call.args["command"] = command
    result = run(bridge.handle_tool_call(call))
    assert result.status == "error"
    assert result.result == "ssh_exec_readonly needs a command."
    assert _rows(audit)[-1][0] == "readonly_command_missing"
    confirm.assert_not_called()
    relay.execute.assert_not_called()


def test_the_escalated_level_comes_from_run_command():
    bridge, _relay, _audit, confirm = _bridge(confirm=False)
    with patch(
        "servonaut.services.dangerous_tool_floor.is_dangerous_floor",
        return_value=False,
    ):
        run(bridge.handle_tool_call(_call("ls; id")))
    assert confirm.await_args.args[0].guard_level == "standard"


def test_the_list_from_config_is_read_on_every_call():
    current: Dict[str, Any] = {"value": ["ls", "systemctl"]}
    bridge, relay, _audit, confirm = _bridge()
    bridge._readonly_commands = lambda: current["value"]
    run(bridge.handle_tool_call(_call("systemctl status nginx")))
    confirm.assert_not_called()
    assert relay.execute.await_count == 1

    current["value"] = "uptime"  # not a list: every command asks
    bridge2_call = _call("uptime")
    bridge2_call.tool_call_id = "tc-2"
    bridge2_call.args["command"] = "uptime"
    run(bridge.handle_tool_call(bridge2_call))
    confirm.assert_awaited_once()


def test_what_is_sent_is_rebuilt_from_the_checked_words_and_is_stable():
    from servonaut.mcp.guards import check_standard_command, render_standard_command

    bridge, relay, _audit, _confirm = _bridge()
    run(bridge.handle_tool_call(_call('grep  "a b"   /var/log/syslog')))
    sent = _sent(relay)
    assert sent == "grep 'a b' /var/log/syslog"
    assert sent == render_standard_command('grep  "a b"   /var/log/syslog')
    assert render_standard_command(sent) == sent
    assert check_standard_command(sent, ["grep"])[0]


def test_other_tools_are_unchanged():
    bridge, relay, _audit, confirm = _bridge()
    result = run(bridge.handle_tool_call(
        _call("ls; id", tool="run_command", guard="standard")
    ))
    assert result.status == "ok"
    confirm.assert_awaited_once()
    assert confirm.await_args.args[0].readonly_check == ""
    assert _sent(relay) == "ls; id"

    bridge, relay, _audit, confirm = _bridge()
    call = ToolCall(
        tool_call_id="tc-9", tool="tail_log",
        args={"instance_id": "web-1", "log_path": "/var/log/syslog"},
        guard_level="readonly", conversation_id="conv-1",
    )
    assert run(bridge.handle_tool_call(call)).status == "ok"
    confirm.assert_not_called()


def test_checked_command_is_ignored_for_other_command_tools():
    for tool, guard in (("run_command", "standard"), ("deploy", "dangerous")):
        bridge, relay, _audit, _confirm = _bridge()
        call = _call("uptime", tool=tool, guard=guard)
        call.checked_command = "touch /tmp/marker"
        run(bridge.handle_tool_call(call))
        assert _sent(relay) == "uptime"


def test_a_preset_checked_command_does_not_survive_the_gate():
    bridge, relay, _audit, _confirm = _bridge(confirm=True)
    call = _call("ls; id")
    call.checked_command = "touch /tmp/marker"
    run(bridge.handle_tool_call(call))
    assert _sent(relay) == "ls; id"


def test_the_chat_default_list_leaves_out_name_lookups_and_ping():
    from servonaut.config.schema import (
        AIProviderConfig, DEFAULT_READONLY_COMMANDS, MCPConfig,
    )

    for command in ("dig example.org", "nslookup example.org", "ping -c1 web-1"):
        bridge, relay, _audit, confirm = _bridge(confirm=False)
        run(bridge.handle_tool_call(_call(command)))
        confirm.assert_awaited_once()
        relay.execute.assert_not_called()
    names = AIProviderConfig().readonly_command_allowlist
    assert not {"dig", "nslookup", "ping"} & set(names)
    assert {"dig", "nslookup", "ping"} <= set(MCPConfig().command_allowlist)
    assert len(DEFAULT_READONLY_COMMANDS) == 28 and len(names) == 25


def test_the_level_never_drops_when_the_run_command_level_is_lower():
    bridge, _relay, _audit, confirm = _bridge(confirm=False)
    with patch(
        "servonaut.services.dangerous_tool_floor.is_dangerous_floor",
        return_value=False,
    ):
        run(bridge.handle_tool_call(_call("ls; id", guard="dangerous")))
    assert confirm.await_args.args[0].guard_level == "dangerous"


@pytest.mark.asyncio
@pytest.mark.parametrize("modal_name", ["standard", "dangerous"])
async def test_the_dialog_shows_the_rebuilt_command_that_will_run(modal_name):
    from textual.app import App

    from servonaut.screens.tool_confirm_modal import build_modal_confirm

    seen = {}

    class _Host(App):
        async def push_screen_wait(self, modal):
            seen["args"] = modal._args
            return True

    call = _call('grep  "a b"   f', guard=modal_name)
    call.checked_command = "grep 'a b' f"
    call.readonly_check = "allowlisted"
    assert await build_modal_confirm(_Host())(call) is True
    assert seen["args"]["command"] == "grep 'a b' f"


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["run_command", "deploy"])
async def test_the_dialog_ignores_a_preset_checked_command_on_other_tools(tool):
    from textual.app import App

    from servonaut.screens.tool_confirm_modal import build_modal_confirm

    seen = {}

    class _Host(App):
        async def push_screen_wait(self, modal):
            seen["args"] = modal._args
            return True

    call = _call("touch /tmp/marker", tool=tool, guard="dangerous")
    call.checked_command = "uptime"
    assert await build_modal_confirm(_Host())(call) is True
    assert seen["args"]["command"] == "touch /tmp/marker"
    bridge, relay, _audit, _confirm = _bridge()
    await bridge.handle_tool_call(call)
    assert _sent(relay) == "touch /tmp/marker"
