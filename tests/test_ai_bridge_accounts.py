"""The ``account`` argument through the AI chat tool paths."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from servonaut.mcp.tool_schemas import chat_tool_list
from servonaut.services.ai_tool_bridge import (
    AIToolBridge,
    ToolCall,
    _split_supported_args,
)
from tests._account_fixtures import build_registry, make_tools


def _run(coro):
    return asyncio.run(coro)


def _bridge(tools):
    auth = MagicMock()
    auth.has_dangerous_ai_tools = True
    api = MagicMock()
    api.post = AsyncMock(return_value={})
    return AIToolBridge(
        api_client=api,
        relay_executors=MagicMock(),
        mcp_audit=MagicMock(),
        confirm_callback=AsyncMock(return_value=True),
        auth_service=auth,
        servonaut_tools=tools,
    )


def _call(tool, **args):
    return ToolCall(
        tool_call_id="tc-1", tool=tool, args=args,
        guard_level="dangerous", conversation_id="conv-1",
    )


def _tools_with_two_projects(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        hetzner={
            "hetzner": [{"id": "1", "name": "web-1", "is_hetzner": True}],
            "staging": [{"id": "2", "name": "web-1", "is_hetzner": True}],
        },
    )
    return make_tools(registry), services


def test_hosted_ai_call_with_account_reaches_the_handler(monkeypatch):
    tools, services = _tools_with_two_projects(monkeypatch)
    result = _run(_bridge(tools).handle_tool_call(
        _call("hetzner_power_on", identifier="web-1", account="staging"),
    ))
    assert result.status == "ok"
    assert result.result == "Hetzner server 'web-1': started."
    assert services[("hetzner", "staging")].called("power_on") == [("web-1",)]
    assert services[("hetzner", "hetzner")].called("power_on") == []


def test_hosted_ai_list_instances_filters_by_account(monkeypatch):
    tools, _ = _tools_with_two_projects(monkeypatch)
    result = _run(_bridge(tools).handle_tool_call(
        _call("list_instances", account="staging"),
    ))
    assert result.status == "ok"
    assert "staging/web-1" in result.result and "hetzner/web-1" not in result.result


def test_hosted_ai_ambiguous_name_reports_the_candidates(monkeypatch):
    tools, services = _tools_with_two_projects(monkeypatch)
    result = _run(_bridge(tools).handle_tool_call(
        _call("hetzner_reboot", identifier="web-1"),
    ))
    assert "hetzner/web-1" in result.result and "staging/web-1" in result.result
    assert all(not s.called("reboot") for s in services.values())


def test_account_is_a_supported_argument_of_the_real_handlers(monkeypatch):
    tools, _ = _tools_with_two_projects(monkeypatch)
    accepted, dropped = _split_supported_args(
        tools.cloudwatch_top_ips, {"log_group": "g", "account": "prod"},
    )
    assert accepted == {"log_group": "g", "account": "prod"} and dropped == []


def test_local_provider_chat_schemas_expose_account():
    by_name = {tool["name"]: tool for tool in chat_tool_list()}
    for name in ("list_instances", "hetzner_list_servers", "aws_list_regions",
                 "cloudwatch_top_ips", "s3_list_buckets"):
        assert "account" in by_name[name]["parameters"]["properties"], name

