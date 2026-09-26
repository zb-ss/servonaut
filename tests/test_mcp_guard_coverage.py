"""Every MCP tool above the readonly tier checks the guard before acting."""
from __future__ import annotations

import ast
import asyncio
import inspect
import json
import shlex
import textwrap
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tool_schemas import TOOL_SCHEMAS
from servonaut.mcp.tools import ServonautTools
from servonaut.services.db_credential_scanner import (
    DBCredentialScanner,
    validate_search_roots,
)
from tests.test_mcp_tools import make_tools

_READONLY = CommandGuard(MCPConfig(guard_level=GuardLevel.READONLY))
_GUARDED_TOOLS = sorted(
    name for name in TOOL_SCHEMAS if not _READONLY.check_tool(name)[0]
)


def _self_calls(function) -> set[str]:
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    return {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "self"
    }


def _checks_guard(name: str, depth: int = 2) -> bool:
    function = getattr(ServonautTools, name)
    source = inspect.getsource(function)
    if "check_tool(" in source:
        return True
    if depth == 0:
        return False
    return any(
        callable(getattr(ServonautTools, called, None)) and _checks_guard(called, depth - 1)
        for called in _self_calls(function)
    )


@pytest.mark.parametrize("name", _GUARDED_TOOLS)
def test_tools_above_readonly_check_the_guard(name):
    assert hasattr(ServonautTools, name), name
    assert _checks_guard(name), f"{name} never calls the guard"


@pytest.fixture
def readonly_tools():
    tools = make_tools(guard_level=GuardLevel.READONLY)
    tools._audit = MagicMock()
    tools._api_request_impl = AsyncMock(side_effect=AssertionError("network used"))
    return tools


@pytest.mark.parametrize(
    ("tool", "kwargs"),
    [
        ("api_request", {"method": "POST", "path": "/api/v1/teams"}),
        ("mcp_tool_call", {"name": "any_tool", "arguments": {"a": 1}}),
        ("relay_reconnect", {"force": True}),
    ],
)
def test_readonly_refuses_backend_tools_without_side_effects(readonly_tools, tool, kwargs):
    result = json.loads(asyncio.run(getattr(readonly_tools, tool)(**kwargs)))

    assert result["error"]["code"] == "guard_denied"
    readonly_tools._api_request_impl.assert_not_called()
    audit_call = readonly_tools._audit.log.call_args
    assert audit_call.args[0] == tool
    assert audit_call.args[3] is False


def test_get_logs_quotes_the_path_and_validates_lines():
    tools = make_tools()
    tools.run_command = AsyncMock(return_value="ok")
    path = "/var/log/app one.log; id"

    asyncio.run(tools.get_logs("i-abc123", log_path=path, lines=25))

    command = tools.run_command.call_args.args[1]
    assert command == f"tail -n 25 -- {shlex.quote(path)}"
    assert shlex.split(command)[-1] == path


@pytest.mark.parametrize("lines", ["ten", 0, 10001, "5; id"])
def test_get_logs_refuses_invalid_line_counts(lines):
    tools = make_tools()
    tools.run_command = AsyncMock(return_value="ok")

    result = asyncio.run(tools.get_logs("i-abc123", lines=lines))

    assert result.startswith("validation:")
    tools.run_command.assert_not_called()


def test_web_traffic_summary_prints_the_marker_from_the_quoted_path():
    tools = make_tools(guard_level=GuardLevel.READONLY)
    tools._find_instance = AsyncMock(return_value={"id": "i-1", "name": "web-1"})
    tools._exec_ssh = AsyncMock(return_value=("", ""))
    path = '/var/log/x".log'

    asyncio.run(tools.web_traffic_summary("web-1", log_path=path))

    remote = tools._exec_ssh.call_args.args[1]
    quoted = shlex.quote(path)
    assert remote.startswith(f"printf '===VHOST:%s===\\n' {quoted};")
    assert path not in remote.replace(quoted, "")


@pytest.mark.parametrize(
    "search_path",
    ["-exec id", "/srv;id", "/srv && id", "$(id)", "/srv`id`", "/srv|id", "/srv > /tmp/x"],
)
def test_scan_roots_refuse_non_paths(search_path):
    with pytest.raises(ValueError):
        validate_search_roots(search_path)


def test_scan_roots_accept_paths_globs_and_home():
    roots = validate_search_roots("/home/*/public_html ~/sites /var/www")
    assert roots == ["/home/*/public_html", "~/sites", "/var/www"]
    command = DBCredentialScanner.build_scan_command("/home/*/public_html")
    assert command.startswith("for d in /home/*/public_html; do")


def test_db_setup_scan_refuses_invalid_roots_before_connecting():
    tools = make_tools()
    tools._audit = MagicMock()
    tools._find_instance = AsyncMock(side_effect=AssertionError("instance lookup"))

    result = asyncio.run(tools.db_setup_scan("i-abc123", search_path="/srv;id"))

    assert result.startswith("validation:")
    assert tools._audit.log.call_args.args[3] is False


def test_run_command_executes_the_rebuilt_standard_command():
    tools = make_tools()
    tools._run_command_via_ssh = AsyncMock(side_effect=RuntimeError("stop after capture"))

    try:
        asyncio.run(tools.run_command("i-abc123", 'grep "$HOME" /etc/profile', transport="ssh"))
    except RuntimeError:
        pass

    executed = tools._run_command_via_ssh.call_args.args[1]
    assert executed == "grep '$HOME' /etc/profile"


@pytest.mark.parametrize(
    ("tool", "kwargs"),
    [
        ("check_status", {"instance_id": "no-such-host"}),
        ("get_server_info", {"instance_id": "no-such-host"}),
        (
            "transfer_file",
            {"instance_id": "no-such-host", "local_path": "/tmp/a", "remote_path": "/tmp/b"},
        ),
    ],
)
def test_unknown_instance_is_audited(tool, kwargs):
    tools = make_tools(guard_level=GuardLevel.DANGEROUS)
    tools._audit = MagicMock()
    tools._find_instance = AsyncMock(return_value=None)

    result = asyncio.run(getattr(tools, tool)(**kwargs))

    assert result.startswith("Instance not found")
    audit_call = tools._audit.log.call_args
    assert audit_call.args[0] == tool
    assert audit_call.args[3] is False
    assert audit_call.args[4] == "instance_not_found"
