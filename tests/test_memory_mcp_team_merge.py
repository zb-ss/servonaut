"""The MCP memory tools run the team-copy merge first when a runner is injected."""
from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.memory.headless_merge import HeadlessTeamMerge
from tests.test_memory_mcp_team_twin import OWN, TWIN
from tests.test_memory_mcp_tools import _make_memory_service, _make_tools, run

ROWS = [OWN, TWIN]


def _tools(order, *, runner=True):
    memory = _make_memory_service()
    memory.remember_finding = MagicMock(
        side_effect=lambda *a, **k: order.append("remember") or {"finding_id": "f_1", "auto_inject": False}
    )
    memory.recall_findings = MagicMock(side_effect=lambda *a, **k: order.append("recall") or [])
    memory.list_all = MagicMock(side_effect=lambda *a, **k: order.append("list") or [])
    memory.get_all_modules = MagicMock(side_effect=lambda *a, **k: order.append("get") or {})
    memory.build_report = AsyncMock(side_effect=lambda *a, **k: order.append("build") or MagicMock(
        successes={}, failures=[], overall_reason=None))
    tools = _make_tools(memory_service=memory, instance_to_find=OWN)
    tools._apply_team_rules = False
    tools._directory.all_instances = AsyncMock(return_value=[OWN])
    tools._shared_server_rows = AsyncMock(return_value=[TWIN])
    tools.connection_rows = AsyncMock(return_value=([TWIN], list(ROWS)))
    if runner:
        merge = MagicMock()
        merge.run = AsyncMock(side_effect=lambda rows: order.append("merge"))
        tools._team_merge = merge
    return tools


CALLS = {
    "get_server_memory": lambda t: t.get_server_memory("web-1"),
    "build_server_memory": lambda t: t.build_server_memory("web-1"),
    "refresh_server_memory": lambda t: t.refresh_server_memory("web-1"),
    "list_server_memories": lambda t: t.list_server_memories(),
    "recall_server_findings": lambda t: t.recall_server_findings("web-1"),
    "remember_server_finding": lambda t: t.remember_server_finding("web-1", "t", "b"),
}


@pytest.mark.parametrize("name", sorted(CALLS))
def test_each_memory_tool_merges_before_it_touches_the_record(name):
    order = []
    tools = _tools(order)
    run(CALLS[name](tools))
    assert order[0] == "merge" and len(order) > 1
    tools._team_merge.run.assert_awaited_with(ROWS)


@pytest.mark.parametrize("name", sorted(CALLS))
def test_without_a_runner_nothing_merges(name):
    order = []
    tools = _tools(order, runner=False)
    run(CALLS[name](tools))
    assert "merge" not in order


def test_a_failing_merge_is_logged_and_the_tool_still_answers(caplog):
    order = []
    tools = _tools(order)
    tools._team_merge.run = AsyncMock(side_effect=RuntimeError("secret detail"))
    with caplog.at_level(logging.WARNING):
        result = run(tools.recall_server_findings("web-1"))
    assert "recall" in order and not result.startswith("Error")
    assert "secret detail" not in caplog.text and "RuntimeError" in caplog.text


def test_unreadable_rows_never_fail_the_tool():
    order = []
    tools = _tools(order)
    tools.connection_rows = AsyncMock(side_effect=RuntimeError("down"))
    run(tools.recall_server_findings("web-1"))
    assert "recall" in order


def test_the_headless_builder_injects_a_runner(monkeypatch, tmp_path):
    from tests.test_mcp_multi_account import build_registry
    from servonaut.mcp.server import build_headless_tools

    config = build_registry(monkeypatch, hetzner={"hetzner": []})[0].config
    config.mcp.audit_path = str(tmp_path / "audit.jsonl")
    manager = MagicMock()
    manager.get.return_value = config
    tools = build_headless_tools(manager)
    assert isinstance(tools._team_merge, HeadlessTeamMerge)


def test_tools_built_without_the_option_have_no_runner():
    assert _make_tools(memory_service=_make_memory_service())._team_merge is None
