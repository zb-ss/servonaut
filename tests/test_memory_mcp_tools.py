"""Unit tests for the server-memory MCP tools (T5).

Covers:
  - get_server_memory: all three formats (summary / markdown / full)
  - get_server_memory: opt-out path → JSON error envelope, audit success=False
  - get_server_memory: guard-blocked path → "Blocked: ..." string
  - get_server_memory: instance not found path
  - get_server_memory: memory_service=None defensive guard
  - refresh_server_memory: happy path → JSON with refreshed + count
  - refresh_server_memory: opt-out path → JSON error envelope
  - refresh_server_memory: guard-blocked path
  - list_server_memories: stale_only=False → all entries
  - list_server_memories: stale_only=True → only entries with stale modules
  - list_server_memories: guard-blocked path
  - Every code path asserts that audit.log was called.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig, MCPConfig, MemoryConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools
from servonaut.services.memory.service import BuildReport, ModuleBuildFailure


# ---------------------------------------------------------------------------
# Canned fixtures
# ---------------------------------------------------------------------------

_CANNED_INSTANCE: Dict[str, Any] = {
    "id": "i-abc123",
    "name": "web-server-prod",
    "type": "t3.medium",
    "state": "running",
    "public_ip": "54.1.2.3",
    "private_ip": "10.0.0.1",
    "region": "us-east-1",
    "key_name": "prod-key",
    "provider": "aws",
}

_CANNED_INSTANCE_CUSTOM: Dict[str, Any] = {
    "id": "my-custom-box",
    "name": "my-custom-box",
    "type": "custom",
    "state": "unknown",
    "public_ip": "1.2.3.4",
    "provider": "custom",
    "is_custom": True,
}


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def _make_memory_service(
    summary_return: str = "## Summary\nsome content",
    list_all_return: Optional[List[Dict]] = None,
    refresh_return: Optional[Dict] = None,
    build_report_return: Optional[BuildReport] = None,
    get_all_modules_return: Optional[Dict] = None,
) -> MagicMock:
    """Create a mock MemoryService with sensible defaults.

    build_report_return wins over refresh_return when supplied; otherwise
    refresh_return is mirrored into the BuildReport so legacy test call-sites
    keep working after the MCP tools moved to build_report().
    """
    # ``None`` → seed default; empty-dict callers (tests simulating "no memory
    # stored") must be honoured literally, so use explicit None check.
    if get_all_modules_return is None:
        modules_data: Dict[str, Any] = {
            "os": {"module": "os", "observed": {"kernel": "Linux 6.8"}},
        }
    else:
        modules_data = get_all_modules_return
    refresh_result = refresh_return or {"os": MagicMock()}
    svc = MagicMock()
    svc.get_summary = AsyncMock(return_value=summary_return)
    svc.refresh = AsyncMock(return_value=refresh_result)

    # MCP tools prefer build_report; mirror refresh_return into a BuildReport
    # so existing tests that pass refresh_return keep describing the same
    # happy-path shape.
    if build_report_return is None:
        build_report_return = BuildReport(
            successes=dict(refresh_result),
            failures=[],
            overall_reason=None,
        )
    svc.build_report = AsyncMock(return_value=build_report_return)

    store = MagicMock()
    store.get_all_modules.return_value = modules_data
    store.stale_modules.return_value = []
    svc._store = store

    # Wire the public methods (B.2) — tools.py now calls these instead of _store.*.
    svc.get_all_modules = MagicMock(return_value=modules_data)
    svc.stale_modules = MagicMock(return_value=[])

    svc.list_all.return_value = list_all_return or []
    return svc


def _make_tools(
    guard_level: GuardLevel = GuardLevel.STANDARD,
    memory_service: Any = None,
    instance_to_find: Optional[Dict[str, Any]] = _CANNED_INSTANCE,
    memory_config: Optional[MemoryConfig] = None,
) -> ServonautTools:
    """Construct a ServonautTools with all services mocked."""
    mem_cfg = memory_config or MemoryConfig(enabled=True)
    app_config = AppConfig(mcp=MCPConfig(guard_level=guard_level), memory=mem_cfg)
    config_manager = MagicMock()
    config_manager.get.return_value = app_config

    aws_service = MagicMock()
    aws_service.fetch_instances_cached = AsyncMock(return_value=[])

    custom_server_service = MagicMock()
    custom_server_service.list_as_instances.return_value = []

    cache_service = MagicMock()
    ssh_service = MagicMock()
    connection_service = MagicMock()
    scp_service = MagicMock()
    ovh_service = MagicMock()
    ovh_service.fetch_instances_cached = AsyncMock(return_value=[])

    guard = CommandGuard(app_config.mcp)
    audit = MagicMock()
    audit.log = MagicMock()

    tools = ServonautTools(
        config_manager, aws_service, custom_server_service, cache_service,
        ssh_service, connection_service, scp_service,
        guard, audit,
        ovh_service=ovh_service,
        memory_service=memory_service,
    )

    # Short-circuit _find_instance so tests don't need real AWS/OVH wiring.
    async def _fake_find_instance(instance_id: str) -> Optional[Dict[str, Any]]:
        if instance_to_find is None:
            return None
        # Match by id or name (case-insensitive), same contract as real impl.
        needle = instance_id.lower()
        iid = instance_to_find.get("id", "")
        name = instance_to_find.get("name", "")
        if (iid == instance_id or iid.lower() == needle
                or name == instance_id or name.lower() == needle):
            return instance_to_find
        return None

    tools._find_instance = _fake_find_instance  # type: ignore[method-assign]
    return tools


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# get_server_memory — format dispatch
# ---------------------------------------------------------------------------

class TestGetServerMemorySummary:
    """get_server_memory with format='summary' (default)."""

    def test_calls_get_summary_with_1500_tokens(self):
        mem_svc = _make_memory_service(summary_return="# Summary\nkernel: Linux")
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.get_server_memory("i-abc123", format="summary"))

        assert "kernel: Linux" in result
        mem_svc.get_summary.assert_awaited_once()
        _, kwargs = mem_svc.get_summary.call_args
        assert kwargs.get("max_tokens") == 1500 or mem_svc.get_summary.call_args[0][1] == 1500

    def test_audit_logged_success(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(memory_service=mem_svc)
        run(tools.get_server_memory("i-abc123"))

        tools._audit.log.assert_called_once()
        call = tools._audit.log.call_args
        assert call[0][0] == "get_server_memory"
        # success=True is the 4th positional arg (index 3)
        assert call[0][3] is True

    def test_default_format_is_summary(self):
        """Calling without format= should behave as format='summary'."""
        mem_svc = _make_memory_service(summary_return="summary-content")
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.get_server_memory("i-abc123"))
        assert "summary-content" in result
        mem_svc.get_summary.assert_awaited_once()


class TestGetServerMemoryMarkdown:
    """get_server_memory with format='markdown'."""

    def test_calls_get_summary_with_large_tokens(self):
        mem_svc = _make_memory_service(summary_return="# Full markdown")
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.get_server_memory("i-abc123", format="markdown"))

        assert "# Full markdown" in result
        mem_svc.get_summary.assert_awaited_once()
        # The max_tokens arg should be 1_000_000 (effectively unbounded)
        args, kwargs = mem_svc.get_summary.call_args
        max_tokens = kwargs.get("max_tokens") or (args[1] if len(args) > 1 else None)
        assert max_tokens == 1_000_000

    def test_audit_logged_success(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(memory_service=mem_svc)
        run(tools.get_server_memory("i-abc123", format="markdown"))
        call = tools._audit.log.call_args
        assert call[0][0] == "get_server_memory"
        assert call[0][3] is True


class TestGetServerMemoryFull:
    """get_server_memory with format='full'."""

    def test_calls_get_all_modules(self):
        modules_data = {
            "os": {"module": "os", "observed": {"kernel": "6.8.0"}},
            "runtimes": {"module": "runtimes", "observed": {"python": "3.11"}},
        }
        mem_svc = _make_memory_service(get_all_modules_return=modules_data)
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.get_server_memory("i-abc123", format="full"))

        parsed = json.loads(result)
        # C.2: result is wrapped in {"instance_id": ..., "modules": {...}}
        modules = parsed.get("modules", parsed)
        assert "os" in modules
        assert "runtimes" in modules
        mem_svc.get_all_modules.assert_called_once()
        # get_summary must NOT be called for full format
        mem_svc.get_summary.assert_not_awaited()

    def test_audit_logged_success(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(memory_service=mem_svc)
        run(tools.get_server_memory("i-abc123", format="full"))
        call = tools._audit.log.call_args
        assert call[0][0] == "get_server_memory"
        assert call[0][3] is True


class TestGetServerMemoryContextBlock:
    """get_server_memory with format='context_block' — same envelope the
    Servonaut chat client injects."""

    def test_returns_context_envelope(self):
        from datetime import datetime, timezone
        modules_data = {
            "os": {
                "module": "os",
                "instance_id": "i-abc123",
                "probed_at": datetime.now(timezone.utc).isoformat(),
                "ttl_seconds": 86400,
                "sudo_used": False,
                "truncated": False,
                "partial": False,
                "observed": {"distro": "Ubuntu", "version": "24.04"},
                "declared": {},
                "raw_output": "",
            },
        }
        mem_svc = _make_memory_service(get_all_modules_return=modules_data)
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.get_server_memory("i-abc123", format="context_block"))

        assert result.startswith('<CONTEXT name="server_memory:i-abc123"')
        assert 'snapshot_at="' in result
        assert "Ubuntu" in result
        assert result.rstrip().endswith("</CONTEXT>")

    def test_audit_logged_success(self):
        from datetime import datetime, timezone
        modules_data = {
            "os": {
                "module": "os",
                "instance_id": "i-abc123",
                "probed_at": datetime.now(timezone.utc).isoformat(),
                "ttl_seconds": 86400,
                "observed": {"distro": "Ubuntu"},
                "declared": {},
                "raw_output": "",
                "partial": False, "sudo_used": False, "truncated": False,
            },
        }
        mem_svc = _make_memory_service(get_all_modules_return=modules_data)
        tools = _make_tools(memory_service=mem_svc)
        run(tools.get_server_memory("i-abc123", format="context_block"))
        call = tools._audit.log.call_args
        assert call[0][0] == "get_server_memory"
        assert call[0][3] is True


# ---------------------------------------------------------------------------
# get_server_memory — opt-out
# ---------------------------------------------------------------------------

class TestGetServerMemoryOptOut:
    """get_server_memory with memory disabled returns JSON error envelope."""

    def _opt_out_config(self, instance_id: str = "i-abc123") -> MemoryConfig:
        return MemoryConfig(
            enabled=True,
            per_server_overrides={instance_id: {"memory_disabled": True}},
        )

    def test_returns_opt_out_json(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(
            memory_service=mem_svc,
            memory_config=self._opt_out_config(),
        )

        result = run(tools.get_server_memory("i-abc123"))

        parsed = json.loads(result)
        assert parsed["error"]["code"] == "opt_out"

    def test_opt_out_via_enabled_false(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(
            memory_service=mem_svc,
            memory_config=MemoryConfig(enabled=False),
        )

        result = run(tools.get_server_memory("i-abc123"))
        parsed = json.loads(result)
        assert parsed["error"]["code"] == "opt_out"

    def test_audit_logged_failure_with_opt_out_reason(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(
            memory_service=mem_svc,
            memory_config=self._opt_out_config(),
        )

        run(tools.get_server_memory("i-abc123"))

        call = tools._audit.log.call_args
        assert call[0][0] == "get_server_memory"
        # success=False (4th positional arg)
        assert call[0][3] is False
        # reason=opt_out (5th positional arg)
        assert call[0][4] == "opt_out"

    def test_no_get_summary_called_on_opt_out(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(
            memory_service=mem_svc,
            memory_config=self._opt_out_config(),
        )
        run(tools.get_server_memory("i-abc123"))
        mem_svc.get_summary.assert_not_awaited()


# ---------------------------------------------------------------------------
# get_server_memory — guard block
# ---------------------------------------------------------------------------

class TestGetServerMemoryGuardBlocked:
    def test_blocked_returns_blocked_prefix(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(
            memory_service=mem_svc,
            guard_level=GuardLevel.READONLY,
        )
        # READONLY guard should allow get_server_memory (it's a read op),
        # so instead we patch the guard directly.
        tools._guard = MagicMock()
        tools._guard.check_tool.return_value = (False, "tool not allowed in policy")

        result = run(tools.get_server_memory("i-abc123"))

        assert result.startswith("Blocked: ")
        assert "tool not allowed in policy" in result

    def test_audit_logged_on_block(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(memory_service=mem_svc)
        tools._guard = MagicMock()
        tools._guard.check_tool.return_value = (False, "blocked reason")

        run(tools.get_server_memory("i-abc123"))

        call = tools._audit.log.call_args
        assert call[0][0] == "get_server_memory"
        assert call[0][3] is False


# ---------------------------------------------------------------------------
# get_server_memory — edge cases
# ---------------------------------------------------------------------------

class TestGetServerMemoryEdgeCases:
    def test_instance_not_found(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(memory_service=mem_svc, instance_to_find=None)

        result = run(tools.get_server_memory("unknown-id"))

        assert "not found" in result.lower()

    def test_memory_service_none_returns_error(self):
        tools = _make_tools(memory_service=None)

        result = run(tools.get_server_memory("i-abc123"))

        assert "memory subsystem not wired" in result


# ---------------------------------------------------------------------------
# refresh_server_memory
# ---------------------------------------------------------------------------

class TestRefreshServerMemory:
    """refresh_server_memory happy path and opt-out."""

    def test_happy_path_returns_refreshed_list(self):
        mem_svc = _make_memory_service(
            refresh_return={"os": MagicMock(), "runtimes": MagicMock()}
        )
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.refresh_server_memory("i-abc123"))

        parsed = json.loads(result)
        assert set(parsed["successes"]) == {"os", "runtimes"}
        assert parsed["count"] == 2
        assert parsed["failures"] == []
        assert parsed["instance_id"] == "i-abc123"
        assert "reason" not in parsed

    def test_refresh_called_with_modules_arg(self):
        mem_svc = _make_memory_service(refresh_return={"os": MagicMock()})
        tools = _make_tools(memory_service=mem_svc)

        run(tools.refresh_server_memory("i-abc123", modules=["os"]))

        mem_svc.build_report.assert_awaited_once()
        call_args, call_kwargs = mem_svc.build_report.call_args
        # modules may be positional or keyword depending on call
        modules_passed = call_kwargs.get("modules") or (call_args[1] if len(call_args) > 1 else None)
        assert modules_passed == ["os"]

    def test_audit_logged_success(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(memory_service=mem_svc)
        run(tools.refresh_server_memory("i-abc123"))

        call = tools._audit.log.call_args
        assert call[0][0] == "refresh_server_memory"
        assert call[0][3] is True

    def test_opt_out_returns_json_error(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(
            memory_service=mem_svc,
            memory_config=MemoryConfig(
                enabled=True,
                per_server_overrides={"i-abc123": {"memory_disabled": True}},
            ),
        )

        result = run(tools.refresh_server_memory("i-abc123"))
        parsed = json.loads(result)
        assert parsed["error"]["code"] == "opt_out"

    def test_opt_out_audit_logged_failure(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(
            memory_service=mem_svc,
            memory_config=MemoryConfig(
                enabled=True,
                per_server_overrides={"i-abc123": {"memory_disabled": True}},
            ),
        )

        run(tools.refresh_server_memory("i-abc123"))

        call = tools._audit.log.call_args
        assert call[0][0] == "refresh_server_memory"
        assert call[0][3] is False
        assert call[0][4] == "opt_out"

    def test_guard_blocked(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(memory_service=mem_svc)
        tools._guard = MagicMock()
        tools._guard.check_tool.return_value = (False, "refresh blocked")

        result = run(tools.refresh_server_memory("i-abc123"))

        assert result.startswith("Blocked: ")
        call = tools._audit.log.call_args
        assert call[0][3] is False

    def test_instance_not_found(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(memory_service=mem_svc, instance_to_find=None)

        result = run(tools.refresh_server_memory("nonexistent"))
        assert "not found" in result.lower()

    def test_memory_service_none_returns_error(self):
        tools = _make_tools(memory_service=None)
        result = run(tools.refresh_server_memory("i-abc123"))
        assert "memory subsystem not wired" in result

    def test_all_probers_failed_reports_structured_failures(self):
        report = BuildReport(
            successes={},
            failures=[
                ModuleBuildFailure(module="os", reason="exception",
                                   message="Connection refused"),
                ModuleBuildFailure(module="runtimes", reason="exception",
                                   message="Connection refused"),
            ],
            overall_reason="all_probers_failed",
        )
        mem_svc = _make_memory_service(build_report_return=report)
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.refresh_server_memory("i-abc123"))
        parsed = json.loads(result)

        assert parsed["count"] == 0
        assert parsed["successes"] == []
        assert {f["module"] for f in parsed["failures"]} == {"os", "runtimes"}
        assert all(f["reason"] == "exception" for f in parsed["failures"])
        assert parsed["reason"] == "all_probers_failed"
        assert "SSH" in parsed["message"] or "ssh" in parsed["message"].lower()

        # Audit entry for count=0 is logged as unsuccessful with the reason.
        call = tools._audit.log.call_args
        assert call[0][0] == "refresh_server_memory"
        assert call[0][3] is False
        assert call[0][4] == "all_probers_failed"


# ---------------------------------------------------------------------------
# build_server_memory — semantic alias for refresh used on first-time builds.
# ---------------------------------------------------------------------------

class TestBuildServerMemory:
    """build_server_memory must share the refresh flow and surface failures."""

    def test_happy_path_returns_successes_and_count(self):
        mem_svc = _make_memory_service(
            refresh_return={"os": MagicMock(), "runtimes": MagicMock()}
        )
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.build_server_memory("i-abc123"))
        parsed = json.loads(result)

        assert parsed["instance_id"] == "i-abc123"
        assert set(parsed["successes"]) == {"os", "runtimes"}
        assert parsed["count"] == 2
        assert parsed["failures"] == []
        mem_svc.build_report.assert_awaited_once()

    def test_all_probers_failed_returns_reason(self):
        report = BuildReport(
            successes={},
            failures=[
                ModuleBuildFailure(module="os", reason="exception",
                                   message="Permission denied"),
            ],
            overall_reason="all_probers_failed",
        )
        mem_svc = _make_memory_service(build_report_return=report)
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.build_server_memory("i-abc123"))
        parsed = json.loads(result)

        assert parsed["count"] == 0
        assert parsed["reason"] == "all_probers_failed"
        assert parsed["failures"][0]["module"] == "os"
        assert parsed["failures"][0]["message"] == "Permission denied"

    def test_opt_out_returns_error_envelope(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(
            memory_service=mem_svc,
            memory_config=MemoryConfig(
                enabled=True,
                per_server_overrides={"i-abc123": {"memory_disabled": True}},
            ),
        )
        result = run(tools.build_server_memory("i-abc123"))
        parsed = json.loads(result)
        assert parsed["error"]["code"] == "opt_out"

    def test_guard_blocks_build(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(memory_service=mem_svc)
        tools._guard = MagicMock()
        tools._guard.check_tool.return_value = (False, "build blocked")

        result = run(tools.build_server_memory("i-abc123"))
        assert result.startswith("Blocked: ")

    def test_memory_service_none_returns_error(self):
        tools = _make_tools(memory_service=None)
        result = run(tools.build_server_memory("i-abc123"))
        assert "memory subsystem not wired" in result


# ---------------------------------------------------------------------------
# get_server_memory — self-healing hint when no memory exists yet.
# ---------------------------------------------------------------------------

class TestGetServerMemoryMissing:
    """When no memory is stored the tool must return code='missing' + hint."""

    def test_missing_returns_structured_error_with_build_hint(self):
        # get_all_modules → empty = no memory stored yet.
        mem_svc = _make_memory_service(get_all_modules_return={})
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.get_server_memory("i-abc123"))
        parsed = json.loads(result)

        assert parsed["error"]["code"] == "missing"
        assert "build_server_memory" in parsed["error"]["hint"]
        # Audit entry logs the missing case for observability.
        call = tools._audit.log.call_args
        assert call[0][0] == "get_server_memory"
        assert call[0][3] is False
        assert call[0][4] == "missing"


# ---------------------------------------------------------------------------
# list_server_memories
# ---------------------------------------------------------------------------

class TestListServerMemories:
    """list_server_memories with and without stale_only filter."""

    def _three_entries(self):
        return [
            {"instance_id": "i-aaa", "provider": "aws", "name": "server-a"},
            {"instance_id": "i-bbb", "provider": "aws", "name": "server-b"},
            {"instance_id": "i-ccc", "provider": "custom", "name": "server-c"},
        ]

    def test_stale_only_false_returns_all(self):
        mem_svc = _make_memory_service(list_all_return=self._three_entries())
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.list_server_memories(stale_only=False))
        parsed = json.loads(result)
        assert len(parsed) == 3

    def test_stale_only_true_filters_to_stale(self):
        entries = self._three_entries()
        mem_svc = _make_memory_service(list_all_return=entries)

        # Only i-aaa has stale modules; i-bbb and i-ccc are fresh.
        # Set the side_effect on the public method (B.2 — tools now call this).
        def _mock_stale(instance_id, provider="custom"):
            return ["os"] if instance_id == "i-aaa" else []

        mem_svc.stale_modules = MagicMock(side_effect=_mock_stale)
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.list_server_memories(stale_only=True))
        parsed = json.loads(result)
        assert len(parsed) == 1
        assert parsed[0]["instance_id"] == "i-aaa"

    def test_stale_only_true_with_no_stale_returns_empty(self):
        entries = self._three_entries()
        mem_svc = _make_memory_service(list_all_return=entries)
        # stale_modules public method returns [] (default from factory)
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.list_server_memories(stale_only=True))
        parsed = json.loads(result)
        assert parsed == []

    def test_audit_logged_success(self):
        mem_svc = _make_memory_service(list_all_return=[])
        tools = _make_tools(memory_service=mem_svc)

        run(tools.list_server_memories())

        call = tools._audit.log.call_args
        assert call[0][0] == "list_server_memories"
        assert call[0][3] is True

    def test_guard_blocked(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(memory_service=mem_svc)
        tools._guard = MagicMock()
        tools._guard.check_tool.return_value = (False, "list blocked")

        result = run(tools.list_server_memories())
        assert result.startswith("Blocked: ")
        call = tools._audit.log.call_args
        assert call[0][0] == "list_server_memories"
        assert call[0][3] is False

    def test_memory_service_none_returns_error(self):
        tools = _make_tools(memory_service=None)
        result = run(tools.list_server_memories())
        assert "memory subsystem not wired" in result

    def test_stale_only_calls_stale_modules_helper(self):
        """stale_modules must be used (not hand-rolled logic)."""
        entries = self._three_entries()
        mem_svc = _make_memory_service(list_all_return=entries)
        # Override public stale_modules to return stale for all entries
        mem_svc.stale_modules = MagicMock(return_value=["os"])
        tools = _make_tools(memory_service=mem_svc)

        run(tools.list_server_memories(stale_only=True))

        # memory_service.stale_modules should have been called once per entry
        assert mem_svc.stale_modules.call_count == len(entries)


# ---------------------------------------------------------------------------
# B.6 — audit on early-return MCP paths
# ---------------------------------------------------------------------------

class TestEarlyReturnAudit:
    """Verify audit.log is called on memory_service=None and instance not found paths."""

    # --- get_server_memory ---

    def test_get_server_memory_none_service_audits(self):
        tools = _make_tools(memory_service=None)
        run(tools.get_server_memory("i-abc123"))
        tools._audit.log.assert_called_once()
        call = tools._audit.log.call_args
        assert call[0][0] == "get_server_memory"
        assert call[0][3] is False
        assert call[0][4] == "memory_service_missing"

    def test_get_server_memory_not_found_audits(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(memory_service=mem_svc, instance_to_find=None)
        run(tools.get_server_memory("no-such-id"))
        tools._audit.log.assert_called_once()
        call = tools._audit.log.call_args
        assert call[0][0] == "get_server_memory"
        assert call[0][3] is False
        assert call[0][4] == "instance_not_found"

    # --- refresh_server_memory ---

    def test_refresh_server_memory_none_service_audits(self):
        tools = _make_tools(memory_service=None)
        run(tools.refresh_server_memory("i-abc123"))
        tools._audit.log.assert_called_once()
        call = tools._audit.log.call_args
        assert call[0][0] == "refresh_server_memory"
        assert call[0][3] is False
        assert call[0][4] == "memory_service_missing"

    def test_refresh_server_memory_not_found_audits(self):
        mem_svc = _make_memory_service()
        tools = _make_tools(memory_service=mem_svc, instance_to_find=None)
        run(tools.refresh_server_memory("no-such-id"))
        tools._audit.log.assert_called_once()
        call = tools._audit.log.call_args
        assert call[0][0] == "refresh_server_memory"
        assert call[0][3] is False
        assert call[0][4] == "instance_not_found"

    # --- list_server_memories ---

    def test_list_server_memories_none_service_audits(self):
        tools = _make_tools(memory_service=None)
        run(tools.list_server_memories())
        tools._audit.log.assert_called_once()
        call = tools._audit.log.call_args
        assert call[0][0] == "list_server_memories"
        assert call[0][3] is False
        assert call[0][4] == "memory_service_missing"


# ---------------------------------------------------------------------------
# C.2 — raw_output stripped from full format
# ---------------------------------------------------------------------------

class TestFullFormatRawOutputStripped:
    """get_server_memory(format='full') must not include raw_output."""

    def test_raw_output_absent_from_full_response(self):
        modules_data = {
            "os": {
                "module": "os",
                "observed": {"kernel": "6.8.0"},
                "raw_output": "SECRET PROBE OUTPUT",
                "probed_at": "2026-04-21T00:00:00+00:00",
            },
        }
        mem_svc = _make_memory_service(get_all_modules_return=modules_data)
        # Wire get_all_modules on the service mock (B.2 public API)
        mem_svc.get_all_modules = MagicMock(return_value=modules_data)
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.get_server_memory("i-abc123", format="full"))

        parsed = json.loads(result)
        # The result is now {"instance_id": ..., "modules": {...}}
        modules = parsed.get("modules", parsed)
        for mod_data in modules.values():
            assert "raw_output" not in mod_data

    def test_observed_and_probed_at_present_in_full_response(self):
        modules_data = {
            "os": {
                "module": "os",
                "observed": {"kernel": "6.8.0"},
                "probed_at": "2026-04-21T00:00:00+00:00",
                "raw_output": "should be stripped",
            },
        }
        mem_svc = _make_memory_service(get_all_modules_return=modules_data)
        mem_svc.get_all_modules = MagicMock(return_value=modules_data)
        tools = _make_tools(memory_service=mem_svc)

        result = run(tools.get_server_memory("i-abc123", format="full"))

        parsed = json.loads(result)
        modules = parsed.get("modules", parsed)
        os_data = modules["os"]
        assert "observed" in os_data
        assert "probed_at" in os_data
