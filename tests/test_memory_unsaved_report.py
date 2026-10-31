"""A module that was probed but not stored is never reported as built."""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from servonaut.cli.memory import _EXIT_PARTIAL_FAILURE, _build_all, _cmd_build, _cmd_refresh
from servonaut.services.memory.fleet_scan_service import FleetScanService, row_reason_text
from servonaut.services.memory.modules.base import ModuleResult
from servonaut.services.memory.service import BuildReport, ModuleBuildFailure

SERVER = {"id": "i-1", "name": "web-1", "provider": "aws"}
BUSY = ModuleBuildFailure("os", "record_busy", "Another Servonaut process was changing this server's memory.")


def _result(module: str) -> ModuleResult:
    return ModuleResult(module=module, instance_id="i-1", probed_at="2026-01-01T00:00:00+00:00",
                        ttl_seconds=60, observed={}, declared={}, raw_output="", partial=True)


def _partial() -> BuildReport:
    return BuildReport(successes={"runtimes": _result("runtimes")}, unsaved={"os": _result("os")},
                       failures=[BUSY])


def _nothing_saved() -> BuildReport:
    return BuildReport(unsaved={"os": _result("os")}, failures=[BUSY], overall_reason="record_busy")


def _service(report: BuildReport) -> MagicMock:
    service = MagicMock()
    service.build_report = AsyncMock(return_value=report)
    service.refresh_report = AsyncMock(return_value=report)
    return service


def test_cli_build_names_the_unsaved_modules_and_fails_when_nothing_was_saved(capsys):
    args = SimpleNamespace(json=False, modules=None)
    assert _cmd_build(args, None, _service(_nothing_saved()), dict(SERVER)) != 0
    err = capsys.readouterr().err
    assert "1 module was probed but not saved" in err and "Run it again" in err


def test_cli_build_prints_saved_modules_and_warns_about_the_rest(capsys):
    args = SimpleNamespace(json=False, modules=None)
    assert _cmd_build(args, None, _service(_partial()), dict(SERVER)) == _EXIT_PARTIAL_FAILURE
    captured = capsys.readouterr()
    assert "Built memory for i-1: runtimes" in captured.out
    assert "not saved" in captured.err


def test_cli_build_json_lists_unsaved_modules(capsys):
    args = SimpleNamespace(json=True, modules=None)
    _cmd_build(args, None, _service(_partial()), dict(SERVER))
    out = json.loads(capsys.readouterr().out)
    assert set(out) == {"runtimes", "_unsaved"}
    assert out["_unsaved"] == ["os"]


def test_cli_refresh_does_not_claim_a_refresh_for_unsaved_modules(capsys):
    args = SimpleNamespace(json=False, modules=None)
    assert _cmd_refresh(args, None, _service(_nothing_saved()), dict(SERVER)) != 0
    captured = capsys.readouterr()
    assert "Refreshed memory" not in captured.out
    assert "not saved" in captured.err


def test_build_all_counts_a_server_with_unsaved_modules_as_not_done():
    failures = asyncio.run(_build_all([dict(SERVER)], _service(_partial()), None))
    assert [iid for iid, _ in failures] == ["i-1"]
    assert "not saved" in failures[0][1]


def test_mcp_returns_unsaved_modules_under_their_own_heading_and_audits_it():
    from servonaut.mcp.guards import GuardLevel
    from tests.test_mcp_tools import make_tools

    tools = make_tools(guard_level=GuardLevel.DANGEROUS)
    tools._memory_service = MagicMock()
    tools._memory_service.build_report = AsyncMock(return_value=_partial())
    payload = json.loads(asyncio.run(tools.build_server_memory("i-abc123")))
    assert payload["successes"] == ["runtimes"] and payload["count"] == 1
    assert payload["unsaved"] == ["os"]
    assert "not saved" in payload["message"]
    args, _ = tools._audit.log.call_args
    assert args[3] is True and args[4] == "unsaved_modules"


def _scan(report: BuildReport):
    ms = MagicMock()
    ms.is_memory_disabled = MagicMock(return_value=False)
    ms.get_all_modules = MagicMock(return_value={})
    ms.snapshot_stale_seconds = 7 * 86400
    ms.build_report = AsyncMock(return_value=report)
    service = FleetScanService(ms)
    return service, asyncio.run(service.scan([dict(SERVER)], stale_only=False))


def test_fleet_scan_does_not_count_unsaved_modules_as_a_success():
    for report in (_partial(), _nothing_saved()):
        service, result = _scan(report)
        assert result.succeeded == []
        assert [f["reason"] for f in result.failed] == ["record_busy"]
        assert service.last_reasons["i-1"] == "record_busy"
    assert row_reason_text("record_busy") == "memory busy, try again"


def test_the_memory_screen_warns_instead_of_saying_refreshed():
    from servonaut.screens.memory import MemoryScreen

    service = MagicMock()
    service.refresh_report = AsyncMock(return_value=_nothing_saved())
    notice = asyncio.run(MemoryScreen(dict(SERVER))._refresh_notice(service))
    assert notice is not None
    message, severity = notice
    assert severity == "warning" and "not saved" in message
