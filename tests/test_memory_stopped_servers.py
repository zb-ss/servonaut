"""Stopped servers are skipped by memory scans and named by single builds."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.fleet_scan_service import FleetScanService
from servonaut.services.memory.service import BuildReport, MemoryService, ModuleBuildFailure
from servonaut.services.memory.store import MemoryStore


def _row(name: str, **extra: Any) -> Dict[str, Any]:
    row: Dict[str, Any] = {"id": name, "name": name, "provider": "aws", "state": "running"}
    row.update(extra)
    return row


def _scan_memory_service(probed: List[str]) -> MagicMock:
    ms = MagicMock()
    ms.is_memory_disabled = MagicMock(return_value=False)
    ms.get_all_modules = MagicMock(return_value={})
    ms.snapshot_stale_seconds = 7 * 86400

    async def _build_report(inst: Dict[str, Any]) -> Any:
        probed.append(inst["id"])
        report = MagicMock()
        report.has_any_success = True
        report.overall_reason = None
        report.failures = []
        return report

    ms.build_report = AsyncMock(side_effect=_build_report)
    return ms


STOPPED_ROWS = [
    _row("aws-stopped", state="stopped"),
    _row("aws-stopping", state="stopping"),
    _row("aws-terminated", state="terminated"),
    _row("aws-shutting-down", state="shutting-down"),
    _row("ovh-vps", provider="OVH", is_ovh=True, state="stopped"),
    _row("hz-off", provider="hetzner", is_hetzner=True, state="stopped"),
]


class TestIsStoppedInstance:
    @pytest.mark.parametrize("row", STOPPED_ROWS, ids=lambda r: r["name"])
    def test_stopped_states_are_stopped(self, row: Dict[str, Any]) -> None:
        from servonaut.services.memory.status import is_stopped_instance

        assert is_stopped_instance(row) is True

    @pytest.mark.parametrize(
        "row",
        [
            _row("running"),
            _row("pending", state="pending"),
            _row("ovh-error", is_ovh=True, state="error"),
            _row("hz-unknown", is_hetzner=True, state="unknown"),
            _row("no-state", state=""),
            _row("custom", is_custom=True, state="stopped"),
            _row("shared", is_shared=True, state="stopped"),
        ],
        ids=lambda r: r["name"],
    )
    def test_other_rows_are_probed(self, row: Dict[str, Any]) -> None:
        from servonaut.services.memory.status import is_stopped_instance

        assert is_stopped_instance(row) is False


class TestFleetScanSkipsStopped:
    def test_stopped_rows_are_not_probed_and_are_reported_skipped(self) -> None:
        probed: List[str] = []
        service = FleetScanService(_scan_memory_service(probed))
        rows = [_row("web-1"), *STOPPED_ROWS, _row("box", is_custom=True, state="stopped")]

        result = asyncio.run(service.scan(rows, stale_only=False))

        assert sorted(probed) == ["box", "web-1"]
        assert sorted(result.skipped) == sorted(r["name"] for r in STOPPED_ROWS)
        assert result.failed == []
        assert sorted(result.succeeded) == ["box", "web-1"]

    def test_eligible_instances_excludes_stopped(self) -> None:
        service = FleetScanService(_scan_memory_service([]))
        eligible = service.eligible_instances(
            [_row("web-1"), _row("off", state="stopped")], stale_only=False
        )
        assert [r["id"] for r in eligible] == ["web-1"]

    def test_skipped_row_keeps_the_stopped_reason(self) -> None:
        service = FleetScanService(_scan_memory_service([]))
        asyncio.run(service.scan([_row("off", state="stopped")], stale_only=False))
        assert service.last_reasons == {"off": "stopped"}


def _memory_service(tmp_path: Path) -> MemoryService:
    return MemoryService(
        store=MemoryStore(root=tmp_path), config=MemoryConfig(enabled=True), probers=[]
    )


class TestSingleBuildOfStoppedServer:
    def test_build_report_names_the_state_without_starting_ssh(self, tmp_path: Path) -> None:
        service = _memory_service(tmp_path)
        with patch.object(service, "_make_ssh_runner") as make_runner:
            report = asyncio.run(service.build_report(_row("off", state="stopped")))
        make_runner.assert_not_called()
        assert report.overall_reason == "stopped"
        assert not report.has_any_success
        assert report.unreached_message
        assert "stopped" in report.unreached_message.lower()
        assert "off" not in report.unreached_message

    def test_a_running_server_is_not_guarded(self, tmp_path: Path) -> None:
        service = _memory_service(tmp_path)
        report = asyncio.run(service.build_report(_row("web-1")))
        assert report.overall_reason != "stopped"


class TestCliSurfacesStopped:
    def test_build_says_the_server_is_stopped(self, tmp_path: Path, capsys: Any) -> None:
        from servonaut.cli.memory import _cmd_build

        service = _memory_service(tmp_path)
        args = MagicMock(json=False, modules=None)
        code = _cmd_build(args, MagicMock(), service, _row("off", state="stopped"))
        err = capsys.readouterr().err
        assert code != 0
        assert "stopped" in err.lower()

    def test_refresh_says_the_server_is_stopped(self, tmp_path: Path, capsys: Any) -> None:
        from servonaut.cli.memory import _cmd_refresh

        service = _memory_service(tmp_path)
        args = MagicMock(modules=None)
        code = _cmd_refresh(args, MagicMock(), service, _row("off", state="stopped"))
        assert code != 0
        assert "stopped" in capsys.readouterr().err.lower()

    def test_build_all_counts_a_stopped_server_as_skipped_not_failed(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        from servonaut.cli.memory import _cmd_build_all

        service = _memory_service(tmp_path)
        fleet = MagicMock()
        with patch(
            "servonaut.cli.memory._list_all_instances",
            return_value=[_row("off", state="stopped")],
        ):
            code = _cmd_build_all(MagicMock(modules=None), MagicMock(), service, fleet)
        captured = capsys.readouterr()
        assert code == 0
        assert "FAILED" not in captured.err
        assert "skipped: stopped" in (captured.out + captured.err)

    def test_build_all_does_not_announce_a_probe_of_a_stopped_server(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        from servonaut.cli.memory import _build_all

        service = MagicMock()
        service.build_report = AsyncMock(return_value=BuildReport(successes={"os": MagicMock()}))
        skipped: List[str] = []
        rows = [_row("off", state="stopped"), _row("on", state="running")]

        failures = asyncio.run(_build_all(rows, service, None, skipped))

        out = capsys.readouterr().out
        assert failures == []
        assert skipped == ["off"]
        assert "Probing on" in out and "[1/1]" in out
        assert "Probing off" not in out
        # The stopped server is never handed to the probes at all.
        assert [call.args[0]["id"] for call in service.build_report.await_args_list] == ["on"]


class TestMcpSurfacesStopped:
    def test_build_server_memory_reports_stopped_with_a_distinct_audit_reason(self) -> None:
        from tests.test_memory_mcp_tools import _make_memory_service, _make_tools, run

        report = BuildReport(
            failures=[ModuleBuildFailure("provider", "stopped", "The server is stopped.")],
            overall_reason="stopped",
        )
        mem_svc = _make_memory_service(build_report_return=report)
        tools = _make_tools(memory_service=mem_svc)

        parsed = json.loads(run(tools.build_server_memory("i-abc123")))

        assert parsed["reason"] == "stopped"
        assert "stopped" in parsed["message"].lower()
        audit_call = tools._audit.log.call_args
        assert audit_call.args[-1] == "stopped"
