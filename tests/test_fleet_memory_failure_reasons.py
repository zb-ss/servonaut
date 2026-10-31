"""Each Fleet Memory row says why its last scan did not succeed."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.screens.fleet_memory import FleetMemoryScreen
from servonaut.services.memory.fleet_scan_service import FleetScanService

# (overall_reason, first failure reason, text shown on the row)
CASES = [
    ("ssh_connection_failed", "ssh_auth_failed", "login refused"),
    ("ssh_connection_failed", "ssh_unreachable", "unreachable"),
    ("ssh_connection_failed", "ssh_failed", "SSH failed"),
    ("ssh_connection_failed", "ssh_no_response", "no answer in time"),
    ("ssh_connection_failed", "vault_credential_unavailable", "no usable vault key"),
    ("ssh_connection_failed", "vault_rate_limited", "rate limited"),
    ("host_key_verification_failed", "ssh_host_key_changed", "host key not trusted"),
    ("all_probers_failed", "timeout", "no answer in time"),
    ("stopped", "stopped", "stopped (skipped)"),
]


def _bind_app(widget: Any, app: Any) -> None:
    """Give one widget instance a fake ``app`` without touching its class.

    Assigning ``app`` on the production class would leak into every later
    test in the process, so the instance gets a private subclass instead.
    """
    widget.__class__ = type(
        widget.__class__.__name__, (widget.__class__,), {"app": property(lambda self: app)}
    )



def _report(overall: str, reason: str) -> Any:
    report = MagicMock()
    report.has_any_success = False
    report.overall_reason = overall
    failure = MagicMock()
    failure.module = "ssh"
    failure.reason = reason
    failure.message = "x"
    report.failures = [failure]
    return report


def _scan_service(report: Any) -> FleetScanService:
    ms = MagicMock()
    ms.is_memory_disabled = MagicMock(return_value=False)
    ms.get_all_modules = MagicMock(return_value={})
    ms.snapshot_stale_seconds = 7 * 86400
    ms.build_report = AsyncMock(return_value=report)
    return FleetScanService(ms)


def _screen(last_reasons: Dict[str, str], instances: List[Dict[str, Any]]):
    screen = object.__new__(FleetMemoryScreen)
    screen._rows = []
    screen._scanning = False
    memory_service = MagicMock()
    memory_service.is_memory_disabled = MagicMock(return_value=False)
    memory_service.get_all_modules = MagicMock(return_value={})
    memory_service.snapshot_stale_seconds = 7 * 86400
    app = MagicMock()
    app.demo_mode = False
    app.redaction_service = None
    app.memory_service = memory_service
    app.instances = instances
    app.fleet_scan_service = MagicMock(last_reasons=last_reasons)
    _bind_app(screen, app)
    table = MagicMock()
    screen.query_one = MagicMock(return_value=table)
    return screen, table


class TestScanRecordsReasonCodes:
    @pytest.mark.parametrize("overall,reason,_text", CASES[:-1])
    def test_failed_probe_keeps_the_specific_code(
        self, overall: str, reason: str, _text: str
    ) -> None:
        service = _scan_service(_report(overall, reason))
        asyncio.run(service.scan([{"id": "web-1", "name": "web-1"}], stale_only=False))
        assert service.last_reasons == {"web-1": reason}

    def test_a_later_success_clears_the_reason(self) -> None:
        service = _scan_service(_report("ssh_connection_failed", "ssh_unreachable"))
        row = [{"id": "web-1", "name": "web-1"}]
        asyncio.run(service.scan(row, stale_only=False))
        ok = MagicMock(has_any_success=True, overall_reason=None, failures=[])
        service._memory_service.build_report = AsyncMock(return_value=ok)
        asyncio.run(service.scan(row, stale_only=False))
        assert service.last_reasons == {}


class TestRowShowsReason:
    @pytest.mark.parametrize("_overall,reason,text", CASES)
    def test_populate_table_shows_the_reason_on_the_row(
        self, _overall: str, reason: str, text: str
    ) -> None:
        code = "stopped" if reason == "stopped" else reason
        screen, table = _screen(
            {"web-1": code}, [{"id": "web-1", "name": "web-1", "provider": "aws"}]
        )
        screen._populate_table()
        cells = table.add_row.call_args.args
        assert text in cells[-1]

    def test_a_row_without_a_failure_shows_a_dash(self) -> None:
        screen, table = _screen({}, [{"id": "web-1", "name": "web-1", "provider": "aws"}])
        screen._populate_table()
        assert table.add_row.call_args.args[-1] == "—"

    def test_reason_text_never_names_the_server(self) -> None:
        screen, table = _screen(
            {"web-1": "ssh_unreachable"},
            [{"id": "web-1", "name": "web-1", "provider": "aws"}],
        )
        screen._populate_table()
        assert "web-1" not in table.add_row.call_args.args[-1]
