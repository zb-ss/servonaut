"""Screenshot tests: the findings inbox, a finding's detail and memory drift.

Each screen is pushed with fixed neutral data and drawn by the real app and
stylesheet at both terminal sizes (see ``test_screens.py``).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Awaitable, Callable, List
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.widgets import DataTable

from . import _harness

Scenario = Callable[[Any], Awaitable[None]]

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))


def _finding(finding_id: str, severity: str, status: str, title: str) -> dict:
    return {
        "id": finding_id,
        "instance_id": "i-0000test01",
        "detector": "ssh_exposure",
        "rule": "password_auth_enabled",
        "severity": severity,
        "status": status,
        "title": title,
        "description": "sshd accepts password logins; key-only is recommended.",
        "remediations": [{
            "label": "Disable password authentication",
            "description": "Set PasswordAuthentication no and reload sshd.",
            "action": "harden_sshd_password_auth",
            "risk_tier": "low",
            "reversible": True,
        }],
        "evidence": ["sshd_config: PasswordAuthentication yes (10.0.0.5)"],
        "team_scoped": False,
        "detected_at": "2026-07-01T10:00:00Z",
        "last_seen_at": "2026-07-02T10:00:00Z",
    }


_FINDINGS: List[dict] = [
    _finding("fnd_01", "critical", "detected", "Root login over SSH is permitted"),
    _finding("fnd_02", "high", "detected", "SSH password authentication is enabled"),
    _finding("fnd_03", "medium", "acked", "Firewall allows the database port"),
    _finding("fnd_04", "low", "resolved", "Outdated TLS protocol is accepted"),
]


def _entitled_app(app: Any) -> None:
    auth = MagicMock()
    auth.is_authenticated = True
    auth.has_feature = MagicMock(return_value=True)
    service = MagicMock()
    service.list_findings = AsyncMock(return_value={
        "findings": _FINDINGS, "total": len(_FINDINGS), "limit": 50, "offset": 0,
    })
    app.auth_service = auth
    app.findings_service = service


async def _findings(pilot: Any) -> None:
    from servonaut.screens.findings import FindingsScreen

    _entitled_app(pilot.app)
    pilot.app.push_screen(FindingsScreen())
    screen = await _harness.wait_for_screen(pilot, "FindingsScreen")
    table = screen.query_one("#findings_table", DataTable)
    await _harness.wait_until(pilot, lambda: table.row_count == len(_FINDINGS), "the findings")
    table.focus()


async def _finding_detail(pilot: Any) -> None:
    from servonaut.screens.findings import FindingDetailScreen

    _entitled_app(pilot.app)
    pilot.app.push_screen(FindingDetailScreen(_FINDINGS[1]))
    await _harness.wait_for_screen(pilot, "FindingDetailScreen")


async def _drift(pilot: Any) -> None:
    from servonaut.screens.memory_drift import MemoryDriftScreen

    events = [
        SimpleNamespace(
            detected_at="2026-07-02T09:30:00Z", instance_id="web-1", module="nginx",
            severity="high", acknowledged_at=None, event_id="d1",
        ),
        SimpleNamespace(
            detected_at="2026-07-02T08:10:00Z", instance_id="web-1", module="packages",
            severity="medium", acknowledged_at=None, event_id="d2",
        ),
        SimpleNamespace(
            detected_at="2026-07-01T17:45:00Z", instance_id="db-1", module="listeners",
            severity="low", acknowledged_at="2026-07-01T18:00:00Z", event_id="d3",
        ),
    ]
    app = pilot.app
    app.auth_service = MagicMock()
    app.auth_service.has_feature = MagicMock(return_value=True)
    app.drift_service = MagicMock()
    app.drift_service.list_drift = AsyncMock(return_value=events)
    app.push_screen(MemoryDriftScreen())
    screen = await _harness.wait_for_screen(pilot, "MemoryDriftScreen")
    table = screen.query_one("#drift-table", DataTable)
    await _harness.wait_until(pilot, lambda: table.row_count == len(events), "the drift events")
    table.focus()


def _capture(screen_snapshot: Any, size: str, scenario: Scenario) -> None:
    async def run_before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        await scenario(pilot)
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], run_before)


@sizes
def test_findings_inbox(screen_snapshot, size: str) -> None:
    """Four findings: the actions sit above the table as words with key hints."""
    _capture(screen_snapshot, size, _findings)


@sizes
def test_finding_detail(screen_snapshot, size: str) -> None:
    """One finding: triage actions above its evidence and remediation."""
    _capture(screen_snapshot, size, _finding_detail)


@sizes
def test_memory_drift(screen_snapshot, size: str) -> None:
    """Three drift events: severity in theme colours, actions in one row."""
    _capture(screen_snapshot, size, _drift)
