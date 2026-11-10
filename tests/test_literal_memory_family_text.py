"""Outside text on the findings, pin and drift-diff screens is shown verbatim.

Server names, finding titles, evidence, memory keys and diff lines come from
outside the app. None of them may act as markup: a value such as ``a [link=``
must neither crash a screen nor leave a stray closing tag behind.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from textual.app import App
from textual.widgets import Static

from servonaut.screens.findings import FindingDetailScreen, FindingsScreen
from servonaut.screens.memory import PinKeyModal
from servonaut.screens.memory_drift import DriftDiffScreen
from tests.test_workspace_security_reflow import (
    _SecurityHost,
    _fake_boundaries as _fake_boundaries,
    _finding,
)

HOSTILE = ["a [link=", "a[/]b", "x\\", "[@click=app.quit]z[/]", "port [::]:22 open ["]


def _plain(widget: Static) -> str:
    content = widget.content
    return content.plain if hasattr(content, "plain") else str(content)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", HOSTILE)
async def test_findings_for_a_server_with_a_hostile_name_open_verbatim(value: str) -> None:
    app = _SecurityHost(True)
    async with app.run_test(size=(160, 50)) as pilot:
        await app.push_screen(FindingsScreen({"id": "i-1", "name": value}))
        await pilot.pause()
        assert _plain(app.screen.query_one("#findings_title", Static)) == (
            f"Monitoring findings — {value}"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("value", HOSTILE)
async def test_finding_detail_shows_hostile_values_verbatim(value: str) -> None:
    finding = _finding(
        title=value,
        evidence=[value],
        remediations=[{
            "label": value, "description": value, "action": value,
            "risk_tier": value, "reversible": True, "automatable": False,
        }],
    )
    app = _SecurityHost(True)
    async with app.run_test(size=(160, 50)) as pilot:
        await app.push_screen(FindingDetailScreen(finding))
        await pilot.pause()
        screen = app.screen
        assert _plain(screen.query_one("#finding_detail_title", Static)) == f"🛡 {value}"
        shown = [_plain(w) for w in screen.query("#finding_detail_body Static")]
        assert sum(value in text for text in shown) >= 4


@pytest.mark.asyncio
@pytest.mark.parametrize("value", HOSTILE)
async def test_pin_dialog_shows_a_hostile_key_verbatim(value: str) -> None:
    class Host(App):
        def on_mount(self) -> None:
            self.push_screen(PinKeyModal(value, value, value))

    app = Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert _plain(screen.query_one("#pin_modal_title", Static)) == (
            f"Pin value for {value}.{value}"
        )
        assert _plain(screen.query_one("#pin_modal_field", Static)).endswith(value)


def _envelope(payload: dict) -> SimpleNamespace:
    return SimpleNamespace(plaintext=payload)


async def _diff_text(old: dict, new: dict, **event: str) -> tuple[str, str]:
    base = {
        "instance_id": "web-1", "module": "services", "old_hash": "", "new_hash": "",
        "old_envelope_id": "e1", "new_envelope_id": "e2",
    }
    service = SimpleNamespace(get_snapshot=AsyncMock(
        side_effect=lambda _i, _m, envelope_id: _envelope(old if envelope_id == "e1" else new),
    ))
    app = _SecurityHost(True)
    async with app.run_test(size=(160, 50)) as pilot:
        await app.push_screen(DriftDiffScreen(SimpleNamespace(**{**base, **event}), service))
        await pilot.pause(0.3)
        return (
            _plain(app.screen.query_one("#drift-diff-title", Static)),
            _plain(app.screen.query_one("#drift-diff-content", Static)),
        )


@pytest.mark.asyncio
async def test_a_list_in_a_drift_diff_shows_no_stray_tag() -> None:
    _, text = await _diff_text(
        {"units": ["cron"]}, {"units": ["cron", "nginx"]},
    )
    assert '+    "nginx"' in text
    assert "[/" not in text
    assert any(line.rstrip().endswith("[") for line in text.splitlines())


@pytest.mark.asyncio
@pytest.mark.parametrize("value", HOSTILE)
async def test_hostile_values_in_a_drift_diff_show_verbatim(value: str) -> None:
    title, text = await _diff_text({"k": "old"}, {"k": value}, instance_id=value, module=value)
    assert f"Drift diff: {value} / {value}" == title.splitlines()[0]
    assert "Diff fetch failed" not in text
    assert value in text


@pytest.mark.asyncio
async def test_findings_table_columns_are_wider_than_their_headers() -> None:
    app = _SecurityHost(True)
    app.findings_service.list_findings.return_value = {
        "findings": [_finding(title="Root login over SSH is permitted", status="acknowledged")],
        "total": 1, "limit": 50, "offset": 0,
    }
    async with app.run_test(size=(160, 50)) as pilot:
        await app.push_screen(FindingsScreen())
        await pilot.pause(0.5)
        table = app.screen.query_one("#findings_table")
        widths = {str(c.label): c.get_render_width(table) for c in table.columns.values()}
        assert widths["Title"] >= len("Root login over SSH is permitted")
        assert widths["Status"] >= len("acknowledged")


@pytest.mark.asyncio
async def test_drift_table_and_diff_heading_hide_the_instance_id_in_demo_mode() -> None:
    from servonaut.services.redaction_service import RedactionService
    from servonaut.screens.memory_drift import MemoryDriftScreen
    from textual.widgets import DataTable

    real = "i-0abc123def456"
    event = SimpleNamespace(
        instance_id=real, module="services", severity="high", detected_at="2026-07-02T09:30:00Z",
        acknowledged_at=None, old_hash="", new_hash="", old_envelope_id="e1", new_envelope_id="e2",
    )
    app = _SecurityHost(True)
    app.demo_mode = True
    app.auth_service.has_feature = lambda feature: True
    app.redaction_service = RedactionService()
    app.drift_service = SimpleNamespace(list_drift=AsyncMock(return_value=[event]))
    async with app.run_test(size=(160, 50)) as pilot:
        await app.push_screen(MemoryDriftScreen())
        await pilot.pause(0.5)
        table = app.screen.query_one("#drift-table", DataTable)
        cells = [str(c) for c in table.get_row_at(0)]
        assert real not in " ".join(cells)
        assert table.columns[next(iter(table.columns))].get_render_width(table) >= 10
        await app.push_screen(DriftDiffScreen(event, SimpleNamespace(
            get_snapshot=AsyncMock(return_value=_envelope({})),
        )))
        await pilot.pause(0.3)
        heading = _plain(app.screen.query_one("#drift-diff-title", Static))
        assert real not in heading


@pytest.mark.asyncio
async def test_findings_and_drift_tables_restyle_on_a_theme_switch() -> None:
    from servonaut.screens.memory_drift import MemoryDriftScreen
    from textual.widgets import DataTable

    event = SimpleNamespace(
        instance_id="web-1", module="services", severity="high",
        detected_at="2026-07-02T09:30:00Z", acknowledged_at=None,
    )
    app = _SecurityHost(True)
    app.auth_service.has_feature = lambda feature: True
    app.findings_service.list_findings.return_value = {
        "findings": [_finding(), _finding(id="fnd_2", severity="low")],
        "total": 2, "limit": 50, "offset": 0,
    }
    app.drift_service = SimpleNamespace(list_drift=AsyncMock(return_value=[event, event]))
    async with app.run_test(size=(160, 50)) as pilot:
        for screen, table_id in ((FindingsScreen(), "#findings_table"),
                                 (MemoryDriftScreen(), "#drift-table")):
            await app.push_screen(screen)
            await pilot.pause(0.5)
            table = screen.query_one(table_id, DataTable)
            table.move_cursor(row=1)
            col = 0 if table_id == "#findings_table" else 3
            before = str(table.get_row_at(0)[col].style)
            app.theme = "servonaut-light" if app.theme != "servonaut-light" else "servonaut"
            await pilot.pause(0.5)
            assert str(table.get_row_at(0)[col].style) != before
            assert table.cursor_row == 1
            await app.pop_screen()
            await pilot.pause()
