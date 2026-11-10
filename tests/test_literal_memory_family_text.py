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
