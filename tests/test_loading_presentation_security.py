"""Held reads expose visible progress and clean up after completion."""

from __future__ import annotations

import asyncio
import re
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from rich.cells import cell_len
from textual.geometry import Region
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input, LoadingIndicator, Static

from servonaut.widgets.busy_indicator import BusyIndicator

from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import content
from tests.test_workspace_pilot import _click


from tests import test_workspace_security_reflow as parent
from tests.test_workspace_security_reflow import _fake_boundaries as _fake_boundaries

pytestmark = pytest.mark.usefixtures("navigation_open")


FAILURE = "Example read failed [literal] Ω"


class _HeldRead:
    """Gate an existing declared fake, preserving its concrete fixture data."""

    def __init__(
        self, read: AsyncMock, monkeypatch: pytest.MonkeyPatch,
        *, fail: bool = False,
    ) -> None:
        assert isinstance(read, AsyncMock)
        assert read.side_effect is None, "Review existing fake semantics first"
        self.value = deepcopy(read.return_value)
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.exited = asyncio.Event()
        self.error: Exception | None = RuntimeError(FAILURE) if fail else None
        self.read = read
        monkeypatch.setattr(read, "side_effect", self._read)

    async def _read(self, *args: Any, **kwargs: Any) -> Any:
        self.entered.set()
        try:
            await self.release.wait()
            if self.error is not None:
                raise self.error
            return deepcopy(self.value)
        finally:
            self.exited.set()


def _loading_viewport(
    screen: Any, body: Widget,
    visible: dict[Widget, tuple[Region, Region]],
) -> tuple[Widget, Region] | None:
    """Use mapped content geometry, or an actual cover replacing its ancestor."""
    for owner in body.ancestors_with_self:
        if not isinstance(owner, Widget):
            continue
        presentation = owner._render_widget
        if owner is not body and presentation is owner:
            continue
        geometry = visible.get(presentation)
        if geometry is None:
            continue
        region, clip = geometry
        viewport = region.shrink(owner.styles.gutter)
        # Native loading covers use the container area without scrollbar cuts.
        if owner.is_scrollable and not owner.loading:
            viewport = viewport.shrink(owner.scrollbar_gutter)
        viewport = viewport.intersection(clip).intersection(
            screen._compositor.size.region,
        )
        if viewport.width and viewport.height:
            return owner, viewport
    return None


def _painted_loading_span(
    screen: Any, widget: Widget, bounds: Region, strips: list[Any],
) -> str | None:
    """Require every cell of actual loading text or a spinner dot to hit its owner."""
    if isinstance(widget, BusyIndicator):
        pattern = re.compile(r"[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]")
    else:
        pattern = re.compile(
            r"●|\bLoading\b" if isinstance(widget, LoadingIndicator)
            else r"\b(?:loading|fetching|refreshing)\b",
            re.I,
        )
    for y in range(bounds.y, bounds.bottom):
        text = strips[y].crop(bounds.x, bounds.right).text
        for match in pattern.finditer(text):
            left = bounds.x + cell_len(text[:match.start()])
            right = bounds.x + cell_len(text[:match.end()])
            hits = [screen.get_widget_at(x, y)[0] for x in range(left, right)]
            if hits and all(
                hit is widget or widget in hit.ancestors for hit in hits
            ):
                return match.group(0)
    return None


def _loading_evidence(screen: Any) -> list[tuple[Widget, str]]:
    """Discover actual compositor presentations, including non-DOM covers."""
    compositor = screen._compositor
    visible = compositor.visible_widgets
    scope = _loading_viewport(screen, content(screen), visible)
    if scope is None:
        return []
    owner, viewport = scope
    strips = compositor.render_strips()
    evidence = []
    for widget, (region, clip) in visible.items():
        if not isinstance(widget, (Static, LoadingIndicator)):
            continue
        if owner is not widget and owner not in widget.ancestors:
            continue
        if not widget.display or not widget.visible:
            continue
        bounds = region.intersection(clip).intersection(viewport)
        if not bounds.width or not bounds.height:
            continue
        painted = _painted_loading_span(screen, widget, bounds, strips)
        if painted is not None:
            evidence.append((widget, painted))
    return evidence


def _loading_diagnostics(screen: Any) -> dict[str, Any]:
    """Distinguish missing scope, absent presentation and unpainted progress."""
    compositor = screen._compositor
    visible = compositor.visible_widgets
    body = content(screen)
    scope = _loading_viewport(screen, body, visible)
    strips = compositor.render_strips()
    candidates = []
    for widget, (region, clip) in visible.items():
        if not isinstance(widget, (Static, LoadingIndicator)):
            continue
        if body is not widget and body not in widget.ancestors:
            continue
        bounds = region.intersection(clip).intersection(compositor.size.region)
        if scope is not None:
            bounds = bounds.intersection(scope[1])
        painted = "\n".join(
            strips[y].crop(bounds.x, bounds.right).text
            for y in range(bounds.y, bounds.bottom)
        ) if bounds.area else ""
        candidates.append({
            "widget": f"{type(widget).__name__}#{widget.id}",
            "region": repr(region), "clip": repr(clip),
            "display": widget.display, "visible": widget.visible,
            "painted": painted[:240],
        })
    return {
        "body": f"{type(body).__name__}#{body.id}",
        "body_mapped": body._render_widget in visible,
        "scope": None if scope is None else (type(scope[0]).__name__, repr(scope[1])),
        "mapped_widgets": len(visible), "candidates": candidates,
    }


async def _assert_pending(screen: Any, pilot: Any, held: _HeldRead) -> None:
    await wait_until(held.entered.is_set)
    await pilot.pause()
    assert not held.release.is_set() and not held.exited.is_set()
    try:
        await wait_until(lambda: bool(_loading_evidence(screen)))
    except TimeoutError:
        raise AssertionError(
            "Held read has no visible loading presentation: "
            + repr(_loading_diagnostics(screen))
        ) from None
    assert not held.release.is_set() and not held.exited.is_set()
    assert all(indicator.is_active for indicator in content(screen).query(BusyIndicator)), (
        "BusyIndicator has no active timer during held read"
    )


async def _settle(screen: Any, pilot: Any, held: _HeldRead) -> None:
    held.release.set()
    await wait_until(held.exited.is_set)
    await wait_until(lambda: all(worker.is_finished for worker in screen.workers))
    assert all(not indicator.is_active for indicator in content(screen).query(BusyIndicator)), (
        "BusyIndicator timer survived worker completion"
    )
    await pilot.pause()
    try:
        await wait_until(lambda: not _loading_evidence(screen))
    except TimeoutError:
        raise AssertionError(
            "Loading presentation survived the read: "
            + repr(_loading_diagnostics(screen))
        ) from None
    assert screen.app._exception is None


def _rows(table: DataTable) -> tuple[tuple[Any, ...], ...]:
    return tuple(tuple(table.get_row_at(i)) for i in range(table.row_count))


def _notifications(app: Any, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    messages: list[str] = []
    original = app.notify

    def record(message: Any, **kwargs: Any) -> Any:
        messages.append(str(message))
        return original(message, **kwargs)

    monkeypatch.setattr(app, "notify", record)
    return messages


def _buttons(screen: Any) -> dict[str, bool]:
    return {button.id: button.disabled for button in content(screen).query(Button)}


@pytest.fixture(autouse=True)
def _bind_parent_sources() -> None:
    """Fail closed if an environment resolves another checkout's sources."""
    import servonaut

    root = Path(__file__).resolve().parents[1]
    assert Path(servonaut.__file__).resolve() == root / "src/servonaut/__init__.py"
    assert Path(parent.__file__).resolve().parent == root / "tests"


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [False, True], ids=["complete", "failure"])
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_ban_list_refresh_loading_keeps_configuration_and_audit(
    fail: bool, size: tuple[int, int], monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = next(case for case in parent.CASES if case.name == "ban")
    app = case.app_factory(False)
    async with app.run_test(size=size) as pilot:
        screen = await parent.open_case(case, app, pilot)
        table = screen.query_one("#banned_table", DataTable)
        before = _rows(table)
        config = screen.query_one("#ban_config_selector").value
        screen.query_one("#ip_input", Input).value = "9.9.9.9"
        audit = screen.query_one("#audit_log")
        controls = _buttons(screen)
        notices = _notifications(app, monkeypatch)
        held = _HeldRead(app.ip_ban_service.list_banned, monkeypatch, fail=fail)
        try:
            screen.query_one("#btn_refresh").scroll_visible(
                animate=False, immediate=True,
            )
            await pilot.pause()
            await _click(pilot, "#btn_refresh")
            await _assert_pending(screen, pilot, held)
            # Clearing on refresh is existing behavior; no stale row is actionable.
            assert table.row_count == 0 and screen._banned_real == []
            assert screen.query_one("#ban_config_selector").value == config
            assert screen.query_one("#ip_input", Input).value == "9.9.9.9"
            assert screen.query_one("#audit_log") is audit
            assert not screen.query_one("#ip_ban_empty_hint").display
            await _settle(screen, pilot, held)
            assert _buttons(screen) == controls
            assert screen.query_one("#ban_config_selector").value == config
            assert screen.query_one("#ip_input", Input).value == "9.9.9.9"
            if fail:
                assert table.row_count == 0
                assert any("Error loading banned IPs: " + FAILURE in n for n in notices)
            else:
                await case.ready(screen)
                assert _rows(table) == before
        finally:
            held.release.set()
