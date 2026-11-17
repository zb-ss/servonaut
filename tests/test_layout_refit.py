"""Tests for layout-driven refitting when Textual skips emitting a Resize event."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.containers import Horizontal, ScrollableContainer
from textual.events import Resize
from textual.geometry import Size
from textual.widgets import Static

from servonaut.styles import CSS_FILES
from servonaut.widgets._layout_refit import LayoutRefitMixin
from servonaut.widgets.action_button import ActionButton, ActionRow
from servonaut.widgets.fleet_values import FleetValueLine
from servonaut.widgets.planned_table import PlannedTable
from tests._async_bounds import wait_until


class _ProbeWidget(LayoutRefitMixin, Static):
    def __init__(self) -> None:
        super().__init__("probe")
        self.resize_calls = 0
        self.refit_calls = 0

    def on_resize(self, _event: Resize) -> None:
        self.resize_calls += 1
        self._mark_layout_fitted()

    def _refit_for_layout(self) -> None:
        self._mark_layout_fitted()
        self.refit_calls += 1


class _ProbeApp(App):
    def compose(self) -> ComposeResult:
        yield _ProbeWidget()


@pytest.mark.asyncio
async def test_layout_refit_skips_when_already_fitted_and_fires_on_size_or_container_delta() -> None:
    app = _ProbeApp()
    async with app.run_test(size=(80, 24)) as pilot:
        widget = app.query_one(_ProbeWidget)
        await pilot.pause()
        widget._mark_layout_fitted()
        widget.refit_calls = 0

        # Duplicate resize/layout dimensions already fitted -> _run_layout_refit is a no-op.
        widget._size_updated(widget._size, widget._size, widget._container_size)
        widget._run_layout_refit()
        assert widget.refit_calls == 0

        # Layout update without Resize event triggers _refit_for_layout.
        widget._size_updated(Size(60, 24), Size(60, 24), Size(60, 24))
        assert widget._layout_refit_pending is True
        widget._run_layout_refit()
        assert widget.refit_calls == 1

        # Changing only container_size (for auto-width widgets) also schedules a refit.
        widget._size_updated(Size(60, 24), Size(60, 24), Size(45, 24))
        assert widget._layout_refit_pending is True
        widget._run_layout_refit()
        assert widget.refit_calls == 2


class _ScrolledReflowApp(App):
    CSS_PATH = CSS_FILES
    CSS = """
    #root { width: 100%; height: 100%; }
    #nav { width: 32; height: 100%; display: none; }
    #body { width: 1fr; height: 100%; }
    #spacer { height: 40; }
    """

    def __init__(self) -> None:
        super().__init__()
        self.planned_widths: list[int] = []

    def compose(self) -> ComposeResult:
        table = PlannedTable(id="planned")
        table.set_plan_handler(lambda: self.planned_widths.append(table.region.width))
        yield Horizontal(
            Static("Nav", id="nav"),
            ScrollableContainer(
                ActionRow(
                    ActionButton("Refresh memory", "r", id="b0"),
                    ActionButton("Scan server", "s", id="b1"),
                    ActionButton("Edit notes", "n", id="b2"),
                    ActionButton("Share memory", "m", id="b3"),
                    id="actions",
                ),
                table,
                FleetValueLine(id="line"),
                Static("spacer", id="spacer"),
                id="body",
            ),
            id="root",
        )


@pytest.mark.asyncio
async def test_fitters_refit_after_scroll_and_sidebar_toggle() -> None:
    app = _ScrolledReflowApp()
    async with app.run_test(size=(100, 30)) as pilot:
        line = app.query_one(FleetValueLine)
        line.set_instance(
            {
                "name": "web-1",
                "public_ip": "192.0.2.10",
                "private_ip": "10.0.1.10",
                "region": "us-east-1",
                "type": "t3.medium",
                "id": "i-0123456789abcdef0",
            }
        )
        await pilot.pause()
        await pilot.pause()

        row = app.query_one("#actions", ActionRow)
        assert not row.has_class("-wrap")
        assert app.planned_widths and app.planned_widths[-1] >= 90
        line_classes_wide = set(line.classes)
        assert "-flexible" not in line_classes_wide

        # Scroll down and back so Textual invalidates the compositor map before toggling nav.
        body = app.query_one("#body", ScrollableContainer)
        body.scroll_to(y=16, animate=False)
        await pilot.pause()
        body.scroll_to(y=0, animate=False)
        await pilot.pause()

        app.query_one("#nav").display = True
        await wait_until(lambda: row.has_class("-wrap"))
        await wait_until(lambda: bool(app.planned_widths) and app.planned_widths[-1] <= 70)
        await wait_until(lambda: set(line.classes) != line_classes_wide)
