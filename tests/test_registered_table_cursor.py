"""Collect native cursor readability across the actual registered theme set."""

from __future__ import annotations

import json

import pytest
from textual.widgets import DataTable, Input

from tests._async_bounds import wait_until
from tests.test_ansi_ordinary_text_contrast import (
    _OrdinaryControls, _app, _assert_colour_mode, _glyphs, _readable, _tab_to,
    _isolated_boundaries, manager, services,  # noqa: F401
)


class _CursorModes(_OrdinaryControls):
    """Keep the existing ordinary host and native row/cell result messages."""

    def __init__(self) -> None:
        super().__init__()
        self.cells_selected: list[tuple] = []

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        self.cells_selected.append((event.value, tuple(event.coordinate), event.cell_key.row_key.value))


def _visible_pair(row: dict) -> set[tuple]:
    return {(tuple(cell["foreground"]), tuple(cell["background"]), cell["bold"], cell["dim"])
            for cell in row["glyphs"] if cell["glyph"].strip()}


@pytest.mark.asyncio
@pytest.mark.timeout(300)
async def test_registered_native_cursor_keeps_readable_glyphs_and_row_cell_targets(
    manager, services, record_property,
) -> None:
    app = _app(manager, services, "servonaut")
    observations, failures = [], []
    async with app.run_test(size=(160, 50)) as pilot:
        screen = _CursorModes()
        await app.push_screen(screen)
        await pilot.pause()
        table = screen.query_one(DataTable)
        origin = screen.query_one(Input)
        assert app.focused is origin and table.cursor_type == "row"
        await _tab_to(pilot, table)
        await pilot.press("down")
        await pilot.pause()
        assert tuple(table.cursor_coordinate) == (1, 0)
        data = tuple(tuple(table.get_row_at(i)) for i in range(table.row_count))
        geometry = table.region
        scroll = table.scroll_offset
        names = sorted(app.available_themes)
        assert names
        for cursor_mode in ("row", "cell"):
            table.cursor_type = cursor_mode
            if cursor_mode == "cell":
                await _tab_to(pilot, table)
                await pilot.press("right")
                await pilot.pause()
            expected_coordinate = (1, 0) if cursor_mode == "row" else (1, 1)
            for theme in names:
                app.theme = theme
                await pilot.pause()
                _assert_colour_mode(app)
                await _tab_to(pilot, table)
                await pilot.pause()
                assert table.has_focus and tuple(table.cursor_coordinate) == expected_coordinate
                palette = app.ansi_theme
                for focused in (True, False):
                    if not focused:
                        await _tab_to(pilot, origin)
                        await pilot.pause()
                    assert table.has_focus is focused
                    labels = ("Beta", "Viewer") if cursor_mode == "row" else ("Viewer",)
                    selected = []
                    for label in labels:
                        row = _glyphs(table, label, palette)
                        row.update(theme=theme, cursor_mode=cursor_mode, focused=focused,
                                   coordinate=list(table.cursor_coordinate), dark=app.current_theme.dark)
                        selected.append(row)
                        before = len(failures)
                        _readable(row, failures)
                        for failure in failures[before:]:
                            failure.update(theme=theme, cursor_mode=cursor_mode, focused=focused)
                    adjacent = _glyphs(table, "Alpha" if cursor_mode == "row" else "Beta", palette)
                    if _visible_pair(selected[-1]) == _visible_pair(adjacent):
                        failures.append({"theme": theme, "cursor_mode": cursor_mode,
                                         "focused": focused, "issue": "cursor indistinguishable from adjacent text"})
                    observations.append({
                        "theme": theme, "cursor_mode": cursor_mode, "focused": focused,
                        "selected": selected, "adjacent": adjacent,
                        "palette_foreground": list(palette.foreground_color),
                        "palette_background": list(palette.background_color),
                        "palette_ansi": [list(palette.ansi_colors[i]) for i in range(16)],
                        "declared_block_cursor_roles": {
                            name: app.get_css_variables().get(name)
                            for name in ("block-cursor-foreground", "block-cursor-background")
                        },
                    })
                    assert tuple(table.cursor_coordinate) == expected_coordinate
                    assert table.region == geometry and table.row_count == 2
                    assert table.scroll_offset == scroll
                    assert tuple(tuple(table.get_row_at(i)) for i in range(table.row_count)) == data
                    assert origin.value == "Retain this draft" and not screen.pressed
                await _tab_to(pilot, table)
                row_count, cell_count = len(screen.selected), len(screen.cells_selected)
                await pilot.press("enter")
                if cursor_mode == "row":
                    await wait_until(lambda: len(screen.selected) == row_count + 1)
                    assert screen.selected[-1] == "second" and len(screen.cells_selected) == cell_count
                else:
                    await wait_until(lambda: len(screen.cells_selected) == cell_count + 1)
                    assert screen.cells_selected[-1] == ("Viewer", (1, 1), "second")
                    assert len(screen.selected) == row_count
                assert app._exception is None
        assert len(observations) == len(names) * 2 * 2
        assert screen.selected == ["second"] * len(names)
        assert screen.cells_selected == [("Viewer", (1, 1), "second")] * len(names)
        record_property("registered_table_cursor", json.dumps({
            "themes": names, "observations": observations, "failures": failures,
            "scope": "one native app; row/cell and focused/blurred; no chat/clipboard/notifications",
        }, sort_keys=True))
    assert not failures, json.dumps(failures)
