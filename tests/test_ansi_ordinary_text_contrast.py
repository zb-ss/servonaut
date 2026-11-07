"""Native ANSI focus surfaces retain readable text and unchanged input targets."""

from __future__ import annotations

import json
from typing import Any

import pytest
from rich.style import Style
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Input, Static, TextArea

from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.safe_header import SafeHeader
from tests._async_bounds import wait_until
from tests.test_ansi_chat_dialog_contrast import _NativeStateDialog
from tests.test_ansi_control_cues import _button_sample
from tests.test_editor_selection_contrast import (
    _active_palette, _assert_colour_mode,
    _isolated_boundaries, manager, services,  # noqa: F401
)
from tests.test_navigation_dialog_contrast import _contrast, _paint_colours
from tests.test_settings_presentation import _tab_to
from tests.test_workspace_pilot import _Host


THEMES = ("ansi-dark", "ansi-light")


class _OrdinaryControls(Screen):
    """Supply native controls without replacing application color rules."""

    CSS = """
    _OrdinaryControls #ordinary-body { padding: 1; height: 1fr; }
    _OrdinaryControls #ordinary-table { height: 8; }
    _OrdinaryControls #ordinary-buttons { height: 3; }
    _OrdinaryControls #ordinary-origin { width: 30; }
    """

    def __init__(self) -> None:
        super().__init__()
        self.pressed: list[str | None] = []
        self.selected: list[str] = []

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        with Vertical(id="ordinary-body"):
            yield DataTable(id="ordinary-table", cursor_type="row")
            with Horizontal(id="ordinary-buttons"):
                yield Button("Open details", id="ordinary-default")
                yield Button("Review change", variant="warning", id="ordinary-warning")
                yield Button("Remove member", variant="error", id="ordinary-error")
                yield Button("Back", id="btn_back")
            yield Input(value="Retain this draft", id="ordinary-origin")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Member", "Role")
        table.add_row("Alpha", "Member", key="first")
        table.add_row("Beta", "Viewer", key="second")
        self.query_one(Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.pressed.append(event.button.id)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.selected.append(event.row_key.value)


def _app(manager, services, theme: str) -> _Host:
    manager.get().theme = theme
    manager.save(manager.get())
    app = _Host(navigation_visible=False)
    app.config_manager = manager
    app.ai_analysis_service = services.analysis
    app.bug_report_service = services.reports
    app.custom_server_service = services.servers
    app.animation_level = "none"
    app.theme = theme
    return app


async def _mount(app, pilot) -> _OrdinaryControls:
    screen = _OrdinaryControls()
    await app.push_screen(screen)
    await pilot.pause()
    assert app.focused is screen.query_one(Input)
    _assert_colour_mode(app)
    return screen


def _glyphs(widget, literal: str, palette) -> dict[str, Any]:
    """Read full compositor text and its native hit target, not computed CSS."""
    region = widget.content_region.intersection(widget.screen.region)
    rows = widget.screen._compositor.render_strips()
    for y in range(region.y, region.bottom):
        strip = rows[y].crop(region.x, region.right)
        start = strip.text.find(literal)
        if start < 0:
            continue
        # These fixture labels and the header use single-cell code points.
        offset = 0
        cells = []
        for segment in strip:
            style = segment.style or Style()
            for char in segment.text:
                if start <= offset < start + len(literal):
                    x = region.x + offset
                    hit, _ = widget.app.get_widget_at(x, y)
                    assert hit is widget or widget in hit.ancestors
                    fg, bg = _paint_colours(style, palette)
                    cells.append({
                        "glyph": char, "x": x, "y": y, "style": str(style),
                        "foreground": list(fg), "background": list(bg),
                        "contrast": _contrast(fg, bg), "dim": bool(style.dim),
                        "bold": bool(style.bold),
                    })
                offset += 1
        assert "".join(cell["glyph"] for cell in cells) == literal
        return {"literal": literal, "region": list(widget.region), "glyphs": cells}
    pytest.fail(f"Complete {literal!r} is not painted in {widget!r}")


def _record(record_property, app, rows, failures) -> None:
    palette = app.ansi_theme
    record_property("native_ordinary_text", json.dumps({
        "theme": app.current_theme.name, "dark": app.current_theme.dark,
        "color_system": app.console.color_system, "no_color": app.no_color,
        "palette": {"foreground": list(palette.foreground_color),
                    "background": list(palette.background_color),
                    "ansi": [list(palette.ansi_colors[i]) for i in range(16)]},
        "rows": rows, "failures": failures,
    }, sort_keys=True))


def _readable(row, failures) -> None:
    for cell in row["glyphs"]:
        if cell["glyph"].strip() and cell["contrast"] < 4.5:
            failures.append({"literal": row["literal"], "cell": cell})


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
async def test_focused_ordinary_buttons_keep_text_and_native_activation(
    manager, services, tmp_path, theme, record_property,
) -> None:
    app = _app(manager, services, theme)
    disk = (tmp_path / "config.json").read_bytes()
    rows, failures = [], []
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _mount(app, pilot)
        origin = screen.query_one(Input)
        palette = _active_palette(app)
        for variant, button_id in (("default", "ordinary-default"), ("warning", "ordinary-warning"),
                                   ("error", "ordinary-error"), ("default", "btn_back")):
            button = screen.query_one(f"#{button_id}", Button)
            geometry = button.region
            for state in ("hover", "focus", "focus-hover"):
                if state == "hover":
                    await _tab_to(pilot, origin)
                    await pilot.hover(button)
                elif state == "focus":
                    await pilot.hover(origin)
                    await _tab_to(pilot, button)
                else:
                    await pilot.hover(button)
                await pilot.pause()
                assert button.has_focus is (state != "hover")
                assert button.mouse_hover is (state != "focus")
                assert button.variant == variant and not button.disabled
                row = _glyphs(button, button.label.plain, palette)
                row.update(variant=variant, state=state, id=button_id,
                           native=_button_sample(app, button, button.label.plain, palette))
                rows.append(row)
                _readable(row, failures)
                assert not any(cell["bold"] for cell in row["glyphs"])
            await pilot.press("enter")
            await wait_until(lambda: screen.pressed[-1:] == [button.id])
            await wait_until(lambda: not button.has_class("-active"))
            assert button.region == geometry
        assert screen.pressed == ["ordinary-default", "ordinary-warning", "ordinary-error", "btn_back"]
        focused = screen.query_one("#ordinary-default", Button)
        hovered = screen.query_one("#btn_back", Button)
        await _tab_to(pilot, focused)
        await pilot.hover(hovered)
        await pilot.pause()
        assert focused.has_focus and not focused.mouse_hover
        assert hovered.mouse_hover and not hovered.has_focus
        pair = [_glyphs(widget, widget.label.plain, palette) for widget in (focused, hovered)]
        for row, state in zip(pair, ("focused-with-other-hover", "hovered-with-other-focus"), strict=True):
            row["state"] = state
            rows.append(row)
            _readable(row, failures)
        assert _contrast(pair[0]["glyphs"][0]["background"], pair[1]["glyphs"][0]["background"]) >= 3
        await pilot.press("enter")
        await wait_until(lambda: screen.pressed[-1:] == [focused.id])
        assert screen.pressed == ["ordinary-default", "ordinary-warning", "ordinary-error", "btn_back", "ordinary-default"]
        assert origin.value == "Retain this draft" and not screen.selected
        assert (tmp_path / "config.json").read_bytes() == disk
        assert app._exception is None
        _record(record_property, app, rows, failures)
    assert not failures, json.dumps(failures)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
async def test_native_chat_controls_keep_hover_and_keyboard_focus_distinct(
    manager, services, monkeypatch, theme, record_property,
) -> None:
    # Keep real controls and dispatch while refusing provider/audio session startup.
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    app = _app(manager, services, theme)
    rows, failures = [], []
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.press("f2")
        await pilot.pause()
        panel = app.screen.query_one(ChatPanel)
        editor = panel.query_one("#chat-input", TextArea)
        await wait_until(lambda: app.focused is editor)
        _assert_colour_mode(app)
        editor.load_text("Keep this draft Ω [literal]")
        await pilot.pause()
        snapshot = editor.document, editor.text, editor.selection, editor.scroll_offset
        palette = _active_palette(app)
        new = panel.query_one("#btn-chat-new", Button)
        history = panel.query_one("#btn-chat-history", Button)
        assert new.focusable and history.focusable and not new.disabled and not history.disabled
        geometry = new.region, history.region
        for focused, hovered in ((new, history), (history, new)):
            await _tab_to(pilot, focused)
            await pilot.hover(hovered)
            await pilot.pause()
            assert focused.has_focus and not hovered.has_focus and hovered.mouse_hover
            pair = [_glyphs(widget, widget.label.plain, palette) for widget in (focused, hovered)]
            for row, state in zip(pair, ("focused-with-other-hover", "hovered-with-other-focus"), strict=True):
                row.update(state=state, id=focused.id if row is pair[0] else hovered.id)
                rows.append(row)
                _readable(row, failures)
            assert _contrast(pair[0]["glyphs"][0]["background"], pair[1]["glyphs"][0]["background"]) >= 3
            await pilot.hover(focused)
            await pilot.pause()
            assert focused.has_focus and focused.mouse_hover
            row = _glyphs(focused, focused.label.plain, palette)
            row.update(state="focused-and-hovered", id=focused.id)
            rows.append(row)
            _readable(row, failures)
            assert not any(cell["bold"] for cell in row["glyphs"])
            assert row["glyphs"][0]["background"] == pair[0]["glyphs"][0]["background"]
            assert (new.region, history.region) == geometry
            assert (editor.document, editor.text, editor.selection, editor.scroll_offset) == snapshot
        assert app._exception is None
        services.analysis.analyze_text.assert_not_called()
        _record(record_property, app, rows, failures)
    assert not failures, json.dumps(failures)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
async def test_table_headers_and_selected_row_keep_glyphs_and_row_target(
    manager, services, theme, record_property,
) -> None:
    app = _app(manager, services, theme)
    rows, failures = [], []
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _mount(app, pilot)
        table = screen.query_one(DataTable)
        origin = screen.query_one(Input)
        palette = _active_palette(app)
        await pilot.hover(origin)
        await _tab_to(pilot, table)
        await pilot.press("down")
        await pilot.pause()
        assert table.cursor_row == 1
        for literal in ("Member", "Role", "Beta", "Viewer"):
            row = _glyphs(table, literal, palette)
            row["state"] = "focused"
            rows.append(row)
            _readable(row, failures)
            if literal in ("Beta", "Viewer"):
                assert not any(cell["bold"] for cell in row["glyphs"])
        geometry, scroll = table.region, table.scroll_offset
        await pilot.press("enter")
        await wait_until(lambda: screen.selected == ["second"])
        await _tab_to(pilot, origin)
        await pilot.pause()
        assert not table.has_focus and table.cursor_row == 1
        for literal in ("Beta", "Viewer"):
            row = _glyphs(table, literal, palette)
            row["state"] = "blurred"
            rows.append(row)
            _readable(row, failures)
            assert not any(cell["bold"] for cell in row["glyphs"])
        assert table.region == geometry and table.scroll_offset == scroll
        assert table.row_count == 2 and origin.value == "Retain this draft"
        assert not screen.pressed and app._exception is None
        _record(record_property, app, rows, failures)
    assert not failures, json.dumps(failures)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
async def test_complete_header_title_and_version_are_readable(
    manager, services, theme, record_property,
) -> None:
    app = _app(manager, services, theme)
    failures = []
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _mount(app, pilot)
        header = screen.query_one(SafeHeader)
        title = header.query_one("HeaderTitle", Static)
        literal = header.format_title().plain
        assert app.title in literal and app.sub_title and app.sub_title in literal
        assert app.sub_title.startswith("v")
        row = _glyphs(title, literal, _active_palette(app))
        _readable(row, failures)
        icon = _glyphs(header.query_one("HeaderIcon"), header.icon, _active_palette(app))
        _readable(icon, failures)
        assert header.region.y == 0 and header.region.width == 160
        assert app.focused is screen.query_one(Input) and app._exception is None
        _record(record_property, app, [row, icon], failures)
    assert not failures, json.dumps(failures)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
async def test_mounted_header_reformats_after_theme_and_ansi_mode_changes(
    manager, services, theme, record_property,
) -> None:
    app = _app(manager, services, "servonaut")
    rows, failures = [], []
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _mount(app, pilot)
        header = screen.query_one(SafeHeader)
        title = header.query_one("HeaderTitle", Static)
        origin = screen.query_one(Input)
        # Literal updates use the existing public title watcher, including markup-like text.
        app.title = "Local [literal] Ω"
        await pilot.pause()
        literal = header.format_title().plain
        version = app.sub_title
        geometry = header.region, title.region
        for chosen, override, native in (
            ("servonaut", None, False),
            (theme, None, True),
            ("servonaut", None, False),
            (theme, None, True),
            (theme, False, False),
            (theme, None, True),
        ):
            app.theme = chosen
            app.ansi_color = override
            await pilot.pause()
            assert app.native_ansi_color is native
            assert header.format_title().plain == literal and app.sub_title == version
            row = _glyphs(title, literal, app.ansi_theme)
            row.update(theme=chosen, ansi_override=override, native_ansi=native)
            suffix = row["glyphs"][-len(version):]
            # Preserve every upstream span except dim, including stored content.
            assert title.render().is_same(header.format_title())
            assert title.render().is_same(super(SafeHeader, header).format_title().stylize("not dim"))
            assert not any(cell["dim"] for cell in suffix), json.dumps(row)
            _readable(row, failures)
            rows.append(row)
            assert (header.region, title.region) == geometry
            assert app.focused is origin and origin.value == "Retain this draft"
            assert not screen.pressed and not screen.selected
        assert app._exception is None
        _record(record_property, app, rows, failures)
    assert not failures, json.dumps(failures)


@pytest.mark.asyncio
async def test_registered_header_title_and_version_glyphs_remain_readable(
    manager, services, record_property,
) -> None:
    app = _app(manager, services, "servonaut")
    rows, failures = [], []
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _mount(app, pilot)
        header = screen.query_one(SafeHeader)
        title = header.query_one("HeaderTitle", Static)
        origin = screen.query_one(Input)
        literal = header.format_title().plain
        geometry = header.region, title.region
        names = sorted(app.available_themes)
        assert names
        for chosen in names:
            app.theme = chosen
            await pilot.pause()
            _assert_colour_mode(app)
            row = _glyphs(title, literal, app.ansi_theme)
            row.update(theme=chosen, native_ansi=app.native_ansi_color,
                       palette_foreground=list(app.ansi_theme.foreground_color),
                       palette_background=list(app.ansi_theme.background_color),
                       palette_ansi=[list(app.ansi_theme.ansi_colors[i]) for i in range(16)])
            row["icon"] = _glyphs(header.query_one("HeaderIcon"), header.icon, app.ansi_theme)
            rows.append(row)
            _readable(row, failures)
            _readable(row["icon"], failures)
            assert title.render().plain == literal
            assert (header.region, title.region) == geometry and app.focused is origin
            assert app._exception is None
        assert len(rows) == len(names)
        record_property("registered_header_themes", json.dumps(names))
        _record(record_property, app, rows, failures)
    assert not failures, json.dumps(failures)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
async def test_dialog_severity_actions_preserve_native_variant_focus_and_result(
    manager, services, theme, record_property,
) -> None:
    app = _app(manager, services, theme)
    rows, failures = [], []
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _mount(app, pilot)
        caller = screen.query_one(Input)
        palette = _active_palette(app)
        for variant in ("warning", "error"):
            dialog = _NativeStateDialog(variant)
            results = []
            await app.push_screen(dialog, results.append)
            await pilot.pause()
            field = dialog.query_one(Input)
            button = dialog.query_one("#state-action", Button)
            assert button.disabled and app.focused is field
            button.disabled = False
            await pilot.hover(field)
            await _tab_to(pilot, button)
            await pilot.pause()
            assert button.has_focus and not button.mouse_hover and button.variant == variant
            geometry = button.region
            row = _glyphs(button, "Continue", palette)
            row.update(variant=variant, native=_button_sample(app, button, "Continue", palette))
            rows.append(row)
            _readable(row, failures)
            await pilot.press("enter")
            await wait_until(lambda: dialog.pressed == ["state-action"])
            await wait_until(lambda: not button.has_class("-active"))
            assert app.screen is dialog and not results and button.region == geometry
            await pilot.press("escape")
            await wait_until(lambda: results == [False] and app.screen is screen)
            assert app.focused is caller
        assert caller.value == "Retain this draft" and app._exception is None
        _record(record_property, app, rows, failures)
    assert not failures, json.dumps(failures)
