"""Menus highlight the hovered row; they never underline its text.

Real stylesheets, three themes. Link-style controls (``LinkButton``) are
underlined on purpose and are not menus.
"""

from __future__ import annotations

from typing import Any, List

import pytest
from textual.geometry import Region
from textual.widgets import Button, Tree

from . import _geometry, test_screens as screens

THEMES = {"dark": "servonaut", "light": "servonaut-light", "ansi": "ansi-dark"}


def _underlined(widget: Any, region: Region | None = None) -> str:
    """Text of the widget's rendered cells that carry an underline."""
    region = region or Region(0, 0, widget.outer_size.width, widget.outer_size.height)
    text = ""
    for strip in widget.render_lines(region):
        for segment in strip:
            if segment.style is not None and segment.style.underline:
                text += segment.text
    return text.strip()


def _row_look(button: Button) -> tuple:
    styles = button.styles
    return (styles.background, bool(styles.text_style.bold), bool(styles.text_style.reverse))


async def _sidebar_problems(pilot: Any, theme: str) -> List[str]:
    screen = pilot.app.screen
    entries = [
        b for b in screen.query("Sidebar .nav-button")
        if b.display and b.region.height and screen.region.contains_region(b.region)
    ]
    assert len(entries) > 3
    current = next((b for b in entries if b.has_class("--active")), None)
    await pilot.hover(screen, offset=(screen.size.width - 1, screen.size.height - 1))
    await pilot.pause()
    idle = {id(b): _row_look(b) for b in entries}
    problems = []
    for button in entries:
        await pilot.hover(button)
        await pilot.pause(0.05)
        if not button.mouse_hover:
            continue
        name = f"{button.id or button.label}"
        if _underlined(button):
            problems.append(f"{name} underlines its text on hover")
        if not button.has_class("--active") and _row_look(button) == idle[id(button)]:
            problems.append(f"{name} shows no row highlight on hover")
        if current is not None and button is not current and _row_look(current) == _row_look(button):
            problems.append(f"the current row looks like the hovered {name}")
    return problems


def _themed(theme: str, scenario: Any, probe: Any) -> List[str]:
    problems: List[str] = []

    async def run(pilot: Any) -> None:
        pilot.app.theme = THEMES[theme]
        await pilot.pause()
        await scenario(pilot)
        await pilot.pause(0.2)
        problems.extend(await probe(pilot))

    _geometry.run(run, "160x50", lambda pilot: None, name=f"menu-{theme}")
    return problems


@pytest.mark.parametrize("theme", list(THEMES))
def test_sidebar_entries_highlight_the_row_on_hover(theme: str) -> None:
    async def probe(pilot: Any) -> List[str]:
        return await _sidebar_problems(pilot, theme)

    problems = _themed(theme, screens._fleet, probe)
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("theme", list(THEMES))
def test_settings_categories_highlight_the_row_on_hover(theme: str) -> None:
    async def scenario(pilot: Any) -> None:
        pilot.app.open_settings_screen("general")
        await screens._harness.wait_for_screen(pilot, "SettingsScreen")
        await pilot.pause(0.3)

    async def probe(pilot: Any) -> List[str]:
        screen = pilot.app.screen
        rows = [
            b for b in screen.query("#settings-nav-list Button")
            if b.display and b.region.height and screen.region.contains_region(b.region)
        ]
        assert rows
        problems = []
        await pilot.hover(screen, offset=(screen.size.width - 1, screen.size.height - 1))
        await pilot.pause()
        idle = {id(b): _row_look(b) for b in rows}
        for button in rows:
            await pilot.hover(button)
            await pilot.pause(0.05)
            if not button.mouse_hover or button.has_focus:
                continue
            if _underlined(button):
                problems.append(f"{button.id or button.label} underlines its text on hover")
            if _row_look(button) == idle[id(button)] and not button.has_class("--active"):
                problems.append(f"{button.id or button.label} shows no row highlight on hover")
        return problems

    problems = _themed(theme, scenario, probe)
    assert not problems, "\n".join(problems)


def _cell_background(widget: Any, x: int, y: int) -> Any:
    """The background colour painted at (x, y) of *widget*."""
    strip = widget.render_lines(Region(0, y, widget.outer_size.width, 1))[0]
    position = 0
    for segment in strip:
        position += len(segment.text)
        if position > x:
            return segment.style.bgcolor if segment.style is not None else None
    return None


@pytest.mark.parametrize("theme", list(THEMES))
def test_help_topics_highlight_the_row_on_hover_and_never_underline(theme: str) -> None:
    async def scenario(pilot: Any) -> None:
        await screens._help(pilot)

    async def probe(pilot: Any) -> List[str]:
        screen = pilot.app.screen
        tree = screen.query_one("#help_topics Tree", Tree)
        problems = []
        await pilot.hover(screen, offset=(screen.size.width - 1, screen.size.height - 1))
        await pilot.pause()
        idle = _cell_background(tree, 8, 2)
        await pilot.hover(tree, offset=(8, 2))
        await pilot.pause(0.1)
        if _underlined(tree):
            problems.append("a help topic is underlined while hovered")
        if theme != "ansi" and _cell_background(tree, 8, 2) == idle:
            problems.append("a hovered help topic row is not highlighted")
        return problems

    problems = _themed(theme, scenario, probe)
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("theme", list(THEMES))
def test_command_list_highlights_the_row_on_hover_and_never_underlines(theme: str) -> None:
    from textual.command import CommandList

    async def scenario(pilot: Any) -> None:
        await pilot.press("ctrl+p")
        await screens._harness.wait_for_screen(pilot, "CommandPalette")
        await pilot.press(*"se")
        await pilot.pause(0.5)

    async def probe(pilot: Any) -> List[str]:
        palette_list = pilot.app.screen.query_one(CommandList)
        if palette_list.option_count < 2:
            return ["the command list shows fewer than two rows"]
        problems = []
        await pilot.hover(pilot.app.screen, offset=(0, pilot.app.screen.size.height - 1))
        await pilot.pause(0.1)
        # The letters that match the query are underlined on purpose; hover adds nothing.
        matches = _underlined(palette_list)
        await pilot.hover(palette_list, offset=(6, 1))
        await pilot.pause(0.1)
        if _underlined(palette_list) != matches:
            problems.append("hovering a command underlines more of its text")
        hovered = _cell_background(palette_list, 6, 1)
        other = _cell_background(palette_list, 6, 0)
        if theme != "ansi" and hovered == other:
            problems.append("a hovered command row is not highlighted")
        return problems

    problems = _themed(theme, scenario, probe)
    assert not problems, "\n".join(problems)
