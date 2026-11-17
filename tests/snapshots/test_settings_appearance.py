"""Settings › Appearance: built-in cards alone, and with user theme files."""

from __future__ import annotations

from typing import Any

import pytest

from servonaut.styles.user_themes import themes_dir

from . import _harness

OCEAN = (
    'primary = "#5EB1FF"\naccent = "#7DD3FC"\nbackground = "#0B1622"\n'
    'surface = "#10233A"\npanel = "#173252"\nwarning = "#F5C451"\n'
    'error = "#FF8A8A"\nsuccess = "#4ADE80"\nforeground = "#EAF2FB"\n'
)
PAPER = (
    'dark = false\nprimary = "#2B6CB0"\naccent = "#2C7A7B"\nbackground = "#FFFDF7"\n'
    'surface = "#F4EFE3"\npanel = "#E7DFCC"\nforeground = "#2D2A24"\n'
    '[variables]\nforeground-muted = "#A39B87"\n'
)
BROKEN = 'primary = "#5EB1FF"\naccent = "#ff88"\n'


def _write_user_themes() -> None:
    folder = themes_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    (folder / "paper.toml").write_text(PAPER, encoding="utf-8")
    (folder / "sunset.toml").write_text(BROKEN, encoding="utf-8")


async def _open_appearance(pilot: Any) -> None:
    await _harness.wait_for_fleet(pilot)
    pilot.app.workspace_state.navigation_visible = False
    pilot.app.open_settings_screen("appearance")
    screen = await _harness.wait_for_screen(pilot, "SettingsScreen")
    await _harness.wait_until(
        pilot,
        lambda: screen._current_panel() is not None
        and screen._current_panel()._loaded
        and not screen._current_panel()._settling
        and bool(screen.query(".theme-card")),
        "the appearance cards to settle",
    )
    await pilot.pause()
    _harness.freeze_cursors(pilot.app)


@pytest.mark.parametrize("size", ["160x50", "100x30"])
def test_appearance_with_the_built_in_themes(screen_snapshot: Any, size: str) -> None:
    async def before(pilot: Any) -> None:
        await _open_appearance(pilot)

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], before)


@pytest.mark.parametrize("size", ["160x50", "100x30"])
def test_appearance_with_user_theme_files(screen_snapshot: Any, size: str) -> None:
    _write_user_themes()

    async def before(pilot: Any) -> None:
        await _open_appearance(pilot)
        card = pilot.app.screen.query_one("#theme_card_paper")
        card.focus()
        await pilot.pause()

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], before)


def test_appearance_name_prompt_asks_before_replacing(screen_snapshot: Any) -> None:
    _write_user_themes()

    async def before(pilot: Any) -> None:
        await _open_appearance(pilot)
        await pilot.click("#appearance_new")
        await _harness.wait_for_screen(pilot, "ThemeNamePromptScreen")
        prompt = pilot.app.screen
        prompt.query_one("#theme_name_input").value = "ocean"
        await pilot.pause()
        await pilot.click("#theme_name_save")
        await _harness.wait_until(
            pilot, lambda: "already exists" in str(prompt.query_one("#theme_name_error").render()),
            "the replace question",
        )
        await _harness.wait_until(
            pilot, lambda: not prompt.query_one("#theme_name_save").has_class("-active"), "the button to rest",
        )
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES["160x50"], before)


@pytest.mark.parametrize("size", ["160x50", "100x30"])
def test_appearance_shows_the_broken_file_and_a_warning_card(screen_snapshot: Any, size: str) -> None:
    _write_user_themes()

    async def before(pilot: Any) -> None:
        await _open_appearance(pilot)
        await _harness.wait_until(
            pilot, lambda: bool(pilot.app.screen.query(".theme-card.-error")), "the broken file's card",
        )
        await pilot.pause()

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], before)
