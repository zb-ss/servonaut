"""Servonaut's colour themes and how the app applies and remembers them."""

from __future__ import annotations

import pytest
from textual.app import App
from textual.color import Color

from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.styles.themes import (
    DEFAULT_THEME,
    SERVONAUT_ANSI_DARK,
    SERVONAUT_ANSI_LIGHT,
    SERVONAUT_DARK,
    SERVONAUT_LIGHT,
    resolve_theme_name,
    theme_label,
    theme_options,
)

BUILT_IN = set(App().available_themes)
ALL_THEMES = BUILT_IN | {SERVONAUT_DARK.name, SERVONAUT_LIGHT.name}


def _contrast(foreground: str, background: str) -> float:
    """WCAG 2 contrast ratio between two colours."""

    def luminance(colour: str) -> float:
        def channel(value: int) -> float:
            c = value / 255
            return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

        r, g, b = Color.parse(colour).rgb
        return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)

    lighter, darker = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


# ---------------------------------------------------------------------------
# Theme definitions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("theme", [SERVONAUT_DARK, SERVONAUT_LIGHT], ids=lambda t: t.name)
@pytest.mark.parametrize("role", ["primary", "accent", "success", "warning", "error", "foreground"])
def test_text_colours_read_at_wcag_aa(theme, role) -> None:
    """Titles, footer keys and status text use these colours on screens and cards."""
    for fill in (theme.background, theme.surface):
        assert _contrast(getattr(theme, role), fill) >= 4.5


@pytest.mark.parametrize("theme", [SERVONAUT_DARK, SERVONAUT_LIGHT], ids=lambda t: t.name)
def test_text_on_highlights_reads_at_wcag_aa(theme) -> None:
    """Buttons and the table cursor print their own foreground on these fills."""
    for fill in (theme.primary, theme.accent):
        assert _contrast(theme.variables["button-color-foreground"], fill) >= 4.5
        assert _contrast(theme.variables["block-cursor-foreground"], fill) >= 4.5


# ANSI palette slots that carry text: red green yellow blue magenta cyan, then
# bright black (grey) and the bright colours. Black and white are left out:
# on a light screen white text is unreadable in any palette, and vice versa.
_TEXT_SLOTS = [1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14]


@pytest.mark.parametrize(
    ("palette", "theme"),
    [(SERVONAUT_ANSI_DARK, SERVONAUT_DARK), (SERVONAUT_ANSI_LIGHT, SERVONAUT_LIGHT)],
    ids=["dark", "light"],
)
def test_markup_colours_read_at_wcag_aa(palette, theme) -> None:
    """ANSI colours (Rich text, command output) are drawn through these palettes."""
    for slot in _TEXT_SLOTS:
        colour = palette.ansi_colors[slot].hex
        for fill in (theme.background, theme.surface):
            assert _contrast(colour, fill) >= 4.5, (slot, colour, fill)


def test_dark_theme_uses_the_website_palette() -> None:
    assert SERVONAUT_DARK.background == "#070B14"
    assert SERVONAUT_DARK.surface == "#111827"
    assert SERVONAUT_DARK.accent == "#00F2FE"
    assert SERVONAUT_DARK.primary == "#4FACFE"
    assert SERVONAUT_DARK.dark and not SERVONAUT_LIGHT.dark


# ---------------------------------------------------------------------------
# Name resolution and picker options
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        ("dark", "servonaut"),
        ("light", "servonaut-light"),
        ("servonaut-light", "servonaut-light"),
        ("nord", "nord"),
        ("no-such-theme", DEFAULT_THEME),
        ("", DEFAULT_THEME),
    ],
)
def test_resolve_theme_name(configured, expected) -> None:
    assert resolve_theme_name(configured, ALL_THEMES) == expected


def test_new_configs_default_to_servonaut() -> None:
    assert AppConfig().theme == DEFAULT_THEME == "servonaut"


def test_picker_lists_servonaut_first_then_every_other_theme_by_label() -> None:
    options = theme_options(ALL_THEMES)
    assert options[:2] == [("Servonaut", "servonaut"), ("Servonaut Light", "servonaut-light")]
    rest = [label for label, _ in options[2:]]
    assert rest == sorted(rest)
    assert {name for _, name in options} == ALL_THEMES


def test_labels() -> None:
    assert theme_label("tokyo-night") == "Tokyo Night"
    assert theme_label("ansi-dark") == "Terminal colours (dark)"


# ---------------------------------------------------------------------------
# The app: registration, applying the saved theme, remembering a new one
# ---------------------------------------------------------------------------


def _app(tmp_path, theme: str) -> tuple[ServonautApp, ConfigManager]:
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.update(theme=theme)
    app = ServonautApp(config_path=tmp_path / "config.json")
    app.config_manager = manager
    return app, manager


def test_app_registers_both_servonaut_themes(tmp_path) -> None:
    app = ServonautApp(config_path=tmp_path / "config.json")
    assert {SERVONAUT_DARK.name, SERVONAUT_LIGHT.name} <= set(app.available_themes)
    assert BUILT_IN <= set(app.available_themes)


@pytest.mark.parametrize(
    ("saved", "applied"),
    [("dark", "servonaut"), ("light", "servonaut-light"), ("gruvbox", "gruvbox"),
     ("gone-theme", "servonaut")],
)
def test_saved_theme_is_applied_without_rewriting_the_config(
    tmp_path, monkeypatch, saved, applied
) -> None:
    monkeypatch.delenv("TEXTUAL_THEME", raising=False)
    app, manager = _app(tmp_path, saved)
    before = (tmp_path / "config.json").read_bytes()

    app._apply_configured_theme(saved)

    assert app.theme == applied
    assert manager.get().theme == saved
    assert (tmp_path / "config.json").read_bytes() == before


def test_textual_theme_variable_wins_for_the_run(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("TEXTUAL_THEME", "nord")
    app, manager = _app(tmp_path, "servonaut-light")
    current = app.theme

    app._apply_configured_theme("servonaut-light")

    assert app.theme == current
    assert manager.get().theme == "servonaut-light"


def test_a_new_theme_is_saved(tmp_path) -> None:
    app, manager = _app(tmp_path, "dark")

    app.theme = "tokyo-night"

    assert ConfigManager(config_path=tmp_path / "config.json").load().theme == "tokyo-night"


def test_a_failed_save_keeps_the_theme_for_the_session(tmp_path, monkeypatch) -> None:
    app, manager = _app(tmp_path, "dark")

    def refuse(**_fields):
        raise PermissionError("read-only config")

    monkeypatch.setattr(manager, "update", refuse)
    app.theme = "dracula"

    assert app.theme == "dracula"


@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
def test_servonaut_themes_bring_their_markup_palettes(tmp_path, theme) -> None:
    app, _ = _app(tmp_path, "dark")
    textual_palettes = (app.ansi_theme_dark, app.ansi_theme_light)

    app.theme = theme
    assert (app.ansi_theme_dark, app.ansi_theme_light) == (
        SERVONAUT_ANSI_DARK, SERVONAUT_ANSI_LIGHT,
    )

    app.theme = "nord"
    assert (app.ansi_theme_dark, app.ansi_theme_light) == textual_palettes
