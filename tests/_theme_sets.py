"""Representative theme coverage, with the full registry for release tests."""

from __future__ import annotations

import os
from collections.abc import Iterable

from textual.theme import BUILTIN_THEMES

from servonaut.styles.themes import SERVONAUT_THEMES

COLOUR_THEMES = ("servonaut", "servonaut-light", "ansi-dark", "ansi-light")
REPRESENTATIVE_THEMES = (*COLOUR_THEMES, "gruvbox", "solarized-light")
REGISTERED_THEMES = tuple(
    sorted(set(BUILTIN_THEMES) | {theme.name for theme in SERVONAUT_THEMES})
)
_THEME_DARK = {
    **{name: theme.dark for name, theme in BUILTIN_THEMES.items()},
    **{theme.name: theme.dark for theme in SERVONAUT_THEMES},
}


def all_themes_enabled() -> bool:
    """Release tests opt in to the full theme and repeated-opening census."""
    return os.environ.get("SERVONAUT_TEST_ALL_THEMES") == "1"


def theme_names(available: Iterable[str] = REGISTERED_THEMES) -> tuple[str, ...]:
    """Keep custom/ANSI palettes and a third-party dark/light pair on every run."""
    registry = set(available)
    names = (
        tuple(sorted(registry))
        if all_themes_enabled()
        else tuple(name for name in REPRESENTATIVE_THEMES if name in registry)
    )
    assert names, "Theme census must not be empty"
    assert any(_THEME_DARK.get(name) is True for name in names), "Missing dark theme"
    assert any(_THEME_DARK.get(name) is False for name in names), "Missing light theme"
    return names


def theme_chunks(
    available: Iterable[str] = REGISTERED_THEMES,
    *,
    max_size: int = 3,
) -> tuple[tuple[str, ...], ...]:
    """Distribute the selected themes evenly without duplicating app starts."""
    if max_size < 1:
        raise ValueError("Theme chunk size must be positive")
    names = theme_names(available)
    count = (len(names) + max_size - 1) // max_size
    return tuple(names[index::count] for index in range(count))
