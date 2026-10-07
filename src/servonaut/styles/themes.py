"""Servonaut's own colour themes and the rules for picking the active one.

``servonaut`` follows the servonaut.dev palette: a near-black navy
background, slate cards, cyan highlights and a blue structural colour.
``servonaut-light`` keeps the same hues for light terminals. In both, every
colour used for text reads at WCAG AA (4.5:1) on the background and on cards;
the website's red is lightened a step for that, as its own danger text is.

Every stylesheet uses design tokens (``$primary``, ``$accent``, ``$surface``
and so on) rather than literal colours, so a registered theme recolours the
whole app. Text that carries ANSI colours (Rich text, command output) is
drawn through an ANSI palette instead; the two themes bring their own, so that
text matches them and stays readable on the light one. Textual's built-in
themes stay available alongside these two, with Textual's own palettes.
"""

from __future__ import annotations

from typing import Iterable, List, Tuple

from rich.terminal_theme import TerminalTheme
from textual.theme import Theme

SERVONAUT_DARK = Theme(
    name="servonaut",
    primary="#4FACFE",
    secondary="#00F2FE",
    accent="#00F2FE",
    warning="#FBB024",
    error="#F87171",
    success="#22C55E",
    foreground="#F9FAFB",
    background="#070B14",
    surface="#111827",
    panel="#1F2937",
    dark=True,
    variables={
        "block-cursor-foreground": "#070B14",
        "block-cursor-text-style": "bold",
        "border-blurred": "#1F2937",
        "button-color-foreground": "#070B14",
        "footer-key-foreground": "#00F2FE",
        "input-selection-background": "#4FACFE 35%",
    },
)

SERVONAUT_LIGHT = Theme(
    name="servonaut-light",
    primary="#0369A1",
    secondary="#0E7490",
    accent="#0E7490",
    warning="#A1460A",
    error="#B91C1C",
    success="#137333",
    foreground="#0F172A",
    background="#F8FAFC",
    surface="#EEF2F7",
    panel="#DCE3EC",
    dark=False,
    variables={
        "block-cursor-foreground": "#FFFFFF",
        "block-cursor-text-style": "bold",
        "border-blurred": "#CBD5E1",
        "button-color-foreground": "#FFFFFF",
        "footer-key-foreground": "#0369A1",
        "input-selection-background": "#0369A1 25%",
    },
)

SERVONAUT_THEMES: Tuple[Theme, ...] = (SERVONAUT_DARK, SERVONAUT_LIGHT)


def _rgb(colour: str) -> Tuple[int, int, int]:
    value = colour.lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def _ansi_palette(background: str, foreground: str, normal: str, bright: str) -> TerminalTheme:
    """A palette from space-separated colours: black red green yellow blue magenta cyan white."""
    return TerminalTheme(
        _rgb(background),
        _rgb(foreground),
        [_rgb(colour) for colour in normal.split()],
        [_rgb(colour) for colour in bright.split()],
    )


SERVONAUT_ANSI_DARK = _ansi_palette(
    SERVONAUT_DARK.background,
    SERVONAUT_DARK.foreground,
    "#1F2937 #F87171 #22C55E #FBB024 #4FACFE #C084FC #00F2FE #E5E7EB",
    "#9CA3AF #FCA5A5 #4ADE80 #FCD34D #93C5FD #D8B4FE #67E8F9 #F9FAFB",
)

SERVONAUT_ANSI_LIGHT = _ansi_palette(
    SERVONAUT_LIGHT.background,
    SERVONAUT_LIGHT.foreground,
    "#0F172A #B91C1C #137333 #A1460A #0369A1 #7E22CE #0E7490 #F1F5F9",
    "#475569 #C2410C #166534 #92400E #075985 #6B21A8 #155E75 #FFFFFF",
)

DEFAULT_THEME = SERVONAUT_DARK.name

# Earlier releases offered only "dark" and "light" and never applied either,
# so every saved config holds one of them. Read them as the Servonaut pair.
_LEGACY_THEME_NAMES = {
    "dark": SERVONAUT_DARK.name,
    "light": SERVONAUT_LIGHT.name,
}

# Names that title-casing would get wrong.
_THEME_LABELS = {
    SERVONAUT_DARK.name: "Servonaut",
    SERVONAUT_LIGHT.name: "Servonaut Light",
    "ansi-dark": "Terminal colours (dark)",
    "ansi-light": "Terminal colours (light)",
}


def resolve_theme_name(configured: str, available: Iterable[str]) -> str:
    """Return the theme to apply for a configured name.

    Legacy ``dark``/``light`` values map to the Servonaut pair; a name that is
    not registered (a typo, or a theme a newer Textual dropped) falls back to
    the default instead of raising.
    """
    name = _LEGACY_THEME_NAMES.get(configured, configured)
    return name if name in set(available) else DEFAULT_THEME


def is_servonaut_theme(name: str) -> bool:
    """Whether *name* is one of Servonaut's own themes."""
    return name in {theme.name for theme in SERVONAUT_THEMES}


def theme_label(name: str) -> str:
    """Human-readable label for a theme name."""
    return _THEME_LABELS.get(name) or name.replace("-", " ").title()


def theme_options(available: Iterable[str]) -> List[Tuple[str, str]]:
    """``(label, name)`` pairs for a picker: Servonaut's first, then A-Z."""
    names = set(available)
    own = [theme.name for theme in SERVONAUT_THEMES if theme.name in names]
    others = sorted(names.difference(own), key=theme_label)
    return [(theme_label(name), name) for name in own + others]
