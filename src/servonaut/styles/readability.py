"""WCAG contrast readings for the colour pairs a theme's text relies on."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from textual.color import Color
from textual.theme import Theme

from servonaut.styles.user_themes import parse_colour, resolved_colours

# WCAG 2 level AA for normal-size text.
MIN_CONTRAST = 4.5


@dataclass(frozen=True)
class Reading:
    """One pair of text and fill colours and how well they contrast."""

    label: str
    ratio: float

    @property
    def is_readable(self) -> bool:
        return self.ratio >= MIN_CONTRAST


def contrast_ratio(foreground: Color, background: Color) -> float:
    """WCAG 2 contrast ratio between two opaque colours."""

    def luminance(colour: Color) -> float:
        def channel(value: int) -> float:
            scaled = value / 255
            return scaled / 12.92 if scaled <= 0.03928 else ((scaled + 0.055) / 1.055) ** 2.4

        return 0.2126 * channel(colour.r) + 0.7152 * channel(colour.g) + 0.0722 * channel(colour.b)

    lighter, darker = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def _tokens(theme: Theme) -> Dict[str, str]:
    """The theme's design tokens as the app resolves them: generated, then overridden."""
    tokens = dict(theme.to_color_system().generate())
    tokens.update(theme.variables)
    return tokens


def _opaque(value: str, over: Color) -> Optional[Color]:
    """A token as an opaque colour; one with opacity is laid over *over*."""
    text = value.strip()
    if text.endswith("%") and " " in text:
        colour_text, _, percent = text.rpartition(" ")
        base = parse_colour(colour_text)
        if base is None or not percent[:-1].isdigit():
            return None
        return over.blend(base, int(percent[:-1]) / 100)
    try:
        colour = Color.parse(text)
    except Exception:  # noqa: BLE001 - "auto" and other non-colours
        return None
    return over.blend(colour, colour.a) if colour.a < 1 else colour


def token_colour(theme: Theme, token: str, over: Color) -> Optional[Color]:
    """The colour the app draws for a design token, laid over *over* if it has opacity."""
    value = _tokens(theme).get(token)
    return None if value is None else _opaque(value, over)


def readings_for(theme: Theme) -> Tuple[Reading, ...]:
    """Contrast of the text colours the app uses on the fills they sit on.

    A theme that follows the terminal's own colours has none to measure.
    """
    if theme.ansi:
        return ()
    colours = resolved_colours(theme)
    background, surface = colours["background"], colours["surface"]
    text = colours["foreground"]
    muted = token_colour(theme, "foreground-muted", surface) or text
    accent = token_colour(theme, "text-accent", surface) or colours["accent"]
    error = token_colour(theme, "text-error", surface) or colours["error"]
    return (
        Reading("Text on background", contrast_ratio(text, background)),
        Reading("Text on cards", contrast_ratio(text, surface)),
        Reading("Muted text on cards", contrast_ratio(muted, surface)),
        Reading("Accent text on cards", contrast_ratio(accent, surface)),
        Reading("Error text on cards", contrast_ratio(error, surface)),
    )


def worst_reading(theme: Theme) -> Optional[Reading]:
    """The lowest reading when it falls short of the minimum, else ``None``."""
    readings = readings_for(theme)
    if not readings:
        return None
    worst = min(readings, key=lambda reading: reading.ratio)
    return None if worst.is_readable else worst
