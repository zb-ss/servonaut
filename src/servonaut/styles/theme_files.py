"""The theme catalogue, and writing a theme out as a file users can edit."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, Optional

from rich.terminal_theme import TerminalTheme
from textual.theme import Theme

from servonaut.styles.themes import (
    SERVONAUT_ANSI_DARK,
    SERVONAUT_ANSI_LIGHT,
    SERVONAUT_DARK,
    SERVONAUT_LIGHT,
    SERVONAUT_THEMES,
    theme_label,
)
from servonaut.styles.user_themes import (
    COLOUR_KEYS,
    THEME_FILE_SUFFIX,
    VARIABLE_KEYS,
    UserTheme,
    is_valid_theme_name,
    resolved_colours,
    themes_dir,
)

SOURCE_BUILT_IN = "built-in"
SOURCE_USER = "user"
GUIDE_PATH = "docs/themes.md"
GUIDE_URL = "https://github.com/zb-ss/servonaut/blob/master/docs/themes.md"

_SERVONAUT_PALETTES = {
    SERVONAUT_DARK.name: SERVONAUT_ANSI_DARK,
    SERVONAUT_LIGHT.name: SERVONAUT_ANSI_LIGHT,
}


@dataclass(frozen=True)
class ThemeInfo:
    """A registered theme as the picker and the CLI list it."""

    name: str
    label: str
    source: str
    theme: Theme
    ansi: Optional[TerminalTheme]
    path: Optional[Path]


def describe_themes(available: Mapping[str, Theme], user_themes: Mapping[str, UserTheme]) -> List[ThemeInfo]:
    """Every registered theme: Servonaut's own, then the user's, then Textual's."""
    own = [theme.name for theme in SERVONAUT_THEMES if theme.name in available]
    yours = sorted((name for name in user_themes if name in available), key=theme_label)
    others = sorted(set(available).difference(own, yours), key=theme_label)
    return [_describe(name, available[name], user_themes.get(name)) for name in own + yours + others]


def _describe(name: str, theme: Theme, user: Optional[UserTheme]) -> ThemeInfo:
    if user is not None:
        return ThemeInfo(name, theme_label(name), SOURCE_USER, theme, user.ansi, user.path)
    return ThemeInfo(name, theme_label(name), SOURCE_BUILT_IN, theme, _SERVONAUT_PALETTES.get(name), None)


def render_theme_file(info: ThemeInfo, name: Optional[str] = None) -> str:
    """The TOML for *info*: every colour written out, ready to edit.

    Only the variables a theme file may set are written; a theme that follows
    the terminal's colours (ANSI) cannot be written as a file.
    """
    theme = info.theme
    if theme.ansi:
        raise ValueError(f'"{info.label}" follows the terminal colours and has no colour values to export')
    colours = resolved_colours(theme)
    lines = [
        "# Servonaut colour theme. Every key is explained in",
        f"# {GUIDE_PATH} ({GUIDE_URL})",
        f'name = "{name or info.name}"',
        f"dark = {'true' if theme.dark else 'false'}",
    ]
    lines += [f'{key} = "{colours[key].hex}"' for key in COLOUR_KEYS if key in colours]
    variables = {key: value for key, value in theme.variables.items() if key in VARIABLE_KEYS}
    if variables:
        lines += ["", "[variables]"] + [f'{key} = "{value}"' for key, value in sorted(variables.items())]
    if info.ansi is not None:
        lines += ["", "[ansi]", _ansi_line("normal", info.ansi, 0), _ansi_line("bright", info.ansi, 8)]
    return "\n".join(lines) + "\n"


def _ansi_line(key: str, palette: TerminalTheme, start: int) -> str:
    entries = ", ".join(
        f'"#{colour.red:02X}{colour.green:02X}{colour.blue:02X}"'
        for colour in (palette.ansi_colors[index] for index in range(start, start + 8))
    )
    return f"{key} = [{entries}]"


class ThemeFileError(Exception):
    """A theme file could not be written; the message is fit to show."""


def write_theme_file(name: str, text: str, overwrite: bool = False, folder: Optional[Path] = None) -> Path:
    """Write ``<themes folder>/<name>.toml`` atomically and return its path.

    The name must be a valid theme name, so it can never carry a path
    separator; the file is only ever created inside the themes folder.
    """
    if not is_valid_theme_name(name):
        raise ThemeFileError("Use 1-40 lowercase letters, digits or dashes, starting with a letter or digit")
    folder = folder or themes_dir()
    target = folder / f"{name}{THEME_FILE_SUFFIX}"
    try:
        folder.mkdir(parents=True, exist_ok=True)
        if target.exists() and not overwrite:
            raise ThemeFileError(f'"{target.name}" already exists')
        _replace_atomically(target, text)
    except OSError as exc:
        raise ThemeFileError(f"Could not write the file: {exc.strerror or exc}") from exc
    return target


def _replace_atomically(target: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=target.parent, prefix=".theme-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(temporary, target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
