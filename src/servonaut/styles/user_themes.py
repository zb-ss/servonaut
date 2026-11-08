"""Colour themes that users write as TOML files.

A theme file lives in ``<servonaut home>/themes/<name>.toml``. Its top-level
keys mirror :class:`textual.theme.Theme`; an optional ``[variables]`` table sets
a short allowlist of extra design tokens and an optional ``[ansi]`` table sets
the palette used for ANSI-coloured text. Files are parsed as data only.

Loading never raises: every problem becomes a :class:`ThemeError`, and the
files that are fine still load, so a broken theme cannot stop the app.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from rich.terminal_theme import TerminalTheme
from textual.color import Color, ColorParseError
from textual.theme import Theme

from servonaut.runtime import data_root_for_home

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on Python 3.10 only
    import tomli as tomllib

logger = logging.getLogger(__name__)

THEMES_DIRNAME = "themes"
THEME_FILE_SUFFIX = ".toml"
THEME_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
# Theme files are small; a cap keeps a stray large file from being read whole.
MAX_THEME_FILE_BYTES = 64 * 1024
MAX_THEME_FILES = 50
# A file with more faults than this lists the first few and counts the rest.
MAX_PROBLEMS_PER_FILE = 10

# Keys that are not colours.
_NAME_KEY = "name"
_DARK_KEY = "dark"
_TABLE_KEYS = ("variables", "ansi")
# Required colour: the one every other colour is derived from.
_REQUIRED_COLOURS = ("primary",)
# Textual derives the rest of a theme from these when they are left out.
OPTIONAL_COLOURS = (
    "secondary", "accent", "warning", "error", "success",
    "foreground", "background", "surface", "panel", "boost",
)
COLOUR_KEYS = _REQUIRED_COLOURS + OPTIONAL_COLOURS

# Design tokens a theme may override. They are the ones Servonaut's own themes
# set plus the Textual tokens its stylesheets read, so every entry changes
# something visible. A value is a colour, optionally followed by an opacity
# such as ``#4FACFE 35%``.
VARIABLE_COLOUR_KEYS = (
    "block-cursor-background",
    "block-cursor-foreground",
    "border",
    "border-blurred",
    "button-color-foreground",
    "footer-key-foreground",
    "foreground-muted",
    "input-selection-background",
    "primary-background",
    "text",
    "text-accent",
    "text-error",
    "text-muted",
    "text-primary",
    "text-secondary",
    "text-success",
    "text-warning",
)
TEXT_STYLE_KEY = "block-cursor-text-style"
TEXT_STYLE_WORDS = frozenset({"none", "bold", "italic", "underline", "reverse", "strike"})
VARIABLE_KEYS = VARIABLE_COLOUR_KEYS + (TEXT_STYLE_KEY,)

ANSI_SLOTS = 8
ANSI_KEYS = ("normal", "bright")

_SHOWN_MAX = 40
# #RGBA and #RRGGBBAA: Textual's own themes write some variables this way.
_HEX_WITH_ALPHA = re.compile(r"^#(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{8})$")
_PERCENT = re.compile(r"^(?P<colour>.+?)\s+(?P<percent>\d{1,3})%$")
_TOML_LINE = re.compile(r"line (\d+)")


@dataclass(frozen=True)
class ThemeError:
    """One problem found in a theme file."""

    file: str
    line: Optional[int]
    message: str


@dataclass(frozen=True)
class UserTheme:
    """A valid theme file: the Textual theme, its ANSI palette and its file."""

    theme: Theme
    ansi: TerminalTheme
    path: Path


@dataclass(frozen=True)
class LoadResult:
    """What a scan of the themes folder found."""

    themes: Tuple[UserTheme, ...] = ()
    errors: Tuple[ThemeError, ...] = ()


class _FileProblem(Exception):
    """A problem in one theme file, carrying the line it belongs to."""

    def __init__(self, message: str, line: Optional[int] = None) -> None:
        super().__init__(message)
        self.message = message
        self.line = line


def _shown(value: object) -> str:
    """*value* as it appears in a message: quoted, and short even for a huge entry."""
    text = json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= _SHOWN_MAX else text[: _SHOWN_MAX - 1] + "…"


def themes_dir(home: Optional[Path] = None) -> Path:
    """The folder user themes live in, under the per-user data root."""
    return data_root_for_home(home or Path.home()) / THEMES_DIRNAME


def is_valid_theme_name(name: object) -> bool:
    """Whether *name* may name a theme and a file."""
    return isinstance(name, str) and THEME_NAME_PATTERN.fullmatch(name) is not None


# ----------------------------------------------------------------------
# Colour helpers
# ----------------------------------------------------------------------


def parse_colour(value: object) -> Optional[Color]:
    """An opaque, non-ANSI colour for *value*, or ``None`` if it is not one."""
    if not isinstance(value, str):
        return None
    try:
        colour = Color.parse(value.strip())
    except ColorParseError:
        return None
    if colour.ansi is not None or colour.a < 1:
        return None
    return colour


def _parse_variable_colour(value: object) -> Optional[str]:
    """*value* normalised to ``#RRGGBB`` or ``#RRGGBB NN%``, else ``None``."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if _HEX_WITH_ALPHA.match(text):
        return _alpha_hex_as_opacity(text)
    percent = _PERCENT.match(text)
    colour = parse_colour(percent.group("colour") if percent else text)
    if colour is None:
        return None
    if percent is None:
        return colour.hex
    if int(percent.group("percent")) > 100:
        return None
    return f"{colour.hex} {percent.group('percent')}%"


def _alpha_hex_as_opacity(text: str) -> Optional[str]:
    """``#RRGGBBAA`` as ``#RRGGBB NN%``, the form the stylesheet variables use."""
    try:
        colour = Color.parse(text)
    except ColorParseError:
        return None
    opaque = Color(colour.r, colour.g, colour.b).hex
    percent = round(colour.a * 100)
    return opaque if percent >= 100 else f"{opaque} {percent}%"


def _mix(first: Color, second: Color, amount: float) -> Color:
    return first.blend(second, amount)


def _rgb(colour: Color) -> Tuple[int, int, int]:
    return colour.r, colour.g, colour.b


# ----------------------------------------------------------------------
# ANSI palette
# ----------------------------------------------------------------------


def resolved_colours(theme: Theme) -> Dict[str, Color]:
    """The theme's colours with Textual's own defaults filled in."""
    generated = theme.to_color_system().generate()
    resolved: Dict[str, Color] = {}
    for key in ("primary", "accent", "error", "success", "warning", "background", "foreground", "surface", "panel"):
        explicit = parse_colour(getattr(theme, key) or "")
        resolved[key] = explicit or parse_colour(generated.get(key, "")) or Color(0, 0, 0)
    return resolved


def derive_ansi_palette(theme: Theme) -> TerminalTheme:
    """An ANSI palette drawn from a theme's own colours.

    Used when a theme file has no ``[ansi]`` table: the colours that carry
    meaning (error, success, warning) keep their slot so command output reads
    the way the rest of the app does.
    """
    colours = resolved_colours(theme)
    background, foreground = colours["background"], colours["foreground"]
    primary, error = colours["primary"], colours["error"]
    magenta = _mix(error, primary, 0.5)
    if theme.dark:
        black, white = colours["panel"], _mix(foreground, background, 0.1)
    else:
        black, white = foreground, background
    normal = [black, error, colours["success"], colours["warning"], primary, magenta, colours["accent"], white]
    if theme.dark:
        bright = [_mix(black, foreground, 0.4)] + [_mix(c, foreground, 0.25) for c in normal[1:7]] + [foreground]
    else:
        bright = [_mix(black, background, 0.3)] + [_mix(c, foreground, 0.2) for c in normal[1:7]] + [background]
    return TerminalTheme(_rgb(background), _rgb(foreground), [_rgb(c) for c in normal], [_rgb(c) for c in bright])


def _read_ansi(table: Mapping[str, Any], theme: Theme) -> Tuple[TerminalTheme, List[str]]:
    """The palette from an ``[ansi]`` table and what is wrong with it."""
    problems: List[str] = []
    for key in table:
        if key not in ANSI_KEYS:
            problems.append(f'[ansi] has an unknown key {_shown(key)}; use "normal" and "bright"')
    palettes: Dict[str, List[Color]] = {}
    for key in ANSI_KEYS:
        palette = _read_ansi_list(key, table.get(key), problems)
        if palette is not None:
            palettes[key] = palette
    if problems:
        return derive_ansi_palette(theme), problems
    if set(palettes) != set(ANSI_KEYS):
        return derive_ansi_palette(theme), ['[ansi] needs both "normal" and "bright" lists']
    colours = resolved_colours(theme)
    background, foreground = colours["background"], colours["foreground"]
    return (
        TerminalTheme(
            _rgb(background), _rgb(foreground),
            [_rgb(c) for c in palettes["normal"]], [_rgb(c) for c in palettes["bright"]],
        ),
        [],
    )


def _read_ansi_list(key: str, value: object, problems: List[str]) -> Optional[List[Color]]:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) != ANSI_SLOTS:
        problems.append(f'[ansi] "{key}" must be a list of {ANSI_SLOTS} colours')
        return None
    colours = [parse_colour(item) for item in value]
    for index, colour in enumerate(colours):
        if colour is None:
            problems.append(f'[ansi] "{key}" entry {index + 1} is not a colour ({_shown(value[index])})')
    return None if None in colours else colours  # type: ignore[return-value]


# ----------------------------------------------------------------------
# One file
# ----------------------------------------------------------------------


_KEY_LINE = re.compile(r'^\s*(?:"?(?P<key>[^"=\s\[\]]+)"?\s*=|\[(?P<table>[^\[\]]+)\])')


def _line_index(source: str) -> Dict[str, int]:
    """The 1-based line that first sets each key or opens each table, in one pass."""
    index: Dict[str, int] = {}
    for number, text in enumerate(source.splitlines(), start=1):
        found = _KEY_LINE.match(text)
        if found:
            index.setdefault(found.group("key") or found.group("table").strip(), number)
    return index


def _find_line(index: Mapping[str, int], key: str) -> Optional[int]:
    return index.get(key)


def _read_source(path: Path) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise _FileProblem(f"Could not be read: {exc.strerror or exc}") from exc
    if size > MAX_THEME_FILE_BYTES:
        raise _FileProblem(f"Is larger than {MAX_THEME_FILE_BYTES // 1024} KiB")
    try:
        # Read one byte past the cap so a file that grew after the stat still fails.
        with path.open("rb") as handle:
            raw = handle.read(MAX_THEME_FILE_BYTES + 1)
        if len(raw) > MAX_THEME_FILE_BYTES:
            raise _FileProblem(f"Is larger than {MAX_THEME_FILE_BYTES // 1024} KiB")
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _FileProblem("Is not valid UTF-8 text") from exc
    except OSError as exc:
        raise _FileProblem(f"Could not be read: {exc.strerror or exc}") from exc


def _parse_toml(source: str) -> Dict[str, Any]:
    try:
        return tomllib.loads(source)
    except tomllib.TOMLDecodeError as exc:
        found = _TOML_LINE.search(str(exc))
        raise _FileProblem(f"Is not valid TOML: {exc}", int(found.group(1)) if found else None) from exc
    except RecursionError as exc:
        raise _FileProblem("Is nested too deeply") from exc


def _theme_name(data: Mapping[str, Any], path: Path, lines: Mapping[str, int]) -> str:
    name = data.get(_NAME_KEY, path.stem)
    if not is_valid_theme_name(name):
        raise _FileProblem(
            'The theme name must be 1-40 characters: lowercase letters, digits and "-", '
            "starting with a letter or digit",
            _find_line(lines, _NAME_KEY) if _NAME_KEY in data else None,
        )
    return str(name)


def _check_keys(data: Mapping[str, Any], lines: Mapping[str, int], problems: List[_FileProblem]) -> None:
    known = {_NAME_KEY, _DARK_KEY, *COLOUR_KEYS, *_TABLE_KEYS}
    for key in data:
        if key not in known:
            problems.append(_FileProblem(f"Unknown key {_shown(key)}", _find_line(lines, key)))


def _read_colours(data: Mapping[str, Any], lines: Mapping[str, int], problems: List[_FileProblem]) -> Dict[str, str]:
    colours: Dict[str, str] = {}
    for key in COLOUR_KEYS:
        if key not in data:
            if key in _REQUIRED_COLOURS:
                problems.append(_FileProblem(f'Missing the required colour "{key}"'))
            continue
        colour = parse_colour(data[key])
        if colour is None:
            problems.append(_FileProblem(
                f'"{key}" is not a colour ({_shown(data[key])}); write it like "#RRGGBB"', _find_line(lines, key),
            ))
            continue
        colours[key] = colour.hex
    return colours


def _read_variables(data: Mapping[str, Any], lines: Mapping[str, int], problems: List[_FileProblem]) -> Dict[str, str]:
    table = data.get("variables", {})
    if not isinstance(table, dict):
        problems.append(_FileProblem('"variables" must be a table', _find_line(lines, "variables")))
        return {}
    variables: Dict[str, str] = {}
    for key, value in table.items():
        line = _find_line(lines, key)
        if key not in VARIABLE_KEYS:
            problems.append(_FileProblem(f"[variables] has an unknown key {_shown(key)}", line))
        elif key == TEXT_STYLE_KEY:
            style = _read_text_style(value)
            if style is None:
                problems.append(_FileProblem(
                    f'"{key}" must use only: {", ".join(sorted(TEXT_STYLE_WORDS))}', line,
                ))
            else:
                variables[key] = style
        else:
            colour = _parse_variable_colour(value)
            if colour is None:
                problems.append(_FileProblem(f'"{key}" is not a colour ({_shown(value)})', line))
            else:
                variables[key] = colour
    return variables


def _read_text_style(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    words = value.split()
    if not words or not all(word in TEXT_STYLE_WORDS for word in words):
        return None
    return " ".join(words)


def _read_dark(data: Mapping[str, Any], lines: Mapping[str, int], problems: List[_FileProblem]) -> bool:
    value = data.get(_DARK_KEY, True)
    if isinstance(value, bool):
        return value
    problems.append(_FileProblem('"dark" must be true or false', _find_line(lines, _DARK_KEY)))
    return True


def _inspect(path: Path, taken: Iterable[str]) -> Tuple[Optional[UserTheme], List[_FileProblem]]:
    """Read one file: the theme if it is valid, and every fault found if not."""
    try:
        source = _read_source(path)
        data = _parse_toml(source)
        lines = _line_index(source)
        name = _theme_name(data, path, lines)
        if name in set(taken):
            raise _FileProblem(f'The theme name "{name}" is already used', _find_line(lines, _NAME_KEY))
    except _FileProblem as problem:
        return None, [problem]
    problems: List[_FileProblem] = []
    _check_keys(data, lines, problems)
    colours = _read_colours(data, lines, problems)
    variables = _read_variables(data, lines, problems)
    dark = _read_dark(data, lines, problems)
    ansi_table = data.get("ansi")
    if ansi_table is not None and not isinstance(ansi_table, dict):
        problems.append(_FileProblem('"ansi" must be a table', _find_line(lines, "ansi")))
        ansi_table = None
    if problems:
        return None, _capped(problems + _ansi_problems(ansi_table, lines))
    theme = Theme(name=name, dark=dark, variables=variables, **colours)
    if ansi_table is None:
        return UserTheme(theme, derive_ansi_palette(theme), path), []
    palette, ansi_faults = _read_ansi(ansi_table, theme)
    if ansi_faults:
        return None, _capped(_ansi_problems(ansi_table, lines, theme))
    return UserTheme(theme, palette, path), []


def _capped(problems: List[_FileProblem]) -> List[_FileProblem]:
    """The first few faults, then a count of the rest, so a hostile file stays small."""
    if len(problems) <= MAX_PROBLEMS_PER_FILE:
        return problems
    hidden = len(problems) - MAX_PROBLEMS_PER_FILE
    return problems[:MAX_PROBLEMS_PER_FILE] + [_FileProblem(f"…and {hidden} more problems")]


def _ansi_problems(table: Optional[Mapping[str, Any]], lines: Mapping[str, int], theme: Optional[Theme] = None) -> List[_FileProblem]:
    if table is None:
        return []
    _, faults = _read_ansi(table, theme or Theme(name="check", primary="#000000"))
    line = _find_line(lines, "ansi")
    return [_FileProblem(message, line) for message in faults]


def check_theme_file(path: Path, taken: Iterable[str] = ()) -> List[ThemeError]:
    """Every problem in one theme file; an empty list means it is valid.

    Unlike a scan, this reports all the faults of the file at once, which is
    what someone editing it wants.
    """
    _, problems = _inspect(path, taken)
    return [ThemeError(path.name, problem.line, problem.message) for problem in problems]


# ----------------------------------------------------------------------
# The folder
# ----------------------------------------------------------------------


def _theme_files(folder: Path) -> Tuple[List[Path], List[ThemeError]]:
    """The theme files to read, in name order, and a note if some were skipped."""
    try:
        entries = sorted(
            (entry for entry in folder.iterdir() if entry.suffix == THEME_FILE_SUFFIX),
            key=lambda entry: entry.name,
        )
    except FileNotFoundError:
        return [], []
    except OSError as exc:
        return [], [ThemeError(folder.name, None, f"The themes folder could not be read: {exc.strerror or exc}")]
    files = [entry for entry in entries if entry.is_file()]
    if len(files) <= MAX_THEME_FILES:
        return files, []
    note = ThemeError(
        folder.name, None,
        f"Only the first {MAX_THEME_FILES} theme files are read; {len(files) - MAX_THEME_FILES} were skipped",
    )
    return files[:MAX_THEME_FILES], [note]


def load_user_themes(reserved: Iterable[str] = (), folder: Optional[Path] = None) -> LoadResult:
    """Read every theme file in the themes folder.

    *reserved* holds the names that are already taken (the built-in themes and
    Textual's own). Never raises.
    """
    taken = set(reserved)
    folder = folder or themes_dir()
    files, errors = _theme_files(folder)
    themes: List[UserTheme] = []
    for path in files:
        try:
            loaded, problems = _inspect(path, taken)
        except RecursionError:
            errors.append(ThemeError(path.name, None, "Is nested too deeply"))
            continue
        except Exception:  # noqa: BLE001 - a theme file must never stop the app
            logger.exception("Theme file %s failed to load", path.name)
            errors.append(ThemeError(path.name, None, "Could not be loaded"))
            continue
        errors.extend(ThemeError(path.name, problem.line, problem.message) for problem in problems)
        if loaded is not None:
            taken.add(loaded.theme.name)
            themes.append(loaded)
    return LoadResult(tuple(themes), tuple(errors))


_MORE_PROBLEMS = re.compile(r"^…and (\d+) more problems$")


def is_more_problems_note(error: ThemeError) -> bool:
    """Whether *error* is the note that counts the faults a file's list left out."""
    return _MORE_PROBLEMS.match(error.message) is not None


def errors_by_file(errors: Iterable[ThemeError]) -> Dict[str, List[ThemeError]]:
    """The faults of each theme file together, in scan order; folder-level notes are left out."""
    grouped: Dict[str, List[ThemeError]] = {}
    for error in errors:
        if error.file.endswith(THEME_FILE_SUFFIX):
            grouped.setdefault(error.file, []).append(error)
    return grouped


def problem_count(errors: Iterable[ThemeError]) -> int:
    """How many faults a file has, counting those its list left out."""
    total = 0
    for error in errors:
        found = _MORE_PROBLEMS.match(error.message)
        total += int(found.group(1)) if found else 1
    return total
