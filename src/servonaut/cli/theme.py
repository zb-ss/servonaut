"""Headless commands for colour themes: ``servonaut theme list | export | check``."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

from tabulate import tabulate
from textual.theme import BUILTIN_THEMES, Theme

from servonaut.services.vault.display import terminal_safe
from servonaut.styles.readability import worst_reading
from servonaut.styles.theme_files import (
    SOURCE_USER,
    ThemeInfo,
    describe_themes,
    render_theme_file,
)
from servonaut.styles.themes import SERVONAUT_THEMES
from servonaut.styles.user_themes import (
    LoadResult,
    ThemeError,
    check_theme_file,
    errors_by_file,
    load_user_themes,
    problem_count,
    themes_dir,
)

_EXIT_OK = 0
_EXIT_INVALID = 1
_EXIT_USAGE = 2


def is_theme_command(args: argparse.Namespace) -> bool:
    return getattr(args, "subcommand", None) == "theme"


def add_theme_parser(subparsers: Any) -> None:
    theme = subparsers.add_parser("theme", help="List, export and check colour themes.")
    commands = theme.add_subparsers(dest="theme_command")
    commands.required = True
    commands.add_parser("list", help="List the built-in themes and the ones in your themes folder.")
    export = commands.add_parser(
        "export", help="Print any theme as a theme file, as a starting point for your own.",
    )
    export.add_argument("name", help="Name of a theme shown by `servonaut theme list`.")
    export.add_argument("--output", metavar="PATH", default=None, help="Write the file here instead of printing it.")
    export.add_argument("--force", action="store_true", help="Replace the output file if it exists.")
    check = commands.add_parser("check", help="Check a theme file; exits 1 if it has problems.")
    check.add_argument("file", help="Path of the .toml theme file.")


def handle_theme_command(args: argparse.Namespace) -> int:
    handlers = {"list": _list, "export": _export, "check": _check}
    return handlers[args.theme_command](args)


def _built_in_themes() -> Dict[str, Theme]:
    available = dict(BUILTIN_THEMES)
    available.update({theme.name: theme for theme in SERVONAUT_THEMES})
    return available


def _load_user_themes() -> LoadResult:
    return load_user_themes(reserved=_built_in_themes())


def _catalogue(result: LoadResult) -> List[ThemeInfo]:
    users = {loaded.theme.name: loaded for loaded in result.themes}
    available = _built_in_themes() | {name: loaded.theme for name, loaded in users.items()}
    return describe_themes(available, users)


def _status(info: ThemeInfo) -> str:
    worst = worst_reading(info.theme)
    if worst is None:
        return "ok"
    return f"warning: {worst.label.lower()} is {worst.ratio:.1f}:1 (needs 4.5:1)"


def _error_text(error: ThemeError) -> str:
    where = f"line {error.line}: " if error.line else ""
    return f"error: {where}{terminal_safe(error.message)}"


def _error_row(file: str, errors: List[ThemeError]) -> List[str]:
    """One row for a broken file: its first problem, and how many it has in all."""
    count = problem_count(errors)
    suffix = f" (and {count - 1} more problems)" if count > 1 else ""
    return [terminal_safe(file), "user", _error_text(errors[0]) + suffix]


def _list(_args: argparse.Namespace) -> int:
    result = _load_user_themes()
    rows = [
        [terminal_safe(info.name), "user" if info.source == SOURCE_USER else "built-in", _status(info)]
        for info in _catalogue(result)
    ]
    rows += [_error_row(file, errors) for file, errors in errors_by_file(result.errors).items()]
    print(tabulate(rows, headers=["NAME", "SOURCE", "STATUS"], tablefmt="plain"))
    print(f"\nUser themes go in {terminal_safe(themes_dir())}")
    return _EXIT_OK


def _export(args: argparse.Namespace) -> int:
    infos = {info.name: info for info in _catalogue(_load_user_themes())}
    info = infos.get(args.name)
    if info is None:
        print(f'No theme named "{terminal_safe(args.name)}". Run `servonaut theme list` to see them.', file=sys.stderr)
        return _EXIT_USAGE
    try:
        text = render_theme_file(info)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return _EXIT_USAGE
    if args.output is None:
        sys.stdout.write(text)
        return _EXIT_OK
    return _write_output(Path(args.output), text, args.force)


def _write_output(path: Path, text: str, force: bool) -> int:
    try:
        with path.open("w" if force else "x", encoding="utf-8") as handle:
            handle.write(text)
    except FileExistsError:
        print(f"{terminal_safe(path)} already exists; use --force to replace it.", file=sys.stderr)
        return _EXIT_USAGE
    except OSError as exc:
        print(f"Could not write {terminal_safe(path)}: {terminal_safe(exc.strerror or exc)}", file=sys.stderr)
        return _EXIT_USAGE
    print(f"Wrote {terminal_safe(path)}")
    return _EXIT_OK


def _other_theme_names(path: Path) -> List[str]:
    """Names a checked file must not take: built-in themes and the other theme files."""
    others = [
        loaded.theme.name for loaded in _load_user_themes().themes if not _same_file(loaded.path, path)
    ]
    return list(_built_in_themes()) + others


def _same_file(first: Path, second: Path) -> bool:
    try:
        return first.resolve() == second.resolve()
    except OSError:
        return False


def _check(args: argparse.Namespace) -> int:
    path = Path(args.file)
    errors = check_theme_file(path, taken=_other_theme_names(path))
    if not errors:
        print(f"{terminal_safe(path)}: ok")
        return _EXIT_OK
    for error in errors:
        where = f":{error.line}" if error.line else ""
        print(f"{terminal_safe(path)}{where}: {terminal_safe(error.message)}", file=sys.stderr)
    return _EXIT_INVALID
