"""A key hint written in square brackets inside markup is read as a style tag and vanishes.

``[o] Open``, ``Press [esc] to close``, ``[Enter] Apply`` and ``Keys: [o]pen``
all lose their key when a ``Static`` or ``Label`` renders them; write the key
as ``[b]o[/b]`` instead.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import servonaut

_KEY_NAMES = r"esc|escape|enter|return|tab|space|backspace|delete|home|end|pageup|pagedown|f\d{1,2}|(?:ctrl|alt|shift)\+\w+"
# A bracketed key name, or a single letter, anywhere in the string.
_BRACKETED_KEY = re.compile(rf"\[(?P<key>{_KEY_NAMES}|[a-zA-Z?])\]", re.IGNORECASE)


def _is_style_tag(text: str, match: re.Match) -> bool:
    """A real tag (``[b]…[/b]``) has its closing tag in the same string."""
    key = match.group("key").lower()
    return f"[/{key}]" in text.lower() or (key in {"b", "i", "u", "s"} and "[/]" in text)


def _strings(tree: ast.AST):
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.body and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    parts = {
        id(piece)
        for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)
        for piece in node.values if isinstance(piece, ast.Constant)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            # An f-string is one markup string: its tags may close after a field.
            yield node.lineno, "".join(
                piece.value if isinstance(piece, ast.Constant) else "{}" for piece in node.values
            )
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings | parts:
            yield node.lineno, node.value


def _offenders(texts) -> list[str]:
    return [
        f"{where}: {text[:60]!r}"
        for where, text in texts
        if any(not _is_style_tag(text, match) for match in _BRACKETED_KEY.finditer(text))
    ]


def test_the_check_tells_key_hints_from_style_tags() -> None:
    bad = ["[o] Open", "Press [esc] to close", "Use [f5] Refresh", "[Enter] Apply", "Keys: [o]pen", "a [Ctrl+S] b"]
    good = ["[b]o[/b] Open", "[dim]Press [b]n[/b] to add[/dim]", "[bold]x[/bold]", "plain text", "[u]x[/u]", "[b]bold[/]"]
    assert len(_offenders(enumerate(bad))) == len(bad)
    assert _offenders(enumerate(good)) == []


# Text that is never markup: a check mark drawn through ``Text`` (shell command
# strings, which hold ``$(...)``, are skipped by content).
_NOT_MARKUP = {("screens/vault_auto_bind.py", "[x]")}


def test_no_text_writes_a_key_hint_as_a_bracketed_key() -> None:
    root = Path(servonaut.__file__).parent
    found: list[str] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        name = path.relative_to(root).as_posix()
        found += _offenders(
            (f"{name}:{line}", text) for line, text in _strings(tree)
            if (name, text) not in _NOT_MARKUP and "$(" not in text
        )
    assert not found, "write the key as [b]o[/b], a bracketed key is parsed as markup:\n" + "\n".join(found)
