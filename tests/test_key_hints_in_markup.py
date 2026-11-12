"""A key hint written as ``[o]`` inside markup is read as a style tag and vanishes."""

from __future__ import annotations

import re
from pathlib import Path

import servonaut

_HINT = re.compile(r"\"[^\"\n]*(?<![\w\]\)])\[[a-zA-Z?]\] [A-Za-z][^\"\n]*\"")


def test_no_text_writes_a_key_hint_as_a_bracketed_letter() -> None:
    root = Path(servonaut.__file__).parent
    found = [
        f"{path.relative_to(root)}:{number}"
        for path in sorted(root.rglob("*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if not line.lstrip().startswith("#") and _HINT.search(line)
    ]
    assert not found, "write the key as [b]o[/b], a bracketed letter is parsed as markup:\n" + "\n".join(found)
