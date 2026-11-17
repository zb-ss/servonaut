"""Help text and hints name settings areas in sentence case, as the screens label them."""

from __future__ import annotations

from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "servonaut"

# Title Case spellings of names the screens write in sentence case.
_FORBIDDEN = (
    "Object Storage keys",
    "Object storage keys",
    "Security Groups, or NACLs",
    "Security Groups or NACLs",
    "IP Ban settings",
    "Settings → IP Ban",
    "Settings ▸ IP Ban",
    "Key Management screen",
)


def test_help_and_hint_text_uses_sentence_case_names() -> None:
    found = []
    for path in sorted(SRC.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for phrase in _FORBIDDEN:
            if phrase in text:
                found.append(f"{path.relative_to(SRC)}: {phrase}")
    assert not found, "\n".join(found)
