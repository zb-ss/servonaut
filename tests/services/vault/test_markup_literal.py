"""Literal Vault metadata in Textual 8 markup."""
from __future__ import annotations

import pytest
from textual.markup import to_content

from servonaut.services.vault.display import terminal_safe


@pytest.mark.parametrize("raw", [
    "[1st key", "key [3", "\x1b[31mred-key", "a [1 [/b]", "[web-1] key",
    "x\\[y", "x\\\\[y", "trailing\\", "trailing\\\\", "[bold]key[/bold]",
])
def test_markup_literal_preserves_plain_text_and_backslashes(raw: str) -> None:
    from servonaut.services.vault.display import markup_literal

    value = terminal_safe(raw)
    escaped = markup_literal(value)
    assert to_content(escaped).plain == value
    assert to_content(escaped + "  [dim]detail[/dim]").plain == value + "  detail"
    # A separator keeps a trailing backslash from escaping a following tag.
    assert to_content("[dim]" + escaped + " [/dim]").plain == value + " "
