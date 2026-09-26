"""Small user-level steps shared by the OVH screen journeys."""

from __future__ import annotations

import json
import re
from typing import Any, Optional, Union

from textual.widgets import Button

_MARKUP = re.compile(r"\[/?[a-z ]+\]")


def plain(cell: str) -> str:
    """A table cell without its colour markup."""
    return _MARKUP.sub("", cell)


async def press(t: Any, target: Union[str, Button]) -> None:
    """Click a button like a user who waits for it to settle.

    A button ignores clicks while its short "pressed" highlight is showing,
    exactly as it would for a real double click, so a second press waits
    for the highlight to clear first.
    """
    button = t.on_screen(target, Button) if isinstance(target, str) else target
    await t.wait_until(lambda: not button.has_class("-active"), desc=f"{button.id} ready")
    await t.click(button)


async def select_row(t: Any, table_selector: str, column: int, value: str) -> None:
    """Move a table's cursor to the row whose *column* reads *value*, by keyboard."""
    table = t.on_screen(table_selector)
    if not table.has_focus:
        await t.click(table)
        await t.wait_until(lambda: table.has_focus, desc=f"focus on {table_selector}")
    values = [plain(row[column]) for row in t.table_rows(table_selector)]
    assert value in values, f"{value!r} not in {values}"
    target = values.index(value)
    for _ in range(len(values) + 1):
        if table.cursor_row == target:
            break
        await t.press("down" if table.cursor_row < target else "up")
    await t.wait_until(lambda: table.cursor_row == target, desc=f"cursor on {value}")
    await t.settle()


async def confirm_typed(t: Any, text: str, *, wrong: Optional[str] = None) -> None:
    """Answer the typed confirmation on screen with *text* (after *wrong*)."""
    await t.wait_for_screen("ConfirmActionScreen")
    confirm = t.on_screen("#btn_confirm")
    if wrong is not None:
        await t.fill("#confirm_input", wrong)
        await t.settle()
        assert confirm.disabled, f"{wrong!r} must not confirm"
    await t.fill("#confirm_input", text)
    await t.wait_until(lambda: not confirm.disabled, desc="confirm enabled")
    await press(t, confirm)


async def cancel_confirmation(t: Any, back_to: str) -> None:
    """Back out of the typed confirmation with escape."""
    await t.wait_for_screen("ConfirmActionScreen")
    await t.press("escape")
    await t.wait_for_screen(back_to)


def ovh_audit(seed: Any) -> list[dict]:
    """Rows of the OVH audit log in the sandbox home."""
    path = seed.data_dir / "ovh_audit.json"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def mutations(providers: Any) -> list[tuple[str, str]]:
    """(method, path) of every changing request OVH received, in order."""
    return [(r["method"], r["api_path"]) for r in providers.mutations("ovh")]
