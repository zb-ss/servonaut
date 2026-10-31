"""The screen where a team member's changed memory key is confirmed."""

from __future__ import annotations

from typing import Any, List, Optional
from unittest.mock import MagicMock

import pytest
from textual.app import App
from textual.widgets import Button, Checkbox, Static

from servonaut.screens.memory_key_change import MemberKeyChangeScreen
from servonaut.services.memory.crypto import short_fingerprint
from servonaut.services.memory.team_wraps import KeyChange

pytestmark = pytest.mark.asyncio

NEW_FP = "ab" * 32
OLD_FP = "cd" * 32


def _change(uid: int = 2, name: str = "Lee", **kw: Any) -> KeyChange:
    return KeyChange("team-a", uid, name, kw.pop("fingerprint", NEW_FP),
                     kw.pop("previous_fingerprint", OLD_FP),
                     kw.pop("rotated_at", "2026-10-30T10:15:00Z"))


class _Host(App):
    def __init__(self, changes: List[KeyChange], mode: str = "share", *, again: bool = False,
                 demo: bool = False) -> None:
        super().__init__()
        self._screen = MemberKeyChangeScreen(changes, mode=mode, again=again)
        self.result: Any = "unset"
        self.demo_mode = demo
        if demo:
            self.redaction_service = MagicMock()
            self.redaction_service.redact_name = lambda n: "stand-in"
            self.redaction_service.scrub_stream = lambda t: t

    def on_mount(self) -> None:
        self.push_screen(self._screen, lambda value: setattr(self, "result", value))


def _text(screen, selector: str) -> str:
    if selector == "#keychange-list":
        return "\n".join(str(w.render()) for w in screen.query(".keychange-details"))
    return str(screen.query_one(selector, Static).render())


def test_the_short_fingerprint_is_what_memory_sync_shows():
    assert short_fingerprint(NEW_FP) == NEW_FP[:24] + "…"


async def test_it_shows_the_member_and_both_keys_and_when_it_changed():
    app = _Host([_change()])
    async with app.run_test(size=(120, 50)) as pilot:
        await pilot.pause()
        text = _text(app.screen, "#keychange-list")
        assert "Lee" in text
        assert f"New key: {short_fingerprint(NEW_FP)}" in text
        assert f"Previous key: {short_fingerprint(OLD_FP)}" in text
        assert "Changed on: 2026-10-30 10:15 UTC" in text
        body = _text(app.screen, "#keychange-body")
        assert "Memory Sync" in body and "Key fingerprint" in body


async def test_an_unknown_previous_key_or_time_is_left_out():
    app = _Host([_change(previous_fingerprint=None, rotated_at=None)])
    async with app.run_test(size=(120, 50)) as pilot:
        await pilot.pause()
        text = _text(app.screen, "#keychange-list")
        assert "Previous key" not in text and "Changed on" not in text


async def test_share_mode_needs_every_member_ticked():
    app = _Host([_change(2, "Lee"), _change(3, "Kim")], "share")
    async with app.run_test(size=(120, 50)) as pilot:
        confirm = app.screen.query_one("#keychange-btn-confirm", Button)
        boxes = list(app.screen.query(Checkbox))
        assert str(confirm.label) == "Trust and share" and confirm.disabled
        boxes[0].value = True
        await pilot.pause()
        assert confirm.disabled
        boxes[1].value = True
        await pilot.pause()
        assert not confirm.disabled
        confirm.press()
        await pilot.pause()
        assert [c.user_id for c in app.result] == [2, 3]


async def test_share_again_has_its_own_button_label():
    app = _Host([_change()], "share", again=True)
    async with app.run_test(size=(120, 50)) as pilot:
        await pilot.pause()
        assert str(app.screen.query_one("#keychange-btn-confirm", Button).label) == "Trust and share again"


async def test_catch_up_mode_needs_one_and_returns_only_the_ticked():
    app = _Host([_change(2, "Lee"), _change(3, "Kim")], "catch_up")
    async with app.run_test(size=(120, 50)) as pilot:
        confirm = app.screen.query_one("#keychange-btn-confirm", Button)
        assert str(confirm.label) == "Trust checked keys" and confirm.disabled
        list(app.screen.query(Checkbox))[1].value = True
        await pilot.pause()
        assert not confirm.disabled
        confirm.press()
        await pilot.pause()
        assert [c.user_id for c in app.result] == [3]


async def test_cancel_has_focus_and_escape_and_the_button_dismiss_with_nothing():
    app = _Host([_change()])
    async with app.run_test(size=(120, 50)) as pilot:
        await pilot.pause()
        assert app.focused is not None and app.focused.id == "keychange-btn-cancel"
        await pilot.press("escape")
        await pilot.pause()
        assert app.result is None
    app = _Host([_change()])
    async with app.run_test(size=(120, 50)) as pilot:
        await pilot.pause()
        app.screen.query_one("#keychange-btn-cancel", Button).press()
        await pilot.pause()
        assert app.result is None


async def test_names_are_literal_and_stand_ins_in_demo_mode():
    app = _Host([_change(name="[bold]Odd[/bold]")])
    async with app.run_test(size=(120, 50)) as pilot:
        await pilot.pause()
        assert "[bold]Odd[/bold]" in _text(app.screen, "#keychange-list")
    app = _Host([_change(name="Real Person")], demo=True)
    async with app.run_test(size=(120, 50)) as pilot:
        await pilot.pause()
        shown = _text(app.screen, "#keychange-list") + str(app.screen.query_one(Checkbox).label)
        assert "Real Person" not in shown and "stand-in" in shown


async def test_a_member_without_a_name_is_told_by_number():
    app = _Host([_change(7, "")])
    async with app.run_test(size=(120, 50)) as pilot:
        await pilot.pause()
        assert "member 7" in _text(app.screen, "#keychange-list")


async def test_the_buttons_stay_on_screen_when_the_list_is_long_on_a_small_terminal():
    """Screen tests load no CSS by default: mount the real stylesheet and measure."""
    from servonaut.styles import CSS_FILES

    class Styled(_Host):
        CSS_PATH = [str(p) for p in CSS_FILES]

    changes = [_change(uid, f"Member {uid}") for uid in range(2, 8)]
    app = Styled(changes, "share")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        screen = app.screen
        for button in ("#keychange-btn-cancel", "#keychange-btn-confirm"):
            region = screen.query_one(button, Button).region
            assert region.height > 0 and region.bottom <= 30, (button, region)
        scroll = screen.query_one("#keychange-scroll")
        assert scroll.max_scroll_y > 0  # the body scrolls instead of pushing the buttons away
