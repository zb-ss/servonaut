"""What the Share form says after a key confirmation: honest reasons, literal names."""

from __future__ import annotations

import asyncio
import time

import pytest
from textual.widgets import Button, Static

from servonaut.services.memory.team_wraps import KeyChange
from tests.test_memory_key_change_screen import _change, _Host as _KeyScreenHost, _text as _key_text
from tests.test_memory_share_key_confirm import (
    COVERAGE,
    _confirm_keys,
    _KeyBackend,
    _KeyHost,
    _live_with_waiting_member,
    _wait_for_key_screen,
)
from tests.test_memory_share_screen import _live_panel, _member, _open, _settle, _text
from servonaut.utils.file_lock import FileLock

pytestmark = pytest.mark.asyncio


async def _review_and_confirm(app, pilot, screen):
    await _settle(pilot, screen, lambda: screen.query_one("#share-btn-keys", Button).display)
    screen.query_one("#share-btn-keys", Button).press()
    keys = await _wait_for_key_screen(app, pilot, screen)
    await _confirm_keys(pilot, screen, keys)


def _skip_with(backend, reason):
    original = backend._post

    async def post(path, **kw):
        if path != COVERAGE:
            return await original(path, **kw)
        backend.wrap_posts.append(kw["json"])
        backend.missing = []
        backend.members = [m for m in backend.members if m["user_id"] != 2]
        return {"wraps_stored": 0, "wraps_unchanged": 0,
                "skipped_recipients": [{"user_id": 2, "reason": reason}]}

    backend.api.post.side_effect = post


@pytest.mark.parametrize("reason,said,not_said", [
    ("key_changed", ["key changed meanwhile", "Review the share"], []),
    ("no_memory_key", ["no memory key at the moment", "set up Memory Sync again"],
     ["Review the share", "key changed"]),
    ("not_eligible", ["can no longer read this share"], ["Review the share", "key changed"]),
    ("something_new", ["did not confirm", "try again"], ["Review the share", "key changed"]),
])
async def test_each_skip_reason_has_its_own_wording(reason, said, not_said):
    backend, _ = _live_with_waiting_member()
    _skip_with(backend, reason)
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await _review_and_confirm(app, pilot, screen)
        await _settle(pilot, screen, lambda: "Could not add" in _text(screen, "#share-status"))
        text = _text(screen, "#share-status")
    assert "Lee Member" in text
    assert all(part in text for part in said), text
    assert not any(part in text for part in not_said), text


async def test_confirming_keys_keeps_the_loop_running_while_the_pin_lock_is_held():
    backend, _ = _live_with_waiting_member()
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        app.pins._lock_wait = lambda: (0.3, 0.01)
        holder = FileLock(app.pins._path.with_name(app.pins._path.name + ".lock"))
        assert holder.try_acquire()
        ticks = []
        timer = app.set_interval(0.01, lambda: ticks.append(time.monotonic()))
        try:
            action = screen._review_action()
            await screen._after_confirmation(
                action, [KeyChange("team-a", 2, "Lee", "a" * 64)], "catch_up", False)
            assert "Could not save" in _text(screen, "#share-status")
        finally:
            timer.stop()
            holder.release()
    assert len(ticks) >= 10, len(ticks)


# --- names from the service are shown exactly as sent ---------------------

NAMES = ["[link=x", "[/bold]", "[@click=app.quit]", "Lee\\"]


@pytest.mark.parametrize("name", NAMES)
async def test_an_unusable_keys_member_name_is_shown_literally(name):
    bad = _member(2, name)
    bad["fingerprint"] = "a" * 64  # does not belong to the key
    app = _KeyHost(_KeyBackend(members=[bad]))
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#share-btn-confirm", Button).press()
        await _settle(pilot, screen, lambda: "does not match" in _text(screen, "#share-status"))
        text = _text(screen, "#share-status")
    assert f"key for {name} that does not match" in text


@pytest.mark.parametrize("name", NAMES)
async def test_a_confirmation_shows_the_member_name_literally(name):
    app = _KeyScreenHost([_change(name=name)])
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        shown = _key_text(app.screen, "#keychange-list")
        label = str(app.screen.query_one("#keychange-check-0").label)
    assert shown.startswith(f"{name}\nNew key:"), shown
    assert label == f"{name}'s key matches"
