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
from tests.test_memory_share_screen import SLUG, _live_panel, _member, _open, _settle, _text
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


# --- names beside markup render literally, even with a trailing backslash ---

@pytest.mark.parametrize("name", ["web-1\\", "[link=x", "[/bold]", "a\\[b"])
async def test_the_title_shows_the_server_name_literally(name):
    from tests.test_memory_share_screen import INSTANCE, _Backend, _Host

    app = _Host(_Backend(members=[_member(1, "Lee")]), shown_instance={**INSTANCE, "name": name})
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        title = _text(screen, "#share-title")
    assert title == f"Share Memory: {name}"


@pytest.mark.parametrize("name", NAMES)
async def test_the_readers_line_shows_member_names_literally(name):
    from tests.test_memory_share_screen import _Backend, _Host

    app = _Host(_Backend(members=[_member(1, name)]))
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        text = _text(screen, "#share-readers")
    assert f"Will be able to read it (1): {name}\n" in text


@pytest.mark.parametrize("name", NAMES)
async def test_the_waiting_line_shows_member_names_literally(name):
    from tests.test_memory_share_key_confirm import _descriptor
    from tests.test_memory_share_screen import _grant

    changed = _member(2, name, key_changed=True)
    backend = _KeyBackend(members=[_member(1, "Kim Member"), changed],
                          live=[_grant("g-1", required_role="member", modules=["os"])])
    backend.missing = [_descriptor(changed, previous_fingerprint="c" * 64)]
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await _settle(pilot, screen, lambda: screen.query_one("#share-btn-keys", Button).display)
        text = _text(screen, "#share-existing-text")
    assert text.endswith(f"waiting for your confirmation: {name}"), text


# --- confirmations are written one at a time --------------------------------

async def test_a_newer_confirmation_waits_for_the_one_still_being_saved():
    import functools
    import threading
    from unittest.mock import AsyncMock

    backend, _ = _live_with_waiting_member()
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        screen._top_up = AsyncMock()
        service = app.team_memory_service
        real = service.confirm_member_keys
        release, entered = threading.Event(), []
        active = {"now": 0, "most": 0}
        guard = threading.Lock()

        def tracked(team_slug, changes):
            with guard:
                entered.append(changes[0].fingerprint)
                active["now"] += 1
                active["most"] = max(active["most"], active["now"])
            try:
                if len(entered) == 1:
                    assert release.wait(10)
                real(team_slug, changes)
            finally:
                with guard:
                    active["now"] -= 1

        service.confirm_member_keys = tracked
        action = screen._review_action()

        def start(fingerprint):
            screen.run_worker(
                functools.partial(
                    screen._after_confirmation, action,
                    [KeyChange("team-a", 2, "Lee", fingerprint)], "catch_up", False),
                group="memory_share", name="share_confirm_keys", exclusive=True,
            )

        start("a" * 64)
        await _settle(pilot, screen, lambda: entered, "the first write")
        start("b" * 64)
        await pilot.pause(0.3)
        assert entered == ["a" * 64]  # the newer one has not started writing
        release.set()
        await _settle(pilot, screen, lambda: len(entered) == 2 and active["now"] == 0, "both writes")
    assert active["most"] == 1
    assert entered == ["a" * 64, "b" * 64]
    assert app.pins.get(SLUG, 2) == "b" * 64
