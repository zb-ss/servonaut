"""The Share form offers a live share to members who cannot read it yet.

A member who sets up Memory Sync after a server was shared holds no wrap for
its snapshots, so the service lists nothing to them. The form names such a
member (a key that needs no confirmation) and "Share with them too" seals
the newest snapshots for them, without revoking or changing the share.

Same fakes as the key confirmation tests: the team memory service is real,
only the HTTP boundary is faked.
"""

from __future__ import annotations

import pytest
from textual.widgets import Button

from tests.test_memory_share_key_confirm import (
    _descriptor,
    _KeyBackend,
    _KeyHost,
)
from tests.test_memory_share_screen import _grant, _live_panel, _member, _settle, _text

pytestmark = pytest.mark.asyncio


def _live_with_new_member():
    lee = _member(2, "Lee Member")
    backend = _KeyBackend(members=[_member(1, "Kim Member"), lee],
                          live=[_grant("g-1", required_role="member", modules=["os"])])
    backend.missing = [_descriptor(lee)]
    return backend, lee


def _existing(screen) -> str:
    return _text(screen, "#share-existing-text")


async def test_a_member_who_enrolled_after_the_share_is_named_with_the_add_button():
    backend, _ = _live_with_new_member()
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await _settle(pilot, screen, lambda: "Cannot read it yet" in _existing(screen), "the line")
        assert "Cannot read it yet: Lee Member." in _existing(screen)
        assert screen.query_one("#share-btn-add", Button).display
        assert not screen.query_one("#share-btn-keys", Button).display


async def test_share_with_them_too_seals_without_revoking_and_clears_the_line():
    backend, lee = _live_with_new_member()
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        add = screen.query_one("#share-btn-add", Button)
        await _settle(pilot, screen, lambda: add.display, "the add button")
        add.press()
        await _settle(pilot, screen, lambda: backend.wrap_posts, "catch-up wraps")
        await _settle(pilot, screen,
                      lambda: "The latest snapshots are shared with Lee Member now." in app.notes,
                      "the toast")
        await _settle(pilot, screen, lambda: "Cannot read it yet" not in _existing(screen), "line gone")
        assert not add.display
    [post] = backend.wrap_posts
    assert [(w["recipient_user_id"], w["recipient_fingerprint"]) for w in post["wraps"]] == [
        (2, lee["fingerprint"])]
    # The share itself is untouched: no revoke, no new grant.
    assert not [c for c in backend.calls if "DELETE" in c]
    assert backend.posted == []
    # The key needed no confirmation, so it is remembered as the one sealed for.
    assert app.pins.get("team-a", 2) == lee["fingerprint"]


async def test_nothing_left_to_add_says_so_without_mentioning_keys():
    backend, _ = _live_with_new_member()
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        add = screen.query_one("#share-btn-add", Button)
        await _settle(pilot, screen, lambda: add.display, "the add button")
        backend.missing = []  # someone else added them meanwhile
        add.press()
        await _settle(pilot, screen,
                      lambda: "There was nothing to share right now." in app.notes, "the toast")
    assert backend.wrap_posts == []
    assert not any(n.startswith("Keys confirmed") for n in app.notes)


async def test_everyone_can_read_it_so_there_is_no_add_button():
    backend = _KeyBackend(members=[_member(1, "Kim Member")], live=[_grant("g-1")])
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await _settle(pilot, screen, lambda: any("wraps" in c for c in backend.calls), "coverage read")
        await pilot.pause(0.2)
        assert not screen.query_one("#share-btn-add", Button).display
        assert "Cannot read it yet" not in _existing(screen)


async def test_a_changed_key_is_offered_the_review_not_the_add_button():
    lee = _member(2, "Lee Member", key_changed=True)
    backend = _KeyBackend(members=[_member(1, "Kim Member"), lee],
                          live=[_grant("g-1", required_role="member", modules=["os"])])
    backend.missing = [_descriptor(lee)]
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await _settle(pilot, screen, lambda: screen.query_one("#share-btn-keys", Button).display,
                      "the review button")
        assert not screen.query_one("#share-btn-add", Button).display
        assert "Cannot read it yet" not in _existing(screen)


async def test_demo_mode_names_stand_ins_in_the_line_and_the_toast():
    backend, _ = _live_with_new_member()
    app = _KeyHost(backend, demo=True)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await _settle(pilot, screen, lambda: "Cannot read it yet" in _existing(screen), "the line")
        assert "Lee Member" not in _existing(screen)
        screen.query_one("#share-btn-add", Button).press()
        await _settle(pilot, screen, lambda: any(n.endswith("now.") for n in app.notes), "the toast")
        assert not any("Lee Member" in n for n in app.notes)
