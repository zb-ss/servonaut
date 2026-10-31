"""The Share form asks the user to confirm a changed member key.

Same fakes as the Share form tests: the team memory service is real, only the
HTTP boundary is faked. The fake service also answers a share's coverage route
and its catch-up wraps.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, List

import pytest
from textual.widgets import Button, Checkbox

import servonaut.services.memory.crypto as crypto_module
from servonaut.screens.memory_key_change import MemberKeyChangeScreen
from servonaut.services.api_client import APIError
from servonaut.services.memory.team_service import TeamMemoryService
from servonaut.services.memory.team_wraps import WrapPinStore
from tests.test_memory_share_screen import (
    INSTANCE,
    SLUG,
    _Backend,
    _grant,
    _Host,
    _live_panel,
    _member,
    _open,
    _settle,
    _text,
)

pytestmark = pytest.mark.asyncio

COVERAGE = f"/api/v1/teams/{SLUG}/memory/grant/g-1/wraps"


def _descriptor(member: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
    return {"user_id": member["user_id"], "name": member["name"],
            "fingerprint": member["fingerprint"], "public_key_b64": member["public_key_b64"],
            "key_changed": member["key_changed"], "previous_fingerprint": None,
            "key_rotated_at": None, **extra}


class _KeyBackend(_Backend):
    """Adds the coverage route (GET) and the catch-up wraps route (POST)."""

    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.missing: List[Dict[str, Any]] = []
        self.coverage_error: Exception | None = None
        self.wrap_posts: List[Dict[str, Any]] = []

    async def _get(self, path: str, **kw: Any) -> Dict[str, Any]:
        if path == COVERAGE:
            self.calls.append(f"GET {path}")
            if self.coverage_error is not None:
                raise self.coverage_error
            return {"grant_id": "g-1", "instance_id": INSTANCE["id"], "pending_recipients": [],
                    "envelopes": [{"envelope_id": "e-os", "module": "os", "snapshot_version": 2,
                                   "wrapped_dek": self.own_wrap(), "missing_recipients": self.missing}]}
        return await super()._get(path, **kw)

    async def _post(self, path: str, **kw: Any) -> Dict[str, Any]:
        if path == COVERAGE:
            self.calls.append(f"POST {path}")
            body = kw["json"]
            self.wrap_posts.append(body)
            stored = {w["recipient_user_id"] for w in body["wraps"]}
            self.missing = [m for m in self.missing if m["user_id"] not in stored]
            return {"wraps_stored": len(body["wraps"])}
        return await super()._post(path, **kw)


class _KeyHost(_Host):
    """A host whose service keeps the confirmed fingerprints, like the app's."""

    def __init__(self, backend: _KeyBackend, **kw: Any) -> None:
        super().__init__(backend, **kw)
        old = self.team_memory_service
        self.pins = WrapPinStore(self_tmp() / "pins.json")
        self.team_memory_service = TeamMemoryService(
            api_client=backend.api, auth_service=old._auth, crypto=crypto_module,
            key_store_provider=old._key_store_provider,
            retrieval_service=old._retrieval_service,
            pin_store_provider=lambda: self.pins,
        )
        backend.own_wrap = self._own_wrap

    def _own_wrap(self) -> str:
        material = self.team_memory_service._key_store_provider()
        env = crypto_module.encrypt_envelope(
            b"{}", self_public_key=material.public_key, self_user_id=material.user_id).to_dict()
        return env["dek_wraps"][0]["wrapped_dek"]


_TMP: List[Any] = []


def self_tmp():
    import pathlib
    import tempfile

    d = pathlib.Path(tempfile.mkdtemp(prefix="share-pins-"))
    _TMP.append(d)
    return d


def _key_text(key_screen) -> str:
    return "\n".join(str(w.render()) for w in key_screen.query(".keychange-details"))


def _status(screen) -> str:
    return _text(screen, "#share-status")


async def _wait_for_key_screen(app, pilot, screen):
    await _settle(pilot, screen, lambda: isinstance(app.screen, MemberKeyChangeScreen), "key screen")
    return app.screen


async def _confirm_keys(pilot, screen, key_screen) -> None:
    """Tick every key, wait until the button is enabled (a message hop), press it."""
    for box in key_screen.query(Checkbox):
        box.value = True
    button = key_screen.query_one("#keychange-btn-confirm", Button)
    await _settle(pilot, screen, lambda: not button.disabled, "the confirm button")
    button.press()


async def test_a_changed_key_opens_the_confirmation_and_sends_nothing_yet():
    backend = _KeyBackend(members=[_member(1, "Kim Member"), _member(2, "Lee Member", key_changed=True)])
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#share-btn-confirm", Button).press()
        key_screen = await _wait_for_key_screen(app, pilot, screen)
        assert "Lee Member" in _key_text(key_screen)
        assert "Kim Member" not in _key_text(key_screen)
        assert str(key_screen.query_one("#keychange-btn-confirm", Button).label) == "Trust and share"
    assert backend.posted == []


async def test_confirming_shares_with_the_same_choices_and_seals_for_the_new_key():
    backend = _KeyBackend(members=[_member(1, "Kim Member"), _member(2, "Lee Member", key_changed=True)])
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#share-btn-confirm", Button).press()
        key_screen = await _wait_for_key_screen(app, pilot, screen)
        await _confirm_keys(pilot, screen, key_screen)
        await _settle(pilot, screen, lambda: backend.posted, "grant")
    wraps = backend.posted[-1]["wraps"]
    assert sorted({w["recipient_user_id"] for w in wraps}) == [1, 2]
    assert app.pins.get(SLUG, 2) == backend.members[1]["fingerprint"]


async def test_cancelling_sends_nothing_and_says_who_cannot_read_it():
    backend = _KeyBackend(members=[_member(2, "Lee Member", key_changed=True)])
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#share-btn-confirm", Button).press()
        key_screen = await _wait_for_key_screen(app, pilot, screen)
        await pilot.press("escape")
        await _settle(pilot, screen, lambda: app.screen is screen, "back on the form")
        await _settle(pilot, screen, lambda: "Nothing was changed" in _status(screen), "message")
        assert "Lee Member cannot read it until you confirm the new key" in _status(screen)
    assert [c for c in backend.calls if not c.startswith("GET")] == []
    assert app.pins.get(SLUG, 2) is None


async def test_share_again_confirms_then_revokes_and_shares():
    backend = _KeyBackend(members=[_member(1, "Kim Member"), _member(2, "Lee Member", key_changed=True)],
                          live=[_grant("g-1", required_role="member", modules=["os"])])
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        screen.query_one("#share-btn-reshare", Button).press()
        key_screen = await _wait_for_key_screen(app, pilot, screen)
        assert str(key_screen.query_one("#keychange-btn-confirm", Button).label) == "Trust and share again"
        assert not [c for c in backend.calls if not c.startswith("GET")]  # nothing revoked yet
        await _confirm_keys(pilot, screen, key_screen)
        await _settle(pilot, screen, lambda: backend.posted, "grant")
    writes = [c for c in backend.calls if not c.startswith("GET")]
    assert writes == [f"DELETE /api/v1/teams/{SLUG}/memory/grant/g-1", f"POST /api/v1/teams/{SLUG}/memory/grant"]


async def test_keys_that_changed_again_bring_the_screen_back_with_the_new_fingerprint():
    backend = _KeyBackend(members=[_member(2, "Lee Member", key_changed=True)])
    app = _KeyHost(backend)
    first_fp = backend.members[0]["fingerprint"]
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#share-btn-confirm", Button).press()
        key_screen = await _wait_for_key_screen(app, pilot, screen)
        # The member replaces the key while the screen is open.
        backend.members[0] = _member(2, "Lee Member", key_changed=True)
        second_fp = backend.members[0]["fingerprint"]
        await _confirm_keys(pilot, screen, key_screen)
        await _settle(pilot, screen, lambda: app.screen is not key_screen
                      and isinstance(app.screen, MemberKeyChangeScreen), "second screen")
        again = app.screen
        text = _key_text(again)
        assert crypto_module.short_fingerprint(second_fp) in text
        assert crypto_module.short_fingerprint(first_fp) in text  # shown as the previous key
    assert backend.posted == []


async def test_a_key_that_does_not_match_its_fingerprint_cannot_be_confirmed():
    member = _member(2, "Lee Member")
    member["fingerprint"] = "d" * 64
    backend = _KeyBackend(members=[member])
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#share-btn-confirm", Button).press()
        await _settle(pilot, screen, lambda: "does not match" in _status(screen), "message")
        assert not isinstance(app.screen, MemberKeyChangeScreen)
        assert "Lee Member" in _status(screen) and "Nothing was changed" in _status(screen)
    assert backend.posted == []


async def test_demo_mode_names_stand_ins_in_the_cancel_message():
    backend = _KeyBackend(members=[_member(2, "Real Person", key_changed=True)])
    app = _KeyHost(backend, demo=True)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#share-btn-confirm", Button).press()
        await _wait_for_key_screen(app, pilot, screen)
        await pilot.press("escape")
        await _settle(pilot, screen, lambda: "Nothing was changed" in _status(screen), "message")
        assert "Real Person" not in _status(screen) and "stand-in" in _status(screen)


# --- an existing share: review changed keys -------------------------------

def _live_with_waiting_member():
    lee = _member(2, "Lee Member", key_changed=True)
    backend = _KeyBackend(members=[_member(1, "Kim Member"), lee],
                          live=[_grant("g-1", required_role="member", modules=["os"])])
    backend.missing = [_descriptor(lee, previous_fingerprint="c" * 64)]
    return backend, lee


async def test_a_share_with_a_waiting_member_says_so_and_offers_the_review():
    backend, _ = _live_with_waiting_member()
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await _settle(pilot, screen, lambda: "waiting for your confirmation" in _text(screen, "#share-existing-text"),
                      "waiting line")
        assert "Key changed, waiting for your confirmation: Lee Member" in _text(screen, "#share-existing-text")
        assert screen.query_one("#share-btn-keys", Button).display


async def test_without_a_waiting_member_there_is_no_review_button():
    backend = _KeyBackend(members=[_member(1, "Kim Member")], live=[_grant("g-1")])
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await pilot.pause(0.2)
        assert not screen.query_one("#share-btn-keys", Button).display
        assert "waiting" not in _text(screen, "#share-existing-text")


async def test_reviewing_confirms_tops_up_and_clears_the_line():
    backend, lee = _live_with_waiting_member()
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await _settle(pilot, screen, lambda: screen.query_one("#share-btn-keys", Button).display, "review button")
        screen.query_one("#share-btn-keys", Button).press()
        key_screen = await _wait_for_key_screen(app, pilot, screen)
        assert str(key_screen.query_one("#keychange-btn-confirm", Button).label) == "Trust checked keys"
        assert "Previous key" in _key_text(key_screen)
        await _confirm_keys(pilot, screen, key_screen)
        await _settle(pilot, screen, lambda: backend.wrap_posts, "catch-up wraps")
        await _settle(pilot, screen, lambda: any("shared with Lee Member now" in n for n in app.notes), "toast")
        await _settle(pilot, screen, lambda: "waiting" not in _text(screen, "#share-existing-text"), "line gone")
        assert not screen.query_one("#share-btn-keys", Button).display
    [post] = backend.wrap_posts
    assert [(w["recipient_user_id"], w["recipient_fingerprint"]) for w in post["wraps"]] == [
        (2, lee["fingerprint"])]
    assert not [c for c in backend.calls if "DELETE" in c]  # a review never revokes


async def test_cancelling_the_review_changes_nothing():
    backend, _ = _live_with_waiting_member()
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await _settle(pilot, screen, lambda: screen.query_one("#share-btn-keys", Button).display, "review button")
        screen.query_one("#share-btn-keys", Button).press()
        await _wait_for_key_screen(app, pilot, screen)
        await pilot.press("escape")
        await _settle(pilot, screen, lambda: app.screen is screen, "back")
        await pilot.pause(0.2)
    assert backend.wrap_posts == [] and app.pins.get(SLUG, 2) is None
    assert not [c for c in backend.calls if c.startswith(("POST", "DELETE"))]


async def test_a_coverage_failure_leaves_the_panel_working_without_the_line():
    backend, _ = _live_with_waiting_member()
    backend.coverage_error = APIError(code="server_error", message="boom", status=500)
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await pilot.pause(0.3)
        assert "Already shared with this team" in _text(screen, "#share-existing-text")
        assert "waiting" not in _text(screen, "#share-existing-text")
        assert not screen.query_one("#share-btn-keys", Button).display
        assert screen.query_one("#share-btn-reshare", Button).display


async def test_a_coverage_404_takes_the_gone_path():
    backend, _ = _live_with_waiting_member()
    backend.coverage_error = APIError(code="not_found", message="gone", status=404)
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        await _settle(pilot, screen, lambda: "no longer exists" in _status(screen), "gone message")


async def test_a_share_gone_during_the_top_up_is_said_not_shown_raw():
    backend, _ = _live_with_waiting_member()
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await _settle(pilot, screen, lambda: screen.query_one("#share-btn-keys", Button).display, "review button")
        screen.query_one("#share-btn-keys", Button).press()
        key_screen = await _wait_for_key_screen(app, pilot, screen)
        backend.coverage_error = APIError(code="grant_not_live", message="revoked", status=409)
        await _confirm_keys(pilot, screen, key_screen)
        await _settle(pilot, screen, lambda: "no longer exists" in _status(screen), "gone message")


async def test_demo_mode_names_stand_ins_in_the_waiting_line_and_the_toast():
    backend, _ = _live_with_waiting_member()
    app = _KeyHost(backend, demo=True)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await _settle(pilot, screen, lambda: "waiting" in _text(screen, "#share-existing-text"), "line")
        assert "Lee Member" not in _text(screen, "#share-existing-text")
        screen.query_one("#share-btn-keys", Button).press()
        key_screen = await _wait_for_key_screen(app, pilot, screen)
        await _confirm_keys(pilot, screen, key_screen)
        await _settle(pilot, screen, lambda: any("now" in n for n in app.notes), "toast")
        assert not any("Lee Member" in n for n in app.notes)
