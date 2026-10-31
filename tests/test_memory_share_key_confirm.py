"""The Share form asks the user to confirm a changed member key.

Same fakes as the Share form tests: the team memory service is real, only the
HTTP boundary is faked. The fake service also answers a share's coverage route
and its catch-up wraps.
"""

from __future__ import annotations

import asyncio
import base64
import gc
import logging
import warnings
from typing import Any, Dict, List

import pytest
from textual.widgets import Button, Checkbox, Select, SelectionList

import servonaut.services.memory.crypto as crypto_module
from servonaut.screens.memory_key_change import MemberKeyChangeScreen
from servonaut.services.api_client import APIError, InsufficientWrapsError
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
        self.skip_users: set = set()  # answered as skipped (key_changed) and left missing
        self.wrap_error: Exception | None = None
        # Holds the member-key request of one team until released.
        self.hold_team: str | None = None
        self.held = asyncio.Event()
        self.release = asyncio.Event()

    async def _get(self, path: str, **kw: Any) -> Dict[str, Any]:
        if self.hold_team and path == f"/api/v1/memory/keys/team/{self.hold_team}":
            self.held.set()
            await self.release.wait()
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
            if self.wrap_error is not None:
                raise self.wrap_error
            sent = {w["recipient_user_id"] for w in body["wraps"]}
            skipped = sent & self.skip_users
            self.missing = [m for m in self.missing if m["user_id"] not in sent - skipped]
            for user_id in skipped:  # the member rotated again: the service holds a new key
                rotated = _member(user_id, f"Lee Member", key_changed=True)
                self.members = [rotated if m["user_id"] == user_id else m for m in self.members]
                self.missing = [_descriptor(rotated) if m["user_id"] == user_id else m
                                for m in self.missing]
            return {"wraps_stored": len(sent - skipped), "wraps_unchanged": 0,
                    "skipped_recipients": [{"user_id": u, "reason": "key_changed"} for u in skipped]}
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


async def _wait_for_key_screen(app, pilot, screen, previous=None):
    """Wait for a mounted confirmation screen (not *previous*) with its controls."""
    def ready() -> bool:
        current = app.screen
        return (isinstance(current, MemberKeyChangeScreen) and current is not previous
                and current.is_mounted and bool(current.query(Checkbox))
                and bool(current.query("#keychange-btn-confirm")))

    await _settle(pilot, screen, ready, "key screen")
    await pilot.pause()
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
        again = await _wait_for_key_screen(app, pilot, screen, previous=key_screen)
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


# --- the action keeps its context ----------------------------------------

TWO_TEAMS = [{"name": "Team A", "slug": "team-a"}, {"name": "Team B", "slug": "team-b"}]


async def test_switching_team_while_sharing_opens_no_confirmation_and_shares_nothing():
    backend = _KeyBackend(members=[_member(1, "Kim Member"), _member(2, "Lee Member", key_changed=True)])
    app = _KeyHost(backend, teams=TWO_TEAMS)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        backend.hold_team = "team-a"
        screen.query_one("#share-btn-confirm", Button).press()
        await _settle(pilot, screen, lambda: backend.held.is_set(), "the pending key request")
        backend.hold_team = None
        screen.query_one("#share-team-select", Select).value = "team-b"
        await _settle(pilot, screen, lambda: screen._selected_team() == "team-b", "team switch")
        backend.release.set()
        await _settle(pilot, screen, lambda: "team changed while sharing" in _status(screen), "message")
        assert "Nothing was shared" in _status(screen) or "nothing was shared" in _status(screen)
        assert app.screen is screen
    assert backend.posted == []
    assert app.pins.get(SLUG, 2) is None and app.pins.get("team-b", 2) is None


async def test_the_retry_after_confirming_uses_the_choices_made_when_sharing_started():
    backend = _KeyBackend(members=[_member(1, "Kim Member"), _member(2, "Lee Member", key_changed=True)])
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#share-role-select", Select).value = "member"
        chosen = list(screen.query_one("#share-modules-list", SelectionList).selected)
        screen.query_one("#share-btn-confirm", Button).press()
        key_screen = await _wait_for_key_screen(app, pilot, screen)
        # The form behind the dialog changes while it is open.
        screen.query_one("#share-role-select", Select).value = "admin"
        screen.query_one("#share-modules-list", SelectionList).deselect_all()
        await _confirm_keys(pilot, screen, key_screen)
        await _settle(pilot, screen, lambda: backend.posted, "grant")
    assert backend.posted[-1]["required_role"] == "member"
    assert backend.posted[-1]["modules"] == chosen


async def test_a_key_that_rotated_during_the_share_says_so_and_reloads_the_keys():
    backend = _KeyBackend(members=[_member(1, "Kim Member")])
    backend.fail_post = InsufficientWrapsError(
        code="insufficient_wraps", message="missing", status=422,
        details={"missing": [{"envelope_id": "e-os", "recipient_user_id": 1}]})
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        loads = len([c for c in backend.calls if c.startswith("GET /api/v1/memory/keys/")])
        screen.query_one("#share-btn-confirm", Button).press()
        await _settle(pilot, screen, lambda: "key changed while sharing" in _status(screen), "message")
        assert "Nothing was shared; try again." in _status(screen)
        await _settle(pilot, screen, lambda: len(
            [c for c in backend.calls if c.startswith("GET /api/v1/memory/keys/")]) > loads, "key reload")


# --- the top-up tells the truth ------------------------------------------

async def test_a_member_the_service_skipped_is_named_and_not_reported_as_shared():
    backend, _ = _live_with_waiting_member()
    backend.skip_users = {2}
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await _settle(pilot, screen, lambda: screen.query_one("#share-btn-keys", Button).display, "review button")
        screen.query_one("#share-btn-keys", Button).press()
        key_screen = await _wait_for_key_screen(app, pilot, screen)
        await _confirm_keys(pilot, screen, key_screen)
        await _settle(pilot, screen, lambda: "Could not add Lee Member" in _status(screen), "message")
        await _settle(pilot, screen, lambda: "waiting for your confirmation"
                      in _text(screen, "#share-existing-text"), "waiting again")
        assert not any("shared with Lee Member now" in n for n in app.notes)
    assert app.pins.get(SLUG, 2) is not None  # the user's confirmation stays
    assert app.pins.get(SLUG, 2) != backend.members[1]["fingerprint"]  # not the unseen new key


async def test_a_busy_service_during_the_top_up_is_retryable_not_a_gone_share():
    backend, _ = _live_with_waiting_member()
    backend.wrap_error = APIError(code="conflict_retry", message="busy", status=409)
    app = _KeyHost(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await _settle(pilot, screen, lambda: screen.query_one("#share-btn-keys", Button).display, "review button")
        screen.query_one("#share-btn-keys", Button).press()
        key_screen = await _wait_for_key_screen(app, pilot, screen)
        await _confirm_keys(pilot, screen, key_screen)
        await _settle(pilot, screen, lambda: "Try again" in _status(screen), "message")
        assert "no longer exists" not in _status(screen)


# --- workers and logs ----------------------------------------------------

async def test_cancelled_refresh_workers_leave_no_unawaited_coroutine():
    backend = _KeyBackend(members=[_member(1, "Kim Member")])
    app = _KeyHost(backend)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        async with app.run_test(size=(120, 50)) as pilot:
            screen = await _open(app, pilot)
            for _ in range(5):  # each exclusive start cancels the one before it
                screen._start_refresh(reload=True)
            await pilot.pause(0.3)
        gc.collect()
    assert [str(w.message) for w in caught if "never awaited" in str(w.message)] == []


async def test_a_failed_top_up_logs_the_error_type_not_the_service_text(caplog):
    backend, _ = _live_with_waiting_member()
    backend.wrap_error = APIError(code="x", message="Team Secret Name is unhappy", status=500)
    app = _KeyHost(backend)
    caplog.set_level(logging.DEBUG)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        await _settle(pilot, screen, lambda: screen.query_one("#share-btn-keys", Button).display, "review button")
        screen.query_one("#share-btn-keys", Button).press()
        key_screen = await _wait_for_key_screen(app, pilot, screen)
        await _confirm_keys(pilot, screen, key_screen)
        await _settle(pilot, screen, lambda: "Could not share the latest" in _status(screen), "message")
    assert "Team Secret Name" not in caplog.text and "APIError" in caplog.text


async def test_a_failed_share_state_load_logs_the_error_type_not_the_service_text(caplog):
    backend = _KeyBackend(members=[_member(1, "Kim Member")])
    original = backend._get

    async def failing(path, **kw):
        if path.startswith("/api/v1/memory/keys/team/"):
            raise APIError(code="x", message="Team Secret Name is unhappy", status=500)
        return await original(path, **kw)

    backend.api.get.side_effect = failing
    app = _KeyHost(backend)
    caplog.set_level(logging.DEBUG)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = app.screen
        await _settle(pilot, screen, lambda: "Could not check the share" in _status(screen), "message")
    assert "Team Secret Name" not in caplog.text
