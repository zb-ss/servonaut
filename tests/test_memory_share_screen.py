"""The Share form: who gets access, and changing a share that exists.

The team memory service is real, so the routes and call order are the real
ones; only the HTTP boundary is faked.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import nacl.public
import pytest
from textual.app import App
from textual.widgets import Button, Select, SelectionList, Static

import servonaut.services.memory.crypto as crypto_module
from servonaut.screens.memory_share import PurgeCopiesModal, ShareInstanceScreen
from servonaut.services.api_client import APIClient, InsufficientWrapsError
from servonaut.services.memory.team_service import TeamMemoryService

pytestmark = pytest.mark.asyncio

SLUG = "team-a"
INSTANCE = {"id": "i-owner-1", "name": "web-1", "provider": "aws"}


_ROLES = {"viewer": 0, "member": 1, "admin": 2, "owner": 3}


def _member(user_id: int, name: str, role: str = "member", *, key_changed: bool = False) -> Dict[str, Any]:
    pub = bytes(nacl.public.PrivateKey.generate().public_key)
    return {
        "user_id": user_id, "fingerprint": f"{user_id:064x}",
        "public_key_b64": base64.b64encode(pub).decode(), "role": role, "name": name,
        "key_changed": key_changed,
    }


def _owner_keys() -> Any:
    private = nacl.public.PrivateKey.generate()
    km = MagicMock()
    km.user_id = 1
    km.private_key, km.public_key = bytes(private), bytes(private.public_key)
    return km


def _retrieval(owner: Any, inventory: List[str]) -> MagicMock:
    """The owner's own envelopes: a data key sealed to the owner's key."""
    async def raw(_instance_id: str, module: str) -> Dict[str, Any]:
        env = crypto_module.encrypt_envelope(
            b"{}", self_public_key=owner.public_key, self_user_id=owner.user_id).to_dict()
        return {"id": f"e-{module}", "wrapped_dek": env["dek_wraps"][0]["wrapped_dek"]}
    return MagicMock(
        list_instance_modules=AsyncMock(return_value={"modules": inventory}),
        get_module_envelope_raw=AsyncMock(side_effect=raw),
    )


def _grant(grant_id: str = "g-1", status: str = "active", **extra: Any) -> Dict[str, Any]:
    return {
        "id": grant_id, "instance_id": INSTANCE["id"], "required_role": "member",
        "modules": ["os", "logs"], "status": status, "granted_by_user_id": 1,
        "created_at": "2026-10-01T10:00:00Z", "revoked_at": None, **extra,
    }


class _Backend:
    """A fake service: the routes the form uses, with a call log."""

    def __init__(self, *, members: List[Dict[str, Any]], live: List[Dict[str, Any]] | None = None,
                 inventory: List[str] | None = None):
        self.members = members
        self.inventory = ["os"] if inventory is None else inventory
        self.posted: List[Dict[str, Any]] = []
        self.fail_post: Exception | None = None
        self.fail_delete: Exception | None = None
        self.live = live or []
        self.live_for: Dict[str, List[Dict[str, Any]]] = {}
        self.calls: List[str] = []
        self.created = _grant("g-new")
        self.api = MagicMock(spec=APIClient)
        self.api.get = AsyncMock(side_effect=self._get)
        self.api.post = AsyncMock(side_effect=self._post)
        self.api.delete = AsyncMock(side_effect=self._delete)

    async def _get(self, path: str, **_kw: Any) -> Dict[str, Any]:
        self.calls.append(f"GET {path}")
        if path.startswith("/api/v1/memory/keys/team/"):
            return {"members": self.members}
        slug = path.split("/")[4] if path.startswith("/api/v1/teams/") else ""
        return {"instances": [
            {"grant": g, "instance": {"instance_id": g["instance_id"]},
             "readable_modules": ["os"], "stale_modules": []}
            for g in self.live_for.get(slug, self.live)
        ]}

    async def _post(self, path: str, **_kw: Any) -> Dict[str, Any]:
        self.calls.append(f"POST {path}")
        if path.endswith("/purge"):
            return {"grant_id": "g-1", "wraps_deleted": 3, "status": "revoked"}
        if self.fail_post is not None:
            raise self.fail_post
        body = _kw.get("json") or {}
        self.posted.append(body)
        # The service refuses a grant that leaves an enrolled reader without a
        # wrap for a module the owner has stored (insufficient_wraps).
        have = {(w["recipient_user_id"], w["envelope_id"]) for w in body.get("wraps", [])}
        missing = [
            {"envelope_id": f"e-{mod}", "recipient_user_id": int(m["user_id"])}
            for m in self.members
            if _ROLES[m["role"]] >= _ROLES[body["required_role"]]
            for mod in body["modules"] if mod in self.inventory
            if (int(m["user_id"]), f"e-{mod}") not in have
        ]
        if missing:
            raise InsufficientWrapsError(
                code="insufficient_wraps", message="missing", status=422,
                details={"missing": missing})
        return self.created

    async def _delete(self, path: str, **_kw: Any) -> Dict[str, Any]:
        self.calls.append(f"DELETE {path}")
        if self.fail_delete is not None:
            raise self.fail_delete
        return _grant("g-1", status="revoked")


class _Host(App):
    def __init__(self, backend: _Backend, *, demo: bool = False, real_redaction: bool = False,
                 teams: List[Dict[str, Any]] | None = None, shown_instance: Dict[str, Any] | None = None) -> None:
        super().__init__()
        self._shown = shown_instance or dict(INSTANCE)
        auth = MagicMock()
        auth.has_feature = MagicMock(return_value=True)
        auth.list_teams = AsyncMock(
            return_value=teams or [{"name": "Real Team Name", "slug": SLUG}])
        self.auth_service = auth
        self.backend = backend
        owner = _owner_keys()
        self.team_memory_service = TeamMemoryService(
            api_client=backend.api, auth_service=auth, crypto=crypto_module,
            key_store_provider=lambda: owner,
            retrieval_service=_retrieval(owner, backend.inventory),
        )
        self.demo_mode = demo
        if demo and real_redaction:
            from servonaut.services.redaction_service import RedactionService
            self.redaction_service = RedactionService()
        elif demo:
            self.redaction_service = MagicMock()
            self.redaction_service.redact_name = lambda n: "stand-in"
            self.redaction_service.scrub_stream = lambda t: t
        self.notes: List[str] = []

    def on_mount(self) -> None:
        self.push_screen(ShareInstanceScreen(dict(self._shown)))

    def connection_instance(self, row):
        """Demo mode: the real record behind a stand-in row."""
        return dict(INSTANCE) if row.get("id") != INSTANCE["id"] else row

    def notify(self, message, *a, **kw):  # type: ignore[override]
        self.notes.append(str(message))


async def _settle(pilot, screen, cond, what="state") -> None:
    for _ in range(200):
        await pilot.pause(0.05)
        if cond():
            return
    raise AssertionError(f"timed out waiting for {what}")


def _text(screen, selector: str) -> str:
    return str(screen.query_one(selector, Static).render())


async def _open(app: _Host, pilot) -> ShareInstanceScreen:
    screen = app.screen
    await _settle(pilot, screen, lambda: "Will be able" in _text(screen, "#share-readers")
                  or "No member" in _text(screen, "#share-readers"), "readers")
    return screen


async def test_the_form_lists_who_can_read_it_at_the_chosen_role():
    backend = _Backend(members=[_member(1, "Sam Viewer", "viewer"), _member(2, "Kim Member"), _member(3, "Lee Admin", "admin")])
    app = _Host(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        text = _text(screen, "#share-readers")
        assert "Viewer" not in text.replace("Sam Viewer", "")  # sanity
        assert "Sam Viewer" in text  # default role is viewer: everyone qualifies
        screen.query_one("#share-role-select", Select).value = "admin"
        await _settle(pilot, screen, lambda: "Kim Member" not in _text(screen, "#share-readers"), "role filter")
        assert "Lee Admin" in _text(screen, "#share-readers")
        assert "added automatically" in _text(screen, "#share-readers")


async def test_a_team_name_with_markup_is_shown_literally():
    backend = _Backend(members=[_member(1, "[bold]Odd[/bold] Name")])
    app = _Host(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        assert "[bold]Odd[/bold] Name" in _text(screen, "#share-readers")


async def test_demo_mode_never_shows_a_real_member_or_team():
    backend = _Backend(members=[_member(1, "Real Person")])
    app = _Host(backend, demo=True)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        assert "Real Person" not in _text(screen, "#share-readers")
        assert "stand-in" in _text(screen, "#share-readers")
        team = screen.query_one("#share-team-select", Select)
        assert team.value == SLUG  # the value stays the real slug
        assert "Real Team Name" not in str(team.render())


async def test_after_sharing_it_lists_who_has_no_memory_key():
    backend = _Backend(members=[_member(1, "Kim Member")])
    backend.created = _grant("g-new", pending_recipients=[
        {"user_id": 9, "name": "Pat Waiting", "role": "member", "reason": "no_memory_key"}])
    app = _Host(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#share-btn-confirm", Button).press()
        await _settle(pilot, screen, lambda: "No memory key yet" in _text(screen, "#share-readers"), "pending")
        assert "Pat Waiting" in _text(screen, "#share-readers")
        assert "Ask them to set up Memory Sync" in _text(screen, "#share-readers")
        assert app.screen is screen  # stays open to show it


async def test_an_existing_share_shows_revoke_and_share_again():
    backend = _Backend(members=[_member(1, "Kim Member")], live=[_grant("g-1")])
    app = _Host(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        await _settle(pilot, screen, lambda: screen.query_one("#share-existing").has_class("-shown"), "panel")
        assert "role member" in _text(screen, "#share-existing-text")
        assert "os, logs" in _text(screen, "#share-existing-text")
        assert screen.query_one("#share-btn-confirm", Button).disabled


async def test_share_again_revokes_then_grants_and_never_purges():
    backend = _Backend(members=[_member(1, "Kim Member")], live=[_grant("g-1")])
    app = _Host(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        await _settle(pilot, screen, lambda: screen.query_one("#share-existing").has_class("-shown"), "panel")
        screen.query_one("#share-btn-reshare", Button).press()
        await _settle(pilot, screen, lambda: any(c.startswith("POST") for c in backend.calls), "grant")
    writes = [c for c in backend.calls if not c.startswith("GET")]
    assert writes == [f"DELETE /api/v1/teams/{SLUG}/memory/grant/g-1", f"POST /api/v1/teams/{SLUG}/memory/grant"]


async def test_purge_waits_for_the_confirmation_and_cancel_changes_nothing():
    backend = _Backend(members=[_member(1, "Kim Member")], live=[_grant("g-1")])
    app = _Host(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        await _settle(pilot, screen, lambda: screen.query_one("#share-existing").has_class("-shown"), "panel")
        screen.query_one("#share-btn-purge", Button).press()
        await _settle(pilot, screen, lambda: isinstance(app.screen, PurgeCopiesModal), "confirmation")
        assert app.screen.query_one("#purge-btn-cancel", Button).has_focus
        assert not [c for c in backend.calls if not c.startswith("GET")]
        await pilot.press("escape")
        await _settle(pilot, screen, lambda: app.screen is screen, "back on the form")
        for _ in range(5):
            await pilot.pause()
        assert not [c for c in backend.calls if not c.startswith("GET")]


async def test_confirmed_purge_calls_the_purge_route_only():
    backend = _Backend(members=[_member(1, "Kim Member")], live=[_grant("g-1")])
    app = _Host(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        await _settle(pilot, screen, lambda: screen.query_one("#share-existing").has_class("-shown"), "panel")
        screen.query_one("#share-btn-purge", Button).press()
        await _settle(pilot, screen, lambda: isinstance(app.screen, PurgeCopiesModal), "confirmation")
        app.screen.query_one("#purge-btn-confirm", Button).press()
        await _settle(pilot, screen, lambda: any("purge" in c for c in backend.calls), "purge")
    assert [c for c in backend.calls if not c.startswith("GET")] == [
        f"POST /api/v1/teams/{SLUG}/memory/grant/g-1/purge"]


async def test_revoke_calls_only_the_revoke_route():
    backend = _Backend(members=[_member(1, "Kim Member")], live=[_grant("g-1")])
    app = _Host(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        await _settle(pilot, screen, lambda: screen.query_one("#share-existing").has_class("-shown"), "panel")
        screen.query_one("#share-btn-revoke", Button).press()
        await _settle(pilot, screen, lambda: not screen.query_one("#share-existing").has_class("-shown"), "revoked")
    assert [c for c in backend.calls if not c.startswith("GET")] == [
        f"DELETE /api/v1/teams/{SLUG}/memory/grant/g-1"]


async def test_the_form_fits_a_narrow_terminal():
    backend = _Backend(members=[_member(1, "Kim Member")], live=[_grant("g-1")])
    app = _Host(backend)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _open(app, pilot)
        await _settle(pilot, screen, lambda: screen.query_one("#share-existing").has_class("-shown"), "panel")
        for sel in ("#share-btn-revoke", "#share-btn-reshare", "#share-btn-purge", "#share-btn-cancel"):
            region = screen.query_one(sel).region
            assert region.width > 0 and region.right <= 100, sel


async def test_toggling_demo_mode_redraws_the_team_and_readers():
    backend = _Backend(members=[_member(1, "Real Person")])
    app = _Host(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        assert "Real Person" in _text(screen, "#share-readers")
        app.demo_mode = True
        app.redaction_service = MagicMock()
        app.redaction_service.redact_name = lambda n: "stand-in"
        app.redaction_service.scrub_stream = lambda t: t
        screen.refresh_after_demo_toggle()
        await pilot.pause()
        assert "Real Person" not in _text(screen, "#share-readers")
        assert screen.query_one("#share-team-select", Select).value == SLUG


async def _live_panel(app, pilot):
    screen = await _open(app, pilot)
    await _settle(pilot, screen, lambda: screen.query_one("#share-existing").has_class("-shown"), "panel")
    return screen


async def test_share_again_keeps_the_existing_grants_role_and_modules():
    backend = _Backend(members=[_member(1, "Kim Admin", "admin")],
                       live=[_grant("g-1", required_role="admin", modules=["os"])])
    app = _Host(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        screen.query_one("#share-btn-reshare", Button).press()
        await _settle(pilot, screen, lambda: backend.posted, "grant")
    assert (backend.posted[-1]["required_role"], backend.posted[-1]["modules"]) == ("admin", ["os"])


async def test_a_deliberate_edit_wins_over_the_existing_grant():
    backend = _Backend(members=[_member(1, "Kim Admin", "admin")],
                       live=[_grant("g-1", required_role="admin", modules=["os"])])
    app = _Host(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        screen.query_one("#share-role-select", Select).value = "viewer"
        await pilot.pause(0.2)
        screen.query_one("#share-btn-reshare", Button).press()
        await _settle(pilot, screen, lambda: backend.posted, "grant")
    assert backend.posted[-1]["required_role"] == "viewer"


async def test_a_changed_key_stops_share_again_before_anything_is_revoked():
    backend = _Backend(members=[_member(1, "Kim Member"), _member(2, "Lee Member", key_changed=True)],
                       live=[_grant("g-1", required_role="member", modules=["os"])])
    app = _Host(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        screen.query_one("#share-btn-reshare", Button).press()
        await _settle(pilot, screen, lambda: "Lee Member" in _text(screen, "#share-status"), "message")
        assert "changed" in _text(screen, "#share-status")
    assert not [c for c in backend.calls if not c.startswith("GET")]


async def test_a_changed_key_stops_a_first_share_too():
    backend = _Backend(members=[_member(2, "Lee Member", key_changed=True)])
    app = _Host(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#share-btn-confirm", Button).press()
        await _settle(pilot, screen, lambda: "Lee Member" in _text(screen, "#share-status"), "message")
    assert backend.posted == []


async def test_demo_mode_never_shows_the_real_team_in_an_error_or_a_success():
    backend = _Backend(members=[_member(1, "Kim Member")], live=[_grant("g-1")])
    backend.fail_delete = RuntimeError("Team team-a is unavailable")
    app = _Host(backend, demo=True, real_redaction=True)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        screen.query_one("#share-btn-revoke", Button).press()
        await _settle(pilot, screen, lambda: "failed" in _text(screen, "#share-status").lower()
                      or "could not" in _text(screen, "#share-status").lower(), "error")
        assert "team-a" not in _text(screen, "#share-status")
        assert "Real Team Name" not in _text(screen, "#share-status")


async def test_a_demo_share_success_names_neither_the_team_nor_its_slug():
    backend = _Backend(members=[_member(1, "Kim Member")])
    app = _Host(backend, demo=True, real_redaction=True)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#share-btn-confirm", Button).press()
        await _settle(pilot, screen, lambda: app.notes, "notification")
    joined = " ".join(app.notes)
    assert "team-a" not in joined and "Real Team Name" not in joined


async def test_a_demo_share_uses_the_real_server_id_for_the_request():
    backend = _Backend(members=[_member(1, "Kim Member")])
    fake_row = {"id": "i-fake-0000", "name": "stand-in-name", "provider": "aws"}
    app = _Host(backend, demo=True, shown_instance=fake_row)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#share-btn-confirm", Button).press()
        await _settle(pilot, screen, lambda: backend.posted, "grant")
    assert backend.posted[-1]["instance_id"] == INSTANCE["id"]


async def test_switching_team_clears_the_other_teams_share():
    teams = [{"name": "Team A", "slug": SLUG}, {"name": "Team B", "slug": "team-b"}]
    backend = _Backend(members=[_member(1, "Kim Member")])
    backend.live_for = {SLUG: [_grant("g-1")], "team-b": []}
    app = _Host(backend, teams=teams)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _live_panel(app, pilot)
        screen.query_one("#share-team-select", Select).value = "team-b"
        await _settle(pilot, screen, lambda: not screen.query_one("#share-existing").has_class("-shown"), "cleared")
        assert screen._grant is None
        assert not screen.query_one("#share-btn-confirm", Button).disabled


async def test_a_refresh_does_not_wipe_the_already_shared_message():
    from servonaut.services.api_client import GrantExistsError
    backend = _Backend(members=[_member(1, "Kim Member")])
    backend.fail_post = GrantExistsError(code="grant_exists", message="exists", status=409)
    app = _Host(backend)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        backend.live = [_grant("g-1")]
        screen.query_one("#share-btn-confirm", Button).press()
        await _settle(pilot, screen, lambda: screen.query_one("#share-existing").has_class("-shown"), "panel")
        for _ in range(10):
            await pilot.pause(0.05)
        assert "already shared" in _text(screen, "#share-status")


async def test_a_team_name_with_markup_is_shown_literally_in_the_picker():
    teams = [{"name": "[bold]Odd[/bold] Team", "slug": SLUG}]
    backend = _Backend(members=[_member(1, "Kim Member")])
    app = _Host(backend, teams=teams)
    async with app.run_test(size=(120, 50)) as pilot:
        screen = await _open(app, pilot)
        select = screen.query_one("#share-team-select", Select)
        shown = " ".join(str(w.render()) for w in select.query("SelectCurrent Static"))
        assert "[bold]Odd[/bold] Team" in shown
