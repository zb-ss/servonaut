"""Single-key deletion: unbind confirmation, other-member counts, fleet rule and failure logging."""
from __future__ import annotations

import logging
from unittest.mock import AsyncMock

import pytest
from textual.widgets import Button, Input

from servonaut.screens._demo_resolve import UNRESOLVED_MESSAGE
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.services.vault.errors import VaultKeyInUse
from tests._async_bounds import wait_until
from tests.test_vault_key_names_tui import _Host, _Service, _loaded

pytestmark = pytest.mark.usefixtures("navigation_open")

SIZES = [(160, 50), (100, 30)]
USAGE = {
    "team_servers": ["team-web-1"], "own_servers": ["site-[bold]1"], "unchecked": [], "checked": 2,
    "other_members": {"members": 1, "servers": 2}, "can_unbind": True,
}


def _service(usage=None, **kwargs) -> _Service:
    service = _Service(usage=dict(usage if usage is not None else USAGE), **kwargs)
    service.delete_ssh_key = AsyncMock(return_value={"deleted": True})
    return service


def _dialog_open(app) -> bool:
    return isinstance(app.screen, ConfirmActionScreen) and bool(app.screen.query("#btn_confirm"))


def _text(app) -> str:
    return "\n".join(str(w.render()) for w in app.screen.query("Static"))


def _toasts(app) -> list[str]:
    return [message for message, _ in app.notes]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_in_use_with_unbind_shows_usage_and_needs_typed_phrase(size):
    service = _service()
    app = _Host(service)
    async with app.run_test(size=size) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: _dialog_open(app))
        dialog = app.screen
        assert dialog.has_class("vault_key_unbind")
        text = _text(app)
        assert "team-web-1" in text and "2 server(s) of 1 other member(s)" in text
        assert "site-[bold]1" in text  # shown literally, not interpreted as markup
        assert dialog.query_one("#btn_confirm", Button).disabled
        dialog.query_one(Input).value = "UNBIND AND DELETE"
        await wait_until(lambda: not dialog.query_one("#btn_confirm", Button).disabled)
        dialog.query_one("#btn_confirm", Button).press()
        await wait_until(lambda: service.delete_ssh_key.await_count == 1)
        assert service.delete_ssh_key.await_args.kwargs["unbind"] is True
        # The delete is told what the user was shown, so it can refuse to remove more.
        assert service.delete_ssh_key.await_args.kwargs["confirmed_usage"] == USAGE


@pytest.mark.asyncio
async def test_cancelling_the_unbind_dialog_deletes_nothing():
    service = _service()
    app = _Host(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: _dialog_open(app))
        app.screen.query_one("#btn_cancel", Button).press()
        await wait_until(lambda: not isinstance(app.screen, ConfirmActionScreen))
        assert service.delete_ssh_key.await_count == 0


@pytest.mark.asyncio
async def test_in_use_without_unbind_shows_the_old_toast_and_logs(caplog):
    service = _service({**USAGE, "can_unbind": False})
    app = _Host(service)
    caplog.set_level(logging.WARNING)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: any("still used" in t for t in _toasts(app)))
        assert not isinstance(app.screen, ConfirmActionScreen)
        assert any("Other members: 2 server(s) of 1 member(s)" in t for t in _toasts(app))
    assert sum(r.getMessage().startswith("Vault key deletion failed: ") for r in caplog.records) == 1
    assert service.delete_ssh_key.await_count == 0


@pytest.mark.asyncio
async def test_delete_refusal_the_review_missed_offers_the_dialog_once():
    clean = {"team_servers": [], "own_servers": [], "unchecked": [], "checked": 1}
    service = _service(clean)
    refusal = VaultKeyInUse(team_servers=["team-web-1"], own_servers=[], unchecked=[], can_unbind=True)
    service.delete_ssh_key = AsyncMock(side_effect=[refusal, {"deleted": True}])
    app = _Host(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: _dialog_open(app))
        app.screen.query_one(Input).value = "DELETE"
        await wait_until(lambda: not app.screen.query_one("#btn_confirm", Button).disabled)
        app.screen.query_one("#btn_confirm", Button).press()
        await wait_until(lambda: _dialog_open(app) and app.screen.has_class("vault_key_unbind"))
        app.screen.query_one(Input).value = "UNBIND AND DELETE"
        await wait_until(lambda: not app.screen.query_one("#btn_confirm", Button).disabled)
        app.screen.query_one("#btn_confirm", Button).press()
        await wait_until(lambda: service.delete_ssh_key.await_count == 2)
        assert "unbind" not in service.delete_ssh_key.await_args_list[0].kwargs
        assert service.delete_ssh_key.await_args_list[1].kwargs["unbind"] is True
        assert service.delete_ssh_key.await_args_list[1].kwargs["confirmed_usage"] == refusal.usage()


@pytest.mark.asyncio
@pytest.mark.parametrize("needed", [False, True])
async def test_unresolved_fleet_depends_on_whether_checks_read_own_servers(needed):
    service = _service({"team_servers": [], "own_servers": [], "unchecked": [], "checked": 0})
    service.key_checks_read_own_servers = AsyncMock(return_value=needed)
    app = _Host(service)
    app.demo_mode = True
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        if needed:
            await wait_until(lambda: UNRESOLVED_MESSAGE in _toasts(app))
            assert service.usage_calls == []
        else:
            await wait_until(lambda: bool(service.usage_calls))
            assert service.usage_calls[0]["servers"] == []
            assert UNRESOLVED_MESSAGE not in _toasts(app)
            await wait_until(lambda: _dialog_open(app))
            app.screen.query_one("#btn_cancel", Button).press()
            await wait_until(lambda: not isinstance(app.screen, ConfirmActionScreen))


@pytest.mark.asyncio
async def test_failure_paths_log_one_warning_each_and_keep_toasts(caplog):
    caplog.set_level(logging.WARNING)
    service = _service(delete_error=RuntimeError("boom"))
    service.delete_ssh_key = AsyncMock(side_effect=RuntimeError("boom"))
    clean = {"team_servers": [], "own_servers": [], "unchecked": [], "checked": 1}
    service.usage = clean
    app = _Host(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: _dialog_open(app))
        app.screen.query_one(Input).value = "DELETE"
        await wait_until(lambda: not app.screen.query_one("#btn_confirm", Button).disabled)
        app.screen.query_one("#btn_confirm", Button).press()
        await wait_until(lambda: any(t.startswith("Could not delete the vault key") for t in _toasts(app)))
    assert sum(r.getMessage().startswith("Vault key deletion failed: ") for r in caplog.records) == 1

    caplog.clear()
    service = _service()
    service.ssh_key_usage = AsyncMock(side_effect=RuntimeError("down"))
    app = _Host(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: any(t.startswith("Could not check key usage") for t in _toasts(app)))
    assert sum(r.getMessage().startswith("Vault key deletion failed: ") for r in caplog.records) == 1


_NAMES = [{"item_id": "k1", "label": "unique-label", "name": "unique-label", "fingerprint": "SHA256:one"}]


def _failure_lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith("Vault key deletion")]


@pytest.mark.asyncio
async def test_the_single_key_in_use_log_has_counts_only(caplog):
    caplog.set_level(logging.WARNING)
    service = _service({**USAGE, "can_unbind": False}, names=_NAMES)
    app = _Host(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: any("still used" in t for t in _toasts(app)))
        assert any("team-web-1" in t for t in _toasts(app))  # the toast keeps the names
    lines = _failure_lines(caplog)
    assert lines == ["Vault key deletion failed: VaultKeyInUse (team servers 1, own servers 1, unchecked 0, "
                     "other members' servers 2 of 1 member(s))"]
    for private in ("unique-label", "k1", "team-web-1", "site-[bold]1"):
        assert private not in caplog.text


@pytest.mark.asyncio
async def test_the_single_key_failure_logs_carry_no_key_name_or_user_message(caplog):
    from servonaut.services.api_client import APIError
    from servonaut.services.vault.errors import VaultUserError

    caplog.set_level(logging.WARNING)
    clean = {"team_servers": [], "own_servers": [], "unchecked": [], "checked": 1}
    service = _service(clean, names=_NAMES)
    service.delete_ssh_key = AsyncMock(side_effect=VaultUserError("message naming unique-label and site-1"))
    app = _Host(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: _dialog_open(app))
        app.screen.query_one(Input).value = "DELETE"
        await wait_until(lambda: not app.screen.query_one("#btn_confirm", Button).disabled)
        app.screen.query_one("#btn_confirm", Button).press()
        await wait_until(lambda: any(t.startswith("Could not delete the vault key") for t in _toasts(app)))
        assert any("unique-label" in t or "site-1" in t for t in _toasts(app))
    assert _failure_lines(caplog) == ["Vault key deletion failed: VaultUserError"]
    assert "unique-label" not in caplog.text and "site-1" not in caplog.text

    caplog.clear()
    service = _service(names=_NAMES)
    service.ssh_key_usage = AsyncMock(side_effect=APIError(code="rate_limited", message="unique-label", status=429))
    app = _Host(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: any(t.startswith("Could not check key usage") for t in _toasts(app)))
    assert _failure_lines(caplog) == ["Vault key deletion failed: APIError: HTTP 429, rate_limited"]
