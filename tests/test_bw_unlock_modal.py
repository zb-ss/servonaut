"""Tests for :class:`servonaut.screens.bw_unlock_modal.BwUnlockModal`.

Unit-tests the unlock worker logic (password handled, dismiss semantics) plus a
``run_test`` pilot smoke test that the state-aware body renders without crashing.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.screens.bw_unlock_modal import BwUnlockModal
from servonaut.services.bw_errors import BwUnlockFailedError
from servonaut.services.bw_session_service import BwAuthState


def test_modal_is_bool_typed():
    bases = [str(b) for b in getattr(BwUnlockModal, "__orig_bases__", [])]
    assert any("bool" in b for b in bases)


def test_escape_binding_present():
    keys = [b.key for b in BwUnlockModal.BINDINGS]
    assert "escape" in keys


class TestDoUnlock:
    def _screen(self, svc, pw="master-pw"):
        screen = BwUnlockModal(session_service=svc)
        screen.query_one = MagicMock(return_value=SimpleNamespace(value=pw))
        screen.dismiss = MagicMock()
        app = MagicMock()
        app.notify = MagicMock()
        patcher = patch.object(type(screen), "app", property(lambda self: app))
        patcher.start()
        screen._test_patcher = patcher
        screen._test_app = app
        return screen

    def test_success_dismisses_true(self):
        svc = MagicMock()
        svc.unlock = AsyncMock(return_value=None)
        screen = self._screen(svc)
        try:
            asyncio.run(screen._do_unlock())
        finally:
            screen._test_patcher.stop()
        svc.unlock.assert_awaited_once_with("master-pw")
        screen.dismiss.assert_called_once_with(True)

    def test_empty_password_warns_and_no_unlock(self):
        svc = MagicMock()
        svc.unlock = AsyncMock()
        screen = self._screen(svc, pw="")
        try:
            asyncio.run(screen._do_unlock())
        finally:
            screen._test_patcher.stop()
        svc.unlock.assert_not_awaited()
        screen.dismiss.assert_not_called()
        assert screen._test_app.notify.called

    def test_bad_password_notifies_markup_false_no_dismiss(self):
        svc = MagicMock()
        svc.unlock = AsyncMock(side_effect=BwUnlockFailedError("Invalid master password."))
        screen = self._screen(svc)
        try:
            asyncio.run(screen._do_unlock())
        finally:
            screen._test_patcher.stop()
        screen.dismiss.assert_not_called()
        kwargs = screen._test_app.notify.call_args.kwargs
        assert kwargs.get("markup") is False


@pytest.mark.asyncio
async def test_locked_state_renders_password_input():
    from textual.app import App
    from textual.widgets import Input

    svc = MagicMock()
    svc.status = AsyncMock(return_value=BwAuthState.LOCKED)

    class _Host(App):
        def on_mount(self) -> None:
            self.push_screen(BwUnlockModal(session_service=svc))

    app = _Host()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.pause()
        inputs = list(app.screen.query(Input))
        assert any(i.id == "bw_master_pw" and i.password for i in inputs)


@pytest.mark.asyncio
async def test_already_unlocked_auto_dismisses():
    from textual.app import App

    svc = MagicMock()
    svc.status = AsyncMock(return_value=BwAuthState.UNLOCKED)
    dismissed = {}

    class _Host(App):
        def on_mount(self) -> None:
            self.push_screen(BwUnlockModal(session_service=svc), lambda r: dismissed.setdefault("r", r))

    app = _Host()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.pause()
    assert dismissed.get("r") is True
