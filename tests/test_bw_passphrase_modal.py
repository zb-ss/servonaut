"""Tests for :class:`servonaut.screens.bw_passphrase_modal.BwPassphraseModal`.

Covers the dismiss semantics (Unlock returns the passphrase, Skip/Escape return
``None``, empty passphrase warns and stays open) and a ``run_test`` pilot smoke
that the masked input renders with the filename in the prompt, centered.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from servonaut.screens.bw_passphrase_modal import BwPassphraseModal


def test_modal_optional_str_typed():
    bases = [str(b) for b in getattr(BwPassphraseModal, "__orig_bases__", [])]
    assert any("str" in b for b in bases)


def test_escape_binding_present():
    keys = [b.key for b in BwPassphraseModal.BINDINGS]
    assert "escape" in keys


class TestUnlock:
    def _screen(self, value: str):
        screen = BwPassphraseModal("id_rsa")
        screen.query_one = MagicMock(return_value=SimpleNamespace(value=value))
        screen.dismiss = MagicMock()
        app = MagicMock()
        patcher = patch.object(type(screen), "app", property(lambda self: app))
        patcher.start()
        screen._test_patcher = patcher
        screen._test_app = app
        return screen

    def test_unlock_dismisses_passphrase(self):
        screen = self._screen("hunter2-placeholder")
        try:
            screen.action_unlock()
        finally:
            screen._test_patcher.stop()
        screen.dismiss.assert_called_once_with("hunter2-placeholder")

    def test_empty_passphrase_warns_and_stays(self):
        screen = self._screen("")
        try:
            screen.action_unlock()
        finally:
            screen._test_patcher.stop()
        screen.dismiss.assert_not_called()
        kwargs = screen._test_app.notify.call_args.kwargs
        assert kwargs.get("markup") is False
        assert kwargs.get("severity") == "warning"

    def test_skip_button_dismisses_none(self):
        screen = BwPassphraseModal("id_rsa")
        screen.dismiss = MagicMock()
        screen.on_button_pressed(
            SimpleNamespace(button=SimpleNamespace(id="bw_passphrase_skip_btn"))
        )
        screen.dismiss.assert_called_once_with(None)

    def test_action_skip_dismisses_none(self):
        screen = BwPassphraseModal("id_rsa")
        screen.dismiss = MagicMock()
        screen.action_skip()
        screen.dismiss.assert_called_once_with(None)


@pytest.mark.asyncio
async def test_pilot_renders_masked_input_with_filename_centered():
    from textual.app import App
    from textual.widgets import Input, Static

    from servonaut.styles import CSS_FILES

    class _Host(App):
        CSS_PATH = CSS_FILES

        def on_mount(self) -> None:
            self.push_screen(BwPassphraseModal("id_ed25519"))

    app = _Host()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await pilot.pause()
        pw_input = app.screen.query_one("#bw_passphrase_input", Input)
        assert pw_input.password is True

        prompt = app.screen.query_one("#bw_passphrase_prompt", Static)
        assert "id_ed25519" in str(prompt.render())

        region = app.screen.query_one("#bw_passphrase_container").region
        assert abs(region.x - (120 - region.width) // 2) <= 1
        assert abs(region.y - (40 - region.height) // 2) <= 1
