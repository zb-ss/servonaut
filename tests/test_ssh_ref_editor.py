"""Tests for the reworked :class:`servonaut.screens.ssh_ref_editor.SshRefEditorModal`.

Focus on the browse-and-pick rework: the picker result is applied to the form,
the Selected line shows the item NAME, and the save path still PUTs the picked
``item_id`` (with the 402 paid backstop intact).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.screens.ssh_ref_editor import SshRefEditorModal
from servonaut.services.api_client import APIError


def _instance():
    return {"id": "i-123", "name": "web-1", "provider": "aws"}


class _FakeInput:
    def __init__(self, value: str = "") -> None:
        self.value = value


class _FakeStatic:
    def __init__(self) -> None:
        self.text = ""

    def update(self, markup: str) -> None:
        self.text = markup


def _wire(screen, widgets, app):
    screen.query_one = lambda sel, *a, **k: widgets[sel]
    patcher = patch.object(type(screen), "app", property(lambda self: app))
    patcher.start()
    screen._patcher = patcher
    return screen


def test_modal_is_bool_typed():
    bases = [str(b) for b in getattr(SshRefEditorModal, "__orig_bases__", [])]
    assert any("bool" in b for b in bases)


def test_selected_text_uses_name_when_set():
    screen = SshRefEditorModal(_instance())
    screen._selected_item_name = "prod web key"
    assert "prod web key" in screen._selected_text()
    assert "Selected" in screen._selected_text()


def test_selected_text_escapes_hostile_name():
    screen = SshRefEditorModal(_instance())
    screen._selected_item_name = "[red]evil[/red]"
    # Markup is escaped so the literal brackets survive (no markup injection).
    assert "\\[red]" in screen._selected_text()


class TestDoPick:
    def _setup(self, picker_result):
        screen = SshRefEditorModal(_instance())
        widgets = {
            "#collection_id": _FakeInput(),
            "#vault_url": _FakeInput(),
            "#item_id": _FakeInput(),
            "#ssh_ref_selected": _FakeStatic(),
        }
        app = MagicMock()
        app.demo_mode = False
        app.redaction_service = None
        app.push_screen_wait = AsyncMock(return_value=picker_result)
        _wire(screen, widgets, app)
        return screen, widgets

    def test_applies_picked_item(self):
        screen, widgets = self._setup(
            {
                "item_id": "ssh-1",
                "item_name": "prod key",
                "collection_id": "col-9",
                "vault_url": "https://vault.example.com",
            }
        )
        try:
            asyncio.run(screen._do_pick())
        finally:
            screen._patcher.stop()
        assert widgets["#item_id"].value == "ssh-1"
        assert screen._selected_item_name == "prod key"
        assert "prod key" in widgets["#ssh_ref_selected"].text
        assert widgets["#collection_id"].value == "col-9"
        assert widgets["#vault_url"].value == "https://vault.example.com"

    def test_cancel_leaves_form_unchanged(self):
        screen, widgets = self._setup(None)
        try:
            asyncio.run(screen._do_pick())
        finally:
            screen._patcher.stop()
        assert widgets["#item_id"].value == ""
        assert screen._selected_item_name == ""


class TestDoSave:
    def _setup(self, *, item_id="ssh-1", put_exc=None):
        screen = SshRefEditorModal(_instance())
        widgets = {
            "#item_id": _FakeInput(item_id),
            "#collection_id": _FakeInput(),
            "#vault_url": _FakeInput(),
        }
        bw = MagicMock()
        if put_exc is not None:
            bw.put_personal_instance_ref = AsyncMock(side_effect=put_exc)
        else:
            bw.put_personal_instance_ref = AsyncMock(return_value={})
        app = MagicMock()
        app.bw_ssh_config_service = bw
        app.notify = MagicMock()
        screen.query_one = lambda sel, *a, **k: widgets[sel]
        screen.dismiss = MagicMock()
        patcher = patch.object(type(screen), "app", property(lambda self: app))
        patcher.start()
        screen._patcher = patcher
        return screen, bw, app

    def test_save_puts_picked_item_id(self):
        screen, bw, app = self._setup()
        try:
            asyncio.run(screen._do_save())
        finally:
            screen._patcher.stop()
        bw.put_personal_instance_ref.assert_awaited_once()
        kwargs = bw.put_personal_instance_ref.call_args.kwargs
        assert kwargs["ssh_credential_ref"] == {"item_id": "ssh-1"}
        assert kwargs["instance_id"] == "i-123"
        assert kwargs["provider"] == "aws"
        screen.dismiss.assert_called_once_with(True)

    def test_empty_item_id_blocks_save(self):
        screen, bw, app = self._setup(item_id="")
        try:
            asyncio.run(screen._do_save())
        finally:
            screen._patcher.stop()
        bw.put_personal_instance_ref.assert_not_awaited()
        screen.dismiss.assert_not_called()
        assert app.notify.called

    def test_402_notifies_paid_and_no_dismiss(self):
        exc = APIError(code="payment_required", message="paid", status=402)
        screen, bw, app = self._setup(put_exc=exc)
        try:
            asyncio.run(screen._do_save())
        finally:
            screen._patcher.stop()
        screen.dismiss.assert_not_called()
        # 402 surfaces as a warning notify with markup disabled.
        assert any(
            call.kwargs.get("markup") is False for call in app.notify.call_args_list
        )
