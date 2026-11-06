"""Rendered layout contracts for both memory passphrase modes."""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest
from textual import events
from textual.app import App
from textual.widgets import Button, Input, Static, Switch

from tests.test_memory_screens import _EnrolApp, _StyledEnrolApp
from servonaut.styles import CSS_FILES

SIZES = [(60, 20), (80, 24), (100, 30), (100, 40), (120, 30), (160, 50)]
# At 44x10, the full app styles leave 35 columns and three scroll rows.
SMALL_SIZES = [(44, 10), (44, 12), (50, 16)]
PASSPHRASE = "Synthetic!Maple7-Orbit"


@pytest.fixture
def modal_policy(monkeypatch):
    """Use the deterministic fallback policy, without an OS keychain."""
    monkeypatch.setitem(sys.modules, "zxcvbn", None)


def _region(region):
    return {"x": region.x, "y": region.y, "width": region.width, "height": region.height}


def _assert_layout(app, mode, state, request):
    """Check geometry against visible content and retain the measured values."""
    container = app.screen.query_one("#enrol-container")
    body = app.screen.query_one("#enrol-body")
    footer = app.screen.query_one("#enrol-btn-row")
    children = [child for child in body.children if child.display]
    natural_height = sum(
        child.region.height + child.styles.margin.top + child.styles.margin.bottom
        for child in children
    ) + footer.region.height + footer.styles.margin.top + container.styles.gutter.height
    gap = footer.region.y - children[-1].region.bottom
    measurements = {
        "mode": mode, "state": state, "viewport": list(app.size),
        "container": _region(container.region), "body": _region(body.region),
        "footer": _region(footer.region), "natural_height": natural_height,
        "footer_gap": gap, "scroll": body.scroll_y, "max_scroll": body.max_scroll_y,
        "focus": app.focused.id if app.focused else None,
    }
    request.node.user_properties.append(("geometry", json.dumps(measurements)))
    assert container.region in app.screen.region, measurements
    assert body.region in container.content_region, measurements
    assert footer.region in container.content_region, measurements
    assert body.region.bottom < footer.region.y, measurements
    actions = list(footer.children)
    for action in actions:
        assert action.region in footer.region, measurements
        for y in range(action.region.y, action.region.bottom):
            for x in range(action.region.x, action.region.right):
                visible, _ = app.get_widget_at(x, y)
                assert visible is action or action in visible.ancestors, (
                    measurements, action.id, visible, x, y,
                )
    assert actions[0].region.right <= actions[1].region.x, measurements
    for previous, current in zip(children, children[1:]):
        assert previous.region.bottom <= current.region.y, measurements
    for child in children:
        assert body.content_region.x <= child.region.x, measurements
        assert child.region.right <= body.content_region.right, measurements
    assert body.max_scroll_y == max(0, body.virtual_size.height - body.scrollable_content_region.height)
    assert 0 <= body.scroll_y <= body.max_scroll_y, measurements
    if app.focused is not None and body in app.focused.ancestors:
        assert app.focused.region in body.region, measurements
    if mode == "unlock":
        assert container.region.height <= natural_height + 1, measurements
        assert gap <= 2, measurements
    if mode == "enrol" and app.size.width >= 100 and app.size.height >= 30 and state != "long-advice":
        assert body.max_scroll_y == 0, measurements
    return body


async def _paste(pilot, value):
    """Send the terminal paste event through the app and the active input."""
    assert isinstance(pilot.app.focused, Input)
    pilot.app.post_message(events.Paste(value))
    await pilot.pause()
    assert pilot.app.focused.value == value


async def _replace(pilot, value):
    await pilot.press("ctrl+shift+a", "backspace")
    await _paste(pilot, value)


async def _tab(pilot, app, expected):
    await pilot.press("tab")
    await pilot.pause()
    await pilot.wait_for_scheduled_animations()
    assert app.focused.id == expected
    body = app.screen.query_one("#enrol-body")
    if expected in ("enrol-pass1", "enrol-pass2", "enrol-remember"):
        assert app.focused.region in body.region


@pytest.mark.parametrize("size", SIZES + SMALL_SIZES, ids=lambda size: f"{size[0]}x{size[1]}")
@pytest.mark.parametrize("mode", ["enrol", "unlock"])
@pytest.mark.parametrize("keychain", [False, True], ids=["no-keychain", "keychain"])
@pytest.mark.parametrize("remember_default", [False, True], ids=["default-off", "default-on"])
@pytest.mark.asyncio
async def test_modes_and_states_use_reachable_actions(
    size, mode, keychain, remember_default, modal_policy, monkeypatch, request,
):
    from servonaut.services.memory import passphrase_store

    monkeypatch.setattr(passphrase_store, "keyring_available", lambda: keychain)
    app = _StyledEnrolApp(mode=mode, remember_default=remember_default)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        modal = app.screen
        assert app.focused.id == "enrol-pass1"
        _assert_layout(app, mode, "empty", request)
        await pilot.press("enter")
        assert app.screen is modal
        assert modal.query_one("#enrol-btn-confirm", Button).disabled
        if mode == "enrol":
            await pilot.press(*"weak")
            await _tab(pilot, app, "enrol-pass2")
            await pilot.press(*"weak")
            await pilot.pause()
            _assert_layout(app, mode, "weak", request)
            assert modal.query_one("#enrol-btn-confirm", Button).disabled
            await pilot.press("shift+tab")
            assert app.focused.id == "enrol-pass1"
            await _replace(pilot, PASSPHRASE)
            await _tab(pilot, app, "enrol-pass2")
            await _replace(pilot, "")
            _assert_layout(app, mode, "unconfirmed", request)
            assert modal.query_one("#enrol-btn-confirm", Button).disabled
            await _paste(pilot, "Different8!Pine")
            _assert_layout(app, mode, "mismatch", request)
            assert "do not match" in str(modal.query_one("#enrol-mismatch", Static).content)
            await pilot.press("enter")
            assert app.screen is modal
            await _replace(pilot, PASSPHRASE)
        else:
            await _paste(pilot, PASSPHRASE)
            assert not modal.query_one("#enrol-pass2_field").display
        _assert_layout(app, mode, "accepted", request)
        assert not modal.query_one("#enrol-btn-confirm", Button).disabled
        field = app.focused
        assert isinstance(field, Input)
        await pilot.press("ctrl+r")
        assert not field.password
        await pilot.press("ctrl+r")
        assert field.password
        remember = modal.query_one("#enrol-remember", Switch)
        if keychain:
            await _tab(pilot, app, "enrol-remember")
            assert remember.value is remember_default
            await pilot.press("space")
            await pilot.pause()
            assert remember.value is not remember_default
            _assert_layout(app, mode, "remember-toggled", request)
        else:
            assert not modal.query_one("#enrol-remember-row").display
        await _tab(pilot, app, "enrol-btn-cancel")
        await _tab(pilot, app, "enrol-btn-confirm")
        await pilot.press("enter")
        assert app.dismissed_value.passphrase == PASSPHRASE
        assert app.dismissed_value.remember is (keychain and not remember_default)


@pytest.mark.parametrize("mode", ["enrol", "unlock"])
@pytest.mark.parametrize("keychain", [False, True])
@pytest.mark.parametrize("remember_default", [False, True])
@pytest.mark.asyncio
async def test_resize_keeps_values_scroll_focus_and_cancel(
    mode, keychain, remember_default, modal_policy, monkeypatch, request,
):
    from servonaut.services.memory import passphrase_store

    monkeypatch.setattr(passphrase_store, "keyring_available", lambda: keychain)
    app = _StyledEnrolApp(mode=mode, remember_default=remember_default)
    async with app.run_test(size=(160, 50)) as pilot:
        await _paste(pilot, PASSPHRASE)
        if mode == "enrol":
            await _tab(pilot, app, "enrol-pass2")
            await _paste(pilot, PASSPHRASE)
        await pilot.pause()
        if keychain:
            await _tab(pilot, app, "enrol-remember")
            await pilot.press("space")
        for size in [(100, 30), (80, 24), (60, 20), *SMALL_SIZES, (100, 40), (120, 30), (160, 50)]:
            await pilot.resize_terminal(*size)
            await pilot.pause()
            await pilot.wait_for_scheduled_animations()
            body = _assert_layout(app, mode, "resize-accepted", request)
            assert app.focused.region in body.region
            assert app.screen.query_one("#enrol-pass1", Input).value == PASSPHRASE
            if mode == "enrol":
                assert app.screen.query_one("#enrol-pass2", Input).value == PASSPHRASE
            if keychain:
                assert app.screen.query_one("#enrol-remember", Switch).value is not remember_default
        await _tab(pilot, app, "enrol-btn-cancel")
        await pilot.press("enter")
        assert app.dismissed_value is None


@pytest.mark.parametrize("size", SIZES + [(44, 10)], ids=lambda size: f"{size[0]}x{size[1]}")
@pytest.mark.parametrize("keychain", [False, True])
@pytest.mark.asyncio
async def test_wrapped_estimator_advice_has_bounded_keyboard_scroll(size, keychain, monkeypatch, request):
    from servonaut.services.memory import passphrase_store

    advice = "Use several unrelated words and avoid repeated patterns. " * 20
    monkeypatch.setattr(passphrase_store, "keyring_available", lambda: keychain)
    monkeypatch.setitem(sys.modules, "zxcvbn", SimpleNamespace(zxcvbn=lambda value: {
        "score": 2, "feedback": {"warning": advice, "suggestions": [advice]},
    }))
    app = _StyledEnrolApp()
    async with app.run_test(size=size) as pilot:
        await _paste(pilot, PASSPHRASE)
        await _tab(pilot, app, "enrol-pass2")
        await _paste(pilot, PASSPHRASE)
        await pilot.pause()
        body = _assert_layout(app, "enrol", "long-advice", request)
        assert body.max_scroll_y > 0
        assert str(app.screen.query_one("#enrol-mismatch", Static).content).count(advice) >= 1
        if keychain:
            await _tab(pilot, app, "enrol-remember")
        await _tab(pilot, app, "enrol-btn-cancel")
        # Disabled Enrol and hidden reveal controls must not receive Tab.
        await _tab(pilot, app, "enrol-body")
        await pilot.press("end")
        await pilot.pause()
        await pilot.wait_for_scheduled_animations()
        assert body.scroll_y == body.max_scroll_y
        _assert_layout(app, "enrol", "long-advice", request)
        await pilot.press("home")
        await pilot.pause()
        await pilot.wait_for_scheduled_animations()
        assert body.scroll_y == 0
        await _tab(pilot, app, "enrol-pass1")
        await pilot.press("escape")
        assert app.dismissed_value is None


class _RetryUnlockApp(App):
    """Run the real prompt and retry methods with a local bootstrap boundary."""

    CSS_PATH = CSS_FILES

    def __init__(self):
        super().__init__()
        self.attempts = []
        self.messages = []

    def on_mount(self):
        from servonaut.app import ServonautApp

        self.unlock_worker = self.run_worker(ServonautApp._unlock_memory_sync_with_prompt(self))

    async def bootstrap_memory_cloud(self):
        from servonaut.app import ServonautApp
        from servonaut.services.memory.crypto import DecryptionFailedError

        value = await ServonautApp._prompt_memory_passphrase(self, mode="unlock")
        self.attempts.append(value)
        if value != PASSPHRASE:
            raise DecryptionFailedError("Decryption failed")

    def notify(self, message, **kwargs):
        self.messages.append(message)
        return super().notify(message, **kwargs)


@pytest.mark.parametrize("size", SIZES + [(44, 10), (50, 16)], ids=lambda size: f"{size[0]}x{size[1]}")
@pytest.mark.parametrize("keychain", [False, True])
@pytest.mark.parametrize("finish", ["enter", "escape", "click"])
@pytest.mark.asyncio
async def test_wrong_unlock_retry_stays_compact_and_accepts_keys(size, keychain, finish, monkeypatch, request):
    from servonaut.app import MEMORY_PASSPHRASE_ENV
    from servonaut.services.memory import passphrase_store
    from servonaut.services.memory.sync_errors import WRONG_PASSPHRASE_MESSAGE

    monkeypatch.delenv(MEMORY_PASSPHRASE_ENV, raising=False)
    monkeypatch.setattr(passphrase_store, "keyring_available", lambda: keychain)
    app = _RetryUnlockApp()
    async with app.run_test(size=size, notifications=True) as pilot:
        await pilot.pause()
        first = app.screen
        _assert_layout(app, "unlock", "empty", request)
        await pilot.press(*"Wrong8!Birch")
        if keychain:
            await _tab(pilot, app, "enrol-remember")
        await _tab(pilot, app, "enrol-btn-cancel")
        await _tab(pilot, app, "enrol-btn-confirm")
        await pilot.press("enter")
        await pilot.pause()
        assert app.attempts == ["Wrong8!Birch"]
        assert WRONG_PASSPHRASE_MESSAGE in app.messages
        assert app.screen is not first
        assert app.focused.id == "enrol-pass1"
        assert app.screen.query_one("#enrol-pass1", Input).value == ""
        _assert_layout(app, "unlock", "wrong-passphrase-retry", request)
        assert app.screen.query("Toast")
        await pilot.click("Toast")
        await pilot.pause()
        assert not app.screen.query("Toast")
        _assert_layout(app, "unlock", "error-dismissed", request)
        if finish != "escape":
            await _paste(pilot, PASSPHRASE)
            _assert_layout(app, "unlock", "retry-valid", request)
            if finish == "enter":
                if keychain:
                    await _tab(pilot, app, "enrol-remember")
                await _tab(pilot, app, "enrol-btn-cancel")
                await _tab(pilot, app, "enrol-btn-confirm")
        if finish == "click":
            await pilot.click("#enrol-btn-confirm")
        else:
            await pilot.press(finish)
        await app.unlock_worker.wait()
        if finish != "escape":
            assert app.attempts == ["Wrong8!Birch", PASSPHRASE]
            assert "Memory Sync unlocked." in app.messages
        else:
            assert app._memory_sync_prompt_skipped
            assert app.attempts == ["Wrong8!Birch"]


@pytest.mark.parametrize("app_class", [_EnrolApp, _StyledEnrolApp], ids=["default-css", "app-css"])
@pytest.mark.parametrize("mode", ["enrol", "unlock"])
@pytest.mark.parametrize("size", [(44, 10), (50, 16)], ids=["44x10", "50x16"])
@pytest.mark.asyncio
async def test_small_prompt_keeps_actions_outside_bounded_scroll(app_class, mode, size, monkeypatch):
    from servonaut.services.memory import passphrase_store

    monkeypatch.setattr(passphrase_store, "keyring_available", lambda: True)
    app = app_class(mode=mode)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        container = app.screen.query_one("#enrol-container")
        body = app.screen.query_one("#enrol-body")
        footer = app.screen.query_one("#enrol-btn-row")
        assert container.region in app.screen.region
        assert body.region in container.content_region
        assert footer.region in container.content_region
        assert body.region.bottom < footer.region.y
        for action in footer.children:
            assert action.region in footer.region
        assert body.max_scroll_y > 0
        await pilot.press("escape")
        assert app.dismissed_value is None


@pytest.mark.parametrize("app_class", [_EnrolApp, _StyledEnrolApp], ids=["default-css", "app-css"])
@pytest.mark.parametrize("size", [(100, 30), (160, 50)], ids=["100x30", "160x50"])
@pytest.mark.parametrize("keychain_available", [False, True], ids=["no-keychain", "keychain"])
@pytest.mark.asyncio
async def test_unlock_height_follows_visible_content(app_class, size, keychain_available, monkeypatch):
    """A shared enrol height must not leave a large gap in the unlock prompt."""
    from servonaut.services.memory import passphrase_store

    monkeypatch.setattr(passphrase_store, "keyring_available", lambda: keychain_available)
    app = app_class(mode="unlock")
    async with app.run_test(size=size) as pilot:
        await pilot.press("o", "l", "d")
        await pilot.pause()
        assert app.screen.query_one("#enrol-pass1", Input).value == "old"
        container = app.screen.query_one("#enrol-container")
        body = app.screen.query_one("#enrol-body")
        footer = app.screen.query_one("#enrol-btn-row")
        visible_content = [child for child in body.children if child.display]
        gap = footer.region.y - visible_content[-1].region.bottom
        assert gap <= 2, f"{size}: unlock leaves {gap} rows before its actions"
        content_height = sum(
            child.region.height + child.styles.margin.top + child.styles.margin.bottom
            for child in visible_content
        )
        footer_height = footer.region.height + footer.styles.margin.top + footer.styles.margin.bottom
        natural_height = content_height + footer_height + container.styles.gutter.height
        assert container.region.height <= natural_height + 1, (
            size, container.region.height, natural_height,
        )
        await pilot.press("escape")
        assert app.dismissed_value is None
