"""Native credential prompts retain results, masking, focus and state workers."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from types import SimpleNamespace
import sys
from unittest.mock import AsyncMock, Mock, patch

import pytest
from textual.color import Color
from textual.geometry import Region
from textual.pilot import Pilot
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Static

from servonaut.screens.bw_passphrase_modal import BwPassphraseModal
from servonaut.screens.bw_unlock_modal import BwUnlockModal
from servonaut.screens.vault_rename_key_modal import VaultRenameKeyModal
from servonaut.services.bw_errors import BwUnlockFailedError
from servonaut.services.bw_session_service import BwAuthState, BwSessionService
from servonaut.styles.themes import SERVONAUT_ANSI_DARK, SERVONAUT_ANSI_LIGHT
from servonaut.widgets.dialogs import DialogBody, DialogFrame
from servonaut.widgets.secret_input import SecretInput
from tests._async_bounds import wait_until
from tests.test_dialog_frame import DialogHost


FIELDS = {
    "passphrase": "#bw_passphrase_input", "unlock": "#bw_master_pw",
    "rename": "#vault_rename_key_input",
}
ACTIONS = {
    "passphrase": ("#bw_passphrase_skip_btn", "#bw_passphrase_unlock_btn"),
    "unlock": ("#bw_cancel_btn", "#bw_unlock_btn"),
    "rename": ("#vault_rename_key_cancel", "#vault_rename_key_save"),
}
PASSWORD = "example-prompt-value"


@pytest.fixture(autouse=True)
def _no_secret_or_process_access(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    process = Mock(side_effect=AssertionError("Unexpected process launch"))
    keyring = Mock(side_effect=AssertionError("Unexpected keyring access"))
    secrets = Mock(side_effect=AssertionError("Unexpected secret-store loading"))
    worker = AsyncMock(side_effect=AssertionError("Unexpected Bitwarden subprocess"))
    monkeypatch.setattr("subprocess.run", process)
    monkeypatch.setattr("subprocess.Popen", process)
    monkeypatch.setattr(BwSessionService, "_run", worker)
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", secrets)
    module = sys.modules.get("keyring")
    if module is None:
        module = SimpleNamespace()
        monkeypatch.setitem(sys.modules, "keyring", module)
    for name in ("get_password", "set_password", "delete_password", "get_credential"):
        monkeypatch.setattr(module, name, keyring, raising=False)
    yield
    for guard in (process, keyring, secrets, worker):
        guard.assert_not_called()


def _session(state: BwAuthState = BwAuthState.LOCKED) -> SimpleNamespace:
    return SimpleNamespace(status=AsyncMock(return_value=state), unlock=AsyncMock())


def _modal(kind: str) -> ModalScreen:
    if kind == "passphrase":
        return BwPassphraseModal("report[red]Ω\x1b[2J\u202e.key")
    if kind == "unlock":
        return BwUnlockModal(session_service=_session())
    return VaultRenameKeyModal("Current key Ω")


async def _open(
    app: DialogHost, pilot: Pilot, modal: ModalScreen, field: str,
    results: list[object],
) -> Input:
    origin = app.query_one("#origin", Input)
    origin.focus()
    await wait_until(lambda: app.focused is origin)
    await app.push_screen(modal, results.append)
    await wait_until(lambda: bool(modal.query(field)))
    control = modal.query_one(field, Input)
    await wait_until(lambda: app.focused is control)
    await pilot.pause()
    return control


def _painted(app: DialogHost) -> str:
    return "\n".join(strip.text for strip in app.screen._compositor.render_strips())


def _action_regions(modal: ModalScreen, kind: str) -> tuple[Region, ...]:
    return tuple(modal.query_one(selector).region for selector in ACTIONS[kind])


def _assert_frame(app: DialogHost, modal: ModalScreen, kind: str) -> None:
    frame = modal.query_one(DialogFrame)
    assert modal.region.contains_region(frame.region)
    for selector in (FIELDS[kind], *ACTIONS[kind]):
        control = modal.query_one(selector)
        assert control.region.width > 0 and control.region.height > 0
        assert frame.content_region.contains_region(control.region)
        assert modal.region.contains_region(control.region)
        assert app.get_widget_at(*control.region.center)[0] is control
        if isinstance(control, Button):
            assert control.label.plain in _painted(app)


async def _click(pilot: Pilot, selector: str) -> None:
    button = pilot.app.screen.query_one(selector, Button)
    await wait_until(lambda: not button.has_class("-active"))
    assert await pilot.click(button)
    await pilot.pause()


async def _assert_native_toast(
    app: DialogHost, pilot: Pilot, modal: ModalScreen, message: str, kind: str,
) -> None:
    await wait_until(lambda: bool(modal.query("Toast")))
    await pilot.pause()
    toast = modal.query_one("Toast")
    rack = modal.query_one("ToastRack")
    frame = modal.query_one(DialogFrame)
    assert message in _painted(app)
    assert rack.scrollable_content_region.contains_region(toast.region)
    assert modal.region.contains_region(rack.region)
    assert not frame.region.overlaps(rack.region)
    assert app.get_widget_at(*toast.content_region.center)[0] is toast
    _assert_frame(app, modal, kind)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("kind", ["passphrase", "unlock", "rename"])
async def test_leaf_prompt_keeps_original_focus_in_shared_frame(
    size: tuple[int, int], kind: str,
) -> None:
    app, modal, results = DialogHost(), _modal(kind), []
    async with app.run_test(size=size) as pilot:
        field = await _open(app, pilot, modal, FIELDS[kind], results)
        _assert_frame(app, modal, kind)
        if kind != "rename":
            assert field.password
        if kind == "passphrase":
            assert "report[red]Ω[2J.key" in _painted(app)
        if kind == "unlock":
            assert modal.query_one("#bw_remember", Checkbox).disabled
        await pilot.press("escape")
        await wait_until(lambda: app.screen is not modal)
        assert results == [False if kind == "unlock" else None]
        assert app.focused is app.query_one("#origin")


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,theme", [
    ("passphrase", "servonaut-light"), ("unlock", "ansi-light"),
    ("rename", "ansi-dark"),
])
async def test_representative_leaf_palette_keeps_actions_painted_and_hittable(
    kind: str, theme: str,
) -> None:
    app, modal = DialogHost(), _modal(kind)
    app.theme = theme
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, FIELDS[kind], [])
        _assert_frame(app, modal, kind)


@pytest.mark.asyncio
@pytest.mark.parametrize("submit", ["enter", "click"])
async def test_native_passphrase_submit_returns_exact_value(submit: str) -> None:
    app, modal, results = DialogHost(), _modal("passphrase"), []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, FIELDS["passphrase"], results)
        await pilot.press(*PASSWORD)
        assert PASSWORD not in _painted(app)
        if submit == "enter":
            await pilot.press("enter")
        else:
            await _click(pilot, ACTIONS["passphrase"][1])
        await wait_until(lambda: bool(results))
        assert results == [PASSWORD]


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", ["escape", "click"])
async def test_native_passphrase_skip_returns_none(cancel: str) -> None:
    app, modal, results = DialogHost(), _modal("passphrase"), []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, FIELDS["passphrase"], results)
        if cancel == "escape":
            await pilot.press("escape")
        else:
            await _click(pilot, ACTIONS["passphrase"][0])
        await wait_until(lambda: bool(results))
        assert results == [None]


@pytest.mark.asyncio
async def test_empty_passphrase_enter_warns_without_moving_actions() -> None:
    app, modal = DialogHost(), _modal("passphrase")
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        await _open(app, pilot, modal, FIELDS["passphrase"], [])
        regions = _action_regions(modal, "passphrase")
        with patch.object(app, "notify", wraps=app.notify) as notify:
            await pilot.press("enter")
            await pilot.pause()
        assert app.screen is modal
        assert notify.call_args.args == ("Passphrase is required — or Skip this key.",)
        assert notify.call_args.kwargs["markup"] is False
        assert regions == _action_regions(modal, "passphrase")
        await _assert_native_toast(
            app, pilot, modal,
            "Passphrase is required — or Skip this key.", "passphrase",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("submit", ["enter", "click"])
async def test_native_rename_submit_cleans_and_returns_name(submit: str) -> None:
    app, modal, results = DialogHost(), _modal("rename"), []
    async with app.run_test(size=(100, 30)) as pilot:
        field = await _open(app, pilot, modal, FIELDS["rename"], results)
        field.value = "  New key Ω\x1b  "
        if submit == "enter":
            await pilot.press("enter")
        else:
            await _click(pilot, ACTIONS["rename"][1])
        await wait_until(lambda: bool(results))
        assert results == ["New key Ω"]


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", ["escape", "click"])
async def test_native_rename_cancel_keeps_original_name(cancel: str) -> None:
    app, modal, results = DialogHost(), _modal("rename"), []
    async with app.run_test(size=(100, 30)) as pilot:
        field = await _open(app, pilot, modal, FIELDS["rename"], results)
        assert field.value == "Current key Ω"
        if cancel == "escape":
            await pilot.press("escape")
        else:
            await _click(pilot, ACTIONS["rename"][0])
        await wait_until(lambda: bool(results))
        assert results == [None]


@pytest.mark.asyncio
@pytest.mark.parametrize("value,message", [
    ("  ", "Name is required."), ("x" * 201, "Name must be at most 200 characters."),
])
async def test_native_rename_validation_keeps_feedback_and_save_stationary(
    value: str, message: str,
) -> None:
    app, modal = DialogHost(), _modal("rename")
    async with app.run_test(size=(100, 30)) as pilot:
        field = await _open(app, pilot, modal, FIELDS["rename"], [])
        field.value = value
        before = modal.query_one(ACTIONS["rename"][1]).region
        await pilot.press("enter")
        await pilot.pause()
        assert app.screen is modal and app.focused is field
        feedback = modal.query_one("#vault_rename_key_feedback", Static)
        assert str(feedback.render()) == message
        assert modal.query_one(ACTIONS["rename"][1]).region == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "theme", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"],
)
async def test_rename_error_uses_native_warning_role_in_actual_paint(
    theme: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    app, modal, results = DialogHost(), _modal("rename"), []
    app.theme = theme
    async with app.run_test(size=(100, 30)) as pilot:
        field = await _open(app, pilot, modal, FIELDS["rename"], results)
        field.value = "  "
        await pilot.press("enter")
        await pilot.pause()
        assert results == [] and app.focused is field
        feedback = modal.query_one("#vault_rename_key_feedback", Static)
        assert "Name is required." in _painted(app)
        region = feedback.content_region
        strips = app.screen._compositor.render_strips()
        segments = [
            segment for row in range(region.y, region.bottom)
            for segment in strips[row].crop(region.x, region.right)
            if segment.text.strip()
        ]
        expected = Color.parse(app.get_css_variables()["text-warning"]).rich_color
        assert segments and all(
            segment.style and segment.style.color == expected for segment in segments
        )
        palette = (
            SERVONAUT_ANSI_LIGHT if theme.endswith("light") else SERVONAUT_ANSI_DARK
        )
        assert all(
            segment.style.bgcolor
            and segment.style.color.get_truecolor(palette)
            != segment.style.bgcolor.get_truecolor(palette, foreground=False)
            for segment in segments
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("submit", ["enter", "click"])
async def test_native_unlock_submit_from_password_returns_true_once(
    submit: str,
) -> None:
    # Enter must reach Unlock through the focused native password field.
    app, session, results = DialogHost(), _session(), []
    modal = BwUnlockModal(session_service=session)
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, FIELDS["unlock"], results)
        await pilot.press(*PASSWORD)
        if submit == "enter":
            await pilot.press("enter")
        else:
            await _click(pilot, ACTIONS["unlock"][1])
        await wait_until(lambda: bool(results))
        session.unlock.assert_awaited_once_with(PASSWORD)
        assert results == [True]
        assert app.focused is app.query_one("#origin")


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", ["escape", "click"])
async def test_native_unlock_cancel_returns_false(cancel: str) -> None:
    app, session, results = DialogHost(), _session(), []
    modal = BwUnlockModal(session_service=session)
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, FIELDS["unlock"], results)
        if cancel == "escape":
            await pilot.press("escape")
        else:
            await _click(pilot, ACTIONS["unlock"][0])
        await wait_until(lambda: bool(results))
        session.unlock.assert_not_awaited()
        assert results == [False]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state", ["missing", "not-installed", "unauthenticated", "error"],
)
async def test_unlock_unusable_states_replace_loading_body_and_close_false(
    state: str,
) -> None:
    app, results = DialogHost(), []
    session = None if state == "missing" else _session(
        BwAuthState.NOT_INSTALLED if state == "not-installed"
        else BwAuthState.UNAUTHENTICATED,
    )
    if state == "error":
        session.status.side_effect = RuntimeError("Example status failure")
    modal = BwUnlockModal(session_service=session)
    async with app.run_test(size=(100, 30)) as pilot:
        await app.push_screen(modal, results.append)
        await wait_until(lambda: bool(modal.query("#bw_close_btn")))
        await pilot.pause()
        assert "Checking Bitwarden status" not in _painted(app)
        assert not modal.query(FIELDS["unlock"])
        assert len(modal.query(".bw_unlock_actions")) == 1
        await _click(pilot, "#bw_close_btn")
        await wait_until(lambda: bool(results))
        assert results == [False]


@pytest.mark.asyncio
async def test_already_unlocked_worker_returns_true_without_a_form() -> None:
    app, session, results = DialogHost(), _session(BwAuthState.UNLOCKED), []
    modal = BwUnlockModal(session_service=session)
    async with app.run_test(size=(100, 30)) as pilot:
        await app.push_screen(modal, results.append)
        await wait_until(lambda: bool(results))
        session.status.assert_awaited_once()
        session.unlock.assert_not_awaited()
        assert results == [True]


@pytest.mark.asyncio
@pytest.mark.parametrize("error,expected", [
    (BwUnlockFailedError("Invalid [example] password."), "Invalid [example] password."),
    (RuntimeError("Example failure"), "Unlock failed: Example failure"),
])
async def test_unlock_error_toast_preserves_value_mask_and_action_positions(
    error: Exception, expected: str,
) -> None:
    app, session = DialogHost(), _session()
    session.unlock.side_effect = error
    modal = BwUnlockModal(session_service=session)
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        field = await _open(app, pilot, modal, FIELDS["unlock"], [])
        await pilot.press(*PASSWORD)
        before = _action_regions(modal, "unlock")
        with patch.object(app, "notify", wraps=app.notify) as notify:
            await _click(pilot, ACTIONS["unlock"][1])
            await wait_until(lambda: notify.called)
        assert notify.call_args.args == (expected,)
        assert notify.call_args.kwargs["markup"] is False
        assert app.screen is modal and field.value == PASSWORD and field.password
        assert PASSWORD not in _painted(app)
        assert before == _action_regions(modal, "unlock")
        await _assert_native_toast(app, pilot, modal, expected, "unlock")


@pytest.mark.asyncio
async def test_empty_unlock_warns_without_calling_session() -> None:
    app, session = DialogHost(), _session()
    modal = BwUnlockModal(session_service=session)
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        await _open(app, pilot, modal, FIELDS["unlock"], [])
        before = _action_regions(modal, "unlock")
        with patch.object(app, "notify", wraps=app.notify) as notify:
            await _click(pilot, ACTIONS["unlock"][1])
            await wait_until(lambda: notify.called)
        session.unlock.assert_not_awaited()
        assert notify.call_args.args == ("Master password is required.",)
        assert app.screen is modal
        await _assert_native_toast(
            app, pilot, modal, "Master password is required.", "unlock",
        )
        assert before == _action_regions(modal, "unlock")


@pytest.mark.asyncio
async def test_status_worker_keeps_loading_visible_until_locked_state_arrives() -> None:
    app, session = DialogHost(), _session()
    release = asyncio.Event()

    async def status() -> BwAuthState:
        await release.wait()
        return BwAuthState.LOCKED

    session.status.side_effect = status
    modal = BwUnlockModal(session_service=session)
    async with app.run_test(size=(100, 30)) as pilot:
        try:
            await app.push_screen(modal)
            await wait_until(lambda: session.status.await_count == 1)
            await pilot.pause()
            assert "Checking Bitwarden status" in _painted(app)
            assert not modal.query(FIELDS["unlock"])
            release.set()
            await wait_until(lambda: bool(modal.query(FIELDS["unlock"])))
            await wait_until(lambda: app.focused is modal.query_one(FIELDS["unlock"]))
            await pilot.pause()
            _assert_frame(app, modal, "unlock")
        finally:
            release.set()


@pytest.mark.asyncio
async def test_escape_during_pending_unlock_keeps_original_false_result() -> None:
    app, session, results = DialogHost(), _session(), []
    release = asyncio.Event()

    async def unlock(value: str) -> None:
        await release.wait()

    session.unlock.side_effect = unlock
    modal = BwUnlockModal(session_service=session)
    async with app.run_test(size=(100, 30)) as pilot:
        origin_stack = tuple(app.screen_stack)
        try:
            await _open(app, pilot, modal, FIELDS["unlock"], results)
            await pilot.press(*PASSWORD)
            await _click(pilot, ACTIONS["unlock"][1])
            await wait_until(lambda: session.unlock.await_count == 1)
            pending = [
                worker for worker in app.workers
                if worker.node is modal and worker.group == "bw_session"
                and not worker.is_finished
            ]
            assert len(pending) == 1
            await pilot.press("escape")
            await wait_until(lambda: bool(results))
            await wait_until(lambda: tuple(app.screen_stack) == origin_stack)
            release.set()
            await wait_until(lambda: all(worker.is_finished for worker in pending))
            await pilot.pause()
            assert results == [False]
            assert tuple(app.screen_stack) == origin_stack
            assert app.focused is app.query_one("#origin")
        finally:
            release.set()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["passphrase", "unlock"])
async def test_secret_reveal_and_demo_remasking_stay_native(kind: str) -> None:
    app, modal = DialogHost(), _modal(kind)
    async with app.run_test(size=(100, 30)) as pilot:
        field = await _open(app, pilot, modal, FIELDS[kind], [])
        await pilot.press(*PASSWORD)
        assert field.password and PASSWORD not in _painted(app)
        reveal = modal.query_one(f"#{field.id}_reveal", Button)
        assert reveal.region.width > 0 and reveal.region.height > 0
        assert modal.region.contains_region(reveal.region)
        frame = modal.query_one(DialogFrame)
        assert frame.content_region.contains_region(reveal.region)
        assert app.get_widget_at(*reveal.region.center)[0] is reveal
        assert reveal.label.plain in _painted(app)
        await _click(pilot, f"#{field.id}_reveal")
        await pilot.pause()
        assert not field.password and PASSWORD in _painted(app)
        await _click(pilot, f"#{field.id}_reveal")
        await pilot.pause()
        assert field.password and PASSWORD not in _painted(app)
        await pilot.press("ctrl+r")
        await pilot.pause()
        assert not field.password
        assert PASSWORD in _painted(app)
        app.demo_mode = True
        modal.query_one(SecretInput).refresh_after_demo_toggle()
        await pilot.pause()
        assert field.password
        await pilot.press("ctrl+r")
        assert field.password and PASSWORD not in _painted(app)


@pytest.mark.asyncio
async def test_long_filename_scrolls_only_body_and_keeps_actions_visible() -> None:
    app = DialogHost()
    modal = BwPassphraseModal("example-key-" * 80)
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, FIELDS["passphrase"], [])
        body = modal.query_one(DialogBody)
        await wait_until(lambda: body.max_scroll_y > 0)
        _assert_frame(app, modal, "passphrase")
        frame = modal.query_one(DialogFrame)
        await wait_until(
            lambda: frame.border_subtitle == "Scroll for all details",
        )
        field = modal.query_one(FIELDS["passphrase"], Input)
        before = frame.region, field.region, _action_regions(modal, "passphrase")
        body.focus()
        await wait_until(lambda: app.focused is body)
        await pilot.press("end")
        await wait_until(lambda: body.scroll_y > 0)
        await pilot.pause()
        assert body.scroll_y == body.max_scroll_y
        assert before == (
            frame.region, field.region, _action_regions(modal, "passphrase"),
        )
        _assert_frame(app, modal, "passphrase")
