"""Access dialogs retain exact results and account workers stay on fake APIs."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, cast

import pytest
from textual.geometry import Region
from textual.pilot import Pilot
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Input, Select, Static

from servonaut.screens.ca import CaEnableConfirmModal, CaEnrollmentConfirmModal, CaScreen
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.login import LoginScreen, PassphraseModal
from servonaut.services import config_crypto
from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogFrame
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import collapse_chat, open_case, open_chat
from tests.test_workspace_access_reflow import (
    CASES, _AccessHost, _fake_access_boundaries as _fake_access_boundaries,
)
from tests.test_workspace_pilot import _click
from tests.test_workspace_reflow import _painted


# Modal default-focus and absent Escape behavior must come from original native evidence.
ORIGINAL_MODAL_FOCUS: dict[str, str | None] | None = {
    'passphrase': 'input_passphrase',
    'passphrase-confirm': 'input_passphrase',
    'enroll': 'ca_confirm_host',
    'enable': 'ca_enable_cancel',
}
ORIGINAL_ENROLL_ESCAPE: tuple[bool, tuple[object, ...]] | None = (True, ())


def _summary() -> dict[str, object]:
    return {
        "kind": "enroll", "params": {
            "server": {"hostname": "web-1 [literal] Ω"},
            "principals_by_login": {"ops[literal]": ["person café Ω"]},
            "user_ca_public_keys": [], "host_ca_public_key": "",
        },
    }


def _modal(kind: str) -> ModalScreen:
    if kind.startswith("passphrase"):
        return PassphraseModal(confirm=kind == "passphrase-confirm")
    if kind == "enroll":
        return CaEnrollmentConfirmModal(_summary())
    return CaEnableConfirmModal("Example [literal] café Ω")


def _critical_regions(app: _AccessHost, modal: ModalScreen) -> dict[str, Region]:
    """Check all critical controls in the same frame without moving any target."""
    frame = modal.query_one(DialogFrame)
    controls = list(frame.query(Input)) + list(frame.query(Button))
    regions = {}
    for widget in controls:
        region = widget.region
        assert region.width > 0 and region.height > 0
        assert frame.content_region.contains_region(region)
        assert modal.region.contains_region(region)
        for row in range(region.y, region.bottom):
            hit = app.get_widget_at(region.center[0], row)[0]
            assert hit is widget or widget in hit.ancestors
        if isinstance(widget, Button):
            assert widget.label.plain in _painted(app, widget)
        assert widget.id is not None
        regions[widget.id] = region
    return regions


async def _native_body_end(pilot: Pilot, body: DialogBody) -> None:
    """Exercise native scrolling only when this body really overflows."""
    if body.max_scroll_y > 0:
        body.focus()
        await pilot.press("end")
        await wait_until(lambda: body.scroll_y == body.max_scroll_y)
        await pilot.pause()


def _assert_error_painted(app: _AccessHost, modal: ModalScreen, expected: str) -> Region:
    error = modal.query_one("#passphrase_error", Static)
    assert modal.query_one(DialogFrame).content_region.contains_region(error.region)
    for row in range(error.region.y, error.region.bottom):
        assert app.get_widget_at(error.region.center[0], row)[0] is error
    assert " ".join(expected.split()) in " ".join(_painted(app, error).split())
    return error.region


async def _target(app: _AccessHost, pilot, selector: str) -> None:
    widget = app.screen.query_one(selector)
    await wait_until(lambda: widget.is_mounted and widget.size.width > 0 and widget.size.height > 0)
    # Finish the preceding mount/reflow focus callback before the sole scroll.
    await pilot.pause()
    widget.scroll_visible(animate=False, immediate=True)
    await pilot.pause()
    assert app.screen.region.contains_region(widget.region)
    hit = app.get_widget_at(*widget.region.center)[0]
    assert hit is widget or widget in hit.ancestors
    if isinstance(widget, Button):
        assert widget.label.plain in _painted(app, widget)


async def _pinned_local_signout_target(app: _AccessHost, pilot: Pilot, selector: str) -> None:
    modal = app.screen
    await wait_until(lambda: bool(modal.query(DialogFrame)) and bool(modal.query(selector)))
    frame = modal.query_one(DialogFrame)
    actions = modal.query_one(DialogActions)
    target = modal.query_one(selector, Button)

    def pinned() -> bool:
        return (modal.is_mounted and frame.is_mounted and actions.is_mounted
                and target.is_mounted and not modal._layout_required
                and target.region.width > 0 and target.region.height > 0
                and app.size.region.contains_region(frame.region)
                and frame.content_region.contains_region(actions.region)
                and actions.region.bottom == frame.content_region.bottom
                and actions.content_region.contains_region(target.region))

    await wait_until(pinned)
    refreshed = asyncio.Event()
    modal.call_after_refresh(refreshed.set)
    await wait_until(refreshed.is_set)
    assert pinned() and app._exception is None
    _critical_regions(app, modal)
    ancestors = (modal, frame, actions.parent, actions)
    scroll = tuple(widget.scroll_offset for widget in ancestors)
    await _target(app, pilot, selector)
    assert tuple(widget.scroll_offset for widget in ancestors) == scroll
    assert pinned()


@pytest.mark.asyncio
@pytest.mark.parametrize("confirm", [False, True])
@pytest.mark.parametrize("finish", ["enter", "button"])
async def test_passphrase_exact_untrimmed_result_pointer_enter_equivalence(confirm: bool, finish: str) -> None:
    app = _AccessHost()
    results: list[object] = []
    value = " " + "p" * config_crypto.MIN_PASSPHRASE_LEN + " Ω "
    async with app.run_test(size=(100, 30)) as pilot:
        modal = PassphraseModal(confirm=confirm)
        await app.push_screen(modal, results.append)
        first = modal.query_one("#input_passphrase", Input)
        await wait_until(lambda: app.focused is first)
        first.value = value
        if confirm:
            await pilot.press("enter")
            second = modal.query_one("#input_passphrase_confirm", Input)
            assert app.focused is second and results == []
            second.value = value
        if finish == "enter":
            await pilot.press("enter")
        else:
            await _target(app, pilot, "#btn_passphrase_ok")
            await _click(pilot, "#btn_passphrase_ok")
        await wait_until(lambda: bool(results))
        assert results == [value]


@pytest.mark.asyncio
@pytest.mark.parametrize("confirm", [False, True])
@pytest.mark.parametrize("finish", ["cancel", "escape"])
async def test_passphrase_cancel_has_one_none_result(confirm: bool, finish: str) -> None:
    app = _AccessHost()
    results: list[object] = []
    async with app.run_test(size=(100, 30)) as pilot:
        modal = PassphraseModal(confirm=confirm)
        await app.push_screen(modal, results.append)
        await pilot.pause()
        if finish == "escape":
            await pilot.press("escape")
        else:
            await _click(pilot, "#btn_passphrase_cancel")
        await wait_until(lambda: bool(results))
        assert results == [None]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["short", "mismatch"])
async def test_passphrase_invalid_keeps_exact_fields_and_pinned_error(failure: str) -> None:
    app = _AccessHost()
    results: list[object] = []
    async with app.run_test(size=(100, 30)) as pilot:
        modal = PassphraseModal(confirm=True)
        await app.push_screen(modal, results.append)
        first = modal.query_one("#input_passphrase", Input)
        second = modal.query_one("#input_passphrase_confirm", Input)
        first.value = "x" if failure == "short" else "x" * config_crypto.MIN_PASSPHRASE_LEN
        second.value = "different"
        before = first.value, second.value
        await pilot.pause()
        initial_regions = _critical_regions(app, modal)
        assert set(initial_regions) == {
            "input_passphrase", "input_passphrase_reveal", "input_passphrase_confirm",
            "input_passphrase_confirm_reveal", "btn_passphrase_ok", "btn_passphrase_cancel",
        }
        await _click(pilot, "#btn_passphrase_ok")
        error = modal.query_one("#passphrase_error", Static)
        expected = (f"Passphrase must be at least {config_crypto.MIN_PASSPHRASE_LEN} characters."
                    if failure == "short" else "Passphrases do not match.")
        await wait_until(lambda: expected in error.render().plain)
        await pilot.pause()
        assert results == [] and app.screen is modal
        assert (first.value, second.value) == before
        invalid_regions = _critical_regions(app, modal)
        assert invalid_regions.keys() == initial_regions.keys()
        error_region = _assert_error_painted(app, modal, expected)
        await _native_body_end(pilot, modal.query_one(DialogBody))
        final_regions = _critical_regions(app, modal)
        for button in modal.query_one(DialogActions).query(Button):
            assert final_regions[button.id] == invalid_regions[button.id]
        assert _assert_error_painted(app, modal, expected) == error_region
        assert (first.value, second.value) == before and results == []


@pytest.mark.asyncio
@pytest.mark.parametrize("finish,expected", [("cancel", ""), ("confirm", "different host")])
async def test_ca_enrollment_modal_returns_trimmed_text_without_own_host_validation(finish: str, expected: str) -> None:
    app = _AccessHost()
    results: list[object] = []
    async with app.run_test(size=(100, 30)) as pilot:
        modal = CaEnrollmentConfirmModal(_summary())
        await app.push_screen(modal, results.append)
        field = modal.query_one("#ca_confirm_host", Input)
        field.value = "  different host  "
        await pilot.pause()
        text = "\n".join(widget.render().plain for widget in modal.query(Static))
        assert "web-1 [literal] Ω" in text and "Login ops[literal]: person café Ω" in text
        assert "User CA fingerprints: missing" in text
        assert "Host CA fingerprint: invalid public key" in text
        await _click(pilot, "#ca_confirm" if finish == "confirm" else "#ca_cancel")
        await wait_until(lambda: bool(results))
        assert results == [expected]
        assert app.vault_command_service.calls_to("ca_enroll") == []


@pytest.mark.asyncio
@pytest.mark.parametrize("finish,expected", [("cancel", False), ("escape", False), ("confirm", True)])
async def test_ca_enable_modal_native_boolean_result_once(finish: str, expected: bool) -> None:
    app = _AccessHost()
    results: list[object] = []
    async with app.run_test(size=(100, 30)) as pilot:
        modal = CaEnableConfirmModal("Example [literal] café Ω")
        await app.push_screen(modal, results.append)
        await pilot.pause()
        assert "Example [literal] café Ω" in modal.query_one("#ca_enable_title", Static).render().plain
        if finish == "escape":
            await pilot.press("escape")
        else:
            await _click(pilot, "#ca_enable_confirm" if finish == "confirm" else "#ca_enable_cancel")
        await wait_until(lambda: bool(results))
        assert results == [expected]
        assert app.vault_command_service.calls_to("ca_enable") == []


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["passphrase", "passphrase-confirm", "enroll", "enable"])
async def test_access_modal_default_focus_matches_qualified_original(kind: str) -> None:
    assert ORIGINAL_MODAL_FOCUS is not None and kind in ORIGINAL_MODAL_FOCUS, "Qualify original native default focus; do not guess a safer policy"
    app = _AccessHost()
    async with app.run_test(size=(100, 30)) as pilot:
        modal = _modal(kind)
        await app.push_screen(modal)
        await pilot.pause()
        assert (app.focused.id if app.focused else None) == ORIGINAL_MODAL_FOCUS[kind]


@pytest.mark.asyncio
async def test_enrollment_escape_matches_original_absent_binding_contract() -> None:
    assert ORIGINAL_ENROLL_ESCAPE is not None, "Qualify original absent Escape behavior before setting its expectation"
    app = _AccessHost()
    results: list[object] = []
    async with app.run_test(size=(100, 30)) as pilot:
        modal = CaEnrollmentConfirmModal(_summary())
        await app.push_screen(modal, results.append)
        await pilot.press("escape")
        await pilot.pause()
        assert (app.screen is modal, tuple(results)) == ORIGINAL_ENROLL_ESCAPE


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["passphrase", "passphrase-confirm", "enroll", "enable"])
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_access_modal_actions_painted_and_hit_through_shared_id_cascade(kind: str, size: tuple[int, int]) -> None:
    app = _AccessHost()
    async with app.run_test(size=size) as pilot:
        if kind == "enroll":
            summary = _summary()
            cast(dict[str, Any], summary["params"])["principals_by_login"] = {
                f"user-{index:02d}": [f"principal-{index:02d} café [literal] Ω"]
                for index in range(60)
            }
            modal = CaEnrollmentConfirmModal(summary)
        else:
            modal = _modal(kind)
        await app.push_screen(modal)
        await pilot.pause()
        frame = modal.query_one(DialogFrame)
        assert modal.region.contains_region(frame.region)
        if kind.startswith("passphrase"):
            assert app.focused is modal.query_one("#input_passphrase")
        before = _critical_regions(app, modal)
        body = frame.query_one(DialogBody)
        if kind == "enroll":
            assert body.max_scroll_y > 0 and body.scroll_y == 0
            assert "Job: enroll" in _painted(app, body)
        await _native_body_end(pilot, body)
        after = _critical_regions(app, modal)
        pinned = [button.id for button in frame.query_one(DialogActions).query(Button)]
        if kind == "enroll":
            pinned.append("ca_confirm_host")
            assert "Login user-59:" in _painted(app, body)
        for selector in pinned:
            assert after[selector] == before[selector]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,theme", [("passphrase", "servonaut"), ("enroll", "servonaut-light"), ("enable", "ansi-dark"), ("passphrase-confirm", "ansi-light")])
async def test_access_modal_named_palette_representatives(kind: str, theme: str) -> None:
    app = _AccessHost()
    app.theme = theme
    assert app.config_manager.get().theme == theme
    async with app.run_test(size=(100, 30)) as pilot:
        await app.push_screen(_modal(kind))
        await pilot.pause()
        for button in app.screen.query_one(DialogActions).query(Button):
            await _target(app, pilot, "#" + button.id)


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["cancel", "success", "timeout", "start-error"])
async def test_login_native_device_flow_cancel_success_and_failure_across_chat(outcome: str) -> None:
    app = _AccessHost(False)
    auth = app.auth_service
    auth.poll_result = outcome != "timeout"
    poll_gate = auth.gates["poll_for_token"] = asyncio.Event()
    if outcome == "start-error":
        auth.failures["start_device_flow"] = RuntimeError("fixture [literal] failure Ω")
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASES[1], app, pilot)
        await _click(pilot, "#btn_login")
        if outcome == "start-error":
            await wait_until(lambda: screen.query_one("#logged_out_container").display)
            assert any(message == "Login failed: fixture [literal] failure Ω" and kwargs.get("markup") is False for message, kwargs in app.notes)
            assert not any(name == "poll_for_token" for name, args in auth.calls)
            return
        await wait_until(lambda: any(name == "poll_for_token" for name, args in auth.calls))
        assert screen._polling and screen._device_code == "fixture-device-code"
        assert not screen.query_one("#login_actions").display
        assert "https://example.invalid/activate" in screen.query_one("#device_url", Static).render().plain
        await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert screen._polling
        await collapse_chat(app, pilot, screen)
        if outcome == "cancel":
            await _target(app, pilot, "#btn_cancel_login")
            await _click(pilot, "#btn_cancel_login")
            assert not screen._polling and screen._device_code is None
        poll_gate.set()
        await wait_until(lambda: "poll_for_token" in auth.finished)
        await wait_until(lambda: not screen._polling)
        await pilot.pause()
        assert app.screen is screen
        if outcome == "success":
            await wait_until(lambda: screen.query_one("#logged_in_container").display)
            app.init_paid_services.assert_called_once_with()
            app.on_user_login_success.assert_called_once_with()
        else:
            assert screen.query_one("#logged_out_container").display
            app.init_paid_services.assert_not_called()
            app.on_user_login_success.assert_not_called()
        assert [args for name, args in auth.calls if name == "poll_for_token"] == [{"device_code": "fixture-device-code", "interval": 1, "client_kind": "tui"}]


@pytest.mark.asyncio
@pytest.mark.parametrize("valid", [False, True])
async def test_login_optimistic_validation_finishes_after_reflow_without_extra_login(valid: bool) -> None:
    app = _AccessHost(False, state="in")
    auth = app.auth_service
    auth.valid = valid
    gate = auth.gates["validate_token"] = asyncio.Event()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASES[2], app, pilot)
        assert screen.query_one("#logged_in_container").display
        await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        gate.set()
        expected = "#logged_in_container" if valid else "#logged_out_container"
        await wait_until(lambda: screen.query_one(expected).display)
        await collapse_chat(app, pilot, screen)
        assert app.screen is screen and not screen._polling
        app.on_user_login_success.assert_not_called()
        assert [name for name, args in auth.calls].count("validate_token") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
async def test_login_native_logout_calls_only_fake_auth_and_preserves_failure_state(failure: bool) -> None:
    app = _AccessHost(False, state="in")
    auth = app.auth_service
    if failure:
        auth.failures["logout"] = RuntimeError("fixture logout failure Ω")
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await open_case(CASES[2], app, pilot)
        await _target(app, pilot, "#btn_logout")
        await _click(pilot, "#btn_logout")
        if failure:
            await wait_until(lambda: any(message == "Logout error: fixture logout failure Ω" and kwargs.get("markup") is False for message, kwargs in app.notes))
        else:
            await wait_until(lambda: screen.query_one("#logged_out_container").display)
        assert screen.query_one("#logged_in_container").display is failure
        assert screen.query_one("#logged_out_container").display is not failure
        assert app.on_user_logout.call_count == (0 if failure else 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("confirm", [False, True])
async def test_local_signout_native_typed_modal_preserves_origin_and_exact_result(confirm: bool) -> None:
    app = _AccessHost(False, state="in")
    auth = app.auth_service
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASES[2], app, pilot)
        await _click(pilot, "#btn_logout_local")
        await wait_until(lambda: isinstance(app.screen, ConfirmActionScreen))
        modal = app.screen

        def ready() -> bool:
            if app._exception is not None:
                raise app._exception
            if app.screen is not modal or not modal.is_mounted or not modal.is_attached:
                return False
            for selector, expected_type in (
                ("#confirm_input", Input), ("#btn_confirm", Button), ("#btn_cancel", Button),
            ):
                children = list(modal.query(selector))
                if len(children) != 1 or not isinstance(children[0], expected_type):
                    return False
                child = children[0]
                if not child.is_mounted or not child.is_attached:
                    return False
                if child.region.width <= 0 or child.region.height <= 0:
                    return False
            return (not modal._layout_required
                    and app.focused is modal.query_one("#confirm_input", Input))

        await wait_until(ready)
        if confirm:
            modal.query_one("#confirm_input", Input).value = "sign out"
            await wait_until(lambda: not modal.query_one("#btn_confirm", Button).disabled)
            await _pinned_local_signout_target(app, pilot, "#btn_confirm")
            await _click(pilot, "#btn_confirm")
        else:
            await _pinned_local_signout_target(app, pilot, "#btn_cancel")
            await _click(pilot, "#btn_cancel")
        await wait_until(lambda: app.screen is screen)
        assert [name for name, args in auth.calls].count("sign_out_locally") == int(confirm)
        assert not any(name == "logout" for name, args in auth.calls)
        assert app.on_user_logout.call_count == int(confirm)
        assert screen.query_one("#logged_out_container").display is confirm


@pytest.mark.asyncio
@pytest.mark.parametrize("return_to,entitled,expected", [(None, True, "login"), ("sync_config", False, "login"), ("sync_config", True, "config"), ("memory_sync", False, "memory")])
async def test_account_return_to_existing_entitlement_gate_and_destination(monkeypatch: pytest.MonkeyPatch, return_to: str | None, entitled: bool, expected: str) -> None:
    class _Destination(Screen):
        def __init__(self, kind: str) -> None:
            super().__init__()
            self.kind = kind

    monkeypatch.setattr("servonaut.screens.snapshot_manager.SnapshotManagerScreen", lambda: _Destination("config"))
    monkeypatch.setattr("servonaut.screens.memory_sync_setup.MemorySyncSetupScreen", lambda: _Destination("memory"))
    app = _AccessHost(False, state="in")
    app.auth_service.config_sync = entitled
    async with app.run_test(size=(100, 30)) as pilot:
        login = LoginScreen(return_to=return_to)
        await app.push_screen(login)
        await wait_until(lambda: app.screen is login or isinstance(app.screen, _Destination))
        await pilot.pause()
        assert (app.screen.kind if isinstance(app.screen, _Destination) else "login") == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_ca_real_enable_caller_retains_confirmation_and_reloads_selected_team(cancel: bool) -> None:
    app = _AccessHost(False)
    service = app.vault_command_service
    service.not_enabled.add("ops")
    service.allowed_actions.add("ca_enable")
    async with app.run_test(size=(160, 50)) as pilot:
        app._access_pilot = pilot
        screen = CaScreen()
        await app.push_screen(screen)
        await wait_until(lambda: screen._teams_listed)
        await wait_until(lambda: app.focused is screen.query_one("#ca_team", Select))
        screen.query_one("#ca_team", Select).value = "ops"
        await wait_until(lambda: screen.query_one("#ca_enable", Button).display and not screen.query_one("#ca_enable", Button).disabled)
        await _target(app, pilot, "#ca_enable")
        await _click(pilot, "#ca_enable")
        await wait_until(lambda: isinstance(app.screen, CaEnableConfirmModal)
                         and app.screen.is_mounted
                         and all(bool(app.screen.query(selector)) for selector in (
                             "#ca_enable_cancel", "#ca_enable_confirm",
                         )))
        assert service.calls_to("ca_enable") == []
        await _target(app, pilot, "#ca_enable_cancel" if cancel else "#ca_enable_confirm")
        await _click(pilot, "#ca_enable_cancel" if cancel else "#ca_enable_confirm")
        await wait_until(lambda: app.screen is screen and not screen._action_running)
        assert service.calls_to("ca_enable") == ([] if cancel else [{"team": "ops"}])
        assert screen.query_one("#ca_team", Select).value == "ops"


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_ca_real_enrollment_worker_keeps_target_and_modal_confirmation_result(cancel: bool) -> None:
    app = _AccessHost(False)
    service = app.vault_command_service
    confirmations: list[str] = []

    async def enroll(*, team: str, server: str, break_glass_item_id: str | None, confirmation: Callable[[Mapping[str, Any]], Awaitable[str]]) -> dict[str, object]:
        service.calls.append(("ca_enroll", {"team": team, "server": server, "break_glass_item_id": break_glass_item_id}))
        confirmations.append(await confirmation(_summary()))
        return {"result": {"status": "cancelled" if cancel else "succeeded", "steps": []}}

    service.ca_enroll = enroll
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASES[-1], app, pilot)
        screen.query_one("#ca_server", Select).value = "srv-web"
        screen.query_one("#ca_break_glass", Select).value = Select.NULL
        await wait_until(lambda: not screen.query_one("#ca_enroll", Button).disabled)
        await _target(app, pilot, "#ca_enroll")
        await _click(pilot, "#ca_enroll")
        await wait_until(lambda: isinstance(app.screen, CaEnrollmentConfirmModal)
                         and app.screen.is_mounted
                         and all(bool(app.screen.query(selector)) for selector in (
                             "#ca_confirm_host", "#ca_cancel", "#ca_confirm",
                         )))
        modal = app.screen
        assert screen._action_running and confirmations == []
        modal.query_one("#ca_confirm_host", Input).value = "  different host  "
        await _target(app, pilot, "#ca_cancel" if cancel else "#ca_confirm")
        await _click(pilot, "#ca_cancel" if cancel else "#ca_confirm")
        await wait_until(lambda: app.screen is screen and not screen._action_running)
        assert confirmations == ["" if cancel else "different host"]
        assert service.calls_to("ca_enroll") == [{"team": "ops", "server": "srv-web", "break_glass_item_id": None}]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
async def test_ca_held_picker_loading_failure_and_explicit_all_selection_are_distinct(failure: bool) -> None:
    app = _AccessHost(False)
    service = app.vault_command_service
    gate = service.gates["shared_server_choices"] = asyncio.Event()
    if failure:
        service.failures["shared_server_choices"] = RuntimeError("fixture picker failure Ω")
    async with app.run_test(size=(100, 30)) as pilot:
        app._access_pilot = pilot
        screen = CaScreen()
        await app.push_screen(screen)
        await wait_until(lambda: screen._teams_listed)
        screen.query_one("#ca_team", Select).value = "ops"
        await wait_until(lambda: screen._picker_state.get("ca_server") == "loading")
        busy = screen.query_one("#ca_busy")
        assert busy.is_active and "Loading" in busy.message
        assert screen.query_one("#ca_krl", Button).disabled
        assert screen.query_one("#ca_break_glass_scan", Button).disabled
        assert screen._chosen_servers() is None
        gate.set()
        await wait_until(lambda: screen._picker_state.get("ca_server") in {"ready", "failed"})
        await wait_until(lambda: not busy.is_active)
        if failure:
            assert screen._picker_state["ca_server"] == "failed"
            assert screen._chosen_servers() is None and screen.query_one("#ca_krl", Button).disabled
            hint = screen.query_one("#ca_hint", Static)
            assert "Could not load" in hint.render().plain
            await _target(app, pilot, "#ca_hint")
            assert "Could not load" in _painted(app, hint)
        else:
            from servonaut.screens.ca import _EVERY_ENROLLED_SERVER
            screen.query_one("#ca_server", Select).value = _EVERY_ENROLLED_SERVER
            assert screen._chosen_servers() == []
        assert service.calls_to("ca_deliver_krl") == []
        assert service.calls_to("ca_break_glass_scan") == []


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["passphrase-title", "account-email"])
async def test_access_original_raw_markup_leads_require_literal_painted_text(kind: str) -> None:
    # Desired literal output: run against exact originals before any escaping fix.
    app = _AccessHost(False, state="in")
    literal = "Name [bold]literal[/bold] café Ω"
    async with app.run_test(size=(160, 50)) as pilot:
        if kind == "passphrase-title":
            modal = PassphraseModal(title=literal)
            await app.push_screen(modal)
            target = modal.query_one("#passphrase_title", Static)
        else:
            app.auth_service._token.email = literal
            screen = LoginScreen()
            await app.push_screen(screen)
            target = screen.query_one("#account_info", Static)
        await pilot.pause()
        assert literal in target.render().plain
        target.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        assert literal in _painted(app, target)
