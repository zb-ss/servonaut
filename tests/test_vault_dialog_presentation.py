"""Vault dialogs retain literal results, masked fields and native caller state."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from collections.abc import Callable, Mapping
from typing import Any
from unittest.mock import ANY

import pytest
from textual.app import ComposeResult
from textual.geometry import Region
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Input, Select, SelectionList, Static, TextArea
from textual.widgets.text_area import Selection

from servonaut.screens.vault import (
    VaultAddDeviceModal, VaultCreateModal, VaultExposureActionModal,
    VaultImportedReferenceModal, VaultImportedTeamBindingModal,
    VaultMemberApprovalModal, VaultPendingDeviceModal,
    VaultRecoveryConfirmModal, VaultRevealModal, VaultSecretPromptModal,
    VaultSasConfirmModal,
)
from servonaut.screens.vault_auto_bind import AutoBindFetchConfirmModal, VaultAutoBindReviewModal
from servonaut.screens import vault_auto_bind
from servonaut.services.vault.auto_bind import AutoBindRow, FETCHED, KeyMatch
from servonaut.services.chat_service import ChatSession
from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogFrame, DialogNotificationSpace
from servonaut.widgets.secret_input import SecretInput
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import open_chat
from tests.test_workspace_vault_reflow import (
    HOST_KEY, RECOVERY_KEY, SIZES, _VaultHost, _VaultService, inert_services,
    stable_open,
)

pytestmark = pytest.mark.usefixtures("navigation_open")


@dataclass(frozen=True)
class _Case:
    name: str
    make: Callable[[_VaultService, bool], ModalScreen]
    cancel: str
    confirm: str
    expected: Any
    size: str = "standard"
    severity: str = "neutral"


def _review_rows(long: bool) -> list[AutoBindRow]:
    return [AutoBindRow(
        {"id": f"server-{index}", "name": f"web-{index}"}, FETCHED,
        match=KeyMatch("key-1", "Example key", "server name"),
        host="10.0.0.1", login="deploy", host_keys=[HOST_KEY],
        verification_source="Read from an example server; not verified",
    ) for index in range(40 if long else 1)]


def _references(long: bool = False) -> list[dict[str, str]]:
    return [{"vault_item_id": f"key-{index}", "source_ref": f"reference-{index}",
             "name": f"Example key {index} [/b] Ω", "fingerprint": "SHA256:example"}
            for index in range(100 if long else 2)]


CASES = (
    _Case("reveal", lambda service, long: VaultRevealModal({"plaintext": {"value":
          "example-secret[/b]Ω\n" * (80 if long else 1)}}), "vault_reveal_close", "vault_reveal_close", None, "large"),
    _Case("secret", lambda service, long: VaultSecretPromptModal("Enter example recovery key",
          "Record the example instructions.\n" * (80 if long else 1)),
          "vault_secret_cancel", "vault_secret_continue", "  example-secret[/b]Ω  "),
    _Case("recovery", lambda service, long: VaultRecoveryConfirmModal(
          "-".join(["SVRK1"] + ["ABCD"] * 90) if long else RECOVERY_KEY),
          "vault_recovery_cancel", "vault_recovery_confirm", True, "large"),
    _Case("sas", lambda service, long: VaultSasConfirmModal("1234 5678\n" * (80 if long else 1)),
          "vault_sas_no", "vault_sas_yes", True),
    _Case("member", lambda service, long: VaultMemberApprovalModal(
          {"display_name": "Example member " * (100 if long else 1), "role": "member"},
          "1234 5678", True), "vault_member_skip", "vault_member_approve", True, "large"),
    # Keep overflow copy taller than the standard frame even on tall terminals.
    _Case("pending", lambda service, long: VaultPendingDeviceModal(
          {"device_name": "Example computer " * (200 if long else 1), "platform": "Example OS"}),
          "vault_pending_device_later", "vault_pending_device_review", True),
    _Case("exposure", lambda service, long: VaultExposureActionModal(rotation=False),
          "vault_exposure_cancel", "vault_exposure_confirm", {"resolution": "rotated", "note": "Example note"}),
    _Case("reference", lambda service, long: VaultImportedReferenceModal(_references(long)),
          "vault_import_bind_cancel", "vault_import_bind_continue", _references()[0], "large"),
    _Case("team-binding", lambda service, long: VaultImportedTeamBindingModal(service),
          "vault_import_bind_target_cancel", "vault_import_bind_target_continue",
          {"team": "example", "server_id": "server-1", "login": "deploy"}, "large"),
    _Case("create", lambda service, long: VaultCreateModal([{"team": None, "label": "Personal example"}]),
          "vault_create_cancel", "vault_create_confirm", {"team": None, "label": "Personal example"}),
    _Case("add-device", lambda service, long: VaultAddDeviceModal(
          "Example computer " * (100 if long else 1), key_file_missing=False),
          "vault_add_device_cancel", "vault_add_device_start", "start", "large"),
    _Case("fetch", lambda service, long: AutoBindFetchConfirmModal(
          "Read example host keys without trusting them.\n" * (80 if long else 1)),
          "auto_bind_confirm_no", "auto_bind_confirm_yes", True, severity="warning"),
    _Case("review", lambda service, long: VaultAutoBindReviewModal(
          _review_rows(long), server_name_fn=lambda row: str(row.instance["name"]), scrub_fn=str,
          team="example", team_name="Example team"),
          "vault_auto_bind_review_cancel", "vault_auto_bind_review_confirm", True, "large"),
)

# Populate only from a separate hash-qualified original native run. Missing
# records fail closed rather than choosing a new focus or Escape contract.
ORIGINAL_BASELINES: dict[tuple[str, tuple[int, int]], Mapping[str, Any]] = {
    ('reveal', (100, 30)): {
        'focused_id': 'vault_reveal_close',
        'stays_open': False,
        'results': [None],
    },
    ('reveal', (160, 50)): {
        'focused_id': 'vault_reveal_close',
        'stays_open': False,
        'results': [None],
    },
    ('secret', (100, 30)): {
        'focused_id': 'vault_secret_input',
        'stays_open': True,
        'results': [],
    },
    ('secret', (160, 50)): {
        'focused_id': 'vault_secret_input',
        'stays_open': True,
        'results': [],
    },
    ('recovery', (100, 30)): {
        'focused_id': 'vault_recovery_group_6',
        'stays_open': True,
        'results': [],
    },
    ('recovery', (160, 50)): {
        'focused_id': 'vault_recovery_group_1',
        'stays_open': True,
        'results': [],
    },
    ('sas', (100, 30)): {
        'focused_id': 'vault_sas_no',
        'stays_open': True,
        'results': [],
    },
    ('sas', (160, 50)): {
        'focused_id': 'vault_sas_no',
        'stays_open': True,
        'results': [],
    },
    ('member', (100, 30)): {
        'focused_id': 'vault_member_skip',
        'stays_open': False,
        'results': [False],
    },
    ('member', (160, 50)): {
        'focused_id': 'vault_member_skip',
        'stays_open': False,
        'results': [False],
    },
    ('pending', (100, 30)): {
        'focused_id': 'vault_pending_device_later',
        'stays_open': True,
        'results': [],
    },
    ('pending', (160, 50)): {
        'focused_id': 'vault_pending_device_later',
        'stays_open': True,
        'results': [],
    },
    ('exposure', (100, 30)): {
        'focused_id': 'vault_exposure_resolution',
        'stays_open': False,
        'results': [None],
    },
    ('exposure', (160, 50)): {
        'focused_id': 'vault_exposure_resolution',
        'stays_open': False,
        'results': [None],
    },
    ('reference', (100, 30)): {
        'focused_id': 'vault_import_bind_list',
        'stays_open': True,
        'results': [],
    },
    ('reference', (160, 50)): {
        'focused_id': 'vault_import_bind_list',
        'stays_open': True,
        'results': [],
    },
    ('team-binding', (100, 30)): {
        'focused_id': 'vault_import_bind_server',
        'stays_open': False,
        'results': [None],
    },
    ('team-binding', (160, 50)): {
        'focused_id': 'vault_import_bind_server',
        'stays_open': False,
        'results': [None],
    },
    ('create', (100, 30)): {
        'focused_id': 'vault_create_target',
        'stays_open': True,
        'results': [],
    },
    ('create', (160, 50)): {
        'focused_id': 'vault_create_target',
        'stays_open': True,
        'results': [],
    },
    ('add-device', (100, 30)): {
        'focused_id': 'vault_add_device_start',
        'stays_open': False,
        'results': [None],
    },
    ('add-device', (160, 50)): {
        'focused_id': 'vault_add_device_start',
        'stays_open': False,
        'results': [None],
    },
    ('fetch', (100, 30)): {
        'focused_id': 'auto_bind_confirm_no',
        'stays_open': False,
        'results': [False],
    },
    ('fetch', (160, 50)): {
        'focused_id': 'auto_bind_confirm_no',
        'stays_open': False,
        'results': [False],
    },
    ('review', (100, 30)): {
        'focused_id': 'auto_bind_review_scroll',
        'stays_open': False,
        'results': [False],
    },
    ('review', (160, 50)): {
        'focused_id': 'auto_bind_review_scroll',
        'stays_open': False,
        'results': [False],
    },
}


def _painted(app: _VaultHost, widget: Any) -> str:
    strips = app.screen._compositor.render_strips()
    return "\n".join(strips[y].crop(max(0, widget.region.x), min(app.size.width, widget.region.right)).text
                     for y in range(max(0, widget.region.y), min(app.size.height, widget.region.bottom)))


def _exposed(app: _VaultHost, widget: Any) -> None:
    frame = app.screen.query_one(DialogFrame)
    assert widget.region.area and frame.content_region.contains_region(widget.region)
    assert app.screen.region.contains_region(widget.region)
    for y in range(widget.region.y, widget.region.bottom):
        for x in range(widget.region.x, widget.region.right):
            hit = app.get_widget_at(x, y)[0]
            assert hit is widget or widget in hit.ancestors
    if isinstance(widget, Button):
        assert widget.label.plain in _painted(app, widget)
    if isinstance(widget, (Input, Checkbox)):
        native = widget.render_lines(Region(0, 0, *widget.region.size))
        assert _painted(app, widget) == "\n".join(strip.text for strip in native)
    if isinstance(widget, Input) and widget.value and not widget.password:
        assert widget.value in _painted(app, widget)
    if isinstance(widget, Checkbox):
        assert " ".join(widget.label.plain.split()) in " ".join(_painted(app, widget).split())


async def _push(app: _VaultHost, modal: ModalScreen, results: list[Any]) -> None:
    await app.push_screen(modal, callback=results.append)
    await wait_until(lambda: app.screen is modal)
    if isinstance(modal, VaultImportedTeamBindingModal):
        await wait_until(lambda: not modal.query_one("#vault_import_bind_target_continue", Button).disabled)


def _critical_fields(modal: ModalScreen) -> list[Any]:
    fields = list(modal.query(Input))
    fields += list(modal.query(Select))
    fields += list(modal.query(SelectionList))
    fields += list(modal.query(Checkbox))
    fields += list(modal.query(".secret-reveal"))
    if modal.query("#vault_member_sas"):
        fields.append(modal.query_one("#vault_member_sas", Static))
    return fields


async def _fill(app: _VaultHost, pilot: Any, case: _Case, modal: ModalScreen) -> None:
    if case.name == "secret":
        modal.query_one("#vault_secret_input", Input).value = case.expected
    elif case.name == "recovery":
        for index in modal._checks:
            modal.query_one(f"#vault_recovery_group_{index}", Input).value = modal._groups[index].lower()
    elif case.name == "exposure":
        resolution = modal.query_one("#vault_exposure_resolution", Select)
        resolution.focus()
        await pilot.press("enter", "home", "down", "enter")
        await wait_until(lambda: resolution.value == "rotated")
        modal.query_one("#vault_exposure_note", Input).value = " Example note "
    elif case.name == "team-binding":
        modal.query_one("#vault_import_bind_login", Input).value = " deploy "
    elif case.name == "review":
        checkbox = modal.query_one("#vault_auto_bind_review_use_trusted", Checkbox)
        assert not checkbox.value and modal.query_one("#vault_auto_bind_review_confirm", Button).disabled
        _exposed(app, checkbox)
        assert await pilot.click(checkbox)
    await pilot.pause()


class _ReferenceFrame(ModalScreen):
    DEFAULT_CLASSES = "dialog-screen"

    def __init__(self, case: _Case) -> None:
        super().__init__()
        self._case = case

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(heading=Static("Example frame"), body=DialogBody(Static("Example copy")),
                          actions=DialogActions(Button("Cancel")), size=self._case.size,
                          severity=self._case.severity)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("accept", [False, True])
async def test_vault_modal_literal_results_resume_native_caller(case: _Case, size: tuple[int, int], accept: bool) -> None:
    app = _VaultHost(False)
    async with app.run_test(size=size) as pilot:
        origin = await stable_open(app, "vault")
        origin.query_one("#vault_table", DataTable).focus()
        modal = case.make(app.vault_command_service, False)
        results: list[Any] = []
        await _push(app, modal, results)
        await pilot.pause()
        if accept:
            await _fill(app, pilot, case, modal)
        for field in _critical_fields(modal):
            _exposed(app, field)
        for button in modal.query_one(DialogActions).query(Button):
            _exposed(app, button)
        button = modal.query_one("#" + (case.confirm if accept else case.cancel), Button)
        assert not button.disabled
        assert await pilot.click(button)
        await wait_until(lambda: len(results) == 1 and app.screen is origin)
        expected = case.expected if accept else (False if case.name in {"recovery", "sas", "member", "pending", "fetch", "review"} else None)
        assert results == [expected]
        if case.name == "team-binding":
            app.vault_command_service.team_choices.assert_awaited_once_with()
            app.vault_command_service.shared_server_choices.assert_awaited_once_with(team="example")
        assert not app.vault_command_service.operations
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
@pytest.mark.parametrize("size", SIZES)
async def test_vault_original_focus_and_escape_contract(case: _Case, size: tuple[int, int]) -> None:
    assert (case.name, size) in ORIGINAL_BASELINES, "Qualify this original native focus/Escape record before adoption acceptance"
    baseline = ORIGINAL_BASELINES[case.name, size]
    app = _VaultHost(False)
    async with app.run_test(size=size) as pilot:
        origin = await stable_open(app, "vault")
        results: list[Any] = []
        modal = case.make(app.vault_command_service, False)
        await _push(app, modal, results)
        await pilot.pause()
        if case.name == "recovery":
            # Recovery group IDs vary with each random challenge; retain its first-field focus role.
            assert isinstance(baseline["focused_id"], str)
            assert baseline["focused_id"].startswith("vault_recovery_group_")
            assert app.focused is modal.query_one(
                f"#vault_recovery_group_{modal._checks[0]}", Input,
            )
        else:
            assert getattr(app.focused, "id", None) == baseline["focused_id"]
        await pilot.press("escape")
        await pilot.pause()
        assert (app.screen is modal) is baseline["stays_open"]
        assert results == baseline["results"]
        if app.screen is modal:
            assert await pilot.click(modal.query_one("#" + case.cancel, Button))
        await wait_until(lambda: app.screen is origin)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
async def test_vault_frames_use_native_role_geometry_without_outer_scroll(case: _Case) -> None:
    app = _VaultHost(False)
    async with app.run_test(size=(100, 30)) as pilot:
        await stable_open(app, "vault")
        results: list[Any] = []
        modal = case.make(app.vault_command_service, False)
        await _push(app, modal, results)
        await pilot.pause()
        frame = modal.query_one(DialogFrame)
        assert frame.max_scroll_y == 0 and modal.region.contains_region(frame.region)
        names = ("height", "max_height", "padding", "border_top", "border_right",
                 "border_bottom", "border_left", "overflow_x", "overflow_y")
        if case.name != "secret":
            names += ("width", "max_width")
        actual = {name: getattr(frame.styles, name) for name in names}
        assert await pilot.click(modal.query_one("#" + case.cancel, Button))
        await wait_until(lambda: app.screen is not modal)
        reference = _ReferenceFrame(case)
        await app.push_screen(reference)
        await pilot.pause()
        native = reference.query_one(DialogFrame)
        assert actual == {name: getattr(native.styles, name) for name in names}
        app.pop_screen()


LONG_NAMES = {"reveal", "secret", "recovery", "sas", "member", "pending", "add-device", "fetch", "review"}


@pytest.mark.asyncio
@pytest.mark.parametrize("case", [case for case in CASES if case.name in LONG_NAMES], ids=lambda case: case.name)
@pytest.mark.parametrize("size", SIZES)
async def test_long_vault_copy_has_one_scroller_and_stationary_pinned_controls(case: _Case, size: tuple[int, int]) -> None:
    app = _VaultHost(False)
    async with app.run_test(size=size) as pilot:
        await stable_open(app, "vault")
        results: list[Any] = []
        modal = case.make(app.vault_command_service, True)
        await _push(app, modal, results)
        await pilot.pause()
        frame, body = modal.query_one(DialogFrame), modal.query_one(DialogBody)
        await wait_until(lambda: body.max_scroll_y > 0)
        assert frame.max_scroll_y == 0
        assert [widget for widget in frame.walk_children() if widget.allow_vertical_scroll and widget.max_scroll_y > 0] == [body]
        pinned = list(modal.query_one(DialogActions).query(Button))
        pinned += list(frame.query("Input.dialog-status, Checkbox.dialog-status, .dialog-status Input, .dialog-status Checkbox, .dialog-status .secret-reveal, .dialog-status #vault_member_sas"))
        positions = [widget.region for widget in pinned]
        for widget in pinned:
            _exposed(app, widget)
        body.focus()
        await pilot.press("end")
        await pilot.pause()
        assert body.scroll_y > 0 and [widget.region for widget in pinned] == positions
        for index in range(3):
            app.notify(f"Example notice {index + 1}", timeout=60)
        await pilot.pause()
        assert [widget.region for widget in pinned] == positions
        for widget in pinned:
            _exposed(app, widget)
        assert await pilot.click(modal.query_one("#" + case.cancel, Button))
        await wait_until(lambda: len(results) == 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_reference_list_owns_its_scrolling_and_actions_remain_visible(size: tuple[int, int]) -> None:
    app = _VaultHost(False)
    async with app.run_test(size=size) as pilot:
        await stable_open(app, "vault")
        modal = VaultImportedReferenceModal(_references(True))
        await app.push_screen(modal)
        await pilot.pause()
        listing = modal.query_one("#vault_import_bind_list", SelectionList)
        frame = modal.query_one(DialogFrame)
        assert listing.max_scroll_y > 0 and frame.max_scroll_y == 0
        assert not modal.query(DialogBody)
        for button in modal.query_one(DialogActions).query(Button):
            _exposed(app, button)
        listing.focus()
        await pilot.press("end")
        await pilot.pause()
        assert listing.scroll_y > 0


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_secret_mask_reveal_and_copy_keep_value_and_actions_together(size: tuple[int, int]) -> None:
    app = _VaultHost(False)
    async with app.run_test(size=size) as pilot:
        await stable_open(app, "vault")
        modal = VaultSecretPromptModal("Example recovery", "Keep the synthetic key offline.")
        await app.push_screen(modal)
        await pilot.pause()
        field = modal.query_one("#vault_secret_input", Input)
        secret = modal.query_one(SecretInput)
        field.value = RECOVERY_KEY
        await pilot.pause()
        assert len(RECOVERY_KEY) == 71 and field.password
        assert RECOVERY_KEY not in _painted(app, modal.query_one(DialogFrame))
        await pilot.press("ctrl+r")
        await pilot.pause()
        assert not field.password and field.value == RECOVERY_KEY
        assert RECOVERY_KEY in _painted(app, field)
        for widget in (field, secret.query_one(".secret-reveal", Button),
                       modal.query_one("#vault_secret_cancel"), modal.query_one("#vault_secret_continue")):
            _exposed(app, widget)
        await pilot.press("ctrl+shift+a", "ctrl+c")
        app.copied.assert_called_with(RECOVERY_KEY)
        assert field.value == RECOVERY_KEY
        app.demo_mode = True
        secret.refresh_after_demo_toggle()
        await pilot.press("ctrl+r")
        await pilot.pause()
        assert field.password and RECOVERY_KEY not in _painted(app, field)


@pytest.mark.asyncio
async def test_picker_loading_error_and_disabled_confirmation_keep_pinned_login_visible() -> None:
    app = _VaultHost(False)
    service = app.vault_command_service
    service.teams_release.clear()
    service.server_error = RuntimeError("Example unavailable servers")
    async with app.run_test(size=(100, 30)) as pilot:
        await stable_open(app, "vault")
        modal = VaultImportedTeamBindingModal(service)
        await app.push_screen(modal)
        await wait_until(service.teams_entered.is_set)
        await pilot.pause()
        confirm = modal.query_one("#vault_import_bind_target_continue", Button)
        assert confirm.disabled
        for selector in ("#vault_import_bind_login", "#vault_import_bind_target_cancel", "#vault_import_bind_target_continue"):
            _exposed(app, modal.query_one(selector))
        service.teams_release.set()
        message = modal.query_one("#vault_import_bind_message", Static)
        await wait_until(lambda: "Could not load" in message.render().plain)
        assert confirm.disabled and not service.operations
        app.notify("Example picker failure", severity="error", timeout=60)
        await pilot.pause()
        for selector in ("#vault_import_bind_login", "#vault_import_bind_target_cancel", "#vault_import_bind_target_continue"):
            _exposed(app, modal.query_one(selector))


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_rotation_picker_returns_exact_team_and_server_ids(size: tuple[int, int]) -> None:
    app = _VaultHost(False)
    async with app.run_test(size=size) as pilot:
        await stable_open(app, "vault")
        modal = VaultExposureActionModal(rotation=True, service=app.vault_command_service)
        results: list[Any] = []
        await _push(app, modal, results)
        await wait_until(lambda: not modal.query_one("#vault_exposure_confirm", Button).disabled)
        await pilot.pause()
        for widget in _critical_fields(modal):
            _exposed(app, widget)
        assert await pilot.click(modal.query_one("#vault_exposure_confirm", Button))
        await wait_until(lambda: len(results) == 1)
        assert results == [{"team": "example", "servers": "server-1"}]
        app.vault_command_service.team_choices.assert_awaited_once_with()
        app.vault_command_service.shared_server_choices.assert_awaited_once_with(team="example")
        assert not app.vault_command_service.operations


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("kind", ["secret", "recovery"])
async def test_empty_secret_and_unmatched_recovery_keep_original_results(kind: str, size: tuple[int, int]) -> None:
    case = next(case for case in CASES if case.name == kind)
    app = _VaultHost(False)
    async with app.run_test(size=size) as pilot:
        await stable_open(app, "vault")
        results: list[Any] = []
        modal = case.make(app.vault_command_service, False)
        await _push(app, modal, results)
        await pilot.pause()
        assert await pilot.click(modal.query_one("#" + case.confirm, Button))
        await wait_until(lambda: len(results) == 1)
        assert results == ([None] if kind == "secret" else [False])


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_missing_device_key_keeps_recover_focus_and_result(size: tuple[int, int]) -> None:
    app = _VaultHost(False)
    async with app.run_test(size=size) as pilot:
        await stable_open(app, "vault")
        modal = VaultAddDeviceModal("Example computer", key_file_missing=True)
        results: list[Any] = []
        await _push(app, modal, results)
        await pilot.pause()
        recover = modal.query_one("#vault_add_device_recover", Button)
        assert app.focused is recover
        for button in modal.query_one(DialogActions).query(Button):
            _exposed(app, button)
        assert await pilot.click(recover)
        await wait_until(lambda: len(results) == 1)
        assert results == ["recover"] and not app.vault_command_service.operations


@pytest.mark.asyncio
async def test_explicit_reveal_stays_literal_under_the_existing_demo_contract() -> None:
    app = _VaultHost(False)
    async with app.run_test(size=(100, 30)) as pilot:
        await stable_open(app, "vault")
        app.demo_mode = True
        from types import SimpleNamespace
        app.redaction_service = SimpleNamespace(scrub_stream=lambda value: "Example scrubbed metadata")
        modal = VaultRevealModal({"plaintext": {"value": "example-secret[/b]Ω"}})
        await app.push_screen(modal)
        await pilot.pause()
        assert "example-secret[/b]Ω" in _painted(app, modal.query_one("#vault_revealed_value", Static))


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["create", "recover", "recovery", "sas", "member", "fetch", "add-device", "typed-reveal"])
async def test_native_vault_callers_resume_after_safe_cancellation(route: str) -> None:
    app = _VaultHost(False)
    async with app.run_test(size=(160, 50)) as pilot:
        origin = await stable_open(app, "auto" if route == "fetch" else "vault")
        service = app.vault_command_service
        panel = await open_chat(app, pilot, origin)
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Keep the example draft Ω")
        editor.selection = Selection((0, 0), (0, 4))
        document, selection = editor.document, editor.selection
        session = panel._session = ChatSession()
        started, release, cancelled = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def held_reply() -> None:
            started.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        worker = panel.run_worker(held_reply(), group="ai_chat")
        await wait_until(started.is_set)

        async def press_source(selector: str) -> None:
            from textual.widgets import Collapsible

            async def click_visible(widget: Any, caption: str) -> None:
                widget.scroll_visible(animate=False, immediate=True)
                await pilot.pause()
                await pilot.wait_for_scheduled_animations()
                await wait_until(lambda: (
                    widget.region.area > 0
                    and origin.region.contains_region(widget.region)
                    and " ".join(caption.split()) in " ".join(_painted(app, widget).split())
                ))
                assert origin.region.contains_region(widget.region)
                assert " ".join(caption.split()) in " ".join(_painted(app, widget).split())
                center_x, center_y = widget.content_region.center
                hit = app.get_widget_at(center_x, center_y)[0]
                assert hit is widget or widget in hit.ancestors
                offset = (center_x - widget.region.x, center_y - widget.region.y)
                assert await pilot.click(widget, offset=offset)

            button = origin.query_one(selector, Button)
            section = next((owner for owner in button.ancestors if isinstance(owner, Collapsible)), None)
            if section is not None and section.collapsed:
                await click_visible(section.query_one("CollapsibleTitle"), section.title)
                await wait_until(lambda: not section.collapsed)
            assert not button.disabled
            await click_visible(button, button.label.plain)

        if route == "create":
            await press_source("#vault_create")
            modal_type, cancel = VaultCreateModal, "vault_create_cancel"
        elif route == "recover":
            service.local = None
            await press_source("#vault_refresh")
            await wait_until(lambda: origin._identity_state == "remote_identity" and not origin._busy_work)
            await press_source("#vault_recover")
            modal_type, cancel = VaultSecretPromptModal, "vault_secret_cancel"
        elif route == "recovery":
            await press_source("#vault_recovery_rotate")
            modal_type, cancel = VaultRecoveryConfirmModal, "vault_recovery_cancel"
        elif route == "sas":
            await press_source("#vault_devices")
            await wait_until(lambda: origin._table_mode == "devices" and not origin._busy_work)
            await press_source("#vault_approve")
            modal_type, cancel = VaultSasConfirmModal, "vault_sas_no"
        elif route == "member":
            await press_source("#vault_grants")
            modal_type, cancel = VaultMemberApprovalModal, "vault_member_skip"
        elif route == "fetch":
            from servonaut.services.vault.auto_bind import NO_HOST_KEYS
            service.need_host_keys = True
            origin.query_one("#auto_bind_table", DataTable).focus()
            await pilot.press("r")
            await wait_until(lambda: not origin._busy.is_busy and all(row.status == NO_HOST_KEYS for row in origin._rows))
            await press_source("#auto_bind_fetch_keys")
            modal_type, cancel = AutoBindFetchConfirmModal, "auto_bind_confirm_no"
        elif route == "add-device":
            service.local = None
            await press_source("#vault_refresh")
            await wait_until(lambda: origin._identity_state == "remote_identity" and not origin._busy_work)
            await press_source("#vault_add_device")
            modal_type, cancel = VaultAddDeviceModal, "vault_add_device_cancel"
        else:
            from servonaut.screens.confirm_action import ConfirmActionScreen
            await press_source("#vault_items")
            await wait_until(lambda: origin._table_mode == "items" and not origin._busy_work)
            await press_source("#vault_reveal")
            modal_type, cancel = ConfirmActionScreen, None
        await wait_until(lambda: isinstance(app.screen, modal_type))
        await pilot.pause()
        if cancel is None:
            await pilot.press("escape")
        else:
            assert await pilot.click(app.screen.query_one("#" + cancel, Button))
        await wait_until(lambda: app.screen is origin)
        await wait_until(lambda: not any(worker.node is origin and not worker.is_finished for worker in app.workers))
        if route == "create":
            service.creatable_vaults.assert_awaited_once_with(vaults=service.vaults)
            service.create_vault.assert_not_called()
        elif route == "recover":
            service.recover.assert_not_called()
        elif route == "recovery":
            service.rotate_recovery_key.assert_awaited_once_with(recovery_confirmation=ANY)
            assert callable(service.rotate_recovery_key.call_args.kwargs["recovery_confirmation"])
            assert service.results == [("recovery", False)]
        elif route == "sas":
            service.approve_device.assert_awaited_once_with(device_id="device-1", confirmation=ANY)
            assert callable(service.approve_device.call_args.kwargs["confirmation"])
            assert service.results == [("sas", False)]
        elif route == "member":
            service.process_grants.assert_awaited_once_with(vault_id="vault-1", approval=ANY)
            assert callable(service.process_grants.call_args.kwargs["approval"])
            assert service.results == [("member", False)]
        elif route == "fetch":
            vault_auto_bind.fetch_host_keys_for_rows.assert_not_called()
        elif route == "add-device":
            service.default_device_name.assert_called_once_with()
        else:
            service.list_items.assert_awaited_once_with(vault_id="vault-1")
            service.ssh_key_choices.assert_awaited_once_with(vault_id="vault-1", name_limit=None)
            service.show_item.assert_not_called()
        assert panel.is_attached and panel._session is session
        assert editor.document is document and editor.selection == selection
        assert editor.text == "Keep the example draft Ω"
        assert not worker.is_finished and not cancelled.is_set()
        assert not service.operations and app._exception is None
        release.set()
        await worker.wait()
