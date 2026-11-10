"""Native presentation of server-key consent dialogs, with inert service boundaries."""
from __future__ import annotations

import asyncio
import socket
import subprocess
import webbrowser
from collections.abc import Iterator
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.pilot import Pilot
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Input, OptionList, Select, Static
from textual.widgets._toast import Toast

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens import server_actions
from servonaut.screens.server_actions import (
    ConfirmSshVerifyModal, OwnKeyUpdateModal, VaultBindingModal, VaultBindingScopeModal,
)
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogFrame, DialogNotificationSpace
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import tab_to
from tests.test_navigation_dialog_contrast import _assert_readable, _painted_text_styles

pytestmark = pytest.mark.usefixtures("navigation_open")

SIZES = ((160, 50), (100, 30))
THEMES = ("servonaut", "servonaut-light", "ansi-dark", "ansi-light")
KINDS = ("scope", "own", "verify-ref", "binding")
FOCUS_KINDS = (*KINDS, "verify-no-ref", "verify-vault")
VAULT_ID, ITEM_ID = "fixture-vault", "fixture-key"
# A public-only fixture. The modal returns this text; binding is owned by its caller.
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
# Deterministic public-only wire-format fixtures; no private key or key generation.
TRUSTED_KEYS = ('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEA')
TRUSTED_FINGERPRINTS = ('SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA', 'SHA256:oIVTIburEfZKUwOmv9YkLGMk4rLhYLrW27NcxmLbxTU')
ROW = {"id": "i-0123456789abcdef0", "name": "web-1", "public_ip": "192.0.2.10", "username": "operator", "port": 22}
# Original native focus must be observed under the same host before any pinning.
ORIGINAL_NATIVE_FOCUS: dict[tuple[str, tuple[int, int]], str | None] | None = {
    ('scope', (100, 30)): 'vault_scope_choices',
    ('scope', (160, 50)): 'vault_scope_choices',
    ('own', (100, 30)): 'own_key_keep',
    ('own', (160, 50)): 'own_key_keep',
    ('verify-ref', (100, 30)): 'btn_ssh_verify_cancel',
    ('verify-ref', (160, 50)): 'btn_ssh_verify_cancel',
    ('binding', (100, 30)): 'vault_bind_item',
    ('binding', (160, 50)): 'vault_bind_item',
    ('verify-no-ref', (100, 30)): 'btn_ssh_verify_cancel',
    ('verify-no-ref', (160, 50)): 'btn_ssh_verify_cancel',
    ('verify-vault', (100, 30)): 'btn_ssh_verify_cancel',
    ('verify-vault', (160, 50)): 'btn_ssh_verify_cancel',
}
_HOSTS: list[_Host] = []


class _Gate:
    def __init__(self) -> None:
        self.entered, self.release = asyncio.Event(), asyncio.Event()

    async def wait(self) -> None:
        self.entered.set()
        await self.release.wait()


class _Service:
    """Only the actual modal read/fetch surface; no real vault or SSH service."""
    def __init__(self) -> None:
        self.gates: dict[str, _Gate] = {}
        self.reads: list[tuple[str, object]] = []
        self.visits: list[tuple[dict, str | None]] = []
        self.fail_keys = False
        self.vault_label = "Example vault"
        self.key_label = "Example key · SHA256:fixture"
        self.bind = AsyncMock(side_effect=AssertionError("Unexpected binding mutation"))
        self.bind_personal = AsyncMock(side_effect=AssertionError("Unexpected personal mutation"))
        self.personal_binding = AsyncMock(side_effect=AssertionError("Unexpected binding lookup"))

    async def _wait(self, name: str) -> None:
        if name in self.gates:
            await self.gates[name].wait()

    async def vault_choices(self, *, team: str | None = None) -> list[dict]:
        self.reads.append(("vaults", team))
        await self._wait("vaults")
        return [{"vault_id": VAULT_ID, "label": self.vault_label, "kind": "team" if team else "personal"}]

    async def ssh_key_choices(self, *, vault_id: str) -> list[dict]:
        self.reads.append(("keys", vault_id))
        await self._wait("keys")
        if self.fail_keys:
            raise RuntimeError("Fixture key list unavailable")
        return [{"item_id": ITEM_ID, "label": self.key_label}]

    def ssh_login(self, instance: dict) -> str:
        return str(instance.get("username") or "operator")

    def ssh_destination(self, instance: dict) -> tuple[str, int]:
        return str(instance["public_ip"]), int(instance["port"])

    def records_new_host_keys(self) -> bool:
        return True

    async def visit_for_host_key(self, instance: dict, *, login: str | None = None) -> str:
        self.visits.append((dict(instance), login))
        await self._wait("visit")
        return "Fixture connection refused"


class _Landing(Screen):
    def compose(self) -> ComposeResult:
        yield Input(id="origin")


class _FrameReference(ModalScreen):
    """Same accepted primitive and size, without a consumer's legacy IDs."""
    DEFAULT_CLASSES = "dialog-screen"
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def __init__(self, kind: str) -> None:
        super().__init__()
        self.frame_size = "large" if kind == "binding" else "standard"

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static("Reference"), body=DialogBody(Static("Reference")),
            actions=DialogActions(Button("Cancel")), size=self.frame_size,
        )

    def action_cancel(self) -> None:
        self.dismiss(None)


class _Host(ServonautApp):
    """Real app key/demo dispatch over an inert landing and actual modal callbacks."""
    def __init__(self) -> None:
        super().__init__()
        self.theme = "servonaut"
        self.animation_level = "none"
        self.instances = [dict(ROW)]
        config = AppConfig()

        def update_theme(*, theme: str) -> AppConfig:
            config.theme = theme
            return config

        self.config_manager = SimpleNamespace(get=lambda: config, update=update_theme)
        self.results: list[object] = []
        self.service = _Service()
        self.landing = _Landing()
        _HOSTS.append(self)

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        # Above the default screen: app.pop_screen's root navigation override
        # must not substitute a fleet for the modal's real callback/focus route.
        self.push_screen(self.landing)

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()


@pytest.fixture(autouse=True)
def _inert_boundaries(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    _HOSTS.clear()
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr(server_actions, "trusted_host_keys", lambda *args: [])
    process = Mock(side_effect=AssertionError("Unexpected process"))
    network = Mock(side_effect=AssertionError("Unexpected network"))
    async_network = AsyncMock(side_effect=AssertionError("Unexpected async boundary"))
    credentials = Mock(side_effect=AssertionError("Unexpected credential store"))
    monkeypatch.setattr(subprocess, "run", process)
    monkeypatch.setattr(subprocess, "Popen", process)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", async_network)
    monkeypatch.setattr(socket, "create_connection", network)
    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", async_network)
    monkeypatch.setattr(webbrowser, "open", network)
    for name in ("get_password", "set_password", "delete_password"):
        monkeypatch.setattr("keyring." + name, credentials)
    yield
    for app in _HOSTS:
        for gate in app.service.gates.values():
            gate.release.set()
        app.service.bind.assert_not_awaited()
        app.service.bind_personal.assert_not_awaited()
        app.service.personal_binding.assert_not_awaited()
        assert app.service.visits == []
    for tripwire in (process, network, async_network, credentials):
        tripwire.assert_not_called()


def _make(app: _Host, kind: str, *, long: bool = False) -> ModalScreen:
    if kind == "scope":
        return VaultBindingScopeModal([
            {"team_slug": f"team-{index}", "team_name": f"Example team {index}", "team_role": "admin"}
            for index in range(30 if long else 2)
        ])
    if kind == "own":
        text = "\n".join(["Keep operator[/b] on this example server until you explicitly update."] * (50 if long else 1))
        return OwnKeyUpdateModal(text)
    if kind.startswith("verify"):
        return ConfirmSshVerifyModal("web[/b].example.test", kind == "verify-ref", vault=kind == "verify-vault")
    return VaultBindingModal(app.service, dict(ROW))


async def _open(app: _Host, pilot: Pilot, kind: str, *, long: bool = False) -> ModalScreen:
    await wait_until(lambda: app.screen is app.landing)
    origin = app.landing.query_one("#origin", Input)
    origin.focus()
    await wait_until(lambda: app.focused is origin)
    modal = _make(app, kind, long=long)
    await app.push_screen(modal, app.results.append)
    if kind == "binding":
        await wait_until(lambda: modal.query_one("#vault_bind_item", Select).value == ITEM_ID)
        await wait_until(lambda: not modal._busy.is_busy)
    await pilot.pause()
    assert len(app.screen_stack) == 3
    return modal


def _painted(app: _Host, widget) -> str:
    strips = app.screen._compositor.render_strips()
    left, right = max(0, widget.region.x), min(app.size.width, widget.region.right)
    return "\n".join(strips[y].crop(left, right).text for y in range(
        max(0, widget.region.y), min(app.size.height, widget.region.bottom),
    ))


def _exposed(app: _Host, widget) -> None:
    assert widget.region.width > 0 and widget.region.height > 0
    assert app.screen.region.contains_region(widget.region)
    for y in range(widget.region.y, widget.region.bottom):
        hit = app.get_widget_at(widget.region.center[0], y)[0]
        assert hit is widget or widget in hit.ancestors
    if isinstance(widget, Button):
        assert widget.label.plain in _painted(app, widget)


async def _click(app: _Host, pilot: Pilot, widget) -> None:
    _exposed(app, widget)
    if isinstance(widget, Button):
        await wait_until(lambda: not widget.has_class("-active"))
    assert await pilot.click(widget, offset=(widget.size.width // 2, widget.size.height // 2))


def _layout(app: _Host, modal: ModalScreen) -> tuple:
    frame = modal.query_one(DialogFrame)
    heading = frame.query_one(".dialog-heading", Static)
    footer = frame.query_one(".dialog-footer")
    assert modal.region.contains_region(frame.region)
    assert not frame.allow_vertical_scroll and frame.max_scroll_y == 0
    assert heading.region.bottom <= footer.region.y
    _exposed(app, heading)
    for button in footer.query(Button):
        _exposed(app, button)
        assert frame.content_region.contains_region(button.region)
    lane = modal.query_one(DialogNotificationSpace)
    assert lane.parent is modal and not lane.can_focus
    # Hidden reservation widgets have no compositor region; use native placement.
    arrangement = modal.arrange(modal.scrollable_content_region.size)
    placement = next(p for p in arrangement.placements if p.widget is lane)
    reserved = placement.region + placement.offset + modal.scrollable_content_region.offset
    assert reserved.height == 4 and reserved.width == modal.scrollable_content_region.width
    assert modal.region.contains_region(reserved)
    assert frame.region.bottom <= reserved.y
    assert len(frame.query(".dialog-body")) == 1
    return heading.region, footer.region, tuple(button.region for button in footer.query(Button))


def _frame_policy(frame: DialogFrame) -> tuple:
    """Use resolved descriptor Scalars, not width-relative set_styles probes."""
    parent = frame.parent
    assert parent is not None and frame.styles.max_height is not None
    styles = frame.styles
    cap = styles.max_height.resolve(parent.content_region.size, frame.app.size)
    return (
        frame.region.width, cap, styles.height, tuple(styles.padding),
        styles.border_top, styles.border_right, styles.border_bottom, styles.border_left,
        styles.overflow_x, styles.overflow_y,
    )


async def _reference_policy(app: _Host, pilot: Pilot, kind: str) -> tuple:
    await wait_until(lambda: app.screen is app.landing)
    reference = _FrameReference(kind)
    await app.push_screen(reference)
    await pilot.pause()
    policy = _frame_policy(reference.query_one(DialogFrame))
    await pilot.press("escape")
    await wait_until(lambda: app.screen is app.landing)
    return policy


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("theme", THEMES)
async def test_dialog_native_regions_and_notification_lane(kind: str, size: tuple[int, int], theme: str) -> None:
    app = _Host()
    app.theme = theme
    async with app.run_test(size=size, notifications=True) as pilot:
        expected_frame = await _reference_policy(app, pilot, kind)
        modal = await _open(app, pilot, kind)
        assert _frame_policy(modal.query_one(DialogFrame)) == expected_frame
        positions = _layout(app, modal)
        heading = modal.query_one(".dialog-heading", Static)
        text = {"scope": "Who is this key for?", "own": "Also update your own key", "verify-ref": "Verify SSH", "binding": "Use vault key"}[kind]
        assert text in _painted(app, heading)
        _assert_readable(_painted_text_styles(heading, text), context=kind + " heading")
        modal.notify("Example notification", title="Review", timeout=30)
        await wait_until(lambda: bool(modal.query(Toast)))
        assert _layout(app, modal) == positions
        await pilot.press("escape")
        await wait_until(lambda: app.screen is app.landing)
        assert app.results == [{"scope": None, "own": False, "verify-ref": False, "binding": None}[kind]]
        assert app.focused is app.landing.query_one("#origin")
        app.service.bind.assert_not_awaited()
        app.service.bind_personal.assert_not_awaited()
        assert app.service.visits == []


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", FOCUS_KINDS)
@pytest.mark.parametrize("size", SIZES)
async def test_initial_focus_matches_qualified_original(kind: str, size: tuple[int, int]) -> None:
    assert ORIGINAL_NATIVE_FOCUS is not None and (kind, size) in ORIGINAL_NATIVE_FOCUS, "Measure original native focus before pinning any modal target"
    app = _Host()
    async with app.run_test(size=size) as pilot:
        modal = await _open(app, pilot, kind)
        expected = ORIGINAL_NATIVE_FOCUS[kind, size]
        assert (app.focused.id if app.focused is not None else None) == expected
        assert modal.is_attached


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_scope_native_end_scroll_and_personal_pointer_result(size: tuple[int, int]) -> None:
    app = _Host()
    async with app.run_test(size=size) as pilot:
        await _open(app, pilot, "scope")
        await pilot.press("enter")
        await wait_until(lambda: app.screen is app.landing)
        assert app.results == [""]
        modal = await _open(app, pilot, "scope", long=True)
        choices = modal.query_one("#vault_scope_choices", OptionList)
        cancel = modal.query_one("#vault_scope_cancel", Button)
        assert choices.highlighted == 30
        assert modal.query_one(".dialog-body") is choices
        assert not modal.query(DialogBody)
        positions = _layout(app, modal)
        choices.focus()
        await pilot.press("home")
        await wait_until(lambda: choices.highlighted == 0)
        start = choices.scroll_y
        await pilot.press("end")
        await wait_until(lambda: choices.highlighted == 30 and choices.scroll_y > start)
        assert "Just me" in _painted(app, choices)
        assert _layout(app, modal) == positions
        _exposed(app, cancel)
        # Select the actual last row at its painted native cells.
        strips = modal._compositor.render_strips()
        for y in range(max(0, choices.region.y), min(app.size.height, choices.region.bottom)):
            x = strips[y].text.find("Just me", choices.region.x, choices.region.right)
            if x >= 0:
                assert app.get_widget_at(x, y)[0] is choices
                assert await pilot.click(choices, offset=(x - choices.region.x, y - choices.region.y))
                break
        else:
            pytest.fail("The final personal choice must be painted and hittable")
        await wait_until(lambda: app.screen is app.landing)
        assert app.results == ["", ""]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_long_own_key_copy_scrolls_without_moving_safe_actions(size: tuple[int, int]) -> None:
    app = _Host()
    async with app.run_test(size=size) as pilot:
        modal = await _open(app, pilot, "own", long=True)
        keep = modal.query_one("#own_key_keep", Button)
        assert app.focused is keep
        body = modal.query_one(DialogBody)
        positions = _layout(app, modal)
        body.focus()
        await pilot.press("home")
        start = body.scroll_y
        await pilot.press("end")
        await wait_until(lambda: body.scroll_y > start)
        assert "operator[/b]" in _painted(app, body)
        assert _layout(app, modal) == positions
        await tab_to(pilot, keep)
        await pilot.press("enter")
        await wait_until(lambda: app.screen is app.landing)
        assert app.results == [False]
        # A real pointer Update is distinct from the safe Enter path.
        modal = await _open(app, pilot, "own", long=True)
        await _click(app, pilot, modal.query_one("#own_key_update", Button))
        await wait_until(lambda: app.screen is app.landing)
        assert app.results == [False, True]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["verify-ref", "verify-no-ref", "verify-vault"])
async def test_verify_variant_disclosure_and_explicit_pointer_result(kind: str) -> None:
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, kind)
        await pilot.press("enter")
        await wait_until(lambda: app.screen is app.landing)
        assert app.results == [False]
        modal = await _open(app, pilot, kind)
        body = modal.query_one("#ssh_verify_modal_body", Static)
        body.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        text = _painted(app, body)
        assert "web[/b].example.test" in text
        disclosure = {
            "verify-ref": "local SSH probe", "verify-vault": "Servonaut Vault key",
            "verify-no-ref": "No SSH ref is stored",
        }[kind]
        assert disclosure in text
        _layout(app, modal)
        button = modal.query_one("#btn_ssh_verify_confirm", Button)
        assert button.label.plain == ("Add SSH Ref" if kind == "verify-no-ref" else "Verify")
        await tab_to(pilot, button)
        await _click(app, pilot, button)
        await wait_until(lambda: app.screen is app.landing)
        assert app.results == [False, True]
        assert app.service.visits == []


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_binding_held_loading_error_and_early_cancel_keep_footer_native(size: tuple[int, int]) -> None:
    app = _Host()
    vaults, keys = _Gate(), _Gate()
    app.service.gates = {"vaults": vaults, "keys": keys}
    app.service.fail_keys = True
    async with app.run_test(size=size) as pilot:
        await wait_until(lambda: app.screen is app.landing)
        modal = _make(app, "binding")
        await app.push_screen(modal, app.results.append)
        try:
            await wait_until(vaults.entered.is_set)
            busy = modal.query_one("#vault_bind_busy", BusyIndicator)
            # The concurrent host-key read may still own the busy display.
            await wait_until(lambda: "Loading your vaults" in _painted(app, busy))
            positions = _layout(app, modal)
            assert "Loading your vaults" in _painted(app, busy)
            assert modal.query_one("#vault_bind_confirm", Button).disabled
            assert not modal.query_one("#vault_bind_cancel", Button).disabled
            vaults.release.set()
            await wait_until(keys.entered.is_set)
            await wait_until(lambda: "Loading this vault" in _painted(app, busy))
            assert _layout(app, modal) == positions
            keys.release.set()
            await wait_until(lambda: not modal._busy.is_busy)
            message = modal.query_one("#vault_bind_message", Static)
            message.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            assert "Could not load the SSH keys" in _painted(app, message)
            assert not modal.query_one("#vault_bind_confirm", Button).disabled
            _layout(app, modal)
            # Retry starts the actual selector worker. Cancel while it is held.
            retry = _Gate()
            app.service.gates["keys"] = retry
            modal.query_one("#vault_bind_vault", Select).value = VAULT_ID
            await wait_until(retry.entered.is_set)
            await _click(app, pilot, modal.query_one("#vault_bind_cancel", Button))
            await wait_until(lambda: app.screen is app.landing)
            retry.release.set()
            await wait_until(lambda: not modal._busy.is_busy)
            assert app.results == [None] and not modal.is_attached
            assert app._exception is None
        finally:
            for gate in app.service.gates.values():
                gate.release.set()
            vaults.release.set()
            keys.release.set()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_binding_demo_toggle_keeps_native_form_and_raw_callback(size: tuple[int, int]) -> None:
    app = _Host()
    async with app.run_test(size=size) as pilot:
        modal = await _open(app, pilot, "binding")
        login = modal.query_one("#vault_bind_login", Input)
        raw_login = login.value
        keys = modal.query_one("#vault_bind_host_keys", Input)
        keys.value = HOST_KEY
        reads = list(app.service.reads)
        origin_instance = dict(modal._instance)
        # App shortcuts are excluded by the native ModalScreen binding chain.
        # Exercise the real runtime action and redaction propagation explicitly.
        app.action_toggle_demo()
        await wait_until(lambda: app.demo_mode)
        assert login.value != raw_login
        assert modal.query_one("#vault_bind_item", Select).value == ITEM_ID
        assert app.service.reads == reads
        app.action_toggle_demo()
        await wait_until(lambda: not app.demo_mode and login.value == raw_login)
        assert modal._instance == origin_instance
        assert keys.value == HOST_KEY
        keys.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        _exposed(app, keys)
        positions = _layout(app, modal)
        button = modal.query_one("#vault_bind_confirm", Button)
        await tab_to(pilot, button)
        assert _layout(app, modal) == positions
        await _click(app, pilot, button)
        await wait_until(lambda: app.screen is app.landing)
        assert app.results == [{"team": "", "vault_id": VAULT_ID, "item_id": ITEM_ID, "login": raw_login, "host_keys": HOST_KEY}]
        assert app.service.visits == []
        app.service.bind.assert_not_awaited()
        app.service.bind_personal.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_binding_trusted_keys_and_long_form_scroll_preserve_pinned_status_and_result(
    size: tuple[int, int], monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted = Mock(return_value=list(TRUSTED_KEYS))
    monkeypatch.setattr(server_actions, "trusted_host_keys", trusted)
    app = _Host()
    app.service.vault_label = "Example vault with " + "a deliberately long display label " * 6
    app.service.key_label = "Example key with " + "a deliberately long display label " * 6
    gate = _Gate()
    app.service.gates["keys"] = gate
    async with app.run_test(size=size) as pilot:
        await wait_until(lambda: app.screen is app.landing)
        modal = _make(app, "binding")
        await app.push_screen(modal, app.results.append)
        try:
            await wait_until(gate.entered.is_set)
            box = modal.query_one("#vault_bind_use_trusted")
            await wait_until(lambda: not box.disabled)
            assert box.value is False
            trusted.assert_called_once_with(ROW, ROW["public_ip"], ROW["port"])
            assert modal._trusted_keys == list(TRUSTED_KEYS)
            busy = modal.query_one("#vault_bind_busy", BusyIndicator)
            await wait_until(lambda: "Loading this vault" in _painted(app, busy))
            positions = _layout(app, modal)
            _exposed(app, busy)
            assert modal.query_one("#vault_bind_confirm", Button).disabled
            assert not modal.query_one("#vault_bind_cancel", Button).disabled
            line = modal.query_one("#vault_bind_trusted", Static)
            # The trusted text grows from one placeholder row to three rows.
            # Scroll only after its native layout includes every fingerprint.
            await wait_until(lambda: line.region.height == len(modal._trusted_text.splitlines()))
            line.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            for fingerprint in TRUSTED_FINGERPRINTS:
                assert fingerprint in _painted(app, line)
            assert _layout(app, modal) == positions
            body = modal.query_one(DialogBody)
            body.focus()
            await pilot.press("home")
            await wait_until(lambda: body.scroll_y == 0)
            start = body.scroll_y
            await pilot.press("end")
            await wait_until(lambda: body.max_scroll_y > 0 and body.scroll_y > start)
            assert body.scroll_y == body.max_scroll_y
            field = modal.query_one("#vault_bind_host_keys", Input)
            _exposed(app, field)
            assert _layout(app, modal) == positions
            assert not modal.query_one(DialogFrame).allow_vertical_scroll
            box.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            await _click(app, pilot, box)
            assert box.value is True
            gate.release.set()
            await wait_until(lambda: modal.query_one("#vault_bind_item", Select).value == ITEM_ID)
            await wait_until(lambda: not modal._busy.is_busy)
            assert _layout(app, modal)[2] == positions[2]
            button = modal.query_one("#vault_bind_confirm", Button)
            await tab_to(pilot, button)
            await _click(app, pilot, button)
            await wait_until(lambda: app.screen is app.landing)
            assert app.results == [{
                "team": "", "vault_id": VAULT_ID, "item_id": ITEM_ID,
                "login": ROW["username"], "host_keys": ",".join(TRUSTED_KEYS),
            }]
            assert app.service.reads == [("vaults", None), ("keys", VAULT_ID)]
            assert app.service.visits == []
        finally:
            gate.release.set()
