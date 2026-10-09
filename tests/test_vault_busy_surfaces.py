"""Slow vault work shows what it is doing, and holds back what would restart it.

Covers the SSH key import dialog, the Use Vault Key dialog and the binding and
SSH connect it leads to on the server screen, and the SSH Certificates screen.
Each slow service call waits on an event the test releases, so the busy state
is observed while the call is genuinely pending.
"""
from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from textual.app import App
from textual.css.query import NoMatches
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import Button, Select, SelectionList, Static

from servonaut.config.schema import AppConfig
from servonaut.screens import server_actions
from servonaut.screens._busy_work import BusyWork
from servonaut.screens.ca import _EVERY_ENROLLED_SERVER, CaScreen
from servonaut.screens.server_actions import ServerActionsScreen, VaultBindingModal
from servonaut.screens.vault_import_modal import VaultImportModal
from servonaut.services.bw_errors import BwError
from servonaut.services.bw_key_import import KeyImportError, ScannedKey
from servonaut.services.bw_session_service import BwItemSummary
from servonaut.services.ssh_ref_resolver import ResolvedSshRef
from servonaut.styles import CSS_FILES
from servonaut.widgets.busy_indicator import BusyIndicator
from tests._async_bounds import STEP_TIMEOUT_SECONDS, wait_until
from tests.test_ca_screen_pickers import _PickerService, _choose_team, _click, _picker

SIZES = [(160, 50), (100, 30)]
TEAM_VAULT = "33333333-3333-4333-8333-333333333333"
KEY_ITEM = "22222222-2222-4222-8222-222222222222"
_TO_THREAD = "servonaut.screens.vault_import_modal.asyncio.to_thread"
_SCAN = "servonaut.screens.vault_import_modal.scan_directory"


class _Gate:
    """Holds one awaited call until the test releases it."""

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def wait(self) -> None:
        self.started.set()
        await self.release.wait()

    async def reached(self) -> None:
        await asyncio.wait_for(self.started.wait(), timeout=STEP_TIMEOUT_SECONDS)


def _busy(screen: Screen, selector: str) -> BusyIndicator:
    return screen.query_one(selector, BusyIndicator)


async def _shows(busy: BusyIndicator, message: str) -> None:
    """Wait until *busy* is laid out on screen saying *message*."""
    await wait_until(
        lambda: busy.is_active and busy.display and busy.message == message and busy.region.height > 0
    )


async def _idle(busy: BusyIndicator) -> None:
    await wait_until(lambda: not busy.is_active and not busy.display)


def _disabled(screen: Screen, *selectors: str) -> list[bool]:
    return [screen.query_one(selector, Widget).disabled for selector in selectors]


def _inside(inner: Widget, outer: Widget) -> bool:
    assert outer.region.contains_region(inner.region), (inner, inner.region, outer.region)
    return True


async def _immediate_thread(function, *args, **kwargs):
    return function(*args, **kwargs)


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------


class _HelperHost(App):
    def compose(self):
        yield BusyIndicator(id="busy")
        yield Button("Go", id="go")


@pytest.mark.asyncio
async def test_overlapping_work_shows_the_newest_and_releases_a_button_only_when_nothing_holds_it() -> None:
    app = _HelperHost()
    async with app.run_test() as pilot:
        busy, button = app.query_one(BusyIndicator), app.query_one(Button)
        button.focus()
        await wait_until(lambda: app.focused is button)
        work = BusyWork(app.screen, "#busy")
        first = work.begin("Loading the list…", hold=("#go",))
        second = work.begin("Reading the key…", hold=("#go",))
        await _shows(busy, "Reading the key…")
        assert button.disabled and app.focused is None  # Enter reaches nothing meanwhile

        work.end(second)
        await _shows(busy, "Loading the list…")
        assert button.disabled  # the first piece still holds it

        work.end(second)  # a late second end changes nothing
        work.end(first)
        await _idle(busy)
        assert not button.disabled
        await wait_until(lambda: app.focused is button)
        await pilot.pause()


@pytest.mark.asyncio
async def test_a_button_disabled_before_the_work_stays_disabled_after_it() -> None:
    app = _HelperHost()
    async with app.run_test():
        button = app.query_one(Button)
        button.disabled = True
        work = BusyWork(app.screen, "#busy")
        with work.running("Loading…", hold=("#go", "#missing")):
            assert button.disabled
        assert button.disabled and not work.is_busy


def test_work_on_a_dialog_that_is_not_mounted_is_skipped() -> None:
    modal = VaultImportModal(MagicMock(), "vault-1", Path("/tmp"))
    work = BusyWork(modal, "#vault_import_busy")
    with work.running("Loading…", hold=("#vault_import_local",)):
        assert work.holds("#vault_import_local")
    assert not work.is_busy
    with pytest.raises(NoMatches):
        modal.query_one("#vault_import_busy")


# ---------------------------------------------------------------------------
# SSH key import dialog
# ---------------------------------------------------------------------------

_IMPORT_BUTTONS = ("#vault_import_local", "#vault_import_bitwarden", "#vault_import_confirm")


class _ImportHost(App):
    CSS_PATH = CSS_FILES

    def __init__(self, modal: VaultImportModal) -> None:
        super().__init__()
        self.modal = modal
        self.result: Any = "pending"
        self.notes: list[str] = []

    def on_mount(self) -> None:
        self.push_screen(self.modal, callback=self._done)

    def _done(self, value: Any) -> None:
        self.result = value

    async def push_screen_wait(self, _screen: Screen) -> Any:
        return True  # Bitwarden is already unlocked

    def notify(self, message: str, **_kwargs: Any) -> None:
        self.notes.append(message)


def _status(modal: VaultImportModal) -> str:
    return str(modal.query_one("#vault_import_status", Static).render())


def test_the_ssh_directory_is_named_from_home() -> None:
    assert VaultImportModal(MagicMock(), "vault-1")._directory_label() == "~/.ssh"
    assert VaultImportModal(MagicMock(), "vault-1", Path("/srv/keys"))._directory_label() == "/srv/keys"


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_reading_local_keys_shows_progress_and_holds_the_source_buttons(tmp_path: Path, size) -> None:
    gate = _Gate()

    async def slow_thread(function, *args, **kwargs):
        await gate.wait()
        return function(*args, **kwargs)

    key = ScannedKey(path=tmp_path / "id_ed25519", filename="id_ed25519", encrypted=False)
    modal = VaultImportModal(MagicMock(), "vault-1", tmp_path)
    with patch(_SCAN, return_value=[key]), patch(_TO_THREAD, new=slow_thread):
        app = _ImportHost(modal)
        async with app.run_test(size=size) as pilot:
            await wait_until(lambda: app.screen is modal)
            await pilot.click("#vault_import_local")
            await gate.reached()
            busy = _busy(modal, "#vault_import_busy")
            await _shows(busy, f"Reading SSH keys in {tmp_path}…")
            assert _disabled(modal, *_IMPORT_BUTTONS) == [True, True, True]
            dialog = modal.query_one("#vault_import_modal")
            for selector in ("#vault_import_busy", "#vault_import_cancel", "#vault_import_confirm"):
                assert _inside(modal.query_one(selector), dialog), selector
            assert dialog.region.bottom <= app.size.height

            await pilot.press("escape")  # closing would cancel the read: say why it stays open
            await wait_until(lambda: "wait for it to finish" in _status(modal))
            assert app.screen is modal and app.result == "pending"

            gate.release.set()
            listing = modal.query_one("#vault_import_list", SelectionList)
            await wait_until(lambda: listing.option_count == 1)
            await _idle(busy)
            assert _disabled(modal, *_IMPORT_BUTTONS) == [False, False, False]
            assert _status(modal) == "Found 1 local SSH key candidate(s)."


@pytest.mark.asyncio
async def test_a_failed_local_read_hides_the_progress_and_gives_the_buttons_back(tmp_path: Path) -> None:
    gate = _Gate()

    async def slow_thread(function, *args, **kwargs):
        await gate.wait()
        return function(*args, **kwargs)

    modal = VaultImportModal(MagicMock(), "vault-1", tmp_path)
    with patch(_SCAN, side_effect=KeyImportError("unreadable")), patch(_TO_THREAD, new=slow_thread):
        app = _ImportHost(modal)
        async with app.run_test(size=(100, 30)) as pilot:
            await wait_until(lambda: app.screen is modal)
            await pilot.click("#vault_import_local")
            await gate.reached()
            busy = _busy(modal, "#vault_import_busy")
            await wait_until(lambda: busy.is_active)
            gate.release.set()
            await wait_until(lambda: _status(modal) == "Could not scan the selected SSH directory.")
            await _idle(busy)
            # Nothing to import: the sources are offered again, Import stays off.
            assert _disabled(modal, *_IMPORT_BUTTONS) == [False, False, True]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [None, BwError("Bitwarden is locked.")])
async def test_listing_bitwarden_items_shows_progress_until_it_ends(tmp_path: Path, failure) -> None:
    gate = _Gate()
    session = MagicMock()

    async def list_items(*, folder_id, ssh_only):
        await gate.wait()
        if failure is not None:
            raise failure
        return [BwItemSummary(id="bw-item-1", name="Deploy key", type=5, has_ssh_key=True)]

    session.list_items = AsyncMock(side_effect=list_items)
    modal = VaultImportModal(MagicMock(), "vault-1", tmp_path, session_service=session)
    app = _ImportHost(modal)
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: app.screen is modal)
        await pilot.click("#vault_import_bitwarden")
        await gate.reached()
        busy = _busy(modal, "#vault_import_busy")
        await _shows(busy, "Loading Bitwarden SSH items…")
        assert _disabled(modal, *_IMPORT_BUTTONS) == [True, True, True]

        gate.release.set()
        await _idle(busy)
        if failure is None:
            await wait_until(lambda: modal.query_one(SelectionList).option_count == 1)
            assert _disabled(modal, *_IMPORT_BUTTONS) == [False, False, False]
        else:
            await wait_until(lambda: _status(modal) == "Bitwarden is locked.")
            assert _disabled(modal, *_IMPORT_BUTTONS) == [False, False, True]


@pytest.mark.asyncio
async def test_importing_counts_the_keys_and_cannot_be_closed_or_restarted_midway(tmp_path: Path) -> None:
    keys = [ScannedKey(path=tmp_path / f"id_{n}", filename=f"id_{n}", encrypted=False) for n in (1, 2)]
    gates = [_Gate(), _Gate()]

    async def import_keys(**_kwargs):
        position = service.import_keys.await_count - 1
        await gates[position].wait()
        return {"item_id": f"item-{position + 1}"}

    service = MagicMock()
    service.import_keys = AsyncMock(side_effect=import_keys)
    modal = VaultImportModal(service, "vault-1", tmp_path)
    with patch(_SCAN, return_value=keys), patch(_TO_THREAD, new=_immediate_thread):
        app = _ImportHost(modal)
        async with app.run_test(size=(100, 30)) as pilot:
            await wait_until(lambda: app.screen is modal)
            await pilot.click("#vault_import_local")
            await wait_until(lambda: modal.query_one(SelectionList).option_count == 2)
            modal._local_private_key = AsyncMock(side_effect=lambda _key: bytearray(b"fixture"))
            busy = _busy(modal, "#vault_import_busy")
            await _idle(busy)
            await _click(pilot, "#vault_import_confirm")

            await gates[0].reached()
            await _shows(busy, "Importing key 1 of 2…")
            assert _disabled(modal, *_IMPORT_BUTTONS) == [True, True, True]
            await _click(pilot, "#vault_import_cancel")
            await wait_until(lambda: "import is still running" in _status(modal))
            assert app.screen is modal

            gates[0].release.set()
            await gates[1].reached()
            await _shows(busy, "Importing key 2 of 2…")
            gates[1].release.set()
            await wait_until(lambda: app.result != "pending")

    assert app.result["imported"] == 2 and app.result["imported_ids"] == ["item-1", "item-2"]
    assert not busy.is_active


@pytest.mark.asyncio
async def test_a_bitwarden_import_says_when_it_reads_the_key_and_when_it_imports_it(tmp_path: Path) -> None:
    read_gate, import_gate = _Gate(), _Gate()
    resolver = MagicMock()
    resolver.resolve_ssh_key.return_value = "fixture-private"

    async def slow_thread(function, *args, **kwargs):
        if function is resolver.resolve_ssh_key:
            await read_gate.wait()
        return function(*args, **kwargs)

    async def import_keys(**_kwargs):
        await import_gate.wait()
        raise RuntimeError("upload failed")

    service = MagicMock()
    service.import_keys = AsyncMock(side_effect=import_keys)
    session = MagicMock()
    session.list_items = AsyncMock(
        return_value=[BwItemSummary(id="bw-item-1", name="Deploy key", type=5, has_ssh_key=True)]
    )
    modal = VaultImportModal(service, "vault-1", tmp_path, session_service=session, resolver=resolver)
    with patch(_TO_THREAD, new=slow_thread):
        app = _ImportHost(modal)
        async with app.run_test(size=(160, 50)) as pilot:
            await wait_until(lambda: app.screen is modal)
            await pilot.click("#vault_import_bitwarden")
            listing = modal.query_one(SelectionList)
            await wait_until(lambda: listing.option_count == 1)
            listing.select_all()
            busy = _busy(modal, "#vault_import_busy")
            buttons = [modal.query_one(selector, Button) for selector in _IMPORT_BUTTONS]
            await _idle(busy)
            await _click(pilot, "#vault_import_confirm")

            await read_gate.reached()
            await _shows(busy, "Reading the key from Bitwarden…")
            read_gate.release.set()
            await import_gate.reached()
            await _shows(busy, "Importing the key…")
            assert _disabled(modal, *_IMPORT_BUTTONS) == [True, True, True]
            import_gate.release.set()
            await wait_until(lambda: app.result != "pending")

    assert app.result["failed"] == 1 and app.notes == ["Could not import the selected Bitwarden SSH key."]
    assert not busy.is_active
    assert [button.disabled for button in buttons] == [False, False, False]  # as when Import was pressed


@pytest.mark.asyncio
async def test_leaving_while_keys_load_cancels_the_read_quietly(tmp_path: Path) -> None:
    gate = _Gate()

    async def slow_thread(function, *args, **kwargs):
        await gate.wait()
        return function(*args, **kwargs)

    modal = VaultImportModal(MagicMock(), "vault-1", tmp_path)
    with patch(_SCAN, return_value=[]), patch(_TO_THREAD, new=slow_thread):
        app = _ImportHost(modal)
        async with app.run_test(size=(100, 30)) as pilot:
            await wait_until(lambda: app.screen is modal)
            await pilot.click("#vault_import_local")
            await gate.reached()
            await app.pop_screen()  # the way the app closes a dialog under it
            gate.release.set()
            await wait_until(lambda: not modal._loading)
            assert app.screen is not modal
            await pilot.pause()


# ---------------------------------------------------------------------------
# Use Vault Key dialog
# ---------------------------------------------------------------------------


class _BindService:
    """The vault choices the dialog loads; a call named in ``gates`` waits for its release."""

    def __init__(self) -> None:
        self.gates: dict[str, _Gate] = {}
        self.fail_keys = False

    async def _pass(self, name: str) -> None:
        if name in self.gates:
            await self.gates[name].wait()

    async def vault_choices(self, *, team=None):
        await self._pass("vault_choices")
        if team is None:
            return [{"vault_id": TEAM_VAULT, "label": "Personal (your personal vault)", "kind": "personal"}]
        return [{"vault_id": TEAM_VAULT, "label": "Team vault (team ops)", "kind": "team"}]

    async def ssh_key_choices(self, *, vault_id):
        await self._pass("ssh_key_choices")
        if self.fail_keys:
            raise RuntimeError("boom")
        return [{"item_id": KEY_ITEM, "label": "deploy · SHA256:def"}]


class _BindHost(App):
    CSS_PATH = CSS_FILES

    def __init__(self, service: _BindService, instance: dict) -> None:
        super().__init__()
        self.service, self.instance = service, instance

    def on_mount(self) -> None:
        self.push_screen(VaultBindingModal(self.service, self.instance))


_SHARED = {"id": "s1", "is_shared": True, "team_slug": "ops", "username": "deploy"}


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_the_dialog_shows_what_it_loads_and_holds_bind_until_the_keys_are_in(size) -> None:
    service = _BindService()
    service.gates = {"vault_choices": _Gate(), "ssh_key_choices": _Gate()}
    app = _BindHost(service, _SHARED)
    async with app.run_test(size=size) as pilot:
        await service.gates["vault_choices"].reached()
        modal = app.screen
        busy = _busy(modal, "#vault_bind_busy")
        await _shows(busy, "Loading your vaults…")
        assert _disabled(modal, "#vault_bind_confirm", "#vault_bind_cancel") == [True, False]
        dialog = modal.query_one("#vault_bind_modal")
        for selector in ("#vault_bind_busy", "#vault_bind_cancel", "#vault_bind_confirm"):
            assert _inside(modal.query_one(selector), dialog), selector
        assert dialog.region.bottom <= app.size.height

        service.gates["vault_choices"].release.set()
        await service.gates["ssh_key_choices"].reached()
        await _shows(busy, "Loading this vault's SSH keys… this can take a few seconds")
        assert modal.query_one("#vault_bind_confirm", Button).disabled

        service.gates["ssh_key_choices"].release.set()
        await _idle(busy)
        assert modal.query_one("#vault_bind_item", Select).value == KEY_ITEM
        assert not modal.query_one("#vault_bind_confirm", Button).disabled
        await pilot.pause()


@pytest.mark.asyncio
async def test_a_failed_key_load_hides_the_progress_and_gives_bind_back() -> None:
    service = _BindService()
    service.fail_keys = True
    service.gates = {"ssh_key_choices": _Gate()}
    app = _BindHost(service, _SHARED)
    async with app.run_test(size=(100, 30)):
        await service.gates["ssh_key_choices"].reached()
        modal = app.screen
        busy = _busy(modal, "#vault_bind_busy")
        await wait_until(lambda: busy.is_active)
        service.gates["ssh_key_choices"].release.set()
        await wait_until(lambda: "Could not load the SSH keys" in str(
            modal.query_one("#vault_bind_message", Static).render()))
        await _idle(busy)
        assert not modal.query_one("#vault_bind_confirm", Button).disabled


@pytest.mark.asyncio
async def test_bind_waits_for_the_trusted_host_keys_as_well(monkeypatch) -> None:
    release = threading.Event()

    def slow_trusted_keys(_instance, _host, _port):
        release.wait(STEP_TIMEOUT_SECONDS)
        return []

    monkeypatch.setattr(server_actions, "trusted_host_keys", slow_trusted_keys)
    app = _BindHost(_BindService(), {"id": "i-1", "hostname": "192.0.2.7", "username": "ec2-user"})
    try:
        async with app.run_test(size=(160, 50)):
            await wait_until(lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
            modal = app.screen
            busy = _busy(modal, "#vault_bind_busy")
            await _shows(busy, "Reading the host keys this machine trusts…")
            assert modal.query_one("#vault_bind_confirm", Button).disabled

            release.set()
            await wait_until(lambda: "does not trust" in str(modal.query_one("#vault_bind_trusted", Static).render()))
            await _idle(busy)
            assert not modal.query_one("#vault_bind_confirm", Button).disabled
    finally:
        release.set()


# ---------------------------------------------------------------------------
# Server screen: binding the chosen key, and preparing an SSH connection
# ---------------------------------------------------------------------------

_CHOICE = {"team": "ops", "vault_id": TEAM_VAULT, "item_id": KEY_ITEM, "login": "deploy", "host_keys": ""}
_SERVER = {
    "id": "custom-web-1", "name": "web-1", "is_custom": True, "is_shared": True, "team_slug": "ops",
    "public_ip": "10.0.0.5", "username": "deploy", "port": 22,
}


class _ServerHost(App):
    CSS_PATH = CSS_FILES
    demo_mode = False
    memory_service = None
    redaction_service = None

    def __init__(self) -> None:
        super().__init__()
        self.notes: list[tuple[str, dict[str, Any]]] = []
        self.config_manager = Mock()
        self.config_manager.get.return_value = AppConfig()
        self.vault_command_service: Any = None
        self.ssh_service = MagicMock()
        self.ssh_service.build_ssh_command.return_value = ["ssh", "deploy@10.0.0.5"]
        self.connection_service = MagicMock()
        self.connection_service.get_extra_options.return_value = []
        self.terminal_service = MagicMock()
        self.terminal_service.launch_ssh_in_terminal.return_value = True

    async def push_screen_wait(self, _screen: Screen) -> Any:
        return dict(_CHOICE)  # the Use Vault Key dialog's answer

    def notify(self, message: str, **kwargs: Any) -> None:
        self.notes.append((message, kwargs))


async def _server_screen(app: _ServerHost) -> ServerActionsScreen:
    screen = ServerActionsScreen(dict(_SERVER))
    await app.push_screen(screen)
    await wait_until(lambda: app.screen is screen)
    return screen


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_binding_shows_progress_and_cannot_be_restarted_midway(size) -> None:
    gate = _Gate()
    service = MagicMock()

    async def bind(**_kwargs):
        await gate.wait()
        return {"source": "servonaut_vault"}

    service.bind = AsyncMock(side_effect=bind)
    app = _ServerHost()
    app.vault_command_service = service
    async with app.run_test(size=size) as pilot:
        screen = await _server_screen(app)
        button = screen.query_one("#btn_use_vault_key", Button)
        button.focus()
        await wait_until(lambda: app.focused is button)
        button.press()
        await gate.reached()
        busy = _busy(screen, "#sa_busy")
        await _shows(busy, "Binding the vault key to this server…")
        assert button.disabled and app.focused is None  # not handed to the next action
        assert _inside(busy, screen.query_one("#sa-detail")) and busy.region.bottom <= app.size.height

        screen.action_use_vault_key()  # e.g. a press queued before the button was disabled
        assert app.notes[-1][0] == "The vault key is still being bound: wait for it to finish."
        assert service.bind.await_count == 1

        gate.release.set()
        await _idle(busy)
        assert not button.disabled
        await wait_until(lambda: app.focused is button)
        assert app.notes[-1][0] == "SSH credential source: servonaut_vault"
        await pilot.pause()


@pytest.mark.asyncio
async def test_a_failed_binding_hides_the_progress_and_gives_the_button_back() -> None:
    gate = _Gate()
    service = MagicMock()

    async def bind(**_kwargs):
        await gate.wait()
        raise RuntimeError("service unavailable")

    service.bind = AsyncMock(side_effect=bind)
    app = _ServerHost()
    app.vault_command_service = service
    async with app.run_test(size=(100, 30)):
        screen = await _server_screen(app)
        screen.action_use_vault_key()
        await gate.reached()
        busy = _busy(screen, "#sa_busy")
        await wait_until(lambda: busy.is_active)
        gate.release.set()
        await _idle(busy)
        assert app.notes[-1][0].startswith("Vault key binding failed")
        assert not screen.query_one("#btn_use_vault_key", Button).disabled


_LOCAL = ResolvedSshRef(
    source="local", item_id=None, vault_url=None, collection_id=None,
    local_key_path="/keys/id_ed25519", team_slug=None, server_id=None,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [None, RuntimeError("vault locked")])
async def test_preparing_ssh_shows_progress_and_a_second_press_does_not_restart_it(failure) -> None:
    gate = _Gate()
    calls: list[Any] = []

    async def resolve(_resolver, instance):
        calls.append(instance)
        await gate.wait()
        if failure is not None:
            raise failure
        return _LOCAL

    app = _ServerHost()
    with patch("servonaut.services.ssh_ref_resolver.SshRefResolver.resolve", new=resolve):
        async with app.run_test(size=(160, 50)) as pilot:
            screen = await _server_screen(app)
            await pilot.press("3")
            await gate.reached()
            busy = _busy(screen, "#sa_busy")
            await _shows(busy, "Preparing the SSH connection…")
            assert screen.query_one("#btn_ssh", Button).disabled

            await pilot.press("3")
            await wait_until(lambda: bool(app.notes))
            assert app.notes[-1][0] == "Still preparing the SSH connection: wait for it to finish."
            assert len(calls) == 1

            gate.release.set()
            await _idle(busy)
            assert not screen.query_one("#btn_ssh", Button).disabled

    if failure is None:
        app.terminal_service.launch_ssh_in_terminal.assert_called_once()
    else:
        app.terminal_service.launch_ssh_in_terminal.assert_not_called()
        assert app.notes[-1][0].startswith("The configured Vault SSH credential could not be used")


# ---------------------------------------------------------------------------
# SSH Certificates screen
# ---------------------------------------------------------------------------


class _CaHost(App):
    CSS_PATH = CSS_FILES

    def __init__(self, service: Any) -> None:
        super().__init__()
        self.vault_command_service = service
        self.notes: list[tuple[str, dict[str, Any]]] = []

    def notify(self, message: str, **kwargs: Any) -> None:
        self.notes.append((message, kwargs))

    async def push_screen_wait(self, _screen: Screen) -> str:
        return "web-1"  # the typed host name in the enrollment confirmation

    def on_mount(self) -> None:
        self.push_screen(CaScreen())


class _ConfirmingService(_PickerService):
    """Enrollment the way the service runs it: prepare, confirm, then write to the host."""

    async def ca_enroll(self, *, team: str, server: str, break_glass_item_id: str | None, confirmation: Any):
        await self._answer("ca_enroll_prepare", team=team, server=server)
        typed = await confirmation({"kind": "enroll", "hostname": "web-1"})
        await self._answer("ca_enroll", team=team, server=server, typed=typed)
        return {"status": "enrolled"}


_CA_ACTIONS = ("#ca_audit", "#ca_enroll", "#ca_krl", "#ca_break_glass_scan")


@pytest.mark.asyncio
async def test_loading_teams_status_and_options_each_say_so() -> None:
    service = _PickerService()
    teams = asyncio.Event()
    service.gates = {"team_choices": teams}
    app = _CaHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: isinstance(app.screen, CaScreen))
        screen = app.screen
        busy = _busy(screen, "#ca_busy")
        await _shows(busy, "Loading your teams…")

        service.gates.update({"ca_status": asyncio.Event(), "list_items": asyncio.Event()})
        teams.set()
        await wait_until(lambda: "Loading" not in _picker(screen, "ca_team").prompt)
        await _idle(busy)

        _picker(screen, "ca_team").value = "ops"
        await wait_until(lambda: len(service.calls_to("list_items")) == 1 and len(service.calls_to("ca_status")) == 1)
        await _shows(busy, "Loading this team's servers and break-glass keys…")  # the newest still running
        service.gates["list_items"].set()
        await _shows(busy, "Loading SSH certificate status…")
        service.gates["ca_status"].set()
        await _idle(busy)
        await pilot.pause()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_enrollment_says_what_it_does_before_and_after_the_confirmation(size) -> None:
    service = _ConfirmingService()
    app = _CaHost(service)
    async with app.run_test(size=size) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        _picker(screen, "ca_server").value = "srv-web"
        service.gates = {"ca_enroll_prepare": asyncio.Event(), "ca_enroll": asyncio.Event()}
        enroll = screen.query_one("#ca_enroll", Button)
        await wait_until(lambda: not enroll.disabled)
        enroll.press()
        busy = _busy(screen, "#ca_busy")
        await _shows(busy, "Preparing to enroll web-1 (web-1)…")
        assert _disabled(screen, *_CA_ACTIONS) == [True, True, True, True]
        content = screen.query_one("#ca_content")
        assert _inside(busy, content) and busy.region.bottom <= app.size.height

        service.gates["ca_enroll_prepare"].set()
        await _shows(busy, "Enrolling web-1 (web-1)… this connects over SSH and can take a minute")
        service.gates["ca_enroll"].set()
        await _idle(busy)
        await wait_until(lambda: _disabled(screen, *_CA_ACTIONS) == [False, False, False, False])
        assert service.calls_to("ca_enroll")[-1]["typed"] == "web-1"


@pytest.mark.asyncio
async def test_a_failed_krl_delivery_hides_the_progress_and_gives_the_actions_back() -> None:
    service = _PickerService()
    app = _CaHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        _picker(screen, "ca_server").value = "srv-web"
        service.gates = {"ca_deliver_krl": asyncio.Event()}
        service.failures = {"ca_deliver_krl": RuntimeError("ssh refused")}
        await pilot.pause()

        await _click(pilot, "#ca_krl")
        busy = _busy(screen, "#ca_busy")
        await _shows(
            busy, "Delivering the revocation list to web-1 (web-1)… this connects over SSH and can take a minute",
        )
        service.gates["ca_deliver_krl"].set()
        await _idle(busy)
        await wait_until(lambda: _disabled(screen, *_CA_ACTIONS) == [False, False, False, False])
        assert app.notes[-1][0].startswith("KRL delivery failed")


@pytest.mark.asyncio
async def test_the_scan_of_every_server_names_it_and_server_names_are_redacted_in_demo_mode() -> None:
    class Redactor:
        def scrub_stream(self, text: str) -> str:
            return text.replace("web-1", "host-redacted")

    service = _PickerService()
    app = _CaHost(service)
    app.redaction_service = Redactor()
    app.demo_mode = True
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        busy = _busy(screen, "#ca_busy")

        _picker(screen, "ca_server").value = _EVERY_ENROLLED_SERVER
        service.gates = {"ca_break_glass_scan": asyncio.Event()}
        await pilot.pause()
        await _click(pilot, "#ca_break_glass_scan")
        await _shows(
            busy, "Scanning every enrolled server for break-glass logins… this connects over SSH and can take a minute",
        )
        service.gates["ca_break_glass_scan"].set()
        await _idle(busy)
        await wait_until(lambda: not screen.query_one("#ca_audit", Button).disabled)

        _picker(screen, "ca_server").value = "srv-web"
        service.gates = {"ca_enroll": asyncio.Event()}
        await pilot.pause()
        await _click(pilot, "#ca_enroll")
        await _shows(busy, "Preparing to enroll host-redacted (host-redacted)…")
        app.demo_mode = False
        screen.refresh_after_demo_toggle()
        await _shows(busy, "Preparing to enroll web-1 (web-1)…")
        service.gates["ca_enroll"].set()
        await _idle(busy)


@pytest.mark.asyncio
async def test_coming_soon_still_ends_the_status_load() -> None:
    service = _PickerService()
    service.switched_off.add("ops")
    app = _CaHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        await _idle(_busy(screen, "#ca_busy"))
        assert _disabled(screen, *_CA_ACTIONS) == [True, True, True, True]
