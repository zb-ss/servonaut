"""The Vault screen shows slow work, holds conflicting actions, and guides device recovery."""
from __future__ import annotations

import asyncio
from typing import Any, Optional

import pytest
from textual.app import App
from textual.widgets import Button, Static

from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.vault import (
    VaultAddDeviceModal,
    VaultRevealModal,
    VaultScreen,
    VaultSecretPromptModal,
)
from servonaut.styles import CSS_FILES
from servonaut.widgets.busy_indicator import BusyIndicator
from tests._async_bounds import wait_until

_VAULT = {"vault_id": "vault-1", "name": "Personal", "kind": "personal", "my_grant": {"version": 1}, "counts": {}}


class _Service:
    """A vault facade whose slow calls wait until the test releases them."""

    def __init__(self, *, local: Optional[str] = "fp-1", remote: Any = None, custody_missing: bool = False) -> None:
        self.local = local
        self.remote = {"identity_id": "id-1", "trust_status": "confirmed"} if remote is None else remote
        self.custody_missing = custody_missing
        self.release = asyncio.Event()
        self.fail_items = False
        self.list_items_calls = 0
        self.add_device_calls: list[dict[str, Any]] = []
        self.poll_states: list[dict[str, Any]] = []
        self.finished: list[Any] = []
        self.cancelled = 0
        self.recovered: list[str] = []
        self.revealed = 0

    async def status(self):
        return {
            "remote": {"identity": self.remote}, "local_identity": self.local,
            "fingerprint": self.local, "custody_missing": self.custody_missing,
        }

    def unlock_existing_identity(self):
        return False

    async def list_vaults(self):
        return [dict(_VAULT)]

    async def can_create_personal_vault(self):
        return False

    async def list_items(self, **_kwargs):
        self.list_items_calls += 1
        await self.release.wait()
        if self.fail_items:
            raise RuntimeError("server unavailable")
        return {"data": [{"item_id": "item-1", "type": "ssh_key", "revision": 1, "public_fingerprint": "SHA256:x"}]}

    async def show_item(self, **_kwargs):
        self.revealed += 1
        await self.release.wait()
        return {"item_id": "item-1", "type": "ssh_key", "payload": {"name": "deploy"}}

    def default_device_name(self) -> str:
        return "workstation"

    async def add_device(self, **kwargs):
        self.add_device_calls.append(kwargs)
        return {"identity": {"identity_id": "id-1"}, "expires_at": "2999-01-01T00:00:00+00:00", "state": "pending"}

    async def poll_pending_device(self, **_kwargs):
        if self.poll_states:
            return self.poll_states.pop(0)
        await self.release.wait()
        return {"state": "pending"}

    def finish_pending_device(self, **kwargs):
        self.finished.append(kwargs)
        self.local = "fp-2"
        return {"device_id": "dev-2"}

    def cancel_pending_device(self) -> None:
        self.cancelled += 1

    def approval_poll_delay(self, attempt: int) -> float:
        return 0.01

    async def recover(self, *, recovery_key: str, **_kwargs):
        self.recovered.append(recovery_key)
        await self.release.wait()
        self.local = "fp-3"
        self.custody_missing = False
        return {"device": {"device_id": "dev-3"}}


class _Host(App):
    def __init__(self, service: _Service) -> None:
        self.vault_command_service = service
        self.vault_available = True
        self.notes: list[str] = []
        super().__init__()

    def notify(self, message, *args, **kwargs):  # type: ignore[override]
        self.notes.append(str(message))
        return super().notify(message, *args, **kwargs)

    def on_mount(self) -> None:
        self.push_screen(VaultScreen())


def _status(screen: VaultScreen) -> str:
    return str(screen.query_one("#vault_status", Static).render())


def _busy(screen: VaultScreen) -> Optional[str]:
    indicator = screen.query_one("#vault_busy", BusyIndicator)
    return indicator.message if indicator.is_active else None


def _press(screen, button_id: str) -> None:
    """Press a button the way a click does (the action row scrolls in a narrow host)."""
    screen.query_one(f"#{button_id}", Button).press()


def _enabled(screen: VaultScreen, button_id: str) -> bool:
    return not screen.query_one(f"#{button_id}", Button).disabled


async def _settled(app: App, text: str) -> VaultScreen:
    await wait_until(lambda: isinstance(app.screen, VaultScreen) and text in _status(app.screen)
                     and _busy(app.screen) is None)
    return app.screen


@pytest.mark.asyncio
async def test_a_slow_items_load_shows_what_is_running_and_holds_the_actions() -> None:
    service = _Service()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _settled(app, "Identity fingerprint")
        assert _enabled(screen, "vault_items") and _enabled(screen, "vault_refresh")

        _press(screen, "vault_items")
        await wait_until(lambda: _busy(screen) == "Loading the vault's items…")
        assert screen.query_one("#vault_busy", BusyIndicator).display
        assert not _enabled(screen, "vault_items") and not _enabled(screen, "vault_refresh")

        # A second action would cancel the running one: it is refused instead.
        await pilot.press("r")
        await pilot.pause()
        assert _busy(screen) == "Loading the vault's items…" and service.list_items_calls == 1
        assert any("Please wait" in note for note in app.notes)

        service.release.set()
        await wait_until(lambda: _busy(screen) is None)
        assert "Item metadata loaded" in _status(screen)
        assert _enabled(screen, "vault_reveal") and _enabled(screen, "vault_refresh")


@pytest.mark.asyncio
async def test_a_failed_slow_action_still_clears_the_indicator() -> None:
    service = _Service()
    service.fail_items = True
    service.release.set()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _settled(app, "Identity fingerprint")
        _press(screen, "vault_items")
        await wait_until(lambda: service.list_items_calls == 1 and _busy(screen) is None)
        assert _enabled(screen, "vault_items") and _enabled(screen, "vault_refresh")
        assert any("Could not load item metadata" in note for note in app.notes)


@pytest.mark.asyncio
async def test_revealing_a_key_says_it_is_decrypting() -> None:
    service = _Service()
    service.release.set()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _settled(app, "Identity fingerprint")
        _press(screen, "vault_items")
        await wait_until(lambda: "Item metadata loaded" in _status(screen) and _busy(screen) is None)
        service.release.clear()

        await pilot.press("v")
        await wait_until(lambda: isinstance(app.screen, ConfirmActionScreen) and bool(app.screen.query("#confirm_input")))
        await pilot.pause()
        app.screen.dismiss(True)
        await wait_until(lambda: _busy(screen) == "Decrypting the item…")
        assert not _enabled(screen, "vault_reveal")

        service.release.set()
        await wait_until(lambda: isinstance(app.screen, VaultRevealModal))
        assert _busy(screen) is None


@pytest.mark.asyncio
async def test_add_device_explains_who_approves_and_stop_waiting_discards_the_request() -> None:
    service = _Service(local=None)
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _settled(app, "Your vault identity is not on this computer")
        assert _enabled(screen, "vault_add_device") and _enabled(screen, "vault_recover")

        _press(screen, "vault_add_device")
        await wait_until(lambda: isinstance(app.screen, VaultAddDeviceModal) and bool(app.screen.query("#vault_add_device_start")))
        modal = app.screen
        steps = str(modal.query_one("#vault_add_device_steps", Static).render())
        assert "already unlocked" in steps and "“workstation”" in steps and "Approve device" in steps
        assert "Recover" in str(modal.query_one("#vault_add_device_other", Static).render())
        assert service.add_device_calls == []  # nothing is asked before Start

        _press(app.screen, "vault_add_device_start")
        await wait_until(lambda: _busy(screen) == "Waiting for another device to approve “workstation”…")
        assert service.add_device_calls == [{"device_name": "workstation", "platform": None}]
        assert "select “workstation”" in _status(screen)
        stop = screen.query_one("#vault_cancel_wait", Button)
        assert stop.display and not stop.disabled
        assert not _enabled(screen, "vault_add_device") and not _enabled(screen, "vault_recover")

        _press(screen, "vault_cancel_wait")
        await wait_until(lambda: _busy(screen) is None)
        assert service.cancelled == 1
        assert "Stopped waiting" in _status(screen)
        assert not stop.display
        assert _enabled(screen, "vault_add_device") and _enabled(screen, "vault_recover")
        assert len(service.add_device_calls) == 1


@pytest.mark.asyncio
async def test_add_device_shows_the_safety_number_and_finishes_when_approved() -> None:
    service = _Service(local=None)
    service.poll_states = [
        {"state": "revealed", "safety_number": "1234 5678"},
        {"state": "approved", "approval": {"bundle": "sealed"}},
    ]
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _settled(app, "Your vault identity is not on this computer")
        _press(screen, "vault_add_device")
        await wait_until(lambda: isinstance(app.screen, VaultAddDeviceModal) and bool(app.screen.query("#vault_add_device_start")))
        _press(app.screen, "vault_add_device_start")

        await wait_until(lambda: service.finished != [] and "Identity fingerprint" in _status(screen))
        assert service.finished[0]["approval"] == {"bundle": "sealed"}
        assert any("now a vault device" in note for note in app.notes)
        assert service.cancelled == 0
        await wait_until(lambda: _busy(screen) is None)


@pytest.mark.asyncio
async def test_leaving_the_screen_while_waiting_discards_the_unapproved_device() -> None:
    service = _Service(local=None)
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _settled(app, "Your vault identity is not on this computer")
        _press(screen, "vault_add_device")
        await wait_until(lambda: isinstance(app.screen, VaultAddDeviceModal) and bool(app.screen.query("#vault_add_device_start")))
        _press(app.screen, "vault_add_device_start")
        await wait_until(lambda: _busy(screen) is not None and service.add_device_calls != [])

        app.pop_screen()
        await wait_until(lambda: service.cancelled == 1)


@pytest.mark.asyncio
async def test_a_missing_key_file_is_named_and_recover_is_the_way_back() -> None:
    service = _Service(local=None, custody_missing=True)
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _settled(app, "key file is missing")
        assert "~/.servonaut/vault/vault_keys.json" in _status(screen)
        assert _enabled(screen, "vault_recover") and _enabled(screen, "vault_add_device")

        _press(screen, "vault_add_device")
        await wait_until(lambda: isinstance(app.screen, VaultAddDeviceModal) and bool(app.screen.query("#vault_add_device_start")))
        modal = app.screen
        assert "key file is missing" in str(modal.query_one("#vault_add_device_other", Static).render())
        await wait_until(lambda: modal.focused is modal.query_one("#vault_add_device_recover", Button))

        _press(app.screen, "vault_add_device_recover")
        await wait_until(lambda: isinstance(app.screen, VaultSecretPromptModal) and bool(app.screen.query("#vault_secret_input")))
        assert service.add_device_calls == []


@pytest.mark.asyncio
async def test_recover_shows_progress_then_unlocks_this_computer() -> None:
    service = _Service(local=None, custody_missing=True)
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _settled(app, "key file is missing")
        _press(screen, "vault_recover")
        await wait_until(lambda: isinstance(app.screen, VaultSecretPromptModal) and bool(app.screen.query("#vault_secret_input")))
        app.screen.dismiss("RECOVERY-KEY")

        await wait_until(lambda: _busy(screen) == "Restoring your vault identity on this computer…")
        assert not _enabled(screen, "vault_recover")
        service.release.set()
        await wait_until(lambda: "Identity fingerprint" in _status(screen) and _busy(screen) is None)
        assert service.recovered == ["RECOVERY-KEY"]
        assert _enabled(screen, "vault_items") and not _enabled(screen, "vault_recover")
        assert any("restored on this computer" in note for note in app.notes)


@pytest.mark.asyncio
async def test_the_button_that_started_slow_work_gets_focus_back_when_it_ends() -> None:
    service = _Service()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _settled(app, "Identity fingerprint")
        items = screen.query_one("#vault_items", Button)
        items.focus()
        await pilot.pause()
        _press(screen, "vault_items")
        await wait_until(lambda: _busy(screen) is not None)
        assert items.disabled

        service.release.set()
        await wait_until(lambda: _busy(screen) is None and screen.focused is items)


class _StyledHost(_Host):
    """Product styles, so the action rows scroll as users see them."""

    CSS_PATH = CSS_FILES


def _in_view(screen: VaultScreen, button_id: str) -> bool:
    button = screen.query_one(f"#{button_id}", Button)
    return screen.query_one("#vault_action_scroll").region.contains_region(button.region)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_the_action_the_status_names_is_focused_and_in_view(size) -> None:
    service = _Service(local=None, custody_missing=True)
    app = _StyledHost(service)
    async with app.run_test(size=size):
        screen = await _settled(app, "key file is missing")
        recover = screen.query_one("#vault_recover", Button)
        await wait_until(lambda: screen.focused is recover and _in_view(screen, "vault_recover"))


@pytest.mark.asyncio
async def test_a_pending_device_is_selected_with_approve_device_in_view() -> None:
    service = _Service()

    async def list_devices():
        return [
            {"device_id": "d-1", "name": "laptop", "status": "active"},
            {"device_id": "d-2", "name": "workstation", "status": "pending"},
        ]

    service.list_devices = list_devices  # type: ignore[attr-defined]
    app = _StyledHost(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _settled(app, "Identity fingerprint")
        await pilot.press("d")
        approve = screen.query_one("#vault_approve", Button)
        await wait_until(lambda: screen.focused is approve and _busy(screen) is None)
        assert screen.query_one("#vault_table").cursor_row == 1
        await wait_until(lambda: _in_view(screen, "vault_approve"))


@pytest.mark.asyncio
async def test_stop_waiting_stays_on_screen_in_a_small_terminal() -> None:
    service = _Service(local=None)
    app = _StyledHost(service)
    async with app.run_test(size=(100, 30)):
        screen = await _settled(app, "Your vault identity is not on this computer")
        _press(screen, "vault_add_device")
        await wait_until(lambda: isinstance(app.screen, VaultAddDeviceModal) and bool(app.screen.query("#vault_add_device_start")))
        _press(app.screen, "vault_add_device_start")
        stop = screen.query_one("#vault_cancel_wait", Button)
        await wait_until(lambda: _busy(screen) is not None and stop.display and stop.region.height > 0)
        assert screen.region.contains_region(stop.region)
        assert screen.region.contains_region(screen.query_one("#vault_busy", BusyIndicator).region)


@pytest.mark.asyncio
async def test_approving_a_device_can_be_stopped_while_it_waits_for_the_new_device() -> None:
    service = _Service()
    approvals: list[str] = []

    async def approve_device(*, device_id: str, confirmation):
        approvals.append(device_id)
        await asyncio.Event().wait()  # the new device never shows its safety number

    service.approve_device = approve_device  # type: ignore[attr-defined]
    app = _Host(service)
    async with app.run_test(size=(160, 50)):
        screen = await _settled(app, "Identity fingerprint")
        screen._devices = [{"device_id": "d-2", "status": "pending"}]
        screen._render_devices()
        screen.action_approve()
        await wait_until(lambda: _busy(screen) is not None and approvals == ["d-2"])
        stop = screen.query_one("#vault_cancel_wait", Button)
        assert stop.display and not stop.disabled

        _press(screen, "vault_cancel_wait")
        await wait_until(lambda: _busy(screen) is None)
        assert "Stopped approving" in _status(screen)
        assert _enabled(screen, "vault_devices")


@pytest.mark.asyncio
async def test_back_is_held_while_a_change_would_be_cut_off_but_not_while_loading() -> None:
    service = _Service(local=None, custody_missing=True)
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _settled(app, "key file is missing")
        _press(screen, "vault_recover")
        await wait_until(lambda: isinstance(app.screen, VaultSecretPromptModal) and bool(app.screen.query("#vault_secret_input")))
        app.screen.dismiss("RECOVERY-KEY")
        await wait_until(lambda: _busy(screen) == "Restoring your vault identity on this computer…")

        screen.action_back()
        await pilot.pause()
        assert app.screen is screen
        assert any("Leaving now would stop it halfway" in note for note in app.notes)

        service.release.set()
        await wait_until(lambda: _busy(screen) is None and "Identity fingerprint" in _status(screen))
        service.release.clear()
        _press(screen, "vault_items")  # a read: leaving just stops it
        await wait_until(lambda: _busy(screen) is not None)
        screen.action_back()
        await wait_until(lambda: app.screen is not screen)


class _DemoRedactor:
    def scrub_stream(self, text: str) -> str:
        return text


@pytest.mark.asyncio
async def test_demo_mode_does_not_show_this_computers_name() -> None:
    service = _Service(local=None)
    app = _Host(service)
    app.demo_mode = True
    app.redaction_service = _DemoRedactor()
    async with app.run_test(size=(160, 50)):
        screen = await _settled(app, "Your vault identity is not on this computer")
        _press(screen, "vault_add_device")
        await wait_until(lambda: isinstance(app.screen, VaultAddDeviceModal) and bool(app.screen.query("#vault_add_device_start")))
        steps = str(app.screen.query_one("#vault_add_device_steps", Static).render())
        assert "workstation" not in steps and "“this computer”" in steps

        _press(app.screen, "vault_add_device_start")
        indicator = screen.query_one("#vault_busy", BusyIndicator)
        await wait_until(lambda: _busy(screen) is not None and "approve" in str(indicator.render()))
        assert "workstation" not in str(indicator.render()) and "workstation" not in _status(screen)


@pytest.mark.asyncio
async def test_a_failed_wait_says_this_computer_was_not_added() -> None:
    service = _Service(local=None)

    async def poll_pending_device(**_kwargs):
        raise RuntimeError("pending device approval ended unexpectedly")

    service.poll_pending_device = poll_pending_device  # type: ignore[method-assign]
    app = _Host(service)
    async with app.run_test(size=(160, 50)):
        screen = await _settled(app, "Your vault identity is not on this computer")
        _press(screen, "vault_add_device")
        await wait_until(lambda: isinstance(app.screen, VaultAddDeviceModal) and bool(app.screen.query("#vault_add_device_start")))
        _press(app.screen, "vault_add_device_start")
        await wait_until(lambda: "This computer was not added" in _status(screen) and _busy(screen) is None)
        assert "Safety number" not in _status(screen)
        assert service.cancelled == 1
