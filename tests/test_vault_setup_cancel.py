"""Declining initial recovery confirmation is quiet and cannot enrol custody."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, Input
from textual.widgets._toast import Toast

from servonaut.screens.vault import VaultRecoveryConfirmModal
from servonaut.services.vault import command_service
from servonaut.services.vault.command_service import VaultCommandService
from servonaut.services.vault.errors import VaultUserError
from tests._async_bounds import wait_until
from tests.test_vault_screen import _StyledVaultHost, _VaultStatusService


class _Store:
    def __init__(self) -> None:
        self.identity = None
        self.events: list[str] = []

    def has_persisted_identity(self) -> bool:
        return False

    def create(self, *, identity_id: str, user_id: int) -> object:
        self.events.append("create")
        self.identity = object()
        return self.identity

    def wipe(self) -> None:
        self.events.append("wipe")
        self.identity = None

    def save(self, *args: object) -> None:
        raise AssertionError("Declined setup must not persist custody")

    def load(self) -> None:
        raise AssertionError("Fixture has no existing custody")


def _facade(monkeypatch: pytest.MonkeyPatch) -> VaultCommandService:
    # Exercise the actual setup method without constructing identity/crypto/API
    # dependencies. These visible words are a placeholder, never a real key.
    monkeypatch.setattr(command_service, "secrets", SimpleNamespace(
        token_bytes=lambda size: bytes(size),
    ))
    monkeypatch.setattr(command_service, "crypto", SimpleNamespace(
        format_recovery_key=lambda _: "fixture recovery placeholder",
    ))
    monkeypatch.setattr(command_service, "uuid", SimpleNamespace(
        uuid4=lambda: "fixture-identity",
    ))
    service = object.__new__(VaultCommandService)
    service._apply_key_store_setting = lambda: None
    service._user_id = AsyncMock(return_value=1)
    service.store = _Store()
    service.identity = SimpleNamespace(
        status=AsyncMock(return_value={"identity": None}),
        enroll=AsyncMock(side_effect=AssertionError("Declined setup must not enrol")),
    )
    return service


class _Service(_VaultStatusService):
    def __init__(self, facade: VaultCommandService) -> None:
        super().__init__(remote_identity=None)
        self.facade = facade
        self.setup_calls = 0

    async def setup(self, *, device_name, platform, recovery_confirmation):
        self.setup_calls += 1
        return await self.facade.setup(
            device_name=device_name, platform=platform,
            recovery_confirmation=recovery_confirmation,
        )


async def _tab_to(pilot: Pilot, button: Widget) -> None:
    for _ in range(len(pilot.app.screen.focus_chain) + 1):
        if pilot.app.focused is button:
            return
        await pilot.press("tab")
    raise AssertionError("Native Tab did not reach recovery control")


def _setup_logs(caplog: pytest.LogCaptureFixture) -> list:
    return [record for record in caplog.records
            if record.name == "servonaut.screens.vault"
            and record.getMessage() == "Vault setup failed"]


@pytest.mark.asyncio
async def test_declined_setup_keeps_service_denial_and_wipes_before_any_enrolment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facade = _facade(monkeypatch)
    confirmation = Mock(return_value=False)
    with pytest.raises(VaultUserError, match="recovery key was not confirmed") as caught:
        await facade.setup(
            device_name=None, platform=None, recovery_confirmation=confirmation,
        )
    # Avoid importing the new subtype: this module can run on unchanged source
    # for the actual red, while retaining the existing public base contract.
    assert type(caught.value).__name__ == "VaultRecoveryNotConfirmed"
    confirmation.assert_called_once()
    assert facade.store.events == ["create", "wipe"]
    assert facade.store.identity is None
    facade.identity.enroll.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("gesture", ["pointer", "tab-enter"])
async def test_native_recovery_cancel_is_quiet_and_setup_can_be_retried(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
    size: tuple[int, int], gesture: str,
) -> None:
    facade = _facade(monkeypatch)
    service = _Service(facade)
    app = _StyledVaultHost(service)
    async with app.run_test(size=size, notifications=True) as pilot:
        screen = app.screen
        await wait_until(lambda: screen._identity_state == "first_user")
        setup = screen.query_one("#vault_setup", Button)
        for attempt in range(2):
            await wait_until(lambda: not setup.disabled and bool(setup.region))
            await pilot.pause()
            assert await pilot.click(setup)
            await wait_until(lambda: isinstance(app.screen, VaultRecoveryConfirmModal))
            modal = app.screen
            await wait_until(lambda: modal.is_mounted)
            cancel = modal.query_one("#vault_recovery_cancel", Button)
            await wait_until(lambda: modal.is_mounted and bool(cancel.content_region))
            await pilot.pause()
            if gesture == "pointer":
                assert await pilot.click(cancel)
            else:
                await _tab_to(pilot, cancel)
                await pilot.press("enter")
            await wait_until(lambda: app.screen is screen and not screen._setup_running)
            await pilot.pause()
            assert screen._identity_state == "first_user"
            assert not setup.disabled and not screen._busy_work
            assert service.setup_calls == attempt + 1
            assert facade.store.events == ["create", "wipe"] * (attempt + 1)
            assert facade.store.identity is None
            facade.identity.enroll.assert_not_awaited()
            assert not _setup_logs(caplog)
            assert not any(t._notification.severity == "error" for t in screen.query(Toast))
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_an_ordinary_setup_failure_still_logs_and_shows_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
    size: tuple[int, int],
) -> None:
    facade = _facade(monkeypatch)
    # Deliberately the same safe text as a decline, but an ordinary service
    # error before confirmation. Message matching must never suppress it.
    failure = VaultUserError("recovery key was not confirmed")
    facade.identity.status.side_effect = failure
    app = _StyledVaultHost(_Service(facade))
    async with app.run_test(size=size, notifications=True) as pilot:
        screen = app.screen
        await wait_until(lambda: screen._identity_state == "first_user")
        setup = screen.query_one("#vault_setup", Button)
        await wait_until(lambda: not setup.disabled and bool(setup.region))
        await pilot.pause()
        assert await pilot.click(setup)
        await wait_until(lambda: not screen._setup_running and bool(_setup_logs(caplog)))
        await wait_until(lambda: any(t._notification.severity == "error" for t in screen.query(Toast)))
        toast = next(t for t in screen.query(Toast) if t._notification.severity == "error")
        await wait_until(lambda: toast.is_mounted and bool(toast.content_region))
        await pilot.pause()
        expected = "Vault setup failed (recovery key was not confirmed)."
        assert toast.render().plain == expected
        box = toast.content_region.intersection(screen.region)
        strips = screen._compositor.render_strips()
        painted = "\n".join(
            strips[y].crop(box.x, box.right).text
            for y in range(box.y, box.bottom)
        )
        assert "".join(expected.split()) in "".join(painted.split())
        assert _setup_logs(caplog)[-1].exc_info[1] is failure
        assert screen._identity_state == "first_user" and not setup.disabled
        assert not screen._busy_work and facade.store.events == []
        facade.identity.enroll.assert_not_awaited()
        assert app._exception is None


async def _enter_fixture_proof(
    pilot: Pilot, modal: VaultRecoveryConfirmModal, *, valid: bool,
) -> None:
    # Public placeholder words passed by _facade, not a recovery-key readback.
    words = ("fixture", "recovery", "placeholder")
    fields = list(modal.query(Input))
    assert len(fields) == 2
    for field in fields:
        assert field.id is not None and field.id.startswith("vault_recovery_group_")
        index = int(field.id.rsplit("_", 1)[1])
        entered = words[index] if valid else "WRONG"
        assert field.value == ""
        await _tab_to(pilot, field)
        await pilot.press(*entered)
        assert field.value == entered


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_wrong_recovery_proof_still_reports_failure_and_wipes(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
    size: tuple[int, int],
) -> None:
    facade = _facade(monkeypatch)
    app = _StyledVaultHost(_Service(facade))
    async with app.run_test(size=size, notifications=True) as pilot:
        screen = app.screen
        await wait_until(lambda: screen._identity_state == "first_user")
        setup = screen.query_one("#vault_setup", Button)
        await wait_until(lambda: not setup.disabled and bool(setup.region))
        await pilot.pause()
        assert await pilot.click(setup)
        await wait_until(lambda: isinstance(app.screen, VaultRecoveryConfirmModal))
        modal = app.screen
        await wait_until(lambda: modal.is_mounted)
        await _enter_fixture_proof(pilot, modal, valid=False)
        confirm = modal.query_one("#vault_recovery_confirm", Button)
        assert await pilot.click(confirm)
        await wait_until(lambda: app.screen is screen and not screen._setup_running)
        await wait_until(lambda: bool(_setup_logs(caplog)))
        await wait_until(lambda: any(t._notification.severity == "error" for t in screen.query(Toast)))
        toast = next(t for t in screen.query(Toast) if t._notification.severity == "error")
        await wait_until(lambda: toast.is_mounted and bool(toast.content_region))
        await pilot.pause()
        expected = "Vault setup failed (recovery key was not confirmed)."
        assert toast.render().plain == expected
        box = toast.content_region.intersection(screen.region)
        strips = screen._compositor.render_strips()
        painted = "\n".join(
            strips[y].crop(box.x, box.right).text
            for y in range(box.y, box.bottom)
        )
        assert "".join(expected.split()) in "".join(painted.split())
        assert screen._identity_state == "first_user" and not setup.disabled
        assert not screen._busy_work and facade.store.events == ["create", "wipe"]
        assert facade.store.identity is None
        facade.identity.enroll.assert_not_awaited()
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_valid_fixture_recovery_proof_keeps_true_modal_result(
    monkeypatch: pytest.MonkeyPatch, size: tuple[int, int],
) -> None:
    facade = _facade(monkeypatch)
    app = _StyledVaultHost(_Service(facade))
    results: list[bool] = []
    async with app.run_test(size=size, notifications=True) as pilot:
        origin = app.screen
        await wait_until(lambda: origin._identity_state == "first_user")
        modal = VaultRecoveryConfirmModal("fixture recovery placeholder")
        await app.push_screen(modal, callback=results.append)
        await wait_until(lambda: modal.is_mounted)
        await _enter_fixture_proof(pilot, modal, valid=True)
        confirm = modal.query_one("#vault_recovery_confirm", Button)
        assert await pilot.click(confirm)
        await wait_until(lambda: app.screen is origin and results == [True])
        assert facade.store.events == []
        facade.identity.enroll.assert_not_awaited()
        assert app._exception is None
