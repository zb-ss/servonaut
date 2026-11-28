"""Regression tests for manual Memory Sync UI behavior."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Button, Static

from servonaut.config.schema import MemoryConfig
from servonaut.styles import CSS_FILES
from servonaut.screens.memory_keys import PassphraseEnrolModal
from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen
from servonaut.screens.snapshot_manager import ConfirmModal
from servonaut.screens.vault import VaultSecretPromptModal
from servonaut.services.memory.custody_move import (
    OUTCOME_MOVED,
    MoveAborted,
    MoveReport,
    MoveStopped,
)

from tests._async_bounds import wait_until
from tests._native_actions import click_action


class _AuthStub:
    is_authenticated = True
    _token = SimpleNamespace(plan="solo")

    @staticmethod
    def has_feature(feature: str) -> bool:
        return feature == "memory_sync"


class _SetupSyncStub:
    """Two-batch sync whose second batch can be held during navigation."""

    is_configured = True

    def __init__(self) -> None:
        self.pending = 0
        self.last_sync_at = None
        self.quota = None
        self.drain_calls = 0
        self.second_batch_started = asyncio.Event()
        self.release_second_batch = asyncio.Event()

    @property
    def status(self) -> SimpleNamespace:
        return SimpleNamespace(
            state="idle",
            last_sync_at=self.last_sync_at,
            last_error=None,
            pending_envelopes=self.pending,
            quota=self.quota,
            halted_reason=None,
        )

    @staticmethod
    def is_enrolled_locally() -> bool:
        return True

    @staticmethod
    def get_key_material() -> None:
        return None

    def backfill_from_local_store(self) -> int:
        self.pending = 2
        return 2

    async def drain_now(self) -> SimpleNamespace:
        self.drain_calls += 1
        if self.drain_calls == 1:
            self.pending = 1
            self.last_sync_at = datetime.now(tz=timezone.utc).isoformat()
            self.quota = SimpleNamespace(
                envelopes_used=1,
                envelopes_soft_cap=100,
            )
            return SimpleNamespace(accepted=["first"], rejected=[])
        if self.drain_calls == 2:
            self.second_batch_started.set()
            await self.release_second_batch.wait()
            self.pending = 0
            self.last_sync_at = datetime.now(tz=timezone.utc).isoformat()
            self.quota = SimpleNamespace(
                envelopes_used=2,
                envelopes_soft_cap=100,
            )
            return SimpleNamespace(accepted=["second"], rejected=[])
        return SimpleNamespace(accepted=[], rejected=[])

    @staticmethod
    async def pull_annotations(instance_id: str, name: str, provider: str) -> str:
        return "unchanged"

    @staticmethod
    async def pull_findings(instance_id: str, name: str, provider: str) -> str:
        return "unchanged"


class _ElsewhereScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Static("Elsewhere", id="elsewhere")


class _SetupApp(App):
    CSS_PATH = CSS_FILES

    def __init__(self, sync_service: _SetupSyncStub) -> None:
        super().__init__()
        self.auth_service = _AuthStub()
        self.memory_sync_service = sync_service
        self.memory_service = MagicMock()
        self.memory_service.list_all.return_value = []
        self.config_manager = MagicMock()
        self.config_manager.get.return_value = SimpleNamespace(
            memory=SimpleNamespace(
                sync_remember_device=False,
                sync_remember_expires_at="",
            )
        )
        self.notifications: list[str] = []

    def on_mount(self) -> None:
        self.push_screen(MemorySyncSetupScreen())

    def notify(self, message: str, **kwargs: object) -> None:
        self.notifications.append(message)


@pytest.mark.asyncio
async def test_sync_card_repaints_and_job_survives_navigation() -> None:
    sync = _SetupSyncStub()
    app = _SetupApp(sync)

    with patch(
        "servonaut.services.memory.passphrase_store.keyring_available",
        return_value=False,
    ):
        async with app.run_test(headless=True, size=(120, 40)) as pilot:
            await pilot.pause()
            button = app.screen.query_one("#msync_btn_sync_now", Button)
            assert str(button.label) == "Sync all local memory"

            await click_action(pilot, "#msync_btn_sync_now")
            await asyncio.wait_for(sync.second_batch_started.wait(), timeout=2)
            await pilot.pause()

            pending = (
                app.screen.query_one("#msync_pending_value", Static).render().plain
            )
            progress = app.screen.query_one("#msync_status", Static).render().plain
            assert pending == "1 envelope(s)"
            assert "1 uploaded" in progress

            app.switch_screen(_ElsewhereScreen())
            await pilot.pause()
            sync.release_second_batch.set()

            for _ in range(20):
                if not getattr(app, "_memory_manual_sync_in_progress", False):
                    break
                await pilot.pause(0.05)

            assert sync.pending == 0
            assert sync.drain_calls == 3
            assert not getattr(app, "_memory_manual_sync_in_progress", False)

            app.switch_screen(MemorySyncSetupScreen())
            await pilot.pause()
            refreshed_pending = (
                app.screen.query_one("#msync_pending_value", Static).render().plain
            )
            refreshed_last_sync = (
                app.screen.query_one("#msync_last_sync_value", Static).render().plain
            )
            assert refreshed_pending == "0 envelope(s)"
            assert refreshed_last_sync != "never"


@pytest.mark.asyncio
@pytest.mark.parametrize("close_action", ["exit", "pop"])
async def test_memory_sync_setup_closed_or_left_during_startup_ends_cleanly(
    close_action: str,
) -> None:
    errors: list[BaseException] = []

    class _BaseHostApp(App):
        CSS_PATH = CSS_FILES

        def __init__(self) -> None:
            super().__init__()
            self.auth_service = _AuthStub()
            self.memory_sync_service = _SetupSyncStub()

    class _ClosedDuringStartup(MemorySyncSetupScreen):
        """Closes the app or pops the screen first so Textual dismantles it
        before MemorySyncSetupScreen.on_mount queries its body."""

        async def on_mount(self) -> None:
            if close_action == "exit":
                self.app.exit()
            else:
                self.app.pop_screen()
            await self.remove_children()

    app = _BaseHostApp()
    original = app._handle_exception

    def record(error: Exception) -> None:
        errors.append(error)
        original(error)

    app._handle_exception = record  # type: ignore[method-assign]
    async with app.run_test(headless=True, size=(120, 40)) as pilot:
        app.push_screen(_ClosedDuringStartup())
        await pilot.pause()
    assert errors == []


# ----------------------------------------------------------------------
# Vault custody states and the move flow
# ----------------------------------------------------------------------


class _CustodyStub:
    """The slice of MemoryKeyCustody the screen reads."""

    def __init__(
        self, *, marker_vault: bool = False, mode: str = "passphrase",
        resolution: str = "not_enrolled",
    ) -> None:
        self.marker_vault = marker_vault
        self.mode = mode
        self.resolution = resolution
        self.mode_gate: asyncio.Event | None = None
        self.mode_calls = 0
        self.resolve_calls = 0

    async def resolve(self, *, quiet: bool = False) -> SimpleNamespace:
        from servonaut.services.memory.key_custody import ResolutionKind

        self.resolve_calls += 1
        return SimpleNamespace(kind=ResolutionKind(self.resolution))

    def marker_says_vault(self, user_id: object) -> bool:
        return self.marker_vault

    async def enrolment_mode(self) -> str:
        self.mode_calls += 1
        if self.mode_gate is not None:
            await self.mode_gate.wait()
        return self.mode


class _KeySyncStub(_SetupSyncStub):
    """Sync stub with a settable configured flag and key source."""

    def __init__(self, *, configured: bool, key_source: str | None, enrolled: bool = False) -> None:
        super().__init__()
        self.is_configured = configured
        self.key_source = key_source
        self._enrolled = enrolled

    def is_enrolled_locally(self) -> bool:
        return self._enrolled


class _CustodyApp(_SetupApp):
    def __init__(
        self,
        sync: _KeySyncStub,
        custody: _CustodyStub | None,
        *,
        vault_unlocked: bool = False,
    ) -> None:
        super().__init__(sync)
        self.memory_key_custody = custody
        self.vault_command_service = SimpleNamespace(is_unlocked=vault_unlocked)
        self.notified: list[tuple[str, dict]] = []
        self.bootstrap_calls = 0

    def notify(self, message: str, **kwargs: object) -> None:  # type: ignore[override]
        self.notifications.append(message)
        self.notified.append((message, dict(kwargs)))

    async def bootstrap_memory_cloud(self, passphrase_provider: object = None) -> None:
        self.bootstrap_calls += 1
        self.memory_sync_service.is_configured = True
        self.memory_sync_service.key_source = "vault"


def _ids(app: App) -> set[str]:
    return {w.id for w in app.screen.query("*") if w.id}


def _modal_types(app: App) -> list[type]:
    return [type(screen) for screen in app.screen_stack]


async def _open(app: _CustodyApp, pilot) -> None:
    """Wait until the screen has drawn its card (the loading card does not count)."""
    def drawn() -> bool:
        if not isinstance(app.screen, MemorySyncSetupScreen):
            return False
        ids = _ids(app)
        return any(i.startswith("msync_btn_") for i in ids) and "msync_loading" not in ids

    await wait_until(drawn)
    await pilot.pause()


def _label(app: App, widget_id: str) -> str:
    return str(app.screen.query_one(f"#{widget_id}", Button).label)


@pytest.mark.asyncio
async def test_active_vault_card_has_no_passphrase_controls() -> None:
    app = _CustodyApp(_KeySyncStub(configured=True, key_source="vault"), _CustodyStub())
    with patch("servonaut.services.memory.passphrase_store.keyring_available", return_value=True):
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await _open(app, pilot)
            ids = _ids(app)
            assert {"msync_btn_sync_now", "msync_btn_rotate", "msync_btn_disable"} <= ids
            assert not ids & {
                "msync_btn_forget", "msync_btn_remember", "msync_btn_move_to_vault",
                "msync_btn_open_vault",
            }
            key = app.screen.query_one("#msync_key_value", Static).render().plain
            assert key == "kept in your vault"
            assert PassphraseEnrolModal not in _modal_types(app)


@pytest.mark.asyncio
async def test_active_passphrase_with_vault_ready_offers_move() -> None:
    app = _CustodyApp(
        _KeySyncStub(configured=True, key_source="passphrase"), _CustodyStub(),
        vault_unlocked=True,
    )
    with patch("servonaut.services.memory.passphrase_store.keyring_available", return_value=False):
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await _open(app, pilot)
            assert _label(app, "msync_btn_move_to_vault") == "Move key to vault"
            assert "msync_btn_open_vault" not in _ids(app)


@pytest.mark.asyncio
async def test_active_passphrase_without_vault_offers_open_vault() -> None:
    app = _CustodyApp(_KeySyncStub(configured=True, key_source="passphrase"), _CustodyStub())
    with patch("servonaut.services.memory.passphrase_store.keyring_available", return_value=False):
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await _open(app, pilot)
            assert _label(app, "msync_btn_open_vault") == "Open vault"
            assert "msync_vault_hint" in _ids(app)
            assert "msync_btn_move_to_vault" not in _ids(app)


@pytest.mark.asyncio
async def test_locked_passphrase_without_vault_offers_open_vault() -> None:
    sync = _KeySyncStub(configured=False, key_source=None, enrolled=True)
    app = _CustodyApp(sync, _CustodyStub())
    async with app.run_test(headless=True, size=(160, 50)) as pilot:
        await _open(app, pilot)
        assert _label(app, "msync_btn_setup") == "Unlock Memory Sync"
        assert _label(app, "msync_btn_open_vault") == "Open vault"


@pytest.mark.asyncio
async def test_locked_vault_custody_has_no_passphrase_button() -> None:
    sync = _KeySyncStub(configured=False, key_source=None, enrolled=True)
    app = _CustodyApp(sync, _CustodyStub(marker_vault=True))
    async with app.run_test(headless=True, size=(160, 50)) as pilot:
        await _open(app, pilot)
        ids = _ids(app)
        assert "msync_btn_open_vault" in ids
        assert "msync_btn_setup" not in ids
        body = app.screen.query_one("#msync_vault_body", Static).render().plain
        assert body == (
            "Your Memory Sync key is kept in your vault. Unlock or add this "
            "device to your vault to use Memory Sync here."
        )
        assert PassphraseEnrolModal not in _modal_types(app)


@pytest.mark.asyncio
async def test_setup_with_vault_ready_enrols_without_a_modal() -> None:
    sync = _KeySyncStub(configured=False, key_source=None)
    app = _CustodyApp(sync, _CustodyStub(mode="vault"), vault_unlocked=True)
    with patch("servonaut.services.memory.passphrase_store.keyring_available", return_value=False):
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await _open(app, pilot)
            assert _label(app, "msync_btn_setup") == "Set up Memory Sync"
            body = app.screen.query_one("#msync_vault_body", Static).render().plain
            assert body == "Your key will be kept in your vault. No passphrase needed."
            await click_action(pilot, "#msync_btn_setup")
            await wait_until(lambda: app.bootstrap_calls == 1)
            await wait_until(lambda: "msync_key_value" in _ids(app))
            assert app.bootstrap_calls == 1
            assert _modal_types(app).count(PassphraseEnrolModal) == 0
            assert "msync_btn_move_to_vault" not in _ids(app)
            assert app.screen.query_one("#msync_key_value", Static)


@pytest.mark.asyncio
async def test_identity_on_another_device_shows_loading_then_guidance() -> None:
    custody = _CustodyStub(mode="needs_vault_device")
    custody.mode_gate = asyncio.Event()
    app = _CustodyApp(_KeySyncStub(configured=False, key_source=None), custody)
    async with app.run_test(headless=True, size=(160, 50)) as pilot:
        await wait_until(lambda: "msync_loading" in _ids(app))
        text = app.screen.query_one("#msync_loading_text", Static).render().plain
        assert text == "Checking where your key is kept…"
        worker_groups = {w.group for w in app.screen.workers}
        assert "memory_custody" in worker_groups
        custody.mode_gate.set()
        await _open(app, pilot)
        ids = _ids(app)
        assert "msync_loading" not in ids
        assert "msync_btn_open_vault" in ids
        assert "msync_btn_setup" not in ids


@pytest.mark.asyncio
async def test_account_without_a_vault_keeps_the_passphrase_setup_card() -> None:
    app = _CustodyApp(_KeySyncStub(configured=False, key_source=None), _CustodyStub(mode="passphrase"))
    async with app.run_test(headless=True, size=(160, 50)) as pilot:
        await _open(app, pilot)
        assert _label(app, "msync_btn_setup") == "Unlock Memory Sync"
        assert "msync_btn_open_vault" not in _ids(app)


class _MoverStub:
    """Calls the providers the way the real mover does: in a helper thread."""

    def __init__(self, *, ask_passphrase: bool = False, stop: MoveStopped | None = None) -> None:
        self.ask_passphrase = ask_passphrase
        self.stop = stop
        self.recovery_key: str | None = None
        self.passphrase: str | None = None
        self.steps: list[str] = []
        self.completed = False
        self.gate: asyncio.Event | None = None

    async def run(self, passphrase_provider, recovery_key_provider, progress) -> MoveReport:
        progress("preflight")
        progress("recovery_check")
        self.recovery_key = await asyncio.to_thread(recovery_key_provider)
        if self.ask_passphrase:
            progress("unlock_key")
            self.passphrase = await asyncio.to_thread(passphrase_provider)
        progress("vault_item")
        if self.gate is not None:
            await self.gate.wait()
        if self.stop is not None:
            raise self.stop
        self.completed = True
        return MoveReport(OUTCOME_MOVED)


def _movable_app() -> _CustodyApp:
    return _CustodyApp(
        _KeySyncStub(configured=True, key_source="passphrase"), _CustodyStub(),
        vault_unlocked=True,
    )


async def _press(app: App, pilot, button_id: str, until=None) -> None:
    """Press a button, then wait for the condition the press must lead to."""
    app.screen.query_one(f"#{button_id}", Button).press()
    await pilot.pause()
    if until is not None:
        await wait_until(until)


async def _type_secret(app: App, pilot, value: str, until=None) -> None:
    app.screen.query_one("#vault_secret_input").value = value
    await _press(app, pilot, "vault_secret_continue", until)


def _on(app: App, screen_type: type):
    return lambda: isinstance(app.screen, screen_type)


async def _start_move(app: _CustodyApp, pilot) -> None:
    await _open(app, pilot)
    await _press(app, pilot, "msync_btn_move_to_vault", _on(app, ConfirmModal))


@pytest.mark.asyncio
async def test_move_flow_confirm_recovery_key_then_toast() -> None:
    app = _movable_app()
    mover = _MoverStub()
    with patch.object(MemorySyncSetupScreen, "_build_mover", return_value=mover), patch(
        "servonaut.services.memory.passphrase_store.keyring_available", return_value=False,
    ):
        async with app.run_test(headless=True, size=(160, 50), notifications=True) as pilot:
            await _start_move(app, pilot)
            message = app.screen.query_one("#confirm_modal_message", Static).render().plain
            assert "passphrase stops working" in message
            assert "recovery key becomes the only way" in message
            assert "from Config snapshots" in message
            worker = next(w for w in app.workers if w.name == "msync_move_to_vault")
            assert worker.group == "memory_custody"
            await _press(app, pilot, "btn_confirm_yes", _on(app, VaultSecretPromptModal))
            await _type_secret(app, pilot, "recovery-key-value", lambda: mover.completed)
            await wait_until(lambda: any("now kept in your vault" in m for m in app.notifications))
            assert mover.recovery_key == "recovery-key-value"
            assert mover.passphrase is None
            assert PassphraseEnrolModal not in _modal_types(app)
            assert all(kw.get("markup") is False for _, kw in app.notified)


@pytest.mark.asyncio
async def test_move_asks_for_the_passphrase_only_when_the_mover_needs_it() -> None:
    app = _movable_app()
    mover = _MoverStub(ask_passphrase=True)
    with patch.object(MemorySyncSetupScreen, "_build_mover", return_value=mover), patch(
        "servonaut.services.memory.passphrase_store.keyring_available", return_value=True,
    ):
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await _start_move(app, pilot)
            await _press(app, pilot, "btn_confirm_yes", _on(app, VaultSecretPromptModal))
            await _type_secret(app, pilot, "recovery-key-value", _on(app, PassphraseEnrolModal))
            # The prompt only proves the passphrase: no keep-unlocked switch.
            assert app.screen.query_one("#enrol-remember-row").has_class("hidden")
            app.screen.query_one("#enrol-pass1").value = "old passphrase"
            await pilot.pause()
            await _press(app, pilot, "enrol-btn-confirm", lambda: mover.completed)
            assert mover.passphrase == "old passphrase"


@pytest.mark.asyncio
async def test_cancel_at_the_confirm_modal_never_starts_the_mover() -> None:
    app = _movable_app()
    mover = _MoverStub()
    with patch.object(MemorySyncSetupScreen, "_build_mover", return_value=mover) as build, patch(
        "servonaut.services.memory.passphrase_store.keyring_available", return_value=False,
    ):
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await _start_move(app, pilot)
            await _press(app, pilot, "btn_confirm_no", _on(app, MemorySyncSetupScreen))
            await _open(app, pilot)
            build.assert_not_called()
            assert mover.steps == [] and not mover.completed
            assert "msync_btn_move_to_vault" in _ids(app)


@pytest.mark.asyncio
async def test_cancel_at_the_recovery_prompt_changes_nothing() -> None:
    app = _movable_app()
    mover = _MoverStub()
    with patch.object(MemorySyncSetupScreen, "_build_mover", return_value=mover), patch(
        "servonaut.services.memory.passphrase_store.keyring_available", return_value=False,
    ):
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await _start_move(app, pilot)
            await _press(app, pilot, "btn_confirm_yes", _on(app, VaultSecretPromptModal))
            await _press(app, pilot, "vault_secret_cancel",
                         lambda: any("Nothing was changed" in m for m in app.notifications))
            await wait_until(_on(app, MemorySyncSetupScreen))
            assert not mover.completed
            assert "msync_btn_move_to_vault" in _ids(app)


@pytest.mark.asyncio
async def test_cancel_at_the_passphrase_prompt_changes_nothing() -> None:
    app = _movable_app()
    mover = _MoverStub(ask_passphrase=True)
    with patch.object(MemorySyncSetupScreen, "_build_mover", return_value=mover), patch(
        "servonaut.services.memory.passphrase_store.keyring_available", return_value=False,
    ):
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await _start_move(app, pilot)
            await _press(app, pilot, "btn_confirm_yes", _on(app, VaultSecretPromptModal))
            await _type_secret(app, pilot, "recovery-key-value", _on(app, PassphraseEnrolModal))
            await _press(app, pilot, "enrol-btn-cancel",
                         lambda: any("Move cancelled" in m for m in app.notifications))
            assert not mover.completed


@pytest.mark.asyncio
async def test_a_stopped_move_shows_the_final_text_without_markup() -> None:
    app = _movable_app()
    mover = _MoverStub(stop=MoveStopped("vault_not_ready", "Your vault is [not] ready."))
    with patch.object(MemorySyncSetupScreen, "_build_mover", return_value=mover), patch(
        "servonaut.services.memory.passphrase_store.keyring_available", return_value=False,
    ):
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await _start_move(app, pilot)
            await _press(app, pilot, "btn_confirm_yes", _on(app, VaultSecretPromptModal))
            await _type_secret(
                app, pilot, "recovery-key-value",
                lambda: any("not] ready" in m for m, _ in app.notified))
            shown = [(m, kw) for m, kw in app.notified if "not] ready" in m]
            assert shown and shown[0][1].get("markup") is False
            assert shown[0][1].get("severity") == "error"
            await wait_until(lambda: "msync_btn_move_to_vault" in _ids(app))


@pytest.mark.asyncio
async def test_move_shows_step_lines_and_loading_while_it_runs() -> None:
    app = _movable_app()
    mover = _MoverStub()
    mover.gate = asyncio.Event()
    with patch.object(MemorySyncSetupScreen, "_build_mover", return_value=mover), patch(
        "servonaut.services.memory.passphrase_store.keyring_available", return_value=False,
    ):
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await _start_move(app, pilot)
            await _press(app, pilot, "btn_confirm_yes", _on(app, VaultSecretPromptModal))
            await _type_secret(
                app, pilot, "recovery-key-value",
                lambda: "msync_move_steps" in _ids(app)
                and "· Saving the key in your vault…"
                in app.screen.query_one("#msync_move_steps", Static).render().plain)
            ids = _ids(app)
            assert "msync_move_loading" in ids
            steps = app.screen.query_one("#msync_move_steps", Static).render().plain
            assert "✓ Checking your vault and account" in steps
            assert "· Saving the key in your vault…" in steps
            mover.gate.set()
            await wait_until(lambda: mover.completed)
            await wait_until(lambda: "msync_move_loading" not in _ids(app))


class _RefusedRotationSync(_KeySyncStub):
    async def rotate_keypair_in_vault(self) -> None:
        from servonaut.services.api_client import APIError

        raise APIError(code="item_type_exists", message="two items", status=409)


@pytest.mark.asyncio
async def test_a_refused_rotation_restores_the_status_line() -> None:
    app = _CustodyApp(
        _RefusedRotationSync(configured=True, key_source="vault"), _CustodyStub())
    with patch("servonaut.services.memory.passphrase_store.keyring_available", return_value=False):
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await _open(app, pilot)
            await _press(app, pilot, "msync_btn_rotate", _on(app, ConfirmModal))
            await _press(
                app, pilot, "btn_confirm_yes",
                lambda: any("cannot be changed again yet" in m for m, _ in app.notified))
            await wait_until(lambda: "msync_btn_rotate" in _ids(app))
            status = app.screen.query_one("#msync_status", Static).render().plain
            assert "Rotating" not in status
            assert "Active" in status


class _DisableSyncStub(_KeySyncStub):
    """Configured sync that locks and stops like the real service."""

    def stop(self) -> None:
        self.stopped = True

    def lock(self) -> None:
        self.is_configured = False
        self.key_source = None

    def clear_local_keypair_cache(self) -> None:
        self.cache_cleared = True


class _ConfigStore:
    """A config manager that keeps what the screen saves."""

    def __init__(self, memory: MemoryConfig) -> None:
        self.memory = memory

    def get(self) -> SimpleNamespace:
        return SimpleNamespace(memory=self.memory)

    def update(self, **sections: object) -> None:
        self.memory = sections["memory"]  # type: ignore[assignment]


def _disabled_app() -> _CustodyApp:
    app = _CustodyApp(
        _KeySyncStub(configured=False, key_source=None, enrolled=True), _CustodyStub(marker_vault=True),
        vault_unlocked=True,
    )
    app.config_manager = _ConfigStore(MemoryConfig(sync_disabled=True))
    return app


_STATE_BUILDERS = {
    "active_vault": lambda: _CustodyApp(
        _KeySyncStub(configured=True, key_source="vault"), _CustodyStub()),
    "active_movable": lambda: _CustodyApp(
        _KeySyncStub(configured=True, key_source="passphrase"), _CustodyStub(),
        vault_unlocked=True),
    "active_no_vault": lambda: _CustodyApp(
        _KeySyncStub(configured=True, key_source="passphrase"), _CustodyStub()),
    "locked_vault": lambda: _CustodyApp(
        _KeySyncStub(configured=False, key_source=None, enrolled=True),
        _CustodyStub(marker_vault=True)),
    "setup_vault": lambda: _CustodyApp(
        _KeySyncStub(configured=False, key_source=None), _CustodyStub(mode="vault"),
        vault_unlocked=True),
    "needs_device": lambda: _CustodyApp(
        _KeySyncStub(configured=False, key_source=None),
        _CustodyStub(mode="needs_vault_device")),
    "vault_retry": lambda: _CustodyApp(
        _KeySyncStub(configured=False, key_source=None, enrolled=True),
        _CustodyStub(marker_vault=True), vault_unlocked=True),
    "locked_passphrase_movable": lambda: _CustodyApp(
        _KeySyncStub(configured=False, key_source=None),
        _CustodyStub(resolution="passphrase"), vault_unlocked=True),
    "disabled": lambda: _disabled_app(),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("state", sorted(_STATE_BUILDERS))
async def test_every_state_keeps_its_buttons_inside_the_screen(
    state: str, size: tuple[int, int],
) -> None:
    app = _STATE_BUILDERS[state]()
    with patch("servonaut.services.memory.passphrase_store.keyring_available", return_value=True):
        async with app.run_test(headless=True, size=size) as pilot:
            await _open(app, pilot)
            buttons = [b for b in app.screen.query(Button) if b.id and b.id.startswith("msync_")]
            assert buttons
            for button in buttons:
                assert button.region.width > 0, button.id
                assert button.region.right <= size[0], button.id


# ----------------------------------------------------------------------
# Review round 1: set-up text vs reality (A6), disable (A4), pending move (A3)
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_passphrase_account_with_an_open_vault_gets_the_passphrase_card() -> None:
    """The service's record comes first: no "No passphrase needed", Unlock and Move offered."""
    custody = _CustodyStub(mode="vault", resolution="passphrase")
    app = _CustodyApp(_KeySyncStub(configured=False, key_source=None), custody, vault_unlocked=True)
    async with app.run_test(headless=True, size=(160, 50)) as pilot:
        await _open(app, pilot)
        assert custody.resolve_calls == 1 and custody.mode_calls == 0
        assert _label(app, "msync_btn_setup") == "Unlock Memory Sync"
        assert _label(app, "msync_btn_move_to_vault") == "Move key to vault"
        assert "msync_vault_body" not in _ids(app)


@pytest.mark.asyncio
async def test_a_passphrase_account_whose_vault_is_elsewhere_still_gets_an_unlock_button() -> None:
    """Not "Add this device to your vault first" with no way in: a passphrase user can unlock."""
    custody = _CustodyStub(mode="needs_vault_device", resolution="passphrase")
    app = _CustodyApp(_KeySyncStub(configured=False, key_source=None), custody)
    async with app.run_test(headless=True, size=(160, 50)) as pilot:
        await _open(app, pilot)
        assert _label(app, "msync_btn_setup") == "Unlock Memory Sync"
        assert "msync_btn_move_to_vault" not in _ids(app)
        assert custody.mode_calls == 0


@pytest.mark.asyncio
async def test_only_an_account_without_a_key_uses_the_enrolment_cards() -> None:
    custody = _CustodyStub(mode="needs_vault_device", resolution="not_enrolled")
    app = _CustodyApp(_KeySyncStub(configured=False, key_source=None), custody)
    async with app.run_test(headless=True, size=(160, 50)) as pilot:
        await _open(app, pilot)
        assert custody.mode_calls == 1
        assert "msync_btn_setup" not in _ids(app) and "msync_btn_open_vault" in _ids(app)


@pytest.mark.asyncio
async def test_a_key_loaded_from_an_unfinished_move_offers_to_finish_it() -> None:
    sync = _KeySyncStub(configured=True, key_source="vault_pending")
    app = _CustodyApp(sync, _CustodyStub(), vault_unlocked=True)
    with patch("servonaut.services.memory.passphrase_store.keyring_available", return_value=False):
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await _open(app, pilot)
            assert _label(app, "msync_btn_move_to_vault") == "Move key to vault"
            assert "msync_key_value" not in _ids(app)  # not "kept in your vault" yet


@pytest.mark.asyncio
async def test_an_open_vault_with_no_key_loaded_offers_a_retry_not_unlock_the_vault() -> None:
    app = _STATE_BUILDERS["vault_retry"]()
    async with app.run_test(headless=True, size=(160, 50)) as pilot:
        await _open(app, pilot)
        ids = _ids(app)
        assert "msync_btn_unlock_vault" in ids and "msync_btn_open_vault" not in ids
        await click_action(pilot, "#msync_btn_unlock_vault")
        await wait_until(lambda: app.bootstrap_calls == 1)


@pytest.mark.asyncio
async def test_disable_holds_in_vault_mode_until_the_user_enables_it_again() -> None:
    sync = _DisableSyncStub(configured=True, key_source="vault")
    app = _CustodyApp(sync, _CustodyStub(marker_vault=True), vault_unlocked=True)
    app.config_manager = _ConfigStore(MemoryConfig())
    with patch("servonaut.services.memory.passphrase_store.keyring_available", return_value=False), patch(
        "servonaut.services.memory.passphrase_store.clear_passphrase",
    ):
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await _open(app, pilot)
            await _press(app, pilot, "msync_btn_disable", lambda: "msync_btn_enable" in _ids(app))
            # The flag survives: no marker-says-vault card, no unlock trigger.
            assert app.config_manager.memory.sync_disabled is True
            assert "msync_btn_unlock_vault" not in _ids(app)
            assert "msync_btn_open_vault" not in _ids(app)
            assert app.bootstrap_calls == 0
            await _press(app, pilot, "msync_btn_enable", lambda: app.bootstrap_calls == 1)
            assert app.config_manager.memory.sync_disabled is False
