"""Small structural tests for the vault TUI surface."""
from __future__ import annotations

import asyncio
from html import unescape
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from textual.app import App, ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, DataTable, Static

from servonaut.screens.ca import CaScreen
from servonaut.screens.vault import (
    VaultImportedReferenceModal,
    VaultPendingDeviceModal,
    VaultRecoveryConfirmModal,
    VaultScreen,
    show_pending_device,
)
from servonaut.styles import CSS_FILES
from tests._async_bounds import wait_until

def test_vault_screen_exposes_safe_metadata_actions() -> None:
    actions = {binding.action for binding in VaultScreen.BINDINGS}

    assert {"back", "refresh", "reveal", "exposures"}.issubset(actions)


def test_vault_screen_rotates_exposures_with_per_host_results() -> None:
    source = Path("src/servonaut/screens/vault.py").read_text()

    assert '"rotate_ssh_key"' in source
    assert 'table.add_columns("Server", "Status", "Detail")' in source
    assert '"ROTATE"' in source


def test_vault_screen_uses_verified_device_callbacks_and_reset_polling() -> None:
    source = Path("src/servonaut/screens/vault.py").read_text()

    assert "async def show_pending_device" in source
    assert "VaultPendingDeviceModal(device)" in source
    assert '"drain_device_pending_events"' in source
    assert '"poll_reset_identity"' in source
    assert '"approval_poll_delay"' in source


class _VaultStatusService:
    def __init__(self, *, remote_identity, local_identity=None, unlock=False, unlock_error=False) -> None:
        self._status = {"remote": {"identity": remote_identity}, "local_identity": local_identity}
        self._unlock = unlock
        self._unlock_error = unlock_error
        self.list_calls = 0
        self.device_calls = 0

    async def status(self):
        return self._status

    def unlock_existing_identity(self):
        if self._unlock_error:
            raise RuntimeError("custody detail must not render")
        return self._unlock

    async def list_vaults(self):
        self.list_calls += 1
        return []

    async def list_devices(self):
        self.device_calls += 1
        return []


class _VaultHost(App):
    def __init__(self, service) -> None:
        self.vault_command_service = service
        self.vault_available = True
        super().__init__()

    def on_mount(self) -> None:
        self.push_screen(VaultScreen())


class _StyledVaultHost(_VaultHost):
    """Load product styles so compact-layout geometry is tested as users see it."""

    CSS_PATH = CSS_FILES


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("size", "remote_identity", "expected", "enabled"),
    [
        ((160, 50), None, "No vault identity exists yet", {"vault_setup"}),
        ((70, 30), {"identity_id": "remote-only"}, "vault identity on another device", {"vault_recover", "vault_add_device"}),
    ],
)
async def test_status_first_vault_flow_only_enables_safe_next_action(
    size, remote_identity, expected, enabled,
) -> None:
    service = _VaultStatusService(remote_identity=remote_identity)
    app = _VaultHost(service)

    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        assert expected in str(screen.query_one("#vault_status", Static).render())
        assert service.list_calls == 0
        screen.action_devices()
        await pilot.pause()
        assert service.device_calls == 0
        action_ids = set(VaultScreen._READY_ACTIONS) | {"vault_setup", "vault_recover", "vault_add_device"}
        for button_id in action_ids:
            assert screen.query_one(f"#{button_id}", Button).disabled is (button_id not in enabled)


@pytest.mark.asyncio
async def test_locked_or_foreign_custody_does_not_become_a_first_user() -> None:
    service = _VaultStatusService(remote_identity=None, unlock_error=True)
    app = _VaultHost(service)

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        status = str(screen.query_one("#vault_status", Static).render())
        assert "could not be unlocked" in status
        assert "custody detail" not in status
        assert service.list_calls == 0
        for button_id in set(VaultScreen._READY_ACTIONS) | {"vault_setup", "vault_recover", "vault_add_device"}:
            assert screen.query_one(f"#{button_id}", Button).disabled


@pytest.mark.asyncio
async def test_unlocked_local_identity_is_the_only_state_that_reads_vaults() -> None:
    service = _VaultStatusService(remote_identity={"identity_id": "remote"}, local_identity="local-fingerprint")
    app = _VaultHost(service)

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        assert "Identity fingerprint: local-fingerprint" in str(screen.query_one("#vault_status", Static).render())
        assert service.list_calls == 1
        assert not screen.query_one("#vault_items", Button).disabled
        assert screen.query_one("#vault_setup", Button).disabled
        assert screen.query_one("#vault_recover", Button).disabled


@pytest.mark.asyncio
async def test_narrow_vault_keeps_metadata_visible_and_scrolls_clear_actions() -> None:
    class DelayedService(_VaultStatusService):
        def __init__(self) -> None:
            super().__init__(remote_identity={"identity_id": "remote"}, local_identity="local-fingerprint")
            self.metadata_requested = asyncio.Event()
            self.release_metadata = asyncio.Event()

        async def list_vaults(self):
            self.metadata_requested.set()
            await self.release_metadata.wait()
            return [{
                "name": "Narrow metadata vault",
                "kind": "personal",
                "vault_id": "vault-narrow",
                "counts": {"items": 1, "open_exposures": 0},
            }]

    service = DelayedService()
    app = _StyledVaultHost(service)

    async with app.run_test(size=(100, 30)) as pilot:
        await asyncio.wait_for(service.metadata_requested.wait(), timeout=2)
        service.release_metadata.set()
        table = app.screen.query_one("#vault_table", DataTable)
        await wait_until(lambda: table.row_count == 1)

        screen = app.screen
        assert isinstance(screen, VaultScreen)
        assert screen.has_class("-narrow") and screen.has_class("-short")
        assert table.region.height >= 7
        await pilot.pause()
        screenshot = unescape(app.export_screenshot(simplify=True))
        assert "Name" in screenshot
        assert all(fragment in screenshot for fragment in ("Narrow", "metadata", "vault"))

        action_scroll = screen.query_one("#vault_action_scroll", VerticalScroll)
        assert action_scroll.region.height <= 8
        assert str(screen.query_one("#vault_rotate_exposure", Button).label) == "Rotate exposed SSH key"
        assert str(screen.query_one("#vault_rotate", Button).label) == "Rotate vault key"

        first = screen.query_one("#vault_refresh", Button)
        last = screen.query_one("#vault_rotate", Button)
        first.focus()
        for _ in range(20):
            if last.has_focus:
                break
            await pilot.press("tab")
        assert last.has_focus
        assert action_scroll.scroll_y > 0


@pytest.mark.asyncio
async def test_import_refreshes_selected_vault_counts_before_bitwarden_binding_offer() -> None:
    class DelayedImportService(_VaultStatusService):
        def __init__(self) -> None:
            super().__init__(remote_identity={"identity_id": "remote"}, local_identity="local-fingerprint")
            self.refresh_requested = asyncio.Event()
            self.release_refresh = asyncio.Event()

        async def list_vaults(self):
            self.list_calls += 1
            if self.list_calls == 1:
                return [
                    {"name": "Other vault", "kind": "personal", "vault_id": "vault-other", "counts": {"items": 0, "open_exposures": 0}},
                    {"name": "Imported vault", "kind": "team", "vault_id": "vault-imported", "counts": {"items": 0, "open_exposures": 0}},
                ]
            self.refresh_requested.set()
            await self.release_refresh.wait()
            return [
                {"name": "Other vault", "kind": "personal", "vault_id": "vault-other", "counts": {"items": 0, "open_exposures": 0}},
                {"name": "Imported vault", "kind": "team", "vault_id": "vault-imported", "counts": {"items": 2, "open_exposures": 0}},
            ]

    service = DelayedImportService()
    app = _StyledVaultHost(service)

    async with app.run_test(size=(100, 30)) as pilot:
        table = app.screen.query_one("#vault_table", DataTable)
        await wait_until(lambda: table.row_count == 2)
        table.move_cursor(row=1)
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        offered = AsyncMock()
        screen._offer_imported_bitwarden_binding = offered
        modal_callback = {}
        app.push_screen = lambda _modal, callback: modal_callback.setdefault("imported", callback)
        screen.action_import()
        modal_callback["imported"]({
            "imported": 2,
            "failed": 0,
            "references": [{"source": "bitwarden", "vault_item_id": "item-1", "source_ref": "bw-1"}],
        })
        await asyncio.wait_for(service.refresh_requested.wait(), timeout=2)
        service.release_refresh.set()
        await wait_until(lambda: table.cursor_row == 1 and offered.await_count == 1)

        assert screen._selected_vault_id == "vault-imported"
        assert "2 imported, 0 failed" in str(screen.query_one("#vault_status", Static).render())
        assert "2" in str(table.get_row_at(1))
        offered.assert_awaited_once_with("vault-imported", [{"source": "bitwarden", "vault_item_id": "item-1", "source_ref": "bw-1"}])


@pytest.mark.asyncio
async def test_setup_result_is_purposeful_metadata_not_raw_identity_payload() -> None:
    class Service:
        async def setup(self, **_kwargs):
            return {"identity": {"identity_id": "not-for-status", "sig_public_key": "public-data"}}

    app = _VaultHost(Service())
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        await screen._setup(lambda _key: True)
        status = str(screen.query_one("#vault_status", Static).render())
        assert "Vault identity setup completed" in status
        assert "not-for-status" not in status
        assert not screen.query_one("#vault_items", Button).disabled


@pytest.mark.asyncio
async def test_demo_toggle_redraws_cached_vault_metadata_without_fetching_again() -> None:
    class Redactor:
        def scrub_stream(self, _text: str) -> str:
            return "redacted"

    service = _VaultStatusService(remote_identity={"identity_id": "remote"}, local_identity="local")
    service.list_vaults = AsyncMock(return_value=[{"name": "private-vault-name", "kind": "personal", "vault_id": "vault-private", "counts": {}}])
    app = _VaultHost(service)
    app.demo_mode = False
    app.redaction_service = Redactor()

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        assert "private-vault-name" in str(screen.query_one("#vault_table", DataTable).get_row_at(0))
        app.demo_mode = True
        screen.refresh_after_demo_toggle()
        assert "private-vault-name" not in str(screen.query_one("#vault_table", DataTable).get_row_at(0))
        assert "redacted" in str(screen.query_one("#vault_table", DataTable).get_row_at(0))
        assert service.list_vaults.await_count == 1


@pytest.mark.asyncio
async def test_demo_mode_redacts_ca_status_and_repaints_cached_value() -> None:
    class Redactor:
        def scrub_stream(self, _text: str) -> str:
            return "redacted CA status"

    class Service:
        async def ca_status(self, *, team: str):
            assert team == "private-team"
            return {"hostname": "private-ca-host", "enabled": True}

    class Host(App):
        demo_mode = True
        redaction_service = Redactor()
        vault_command_service = Service()

        def on_mount(self) -> None:
            self.push_screen(CaScreen())

    app = Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, CaScreen)
        await screen._load("private-team")
        rendered = str(screen.query_one("#ca_status", Static).render())
        assert "private-ca-host" not in rendered
        assert "redacted CA status" in rendered
        app.demo_mode = False
        screen.refresh_after_demo_toggle()
        assert "private-ca-host" in str(screen.query_one("#ca_status", Static).render())


@pytest.mark.asyncio
async def test_pending_device_modal_is_presented_while_fleet_is_active() -> None:
    class FleetScreen(Screen):
        def compose(self) -> ComposeResult:
            yield Static("Fleet", id="fleet_label")

    class Host(App):
        def on_mount(self) -> None:
            self.push_screen(FleetScreen())

    app = Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, FleetScreen)
        presenter = asyncio.create_task(
            show_pending_device(
                app,
                object(),
                {"device_id": "device-1", "name": "New laptop", "platform": "linux"},
            )
        )
        await pilot.pause()
        assert isinstance(app.screen, VaultPendingDeviceModal)
        await pilot.click("#vault_pending_device_later")
        await presenter
        assert isinstance(app.screen, FleetScreen)


@pytest.mark.asyncio
async def test_imported_bitwarden_reference_requires_explicit_tui_selection() -> None:
    reference = {"vault_item_id": "vault-item-1", "source_ref": "bitwarden-item-1"}

    class Host(App):
        selected = None

        def on_mount(self) -> None:
            self.run_worker(self.choose())

        async def choose(self) -> None:
            self.selected = await self.push_screen_wait(VaultImportedReferenceModal([reference]))

    app = Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, VaultImportedReferenceModal)
        await pilot.click("#vault_import_bind_continue")
        await pilot.pause()
        assert app.selected == reference


def test_ca_screen_exposes_refresh() -> None:
    actions = {binding.action for binding in CaScreen.BINDINGS}

    assert {"back", "refresh"}.issubset(actions)


def test_native_server_action_passes_public_identity_file() -> None:
    source = Path("src/servonaut/screens/server_actions.py").read_text()

    assert 'identity_file=getattr(resolved, "identity_file", None)' in source
    assert 'not getattr(resolved, "identity_file", None)' in source
    assert '"servonaut_vault": "Servonaut Vault"' in source


def test_recovery_modal_challenges_only_secret_groups(monkeypatch) -> None:
    candidate_indices: list[int] = []

    def sample(_self, population, _count):
        candidate_indices.extend(population)
        return [1, 2]

    monkeypatch.setattr("servonaut.screens.vault.secrets.SystemRandom.sample", sample)

    modal = VaultRecoveryConfirmModal("SVRK1-ABCDE-FGHIJ")

    assert candidate_indices == [1, 2]
    assert modal._checks == [1, 2]


def test_recovery_modal_requires_two_secret_groups() -> None:
    assert VaultRecoveryConfirmModal("SVRK1-ABCDE")._checks == []



def test_rotation_summary_says_what_happened_to_the_exposure() -> None:
    from servonaut.screens.vault import _rotation_summary

    assert _rotation_summary({"resolved": ["e-1"], "needs_owner": False, "failed": []}).endswith(
        "1 exposure resolved as rotated."
    )
    assert "Ask an owner or admin to resolve the exposure." in _rotation_summary(
        {"resolved": [], "needs_owner": True, "failed": []}
    )
    assert "could not be marked resolved (HTTP 500)" in _rotation_summary(
        {"resolved": [], "needs_owner": False, "failed": [{"exposure_id": "e-1", "reason": "HTTP 500"}]}
    )
    assert _rotation_summary(None) == "SSH key rotation completed on all selected hosts."


@pytest.mark.asyncio
async def test_exposure_table_notes_a_key_replaced_in_the_vault() -> None:
    class Service(_VaultStatusService):
        async def list_exposures(self, *, vault_id):
            return {"data": [
                {"exposure_id": "e-1", "item_id": "i", "subject": "member", "reason": "member_removed", "key_replaced": True},
                {"exposure_id": "e-2", "item_id": "j", "subject": "member", "reason": "member_removed", "key_replaced": False},
            ]}

    service = Service(remote_identity={"identity_id": "remote"}, local_identity="local-fingerprint")
    app = _VaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await wait_until(lambda: "Identity fingerprint" in str(screen.query_one("#vault_status", Static).render()))
        screen._selected_vault_id = "vault-1"
        await screen._load_exposures()
        table = screen.query_one("#vault_table", DataTable)
        rows = [table.get_row_at(index) for index in range(table.row_count)]

    assert rows[0][2] == "Key replaced in vault; old key may still be on servers"
    assert rows[1][2] == ""
