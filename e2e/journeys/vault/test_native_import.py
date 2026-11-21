"""Native-vault SSH import journeys against the strict fake cloud."""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from textual.app import App
from textual.widgets import Button, DataTable, Input, SelectionList, Static

from e2e.harness.waits import wait_for_async
from servonaut.screens.vault import VaultScreen
from servonaut.screens.vault_import_modal import VaultImportModal
from servonaut.services.api_client import APIClient
from servonaut.services.auth_service import AuthService
from servonaut.services.bw_key_import import OPENSSH_PEM_HEADER
from servonaut.services.vault.command_service import VaultCommandService
from servonaut.services.vault.errors import VaultUserError
from servonaut.services.vault.identity_store import IdentityStore, LocalDevice, LocalIdentity
from servonaut.widgets.filterable_selection import FilterableSelection


pytestmark = [pytest.mark.e2e_pr]


def _vault_config() -> SimpleNamespace:
    return SimpleNamespace(vault=SimpleNamespace(
        allow_file_key_store=False,
        request_timeout_seconds=30.0,
        binding_read_cache_seconds=60.0,
        binding_read_backoff_seconds=60.0,
        strict_verification=False,
        auto_grant=True,
        agent_key_ttl_seconds=60,
        poll_after_seconds=300,
        approval_poll_initial_seconds=0.01,
        approval_poll_max_seconds=0.02,
    ))


def _native_service(fake_cloud: Any, home: Path, monkeypatch: pytest.MonkeyPatch) -> VaultCommandService:
    import servonaut.services.auth_service as auth_module

    monkeypatch.setattr(auth_module, "AUTH_FILE", home / ".servonaut" / "auth.json")
    auth = AuthService()
    user_id = auth.user_id
    assert isinstance(user_id, int)
    persona = fake_cloud.vault.seed_identity(user_id)
    identity = persona["identity"]
    store = IdentityStore(home / ".servonaut" / "vault" / "identity.json")
    store.adopt(LocalIdentity(
        identity["identity_id"],
        user_id,
        base64.b64decode(persona["identity_signing_key"]),
        base64.b64decode(persona["identity_encryption_key"]),
        LocalDevice(
            persona["device"]["device_id"],
            base64.b64decode(persona["device_signing_key"]),
            base64.b64decode(persona["device_encryption_key"]),
        ),
    ))
    return VaultCommandService(APIClient(auth), auth, _vault_config(), store=store)


@pytest.mark.asyncio
@pytest.mark.parametrize("import_delay_seconds", [0.0, 0.1], ids=["immediate", "delayed"])
async def test_modal_imports_valid_local_key_and_refuses_malformed_source(
    fake_cloud: Any,
    account_home: Any,
    monkeypatch: pytest.MonkeyPatch,
    import_delay_seconds: float,
) -> None:
    """A usable local key becomes one encrypted item; malformed input never writes."""
    sandbox = account_home("native-import")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    vault = await service.create_vault(team=None, name="Personal vault", grant_policy="auto")
    keys = sandbox.home / "keys"
    keys.mkdir()
    valid_key = Ed25519PrivateKey.generate().private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption(),
    )
    (keys / "id_ed25519").write_bytes(valid_key)
    (keys / "malformed").write_bytes(OPENSSH_PEM_HEADER.encode() + b"\ncorrupt")
    completed_write = asyncio.Event()
    import_keys = service.import_keys

    async def delayed_import_keys(**kwargs: Any) -> dict[str, Any]:
        await asyncio.sleep(import_delay_seconds)
        result = await import_keys(**kwargs)
        completed_write.set()
        return result

    service.import_keys = delayed_import_keys  # type: ignore[method-assign]

    class ImportHost(App):
        result: dict[str, Any] | None = None

        def on_mount(self) -> None:
            self.push_screen(VaultImportModal(service, vault["vault_id"], keys), self._finished)

        def _finished(self, result: dict[str, Any] | None) -> None:
            self.result = result

    app = ImportHost()
    async with app.run_test(size=(70, 30)) as pilot:
        await wait_for_async(
            lambda: app.screen if isinstance(app.screen, VaultImportModal) else None,
            desc="the native import modal",
        )
        await pilot.click("#vault_import_local")
        listing = await wait_for_async(
            lambda: _ready_listing(app), desc="the scanned local key options",
        )
        assert listing.option_count == 2
        assert listing.get_option_at_index(1).disabled is True
        assert list(listing.selected) == [0]
        confirm = app.screen.query_one("#vault_import_confirm", Button)
        assert confirm.disabled is False
        confirm.press()
        await wait_for_async(completed_write.is_set, desc="the signed vault item write")
        await wait_for_async(lambda: app.result, desc="the import result")

    assert app.result is not None
    assert app.result["imported"] == 1
    assert app.result["failed"] == 0
    assert len((await service.list_items(vault_id=vault["vault_id"]))["data"]) == 1
    with pytest.raises(VaultUserError, match="OpenSSH private key, unlocked or with its passphrase"):
        await service.import_keys(
            source="ssh", vault_id=vault["vault_id"], path="/invalid", private_key=b"invalid",
        )
    assert len((await service.list_items(vault_id=vault["vault_id"]))["data"]) == 1


def _ready_listing(app: App) -> SelectionList | None:
    """Return only a fully populated, idle local-key selection list."""
    if not isinstance(app.screen, VaultImportModal) or app.screen._loading:
        return None
    listing = app.screen.query_one("#vault_import_list", SelectionList)
    return listing if listing.option_count == 2 else None


class _VaultScreenHost(App):
    """Hosts the Vault screen with a native command service."""

    def __init__(self, service: VaultCommandService) -> None:
        self.vault_command_service = service
        self.vault_available = True
        self.bw_session_service = None
        self.instances: list[dict[str, Any]] = []
        super().__init__()

    def on_mount(self) -> None:
        self.push_screen(VaultScreen())


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)], ids=["wide", "narrow"])
async def test_import_dialog_marks_a_key_the_vault_holds_and_imports_only_the_new_one(
    fake_cloud: Any,
    account_home: Any,
    monkeypatch: pytest.MonkeyPatch,
    size: tuple[int, int],
) -> None:
    """A stored key is shown as already in the vault and cannot be picked again."""
    sandbox = account_home("native-import-duplicate")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    vault = await service.create_vault(team=None, name="Personal vault", grant_policy="auto")
    vault_id = vault["vault_id"]
    ssh_dir = sandbox.home / ".ssh"
    ssh_dir.mkdir()
    for filename in ("stored_key", "new_key"):
        (ssh_dir / filename).write_bytes(Ed25519PrivateKey.generate().private_bytes(
            Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption(),
        ))
        (ssh_dir / filename).chmod(0o600)
    await service.import_keys(
        source="ssh", vault_id=vault_id, path=str(ssh_dir / "stored_key"), name="stored-key",
    )
    monkeypatch.setenv("HOME", str(sandbox.home))

    app = _VaultScreenHost(service)
    async with app.run_test(size=size) as pilot:
        screen = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, VaultScreen) else None, desc="the Vault screen",
        )
        await wait_for_async(lambda: screen.query_one("#vault_table", DataTable).row_count >= 1, desc="the vaults table")
        import_button = screen.query_one("#vault_import", Button)
        await wait_for_async(lambda: not import_button.disabled, desc="the import button")
        import_button.press()
        modal = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, VaultImportModal) and app.screen.query("#vault_import_local") else None,
            desc="the import dialog",
        )
        modal.query_one("#vault_import_local", Button).press()
        listing = await wait_for_async(lambda: _ready_listing(app), desc="the scanned local key options")

        rows = {
            option.value: option for option in (listing.get_option_at_index(i) for i in range(listing.option_count))
        }
        stored = next(o for o in rows.values() if "already in this vault as stored-key" in str(o.prompt))
        other = next(o for o in rows.values() if o is not stored)
        assert stored.disabled is True
        assert stored.value not in listing.selected
        assert "already in this vault" not in str(other.prompt)
        assert list(listing.selected) == [other.value]
        picker = modal.query_one(FilterableSelection)
        search = modal.query_one("#vault_import_search", Input)
        # Filter down to the new key's file, select every shown row, then clear the filter.
        search.value = "new_key"
        await wait_for_async(lambda: listing.option_count == 1, desc="one row shown for the filter")
        modal.query_one("#vault_import_all", Button).press()
        await wait_for_async(
            lambda: picker.selected == [other.value], desc="the shown row selected",
        )
        search.value = ""
        await wait_for_async(lambda: listing.option_count == 2, desc="both rows shown again")
        assert stored.value not in picker.selected
        shown_stored = next(
            listing.get_option_at_index(i) for i in range(listing.option_count)
            if listing.get_option_at_index(i).value == stored.value
        )
        assert shown_stored.disabled is True
        assert "already in this vault as stored-key" in str(shown_stored.prompt)
        listing.focus()
        listing.highlighted = stored.value  # option value is its index
        await pilot.press("space")
        await pilot.pause()
        assert stored.value not in listing.selected

        confirm = modal.query_one("#vault_import_confirm", Button)
        assert confirm.disabled is False
        confirm.press()
        await wait_for_async(lambda: app.screen is screen, desc="the dialog to close")
        await wait_for_async(
            lambda: "1 imported, 0 failed, 0 skipped: already in vault"
            in str(screen.query_one("#vault_status", Static).render()),
            desc="the import status",
        )
        # The status is shown before the vault list is re-read; leaving earlier
        # would tear the screen down under that refresh.
        await wait_for_async(
            lambda: not screen._busy_work and all(w.is_finished for w in screen.workers),
            desc="the vault refresh after the import",
        )

    live = [item for item in fake_cloud.vault._items[vault_id].values() if not item.get("deleted_at")]
    assert len(live) == 2
