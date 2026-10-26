"""End-to-end TUI journeys for vault SSH key names, rename, and delete.

Validates that:
1. Importing keys from Bitwarden retains the Bitwarden item's name (rather than
   falling back to a generic default), renders those names in the Vault screen's
   items table, and enables Auto-bind keys to match servers to their key pair.
2. A key can be renamed from the Vault screen items table; empty/invalid names are
   refused before writing, and successful renames update the table and fake cloud.
3. Deleting an in-use key is refused with a notice naming the bound servers and
   without issuing a DELETE request; deleting an unused key prompts for typed
   confirmation ("DELETE"), handles cancellation cleanly, and records the tombstone
   on confirmation.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping, Optional

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from textual.app import App
from textual.widgets import Button, DataTable, Input, SelectionList, Static

from e2e.harness import fleet
from e2e.harness.bitwarden import FakeBitwarden
from e2e.harness.waits import wait_for_async
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.vault import VaultImportedReferenceModal, VaultScreen
from servonaut.screens.vault_auto_bind import VaultAutoBindScreen
from servonaut.screens.vault_import_modal import VaultImportModal
from servonaut.services.api_client import APIClient
from servonaut.services.auth_service import AuthService
from servonaut.services.bw_session_service import BwSessionService
from servonaut.services.vault.auto_bind import plan_auto_bind
from servonaut.services.vault.command_service import VaultCommandService
from servonaut.services.vault.identity_store import IdentityStore, LocalDevice, LocalIdentity

pytestmark = [pytest.mark.e2e_pr]

SERVER_1 = {
    **fleet.EDGE_1.cache_row(),
    "key_name": "ops-key",
    "login_user": "ubuntu",
}

SERVER_2 = {
    **fleet.BASTION_1.cache_row(),
    "key_name": "web-key",
    "login_user": "ubuntu",
}


def _vault_config() -> SimpleNamespace:
    return SimpleNamespace(
        default_username="ubuntu",
        vault=SimpleNamespace(
            allow_file_key_store=False,
            request_timeout_seconds=30.0,
            strict_verification=False,
            auto_grant=True,
            agent_key_ttl_seconds=60,
            poll_after_seconds=300,
            approval_poll_initial_seconds=0.01,
            approval_poll_max_seconds=0.02,
        ),
    )


def _native_service(
    fake_cloud: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> VaultCommandService:
    import servonaut.services.auth_service as auth_module

    monkeypatch.setattr(auth_module, "AUTH_FILE", home / ".servonaut" / "auth.json")
    auth = AuthService()
    user_id = auth.user_id
    assert isinstance(user_id, int)
    persona = fake_cloud.vault.seed_identity(user_id)
    identity = persona["identity"]
    store = IdentityStore(home / ".servonaut" / "vault" / "identity.json")
    store.adopt(
        LocalIdentity(
            identity["identity_id"],
            user_id,
            base64.b64decode(persona["identity_signing_key"]),
            base64.b64decode(persona["identity_encryption_key"]),
            LocalDevice(
                persona["device"]["device_id"],
                base64.b64decode(persona["device_signing_key"]),
                base64.b64decode(persona["device_encryption_key"]),
            ),
        )
    )
    return VaultCommandService(APIClient(auth), auth, _vault_config(), store=store)


def _ed25519_key_pair() -> tuple[str, str]:
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
    ).decode("utf-8")
    public_ssh = key.public_key().public_bytes(
        Encoding.OpenSSH, PublicFormat.OpenSSH
    ).decode("ascii")
    return private_pem, public_ssh


def _host_key() -> str:
    public = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    )
    return public.decode("ascii")


def _plain(cell: Any) -> str:
    return cell.plain if hasattr(cell, "plain") else str(cell)


class _VaultHost(App):
    """Host harness for the Vault screen with session service and inventory."""

    def __init__(
        self,
        service: Any,
        session_service: Optional[BwSessionService] = None,
        instances: Optional[list[Mapping[str, Any]]] = None,
    ) -> None:
        self.vault_command_service = service
        self.vault_available = True
        self.bw_session_service = session_service
        self.instances = instances or []
        self.notifications: list[str] = []
        super().__init__()

    def on_mount(self) -> None:
        self.push_screen(VaultScreen())

    def notify(self, message: str, **kwargs: Any) -> None:
        self.notifications.append(str(message))
        super().notify(message, **kwargs)


@pytest.mark.asyncio
async def test_import_from_bitwarden_retains_names_and_matches_auto_bind(
    fake_cloud: Any,
    journey: Any,
    account_home: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Importing from Bitwarden keeps item names, showing them in the table and matching key pairs."""
    sandbox = account_home("vault-bw-key-names")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    vault = await service.create_vault(team=None, name="Personal vault", grant_policy="auto")

    # Seed Bitwarden fake with two SSH items named like our AWS servers' key pairs.
    bw_fake = FakeBitwarden(journey.shims, tools=("bw",))
    ops_priv, ops_pub = _ed25519_key_pair()
    web_priv, web_pub = _ed25519_key_pair()
    bw_fake.add_ssh_key_item("ops-key", ops_priv, ops_pub)
    bw_fake.add_ssh_key_item("web-key", web_priv, web_pub)

    # Wire environment so bw CLI shim and session service authenticate.
    monkeypatch.setenv("PATH", f"{journey.shims.directory}:{os.environ['PATH']}")
    monkeypatch.setenv("BW_SESSION", bw_fake.session)
    bw_session = BwSessionService()

    app = _VaultHost(service, session_service=bw_session, instances=[SERVER_1, SERVER_2])
    async with app.run_test(size=(160, 50)):
        screen = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, VaultScreen) else None,
            desc="the Vault screen",
        )

        # Wait for personal vault to be loaded in the vaults table.
        table = screen.query_one("#vault_table", DataTable)
        await wait_for_async(lambda: table.row_count >= 1, desc="the vaults table")

        # Open import modal via action row button.
        import_btn = screen.query_one("#vault_import", Button)
        await wait_for_async(lambda: not import_btn.disabled, desc="vault import button enabled")
        import_btn.press()

        modal = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, VaultImportModal) and app.screen.query("#vault_import_bitwarden") else None,
            desc="the vault import wizard modal",
        )

        # Switch to Bitwarden source.
        modal.query_one("#vault_import_bitwarden", Button).press()

        # Wait for scanned Bitwarden options to load.
        listing = await wait_for_async(
            lambda: (
                modal.query_one("#vault_import_list", SelectionList)
                if modal.query("#vault_import_list")
                and modal.query_one("#vault_import_list", SelectionList).option_count == 2
                else None
            ),
            desc="the two Bitwarden key candidates",
        )
        assert listing.option_count == 2
        for idx in range(listing.option_count):
            listing.select(idx)

        confirm = modal.query_one("#vault_import_confirm", Button)
        await wait_for_async(lambda: not confirm.disabled, desc="import confirm button")
        confirm.press()

        # The import modal closes. If an optional team-migration modal is offered, dismiss it.
        def _dismiss_migration_if_open() -> bool:
            if isinstance(app.screen, VaultImportedReferenceModal):
                if cancel_btn := app.screen.query("#vault_import_bind_cancel"):
                    cancel_btn.first(Button).press()
                    return False
            return not isinstance(app.screen, VaultImportModal) and app.screen is screen and not screen._busy_work

        await wait_for_async(_dismiss_migration_if_open, desc="return to VaultScreen after import")

        # Switch to items view.
        items_btn = screen.query_one("#vault_items", Button)
        await wait_for_async(lambda: not items_btn.disabled and not screen._busy_work, desc="vault items button")
        items_btn.press()

        # The table should show both imported keys with their Bitwarden names in column 0.
        await wait_for_async(
            lambda: screen._table_mode == "items" and table.row_count == 2,
            desc="items table with 2 rows",
        )
        names = {_plain(table.get_row_at(r)[0]) for r in range(table.row_count)}
        assert names == {"ops-key", "web-key"}, f"unexpected names in items table: {names}"

        # Open Auto-bind screen from the Vault screen action row.
        auto_bind_btn = screen.query_one("#vault_auto_bind", Button)
        await wait_for_async(lambda: not auto_bind_btn.disabled, desc="auto-bind button")
        auto_bind_btn.press()

        auto_screen = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, VaultAutoBindScreen) else None,
            desc="the VaultAutoBindScreen",
        )

        # The review table matches edge-1 to ops-key and bastion-1 to web-key by key pair.
        auto_table = auto_screen.query_one("#auto_bind_table", DataTable)
        await wait_for_async(
            lambda: auto_table.row_count == 2,
            desc="auto-bind review table with both server rows",
        )
        auto_text = " ".join(
            _plain(cell)
            for r in range(auto_table.row_count)
            for cell in auto_table.get_row_at(r)
        )
        assert "ops-key" in auto_text
        assert "web-key" in auto_text
        assert "key pair" in auto_text

    # Also prove via service call that plan_auto_bind matched each server correctly.
    choices = await service.ssh_key_choices(vault_id=vault["vault_id"], name_limit=None)
    planned = await plan_auto_bind(service, [SERVER_1, SERVER_2], choices)
    by_name = {row.instance["name"]: row for row in planned}
    assert by_name["edge-1"].match is not None
    assert by_name["edge-1"].match.name == "ops-key"
    assert by_name["edge-1"].match.matched_by == "key pair"
    assert by_name["bastion-1"].match is not None
    assert by_name["bastion-1"].match.name == "web-key"
    assert by_name["bastion-1"].match.matched_by == "key pair"


@pytest.mark.asyncio
async def test_rename_vault_key_updates_table_and_validates_input(
    fake_cloud: Any,
    journey: Any,
    account_home: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Renaming an SSH key validates input, updates the items table, and writes to fake cloud."""
    sandbox = account_home("vault-rename-key")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    vault = await service.create_vault(team=None, name="Personal vault", grant_policy="auto")

    # Import one initial key named "ops-key".
    priv, _ = _ed25519_key_pair()
    imported = await service.import_keys(
        source="ssh",
        vault_id=vault["vault_id"],
        path="/fake/ops-key.pem",
        private_key=priv.encode("utf-8"),
        name="ops-key",
    )
    item_id = imported["item_id"]
    item_route = f"/api/v1/vaults/{vault['vault_id']}/items/{item_id}"

    app = _VaultHost(service, instances=[SERVER_1])
    async with app.run_test(size=(160, 50)):
        screen = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, VaultScreen) else None,
            desc="the Vault screen",
        )

        table = screen.query_one("#vault_table", DataTable)
        await wait_for_async(lambda: table.row_count >= 1, desc="vault loaded")

        # Switch to items view.
        items_btn = screen.query_one("#vault_items", Button)
        await wait_for_async(lambda: not items_btn.disabled, desc="items button")
        items_btn.press()

        await wait_for_async(
            lambda: screen._table_mode == "items" and table.row_count == 1,
            desc="items table loaded",
        )
        assert _plain(table.get_row_at(0)[0]) == "ops-key"

        # Select the item row and press Rename key.
        rename_btn = screen.query_one("#vault_rename_key", Button)
        await wait_for_async(lambda: not rename_btn.disabled, desc="rename key button")
        rename_btn.press()

        # The rename modal opens with input prefilled with current name.
        modal = await wait_for_async(
            lambda: app.screen if app.screen is not screen and app.screen.query("#vault_rename_key_input") else None,
            desc="the rename key modal screen",
        )
        name_input = modal.query_one("#vault_rename_key_input", Input)
        assert name_input.value == "ops-key"

        save_btn = modal.query_one("#vault_rename_key_save", Button)
        feedback = modal.query_one("#vault_rename_key_feedback", Static)

        # Record PUT requests before the blank attempt.
        puts_before = len(fake_cloud.requests(path=item_route, method="PUT"))

        # 1. Blank name is refused: clear input and attempt save.
        name_input.value = "   "
        save_btn.press()

        # Wait for validation feedback to appear in the modal without a fixed sleep.
        await wait_for_async(
            lambda: "Name is required" in str(feedback.render()),
            desc="validation feedback in rename modal",
        )
        assert app.screen is modal, "modal must remain active on validation failure"
        assert len(fake_cloud.requests(path=item_route, method="PUT")) == puts_before

        # 2. Enter a valid new name.
        name_input.value = "ops-key-renamed"
        save_btn.press()

        # Modal dismisses and returns to VaultScreen.
        await wait_for_async(lambda: app.screen is screen, desc="return to VaultScreen")

        # Items table updates and shows the exact new name in column 0.
        await wait_for_async(
            lambda: _plain(table.get_row_at(0)[0]) == "ops-key-renamed",
            desc="items table row showing exact renamed key",
        )
        names = [_plain(table.get_row_at(r)[0]) for r in range(table.row_count)]
        assert names == ["ops-key-renamed"]

        # Exactly one PUT request reached the fake cloud for the valid rename.
        assert len(fake_cloud.requests(path=item_route, method="PUT")) == puts_before + 1

    # Assert that choice inspection reads the new name.
    choices = await service.ssh_key_choices(vault_id=vault["vault_id"], name_limit=None)
    assert len(choices) == 1
    assert choices[0]["name"] == "ops-key-renamed"


@pytest.mark.asyncio
async def test_delete_vault_key_refuses_bound_and_handles_confirmation(
    fake_cloud: Any,
    journey: Any,
    account_home: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deleting a key bound to a server is refused without calling DELETE; unused keys confirm and delete."""
    sandbox = account_home("vault-delete-key")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    vault = await service.create_vault(team=None, name="Personal vault", grant_policy="auto")

    # Import two keys: one to be bound, one left unused.
    priv_bound, _ = _ed25519_key_pair()
    priv_unused, _ = _ed25519_key_pair()
    item_bound = await service.import_keys(
        source="ssh",
        vault_id=vault["vault_id"],
        path="/fake/bound-key.pem",
        private_key=priv_bound.encode("utf-8"),
        name="bound-key",
    )
    item_unused = await service.import_keys(
        source="ssh",
        vault_id=vault["vault_id"],
        path="/fake/unused-key.pem",
        private_key=priv_unused.encode("utf-8"),
        name="unused-key",
    )
    bound_id = item_bound["item_id"]
    unused_id = item_unused["item_id"]

    # Bind bound-key to SERVER_1 (edge-1).
    await service.bind_personal(
        vault_id=vault["vault_id"],
        item_id=bound_id,
        provider="aws",
        instance_id=fleet.EDGE_1.instance_id,
        hostname=fleet.EDGE_1.public_ip,
        port=22,
        login="ubuntu",
        host_keys=[_host_key()],
        replace_existing=True,
    )

    app = _VaultHost(service, instances=[SERVER_1, SERVER_2])
    async with app.run_test(size=(160, 50)):
        screen = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, VaultScreen) else None,
            desc="the Vault screen",
        )

        table = screen.query_one("#vault_table", DataTable)
        await wait_for_async(lambda: table.row_count >= 1, desc="vault loaded")

        # Switch to items view.
        items_btn = screen.query_one("#vault_items", Button)
        await wait_for_async(lambda: not items_btn.disabled, desc="items button")
        items_btn.press()

        await wait_for_async(
            lambda: screen._table_mode == "items" and table.row_count == 2,
            desc="items table with 2 rows",
        )

        # Locate row index for the bound key and unused key.
        bound_row_idx = next(
            r for r in range(table.row_count) if _plain(table.get_row_at(r)[0]) == "bound-key"
        )
        unused_row_idx = next(
            r for r in range(table.row_count) if _plain(table.get_row_at(r)[0]) == "unused-key"
        )

        delete_btn = screen.query_one("#vault_delete_key", Button)
        await wait_for_async(lambda: not delete_btn.disabled, desc="delete key button")

        # --------------------------------------------------------------
        # 1. Attempt to delete bound key -> Refused, naming server edge-1.
        # --------------------------------------------------------------
        table.move_cursor(row=bound_row_idx)
        delete_btn.press()

        # Refusal notice must mention the bound server name and no confirm modal is shown.
        await wait_for_async(
            lambda: any("edge-1" in n and "used" in n.lower() for n in app.notifications),
            desc="notification naming bound server edge-1",
        )
        assert not isinstance(app.screen, ConfirmActionScreen), "no confirmation offered when key is in use"
        # The refused key's row is still present in the table.
        names_after_refusal = [_plain(table.get_row_at(r)[0]) for r in range(table.row_count)]
        assert "bound-key" in names_after_refusal
        assert len(fake_cloud.requests(path=f"/api/v1/vaults/{vault['vault_id']}/items/{bound_id}", method="DELETE")) == 0

        # --------------------------------------------------------------
        # 2. Cancel delete of unused key -> Nothing deleted.
        # --------------------------------------------------------------
        table.move_cursor(row=unused_row_idx)
        delete_btn.press()

        confirm_modal = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, ConfirmActionScreen) and app.screen.query("#btn_cancel") else None,
            desc="ConfirmActionScreen modal",
        )

        # Cancel confirmation.
        cancel_btn = confirm_modal.query_one("#btn_cancel", Button)
        cancel_btn.press()

        await wait_for_async(lambda: app.screen is screen, desc="return after cancel")
        assert table.row_count == 2, "both keys must remain after cancel"
        assert len(fake_cloud.requests(path=f"/api/v1/vaults/{vault['vault_id']}/items/{unused_id}", method="DELETE")) == 0

        # --------------------------------------------------------------
        # 3. Confirm delete of unused key -> Deleted from table & fake.
        # --------------------------------------------------------------
        table.move_cursor(row=unused_row_idx)
        delete_btn.press()

        confirm_modal = await wait_for_async(
            lambda: (
                app.screen
                if isinstance(app.screen, ConfirmActionScreen)
                and app.screen.query("#confirm_input")
                and app.screen.query("#btn_confirm")
                else None
            ),
            desc="ConfirmActionScreen modal for confirm",
        )

        # Type DELETE to satisfy the confirmation requirement.
        confirm_input = confirm_modal.query_one("#confirm_input", Input)
        confirm_input.value = "DELETE"

        btn_confirm = confirm_modal.query_one("#btn_confirm", Button)
        await wait_for_async(lambda: not btn_confirm.disabled, desc="btn_confirm enabled")
        btn_confirm.press()

        await wait_for_async(lambda: app.screen is screen, desc="return after delete")

        # Table reloads and only the bound key remains.
        await wait_for_async(
            lambda: table.row_count == 1 and _plain(table.get_row_at(0)[0]) == "bound-key",
            desc="items table with only bound-key remaining",
        )

    # Verify that fake cloud recorded the item tombstone and exactly one DELETE occurred.
    items = (await service.list_items(vault_id=vault["vault_id"]))["data"]
    assert len(items) == 1
    assert items[0]["item_id"] == bound_id
    assert len(fake_cloud.requests(path=f"/api/v1/vaults/{vault['vault_id']}/items/{unused_id}", method="DELETE")) == 1
