"""Import refuses a key the target vault already holds."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

import servonaut.services.vault.command_service as module
from servonaut.services.api_client import APIError
from servonaut.services.vault.command_service import VaultCommandService
from servonaut.services.vault.errors import VaultDuplicateKey, VaultUserError

EXISTING_ID = "22222222-2222-4222-8222-222222222222"
VAULT = "11111111-1111-4111-8111-111111111111"
OTHER_VAULT = "33333333-3333-4333-8333-333333333333"


def _pem(passphrase: bytes | None = None) -> bytes:
    encryption = BestAvailableEncryption(passphrase) if passphrase else NoEncryption()
    return Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, encryption)


def _page(*rows: dict) -> dict:
    return {"data": list(rows), "meta": {"next_cursor": None}}


@pytest.fixture
def service() -> VaultCommandService:
    service = VaultCommandService.__new__(VaultCommandService)
    service.items = SimpleNamespace(
        list_items=AsyncMock(return_value=_page()),
        get_item=AsyncMock(return_value={"item_id": EXISTING_ID, "type": "ssh_key"}),
        read_item=MagicMock(side_effect=lambda *_a: {"name": "key-1"}),
        write_item=AsyncMock(return_value={"revision": 1}),
    )
    service.vaults = SimpleNamespace(get_vault=AsyncMock(return_value={"vault_id": VAULT}))
    service._key_names = {}
    return service


def _row(fingerprint: str, item_id: str = EXISTING_ID, **extra) -> dict:
    return {"item_id": item_id, "type": "ssh_key", "public_fingerprint": fingerprint, **extra}


def _fixed_fingerprint(monkeypatch, value: str = "SHA256:dup") -> None:
    monkeypatch.setattr(module.crypto, "ssh_public_fingerprint", lambda _: value)


@pytest.mark.asyncio
async def test_duplicate_is_refused_and_buffer_zeroed(service, monkeypatch) -> None:
    _fixed_fingerprint(monkeypatch)
    service.items.list_items.return_value = _page(_row("SHA256:dup"))
    buffers: list[bytearray] = []

    def tracked(value):
        buffer = bytearray(value)
        buffers.append(buffer)
        return buffer
    monkeypatch.setattr(module, "bytearray", tracked, raising=False)
    material = _pem()
    with pytest.raises(VaultDuplicateKey) as caught:
        await service.import_keys(source="bitwarden", vault_id=VAULT, private_key=material)
    assert caught.value.existing_item_id == EXISTING_ID
    assert caught.value.existing_name == "key-1"
    assert isinstance(caught.value, VaultUserError)
    service.items.write_item.assert_not_awaited()
    assert buffers[0] == bytearray(len(material))


@pytest.mark.asyncio
async def test_passphrase_key_is_checked_after_decryption(service, monkeypatch) -> None:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, BestAvailableEncryption(b"pw"))
    plain = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    fingerprint = module.crypto.ssh_public_fingerprint(plain)
    service.items.list_items.return_value = _page(_row(fingerprint))
    with pytest.raises(VaultDuplicateKey):
        await service.import_keys(source="ssh", vault_id=VAULT, private_key=pem, passphrase=b"pw", path="/k/id")
    service.items.write_item.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("marker", [{"deleted": True}, {"deleted_at": "2026-01-01T00:00:00Z"}])
async def test_deleted_item_does_not_block(service, monkeypatch, marker) -> None:
    _fixed_fingerprint(monkeypatch)
    service.items.list_items.return_value = _page(_row("SHA256:dup", **marker))
    result = await service.import_keys(source="bitwarden", vault_id=VAULT, private_key=_pem())
    assert result["public_fingerprint"] == "SHA256:dup"
    service.items.write_item.assert_awaited_once()


@pytest.mark.asyncio
async def test_other_vault_is_checked_on_its_own_listing(service, monkeypatch) -> None:
    _fixed_fingerprint(monkeypatch)

    async def listing(vault_id, **_kw):
        return _page(_row("SHA256:dup")) if vault_id == VAULT else _page()
    service.items.list_items.side_effect = listing
    await service.import_keys(source="bitwarden", vault_id=OTHER_VAULT, private_key=_pem())
    assert service.items.write_item.await_args.args[0] == OTHER_VAULT


@pytest.mark.asyncio
async def test_listing_failure_blocks_the_import(service, monkeypatch) -> None:
    _fixed_fingerprint(monkeypatch)
    service.items.list_items.side_effect = RuntimeError("listing down")
    with pytest.raises(RuntimeError, match="listing down"):
        await service.import_keys(source="bitwarden", vault_id=VAULT, private_key=_pem())
    service.items.write_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_service_409_duplicate_item_becomes_duplicate_key(service, monkeypatch) -> None:
    _fixed_fingerprint(monkeypatch)
    service.items.write_item.side_effect = APIError(
        code="duplicate_item", message="x", status=409, details={"existing_item_id": EXISTING_ID},
    )
    with pytest.raises(VaultDuplicateKey) as caught:
        await service.import_keys(source="bitwarden", vault_id=VAULT, private_key=_pem())
    assert caught.value.existing_item_id == EXISTING_ID
    assert caught.value.existing_name == "key-1"


@pytest.mark.asyncio
async def test_unreadable_existing_item_still_refuses_without_name(service, monkeypatch) -> None:
    _fixed_fingerprint(monkeypatch)
    service.items.list_items.return_value = _page(_row("SHA256:dup"))
    service.items.get_item.side_effect = RuntimeError("gone")
    with pytest.raises(VaultDuplicateKey) as caught:
        await service.import_keys(source="bitwarden", vault_id=VAULT, private_key=_pem())
    assert caught.value.existing_item_id == EXISTING_ID
    assert caught.value.existing_name is None
    assert caught.value.described() == "already in this vault"


@pytest.mark.asyncio
async def test_409_with_another_code_is_not_reclassified(service, monkeypatch) -> None:
    _fixed_fingerprint(monkeypatch)
    error = APIError(code="revision_conflict", message="x", status=409, details=None)
    service.items.write_item.side_effect = error
    with pytest.raises(APIError) as caught:
        await service.import_keys(source="bitwarden", vault_id=VAULT, private_key=_pem())
    assert caught.value is error


@pytest.mark.asyncio
async def test_409_duplicate_without_details_has_no_id(service, monkeypatch) -> None:
    _fixed_fingerprint(monkeypatch)
    service.items.write_item.side_effect = APIError(code="duplicate_item", message="x", status=409)
    with pytest.raises(VaultDuplicateKey) as caught:
        await service.import_keys(source="bitwarden", vault_id=VAULT, private_key=_pem())
    assert caught.value.existing_item_id is None and caught.value.existing_name is None
    service.items.get_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_stored_keys_shape_live_only_first_wins_and_unknown_names(service) -> None:
    other_id = "44444444-4444-4444-8444-444444444444"
    third_id = "55555555-5555-4555-8555-555555555555"
    service.items.list_items.return_value = _page(
        _row("SHA256:a"),
        _row("SHA256:a", item_id=other_id),
        _row("SHA256:gone", item_id=third_id, deleted=True),
        {"item_id": "66666666-6666-4666-8666-666666666666", "type": "note"},  # synthetic fixture  leak-guard:allow
        _row("SHA256:b", item_id="77777777-7777-4777-8777-777777777777", type="break_glass"),  # synthetic fixture  leak-guard:allow
    )
    service.ssh_key_choices = AsyncMock(return_value=[{"item_id": EXISTING_ID, "name": "key-1", "label": "l", "fingerprint": "SHA256:a"}])
    stored = await service.stored_keys(vault_id=VAULT)
    assert stored == {
        "SHA256:a": {"item_id": EXISTING_ID, "name": "key-1"},
        "SHA256:b": {"item_id": "77777777-7777-4777-8777-777777777777", "name": None},  # synthetic fixture  leak-guard:allow
    }


@pytest.mark.asyncio
async def test_stored_keys_lists_the_vault_once(service) -> None:
    service.items.list_items.return_value = _page(_row("SHA256:a"))
    await service.stored_keys(vault_id=VAULT)
    service.items.list_items.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("vault", [{"vault_id": VAULT}, {"vault_id": VAULT, "capabilities": ["duplicate_item"]}])
async def test_known_keys_skip_the_listing_and_the_vault_read(service, monkeypatch, vault) -> None:
    _fixed_fingerprint(monkeypatch, "SHA256:new")
    service.vaults.get_vault.return_value = vault
    await service.import_keys(
        source="bitwarden", vault_id=VAULT, private_key=_pem(),
        known_keys={"SHA256:other": {"item_id": EXISTING_ID, "name": "key-1"}},
    )
    service.items.list_items.assert_not_awaited()
    service.vaults.get_vault.assert_not_awaited()
    service.items.write_item.assert_awaited_once()


@pytest.mark.asyncio
async def test_known_keys_duplicate_is_refused_without_write_on_a_service_without_the_backstop(
    service, monkeypatch,
) -> None:
    _fixed_fingerprint(monkeypatch)
    with pytest.raises(VaultDuplicateKey) as caught:
        await service.import_keys(
            source="bitwarden", vault_id=VAULT, private_key=_pem(),
            known_keys={"SHA256:dup": {"item_id": EXISTING_ID, "name": "key-1"}},
        )
    assert caught.value.existing_item_id == EXISTING_ID
    service.items.list_items.assert_not_awaited()
    service.items.write_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_imported_key_joins_the_known_set_so_a_second_copy_is_refused(service, monkeypatch) -> None:
    _fixed_fingerprint(monkeypatch, "SHA256:new")
    known: dict = {}
    first = await service.import_keys(source="bitwarden", vault_id=VAULT, private_key=_pem(), known_keys=known)
    assert known == {"SHA256:new": {"item_id": first["item_id"], "name": first["name"]}}
    with pytest.raises(VaultDuplicateKey) as caught:
        await service.import_keys(source="bitwarden", vault_id=VAULT, private_key=_pem(), known_keys=known)
    assert caught.value.existing_item_id == first["item_id"]
    service.items.list_items.assert_not_awaited()
    service.items.write_item.assert_awaited_once()


@pytest.mark.asyncio
async def test_a_service_409_duplicate_is_still_mapped_with_known_keys(service, monkeypatch) -> None:
    _fixed_fingerprint(monkeypatch)
    service.items.write_item.side_effect = APIError(
        code="duplicate_item", message="x", status=409, details={"existing_item_id": EXISTING_ID},
    )
    with pytest.raises(VaultDuplicateKey):
        await service.import_keys(source="bitwarden", vault_id=VAULT, private_key=_pem(), known_keys={})
