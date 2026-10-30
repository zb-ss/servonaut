"""Names and safe mutations of vault SSH keys."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import APIError
from servonaut.services.vault.command_service import VaultCommandService
from servonaut.services.vault.errors import VaultKeyInUse, VaultUserError, vault_failure_reason
from servonaut.services.vault.items import clean_item_name
from servonaut.services.vault.team_vault_client import VaultStateError


@pytest.mark.parametrize("value, expected", [
    ("  web-1  ", "web-1"),
    ("\x1b[31mweb\x1b[0m", "[31mweb[0m"),
    ("web\u202e-1\u2069", "web-1"),
    ("web\n-1\r\t\x9b", "web-1"),
    (123, "123"),
])
def test_clean_names_remove_terminal_controls(value: object, expected: str) -> None:
    assert clean_item_name(value) == expected


@pytest.mark.parametrize("value", ["", "  \n\t", "\x1b\u202e", "x" * 201])
def test_invalid_names_are_refused(value: str) -> None:
    with pytest.raises(ValueError, match="vault key name must contain 1 to 200 characters"):
        clean_item_name(value)


def test_import_names_can_be_shortened_and_stripped_again() -> None:
    assert clean_item_name("  " + "x" * 199 + "  tail", truncate=True) == "x" * 199
    assert clean_item_name("x" * 201, truncate=True) == "x" * 200
    with pytest.raises(ValueError):
        clean_item_name("\n", truncate=True)


@pytest.fixture
def service() -> VaultCommandService:
    service = VaultCommandService.__new__(VaultCommandService)
    service.items = SimpleNamespace(
        get_item=AsyncMock(return_value={"item_id": "key", "type": "ssh_key", "revision": 3, "bound_server_ids": [], "public_fingerprint": "SHA256:key"}),
        read_item=MagicMock(side_effect=lambda *_args: {"name": "web-1", "notes": "unchanged", "private_key_openssh": "opaque"}),
        write_item=AsyncMock(return_value={"revision": 4}), delete_item=AsyncMock(),
    )
    service.vaults = SimpleNamespace(get_vault=AsyncMock(return_value={"vault_id": "vault"}))
    service.personal_binding = AsyncMock(return_value=None)
    service.list_exposures = AsyncMock(return_value={"data": []})
    return service


@pytest.mark.asyncio
@pytest.mark.parametrize("source, path, name, expected", [
    ("bitwarden", None, "Ops key", "Ops key"),
    ("bitwarden", "ignored", None, "Imported SSH key"),
    ("bitwarden", None, " \n\u202e", "Imported SSH key"),
    ("ssh", "/keys/web-1.pem", None, "web-1.pem"),
    ("ssh", "/keys/\u202eweb-1.pem", " ", "web-1.pem"),
    ("ssh", None, "\u202e " + "x" * 201, "x" * 200),
])
async def test_import_uses_cleaned_explicit_name_or_source_default(service, source, path, name, expected) -> None:
    service._public_key_from_private = MagicMock(return_value="ssh-ed25519 public")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("servonaut.services.vault.command_service.crypto.ssh_public_fingerprint", lambda _: "SHA256:key")
        result = await service.import_keys(source=source, vault_id="vault", path=path, private_key=b"opaque", name=name)
    payload = service.items.write_item.call_args.args[3]
    assert result["name"] == payload["name"] == expected


@pytest.mark.asyncio
async def test_rename_verifies_and_preserves_payload_without_conflict_retry(service) -> None:
    payload = {"name": "web-1", "notes": "unchanged", "private_key_openssh": "opaque"}
    written = {}
    async def write(*args, **kwargs):
        written.update(args[3])
        assert kwargs == {"expected_revision": 3, "retry_stale_once": False}
        return {"revision": 4}
    service.items.write_item.side_effect = write
    service.items.read_item.side_effect = lambda *_: dict(payload)

    result = await service.rename_ssh_key(vault_id="vault", item_id="key", name=" \u202eapp-1\n ")

    assert result == {"item_id": "key", "name": "app-1", "revision": 4}
    assert written == {**payload, "name": "app-1"}
    service.items.read_item.assert_called_once_with({"vault_id": "vault"}, service.items.get_item.return_value)


@pytest.mark.asyncio
async def test_rename_to_the_same_name_verifies_but_does_not_write(service) -> None:
    assert await service.rename_ssh_key(vault_id="vault", item_id="key", name="web-1") == {
        "item_id": "key", "name": "web-1", "revision": 3,
    }
    service.items.read_item.assert_called_once()
    service.items.write_item.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("name", [" \n", "x" * 201])
async def test_rename_reports_invalid_names_without_truncating(service, name) -> None:
    with pytest.raises(VaultUserError, match="a vault key name must contain 1 to 200 characters"):
        await service.rename_ssh_key(vault_id="vault", item_id="key", name=name)
    service.items.write_item.assert_not_awaited()
    service.items.get_item.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["rename_ssh_key", "delete_ssh_key"])
@pytest.mark.parametrize("change, message", [
    ({"type": "secret"}, "only SSH key"), ({"deleted": True}, "already been deleted"),
    ({"deleted_at": "2030-01-01"}, "already been deleted"),
])
async def test_mutations_refuse_wrong_types_and_deleted_keys(service, method, change, message) -> None:
    service.items.get_item.return_value.update(change)
    options = {"name": "new"} if method == "rename_ssh_key" else {"servers": []}
    with pytest.raises(VaultUserError, match=message):
        await getattr(service, method)(vault_id="vault", item_id="key", **options)
    service.items.write_item.assert_not_awaited()
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_rename_trust_failure_stops_the_write(service) -> None:
    service.items.read_item.side_effect = ValueError("untrusted item")
    with pytest.raises(ValueError, match="untrusted item"):
        await service.rename_ssh_key(vault_id="vault", item_id="key", name="new")
    service.items.write_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_rename_conflict_is_propagated_with_reload_guidance(service) -> None:
    service.items.write_item.side_effect = APIError(code="revision_conflict", message="opaque", status=409)
    with pytest.raises(APIError) as caught:
        await service.rename_ssh_key(vault_id="vault", item_id="key", name="new")
    assert "changed since it was read; reload and try again" in vault_failure_reason(caught.value)
    assert service.items.write_item.await_count == 1


@pytest.mark.asyncio
async def test_usage_filters_shared_rows_and_keeps_failed_reads_separate(service) -> None:
    service.items.get_item.return_value["bound_server_ids"] = [{"server_id": "shared", "name": "\u202eteam-web\n"}]
    async def binding(row, **_kwargs):
        if row["id"] == "down":
            raise APIError(code="unavailable", message="opaque", status=503)
        return {"vault_id": "other" if row["id"] == "other-vault" else "vault", "vault_item_id": "key"}
    service.personal_binding.side_effect = binding
    servers = [{"id": "own", "name": "\u202eweb-1"}, {"id": "down", "name": "db-1\n"},
               {"id": "other-vault", "name": "other"}, {"id": "shared", "is_shared": True}]

    usage = await service.ssh_key_usage(vault_id="vault", item_id="key", servers=servers)

    assert usage == {"team_servers": ["team-web"], "own_servers": ["web-1"], "unchecked": ["db-1"],
                     "unchecked_targets": [["aws", "", "down"]], "checked": 2,
                     "name": "web-1", "fingerprint": "SHA256:key"}
    assert service.personal_binding.await_count == 3


@pytest.mark.asyncio
async def test_usage_limits_parallel_binding_reads(service) -> None:
    active = peak = 0
    release = asyncio.Event()
    first_batch = asyncio.Event()
    async def binding(_row, **_kwargs):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        if active == 6:
            first_batch.set()
        await release.wait()
        active -= 1
    service.personal_binding.side_effect = binding
    running = asyncio.create_task(service.ssh_key_usage(
        vault_id="vault", item_id="key", servers=[{"id": str(i)} for i in range(18)],
    ))
    try:
        await asyncio.wait_for(first_batch.wait(), timeout=1)
        assert active == 6
    finally:
        release.set()
        usage = await running
    assert peak == 6
    assert usage["checked"] == 18


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["team", "own", "unchecked"])
async def test_delete_refuses_every_kind_of_usage_or_failed_check(service, kind) -> None:
    if kind == "team":
        service.items.get_item.return_value["bound_server_ids"] = [{"server_id": "s", "name": "web-1"}]
    if kind == "own":
        service.personal_binding.return_value = {"vault_id": "vault", "vault_item_id": "key"}
    if kind == "unchecked":
        service.personal_binding.side_effect = RuntimeError("opaque")
    with pytest.raises(VaultKeyInUse) as caught:
        await service.delete_ssh_key(vault_id="vault", item_id="key", servers=[{"id": "i-1", "name": "web-1"}])
    error = caught.value
    assert getattr(error, {"team": "team_servers", "own": "own_servers", "unchecked": "unchecked"}[kind]) == ["web-1"]
    assert "web-1" not in str(error)
    assert ("hosts do not need to be running" if kind == "unchecked" else "another vault key") in str(error)
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("exposure", [{"item_id": "key", "status": "open"}, {"item_id": "key", "resolved_at": None}])
async def test_delete_refuses_open_exposures_and_failed_exposure_checks(service, exposure) -> None:
    service.list_exposures.return_value = {"data": [exposure]}
    with pytest.raises(VaultUserError, match="resolve or rotate its open exposures first"):
        await service.delete_ssh_key(vault_id="vault", item_id="key", servers=[])
    service.list_exposures.side_effect = RuntimeError("unavailable")
    with pytest.raises(RuntimeError):
        await service.delete_ssh_key(vault_id="vault", item_id="key", servers=[])
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_delete_unused_key_uses_fresh_revision_and_ignores_other_or_closed_exposures(service) -> None:
    service.items.get_item.return_value["revision"] = 8
    service.list_exposures.return_value = {"data": [
        {"item_id": "other", "status": "open"}, {"item_id": "key", "status": "resolved"},
        {"item_id": "key", "resolved_at": "2030-01-01"},
    ]}
    assert await service.delete_ssh_key(vault_id="vault", item_id="key", servers=[]) == {"item_id": "key", "deleted": True}
    service.items.get_item.assert_awaited_once_with("vault", "key")
    service.items.delete_item.assert_awaited_once_with("vault", "key", 8)


@pytest.mark.asyncio
async def test_delete_conflict_does_not_retry_a_stale_tombstone(service) -> None:
    service.items.delete_item.side_effect = APIError(code="revision_conflict", message="opaque", status=409)
    with pytest.raises(APIError):
        await service.delete_ssh_key(vault_id="vault", item_id="key", servers=[])
    assert service.items.delete_item.await_count == 1


@pytest.mark.asyncio
async def test_deleting_an_unbound_key_never_contacts_offline_hosts(service) -> None:
    service._remote_executor = MagicMock(side_effect=AssertionError("SSH must not be used for vault deletion"))
    servers = [{"id": "i-0001", "name": "offline-1", "state": "stopped", "public_ip": "10.0.0.1"}]
    assert await service.delete_ssh_key(vault_id="vault", item_id="key", servers=servers) == {
        "item_id": "key", "deleted": True,
    }
    service._remote_executor.assert_not_called()


@pytest.mark.asyncio
async def test_unavailable_saved_assignments_need_explicit_acknowledgement(service) -> None:
    service.personal_binding.side_effect = APIError(code="unavailable", message="opaque", status=503)
    servers = [{"id": "i-0001", "name": "offline-1"}]
    with pytest.raises(VaultKeyInUse):
        await service.delete_ssh_key(vault_id="vault", item_id="key", servers=servers)
    service.items.delete_item.assert_not_awaited()
    with pytest.raises(VaultKeyInUse):
        await service.delete_ssh_key(vault_id="vault", item_id="key", servers=servers, allow_unchecked=True)
    result = await service.delete_ssh_key(
        vault_id="vault", item_id="key", servers=servers, allow_unchecked=True,
        unchecked_targets=[["aws", "", "i-0001"]],
    )
    assert result["deleted"] is True
    service.items.delete_item.assert_awaited_once_with("vault", "key", 3)


@pytest.mark.asyncio
async def test_unchecked_override_is_limited_to_the_reviewed_servers(service) -> None:
    service.personal_binding.side_effect = APIError(code="unavailable", message="opaque", status=503)
    servers = [{"id": "i-0001", "name": "web-1"}, {"id": "i-0002", "name": "db-1"}]
    with pytest.raises(VaultUserError, match="assignment checks changed"):
        await service.delete_ssh_key(
            vault_id="vault", item_id="key", servers=servers,
            allow_unchecked=True, unchecked_targets=[["aws", "", "i-0001"]],
        )
    service.items.delete_item.assert_not_awaited()
    await service.delete_ssh_key(
        vault_id="vault", item_id="key", servers=servers,
        allow_unchecked=True, unchecked_targets=[["aws", "", "i-0001"], ["aws", "", "i-0002"]],
    )
    service.items.delete_item.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", ["id", "account", "resolved"])
async def test_unchecked_review_is_bound_to_exact_server_identities(service, changed) -> None:
    service.personal_binding.side_effect = RuntimeError("unavailable")
    server = {"id": "i-0001", "account": "first", "name": "web-1"}
    usage = await service.ssh_key_usage(vault_id="vault", item_id="key", servers=[server])
    reviewed = usage["unchecked_targets"]
    assert reviewed == [["aws", "first", "i-0001"]]
    if changed == "resolved":
        service.personal_binding.side_effect = None
    else:
        server[changed] = "second" if changed == "account" else "i-0002"
    with pytest.raises(VaultUserError, match="assignment checks changed"):
        await service.delete_ssh_key(
            vault_id="vault", item_id="key", servers=[server],
            allow_unchecked=True, unchecked_targets=reviewed,
        )
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_unchecked_review_uses_the_custom_binding_identity(service) -> None:
    from servonaut.services.vault.personal_targets import custom_binding_id

    service.personal_binding.side_effect = RuntimeError("unavailable")
    server = {"id": "custom-web", "name": "web-1", "is_custom": True}
    usage = await service.ssh_key_usage(vault_id="vault", item_id="key", servers=[server])
    assert usage["unchecked_targets"] == [["custom", "", custom_binding_id("web-1")]]
    await service.delete_ssh_key(
        vault_id="vault", item_id="key", servers=[server], allow_unchecked=True,
        unchecked_targets=usage["unchecked_targets"],
    )
    service.items.delete_item.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["personal", "team", "exposure"])
async def test_acknowledgement_never_bypasses_known_assignments_or_open_exposures(service, kind) -> None:
    if kind == "personal":
        service.personal_binding.return_value = {"vault_id": "vault", "vault_item_id": "key"}
    elif kind == "team":
        service.items.get_item.return_value["bound_server_ids"] = [{"server_id": "s1", "name": "web-1"}]
    else:
        service.list_exposures.return_value = {"data": [{"item_id": "key", "status": "open"}]}
    with pytest.raises(VaultUserError):
        await service.delete_ssh_key(
            vault_id="vault", item_id="key", servers=[{"id": "i-0001", "name": "web-1"}], allow_unchecked=True,
        )
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_usage_returns_the_verified_name_and_drops_key_material(service) -> None:
    payload = {"name": " \u202eweb-1\n", "private_key_openssh": "opaque"}
    service.items.read_item.side_effect = None
    service.items.read_item.return_value = payload
    usage = await service.ssh_key_usage(vault_id="vault", item_id="key", servers=[])
    assert usage["name"] == " web-1" and usage["fingerprint"] == "SHA256:key"
    assert "opaque" not in str(usage)
    assert payload == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["vault", "item"])
async def test_usage_has_no_name_if_the_item_cannot_be_verified(service, failure) -> None:
    if failure == "vault":
        service.vaults.get_vault.side_effect = RuntimeError("unavailable")
    else:
        service.items.read_item.side_effect = ValueError("untrusted")
    usage = await service.ssh_key_usage(vault_id="vault", item_id="key", servers=[])
    assert usage["name"] is None and usage["fingerprint"] == "SHA256:key"


@pytest.mark.asyncio
@pytest.mark.parametrize("revision", [True, 0, -1, None])
async def test_rename_refuses_invalid_revisions_before_decrypting(service, revision) -> None:
    service.items.get_item.return_value["revision"] = revision
    with pytest.raises(VaultStateError, match="item.revision"):
        await service.rename_ssh_key(vault_id="vault", item_id="key", name="new")
    service.items.read_item.assert_not_called()
    service.items.write_item.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["ssh", "bitwarden"])
async def test_unreadable_import_has_actionable_error_and_wipes_private_buffer(service, monkeypatch, source) -> None:
    import servonaut.services.vault.command_service as module

    buffers: list[bytearray] = []
    def tracked_buffer(value):
        buffer = bytearray(value)
        buffers.append(buffer)
        return buffer
    monkeypatch.setattr(module, "bytearray", tracked_buffer, raising=False)
    with pytest.raises(VaultUserError) as caught:
        await service.import_keys(source=source, vault_id="vault", private_key=b"unreadable key material")
    assert str(caught.value) == (
        "this is not an SSH private key Servonaut can read: it must be an OpenSSH private key, unlocked or with its passphrase"
    )
    assert isinstance(caught.value.__cause__, ValueError)
    assert buffers and buffers[0] == bytearray(len(b"unreadable key material"))
    service.items.write_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_import_does_not_reclassify_unrelated_errors(service, monkeypatch) -> None:
    service._public_key_from_private = MagicMock(side_effect=RuntimeError("loader unavailable"))
    with pytest.raises(RuntimeError, match="loader unavailable"):
        await service.import_keys(source="bitwarden", vault_id="vault", private_key=b"fixture")
    service._public_key_from_private.side_effect = None
    service._public_key_from_private.return_value = "ssh-ed25519 public"
    monkeypatch.setattr("servonaut.services.vault.command_service.crypto.ssh_public_fingerprint", lambda _: "SHA256:key")
    service.items.write_item.side_effect = ValueError("write refused")
    with pytest.raises(ValueError, match="write refused"):
        await service.import_keys(source="bitwarden", vault_id="vault", private_key=b"fixture")


@pytest.mark.asyncio
@pytest.mark.parametrize("instance_id", [
    "ns0000001.example.test", "vps-000001.vps.example.test",
    "project-1/00000000-0000-4000-8000-000000000001",  # synthetic fixture  leak-guard:allow
])
async def test_unsupported_ovh_targets_do_not_block_deleting_an_unused_key(service, instance_id) -> None:
    service._personal_binding = AsyncMock(return_value=(None, "unused"))
    service.personal_binding = AsyncMock(wraps=VaultCommandService.personal_binding.__get__(service))
    servers = [{"id": instance_id, "provider": "ovh", "name": "storage-1"}]
    usage = await service.ssh_key_usage(vault_id="vault", item_id="key", servers=servers)
    assert usage["team_servers"] == usage["own_servers"] == usage["unchecked"] == []
    assert usage["checked"] == 0
    assert await service.delete_ssh_key(vault_id="vault", item_id="key", servers=servers) == {
        "item_id": "key", "deleted": True,
    }
    service.personal_binding.assert_not_awaited()
    service._personal_binding.assert_not_awaited()
    service.items.delete_item.assert_awaited_once_with("vault", "key", 3)


@pytest.mark.asyncio
async def test_real_aws_binding_read_failure_still_blocks_delete_beside_unsupported_ovh_rows(service) -> None:
    service._personal_binding = AsyncMock(side_effect=APIError(code="unavailable", message="opaque", status=503))
    service.personal_binding = VaultCommandService.personal_binding.__get__(service)
    servers = [
        {"id": "ns0000001.example.test", "provider": "ovh", "name": "storage-1"},
        {"id": "i-0001", "provider": "aws", "name": "web-1"},
    ]
    with pytest.raises(VaultKeyInUse) as caught:
        await service.delete_ssh_key(vault_id="vault", item_id="key", servers=servers)
    assert caught.value.unchecked == ["web-1"]
    service._personal_binding.assert_awaited_once_with("aws", "i-0001", fresh=True)
    service.items.delete_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_encrypted_import_without_passphrase_explains_unlocking(service) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, Encoding, PrivateFormat

    encrypted = Ed25519PrivateKey.generate().private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, BestAvailableEncryption(b"test passphrase"),
    )
    with pytest.raises(VaultUserError, match="OpenSSH private key, unlocked or with its passphrase") as caught:
        await service.import_keys(source="bitwarden", vault_id="vault", private_key=encrypted)
    assert isinstance(caught.value.__cause__, ValueError)
    service.items.write_item.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("source, path, name, expected", [
    ("ssh", "/keys/  id_ed25519\n", None, "id_ed25519"),
    ("bitwarden", None, "  [1st key\u202e\n", "[1st key"),
    ("bitwarden", None, "\n\u202e ", "Imported SSH key"),
    ("bitwarden", None, "k" * 201, "k" * 200),
])
async def test_import_returned_name_matches_stored_name(service, source, path, name, expected) -> None:
    service._public_key_from_private = MagicMock(return_value="ssh-ed25519 public")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("servonaut.services.vault.command_service.crypto.ssh_public_fingerprint", lambda _: "SHA256:key")
        result = await service.import_keys(source=source, vault_id="vault", path=path, private_key=b"opaque", name=name)
    assert result["name"] == service.items.write_item.call_args.args[3]["name"] == expected
