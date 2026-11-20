"""The vault fake rejects requests which would be unsafe in production."""

from __future__ import annotations

import asyncio
import base64
import json
import time
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from nacl.signing import SigningKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_ssh_public_identity,
)

from e2e.harness.fake_cloud.routes_vault import TEAM_ID
from e2e.journeys.vault.test_native_import import _native_service
from servonaut.services.vault.ca_audit import CaIssuanceAuditor
from servonaut.services.vault.crypto import request_message
from servonaut.services.vault.identity_store import LocalDevice, LocalIdentity
from servonaut.services.vault.roster_pins import RosterPins
from servonaut.services.vault.team_vault_client import TeamVaultClient


pytestmark = [pytest.mark.e2e_pr]


def _signed_headers(device: dict[str, str], method: str, path: str, body: bytes, nonce: bytes) -> dict[str, str]:
    timestamp = int(time.time())
    signature = SigningKey(base64.b64decode(device["device_signing_key"])).sign(
        request_message(method, path, timestamp, nonce, device["device"]["device_id"], body)
    ).signature
    return {
        "X-Servonaut-Device": device["device"]["device_id"],
        "X-Servonaut-Timestamp": str(timestamp),
        "X-Servonaut-Nonce": base64.b64encode(nonce).decode(),
        "X-Servonaut-Signature": base64.b64encode(signature).decode(),
    }


def test_vault_requests_need_a_real_owned_signature_and_fresh_nonce(fake_cloud):
    """A bearer token cannot bypass the device-signature and replay boundary."""
    persona = fake_cloud.vault.seed_identity(fake_cloud.entitlements()["user_id"])
    access, _ = fake_cloud.tokens()
    path, body, nonce = "/api/v1/vaults", b"", b"n" * 16
    headers = {"Authorization": f"Bearer {access}", **_signed_headers(persona, "GET", path, body, nonce)}

    with httpx.Client(base_url=fake_cloud.url, verify=False, timeout=10) as client:
        good = client.get(path, headers=headers)
        assert good.status_code == 200
        assert good.json() == {"data": []}

        replay = client.get(path, headers=headers)
        assert replay.status_code == 403
        assert replay.json()["error"]["code"] == "device_signature_replayed"

        forged_headers = dict(headers)
        forged_headers["X-Servonaut-Nonce"] = base64.b64encode(b"o" * 16).decode()
        forged = client.get(path, headers=forged_headers)
        assert forged.status_code == 403
        assert forged.json()["error"]["code"] == "device_signature_invalid"


def test_vault_persona_controls_are_not_an_http_backdoor(fake_cloud):
    """Fixture controls create public test personas without registering routes."""
    owner = fake_cloud.vault.seed_identity(4242)
    member = fake_cloud.vault.seed_identity(4243)
    team = fake_cloud.vault.seed_team(4242, 4243)
    assert team["team_slug"] == "example-team"
    assert owner["identity"]["grantable"] is True
    assert member["identity"]["grantable"] is True

    access, _ = fake_cloud.tokens()
    with httpx.Client(base_url=fake_cloud.url, verify=False, timeout=10) as client:
        response = client.post("/__e2e/vault/seed", headers={"Authorization": f"Bearer {access}"}, json={})
    assert response.status_code == 404


def test_seeded_team_is_a_client_verifiable_version_chain_with_a_real_grant(fake_cloud):
    owner = fake_cloud.vault.seed_identity(4242)
    fake_cloud.vault.seed_identity(4243)
    team = fake_cloud.vault.seed_team(4242, 4243)
    device = LocalDevice(owner["device"]["device_id"], base64.b64decode(owner["device_signing_key"]), base64.b64decode(owner["device_encryption_key"]))
    identity = LocalIdentity(owner["identity"]["identity_id"], 4242, base64.b64decode(owner["identity_signing_key"]), base64.b64decode(owner["identity_encryption_key"]), device)
    pins: dict[str, str] = {}
    heads: dict[str, dict[str, object]] = {}
    client = TeamVaultClient(
        api=None,
        identity_store=SimpleNamespace(current_identity=lambda: identity, signer=lambda: identity.device),
        pins=RosterPins(lambda: pins, lambda saved: pins.update(saved)),
        state=SimpleNamespace(load=lambda: {"vault_heads": heads}, record_vault_head=lambda vault_id, version, record_hash: heads.update({vault_id: {"version": version, "record_hash": record_hash}})),
    )
    payload = fake_cloud.vault._vault_payload(fake_cloud.vault._vaults[team["vault_id"]], 4242)
    assert client.verify_vault(payload)[0] == 1
    assert len(client.open_my_grant(payload)) == 32


def test_fake_ca_issues_a_real_certificate_for_a_registered_device_key(fake_cloud):
    persona = fake_cloud.vault.seed_identity(fake_cloud.entitlements()["user_id"])
    access, _ = fake_cloud.tokens()
    device_key = Ed25519PrivateKey.generate()
    device_public = device_key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()

    def request(client, method: str, path: str, body: dict, nonce: bytes):
        raw = json.dumps(body, separators=(",", ":")).encode()
        return client.request(method, path, content=raw, headers={
            "Authorization": f"Bearer {access}", "Content-Type": "application/json",
            **_signed_headers(persona, method, path, raw, nonce),
        })

    with httpx.Client(base_url=fake_cloud.url, verify=False, timeout=10) as client:
        registered = request(client, "PUT", f"/api/v1/vault/devices/{persona['device']['device_id']}/ssh-key", {"ssh_public_key": device_public}, b"a" * 16)
        assert registered.status_code == 200, registered.text
        enabled = request(client, "POST", "/api/v1/teams/example-team/ssh-ca", {}, b"b" * 16)
        assert enabled.status_code == 201, enabled.text
        krl = client.get("/api/v1/teams/example-team/ssh-ca/krl", headers={"Authorization": f"Bearer {access}"})
        assert krl.status_code == 200, krl.text
        assert krl.content.startswith(b"SSHKRL\n\0")
        assert krl.headers["X-Servonaut-KRL-Version"] == "1"
        certificate = request(client, "POST", "/api/v1/teams/example-team/ssh-ca/certs", {"server_ids": ["c2a4e6f8-1b3d-4f5a-9c7e-0a2b4c6d8e1f"], "purpose": "automation", "requested_ttl_seconds": 600}, b"c" * 16)
        assert certificate.status_code == 201, certificate.text
        issued_page = client.get("/api/v1/teams/example-team/ssh-ca/issued?limit=500", headers={"Authorization": f"Bearer {access}"})
        assert issued_page.status_code == 200, issued_page.text

    parsed = load_ssh_public_identity(certificate.json()["certificate"].encode())
    parsed.verify_cert_signature()

    # The client's auditor recomputes the fake's chain and matches the held
    # certificate against the logged blob hash, as against the real service.
    class _Page:
        async def get(self, _path: str) -> dict:
            return issued_page.json()

    held = (certificate.json()["certificate"] + "\n").encode()
    report = asyncio.run(CaIssuanceAuditor(
        _Page(), "example-team", team_id=TEAM_ID, local_certificates={certificate.json()["serial"]: held},
    ).audit())
    assert report.entries_checked == 1
    assert report.valid


@pytest.mark.parametrize("revision", [None, 3, 4, 6, True])
def test_fake_delete_refuses_a_tombstone_with_the_wrong_revision(fake_cloud, revision):
    cloud = fake_cloud.vault
    cloud._items["vault"] = {"key": {"item_id": "key", "revision": 4, "deleted_at": None}}
    status, body = cloud.delete_item("vault", "key", {"revision": revision}, 1)
    assert status == 409 and body["error"]["code"] == "revision_conflict"
    assert cloud._items["vault"]["key"]["deleted_at"] is None
    assert cloud._items["vault"]["key"]["revision"] == 4


def test_fake_delete_accepts_the_next_revision_and_refuses_a_second_delete(fake_cloud):
    cloud = fake_cloud.vault
    cloud._items["vault"] = {"key": {"item_id": "key", "revision": 4, "deleted_at": None}}
    status, body = cloud.delete_item("vault", "key", {"revision": 5}, 1)
    assert status == 200 and body["revision"] == 5 and body["deleted_at"]
    status, body = cloud.delete_item("vault", "key", {"revision": 6}, 1)
    assert status == 409 and body["error"]["code"] == "item_deleted"


def test_fake_item_metadata_lists_only_the_items_team_server_bindings(fake_cloud):
    cloud = fake_cloud.vault
    cloud._vaults["vault"] = {"team": {"slug": "example-team"}}
    item = {"vault_id": "vault", "item_id": "key", "revision": 1}
    cloud._bindings[("aws", "i-1")] = {"vault_id": "vault", "vault_item_id": "key"}
    assert cloud.item_payload(item)["bound_server_ids"] == []
    server = cloud._shared_servers("example-team")[0]
    server_id = str(server["id"])
    cloud._bindings[("team", server_id)] = {"vault_id": "vault", "vault_item_id": "key"}
    bound = cloud.item_payload(item)["bound_server_ids"]
    assert bound == [{"server_id": server_id, "name": server["name"]}]
    cloud._bindings[("team", server_id)]["vault_item_id"] = "other"
    assert cloud.item_payload(item)["bound_server_ids"] == []
    assert "bound_server_ids" not in item


def _plain_vault(cloud, vault_id="vault", owner=1):
    cloud._vaults[vault_id] = {
        "vault_id": vault_id, "kind": "personal", "scope": f"user:{owner}", "owner_user_id": owner, "team": None,
        "name": "Personal vault", "grant_policy": "auto", "created_at": "", "updated_at": "",
        "rotation": {"required": False}, "grants": {}, "versions": [], "roster": [], "current_version": 1,
    }
    cloud._items.setdefault(vault_id, {})


def _put(cloud, item_id, fingerprint, *, vault_id="vault", expected=None):
    body = {"type": "ssh_key", "nonce": base64.b64encode(b"n" * 24).decode(),
            "ciphertext": base64.b64encode(b"c" * 32).decode(), "public_fingerprint": fingerprint,
            "expected_revision": expected}
    return cloud.put_item(vault_id, item_id, body, 1)


def _live_item(cloud, item_id="key", vault_id="vault", revision=1, fingerprint="SHA256:aaa"):
    cloud._items.setdefault(vault_id, {})[item_id] = {
        "item_id": item_id, "vault_id": vault_id, "revision": revision, "deleted_at": None,
        "public_fingerprint": fingerprint,
    }


def test_fake_capabilities_are_absent_by_default_and_announced_once_set(fake_cloud):
    cloud = fake_cloud.vault
    _plain_vault(cloud)
    assert "capabilities" not in cloud._vault_payload(cloud._vaults["vault"], 1)
    cloud.set_capabilities(["item_usage", "unknown_feature"])
    assert cloud._vault_payload(cloud._vaults["vault"], 1)["capabilities"] == ["item_usage", "unknown_feature"]
    cloud.set_capabilities([])
    assert cloud._vault_payload(cloud._vaults["vault"], 1)["capabilities"] == []
    cloud.set_capabilities(None)
    assert "capabilities" not in cloud._vault_payload(cloud._vaults["vault"], 1)


def test_fake_duplicate_refusal_rules(fake_cloud):
    cloud = fake_cloud.vault
    _plain_vault(cloud)
    _plain_vault(cloud, "other-vault")
    ids = [str(uuid4()) for _ in range(4)]
    # Without the capability the fake stores duplicates, as an old service does.
    assert _put(cloud, ids[0], "SHA256:one")[0] == 201
    assert _put(cloud, ids[1], "SHA256:one")[0] == 201
    cloud._items["vault"].clear()
    cloud.set_capabilities(["duplicate_item"])
    assert _put(cloud, ids[0], "SHA256:one")[0] == 201
    status, body = _put(cloud, ids[1], "SHA256:one")
    assert status == 409 and body["error"]["code"] == "duplicate_item"
    assert body["error"]["details"] == {"existing_item_id": ids[0]}
    # Same fingerprint kept on update: never refused.
    assert _put(cloud, ids[0], "SHA256:one", expected=1)[0] == 200
    # An update that changes the fingerprint onto another live item's is refused.
    assert _put(cloud, ids[2], "SHA256:two")[0] == 201
    status, body = _put(cloud, ids[2], "SHA256:one", expected=1)
    assert status == 409 and body["error"]["details"]["existing_item_id"] == ids[0]
    # Other vaults are not considered.
    assert _put(cloud, ids[3], "SHA256:one", vault_id="other-vault")[0] == 201
    # A deleted item does not count.
    cloud._items["vault"][ids[0]]["deleted_at"] = "now"
    assert _put(cloud, ids[1], "SHA256:one")[0] == 201


def test_fake_item_usage_lists_team_own_and_other_member_bindings(fake_cloud):
    cloud = fake_cloud.vault
    _plain_vault(cloud)
    _live_item(cloud)
    empty = {"item_id": "key", "team_servers": [], "own_instances": [], "other_members": {"members": 0, "servers": 0}}
    assert cloud.item_usage("vault", "key") == empty
    cloud._vaults["vault"]["team"] = {"slug": "example-team"}
    server = cloud._shared_servers("example-team")[0]
    cloud._bindings[("team", str(server["id"]))] = {"vault_id": "vault", "vault_item_id": "key"}
    cloud._bindings[("aws", "i-1")] = {"vault_id": "vault", "vault_item_id": "key"}
    cloud._bindings[("aws", "i-2")] = {"vault_id": "vault", "vault_item_id": "other"}
    cloud.bind_for_other_members("vault", "key", members=2, servers=3)
    usage = cloud.item_usage("vault", "key")
    assert usage["team_servers"] == [{"server_id": str(server["id"]), "name": server["name"]}]
    assert usage["own_instances"] == [{"provider": "aws", "instance_id": "i-1"}]
    assert usage["other_members"] == {"members": 2, "servers": 3}
    cloud._items["vault"]["key"]["deleted_at"] = "now"
    assert cloud.item_usage("vault", "key") == empty
    assert cloud.item_usage("missing-vault", "key") == empty


def test_fake_delete_refuses_a_bound_item_with_the_usage_and_unbind_clears_it(fake_cloud):
    cloud = fake_cloud.vault
    _plain_vault(cloud)
    _live_item(cloud, revision=4)
    cloud._bindings[("aws", "i-1")] = {"vault_id": "vault", "vault_item_id": "key"}
    cloud.bind_for_other_members("vault", "key", members=1, servers=2)
    # Old service: the bound item is deleted regardless.
    cloud._items["vault"]["old"] = {"item_id": "old", "vault_id": "vault", "revision": 1, "deleted_at": None}
    assert cloud.delete_item("vault", "old", {"revision": 2, "unbind": "x"}, 1)[0] == 200
    cloud.set_capabilities(["delete_refuses_bound"])
    status, body = cloud.delete_item("vault", "key", {"revision": 5}, 1)
    assert status == 409 and body["error"]["code"] == "item_in_use"
    assert body["error"]["details"] == cloud.item_usage("vault", "key")
    assert cloud._items["vault"]["key"]["deleted_at"] is None
    for bad in ("true", 1, None):
        status, body = cloud.delete_item("vault", "key", {"revision": 5, "unbind": bad}, 1)
        assert status == 422 and body["error"]["details"] == {"field": "unbind"}
    status, body = cloud.delete_item("vault", "key", {"revision": 5, "unbind": True}, 1)
    assert status == 200 and body["revision"] == 5
    assert cloud._bindings == {}
    assert cloud.item_usage("vault", "key")["other_members"] == {"members": 0, "servers": 0}
    assert cloud._other_member_bindings == {}


def test_fake_delete_with_capability_still_orders_revision_checks_first(fake_cloud):
    cloud = fake_cloud.vault
    _plain_vault(cloud)
    _live_item(cloud, revision=4)
    cloud._bindings[("aws", "i-1")] = {"vault_id": "vault", "vault_item_id": "key"}
    cloud.set_capabilities(["delete_refuses_bound"])
    status, body = cloud.delete_item("vault", "key", {"revision": 9}, 1)
    assert status == 409 and body["error"]["code"] == "revision_conflict"
    assert cloud.delete_item("vault", "nope", {"revision": 1}, 1)[0] == 404
    _live_item(cloud, "unused", revision=1)
    assert cloud.delete_item("vault", "unused", {"revision": 2}, 1)[0] == 200


def test_fake_usage_route_rules(fake_cloud):
    cloud = fake_cloud.vault
    user_id = fake_cloud.entitlements()["user_id"]
    persona = cloud.seed_identity(user_id)
    access, _ = fake_cloud.tokens()
    _plain_vault(cloud, owner=user_id)
    ids = [str(uuid4()), str(uuid4())]
    _live_item(cloud, ids[0])
    cloud._bindings[("aws", "i-1")] = {"vault_id": "vault", "vault_item_id": ids[0]}
    path = "/api/v1/vaults/vault/items/usage"
    counter = iter(range(1, 100))

    def post(payload, route=path):
        raw = json.dumps(payload).encode()
        headers = {"Authorization": f"Bearer {access}", "Content-Type": "application/json",
                   **_signed_headers(persona, "POST", route, raw, bytes([next(counter)]) * 16)}
        with httpx.Client(base_url=fake_cloud.url, verify=False, timeout=10) as client:
            return client.post(route, content=raw, headers=headers)

    # An old service has no such route.
    assert post({"item_ids": ids}).status_code == 404
    cloud.set_capabilities(["item_usage"])
    answer = post({"item_ids": ids})
    assert answer.status_code == 200
    data = answer.json()
    assert [u["item_id"] for u in data["data"]] == [ids[0]]
    assert data["data"][0]["own_instances"] == [{"provider": "aws", "instance_id": "i-1"}]
    assert data["meta"] == {"unknown_item_ids": [ids[1]]}
    for bad in ([], "x", [ids[0], ids[0]], ["not-a-uuid"], [ids[0].upper()], [str(uuid4()) for _ in range(501)]):
        refused = post({"item_ids": bad})
        assert refused.status_code == 422
        assert refused.json()["error"]["details"] == {"field": "item_ids"}
    assert post({}).status_code == 422
    assert post({"item_ids": ids}, "/api/v1/vaults/missing/items/usage").status_code == 404


def test_fake_usage_route_refuses_a_non_admin_caller(fake_cloud):
    cloud = fake_cloud.vault
    _plain_vault(cloud, owner=1)
    cloud._vaults["vault"].update(kind="team", roster=[{"user_id": 7, "status": "granted", "role": "member"}])
    cloud.set_capabilities(["item_usage"])
    status, body = cloud.usage_batch("vault", {"item_ids": [str(uuid4())]}, 7)
    assert status == 403 and body["error"]["code"] == "forbidden"
    assert cloud.usage_batch("vault", {"item_ids": [str(uuid4())]}, 8)[0] == 404


@pytest.mark.asyncio
async def test_vault_count_excludes_deleted_items_but_history_keeps_them(fake_cloud, account_home, monkeypatch) -> None:
    home = account_home("vault-live-count")
    service = _native_service(fake_cloud, home.home, monkeypatch)
    vault = await service.create_vault(team=None, name="Personal vault", grant_policy="auto")
    vault_id = vault["vault_id"]
    deleted_id, live_id = str(uuid4()), str(uuid4())
    for index, item_id in enumerate((deleted_id, live_id), 1):
        await service.items.write_item(vault_id, item_id, "secret", {"name": f"Secret {index}"}, expected_revision=0)
    assert (await service.list_vaults())[0]["counts"]["items"] == 2

    tombstone = await service.items.delete_item(vault_id, deleted_id, 1)
    assert tombstone["deleted_at"] and tombstone["revision"] == 2
    live = await service.list_items(vault_id=vault_id)
    assert [item["item_id"] for item in live["data"]] == [live_id]
    assert (await service.list_vaults())[0]["counts"]["items"] == 1
    history = await service.list_items(vault_id=vault_id, include_deleted=True)
    assert {item["item_id"] for item in history["data"]} == {deleted_id, live_id}
    assert next(item for item in history["data"] if item["item_id"] == deleted_id)["deleted_at"]


@pytest.mark.asyncio
async def test_vault_count_excludes_resolved_exposures_but_history_keeps_them(fake_cloud, account_home, monkeypatch) -> None:
    home = account_home("vault-open-count")
    service = _native_service(fake_cloud, home.home, monkeypatch)
    vault = await service.create_vault(team=None, name="Personal vault", grant_policy="auto")
    vault_id = vault["vault_id"]
    private_key = Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
    item = await service.import_keys(source="ssh", vault_id=vault_id, path="id_ed25519", private_key=private_key)
    exposure_id = fake_cloud.vault.open_exposure(vault_id, item["item_id"], public_fingerprint=item["public_fingerprint"])
    assert (await service.list_vaults())[0]["counts"]["open_exposures"] == 1

    resolved = await service.resolve_exposure(vault_id=vault_id, exposure_id=exposure_id, resolution="accepted_risk")
    assert resolved["status"] == "resolved"
    assert (await service.list_exposures(vault_id=vault_id))["data"] == []
    assert (await service.list_vaults())[0]["counts"]["open_exposures"] == 0
    history = await service.rotation.list_exposures(vault_id, status="all")
    assert [(row["exposure_id"], row["status"]) for row in history["data"]] == [(exposure_id, "resolved")]
