"""The vault fake rejects requests which would be unsafe in production."""

from __future__ import annotations

import asyncio
import base64
import json
import time
from types import SimpleNamespace

import httpx
import pytest
from nacl.signing import SigningKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_ssh_public_identity,
)

from e2e.harness.fake_cloud.routes_vault import TEAM_ID
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
