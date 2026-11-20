from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from servonaut.services.vault import crypto
from servonaut.services.vault.bindings import VaultBindingService, binding_scope
from servonaut.services.vault.identity_store import IdentityStore
from servonaut.services.vault.team_vault_client import (
    VaultStateError,
    identity_signing_seed,
)


def test_binding_rejects_host_key_comment_and_invalid_key() -> None:
    with pytest.raises(ValueError):
        VaultBindingService._validate_host_keys(["ssh-ed25519 AAAA comment"])


def test_binding_rejects_boolean_port_before_signature_verification() -> None:
    class Vaults:
        def verify_vault(self, _vault):
            return None

    service = VaultBindingService(None, Vaults())
    with pytest.raises(Exception, match="destination"):
        service.verify_binding(
            {"source": "servonaut_vault", "valid": True, "hostname": "host", "port": True},
            {}, target="shared_server:x", hostname="host", port=1,
        )


# --- Which scope a binding is signed for -------------------------------------

_USER_ID = 7
_IDENTITY_ID = "44444444-4444-4444-8444-444444444444"
_TEAM_VAULT = {
    "vault_id": "55555555-5555-4555-8555-555555555555", "scope": "team:3", "kind": "team",
    "roster": [{"user_id": _USER_ID, "role": "admin"}],
}
_OWN_TARGET = "instance:aws:i-1"
_SHARED_TARGET = "shared_server:9"


def _host_key() -> str:
    return Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()


def _signing_service():
    identity = IdentityStore.generate_identity(identity_id=_IDENTITY_ID, user_id=_USER_ID)
    public = crypto.public_from_seed(identity_signing_seed(identity))
    vault = {**_TEAM_VAULT, "identities": {
        _IDENTITY_ID: {"identity_id": _IDENTITY_ID, "user_id": _USER_ID, "sig_public_key": base64.b64encode(public).decode()},
    }}
    vaults = SimpleNamespace(
        _identity_store=SimpleNamespace(identity=identity),
        _pins=SimpleNamespace(observe=lambda _binder: None),
        verify_vault=lambda _vault: None,
    )
    return VaultBindingService(None, vaults), vault, identity, public


def _build(service, vault, target: str, host_key: str) -> dict:
    return service.build_binding(
        vault=vault, target=target, hostname="192.0.2.10", port=22, login_user="deploy",
        vault_id=vault["vault_id"], vault_item_id="22222222-2222-4222-8222-222222222222",
        public_fingerprint="SHA256:abc", host_keys=[host_key], binding_revision=1,
    )


def _signed_for(scope: str, target: str, binding: dict) -> bytes:
    return crypto.binding_message(
        scope, target, binding["hostname"], binding["port"], binding["login_user"], binding["vault_id"],
        binding["vault_item_id"], binding["public_fingerprint"], binding["host_keys"],
        binding["binding_revision"], binding["binder_identity_id"],
    )


def test_an_own_server_binding_is_signed_for_the_user_scope_whichever_vault_holds_the_key() -> None:
    assert binding_scope(_TEAM_VAULT, _OWN_TARGET, _USER_ID) == f"user:{_USER_ID}"
    assert binding_scope({"scope": f"user:{_USER_ID}"}, _OWN_TARGET, _USER_ID) == f"user:{_USER_ID}"
    assert binding_scope(_TEAM_VAULT, _SHARED_TARGET, _USER_ID) == "team:3"


def test_a_team_key_bound_to_an_own_server_signs_what_the_service_verifies() -> None:
    service, vault, _identity, public = _signing_service()
    binding = _build(service, vault, _OWN_TARGET, _host_key())
    signature = base64.b64decode(binding["signature"])

    assert crypto.verify(public, _signed_for(f"user:{_USER_ID}", _OWN_TARGET, binding), signature)
    assert not crypto.verify(public, _signed_for("team:3", _OWN_TARGET, binding), signature)


def test_a_shared_server_binding_is_still_signed_for_its_vault_scope() -> None:
    service, vault, _identity, public = _signing_service()
    binding = _build(service, vault, _SHARED_TARGET, _host_key())

    assert crypto.verify(public, _signed_for("team:3", _SHARED_TARGET, binding), base64.b64decode(binding["signature"]))


def test_an_own_server_binding_to_a_team_key_verifies_and_a_team_scoped_one_does_not() -> None:
    service, vault, identity, _public = _signing_service()
    host_key = _host_key()
    binding = {**_build(service, vault, _OWN_TARGET, host_key), "source": "servonaut_vault", "valid": True}

    verified = service.verify_binding(binding, vault, target=_OWN_TARGET, hostname="192.0.2.10", port=22)
    assert verified["vault_id"] == vault["vault_id"]

    # What earlier versions signed: the team vault's scope. The service never accepted it.
    team_scoped = crypto.sign(identity_signing_seed(identity), _signed_for("team:3", _OWN_TARGET, binding))
    stale = {**binding, "signature": base64.b64encode(team_scoped).decode()}
    with pytest.raises(VaultStateError, match="signature is invalid"):
        service.verify_binding(stale, vault, target=_OWN_TARGET, hostname="192.0.2.10", port=22)
