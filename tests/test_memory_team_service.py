"""Unit tests for services/memory/team_service.py.

Covers:
- list_team_member_keys: happy path, entitlement gate, API error mapping
- list_shared_instances: happy path, empty list, entitlement gate
- read_team_envelope: happy path, entitlement gate
- share_instance: happy path (wraps built correctly), insufficient_wraps,
  grant_exists → GrantAlreadyExistsError, entitlement gate,
  role filtering (only members with role >= required_role get wrapped)
- revoke_grant: happy path, entitlement gate
- purge_grant: happy path returns count, entitlement gate
"""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

# nacl for generating test keys
import nacl.public

from servonaut.services.memory.team_service import (
    Grant,
    GrantAlreadyExistsError,
    InsufficientWrapsError,
    MissingWrap,
    SharedInstance,
    TeamMemberKey,
    TeamMemoryService,
    WrapEntry,
)
from servonaut.services.memory.interfaces import (
    BackendMaintenance,
    BetaWaitlist,
    UpsellRequired,
    ValidationFailed,
)
from servonaut.services.api_client import (
    ForbiddenEntitlementError,
    FeatureDisabledError,
    FeatureNotAvailableError,
    GrantExistsError,
    InsufficientWrapsError as APIInsufficientWrapsError,
)
import servonaut.services.memory.crypto as crypto_module


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_api():
    api = MagicMock()
    api.get = AsyncMock()
    api.post = AsyncMock()
    api.delete = AsyncMock()
    return api


@pytest.fixture
def mock_auth():
    auth = MagicMock()
    auth.has_feature = MagicMock(return_value=True)
    return auth


@pytest.fixture
def mock_auth_no_entitlement():
    auth = MagicMock()
    auth.has_feature = MagicMock(return_value=False)
    return auth


def _make_keypair():
    """Return (private_key_bytes, public_key_bytes) for a fresh X25519 keypair."""
    private = nacl.public.PrivateKey.generate()
    return bytes(private), bytes(private.public_key)


@pytest.fixture
def caller_keypair():
    return _make_keypair()


@pytest.fixture
def key_material(caller_keypair):
    priv, pub = caller_keypair
    km = MagicMock()
    km.user_id = 1
    km.private_key = priv
    km.public_key = pub
    return km


@pytest.fixture
def key_store_provider(key_material):
    return MagicMock(return_value=key_material)


@pytest.fixture
def mock_retrieval():
    rs = MagicMock()
    rs.list_instance_modules = AsyncMock()
    rs.get_module_envelope_raw = AsyncMock()
    return rs


@pytest.fixture
def service(mock_api, mock_auth, key_store_provider, mock_retrieval):
    return TeamMemoryService(
        api_client=mock_api,
        auth_service=mock_auth,
        crypto=crypto_module,
        key_store_provider=key_store_provider,
        retrieval_service=mock_retrieval,
    )


@pytest.fixture
def service_no_entitlement(mock_api, mock_auth_no_entitlement, key_store_provider, mock_retrieval):
    return TeamMemoryService(
        api_client=mock_api,
        auth_service=mock_auth_no_entitlement,
        crypto=crypto_module,
        key_store_provider=key_store_provider,
        retrieval_service=mock_retrieval,
    )


def _grant_dict(instance_id="i-123", required_role="member", status="active"):
    return {
        "id": "grant-uuid",
        "instance_id": instance_id,
        "required_role": required_role,
        "modules": ["os", "services"],
        "status": status,
        "granted_by_user_id": 1,
        "created_at": "2026-04-25T10:00:00+00:00",
        "revoked_at": None,
    }


# ---------------------------------------------------------------------------
# list_team_member_keys
# ---------------------------------------------------------------------------

class TestListTeamMemberKeys:
    def test_happy_path(self, service, mock_api):
        mock_api.get.return_value = {
            "members": [
                {"user_id": 42, "fingerprint": "abc123", "public_key_b64": "AAAA", "role": "admin"},
                {"user_id": 99, "fingerprint": "def456", "public_key_b64": "BBBB", "role": "viewer"},
            ]
        }
        result = run(service.list_team_member_keys("myteam"))

        assert len(result) == 2
        assert result[0].user_id == 42
        assert result[0].role == "admin"
        assert result[1].user_id == 99
        mock_api.get.assert_called_once_with("/api/v1/memory/keys/team/myteam")

    def test_empty_members(self, service, mock_api):
        mock_api.get.return_value = {"members": []}
        result = run(service.list_team_member_keys("myteam"))
        assert result == []

    def test_entitlement_gate(self, service_no_entitlement):
        with pytest.raises(UpsellRequired) as exc_info:
            run(service_no_entitlement.list_team_member_keys("myteam"))
        assert exc_info.value.plan == "memory_team_share"

    def test_forbidden_entitlement_from_api(self, service, mock_api):
        mock_api.get.side_effect = ForbiddenEntitlementError(
            code="forbidden_entitlement", message="no", status=403
        )
        with pytest.raises(UpsellRequired):
            run(service.list_team_member_keys("myteam"))

    def test_backend_maintenance(self, service, mock_api):
        mock_api.get.side_effect = FeatureDisabledError(
            code="feature_disabled", message="maint", status=503
        )
        with pytest.raises(BackendMaintenance):
            run(service.list_team_member_keys("myteam"))

    def test_member_public_key_bytes_property(self, service, mock_api):
        raw_key = nacl.public.PrivateKey.generate().public_key
        b64 = base64.b64encode(bytes(raw_key)).decode()
        mock_api.get.return_value = {
            "members": [{"user_id": 1, "fingerprint": "f", "public_key_b64": b64, "role": "member"}]
        }
        result = run(service.list_team_member_keys("myteam"))
        assert result[0].public_key_bytes == bytes(raw_key)


# ---------------------------------------------------------------------------
# list_shared_instances
# ---------------------------------------------------------------------------

class TestListSharedInstances:
    def test_happy_path(self, service, mock_api):
        mock_api.get.return_value = {
            "instances": [
                {
                    "grant": _grant_dict("i-123"),
                    "instance": {"id": "i-123", "instance_id": "i-123"},
                    "readable_modules": ["os"],
                }
            ]
        }
        result = run(service.list_shared_instances("myteam"))

        assert len(result) == 1
        item = result[0]
        assert isinstance(item, SharedInstance)
        assert isinstance(item.grant, Grant)
        assert item.grant.instance_id == "i-123"
        assert item.readable_modules == ["os"]
        mock_api.get.assert_called_once_with("/api/v1/teams/myteam/memory")

    def test_empty_list(self, service, mock_api):
        mock_api.get.return_value = {"instances": []}
        result = run(service.list_shared_instances("myteam"))
        assert result == []

    def test_entitlement_gate(self, service_no_entitlement):
        with pytest.raises(UpsellRequired):
            run(service_no_entitlement.list_shared_instances("myteam"))

    def test_grant_revoked_at_parsed(self, service, mock_api):
        grant = _grant_dict()
        grant["revoked_at"] = "2026-04-26T00:00:00+00:00"
        grant["status"] = "revoked"
        mock_api.get.return_value = {
            "instances": [{"grant": grant, "instance": {}, "readable_modules": []}]
        }
        result = run(service.list_shared_instances("myteam"))
        assert result[0].grant.revoked_at is not None
        assert result[0].grant.status == "revoked"


# ---------------------------------------------------------------------------
# read_team_envelope
# ---------------------------------------------------------------------------

class TestReadTeamEnvelope:
    def test_happy_path(self, service, mock_api):
        envelope = {"id": "env-uuid", "module": "os", "grant_id": "grant-1"}
        mock_api.get.return_value = envelope

        result = run(service.read_team_envelope("myteam", "i-123", "os"))
        assert result == envelope
        mock_api.get.assert_called_once_with("/api/v1/teams/myteam/memory/i-123/os")

    def test_entitlement_gate(self, service_no_entitlement):
        with pytest.raises(UpsellRequired):
            run(service_no_entitlement.read_team_envelope("myteam", "i-123", "os"))


# ---------------------------------------------------------------------------
# share_instance
# ---------------------------------------------------------------------------

def _make_member_key(user_id: int, role: str = "member") -> TeamMemberKey:
    """Create a TeamMemberKey with a real X25519 public key."""
    private = nacl.public.PrivateKey.generate()
    pub_b64 = base64.b64encode(bytes(private.public_key)).decode()
    return TeamMemberKey(
        user_id=user_id,
        fingerprint="fp",
        public_key_b64=pub_b64,
        role=role,
    )


def _make_synthetic_envelope(caller_user_id: int, caller_priv: bytes, caller_pub: bytes) -> dict:
    """Build a synthetic envelope where the DEK is wrapped for the caller."""
    import os as _os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    dek = _os.urandom(32)
    iv = _os.urandom(12)
    plaintext = b'{"os": "ubuntu"}'
    ct_with_tag = AESGCM(dek).encrypt(iv, plaintext, None)
    ct = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    box = nacl.public.SealedBox(nacl.public.PublicKey(caller_pub))
    wrapped_dek = box.encrypt(dek)

    return {
        "id": "env-001",
        "module": "os",
        "iv": base64.b64encode(iv).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "encryption": "aes-256-gcm",
        "dek_wraps": [
            {
                "recipient_user_id": caller_user_id,
                "wrapped_dek": base64.b64encode(wrapped_dek).decode(),
            }
        ],
    }


class TestShareInstance:
    def test_entitlement_gate(self, service_no_entitlement):
        with pytest.raises(UpsellRequired):
            run(service_no_entitlement.share_instance("myteam", "i-123", "member", None, []))

    def test_happy_path_wraps_members(
        self, service, mock_api, mock_retrieval, key_material, caller_keypair
    ):
        priv, pub = caller_keypair
        member = _make_member_key(42, role="member")

        mock_retrieval.list_instance_modules.return_value = {
            "modules": ["os"]
        }
        raw_env = _make_synthetic_envelope(key_material.user_id, priv, pub)
        mock_retrieval.get_module_envelope_raw.return_value = raw_env

        grant_response = _grant_dict()
        mock_api.post.return_value = grant_response

        result = run(
            service.share_instance("myteam", "i-123", "member", ["os"], [member])
        )

        assert isinstance(result, Grant)
        assert result.instance_id == "i-123"

        # Verify the grant POST was made with wraps
        post_call = mock_api.post.call_args
        assert post_call.args[0] == "/api/v1/teams/myteam/memory/grant"
        body = post_call.kwargs["json"]
        assert body["instance_id"] == "i-123"
        assert body["required_role"] == "member"
        assert len(body["wraps"]) == 1
        wrap = body["wraps"][0]
        assert wrap["recipient_user_id"] == 42
        assert wrap["envelope_id"] == "env-001"
        assert isinstance(wrap["wrapped_dek"], str)
        # Ensure the wrapped DEK is base64-decodeable
        decoded = base64.b64decode(wrap["wrapped_dek"])
        assert len(decoded) > 32

    def test_role_filtering_excludes_lower_roles(
        self, service, mock_api, mock_retrieval, key_material, caller_keypair
    ):
        """Members with role < required_role should NOT receive wraps."""
        priv, pub = caller_keypair

        admin_member = _make_member_key(10, role="admin")
        viewer_member = _make_member_key(11, role="viewer")

        mock_retrieval.list_instance_modules.return_value = {
            "modules": ["os"]
        }
        raw_env = _make_synthetic_envelope(key_material.user_id, priv, pub)
        mock_retrieval.get_module_envelope_raw.return_value = raw_env

        mock_api.post.return_value = _grant_dict()

        run(service.share_instance(
            "myteam", "i-123", "admin",  # required_role = admin
            None, [admin_member, viewer_member]
        ))

        body = mock_api.post.call_args.kwargs["json"]
        recipient_ids = [w["recipient_user_id"] for w in body["wraps"]]
        assert 10 in recipient_ids       # admin included
        assert 11 not in recipient_ids   # viewer excluded

    def test_insufficient_wraps_raises_typed_error(
        self, service, mock_api, mock_retrieval, key_material, caller_keypair
    ):
        priv, pub = caller_keypair
        member = _make_member_key(42, role="member")

        mock_retrieval.list_instance_modules.return_value = {
            "modules": ["os"]
        }
        raw_env = _make_synthetic_envelope(key_material.user_id, priv, pub)
        mock_retrieval.get_module_envelope_raw.return_value = raw_env

        mock_api.post.side_effect = APIInsufficientWrapsError(
            code="insufficient_wraps",
            message="missing wraps",
            status=422,
            details={"missing": [{"envelope_id": "env-001", "recipient_user_id": 42}]},
        )

        with pytest.raises(InsufficientWrapsError) as exc_info:
            run(service.share_instance("myteam", "i-123", "member", None, [member]))

        assert len(exc_info.value.missing) == 1
        assert exc_info.value.missing[0].envelope_id == "env-001"
        assert exc_info.value.missing[0].recipient_user_id == 42

    def test_grant_exists_raises_typed_error(
        self, service, mock_api, mock_retrieval, key_material, caller_keypair
    ):
        priv, pub = caller_keypair
        member = _make_member_key(42, role="member")

        mock_retrieval.list_instance_modules.return_value = {
            "modules": ["os"]
        }
        raw_env = _make_synthetic_envelope(key_material.user_id, priv, pub)
        mock_retrieval.get_module_envelope_raw.return_value = raw_env

        mock_api.post.side_effect = GrantExistsError(
            code="grant_exists", message="exists", status=409
        )

        with pytest.raises(GrantAlreadyExistsError) as exc_info:
            run(service.share_instance("myteam", "i-123", "member", None, [member]))

        assert exc_info.value.instance_id == "i-123"
        assert exc_info.value.team_slug == "myteam"

    def test_no_envelopes_posts_empty_wraps(
        self, service, mock_api, mock_retrieval
    ):
        mock_retrieval.list_instance_modules.return_value = {"modules": []}
        mock_api.post.return_value = _grant_dict()

        run(service.share_instance("myteam", "i-123", "member", None, []))
        body = mock_api.post.call_args.kwargs["json"]
        assert body["wraps"] == []

    def test_backend_maintenance(
        self, service, mock_api, mock_retrieval, key_material, caller_keypair
    ):
        priv, pub = caller_keypair
        mock_retrieval.list_instance_modules.return_value = {"modules": []}
        mock_api.post.side_effect = FeatureDisabledError(
            code="feature_disabled", message="maint", status=503
        )
        with pytest.raises(BackendMaintenance):
            run(service.share_instance("myteam", "i-123", "member", None, []))


# ---------------------------------------------------------------------------
# revoke_grant
# ---------------------------------------------------------------------------

class TestRevokeGrant:
    def test_happy_path(self, service, mock_api):
        revoked = _grant_dict(status="revoked")
        revoked["revoked_at"] = "2026-04-25T15:00:00+00:00"
        mock_api.delete.return_value = revoked

        result = run(service.revoke_grant("myteam", "grant-uuid"))
        assert isinstance(result, Grant)
        assert result.status == "revoked"
        assert result.revoked_at is not None
        mock_api.delete.assert_called_once_with(
            "/api/v1/teams/myteam/memory/grant/grant-uuid"
        )

    def test_entitlement_gate(self, service_no_entitlement):
        with pytest.raises(UpsellRequired):
            run(service_no_entitlement.revoke_grant("myteam", "grant-uuid"))

    def test_backend_maintenance(self, service, mock_api):
        mock_api.delete.side_effect = FeatureDisabledError(
            code="feature_disabled", message="maint", status=503
        )
        with pytest.raises(BackendMaintenance):
            run(service.revoke_grant("myteam", "grant-uuid"))


# ---------------------------------------------------------------------------
# purge_grant
# ---------------------------------------------------------------------------

class TestPurgeGrant:
    def test_returns_wraps_deleted_count(self, service, mock_api):
        mock_api.post.return_value = {"grant_id": "grant-uuid", "wraps_deleted": 14}
        count = run(service.purge_grant("myteam", "grant-uuid"))
        assert count == 14
        mock_api.post.assert_called_once_with(
            "/api/v1/teams/myteam/memory/grant/grant-uuid/purge",
            json=None,
        )

    def test_returns_zero_when_field_missing(self, service, mock_api):
        mock_api.post.return_value = {"grant_id": "grant-uuid"}
        count = run(service.purge_grant("myteam", "grant-uuid"))
        assert count == 0

    def test_entitlement_gate(self, service_no_entitlement):
        with pytest.raises(UpsellRequired):
            run(service_no_entitlement.purge_grant("myteam", "grant-uuid"))

    def test_backend_maintenance(self, service, mock_api):
        mock_api.post.side_effect = FeatureDisabledError(
            code="feature_disabled", message="maint", status=503
        )
        with pytest.raises(BackendMaintenance):
            run(service.purge_grant("myteam", "grant-uuid"))
