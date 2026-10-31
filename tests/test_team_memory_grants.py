"""Changing a team memory share: who can read it, revoke, share again, purge.

The service is real; only the HTTP boundary is faked, with the routes and
response shapes the Servonaut service documents.
"""

from __future__ import annotations

import asyncio
import base64
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import nacl.public
import pytest

import servonaut.services.memory.crypto as crypto_module
from servonaut.services.api_client import APIClient
from servonaut.services.memory.team_service import TeamMemberKey, TeamMemoryService

SLUG = "team-a"
INSTANCE = "i-owner-1"


def _grant_json(grant_id: str = "g-1", *, status: str = "active", **extra: Any) -> Dict[str, Any]:
    return {
        "id": grant_id,
        "instance_id": INSTANCE,
        "required_role": "member",
        "modules": ["os", "services"],
        "status": status,
        "granted_by_user_id": 1,
        "created_at": "2026-10-01T10:00:00Z",
        "revoked_at": None,
        **extra,
    }


def _listing(*grants: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "instances": [
            {
                "grant": g,
                "instance": {"instance_id": g["instance_id"], "display_name": "web-1"},
                "readable_modules": ["os"],
                "stale_modules": [],
            }
            for g in grants
        ]
    }


def _member_json(user_id: int, name: str, role: str = "member") -> Dict[str, Any]:
    pub = bytes(nacl.public.PrivateKey.generate().public_key)
    return {
        "user_id": user_id,
        "fingerprint": f"{user_id:064x}",
        "public_key_b64": base64.b64encode(pub).decode(),
        "role": role,
        "name": name,
        "key_changed": False,
    }


@pytest.fixture
def api() -> MagicMock:
    api = MagicMock(spec=APIClient)
    api.get = AsyncMock(return_value=_listing())
    api.post = AsyncMock(return_value=_grant_json("g-2"))
    api.delete = AsyncMock(return_value=_grant_json("g-1", status="revoked"))
    return api


@pytest.fixture
def service(api: MagicMock) -> TeamMemoryService:
    auth = MagicMock()
    auth.has_feature = MagicMock(return_value=True)
    retrieval = MagicMock()
    retrieval.list_instance_modules = AsyncMock(return_value={"modules": []})
    return TeamMemoryService(
        api_client=api,
        auth_service=auth,
        crypto=crypto_module,
        key_store_provider=MagicMock(),
        retrieval_service=retrieval,
    )


def run(coro):
    return asyncio.run(coro)


class TestMemberKeys:
    def test_keys_carry_the_member_name(self, service, api):
        api.get.return_value = {"members": [_member_json(7, "Sam Doe")]}
        keys = run(service.list_team_member_keys(SLUG))
        assert [k.name for k in keys] == ["Sam Doe"]

    def test_eligible_members_are_at_or_above_the_role(self, service):
        keys = [
            TeamMemberKey(1, "f" * 64, "AAAA", "viewer", "V"),
            TeamMemberKey(2, "f" * 64, "AAAA", "member", "M"),
            TeamMemberKey(3, "f" * 64, "AAAA", "admin", "A"),
        ]
        assert [k.name for k in service.eligible_members(keys, "member")] == ["M", "A"]


class TestShareResult:
    def test_create_response_lists_who_has_no_memory_key(self, service, api):
        api.post.return_value = _grant_json(
            "g-2",
            pending_recipients=[
                {"user_id": 9, "name": "Kim Roe", "role": "member", "reason": "no_memory_key"}
            ],
        )
        grant = run(service.share_instance(SLUG, INSTANCE, "member", ["os"], []))
        assert [p["name"] for p in grant.pending_recipients] == ["Kim Roe"]

    def test_no_pending_recipients_is_an_empty_list(self, service, api):
        grant = run(service.share_instance(SLUG, INSTANCE, "member", ["os"], []))
        assert grant.pending_recipients == []


class TestLiveGrantLookup:
    def test_grant_id_comes_from_the_list_route(self, service, api):
        api.get.return_value = _listing(_grant_json("g-77"))
        grant = run(service.find_live_grant(SLUG, INSTANCE))
        assert grant is not None and grant.id == "g-77"
        api.get.assert_awaited_once_with(f"/api/v1/teams/{SLUG}/memory")

    def test_a_revoked_grant_is_not_live(self, service, api):
        api.get.return_value = _listing(_grant_json("g-1", status="revoked"))
        assert run(service.find_live_grant(SLUG, INSTANCE)) is None

    def test_another_servers_grant_is_not_this_ones(self, service, api):
        other = _grant_json("g-3")
        other["instance_id"] = "i-other"
        api.get.return_value = _listing(other)
        assert run(service.find_live_grant(SLUG, INSTANCE)) is None


class TestShareAgain:
    def test_revokes_then_grants_in_order_without_a_purge(self, service, api):
        order: List[str] = []
        api.delete.side_effect = lambda path, **kw: order.append(f"DELETE {path}") or _grant_json(
            "g-1", status="revoked"
        )
        api.post.side_effect = lambda path, **kw: order.append(f"POST {path}") or _grant_json("g-2")
        run(service.reshare_instance(SLUG, "g-1", INSTANCE, "member", ["os"], []))
        assert order == [
            f"DELETE /api/v1/teams/{SLUG}/memory/grant/g-1",
            f"POST /api/v1/teams/{SLUG}/memory/grant",
        ]

    def test_a_failed_revoke_creates_no_grant(self, service, api):
        api.delete.side_effect = RuntimeError("boom")
        with pytest.raises(RuntimeError):
            run(service.reshare_instance(SLUG, "g-1", INSTANCE, "member", ["os"], []))
        api.post.assert_not_awaited()


class TestListMemo:
    def test_repeated_lookups_inside_the_ttl_ask_once(self, api):
        auth = MagicMock()
        auth.has_feature = MagicMock(return_value=True)
        svc = TeamMemoryService(
            api_client=api, auth_service=auth, crypto=crypto_module,
            key_store_provider=MagicMock(), retrieval_service=MagicMock(),
            cache_ttl_provider=lambda: 60.0,
        )
        run(svc.find_live_grant(SLUG, INSTANCE))
        run(svc.find_live_grant(SLUG, INSTANCE))
        assert api.get.await_count == 1

    def test_a_revoke_forgets_the_memo(self, api):
        auth = MagicMock()
        auth.has_feature = MagicMock(return_value=True)
        svc = TeamMemoryService(
            api_client=api, auth_service=auth, crypto=crypto_module,
            key_store_provider=MagicMock(), retrieval_service=MagicMock(),
            cache_ttl_provider=lambda: 60.0,
        )
        run(svc.find_live_grant(SLUG, INSTANCE))
        run(svc.revoke_grant(SLUG, "g-1"))
        run(svc.find_live_grant(SLUG, INSTANCE))
        assert api.get.await_count == 2

    def test_no_ttl_means_no_memo(self, service, api):
        run(service.find_live_grant(SLUG, INSTANCE))
        run(service.find_live_grant(SLUG, INSTANCE))
        assert api.get.await_count == 2
