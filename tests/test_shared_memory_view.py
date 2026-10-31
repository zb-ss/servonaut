"""A member reads the memory a team shares with them.

The decrypt path uses the real crypto with generated keys; only the HTTP
boundary is faked.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import nacl.public
import pytest

import servonaut.services.memory.crypto as crypto_module
from servonaut.services.api_client import APIClient, NotFoundError
from servonaut.services.memory.shared_view import SharedMemoryReader
from servonaut.services.memory.team_service import TeamMemoryService

SLUG = "team-a"
OWNER_INSTANCE = "i-owner-1"
MEMBER_ID = 7


def run(coro):
    return asyncio.run(coro)




def _sealed_for(material: Any, payload: Dict[str, Any], probed_at: str) -> Dict[str, Any]:
    env = crypto_module.encrypt_envelope(
        json.dumps(payload).encode(),
        self_public_key=material.public_key,
        self_user_id=material.user_id,
    )
    data = env.to_dict()
    data["wrapped_dek"] = data.pop("dek_wraps")[0]["wrapped_dek"]
    data.update({"id": "e-1", "probed_at": probed_at, "is_latest": True,
        "instance_id": OWNER_INSTANCE, "module": "os"})
    return data


class _Backend:
    def __init__(self, material: Any, *, granted: bool = True) -> None:
        self.material = material
        self.granted = granted
        self.api = MagicMock(spec=APIClient)
        self.api.get = AsyncMock(side_effect=self._get)
        self.api.post = AsyncMock()
        self.api.delete = AsyncMock()
        self.reads: List[str] = []

    async def _get(self, path: str, **_kw: Any) -> Dict[str, Any]:
        if path == f"/api/v1/teams/{SLUG}/memory":
            if not self.granted:
                return {"instances": []}
            return {"instances": [{
                "grant": {
                    "id": "g-1", "instance_id": OWNER_INSTANCE, "required_role": "member",
                    "modules": None, "status": "active", "granted_by_user_id": 1,
                    "created_at": "2026-10-01T10:00:00Z", "revoked_at": None,
                },
                "instance": {"instance_id": OWNER_INSTANCE, "last_probe_at": "2026-10-20T08:00:00Z"},
                "readable_modules": ["os"], "stale_modules": [],
            }]}
        self.reads.append(path)
        if not self.granted:
            raise NotFoundError(code="not_found", message="access_revoked", status=404)
        return _sealed_for(
            self.material,
            {"observed": {"distro": "Debian 12"}, "declared": {}, "raw_output": "x"},
            "2026-10-20T08:00:00Z",
        )


def _reader(backend: _Backend, material: Any, ttl: float = 60.0) -> SharedMemoryReader:
    auth = MagicMock()
    auth.has_feature = MagicMock(return_value=True)
    service = TeamMemoryService(
        api_client=backend.api, auth_service=auth, crypto=crypto_module,
        key_store_provider=lambda: material, retrieval_service=MagicMock(),
    )
    return SharedMemoryReader(service, lambda: ttl)


@pytest.fixture
def material() -> Any:
    private = nacl.public.PrivateKey.generate()
    km = MagicMock()
    km.user_id = MEMBER_ID
    km.private_key = bytes(private)
    km.public_key = bytes(private.public_key)
    return km


def test_a_member_with_a_grant_sees_the_shared_os_module(material):
    backend = _Backend(material)
    shared = run(_reader(backend, material).read(SLUG, "Team A", OWNER_INSTANCE))
    assert shared is not None
    assert shared.modules["os"]["observed"] == {"distro": "Debian 12"}
    assert shared.modules["os"]["probed_at"] == "2026-10-20T08:00:00Z"
    assert shared.probed_at == "2026-10-20T08:00:00Z"
    assert shared.team_name == "Team A"


def test_reading_never_uploads(material):
    backend = _Backend(material)
    run(_reader(backend, material).read(SLUG, "Team A", OWNER_INSTANCE))
    backend.api.post.assert_not_awaited()
    backend.api.delete.assert_not_awaited()


def test_a_member_without_a_grant_sees_nothing(material):
    backend = _Backend(material, granted=False)
    assert run(_reader(backend, material).read(SLUG, "Team A", OWNER_INSTANCE)) is None


def test_a_revoked_read_is_nothing_shared_not_an_error(material):
    backend = _Backend(material)
    service = _reader(backend, material)._team_service
    backend.granted = False
    assert run(service.read_shared_module(SLUG, OWNER_INSTANCE, "os")) is None


def test_a_locked_key_reads_nothing_and_asks_nothing(material):
    backend = _Backend(material)
    reader = _reader(backend, None)
    assert run(reader.read(SLUG, "Team A", OWNER_INSTANCE)) is None
    assert backend.reads == []


def test_a_copy_sealed_to_someone_else_is_not_shown(material):
    backend = _Backend(material)
    other = MagicMock()
    other.user_id = 99
    other_private = nacl.public.PrivateKey.generate()
    other.private_key, other.public_key = bytes(other_private), bytes(other_private.public_key)
    assert run(_reader(backend, other).read(SLUG, "Team A", OWNER_INSTANCE)) is None


def test_the_answer_is_reused_inside_the_ttl(material):
    backend = _Backend(material)
    reader = _reader(backend, material)
    run(reader.read(SLUG, "Team A", OWNER_INSTANCE))
    run(reader.read(SLUG, "Team A", OWNER_INSTANCE))
    assert len(backend.reads) == 1


def test_the_listing_gives_a_count_and_an_age_without_opening_anything(material):
    backend = _Backend(material)
    reader = _reader(backend, material)
    run(reader.prefetch_listing(SLUG))
    listing = reader.cached_listing(SLUG, OWNER_INSTANCE)
    assert listing is not None
    assert (listing.module_count, listing.last_probe_at) == (1, "2026-10-20T08:00:00Z")
    assert backend.reads == []
