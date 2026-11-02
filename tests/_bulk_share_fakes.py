"""Fakes for the bulk memory share tests: the service routes and the owner's envelopes.

The team memory service built here is the real one; only the HTTP boundary
and the owner's stored envelopes are faked. Neutral fixtures only.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import nacl.public

import servonaut.services.memory.crypto as crypto_module
from servonaut.services.api_client import APIClient, NotFoundError, RateLimitedError
from servonaut.services.memory.interfaces import MemoryNotFound
from servonaut.services.memory.team_service import TeamMemoryService

SLUG = "team-a"
GRANT_PATH = f"/api/v1/teams/{SLUG}/memory/grant"
KEYS_PATH = f"/api/v1/memory/keys/team/{SLUG}"


def member(user_id: int, name: str, role: str = "member", **extra: Any) -> Dict[str, Any]:
    pub = bytes(nacl.public.PrivateKey.generate().public_key)
    return {
        "user_id": user_id, "fingerprint": crypto_module.fingerprint(pub),
        "public_key_b64": base64.b64encode(pub).decode(), "role": role, "name": name,
        **extra,
    }


def grant(instance_id: str, grant_id: str = "g-1", **extra: Any) -> Dict[str, Any]:
    return {
        "id": grant_id, "instance_id": instance_id, "required_role": "member",
        "modules": ["os", "logs"], "status": "active", "granted_by_user_id": 1,
        "created_at": "2026-10-01T10:00:00Z", "revoked_at": None, **extra,
    }


def rate_limited(retry_after: Optional[str] = None) -> RateLimitedError:
    headers = {"retry-after": retry_after} if retry_after is not None else {}
    return RateLimitedError(code="rate_limited", message="slow down", status=429,
                            response_headers=headers)


class FakeTeamBackend:
    """The service routes a batch uses, with a call log and scripted refusals."""

    def __init__(self, *, members: List[Dict[str, Any]], live: Optional[List[Dict[str, Any]]] = None,
                 stored: Optional[Dict[str, List[str]]] = None) -> None:
        self.members = members
        self.live = live or []
        # instance id -> the modules the service holds for it; absent = 404.
        self.stored = stored if stored is not None else {}
        self.calls: List[str] = []
        self.posted: List[Dict[str, Any]] = []
        # instance id -> errors the next grant POSTs for it raise, in order.
        self.post_errors: Dict[str, List[Exception]] = {}
        # Errors the next calls raise, in order: GETs by path, revokes by
        # grant id, the owner's envelope reads by "<instance id>/<module>".
        self.get_errors: Dict[str, List[Exception]] = {}
        self.delete_errors: Dict[str, List[Exception]] = {}
        self.envelope_errors: Dict[str, List[Exception]] = {}
        self.pending: Dict[str, List[Dict[str, Any]]] = {}
        self.api = MagicMock(spec=APIClient)
        self.api.get.side_effect = self._get
        self.api.post.side_effect = self._post
        self.api.delete.side_effect = self._delete

    async def _get(self, path: str, **_kw: Any) -> Dict[str, Any]:
        self.calls.append(f"GET {path}")
        queued = self.get_errors.get(path, [])
        if queued:
            raise queued.pop(0)
        if path == KEYS_PATH:
            return {"members": self.members}
        return {"instances": [
            {"grant": g, "instance": {"instance_id": g["instance_id"]}, "readable_modules": ["os"]}
            for g in self.live
        ]}

    async def _post(self, path: str, **kw: Any) -> Dict[str, Any]:
        body = kw.get("json") or {}
        self.calls.append(f"POST {path} {body.get('instance_id', '')}".rstrip())
        queued = self.post_errors.get(body.get("instance_id", ""), [])
        if queued:
            raise queued.pop(0)
        self.posted.append(body)
        return grant(body["instance_id"], grant_id=f"g-{body['instance_id']}",
                      required_role=body["required_role"], modules=body["modules"],
                      pending_recipients=self.pending.get(body["instance_id"], []))

    async def _delete(self, path: str, **_kw: Any) -> Dict[str, Any]:
        self.calls.append(f"DELETE {path}")
        grant_id = path.rsplit("/", 1)[1]
        queued = self.delete_errors.get(grant_id, [])
        if queued:
            raise queued.pop(0)
        found = next((g for g in self.live if g["id"] == grant_id), None)
        if found is None:
            raise NotFoundError(code="not_found", message="no such grant", status=404)
        return {**found, "status": "revoked", "revoked_at": "2026-10-02T10:00:00Z"}

    def writes(self) -> List[str]:
        return [c for c in self.calls if not c.startswith("GET")]


def _owner() -> Any:
    private = nacl.public.PrivateKey.generate()
    km = MagicMock()
    km.user_id = 1
    km.private_key, km.public_key = bytes(private), bytes(private.public_key)
    return km


def _retrieval(backend: "FakeTeamBackend", owner: Any) -> MagicMock:
    """The owner's own envelopes: one data key sealed to the owner per module."""

    async def modules(instance_id: str) -> Dict[str, Any]:
        backend.calls.append(f"GET /api/v1/memory/{instance_id}")
        if instance_id not in backend.stored:
            raise MemoryNotFound("access_revoked")
        return {"modules": list(backend.stored[instance_id])}

    async def raw(instance_id: str, module: str) -> Dict[str, Any]:
        queued = backend.envelope_errors.get(f"{instance_id}/{module}", [])
        if queued:
            raise queued.pop(0)
        env = crypto_module.encrypt_envelope(
            b"{}", self_public_key=owner.public_key, self_user_id=owner.user_id).to_dict()
        return {"id": f"e-{module}", "wrapped_dek": env["dek_wraps"][0]["wrapped_dek"]}

    retrieval = MagicMock()
    retrieval.list_instance_modules.side_effect = modules
    retrieval.get_module_envelope_raw.side_effect = raw
    return retrieval


def team_memory_service(backend: "FakeTeamBackend", *, locked: bool = False) -> TeamMemoryService:
    """The real team memory service over *backend*; *locked* = no memory key at hand."""
    owner = _owner()
    return TeamMemoryService(
        api_client=backend.api, auth_service=MagicMock(has_feature=MagicMock(return_value=True)),
        crypto=crypto_module, key_store_provider=lambda: None if locked else owner,
        retrieval_service=_retrieval(backend, owner),
    )
