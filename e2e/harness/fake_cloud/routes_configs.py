"""Config-snapshot routes: encrypted copies of the client's configuration.

This module owns everything under ``/api/v1/configs``. :class:`ConfigSnapshots`
(``FakeCloud.configs``) keeps what clients pushed. As on the service, a
snapshot is ciphertext the server cannot read: ``POST`` requires the
client-side encryption envelope with the shape of AES-256-GCM output
(``encryption``, base64 ``data``, a 16-byte ``salt``, a 12-byte ``iv``, a
16-byte ``tag``) and refuses anything else (422). Listing returns metadata
only, newest first; ``GET /latest`` and ``GET /{id}`` (by snapshot id only)
return the envelope for a restore; ``PATCH`` renames and ``DELETE`` removes.

Key custody: a snapshot is sealed with a passphrase-derived key (``salt``) or
with a random key held in the user's vault (``key_custody: "vault"``, a
``key_id`` naming that key, no salt). The service's two settings decide what is
accepted, and ``DELETE /api/v1/configs?key_custody=passphrase`` (or
``?key_id=<hex>``) removes old copies once a vault snapshot exists.

Every route needs the account's current access token.
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
import os
import re
import threading
import uuid
from typing import Any, Callable, Optional

from aiohttp import web

from e2e.harness.fake_cloud.routes_auth import (
    bearer_ok,
    json_body,
    unauthorized,
    validation_failed,
)
from e2e.harness.fake_cloud.shapes import GCM_IV, GCM_TAG, KDF_SALT, has_bytes, has_size
from e2e.harness.fake_cloud.state import ScenarioStore

CONFIGS = "/api/v1/configs"
ENVELOPE_FIELDS = ("encryption", "data", "salt", "iv", "tag")
ENCRYPTION = "aes-256-gcm"
_METADATA = ("id", "version", "name", "label", "hash", "created_at", "key_custody", "key_id")
KEY_ID = re.compile(r"[0-9a-f]{64}")


def _refusal(status: int, code: str, message: str, **details: Any) -> tuple[int, dict[str, Any]]:
    error: dict[str, Any] = {"code": code, "message": message}
    if details:
        error["details"] = details
    return status, {"error": error}


def _not_found() -> web.Response:
    return web.json_response(
        {"error": {"code": "not_found", "message": "No such snapshot"}}, status=404
    )


class ConfigSnapshots:
    """Thread-safe store of pushed config snapshots."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Wired by FakeCloud: the service's two settings and the key_ids of the
        # user's live ``config_sync_key`` vault items.
        self.custody_enabled: Callable[[], bool] = lambda: True
        self.passphrase_accepted: Callable[[], bool] = lambda: True
        self.vault_key_ids: Callable[[], list[str]] = lambda: []
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._snapshots: list[dict[str, Any]] = []

    def all(self) -> list[dict[str, Any]]:
        """Every stored snapshot, oldest first, envelope included."""
        with self._lock:
            return copy.deepcopy(self._snapshots)

    def uses_key_id(self, key_id: str) -> bool:
        """Whether any snapshot is sealed under the vault key *key_id*."""
        with self._lock:
            return any(s.get("key_id") == key_id for s in self._snapshots)

    def seed_vault_snapshot(self, key_id: Optional[str] = None, *, name: str = "default") -> dict[str, Any]:
        """A snapshot sealed under a vault key (random ciphertext of the right shape)."""
        key_id = key_id or os.urandom(32).hex()
        # Stored directly: a fixture, so the vault-item precondition of a push does not apply.
        return self._append({
            "name": name, "encryption": ENCRYPTION,
            "data": base64.b64encode(os.urandom(48)).decode(),
            "iv": base64.b64encode(os.urandom(12)).decode(),
            "tag": base64.b64encode(os.urandom(16)).decode(),
        }, "vault", key_id)

    def push(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        custody = body.get("key_custody", "passphrase")
        key_id = body.get("key_id")
        if custody not in ("passphrase", "vault"):
            return _refusal(422, "validation_failed", "key_custody must be passphrase or vault", field="key_custody")
        if custody == "vault":
            refusal = self._vault_push_refusal(body, key_id)
        else:
            refusal = self._passphrase_push_refusal(body, key_id)
        if refusal is not None:
            return refusal
        return 201, self._append(body, custody, key_id)

    def _append(self, body: dict[str, Any], custody: str, key_id: Optional[str]) -> dict[str, Any]:
        with self._lock:
            snapshot = {
                "id": str(uuid.uuid4()),
                "version": len(self._snapshots) + 1,
                "name": body.get("name") or "default",
                "label": body.get("label") or "",
                "hash": body.get("hash") or "",
                "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "key_custody": custody,
                "key_id": key_id if custody == "vault" else None,
                "salt": body.get("salt") if custody == "passphrase" else None,
                **{k: body[k] for k in ENVELOPE_FIELDS if k != "salt"},
            }
            self._snapshots.append(snapshot)
            return {k: snapshot[k] for k in _METADATA}

    @staticmethod
    def _envelope_ok(body: dict[str, Any]) -> bool:
        return (
            body.get("encryption") == ENCRYPTION
            and has_bytes(body.get("data"))
            and has_size(body.get("iv"), GCM_IV)
            and has_size(body.get("tag"), GCM_TAG)
        )

    def _vault_push_refusal(self, body: dict[str, Any], key_id: Any) -> Optional[tuple[int, dict[str, Any]]]:
        if not self.custody_enabled():
            return _refusal(503, "feature_disabled", "Vault custody for Memory Sync keys is not available yet.")
        if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
            return _refusal(422, "validation_failed", "key_id must be 64 lowercase hex", field="key_id")
        if body.get("salt") is not None:
            return _refusal(422, "validation_failed", "A vault snapshot has no salt", field="salt")
        if not self._envelope_ok(body):
            return _refusal(422, "validation_failed", "snapshots must carry the client-side encryption envelope")
        if key_id not in self.vault_key_ids():
            return _refusal(409, "config_key_not_ready", "Store your config sync key in your personal vault first.")
        return None

    def _passphrase_push_refusal(self, body: dict[str, Any], key_id: Any) -> Optional[tuple[int, dict[str, Any]]]:
        if key_id is not None:
            return _refusal(422, "validation_failed", "key_id belongs to vault snapshots", field="key_id")
        if not self.passphrase_accepted():
            return _refusal(409, "config_key_custody_vault", "Update Servonaut to use config sync.")
        if not self._envelope_ok(body) or not has_size(body.get("salt"), KDF_SALT):
            return _refusal(422, "validation_failed", "snapshots must carry the client-side encryption envelope")
        return None

    def delete_many(self, query: Any) -> tuple[int, dict[str, Any]]:
        """Bulk delete by ``key_custody=passphrase`` or by ``key_id`` (exactly one of them)."""
        custody, key_id = query.get("key_custody"), query.get("key_id")
        if (custody is None) == (key_id is None):
            return _refusal(422, "validation_failed", "Pass exactly one of key_custody and key_id",
                            field="key_custody")
        if custody is not None and custody != "passphrase":
            return _refusal(422, "validation_failed", "key_custody must be passphrase", field="key_custody")
        if key_id is not None and not KEY_ID.fullmatch(key_id):
            return _refusal(422, "validation_failed", "key_id must be 64 lowercase hex", field="key_id")
        with self._lock:
            # Never leave the user without a readable copy: another vault snapshot must exist.
            safe = any(
                s["key_custody"] == "vault" and (custody is not None or s["key_id"] != key_id)
                for s in self._snapshots
            )
            if not safe:
                return _refusal(409, "no_vault_snapshot",
                                "Upload your config under the vault key before removing the old copies.")
            keep = [
                s for s in self._snapshots
                if not (s["key_custody"] == "passphrase" if custody is not None else s["key_id"] == key_id)
            ]
            deleted = len(self._snapshots) - len(keep)
            self._snapshots = keep
            return 200, {"deleted": deleted}

    def listing(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            newest_first = list(reversed(self._snapshots))[:limit]
            return [{k: s[k] for k in _METADATA} for s in newest_first]

    def latest(self) -> Optional[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._snapshots[-1]) if self._snapshots else None

    def find(self, snapshot_id: str) -> Optional[dict[str, Any]]:
        """The snapshot with this id (never looked up by version)."""
        with self._lock:
            for snapshot in self._snapshots:
                if snapshot["id"] == snapshot_id:
                    return copy.deepcopy(snapshot)
        return None

    def rename(self, key: str, label: str) -> Optional[dict[str, Any]]:
        with self._lock:
            for snapshot in self._snapshots:
                if snapshot["id"] == key:
                    snapshot["label"] = label
                    return {k: snapshot[k] for k in _METADATA}
        return None

    def delete(self, key: str) -> bool:
        with self._lock:
            before = len(self._snapshots)
            self._snapshots = [s for s in self._snapshots if s["id"] != key]
            return len(self._snapshots) != before


def add_routes(app: web.Application, store: ScenarioStore, snapshots: ConfigSnapshots) -> None:
    """Register the config-snapshot routes on *app*."""

    def guarded(handler: Any) -> Any:
        async def wrapper(request: web.Request) -> web.StreamResponse:
            if not bearer_ok(request, store):
                return unauthorized()
            return await handler(request)

        return wrapper

    async def push(request: web.Request) -> web.Response:
        status, body = snapshots.push(await json_body(request))
        return web.json_response(body, status=status)

    async def delete_many(request: web.Request) -> web.Response:
        status, body = snapshots.delete_many(request.query)
        return web.json_response(body, status=status)

    async def listing(request: web.Request) -> web.Response:
        try:
            limit = max(1, min(int(request.query.get("limit", "30")), 100))
        except ValueError:
            return validation_failed("limit must be an integer")
        return web.json_response({"snapshots": snapshots.listing(limit)})

    async def latest(request: web.Request) -> web.Response:
        snapshot = snapshots.latest()
        return web.json_response(snapshot) if snapshot else _not_found()

    async def fetch(request: web.Request) -> web.Response:
        snapshot = snapshots.find(request.match_info["snapshot_id"])
        return web.json_response(snapshot) if snapshot else _not_found()

    async def rename(request: web.Request) -> web.Response:
        body = await json_body(request)
        label = body.get("label")
        if not isinstance(label, str) or not label.strip():
            return validation_failed("label is required")
        renamed = snapshots.rename(request.match_info["snapshot_id"], label)
        return web.json_response(renamed) if renamed else _not_found()

    async def delete(request: web.Request) -> web.Response:
        if not snapshots.delete(request.match_info["snapshot_id"]):
            return _not_found()
        return web.Response(status=204)

    one = f"{CONFIGS}/{{snapshot_id}}"
    app.router.add_post(CONFIGS, guarded(push))
    app.router.add_get(CONFIGS, guarded(listing))
    app.router.add_delete(CONFIGS, guarded(delete_many))
    app.router.add_get(f"{CONFIGS}/latest", guarded(latest))
    app.router.add_get(one, guarded(fetch))
    app.router.add_patch(one, guarded(rename))
    app.router.add_delete(one, guarded(delete))
