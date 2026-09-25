"""Config-snapshot routes: encrypted copies of the client's configuration.

This module owns everything under ``/api/v1/configs``. :class:`ConfigSnapshots`
(``FakeCloud.configs``) keeps what clients pushed. As on the service, a
snapshot is ciphertext the server cannot read: ``POST`` requires the
client-side encryption envelope (``encryption``, ``data``, ``salt``, ``iv``,
``tag``) and refuses a body that carries none (422). Listing returns
metadata only, newest first; ``GET /latest`` and ``GET /{id}`` return the
envelope for a restore; ``PATCH`` renames and ``DELETE`` removes.

Every route needs the account's current access token.
"""

from __future__ import annotations

import copy
import datetime as dt
import threading
import uuid
from typing import Any, Optional

from aiohttp import web

from e2e.harness.fake_cloud.routes_auth import (
    bearer_ok,
    json_body,
    unauthorized,
    validation_failed,
)
from e2e.harness.fake_cloud.state import ScenarioStore

CONFIGS = "/api/v1/configs"
ENVELOPE_FIELDS = ("encryption", "data", "salt", "iv", "tag")
_METADATA = ("id", "version", "name", "label", "hash", "created_at")


def _not_found() -> web.Response:
    return web.json_response(
        {"error": {"code": "not_found", "message": "No such snapshot"}}, status=404
    )


class ConfigSnapshots:
    """Thread-safe store of pushed config snapshots."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._snapshots: list[dict[str, Any]] = []

    def all(self) -> list[dict[str, Any]]:
        """Every stored snapshot, oldest first, envelope included."""
        with self._lock:
            return copy.deepcopy(self._snapshots)

    def push(self, body: dict[str, Any]) -> Optional[dict[str, Any]]:
        if any(not isinstance(body.get(k), str) or not body[k] for k in ENVELOPE_FIELDS):
            return None
        with self._lock:
            snapshot = {
                "id": str(uuid.uuid4()),
                "version": len(self._snapshots) + 1,
                "name": body.get("name") or "default",
                "label": body.get("label") or "",
                "hash": body.get("hash") or "",
                "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                **{k: body[k] for k in ENVELOPE_FIELDS},
            }
            self._snapshots.append(snapshot)
            return {k: snapshot[k] for k in _METADATA}

    def listing(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            newest_first = list(reversed(self._snapshots))[:limit]
            return [{k: s[k] for k in _METADATA} for s in newest_first]

    def find(self, key: str) -> Optional[dict[str, Any]]:
        with self._lock:
            if key == "latest":
                return copy.deepcopy(self._snapshots[-1]) if self._snapshots else None
            for snapshot in self._snapshots:
                if snapshot["id"] == key or str(snapshot["version"]) == key:
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
        created = snapshots.push(await json_body(request))
        if created is None:
            return validation_failed("snapshots must carry the client-side encryption envelope")
        return web.json_response(created, status=201)

    async def listing(request: web.Request) -> web.Response:
        try:
            limit = max(1, min(int(request.query.get("limit", "30")), 100))
        except ValueError:
            return validation_failed("limit must be an integer")
        return web.json_response({"snapshots": snapshots.listing(limit)})

    async def fetch(request: web.Request) -> web.Response:
        snapshot = snapshots.find(request.match_info.get("snapshot_id", "latest"))
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
    app.router.add_get(f"{CONFIGS}/latest", guarded(fetch))
    app.router.add_get(one, guarded(fetch))
    app.router.add_patch(one, guarded(rename))
    app.router.add_delete(one, guarded(delete))
