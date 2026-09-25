"""Memory Sync routes: the encrypted server-memory store and team sharing.

This module owns everything under ``/api/v1/memory/`` plus the team-memory
grants under ``/api/v1/teams/{slug}/memory``. :class:`MemoryCloud`
(``FakeCloud.memory``) holds what a client uploaded:

* the account's keypair, as the client enrolled it (``POST /keys``;
  ``GET /keys/me`` answers 404 until then), and the team members' public
  keys a journey adds with :meth:`MemoryCloud.add_team_member`;
* registered instances and every envelope ``POST /sync`` accepted. Like the
  service, the fake stores ciphertext it cannot read: each envelope must be
  AES-256-GCM with a DEK wrapped to the caller, or it is rejected
  (``missing_self_wrap``, ``unknown_instance``, ``invalid_envelope``);
* drift events a journey records with :meth:`MemoryCloud.record_drift`,
  linking the two newest envelopes of one module, and their
  acknowledgements;
* team grants (``POST /teams/{slug}/memory/grant``), whose DEK wraps must
  reference stored envelopes and known team members.

Every route needs the account's current access token.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import itertools
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
from e2e.harness.fake_cloud.state import ScenarioStore

MEMORY = "/api/v1/memory"
SYNC_PATH = f"{MEMORY}/sync"
KEYS_PATH = f"{MEMORY}/keys"
DRIFT_PATH = f"{MEMORY}/drift"
ENCRYPTION = "aes-256-gcm"
ENVELOPE_FIELDS = ("instance_id", "module", "iv", "tag", "ciphertext", "probed_at")
KEY_FIELDS = ("public_key", "wrapped_private_key", "fingerprint")
TEAM_ROLES = ("viewer", "member", "admin", "owner")
QUOTA = {"envelopes_soft_cap": 50000, "envelopes_hard_cap": 100000, "retention_days": 30}
# Envelope fields a retrieval answer carries besides the ciphertext.
_METADATA = (
    "instance_id",
    "module",
    "probed_at",
    "ttl_seconds",
    "truncated",
    "partial",
    "sudo_used",
    "safe_metrics",
)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _error(code: str, message: str, status: int) -> web.Response:
    return web.json_response({"error": {"code": code, "message": message}}, status=status)


def _not_found(message: str = "Not found") -> web.Response:
    return _error("not_found", message, 404)


class MemoryCloud:
    """Thread-safe server-side memory state for the one fake account."""

    def __init__(self, user_id: Callable[[], int]) -> None:
        self._user_id = user_id
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._key: Optional[dict[str, Any]] = None
            self._key_history: list[dict[str, Any]] = []
            self._instances: dict[str, dict[str, Any]] = {}
            self._envelopes: list[dict[str, Any]] = []
            self._drift: list[dict[str, Any]] = []
            self._members: dict[str, list[dict[str, Any]]] = {}
            self._grants: list[dict[str, Any]] = []
            self._settings: dict[str, Any] = {
                "digest_frequency": "off",
                "mercure_push_enabled": False,
                "auto_sync_enabled": False,
                "ai_consent_mode": "off",
                "anomaly_rules": {},
            }
            self._ids = itertools.count(1)

    # ------------------------------------------------------------------
    # Journey controls and observations
    # ------------------------------------------------------------------

    def enrolled_key(self) -> Optional[dict[str, Any]]:
        """The keypair the client enrolled (wrapped private key included)."""
        with self._lock:
            return copy.deepcopy(self._key)

    def instances(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._instances)

    def envelopes(
        self, instance_id: Optional[str] = None, module: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Stored envelopes, oldest first, exactly as uploaded (plus id)."""
        with self._lock:
            return [
                copy.deepcopy(e)
                for e in self._envelopes
                if (instance_id is None or e["instance_id"] == instance_id)
                and (module is None or e["module"] == module)
            ]

    def add_team_member(
        self, team_slug: str, user_id: int, public_key_b64: str, *, role: str = "member"
    ) -> None:
        """A teammate with an enrolled keypair (their private key stays with the test)."""
        if role not in TEAM_ROLES:
            raise ValueError(f"role must be one of {TEAM_ROLES}")
        with self._lock:
            self._members.setdefault(team_slug, []).append(
                {
                    "user_id": user_id,
                    "public_key_b64": public_key_b64,
                    "fingerprint": hashlib.sha256(public_key_b64.encode()).hexdigest(),
                    "role": role,
                }
            )

    def record_drift(self, instance_id: str, module: str, *, severity: str = "medium") -> str:
        """Detect drift between the two newest envelopes of one module."""
        with self._lock:
            stored = [
                e
                for e in self._envelopes
                if e["instance_id"] == instance_id and e["module"] == module
            ]
            if not stored:
                raise ValueError(f"no envelopes stored for {instance_id}/{module}")
            new = stored[-1]
            old = stored[-2] if len(stored) > 1 else None
            event = {
                "id": str(uuid.uuid4()),
                "instance_id": instance_id,
                "module": module,
                "old_hash": _digest(old) if old else None,
                "new_hash": _digest(new),
                "probed_at": new["probed_at"],
                "detected_at": _now(),
                "severity": severity,
                "acknowledged_at": None,
                "old_envelope_id": old["id"] if old else None,
                "new_envelope_id": new["id"],
            }
            self._drift.append(event)
            return event["id"]

    def drift_events(self) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._drift)

    def grants(self, team_slug: Optional[str] = None) -> list[dict[str, Any]]:
        """Grants created so far, with the DEK wraps the client sent."""
        with self._lock:
            return [
                copy.deepcopy(g)
                for g in self._grants
                if team_slug is None or g["team_slug"] == team_slug
            ]

    # ------------------------------------------------------------------
    # Operations behind the routes
    # ------------------------------------------------------------------

    def settings(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._settings)

    def enrol(self, body: dict[str, Any]) -> Optional[str]:
        missing = [k for k in KEY_FIELDS if not isinstance(body.get(k), str) or not body[k]]
        if missing:
            return f"missing {', '.join(missing)}"
        with self._lock:
            if self._key is not None:
                self._key_history.append(self._key)
            self._key = {k: body[k] for k in KEY_FIELDS}
            self._key["created_at"] = _now()
        return None

    def upsert_instance(self, body: dict[str, Any]) -> dict[str, Any]:
        instance_id = str(body.get("instance_id") or "")
        with self._lock:
            created = instance_id not in self._instances
            self._instances[instance_id] = {
                "instance_id": instance_id,
                "display_name": body.get("display_name") or instance_id,
                "provider": body.get("provider") or "custom",
                "memory_disabled": bool(body.get("memory_disabled")),
                "last_probe_at": self._instances.get(instance_id, {}).get("last_probe_at"),
            }
            return {**self._instances[instance_id], "created": created}

    def accept(self, envelopes: list[Any]) -> dict[str, Any]:
        user_id = self._user_id()
        accepted: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        with self._lock:
            for index, envelope in enumerate(envelopes):
                reason = self._rejection(envelope, user_id)
                if reason:
                    rejected.append({"index": index, "reason": reason, "message": reason})
                    continue
                stored = copy.deepcopy(envelope)
                stored["id"] = str(uuid.uuid4())
                stored["created_at"] = _now()
                stored["snapshot_version"] = 1 + sum(
                    e["instance_id"] == envelope["instance_id"]
                    and e["module"] == envelope["module"]
                    for e in self._envelopes
                )
                self._envelopes.append(stored)
                self._instances[envelope["instance_id"]]["last_probe_at"] = envelope["probed_at"]
                accepted.append({"index": index, "id": stored["id"]})
            quota = {**QUOTA, "envelopes_used": len(self._envelopes)}
        return {"accepted": accepted, "rejected": rejected, "quota": quota}

    def _rejection(self, envelope: Any, user_id: int) -> Optional[str]:
        if not isinstance(envelope, dict) or any(
            not envelope.get(field) for field in ENVELOPE_FIELDS
        ):
            return "invalid_envelope"
        if envelope.get("encryption") != ENCRYPTION:
            return "invalid_envelope"
        if envelope["instance_id"] not in self._instances:
            return "unknown_instance"
        wraps = envelope.get("dek_wraps")
        if not isinstance(wraps, list) or not any(
            isinstance(w, dict) and w.get("recipient_user_id") == user_id and w.get("wrapped_dek")
            for w in wraps
        ):
            return "missing_self_wrap"
        return None

    def retrieval(self, envelope: dict[str, Any], user_id: int) -> Optional[dict[str, Any]]:
        """An envelope as the service returns it: addressed to the caller only."""
        wrap = next(
            (w for w in envelope["dek_wraps"] if w.get("recipient_user_id") == user_id), None
        )
        if wrap is None:
            return None
        answer = {k: envelope.get(k) for k in _METADATA}
        answer.update(
            {
                "id": envelope["id"],
                "snapshot_version": envelope["snapshot_version"],
                "created_at": envelope["created_at"],
                "iv": envelope["iv"],
                "tag": envelope["tag"],
                "salt": envelope.get("salt"),
                "ciphertext": envelope["ciphertext"],
                "encryption": envelope["encryption"],
                "wrapped_dek": wrap["wrapped_dek"],
            }
        )
        return answer

    def find(self, **match: str) -> list[dict[str, Any]]:
        with self._lock:
            return [
                copy.deepcopy(e)
                for e in self._envelopes
                if all(e.get(key) == value for key, value in match.items())
            ]

    def team_keys(self, team_slug: str) -> list[dict[str, Any]]:
        """Members with an enrolled keypair: the caller (as owner) and teammates."""
        with self._lock:
            members = copy.deepcopy(self._members.get(team_slug, []))
            key = copy.deepcopy(self._key)
        if key is not None:
            members.insert(
                0,
                {
                    "user_id": self._user_id(),
                    "public_key_b64": key["public_key"],
                    "fingerprint": key["fingerprint"],
                    "role": "owner",
                },
            )
        return members

    def create_grant(self, team_slug: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        instance_id = str(body.get("instance_id") or "")
        role = body.get("required_role")
        wraps = body.get("wraps")
        members = {m["user_id"] for m in self.team_keys(team_slug)}
        with self._lock:
            if instance_id not in self._instances:
                return 404, {"error": {"code": "not_found", "message": "unknown instance"}}
            if role not in TEAM_ROLES or not isinstance(wraps, list):
                return 422, {"error": {"code": "validation_failed", "message": "bad grant"}}
            stored_ids = {e["id"] for e in self._envelopes if e["instance_id"] == instance_id}
            for wrap in wraps:
                if (
                    not isinstance(wrap, dict)
                    or wrap.get("envelope_id") not in stored_ids
                    or wrap.get("recipient_user_id") not in members
                    or not wrap.get("wrapped_dek")
                ):
                    return 422, {
                        "error": {"code": "validation_failed", "message": "invalid wrap"}
                    }
            if any(
                g["team_slug"] == team_slug
                and g["instance_id"] == instance_id
                and g["status"] == "active"
                for g in self._grants
            ):
                return 409, {"error": {"code": "grant_exists", "message": "already shared"}}
            grant = {
                "id": str(uuid.uuid4()),
                "team_slug": team_slug,
                "instance_id": instance_id,
                "required_role": role,
                "modules": body.get("modules"),
                "status": "active",
                "granted_by_user_id": self._user_id(),
                "created_at": _now(),
                "revoked_at": None,
                "wraps": copy.deepcopy(wraps),
            }
            self._grants.append(grant)
        return 201, _public_grant(grant)

    def shared_instances(self, team_slug: str) -> list[dict[str, Any]]:
        rows = []
        for grant in self.grants(team_slug):
            with self._lock:
                instance = copy.deepcopy(self._instances.get(grant["instance_id"], {}))
                wrapped = {w["envelope_id"] for w in grant["wraps"]}
                modules = sorted(
                    {e["module"] for e in self._envelopes if e["id"] in wrapped}
                )
            rows.append(
                {"grant": _public_grant(grant), "instance": instance, "readable_modules": modules}
            )
        return rows

    def acknowledge(self, event_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            for event in self._drift:
                if event["id"] == event_id:
                    event["acknowledged_at"] = event["acknowledged_at"] or _now()
                    return {"id": event_id, "acknowledged_at": event["acknowledged_at"]}
        return None

    def fleet(self) -> dict[str, Any]:
        with self._lock:
            instances = copy.deepcopy(list(self._instances.values()))
            drift = copy.deepcopy(self._drift)
        items = [
            {
                "instance": instance,
                "drift_count_7d": sum(e["instance_id"] == instance["instance_id"] for e in drift),
                "memory_age": "fresh" if instance.get("last_probe_at") else "unknown",
            }
            for instance in instances
        ]
        by_provider: dict[str, int] = {}
        for instance in instances:
            by_provider[instance["provider"]] = by_provider.get(instance["provider"], 0) + 1
        probes = [i["last_probe_at"] for i in instances if i.get("last_probe_at")]
        return {
            "total": len(items),
            "by_provider": by_provider,
            "oldest_last_probe_at": min(probes) if probes else None,
            "items": items,
        }


def _digest(envelope: dict[str, Any]) -> str:
    return hashlib.sha256(envelope["ciphertext"].encode()).hexdigest()


def _public_grant(grant: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in grant.items() if k not in ("wraps", "team_slug")}


def add_routes(app: web.Application, store: ScenarioStore, memory: MemoryCloud) -> None:
    """Register the memory routes on *app* (fixed paths before patterns)."""

    def guarded(handler: Any) -> Any:
        async def wrapper(request: web.Request) -> web.StreamResponse:
            if not bearer_ok(request, store):
                return unauthorized()
            return await handler(request)

        return wrapper

    def user_id() -> int:
        return store.snapshot().user_id

    async def settings(request: web.Request) -> web.Response:
        return web.json_response(memory.settings())

    async def key_me(request: web.Request) -> web.Response:
        key = memory.enrolled_key()
        if key is None:
            return _not_found("No active keypair")
        return web.json_response(key)

    async def enrol(request: web.Request) -> web.Response:
        problem = memory.enrol(await json_body(request))
        if problem:
            return validation_failed(problem)
        key = memory.enrolled_key() or {}
        return web.json_response({"fingerprint": key.get("fingerprint")}, status=201)

    async def team_keys(request: web.Request) -> web.Response:
        return web.json_response({"members": memory.team_keys(request.match_info["team_slug"])})

    async def upsert_instance(request: web.Request) -> web.Response:
        body = await json_body(request)
        if not body.get("instance_id"):
            return validation_failed("instance_id is required")
        return web.json_response(memory.upsert_instance(body))

    async def sync(request: web.Request) -> web.Response:
        body = await json_body(request)
        envelopes = body.get("envelopes")
        if not isinstance(envelopes, list) or not envelopes:
            return validation_failed("envelopes must be a non-empty list")
        return web.json_response(memory.accept(envelopes))

    async def fleet(request: web.Request) -> web.Response:
        return web.json_response(memory.fleet())

    async def drift(request: web.Request) -> web.Response:
        return web.json_response({"drift_events": memory.drift_events()})

    async def drift_ack(request: web.Request) -> web.Response:
        answer = memory.acknowledge(request.match_info["event_id"])
        return web.json_response(answer) if answer else _not_found("No such drift event")

    async def instance_modules(request: web.Request) -> web.Response:
        instance_id = request.match_info["instance_id"]
        instance = memory.instances().get(instance_id)
        if instance is None:
            return _not_found("No such instance")
        modules = sorted({e["module"] for e in memory.find(instance_id=instance_id)})
        return web.json_response({"instance": instance, "modules": modules})

    def _answer(found: list[dict[str, Any]]) -> web.Response:
        if not found:
            return _not_found("No snapshot")
        envelope = memory.retrieval(found[-1], user_id())
        return web.json_response(envelope) if envelope else _not_found("No snapshot")

    async def latest(request: web.Request) -> web.Response:
        return _answer(
            memory.find(
                instance_id=request.match_info["instance_id"],
                module=request.match_info["module"],
            )
        )

    async def snapshot(request: web.Request) -> web.Response:
        return _answer(
            memory.find(
                instance_id=request.match_info["instance_id"],
                module=request.match_info["module"],
                id=request.match_info["snapshot_id"],
            )
        )

    async def create_grant(request: web.Request) -> web.Response:
        status, body = memory.create_grant(
            request.match_info["team_slug"], await json_body(request)
        )
        return web.json_response(body, status=status)

    async def shared(request: web.Request) -> web.Response:
        return web.json_response(
            {"instances": memory.shared_instances(request.match_info["team_slug"])}
        )

    router = app.router
    router.add_get(f"{MEMORY}/settings", guarded(settings))
    router.add_get(f"{KEYS_PATH}/me", guarded(key_me))
    router.add_post(KEYS_PATH, guarded(enrol))
    router.add_get(f"{KEYS_PATH}/team/{{team_slug}}", guarded(team_keys))
    router.add_post(f"{MEMORY}/instances", guarded(upsert_instance))
    router.add_post(SYNC_PATH, guarded(sync))
    router.add_get(f"{MEMORY}/fleet", guarded(fleet))
    router.add_get(DRIFT_PATH, guarded(drift))
    router.add_post(f"{DRIFT_PATH}/{{event_id}}/ack", guarded(drift_ack))
    router.add_get(f"{MEMORY}/{{instance_id}}", guarded(instance_modules))
    router.add_get(f"{MEMORY}/{{instance_id}}/{{module}}", guarded(latest))
    router.add_get(
        f"{MEMORY}/{{instance_id}}/{{module}}/at/{{snapshot_id}}", guarded(snapshot)
    )
    router.add_post("/api/v1/teams/{team_slug}/memory/grant", guarded(create_grant))
    router.add_get("/api/v1/teams/{team_slug}/memory", guarded(shared))
