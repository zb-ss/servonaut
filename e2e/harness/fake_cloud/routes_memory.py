"""Memory Sync routes: the encrypted server-memory store and team sharing.

This module owns everything under ``/api/v1/memory/`` plus the team-memory
grants under ``/api/v1/teams/{slug}/memory``. :class:`MemoryCloud`
(``FakeCloud.memory``) holds what a client uploaded:

* the account's keypair, as the client enrolled it (``POST /keys``;
  ``GET /keys/me`` answers 404 until then), and the team members' public
  keys a journey adds with :meth:`MemoryCloud.add_team_member`;
* registered instances and every envelope ``POST /sync`` accepted. Like the
  service, the fake stores ciphertext it cannot read: each envelope must
  have the shape of AES-256-GCM output (12-byte nonce, 16-byte tag) with an
  80-byte sealed data key for the caller, or it is rejected
  (``missing_self_wrap``, ``unknown_instance``, ``invalid_envelope``);
* the latest envelope of each module, including the ``annotations`` and
  ``findings`` modules the client pulls back after a sync. They are ordinary
  modules on the same route: with none stored the answer is the service's
  ``not_found``, which the client reads as "nothing to pull";
* drift events a journey records with :meth:`MemoryCloud.record_drift`,
  linking the two newest envelopes of one module, and their
  acknowledgements;
* team grants (``POST /teams/{slug}/memory/grant``), whose DEK wraps must
  be sealed boxes for known team members, and reference stored envelopes of
  the modules the grant names (422 otherwise).

Every route needs the account's current access token.
"""

from __future__ import annotations

import copy
import datetime as dt
import base64
import hashlib
import itertools
import json
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
from e2e.harness.fake_cloud.shapes import (
    GCM_IV,
    GCM_TAG,
    KDF_SALT,
    SEALED_DATA_KEY,
    SECRETBOX_MAC,
    SECRETBOX_NONCE,
    X25519_KEY,
    has_bytes,
    has_size,
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

    def __init__(self, user_id: Callable[[], int], owner_id: Optional[Callable[[], int]] = None) -> None:
        # ``user_id`` is whoever makes the current request; ``owner_id`` is the
        # scenario's own account (the one ``enrolled_key`` and the grants of
        # the single-account journeys belong to).
        self._user_id = user_id
        self._owner_id = owner_id or user_id
        self._lock = threading.RLock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._keys: dict[int, dict[str, Any]] = {}
            self._key_history: list[dict[str, Any]] = []
            self._instances: dict[str, dict[str, Any]] = {}
            self._envelopes: list[dict[str, Any]] = []
            self._drift: list[dict[str, Any]] = []
            self._members: dict[str, list[dict[str, Any]]] = {}
            # (team, user) -> {"previous": fingerprint, "at": time} once that
            # member replaced a key; the directory flags them from then on.
            self._rotations: dict[tuple[str, int], dict[str, str]] = {}
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

    def enrolled_key(self, user_id: Optional[int] = None) -> Optional[dict[str, Any]]:
        """The keypair a client enrolled (wrapped private key included).

        The scenario account's by default; pass an added user's id for theirs.
        """
        with self._lock:
            return copy.deepcopy(self._keys.get(self._owner_id() if user_id is None else user_id))

    def current_key(self) -> Optional[dict[str, Any]]:
        """The enrolled keypair of whoever makes the current request."""
        return self.enrolled_key(self._user_id())

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
        self, team_slug: str, user_id: int, public_key_b64: str, *, role: str = "member",
        name: str = "",
    ) -> None:
        """A teammate with an enrolled keypair (their private key stays with the test)."""
        if role not in TEAM_ROLES:
            raise ValueError(f"role must be one of {TEAM_ROLES}")
        # As the real service: a strictly decoded 32-byte key, fingerprinted
        # over those bytes.
        raw = base64.b64decode(public_key_b64, validate=True)
        if len(raw) != X25519_KEY:
            raise ValueError("public_key must be a 32-byte X25519 key")
        with self._lock:
            self._members.setdefault(team_slug, []).append(
                {
                    "user_id": user_id,
                    "public_key_b64": public_key_b64,
                    "fingerprint": hashlib.sha256(raw).hexdigest(),
                    "role": role,
                    **({"name": name} if name else {}),
                }
            )

    def rotate_member_key(self, team_slug: str, user_id: int, public_key_b64: str) -> None:
        """The member replaces their key (Memory Sync set up again, a new computer).

        From now on the team key directory flags them for good, as the service
        does; a server's own flag clears once a wrap is stored for the new key,
        and a wrap made for the old key stops counting as one.
        """
        raw = base64.b64decode(public_key_b64, validate=True)
        if len(raw) != X25519_KEY:
            raise ValueError("public_key must be a 32-byte X25519 key")
        with self._lock:
            member = next(m for m in self._members[team_slug] if m["user_id"] == user_id)
            self._rotations[(team_slug, user_id)] = {
                "previous": member["fingerprint"], "at": _now(),
            }
            member["public_key_b64"] = public_key_b64
            member["fingerprint"] = hashlib.sha256(raw).hexdigest()

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
        problem = _key_problem(body)
        if problem:
            return problem
        uid = self._user_id()
        with self._lock:
            if uid in self._keys:
                self._key_history.append(self._keys[uid])
            self._keys[uid] = {k: body[k] for k in KEY_FIELDS}
            self._keys[uid]["created_at"] = _now()
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
                stored["uploader_id"] = user_id
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
        return {"accepted": accepted, "rejected": rejected, "quota": quota,
                "missing_team_wraps": self.missing_team_wraps(accepted)}

    def _rejection(self, envelope: Any, user_id: int) -> Optional[str]:
        if not isinstance(envelope, dict) or any(
            not envelope.get(field) for field in ENVELOPE_FIELDS
        ):
            return "invalid_envelope"
        if (
            envelope.get("encryption") != ENCRYPTION
            or not has_size(envelope["iv"], GCM_IV)
            or not has_size(envelope["tag"], GCM_TAG)
            or not has_bytes(envelope["ciphertext"])
            or (envelope.get("salt") not in (None, "") and not has_size(envelope["salt"], KDF_SALT))
        ):
            return "invalid_envelope"
        if envelope["instance_id"] not in self._instances:
            return "unknown_instance"
        wraps = envelope.get("dek_wraps")
        if not isinstance(wraps, list) or not all(
            isinstance(w, dict) and has_size(w.get("wrapped_dek"), SEALED_DATA_KEY)
            for w in wraps
        ):
            return "invalid_envelope"
        if not any(w.get("recipient_user_id") == user_id for w in wraps):
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
            key = copy.deepcopy(self._keys.get(self._owner_id()))
        if key is not None and all(m["user_id"] != self._owner_id() for m in members):
            members.insert(
                0,
                {
                    "user_id": self._owner_id(),
                    "public_key_b64": key["public_key"],
                    "fingerprint": key["fingerprint"],
                    "role": "owner",
                },
            )
        return [self._directory_entry(team_slug, m) for m in members]

    def _directory_entry(self, team_slug: str, member: dict[str, Any]) -> dict[str, Any]:
        """A member as the team key directory describes them: flagged once rotated, for good."""
        rotation = self._rotations.get((team_slug, member["user_id"]))
        return {
            **member,
            "name": member.get("name") or f"member {member['user_id']}",
            "key_changed": rotation is not None,
            "previous_fingerprint": rotation["previous"] if rotation else None,
            "key_rotated_at": rotation["at"] if rotation else None,
        }

    def _recipient(self, team_slug: str, instance_id: str, member: dict[str, Any]) -> dict[str, Any]:
        """A member as a server's recipient list describes them: flagged until a wrap is stored for the new key."""
        entry = self._directory_entry(team_slug, member)
        entry["key_changed"] = entry["key_changed"] and not any(
            w["recipient_user_id"] == member["user_id"] and w.get("fingerprint") == member["fingerprint"]
            for g in self._grants if g["instance_id"] == instance_id
            for w in g["wraps"]
        )
        return {k: entry[k] for k in (
            "user_id", "name", "fingerprint", "public_key_b64", "key_changed",
            "previous_fingerprint", "key_rotated_at")}

    # -- team sharing ------------------------------------------------------

    def _role_of(self, team_slug: str, user_id: int) -> Optional[str]:
        """A member's role in the team memory sharing, None for a stranger."""
        return next((m["role"] for m in self.team_keys(team_slug) if m["user_id"] == user_id), None)

    @staticmethod
    def _covers(grant: dict[str, Any], module: str) -> bool:
        modules = grant.get("modules")
        return not isinstance(modules, list) or module in modules

    def _eligible(self, grant: dict[str, Any]) -> list[dict[str, Any]]:
        """Members with a key whose role reaches the grant's required role."""
        need = TEAM_ROLES.index(grant["required_role"])
        return [m for m in self.team_keys(grant["team_slug"]) if TEAM_ROLES.index(m["role"]) >= need]

    def _grant_on(self, team_slug: str, grant_id: str) -> Optional[dict[str, Any]]:
        return next(
            (g for g in self._grants if g["id"] == grant_id and g["team_slug"] == team_slug), None
        )

    def _may_manage(self, team_slug: str, grant: dict[str, Any]) -> bool:
        uid = self._user_id()
        return uid == grant["granted_by_user_id"] or self._role_of(team_slug, uid) in ("owner", "admin")

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
            modules = body.get("modules")
            stored = {
                e["id"]: e["module"] for e in self._envelopes if e["instance_id"] == instance_id
            }
            for wrap in wraps:
                if (
                    not isinstance(wrap, dict)
                    or wrap.get("envelope_id") not in stored
                    or wrap.get("recipient_user_id") not in members
                    or not has_size(wrap.get("wrapped_dek"), SEALED_DATA_KEY)
                ):
                    return 422, {
                        "error": {"code": "validation_failed", "message": "invalid wrap"}
                    }
                if isinstance(modules, list) and stored[wrap["envelope_id"]] not in modules:
                    return 422, {
                        "error": {
                            "code": "validation_failed",
                            "message": "a wrap covers a module the grant does not share",
                        }
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
                "wraps": self._stamped(team_slug, wraps),
            }
            missing = self._missing_wraps(grant)
            if missing:
                # An enrolled reader with no wrap for a granted module (in this
                # request or already stored) is refused, as the service does.
                return 422, {"error": {
                    "code": "insufficient_wraps", "message": "missing wraps",
                    "details": {"missing": [
                        {"envelope_id": e["id"], "recipient_user_id": m["user_id"]}
                        for e, m in missing
                    ]},
                }}
            self._grants.append(grant)
        return 201, {**_public_grant(grant), "pending_recipients": [], "missing_wraps": [],
                     "skipped_recipients": []}

    def _stamped(self, team_slug: str, wraps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Copies of *wraps*, each marked with the key it was sealed for (the member's current one)."""
        current = {m["user_id"]: m["fingerprint"] for m in self.team_keys(team_slug)}
        return [{**copy.deepcopy(w), "fingerprint": current.get(w["recipient_user_id"])} for w in wraps]

    def _latest_envelopes(self, grant: dict[str, Any]) -> list[dict[str, Any]]:
        """The newest stored envelope of each module the grant covers."""
        latest: dict[str, dict[str, Any]] = {}
        for e in self._envelopes:
            if e["instance_id"] == grant["instance_id"] and self._covers(grant, e["module"]):
                latest[e["module"]] = e
        return list(latest.values())

    def _has_wrap(self, grant: dict[str, Any], envelope: dict[str, Any], user_id: int) -> bool:
        """Whether the member can open *envelope*: a wrap made for the key they hold now."""
        if any(w.get("recipient_user_id") == user_id for w in envelope.get("dek_wraps", [])):
            return True
        current = next((m["fingerprint"] for m in self.team_keys(grant["team_slug"])
                        if m["user_id"] == user_id), None)
        return any(
            w["envelope_id"] == envelope["id"] and w["recipient_user_id"] == user_id
            and w.get("fingerprint", current) == current
            for g in [*self._grants, grant]
            if g["instance_id"] == grant["instance_id"]
            for w in g["wraps"]
        )

    def _missing_wraps(self, grant: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        return [
            (e, m)
            for e in self._latest_envelopes(grant)
            for m in self._eligible(grant)
            if not self._has_wrap(grant, e, m["user_id"])
        ]

    def revoke_grant(self, team_slug: str, grant_id: str) -> tuple[int, dict[str, Any]]:
        """Revoke: idempotent, wraps kept; 404 only when the grant is not the team's."""
        with self._lock:
            grant = self._grant_on(team_slug, grant_id)
            if grant is None or not self._may_manage(team_slug, grant):
                return 404, {"error": {"code": "not_found", "message": "no such grant"}}
            if grant["status"] != "revoked":
                grant["status"] = "revoked"
                grant["revoked_at"] = _now()
            return 200, _public_grant(grant)

    def purge_grant(self, team_slug: str, grant_id: str) -> tuple[int, dict[str, Any]]:
        """Revoke if live, then delete the team members' wraps (not the owner's)."""
        with self._lock:
            grant = self._grant_on(team_slug, grant_id)
            if grant is None or not self._may_manage(team_slug, grant):
                return 404, {"error": {"code": "not_found", "message": "no such grant"}}
            if grant["status"] != "revoked":
                grant["status"] = "revoked"
                grant["revoked_at"] = _now()
            envelope_module = {e["id"]: e["module"] for e in self._envelopes}
            still = [
                g for g in self._grants
                if g is not grant and g["status"] == "active" and g["instance_id"] == grant["instance_id"]
            ]
            keep, deleted = [], 0
            for w in grant["wraps"]:
                other = any(self._covers(g, envelope_module.get(w["envelope_id"], "")) for g in still)
                if w["recipient_user_id"] == grant["granted_by_user_id"] or other:
                    keep.append(w)
                else:
                    deleted += 1
            grant["wraps"] = keep
            return 200, {"grant_id": grant_id, "wraps_deleted": deleted, "status": "revoked"}

    def add_wraps(self, team_slug: str, grant_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """The catch-up route: wraps for snapshots uploaded after the share."""
        with self._lock:
            grant = self._grant_on(team_slug, grant_id)
            if grant is None or not self._may_manage(team_slug, grant):
                return 404, {"error": {"code": "not_found", "message": "no such grant"}}
            if grant["status"] != "active":
                return 409, {"error": {"code": "grant_not_live", "message": "grant revoked"}}
            wraps = body.get("wraps")
            if not isinstance(wraps, list):
                return 422, {"error": {"code": "validation_failed", "message": "wraps required"}}
            eligible = {m["user_id"]: m for m in self._eligible(grant)}
            stored = {e["id"]: e for e in self._envelopes if e["instance_id"] == grant["instance_id"]}
            kept, unchanged, skipped = 0, 0, []
            for wrap in wraps:
                member = eligible.get(wrap.get("recipient_user_id")) if isinstance(wrap, dict) else None
                envelope = stored.get(wrap.get("envelope_id")) if isinstance(wrap, dict) else None
                if (
                    member is None or envelope is None
                    or not self._covers(grant, envelope["module"])
                    or not has_size(wrap.get("wrapped_dek"), SEALED_DATA_KEY)
                ):
                    return 422, {"error": {"code": "validation_failed", "message": "invalid wrap"}}
                claimed = wrap.get("recipient_fingerprint")
                if claimed and claimed != member["fingerprint"]:
                    skipped.append({"user_id": member["user_id"], "reason": "key_changed"})
                    continue
                if any(w["envelope_id"] == wrap["envelope_id"]
                       and w["recipient_user_id"] == wrap["recipient_user_id"]
                       and w.get("fingerprint") == member["fingerprint"]
                       for w in grant["wraps"]):
                    unchanged += 1
                    continue
                # A wrap made for a key the member no longer holds is replaced.
                grant["wraps"] = [
                    w for w in grant["wraps"]
                    if not (w["envelope_id"] == wrap["envelope_id"]
                            and w["recipient_user_id"] == wrap["recipient_user_id"])
                ]
                grant["wraps"].extend(self._stamped(team_slug, [
                    {k: wrap[k] for k in ("recipient_user_id", "envelope_id", "wrapped_dek")}]))
                kept += 1
            return 200, {"grant_id": grant_id, "wraps_stored": kept, "wraps_unchanged": unchanged,
                         "missing_count": len(self._missing_wraps(grant)),
                         "pending_recipients": [], "skipped_recipients": skipped}

    def wrap_coverage(self, team_slug: str, grant_id: str) -> tuple[int, dict[str, Any]]:
        with self._lock:
            grant = self._grant_on(team_slug, grant_id)
            if grant is None or not self._may_manage(team_slug, grant):
                return 404, {"error": {"code": "not_found", "message": "no such grant"}}
            uid = self._user_id()
            rows = []
            for e in self._latest_envelopes(grant):
                own = next((w for w in e.get("dek_wraps", []) if w.get("recipient_user_id") == uid), None)
                rows.append({
                    "envelope_id": e["id"], "module": e["module"],
                    "snapshot_version": e["snapshot_version"],
                    "wrapped_dek": own["wrapped_dek"] if own else None,
                    "missing_recipients": [
                        self._recipient(team_slug, grant["instance_id"], m)
                        for m in self._eligible(grant)
                        if not self._has_wrap(grant, e, m["user_id"])
                    ],
                })
            return 200, {"grant_id": grant_id, "envelopes": rows, "pending_recipients": []}

    def missing_team_wraps(self, accepted: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """For accepted envelopes: covered members that still lack a wrap."""
        entries = []
        with self._lock:
            by_id = {e["id"]: e for e in self._envelopes}
            for item in accepted:
                envelope = by_id[item["id"]]
                for grant in self._grants:
                    if (grant["status"] != "active" or grant["instance_id"] != envelope["instance_id"]
                            or not self._covers(grant, envelope["module"])):
                        continue
                    recipients = [
                        self._recipient(grant["team_slug"], grant["instance_id"], m)
                        for m in self._eligible(grant)
                        if m["user_id"] != envelope.get("uploader_id")
                        and not self._has_wrap(grant, envelope, m["user_id"])
                    ]
                    if recipients:
                        entries.append({
                            "envelope_id": envelope["id"], "instance_id": envelope["instance_id"],
                            "module": envelope["module"], "team_slug": grant["team_slug"],
                            "grant_id": grant["id"], "recipients": recipients,
                        })
        return entries

    def shared_instances(self, team_slug: str) -> list[dict[str, Any]]:
        """The live grants the caller may read (the granter and team admins see all)."""
        uid = self._user_id()
        role = self._role_of(team_slug, uid)
        rows = []
        for grant in self.grants(team_slug):
            if grant["status"] != "active" or role is None:
                continue
            if not (uid == grant["granted_by_user_id"]
                    or TEAM_ROLES.index(role) >= TEAM_ROLES.index(grant["required_role"])):
                continue
            with self._lock:
                instance = copy.deepcopy(self._instances.get(grant["instance_id"], {}))
                if uid == grant["granted_by_user_id"]:
                    wrapped = {w["envelope_id"] for w in grant["wraps"]}
                else:
                    wrapped = {w["envelope_id"] for w in grant["wraps"] if w["recipient_user_id"] == uid}
                modules = sorted({e["module"] for e in self._envelopes if e["id"] in wrapped})
            rows.append({"grant": _public_grant(grant), "instance": instance,
                         "readable_modules": modules, "stale_modules": []})
        return rows

    def team_read(self, team_slug: str, instance_id: str, module: str) -> tuple[int, dict[str, Any]]:
        """The newest envelope of *module* the caller holds a wrap for, else access_revoked."""
        uid = self._user_id()
        denied = (404, {"error": {"code": "access_revoked", "message": "no readable copy"}})
        role = self._role_of(team_slug, uid)
        with self._lock:
            grant = next(
                (g for g in self._grants
                 if g["team_slug"] == team_slug and g["instance_id"] == instance_id
                 and g["status"] == "active" and self._covers(g, module)), None)
            if grant is None or role is None or TEAM_ROLES.index(role) < TEAM_ROLES.index(grant["required_role"]):
                return denied
            candidates = [e for e in self._envelopes
                          if e["instance_id"] == instance_id and e["module"] == module]
            for envelope in reversed(candidates):
                wrap = next((w for w in grant["wraps"]
                             if w["envelope_id"] == envelope["id"] and w["recipient_user_id"] == uid), None)
                if wrap is None:
                    continue
                answer = {k: envelope.get(k) for k in _METADATA}
                answer.update({
                    "id": envelope["id"], "snapshot_version": envelope["snapshot_version"],
                    "created_at": envelope["created_at"], "iv": envelope["iv"], "tag": envelope["tag"],
                    "salt": envelope.get("salt"), "ciphertext": envelope["ciphertext"],
                    "encryption": envelope["encryption"], "wrapped_dek": wrap["wrapped_dek"],
                    "grant_id": grant["id"], "required_role": grant["required_role"],
                    "is_latest": envelope is candidates[-1],
                    "latest_snapshot_version": candidates[-1]["snapshot_version"],
                })
                return 200, answer
        return denied

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


def _key_problem(body: dict[str, Any]) -> Optional[str]:
    """Why an enrolled key is not a wrapped X25519 key, or None."""
    if not has_size(body["public_key"], X25519_KEY):
        return "public_key must be a 32-byte X25519 key"
    if body.get("fingerprint") != hashlib.sha256(base64.b64decode(body["public_key"])).hexdigest():
        return "fingerprint must be the SHA-256 of the public key"
    try:
        wrapped = json.loads(body["wrapped_private_key"])
    except ValueError:
        return "wrapped_private_key must be JSON"
    if (
        not isinstance(wrapped, dict)
        or wrapped.get("kdf") != "argon2id"
        or not has_size(wrapped.get("salt"), KDF_SALT)
        or not has_size(wrapped.get("nonce"), SECRETBOX_NONCE)
        or not has_size(wrapped.get("ct"), X25519_KEY + SECRETBOX_MAC)
    ):
        return "wrapped_private_key must be an Argon2id-wrapped 32-byte key"
    return None


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
        key = memory.current_key()
        if key is None:
            return _not_found("No active keypair")
        return web.json_response(key)

    async def enrol(request: web.Request) -> web.Response:
        problem = memory.enrol(await json_body(request))
        if problem:
            return validation_failed(problem)
        key = memory.current_key() or {}
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

    def answer(result: tuple[int, dict[str, Any]]) -> web.Response:
        return web.json_response(result[1], status=result[0])

    async def revoke_grant(request: web.Request) -> web.Response:
        return answer(memory.revoke_grant(request.match_info["team_slug"], request.match_info["grant_id"]))

    async def purge_grant(request: web.Request) -> web.Response:
        return answer(memory.purge_grant(request.match_info["team_slug"], request.match_info["grant_id"]))

    async def add_wraps(request: web.Request) -> web.Response:
        return answer(memory.add_wraps(
            request.match_info["team_slug"], request.match_info["grant_id"], await json_body(request)))

    async def wrap_coverage(request: web.Request) -> web.Response:
        return answer(memory.wrap_coverage(request.match_info["team_slug"], request.match_info["grant_id"]))

    async def team_read(request: web.Request) -> web.Response:
        return answer(memory.team_read(
            request.match_info["team_slug"], request.match_info["instance_id"],
            request.match_info["module"]))

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
    grant = "/api/v1/teams/{team_slug}/memory/grant/{grant_id}"
    router.add_delete(grant, guarded(revoke_grant))
    router.add_post(f"{grant}/purge", guarded(purge_grant))
    router.add_post(f"{grant}/wraps", guarded(add_wraps))
    router.add_get(f"{grant}/wraps", guarded(wrap_coverage))
    router.add_get("/api/v1/teams/{team_slug}/memory/{instance_id}/{module}", guarded(team_read))
