"""Strict in-memory Team Vault and SSH-CA FakeCloud routes.

The fake deliberately verifies the cryptographic boundary which normally gets
lost in HTTP-only journeys: an authenticated account is not sufficient to
read, write, or issue a certificate.  A request must belong to an active
device and carry an unexpired, unique Ed25519 request signature.

It stores only opaque vault ciphertext and sealed keys.  The small control
surface is intentionally Python-only (``FakeCloud.vault``), so test personas
cannot be manufactured through an unguarded HTTP endpoint.
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import struct
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Optional

from aiohttp import web
from nacl.exceptions import BadSignatureError
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    SSHCertificateBuilder,
    SSHCertificateType,
    load_ssh_public_key,
)

from e2e.harness.fake_cloud.routes_auth import bearer_ok, json_body, unauthorized
from e2e.harness.fake_cloud.state import ScenarioStore
from servonaut.services.vault.crypto import build_krl

VAULT = "/api/v1/vault"
VAULTS = "/api/v1/vaults"
UUID = uuid.UUID
KEY_BYTES = 32
SIG_BYTES = 64
REQUEST_NONCE_BYTES = 16
DEVICE_NONCE_BYTES = 32
ITEM_NONCE_BYTES = 24
SEALED_KEY_BYTES = 80
RECOVERY_WRAP_BYTES = 110
MAX_SKEW_SECONDS = 300
TEAM_SLUG = "example-team"
TEAM_ID = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
SERVER_ID = "c2a4e6f8-1b3d-4f5a-9c7e-0a2b4c6d8e1f"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _approval_expiry() -> str:
    """A real future deadline for client-side pending-device validation."""
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=15)).isoformat()


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def json_dumps(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode(value: object, size: Optional[int] = None) -> Optional[bytes]:
    if not isinstance(value, str) or not value:
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return None
    return decoded if size is None or len(decoded) == size else None


def _uuid(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        return None
    return value if str(parsed) == value and parsed.version == 4 else None


def _fingerprint(value: object) -> Optional[bytes]:
    """The identity fingerprint is a lowercase hexadecimal wire value."""
    if not isinstance(value, str) or len(value) != KEY_BYTES * 2:
        return None
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        return None
    return decoded if decoded.hex() == value else None


def _lp(*values: object) -> bytes:
    """Contract §3.1 length-prefix encoding."""
    encoded: list[bytes] = []
    for value in values:
        if isinstance(value, str):
            raw = value.encode("utf-8")
        elif isinstance(value, bytes):
            raw = value
        elif isinstance(value, int):
            raw = struct.pack(">Q", value)
        else:
            raise TypeError(f"cannot LP encode {type(value)!r}")
        encoded.append(struct.pack(">I", len(raw)) + raw)
    return b"".join(encoded)


def _digest(*values: object) -> bytes:
    return hashlib.sha256(_lp(*values)).digest()


def _error(code: str, message: str, status: int, **details: Any) -> web.Response:
    error: dict[str, Any] = {"code": code, "message": message}
    if details:
        error["details"] = details
    return web.json_response({"error": error}, status=status)


def _not_found() -> web.Response:
    return _error("not_found", "Not found", 404)


def _problem(field: str, message: str = "invalid value") -> web.Response:
    return _error("validation_failed", message, 422, field=field)


@dataclass
class _Device:
    user_id: int
    device_id: str
    name: str
    platform: str
    client: str
    sig_key: bytes
    enc_key: bytes
    status: str = "pending"
    activation_method: Optional[str] = None
    endorsed_by_device_id: Optional[str] = None
    commitment: Optional[bytes] = None
    registration_signature: Optional[bytes] = None
    approver_nonce: Optional[bytes] = None
    approver_device_id: Optional[str] = None
    device_nonce: Optional[bytes] = None
    sealed_bundle: Optional[bytes] = None
    endorsement_signature: Optional[bytes] = None
    ssh_public_key: Optional[str] = None
    created_at: str = ""
    activated_at: Optional[str] = None
    revoked_at: Optional[str] = None
    revoke_reason: Optional[str] = None


class VaultCloud:
    """Thread-safe opaque Vault state with strict device authentication."""

    def __init__(self, user_id: Callable[[], int]) -> None:
        self._user_id = user_id
        self._lock = threading.RLock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._identities: dict[int, dict[str, Any]] = {}
            self._fixture_keys: dict[int, tuple[bytes, bytes]] = {}
            self._devices: dict[str, _Device] = {}
            self._recovery_wraps: dict[int, dict[str, Any]] = {}
            self._used_nonces: set[tuple[str, bytes]] = set()
            self._vaults: dict[str, dict[str, Any]] = {}
            self._items: dict[str, dict[str, dict[str, Any]]] = {}
            self._bindings: dict[tuple[str, str], dict[str, Any]] = {}
            self._exposures: dict[str, list[dict[str, Any]]] = {}
            self._ca: dict[str, dict[str, Any]] = {}
            self._ca_keys: dict[str, tuple[Ed25519PrivateKey, Ed25519PrivateKey]] = {}
            self._enrolments: dict[str, dict[str, Any]] = {}
            # Serials count from 1 per team; user and host certificates share them.
            self._serial = 0
            # How a new identity is confirmed: "auto" (confirmed at enrolment),
            # "email" (pending until the e-mailed link is opened) or "mfa"
            # (pending until the confirmation request, made with a fresh second factor).
            self.identity_confirmation = "auto"

    def open_exposure(self, vault_id: str, item_id: str, *, public_fingerprint: str, subject: str = "member") -> str:
        """Control: record that a removed member had fetched this item's key."""
        with self._lock:
            exposure_id = str(uuid.uuid4())
            self._exposures.setdefault(vault_id, []).append({
                "exposure_id": exposure_id, "item_id": item_id, "public_fingerprint": public_fingerprint,
                "subject": subject, "reason": "member_removed", "status": "open", "created_at": _now(),
            })
            return exposure_id

    # Controls are intentionally not routes. They provide generic, public-safe
    # fixture names and reveal only public/key-management data to journeys.
    def personas(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {
                str(user_id): copy.deepcopy(identity)
                for user_id, identity in self._identities.items()
            }

    def devices(self, user_id: Optional[int] = None) -> list[dict[str, Any]]:
        with self._lock:
            return [
                self._public_device(device, None)
                for device in self._devices.values()
                if user_id is None or device.user_id == user_id
            ]

    def seed_identity(self, user_id: int, *, name: str = "fixture device") -> dict[str, Any]:
        """Create a cryptographically real generic identity for API journeys.

        The signing material is returned only to the calling test fixture; it
        never crosses FakeCloud HTTP and is not logged.
        """
        with self._lock:
            sig = SigningKey.generate()
            enc = PrivateKey.generate()
            identity_id = str(uuid.uuid4())
            sig_pk, enc_pk = bytes(sig.verify_key), bytes(enc.public_key)
            fingerprint = _digest("svn-vi-fp-v1", sig_pk, enc_pk)
            self_sig = sig.sign(
                _lp("svn-vi-self-v1", identity_id, user_id, sig_pk, enc_pk)
            ).signature
            identity = {
                "identity_id": identity_id,
                "user_id": user_id,
                "sig_public_key": _b64(sig_pk),
                "enc_public_key": _b64(enc_pk),
                "fingerprint": fingerprint.hex(),
                "self_signature": _b64(self_sig),
                "alg": "svn-v1",
                "status": "active",
                "trust_status": "confirmed",
                "grantable": True,
                "confirmed_via": "fixture",
                "created_at": _now(),
            }
            self._identities[user_id] = identity
            self._fixture_keys[user_id] = (bytes(sig), bytes(enc))
            device_id = str(uuid.uuid4())
            device_sign = SigningKey.generate()
            device_enc = PrivateKey.generate()
            device = _Device(
                user_id, device_id, name, "linux", "cli", bytes(device_sign.verify_key),
                bytes(device_enc.public_key), status="active", activation_method="first_device",
                created_at=_now(), activated_at=_now(),
            )
            self._devices[device_id] = device
            return {
                "identity": copy.deepcopy(identity),
                "device": self._public_device(device, device_id),
                "identity_signing_key": _b64(bytes(sig)),
                "identity_encryption_key": _b64(bytes(enc)),
                "device_signing_key": _b64(bytes(device_sign)),
                "device_encryption_key": _b64(bytes(device_enc)),
            }

    def seed_team(self, owner_user_id: int, member_user_id: int) -> dict[str, Any]:
        """Create a small team vault only after both generic identities exist."""
        with self._lock:
            owner, member = self._identities.get(owner_user_id), self._identities.get(member_user_id)
            if owner is None or member is None:
                raise ValueError("seed identities before creating a fixture team")
            vault_id = str(uuid.uuid4())
            vault = self._new_vault(
                vault_id, "team", f"team:{TEAM_ID}", owner_user_id, TEAM_SLUG,
                [owner_user_id, member_user_id],
            )
            vault_key = os.urandom(KEY_BYTES)
            owner_seed, _ = self._fixture_keys[owner_user_id]
            owner_id = owner["identity_id"]
            version_message = _lp("svn-tv-version-v1", vault_id, vault["scope"], 1,
                                  bytes(PrivateKey(vault_key).public_key), b"\0" * KEY_BYTES, owner_id)
            version_signature = SigningKey(owner_seed).sign(version_message).signature
            vault["versions"] = [{
                "version": 1, "public_key": _b64(bytes(PrivateKey(vault_key).public_key)),
                "prev_hash": _b64(b"\0" * KEY_BYTES),
                "record_hash": _b64(_digest("svn-tv-version-hash-v1", version_message, version_signature)),
                "creator_identity_id": owner_id, "signature": _b64(version_signature),
                "created_at": _now(), "retired_at": None,
            }]
            for user_id, identity in ((owner_user_id, owner), (member_user_id, member)):
                recipient_key = _decode(identity["enc_public_key"], KEY_BYTES)
                assert recipient_key is not None
                sealed = SealedBox(PublicKey(recipient_key)).encrypt(vault_key)
                signature_message = _lp("svn-tv-grant-v1", vault_id, vault["scope"], 1,
                                        bytes(PrivateKey(vault_key).public_key), user_id, identity["identity_id"],
                                        _fingerprint(identity["fingerprint"]) or b"", hashlib.sha256(sealed).digest(), owner_id)
                grant_signature = SigningKey(owner_seed).sign(signature_message).signature
                vault["grants"][user_id] = {"grant_id": str(uuid.uuid4()), "version": 1,
                                              "sealed_private_key": _b64(sealed), "granter_identity_id": owner_id,
                                              "signature": _b64(grant_signature), "created_at": _now()}
            self._vaults[vault_id] = vault
            self._items[vault_id] = {}
            self._exposures[vault_id] = []
            return {"team_slug": TEAM_SLUG, "team_id": TEAM_ID, "vault_id": vault_id}

    def _identity(self, user_id: int) -> Optional[dict[str, Any]]:
        return self._identities.get(user_id)

    def _public_identity(self, identity: dict[str, Any]) -> dict[str, Any]:
        return copy.deepcopy(identity)

    def _public_device(self, device: _Device, current: Optional[str]) -> dict[str, Any]:
        return {
            "device_id": device.device_id, "name": device.name, "platform": device.platform,
            "client": device.client, "device_sig_public_key": _b64(device.sig_key),
            "device_enc_public_key": _b64(device.enc_key), "status": device.status,
            "activation_method": device.activation_method,
            "endorsed_by_device_id": device.endorsed_by_device_id,
            "ssh_public_key": device.ssh_public_key,
            "ssh_key_fingerprint": self._ssh_fingerprint(device.ssh_public_key),
            "created_at": device.created_at, "activated_at": device.activated_at,
            "last_seen_at": None, "revoked_at": device.revoked_at,
            "revoke_reason": device.revoke_reason, "is_current": current == device.device_id,
        }

    @staticmethod
    def _ssh_fingerprint(public_key: Optional[str]) -> Optional[str]:
        if public_key is None:
            return None
        try:
            encoded = public_key.split(" ", 2)[1]
            blob = base64.b64decode(encoded, validate=True)
        except (IndexError, ValueError, TypeError):
            return None
        return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")

    def _new_vault(
        self, vault_id: str, kind: str, scope: str, owner_user_id: int, team_slug: Optional[str],
        members: list[int],
    ) -> dict[str, Any]:
        roster = []
        for user_id in members:
            identity = self._identities[user_id]
            roster.append({
                "user_id": user_id, "email": f"user-{user_id}@example.test", "name": f"User {user_id}",
                "role": "owner" if user_id == owner_user_id else "member", "status": "granted",
                "identity_id": identity["identity_id"], "fingerprint": identity["fingerprint"],
                "identity": self._public_identity(identity), "grant_status": "granted", "joined_at": _now(),
            })
        return {
            "vault_id": vault_id, "kind": kind, "scope": scope,
            "team": None if team_slug is None else {"id": TEAM_ID, "slug": team_slug, "name": "Example team"},
            "owner_user_id": owner_user_id if kind == "personal" else None,
            "name": "Personal vault" if kind == "personal" else "Team vault", "grant_policy": "auto",
            "current_version": 1, "versions": [], "roster": roster, "grants": {},
            "rotation": {"required": False, "required_since": None, "reasons": [], "last_rotated_at": None},
            "created_at": _now(), "updated_at": _now(),
        }

    # ------------------------------------------------------------------
    # Device request signature verifier
    # ------------------------------------------------------------------

    def authenticate(
        self, request: web.Request, *, allow_pending: bool = False, unsigned: bool = False
    ) -> tuple[Optional[_Device], Optional[web.Response]]:
        if unsigned:
            return None, None
        device_id = request.headers.get("X-Servonaut-Device")
        timestamp = request.headers.get("X-Servonaut-Timestamp")
        nonce = _decode(request.headers.get("X-Servonaut-Nonce"), REQUEST_NONCE_BYTES)
        signature = _decode(request.headers.get("X-Servonaut-Signature"), SIG_BYTES)
        if not all((device_id, timestamp, nonce, signature)):
            return None, _error("device_signature_required", "A signed device request is required", 403)
        try:
            moment = int(timestamp)
        except (TypeError, ValueError):
            return None, _error("device_signature_expired", "Invalid signature timestamp", 403)
        if abs(time.time() - moment) > MAX_SKEW_SECONDS:
            return None, _error("device_signature_expired", "Device clock is outside the allowed skew", 403,
                                server_time=int(time.time()))
        with self._lock:
            device = self._devices.get(device_id)
            if device is None or device.user_id != self._user_id():
                return None, _error("device_not_owned", "Device is not available for this account", 403)
            if device.status != "active" and not (allow_pending and device.status == "pending"):
                return None, _error("device_not_active", "Device is not active for this operation", 403,
                                    status=device.status)
            raw = bytes(request._read_bytes or b"")
            message = _lp(
                "svn-req-v1", request.method, request.raw_path, moment, nonce, device_id,
                hashlib.sha256(raw).digest(),
            )
            try:
                VerifyKey(device.sig_key).verify(message, signature)
            except BadSignatureError:
                return None, _error("device_signature_invalid", "Device signature did not verify", 403)
            nonce_key = (device_id, nonce)
            if nonce_key in self._used_nonces:
                return None, _error("device_signature_replayed", "Device signature nonce was already used", 403)
            self._used_nonces.add(nonce_key)
            return device, None

    def authenticate_bootstrap(
        self, request: web.Request, *, device_id: object, signing_key: object
    ) -> Optional[web.Response]:
        """Verify a first-device request before the device exists server-side.

        Bootstrap is not a signature exception: the submitted device public key
        verifies the same request envelope that active devices use.  The route
        caller supplies fields from the already parsed JSON document, keeping
        the device id bound to both the body and signed headers.
        """
        parsed_id = _uuid(device_id)
        public_key = _decode(signing_key, KEY_BYTES)
        header_id = request.headers.get("X-Servonaut-Device")
        timestamp = request.headers.get("X-Servonaut-Timestamp")
        nonce = _decode(request.headers.get("X-Servonaut-Nonce"), REQUEST_NONCE_BYTES)
        signature = _decode(request.headers.get("X-Servonaut-Signature"), SIG_BYTES)
        if not all((parsed_id, public_key, header_id, timestamp, nonce, signature)):
            return _error("device_signature_required", "A signed device request is required", 403)
        if header_id != parsed_id:
            return _error("device_signature_invalid", "Request device does not match the enrolled device", 403)
        try:
            moment = int(timestamp)
        except (TypeError, ValueError):
            return _error("device_signature_expired", "Invalid signature timestamp", 403)
        if abs(time.time() - moment) > MAX_SKEW_SECONDS:
            return _error("device_signature_expired", "Device clock is outside the allowed skew", 403,
                          server_time=int(time.time()))
        raw = bytes(request._read_bytes or b"")
        message = _lp(
            "svn-req-v1", request.method, request.raw_path, moment, nonce, parsed_id,
            hashlib.sha256(raw).digest(),
        )
        if not _verify(public_key, message, signature):
            return _error("device_signature_invalid", "Device signature did not verify", 403)
        nonce_key = (parsed_id, nonce)
        with self._lock:
            if nonce_key in self._used_nonces:
                return _error("device_signature_replayed", "Device signature nonce was already used", 403)
            self._used_nonces.add(nonce_key)
        return None

    # ------------------------------------------------------------------
    # Vault state operations
    # ------------------------------------------------------------------

    def identity_payload(self, current_device: Optional[str] = None) -> dict[str, Any]:
        with self._lock:
            user_id = self._user_id()
            identity = self._identity(user_id)
            devices = [self._public_device(d, current_device) for d in self._devices.values() if d.user_id == user_id]
            wrap = self._recovery_wraps.get(user_id)
            return {
                "identity": self._public_identity(identity) if identity else None,
                "pending_reset": None, "previous_identities": [], "devices": devices,
                "recovery_wrap": {"present": wrap is not None, "created_at": wrap["created_at"] if wrap else None,
                                  "last_fetched_at": wrap.get("last_fetched_at") if wrap else None},
                "settings": {"request_signature_skew_seconds": MAX_SKEW_SECONDS,
                             "device_approval_ttl_seconds": 900, "poll_after_seconds": 300},
                "mfa": None,
            }

    def enrol_identity(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        with self._lock:
            user_id = self._user_id()
            if self._identity(user_id) is not None:
                return 409, {"error": {"code": "identity_exists", "message": "An identity already exists"}}
            identity_body, device_body, recovery = body.get("identity"), body.get("device"), body.get("recovery_wrap")
            if not isinstance(identity_body, dict) or not isinstance(device_body, dict) or not isinstance(recovery, dict):
                return 422, {"error": {"code": "validation_failed", "message": "identity, device and recovery_wrap are required"}}
            identity_id, device_id = _uuid(identity_body.get("identity_id")), _uuid(device_body.get("device_id"))
            sig_pk, enc_pk = _decode(identity_body.get("sig_public_key"), KEY_BYTES), _decode(identity_body.get("enc_public_key"), KEY_BYTES)
            self_sig = _decode(identity_body.get("self_signature"), SIG_BYTES)
            device_sig = _decode(device_body.get("device_sig_public_key"), KEY_BYTES)
            device_enc = _decode(device_body.get("device_enc_public_key"), KEY_BYTES)
            registration = _decode(device_body.get("registration_signature"), SIG_BYTES)
            endorsement = _decode(device_body.get("endorsement_signature"), SIG_BYTES)
            blob = _decode(recovery.get("blob"), RECOVERY_WRAP_BYTES)
            if not all((identity_id, device_id, sig_pk, enc_pk, self_sig, device_sig, device_enc, registration, endorsement, blob)):
                return 422, {"error": {"code": "validation_failed", "message": "Invalid identity enrolment shape"}}
            try:
                VerifyKey(sig_pk).verify(_lp("svn-vi-self-v1", identity_id, user_id, sig_pk, enc_pk), self_sig)
                VerifyKey(device_sig).verify(_lp("svn-dev-reg-v1", device_id, user_id, device_sig, device_enc, b"\0" * 32), registration)
                VerifyKey(sig_pk).verify(_lp("svn-dev-endorse-v1", identity_id, user_id, device_id, device_sig, device_enc), endorsement)
            except BadSignatureError:
                return 422, {"error": {"code": "invalid_signature", "message": "Identity enrolment signature did not verify"}}
            fingerprint = _digest("svn-vi-fp-v1", sig_pk, enc_pk)
            confirmed = self.identity_confirmation == "auto"
            identity = {"identity_id": identity_id, "user_id": user_id, "sig_public_key": _b64(sig_pk),
                        "enc_public_key": _b64(enc_pk), "fingerprint": fingerprint.hex(),
                        "self_signature": _b64(self_sig), "alg": "svn-v1", "status": "active",
                        "trust_status": "confirmed" if confirmed else "pending_confirmation",
                        "grantable": confirmed, "confirmed_via": "fixture" if confirmed else None, "created_at": _now()}
            device = _Device(user_id, device_id, str(device_body.get("name") or "device"),
                             str(device_body.get("platform") or "other"), str(device_body.get("client") or "cli"),
                             device_sig, device_enc, status="active", activation_method="first_device",
                             created_at=_now(), activated_at=_now())
            self._identities[user_id], self._devices[device_id] = identity, device
            self._recovery_wraps[user_id] = {"blob": blob, "created_at": _now(), "last_fetched_at": None}
            confirmation = {"state": "confirmed", "expires_at": None} if confirmed else self._link_sent("pending_confirmation")
            return 201, {"identity": self._public_identity(identity), "device": self._public_device(device, device_id),
                         "confirmation": confirmation}

    @staticmethod
    def _link_sent(state: str) -> dict[str, Any]:
        expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=24)
        return {"state": state, "expires_at": expires.isoformat()}

    def require_confirmation(self, user_id: int) -> None:
        """Control: put an existing identity back to waiting for confirmation."""
        with self._lock:
            identity = self._identity(user_id)
            if identity is None:
                raise KeyError(user_id)
            identity.update({"trust_status": "pending_confirmation", "grantable": False, "confirmed_via": None})

    def confirm_identity(self, user_id: int, *, via: str = "email") -> None:
        """Control: the user opened the e-mailed link (or confirmed with MFA)."""
        with self._lock:
            identity = self._identity(user_id)
            if identity is None:
                raise KeyError(user_id)
            identity.update({"trust_status": "confirmed", "grantable": True, "confirmed_via": via})

    def request_confirmation(self, user_id: int) -> tuple[int, dict[str, Any]]:
        """``POST …/identity/me/confirmation``: confirm with fresh MFA, else e-mail a new link."""
        with self._lock:
            identity = self._identity(user_id)
            if identity is None:
                return 409, {"error": {"code": "no_identity", "message": "No active identity"}}
            if identity.get("trust_status") == "compromised":
                return 409, {"error": {"code": "identity_compromised", "message": "Identity is compromised"}}
            if identity.get("trust_status") != "confirmed" and self.identity_confirmation in {"mfa", "auto"}:
                identity.update({"trust_status": "confirmed", "grantable": True, "confirmed_via": "mfa"})
            if identity.get("trust_status") == "confirmed":
                return 200, {"identity": self._public_identity(identity), "confirmation": {"state": "confirmed", "expires_at": None}}
            return 200, {"identity": self._public_identity(identity), "confirmation": self._link_sent("email_sent")}

    def register_device(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        with self._lock:
            user_id = self._user_id()
            identity = self._identity(user_id)
            if identity is None:
                return 409, {"error": {"code": "no_identity", "message": "Enrol an identity first"}}
            device_id = _uuid(body.get("device_id"))
            sig_pk, enc_pk = _decode(body.get("device_sig_public_key"), KEY_BYTES), _decode(body.get("device_enc_public_key"), KEY_BYTES)
            commitment, registration = _decode(body.get("commitment"), KEY_BYTES), _decode(body.get("registration_signature"), SIG_BYTES)
            if not all((device_id, sig_pk, enc_pk, commitment, registration)) or device_id in self._devices:
                return 422, {"error": {"code": "validation_failed", "message": "Invalid device registration"}}
            try:
                VerifyKey(sig_pk).verify(_lp("svn-dev-reg-v1", device_id, user_id, sig_pk, enc_pk, commitment), registration)
            except BadSignatureError:
                return 422, {"error": {"code": "invalid_signature", "message": "Device registration did not verify"}}
            device = _Device(user_id, device_id, str(body.get("name") or "device"), str(body.get("platform") or "other"),
                             str(body.get("client") or "cli"), sig_pk, enc_pk, commitment=commitment,
                             registration_signature=registration, created_at=_now())
            self._devices[device_id] = device
            return 201, {"device": self._public_device(device, None), "identity": self._public_identity(identity),
                         "approval": {"state": "pending", "expires_at": _approval_expiry(), "attempts_remaining": 1}}

    def vault_list(self, user_id: int) -> list[dict[str, Any]]:
        return [self._vault_payload(vault, user_id) for vault in self._vaults.values() if self._role(vault, user_id)]

    def _role(self, vault: dict[str, Any], user_id: int) -> Optional[str]:
        if vault["kind"] == "personal":
            return "owner" if vault["owner_user_id"] == user_id else None
        for entry in vault["roster"]:
            if entry["user_id"] == user_id and entry["status"] not in {"removed", "revoked", "identity_compromised"}:
                return entry["role"]
        return None

    def _vault_payload(self, vault: dict[str, Any], user_id: int) -> dict[str, Any]:
        role = self._role(vault, user_id)
        write = role in {"owner", "admin"}
        identities = {identity["identity_id"]: self._public_identity(identity) for identity in self._identities.values()}
        answer = {key: copy.deepcopy(vault[key]) for key in ("vault_id", "kind", "scope", "team", "owner_user_id", "name", "grant_policy", "current_version", "rotation", "created_at", "updated_at")}
        answer.update({"versions": copy.deepcopy(vault["versions"]), "my_grant": copy.deepcopy(vault["grants"].get(user_id)), "my_role": role,
                       "permissions": {"read_items": role in {"owner", "admin", "member"}, "write_items": write,
                                       "grant": write, "rotate": write, "manage": write, "view_exposures": write},
                       "counts": {"items": len(self._items.get(vault["vault_id"], {})), "open_exposures": len(self._exposures.get(vault["vault_id"], [])), "pending_recipients": 0},
                       "poll_after_seconds": 300, "access_recovery": None})
        if vault["kind"] == "team":
            answer["roster"] = copy.deepcopy(vault["roster"])
            answer["identities"] = identities
        return answer

    def create_personal(self, user_id: int, body: dict[str, Any], *, team_slug: Optional[str] = None) -> tuple[int, dict[str, Any]]:
        with self._lock:
            identity = self._identity(user_id)
            if identity is None or not identity["grantable"]:
                return 409, {"error": {"code": "no_identity", "message": "A grantable identity is required"}}
            kind = "team" if team_slug is not None else "personal"
            existing = next((v for v in self._vaults.values() if v["kind"] == kind and ((v.get("team") or {}).get("slug") == team_slug if team_slug else v["owner_user_id"] == user_id)), None)
            if existing:
                return 409, {"error": {"code": "already_exists", "message": "Vault already exists"}}
            vault_id = _uuid(body.get("vault_id"))
            version = body.get("version")
            grants = body.get("grants")
            if vault_id is None or not isinstance(version, dict) or not isinstance(grants, list):
                return 422, {"error": {"code": "validation_failed", "message": "vault_id, version and grants are required"}}
            scope = f"team:{TEAM_ID}" if team_slug else f"user:{user_id}"
            public_key = _decode(version.get("public_key"), KEY_BYTES)
            prev_hash = _decode(version.get("prev_hash"), KEY_BYTES)
            signature = _decode(version.get("signature"), SIG_BYTES)
            if public_key is None or prev_hash != b"\0" * KEY_BYTES or signature is None or int(version.get("version", 0)) != 1:
                return 422, {"error": {"code": "validation_failed", "message": "Initial vault version is invalid"}}
            version_message = _lp("svn-tv-version-v1", vault_id, scope, 1, public_key, prev_hash, identity["identity_id"])
            if not _verify(_decode(identity["sig_public_key"], KEY_BYTES), version_message, signature):
                return 422, {"error": {"code": "invalid_signature", "message": "Vault version signature did not verify"}}
            if len(grants) != 1:
                return 422, {"error": {"code": "validation_failed", "message": "Initial vault needs exactly one owner grant"}}
            grant = grants[0]
            sealed = _decode(grant.get("sealed_private_key"), SEALED_KEY_BYTES) if isinstance(grant, dict) else None
            grant_sig = _decode(grant.get("signature"), SIG_BYTES) if isinstance(grant, dict) else None
            if not isinstance(grant, dict) or int(grant.get("recipient_user_id", -1)) != user_id or grant.get("recipient_identity_id") != identity["identity_id"] or sealed is None or grant_sig is None:
                return 422, {"error": {"code": "validation_failed", "message": "Initial vault grant is invalid"}}
            grant_message = _lp("svn-tv-grant-v1", vault_id, scope, 1, public_key, user_id, identity["identity_id"], _fingerprint(identity["fingerprint"]) or b"", hashlib.sha256(sealed).digest(), identity["identity_id"])
            if not _verify(_decode(identity["sig_public_key"], KEY_BYTES), grant_message, grant_sig):
                return 422, {"error": {"code": "invalid_signature", "message": "Vault grant signature did not verify"}}
            vault = self._new_vault(vault_id, kind, scope, user_id, team_slug, [user_id])
            vault["name"] = str(body.get("name") or vault["name"])
            vault["grant_policy"] = str(body.get("grant_policy") or "auto")
            record_hash = _digest("svn-tv-version-hash-v1", version_message, signature)
            vault["versions"] = [{"version": 1, "public_key": _b64(public_key), "prev_hash": _b64(prev_hash), "record_hash": _b64(record_hash), "creator_identity_id": identity["identity_id"], "signature": _b64(signature), "created_at": _now(), "retired_at": None}]
            vault["grants"][user_id] = {"grant_id": str(uuid.uuid4()), "version": 1, "sealed_private_key": _b64(sealed), "granter_identity_id": identity["identity_id"], "signature": _b64(grant_sig), "created_at": _now()}
            self._vaults[vault_id], self._items[vault_id], self._exposures[vault_id] = vault, {}, []
            return 201, self._vault_payload(vault, user_id)

    def put_item(self, vault_id: str, item_id: str, body: dict[str, Any], user_id: int) -> tuple[int, dict[str, Any]]:
        with self._lock:
            vault = self._vaults.get(vault_id)
            if vault is None or self._role(vault, user_id) not in {"owner", "admin"}:
                return 404, {"error": {"code": "not_found", "message": "Vault not found"}}
            if _uuid(item_id) is None or not isinstance(body.get("type"), str):
                return 422, {"error": {"code": "validation_failed", "message": "Invalid item identity"}}
            nonce, ciphertext = _decode(body.get("nonce"), ITEM_NONCE_BYTES), _decode(body.get("ciphertext"))
            if nonce is None or not ciphertext or len(ciphertext) < 16:
                return 422, {"error": {"code": "validation_failed", "message": "Item must contain authenticated ciphertext"}}
            expected = body.get("expected_revision")
            old = self._items.setdefault(vault_id, {}).get(item_id)
            if old is not None and expected != old["revision"]:
                return 409, {"error": {"code": "revision_conflict", "message": "Item revision changed"}}
            if old is None and expected not in (None, 0):
                return 409, {"error": {"code": "revision_conflict", "message": "Item does not exist"}}
            revision = 1 if old is None else old["revision"] + 1
            item = copy.deepcopy(body)
            item.update({
                "item_id": item_id, "vault_id": vault_id, "revision": revision,
                "ciphertext_sha256": _b64(hashlib.sha256(ciphertext).digest()),
                # A fresh item wrap is authored by the same owner/admin that
                # signed the submitted content.  The client verifies this
                # server-derived provenance separately from the content.
                "wrapper_identity_id": str(body.get("author_identity_id", "")),
                "updated_at": _now(), "deleted_at": None,
            })
            self._items[vault_id][item_id] = item
            return 201 if old is None else 200, copy.deepcopy(item)

    def add_grants(self, vault_id: str, body: dict[str, Any], user_id: int) -> tuple[int, dict[str, Any]]:
        with self._lock:
            vault = self._vaults.get(vault_id)
            identity = self._identity(user_id)
            if vault is None or identity is None or self._role(vault, user_id) not in {"owner", "admin"}:
                return 404, {"error": {"code": "not_found", "message": "Vault not found"}}
            version = int(body.get("version", 0))
            records = body.get("grants")
            if version != vault["current_version"] or not isinstance(records, list):
                return 422, {"error": {"code": "validation_failed", "message": "Grant version or records are invalid"}}
            record = vault["versions"][-1]
            public_key = _decode(record["public_key"], KEY_BYTES)
            signer_key = _decode(identity["sig_public_key"], KEY_BYTES)
            if public_key is None or signer_key is None:
                raise AssertionError("stored vault identity is malformed")
            accepted, skipped = [], []
            for grant in records:
                if not isinstance(grant, dict):
                    return 422, {"error": {"code": "validation_failed", "message": "Grant is not an object"}}
                recipient_id = str(grant.get("recipient_identity_id", ""))
                recipient_user = int(grant.get("recipient_user_id", -1))
                recipient = self._identity(recipient_user)
                sealed = _decode(grant.get("sealed_private_key"), SEALED_KEY_BYTES)
                signature = _decode(grant.get("signature"), SIG_BYTES)
                if recipient is None or recipient["identity_id"] != recipient_id or not recipient.get("grantable"):
                    return 422, {"error": {"code": "validation_failed", "message": "Grant recipient is not grantable"}}
                if sealed is None or signature is None:
                    return 422, {"error": {"code": "invalid_signature", "message": "Grant signature is missing"}}
                message = _lp("svn-tv-grant-v1", vault_id, vault["scope"], version, public_key, recipient_user,
                              recipient_id, _fingerprint(recipient["fingerprint"]) or b"", hashlib.sha256(sealed).digest(), identity["identity_id"])
                if not _verify(signer_key, message, signature):
                    return 422, {"error": {"code": "invalid_signature", "message": "Grant signature did not verify"}}
                vault["grants"][recipient_user] = {"grant_id": str(uuid.uuid4()), "version": version,
                                                     "sealed_private_key": _b64(sealed), "granter_identity_id": identity["identity_id"],
                                                     "signature": _b64(signature), "created_at": _now()}
                for roster in vault.get("roster", []):
                    if roster["user_id"] == recipient_user:
                        roster["status"], roster["grant_status"] = "granted", "granted"
                accepted.append({"recipient_user_id": recipient_user, "recipient_identity_id": recipient_id})
            return 200, {"accepted": accepted, "skipped": skipped}

    def rotate(self, vault_id: str, body: dict[str, Any], user_id: int) -> tuple[int, dict[str, Any]]:
        with self._lock:
            vault = self._vaults.get(vault_id)
            identity = self._identity(user_id)
            if vault is None or identity is None or self._role(vault, user_id) not in {"owner", "admin"}:
                return 404, {"error": {"code": "not_found", "message": "Vault not found"}}
            old_version = vault["current_version"]
            version = body.get("version")
            if int(body.get("expected_version", 0)) != old_version or not isinstance(version, dict) or int(version.get("version", 0)) != old_version + 1:
                return 409, {"error": {"code": "version_conflict", "message": "Vault version changed"}}
            public_key = _decode(version.get("public_key"), KEY_BYTES)
            previous = _decode(version.get("prev_hash"), KEY_BYTES)
            signature = _decode(version.get("signature"), SIG_BYTES)
            previous_record = vault["versions"][-1]
            if public_key is None or previous != _decode(previous_record["record_hash"], KEY_BYTES) or signature is None:
                return 422, {"error": {"code": "validation_failed", "message": "Rotation version is invalid"}}
            message = _lp("svn-tv-version-v1", vault_id, vault["scope"], old_version + 1, public_key, previous, identity["identity_id"])
            if not _verify(_decode(identity["sig_public_key"], KEY_BYTES), message, signature):
                return 422, {"error": {"code": "invalid_signature", "message": "Rotation version signature did not verify"}}
            vault["versions"].append({"version": old_version + 1, "public_key": _b64(public_key), "prev_hash": _b64(previous),
                                      "record_hash": _b64(_digest("svn-tv-version-hash-v1", message, signature)),
                                      "creator_identity_id": identity["identity_id"], "signature": _b64(signature), "created_at": _now(), "retired_at": None})
            vault["current_version"] = old_version + 1
            grant_status, grant_result = self.add_grants(vault_id, {"version": old_version + 1, "grants": body.get("grants")}, user_id)
            if grant_status != 200:
                vault["versions"].pop()
                vault["current_version"] = old_version
                return grant_status, grant_result
            vault["rotation"] = {"required": False, "required_since": None, "reasons": [], "last_rotated_at": _now()}
            return 200, {"vault": self._vault_payload(vault, user_id), "accepted": grant_result["accepted"]}

    def delete_item(self, vault_id: str, item_id: str, body: dict[str, Any], user_id: int) -> tuple[int, dict[str, Any]]:
        with self._lock:
            item = self._items.get(vault_id, {}).get(item_id)
            if item is None:
                return 404, {"error": {"code": "not_found", "message": "Item not found"}}
            item["deleted_at"] = _now()
            item["revision"] += 1
            return 200, {"item_id": item_id, "revision": item["revision"], "deleted_at": item["deleted_at"]}


def add_routes(app: web.Application, store: ScenarioStore, vault: VaultCloud) -> None:
    """Register strict Vault routes. Fixed paths come before parameter paths."""

    def current_user() -> int:
        return store.snapshot().user_id

    async def guarded(request: web.Request, handler: Any, *, pending: bool = False, unsigned: bool = False) -> web.Response:
        if not bearer_ok(request, store):
            return unauthorized()
        device, failure = vault.authenticate(request, allow_pending=pending, unsigned=unsigned)
        if failure:
            return failure
        return await handler(request, device)

    def route(handler: Any, *, pending: bool = False, unsigned: bool = False) -> Any:
        async def endpoint(request: web.Request) -> web.Response:
            return await guarded(request, handler, pending=pending, unsigned=unsigned)
        return endpoint

    async def identity_me(request: web.Request, device: Optional[_Device]) -> web.Response:
        return web.json_response(vault.identity_payload(request.headers.get("X-Servonaut-Device")))

    async def identity_confirmation(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        status, body = vault.request_confirmation(device.user_id)
        return web.json_response(body, status=status)

    async def identity_enrol(request: web.Request, device: Optional[_Device]) -> web.Response:
        body = await json_body(request)
        candidate = body.get("device")
        failure = vault.authenticate_bootstrap(
            request,
            device_id=candidate.get("device_id") if isinstance(candidate, dict) else None,
            signing_key=candidate.get("device_sig_public_key") if isinstance(candidate, dict) else None,
        )
        if failure:
            return failure
        status, body = vault.enrol_identity(body)
        return web.json_response(body, status=status)

    async def recovery_get(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        wrap = vault._recovery_wraps.get(device.user_id)
        identity = vault._identity(device.user_id)
        if not wrap or not identity:
            return _not_found()
        wrap["last_fetched_at"] = _now()
        return web.json_response({"identity_id": identity["identity_id"], "fingerprint": identity["fingerprint"],
                                  "blob": _b64(wrap["blob"]), "created_at": wrap["created_at"]})

    async def recovery_put(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        blob = _decode((await json_body(request)).get("blob"), RECOVERY_WRAP_BYTES)
        if blob is None:
            return _error("invalid_recovery_wrap", "Recovery wrap has an invalid format", 422)
        vault._recovery_wraps[device.user_id] = {"blob": blob, "created_at": _now(), "last_fetched_at": None}
        return web.json_response({"created_at": vault._recovery_wraps[device.user_id]["created_at"]})

    async def device_register(request: web.Request, device: Optional[_Device]) -> web.Response:
        status, body = vault.register_device(await json_body(request))
        return web.json_response(body, status=status)

    async def device_register_bootstrap(request: web.Request) -> web.Response:
        if not bearer_ok(request, store):
            return unauthorized()
        body = await json_body(request)
        failure = vault.authenticate_bootstrap(
            request, device_id=body.get("device_id"), signing_key=body.get("device_sig_public_key")
        )
        if failure:
            return failure
        status, response = vault.register_device(body)
        return web.json_response(response, status=status)

    async def devices_list(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        return web.json_response({"devices": vault.devices(device.user_id)})

    async def approval_read(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        target = vault._devices.get(request.match_info["device_id"])
        if target is None or target.user_id != device.user_id:
            return _not_found()
        return web.json_response({"state": _approval_state(target), "device": vault._public_device(target, device.device_id),
                                  "commitment": _b64(target.commitment or b""),
                                  "registration_signature": _b64(target.registration_signature or b""),
                                  # Like the real server, the approver never gets its own nonce back.
                                  "device_nonce": _b64(target.device_nonce) if target.device_nonce else None})

    async def challenge(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        target = vault._devices.get(request.match_info["device_id"])
        if target is None or target.user_id != device.user_id:
            return _not_found()
        body = await json_body(request)
        nonce, commitment = _decode(body.get("approver_nonce"), DEVICE_NONCE_BYTES), _decode(body.get("commitment"), KEY_BYTES)
        if nonce is None or commitment is None:
            return _problem("commitment")
        if not hmac.compare_digest(commitment, target.commitment or b""):
            return _error("commitment_mismatch", "Pinned commitment does not match registration", 422, field="commitment")
        if target.status != "pending":
            return _error("approval_expired", "Device registration is no longer pending", 410)
        if target.approver_nonce is not None and not hmac.compare_digest(target.approver_nonce, nonce):
            return _error("approval_in_progress", "A different device is already approving this registration", 409)
        target.approver_nonce, target.approver_device_id = nonce, device.device_id
        return web.json_response({"state": "challenged", "expires_at": _approval_expiry()})

    async def approval_me(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        target = device
        return web.json_response({"state": _approval_state(target), "approver_device_id": target.approver_device_id,
                                  "approver_device_name": vault._devices[target.approver_device_id].name if target.approver_device_id else None,
                                  "approver_nonce": _b64(target.approver_nonce) if target.approver_nonce else None,
                                  "sealed_bundle": _b64(target.sealed_bundle) if target.sealed_bundle else None,
                                  "endorsement_signature": _b64(target.endorsement_signature) if target.endorsement_signature else None,
                                  "attempts_remaining": 1 if target.status == "pending" else 0, "expires_at": _approval_expiry()})

    async def reveal(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        target = device
        nonce = _decode((await json_body(request)).get("device_nonce"), DEVICE_NONCE_BYTES)
        if nonce is None:
            return _problem("device_nonce")
        if target.approver_nonce is None:
            return _error("approval_not_challenged", "Approval has not been challenged", 409)
        if target.device_nonce is not None and not hmac.compare_digest(target.device_nonce, nonce):
            return _error("commitment_mismatch", "A device nonce was already revealed", 422)
        computed = _digest("svn-dev-commit-v1", target.device_id, target.sig_key, target.enc_key, nonce)
        if not hmac.compare_digest(computed, target.commitment or b""):
            target.status = "rejected"
            return _error("commitment_mismatch", "Commitment mismatch ended this registration", 422, state="rejected", attempts_remaining=0)
        target.device_nonce = nonce
        return web.json_response({"state": "revealed"})

    async def approve(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        target = vault._devices.get(request.match_info["device_id"])
        identity = vault._identity(device.user_id)
        if target is None or identity is None or target.user_id != device.user_id:
            return _not_found()
        body = await json_body(request)
        sealed, endorsement = _decode(body.get("sealed_bundle"), 117), _decode(body.get("endorsement_signature"), SIG_BYTES)
        if target.device_nonce is None:
            return _error("approval_not_revealed", "Device has not revealed its nonce", 409)
        if sealed is None or endorsement is None:
            return _problem("sealed_bundle")
        try:
            VerifyKey(_decode(identity["sig_public_key"], KEY_BYTES) or b"").verify(
                _lp("svn-dev-endorse-v1", identity["identity_id"], device.user_id, target.device_id, target.sig_key, target.enc_key), endorsement)
        except BadSignatureError:
            return _error("invalid_signature", "Device endorsement did not verify", 422)
        target.status, target.activation_method, target.endorsed_by_device_id = "active", "device_approval", device.device_id
        target.sealed_bundle, target.endorsement_signature, target.activated_at = sealed, endorsement, _now()
        return web.json_response({"device": vault._public_device(target, None)})

    async def reject(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        target = vault._devices.get(request.match_info["device_id"])
        if target is None or target.user_id != device.user_id:
            return _not_found()
        if (await json_body(request)).get("reason") not in {"sas_mismatch", "not_mine", "cancelled"}:
            return _problem("reason")
        target.status = "rejected"
        return web.json_response({"state": "rejected", "attempts_remaining": 0})

    async def device_activate(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        identity = vault._identity(device.user_id)
        endorsement = _decode((await json_body(request)).get("endorsement_signature"), SIG_BYTES)
        if identity is None or endorsement is None:
            return _error("invalid_signature", "Activation endorsement is required", 422)
        try:
            VerifyKey(_decode(identity["sig_public_key"], KEY_BYTES) or b"").verify(
                _lp("svn-dev-endorse-v1", identity["identity_id"], device.user_id, device.device_id, device.sig_key, device.enc_key), endorsement)
        except BadSignatureError:
            return _error("invalid_signature", "Activation endorsement did not verify", 422)
        device.status, device.activation_method, device.activated_at = "active", "recovery_key", _now()
        return web.json_response({"device": vault._public_device(device, device.device_id)})

    async def device_ssh_key(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        if request.match_info["device_id"] != device.device_id:
            return _error("device_not_owned", "A device can only set its own SSH key", 403)
        value = (await json_body(request)).get("ssh_public_key")
        if not isinstance(value, str) or not value.startswith(("ssh-ed25519 ", "ecdsa-sha2-nistp256 ", "sk-ssh-ed25519@openssh.com ")):
            return _problem("ssh_public_key")
        device.ssh_public_key = value
        return web.json_response({"device": vault._public_device(device, device.device_id)})

    async def vaults_list(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        return web.json_response({"data": vault.vault_list(device.user_id)})

    async def personal_create(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        status, body = vault.create_personal(device.user_id, await json_body(request))
        return web.json_response(body, status=status)

    async def team_create(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        slug = request.match_info["slug"]
        if slug != TEAM_SLUG:
            return _not_found()
        status, body = vault.create_personal(device.user_id, await json_body(request), team_slug=slug)
        return web.json_response(body, status=status)

    async def vault_read(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        item = vault._vaults.get(request.match_info["vault_id"])
        if item is None or not vault._role(item, device.user_id):
            return _not_found()
        return web.json_response(vault._vault_payload(item, device.user_id))

    def _no_grant(vault_row: dict[str, Any], user_id: int) -> Optional[web.Response]:
        # The service refuses item reads to a team member who holds no grant yet.
        if vault_row["kind"] == "team" and vault_row["grants"].get(user_id) is None:
            return _error("forbidden", "You have not been granted access to this vault yet.", 403)
        return None

    async def item_list(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        vault_id = request.match_info["vault_id"]
        if vault_id not in vault._vaults or not vault._role(vault._vaults[vault_id], device.user_id):
            return _not_found()
        if (refused := _no_grant(vault._vaults[vault_id], device.user_id)) is not None:
            return refused
        include_deleted = request.query.get("include_deleted") == "1"
        items = [copy.deepcopy(item) for item in vault._items.get(vault_id, {}).values() if include_deleted or not item.get("deleted_at")]
        return web.json_response({"data": items, "meta": {"next_cursor": None}})

    async def item_read(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        vault_id, item_id = request.match_info["vault_id"], request.match_info["item_id"]
        if vault_id not in vault._vaults or not vault._role(vault._vaults[vault_id], device.user_id):
            return _not_found()
        if (refused := _no_grant(vault._vaults[vault_id], device.user_id)) is not None:
            return refused
        item = vault._items.get(vault_id, {}).get(item_id)
        return web.json_response(copy.deepcopy(item)) if item else _not_found()

    async def item_put(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        status, body = vault.put_item(request.match_info["vault_id"], request.match_info["item_id"], await json_body(request), device.user_id)
        return web.json_response(body, status=status)

    async def item_delete(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        status, body = vault.delete_item(request.match_info["vault_id"], request.match_info["item_id"], await json_body(request), device.user_id)
        return web.json_response(body, status=status)

    async def grants(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        status, body = vault.add_grants(request.match_info["vault_id"], await json_body(request), device.user_id)
        return web.json_response(body, status=status)

    async def rotate(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        status, body = vault.rotate(request.match_info["vault_id"], await json_body(request), device.user_id)
        return web.json_response(body, status=status)

    async def exposures(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        vault_id = request.match_info["vault_id"]
        if vault_id not in vault._vaults or vault._role(vault._vaults[vault_id], device.user_id) not in {"owner", "admin"}:
            return _not_found()
        wanted = request.query.get("status", "open")
        rows = []
        for exposure in vault._exposures.get(vault_id, []):
            if wanted != "all" and exposure.get("status", "open") != wanted:
                continue
            row = copy.deepcopy(exposure)
            # The service names the key the vault holds now; replacing it
            # does not close the exposure (the old key may still be deployed).
            current = vault._items.get(vault_id, {}).get(exposure.get("item_id"), {}).get("public_fingerprint")
            row["current_public_fingerprint"] = current
            row["key_replaced"] = current is not None and current != exposure.get("public_fingerprint")
            rows.append(row)
        return web.json_response({"data": rows, "meta": {"next_cursor": None}})

    async def exposure_resolve(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        vault_id, exposure_id = request.match_info["vault_id"], request.match_info["exposure_id"]
        if vault_id not in vault._vaults or vault._role(vault._vaults[vault_id], device.user_id) not in {"owner", "admin"}:
            return _not_found()
        body = await json_body(request)
        if body.get("resolution") not in {"rotated", "accepted_risk", "not_deployed"} or not isinstance(body.get("note", ""), str) or len(body.get("note", "")) > 500:
            return _problem("resolution")
        for exposure in vault._exposures.get(vault_id, []):
            if exposure.get("exposure_id") == exposure_id:
                if exposure.get("status", "open") != "open":
                    return _error("already_resolved", "This exposure is already resolved", 409)
                exposure.update({"status": "resolved", "resolution": body["resolution"],
                                 "note": body.get("note", ""), "resolved_at": _now()})
                return web.json_response(copy.deepcopy(exposure))
        return _not_found()

    # Personal bindings exist for cloud instances and named custom servers only.
    personal_providers = {"aws", "ovh", "hetzner", "custom"}

    async def binding_get(request: web.Request, device: Optional[_Device]) -> web.Response:
        if request.match_info["provider"] not in personal_providers:
            return _not_found()
        assert device is not None
        value = vault._bindings.get((request.match_info["provider"], request.match_info["instance_id"]))
        return web.json_response(copy.deepcopy(value)) if value else _not_found()

    async def binding_put(request: web.Request, device: Optional[_Device]) -> web.Response:
        if request.match_info["provider"] not in personal_providers:
            return _not_found()
        assert device is not None
        body = await json_body(request)
        target = f"instance:{request.match_info['provider']}:{request.match_info['instance_id']}"
        if not _valid_binding(vault, body, device, target):
            return _problem("credential_binding")
        vault._bindings[(request.match_info["provider"], request.match_info["instance_id"])] = {
            **copy.deepcopy(body), "target": target, "source": "servonaut_vault", "valid": True, "updated_at": _now(),
        }
        return web.json_response(copy.deepcopy(vault._bindings[(request.match_info["provider"], request.match_info["instance_id"])]))

    async def team_binding_put(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        if request.match_info["slug"] != TEAM_SLUG:
            return _not_found()
        body = await json_body(request)
        target = f"shared_server:{request.match_info['server_id']}"
        if not _valid_binding(vault, body, device, target):
            return _problem("credential_binding")
        key = ("team", request.match_info["server_id"])
        vault._bindings[key] = {**copy.deepcopy(body), "target": target,
                                "source": "servonaut_vault", "valid": True, "updated_at": _now()}
        return web.json_response(copy.deepcopy(vault._bindings[key]))

    # The CA routes are intentionally strict about device ownership and SSH-key
    # registration. Certificate material is added once ca_client's payload shape
    # lands; until then a request receives the same explicit contract refusal as
    # an unenrolled real host rather than a fake certificate.
    async def ca_get(request: web.Request, device: Optional[_Device]) -> web.Response:
        if request.match_info["slug"] != TEAM_SLUG:
            return _not_found()
        state = vault._ca.get(TEAM_SLUG)
        return web.json_response(_ca_public(state) if state else {"enabled": False, "team_slug": TEAM_SLUG, "krl_version": 0})

    async def ca_get_bearer(request: web.Request) -> web.Response:
        if not bearer_ok(request, store):
            return unauthorized()
        return await ca_get(request, None)

    async def ca_enable(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        if request.match_info["slug"] != TEAM_SLUG:
            return _not_found()
        user_key, host_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        vault._ca_keys[TEAM_SLUG] = (user_key, host_key)
        user_public = user_key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
        host_public = host_key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
        krl_version = 1
        policy = (await json_body(request)).get("policy") or {
            "interactive_ttl_seconds": 28_800, "automation_ttl_seconds": 600,
            "max_ttl_seconds": 57_600, "require_member_mfa": False,
        }
        vault._ca[TEAM_SLUG] = {
            "enabled": True, "team_slug": TEAM_SLUG,
            "user_ca": {"public_key": user_public, "fingerprint": vault._ssh_fingerprint(user_public)},
            "host_ca": {"public_key": host_public, "fingerprint": vault._ssh_fingerprint(host_public)},
            "policy": policy, "krl_version": krl_version,
            "my_logins_by_server": {SERVER_ID: ["deploy"]}, "issued": [], "hosts": [],
            "krl": build_krl(
                user_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                krl_version, int(time.time()), [],
            ),
            "revoked_serials": [],
        }
        return web.json_response(_ca_public(vault._ca[TEAM_SLUG]), status=201)

    async def ca_policy_put(request: web.Request, device: Optional[_Device]) -> web.Response:
        """Like the real endpoint: top-level fields, omitted ones kept, then validated."""
        assert device is not None
        state = vault._ca.get(request.match_info["slug"])
        if state is None:
            return _error("ca_disabled", "The SSH CA is not enabled", 403)
        body = await json_body(request)
        policy = {**state["policy"], **{key: value for key, value in body.items() if key != "policy"}}
        login_re = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
        for role, logins in (policy.get("role_logins") or {}).items():
            if not isinstance(logins, list) or len(logins) > 16 or not all(
                isinstance(login, str) and login_re.fullmatch(login) for login in logins
            ):
                return _error("validation_failed", "Invalid login", 422, field=f"role_logins.{role}")
        bounds = {"interactive_ttl_seconds": 57_600, "max_ttl_seconds": 57_600, "automation_ttl_seconds": 600}
        for field, maximum in bounds.items():
            value = policy.get(field)
            if value is not None and (not isinstance(value, int) or not 60 <= value <= maximum):
                return _error("validation_failed", "TTL out of range", 422, field=field)
        if policy.get("interactive_ttl_seconds", 0) > policy.get("max_ttl_seconds", 57_600):
            return _error("validation_failed", "TTL out of range", 422, field="interactive_ttl_seconds")
        state["policy"] = policy
        return web.json_response({"policy": policy, "hosts_needing_refresh": [], "certificates_revoked": 0})

    async def ca_cert(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        if request.match_info["slug"] != TEAM_SLUG:
            return _not_found()
        if not vault._ca.get(TEAM_SLUG, {}).get("enabled"):
            return _error("ca_disabled", "The team SSH certificate authority is disabled", 403)
        if not device.ssh_public_key:
            return _error("no_device_ssh_key", "Register a device SSH key before issuing a certificate", 403)
        state = vault._ca[TEAM_SLUG]
        body = await json_body(request)
        server_ids = body.get("server_ids")
        if not isinstance(server_ids, list) or not server_ids:
            return _problem("server_ids")
        selected = [SERVER_ID] if server_ids == ["*"] else list(map(str, server_ids))
        if selected != [SERVER_ID]:
            return _error("server_not_enrolled", "The requested server is not enrolled", 409)
        purpose = str(body.get("purpose", "interactive"))
        ttl = int(body.get("requested_ttl_seconds") or state["policy"].get(f"{purpose}_ttl_seconds", 28_800))
        maximum = int(state["policy"].get("max_ttl_seconds", 57_600))
        if purpose not in {"interactive", "automation"} or ttl <= 0 or ttl > maximum:
            return _error("ttl_out_of_range", "Requested certificate lifetime is not allowed", 422)
        try:
            public_key = load_ssh_public_key(device.ssh_public_key.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            return _problem("ssh_public_key")
        vault._serial += 1
        now = int(time.time())
        principals = [f"svn:{SERVER_ID}:deploy".encode("ascii")]
        key_id = f"u:{device.user_id} d:{device.device_id} t:{TEAM_ID} r:{vault._serial}".encode("ascii")
        certificate = (SSHCertificateBuilder().public_key(public_key).serial(vault._serial)
                       .type(SSHCertificateType.USER).key_id(key_id).valid_principals(principals)
                       .valid_after(now).valid_before(now + ttl).sign(vault._ca_keys[TEAM_SLUG][0]))
        raw_certificate = certificate.public_bytes().decode("ascii")
        valid_after = dt.datetime.fromtimestamp(now, tz=dt.timezone.utc)
        valid_before = dt.datetime.fromtimestamp(now + ttl, tz=dt.timezone.utc)
        entry_hash = _log_issuance(state, vault._serial, "user", key_id.decode("ascii"), device.user_id, device.device_id,
                      [value.decode() for value in principals], now, now + ttl, raw_certificate)
        return web.json_response({"certificate": raw_certificate, "serial": vault._serial,
                                  "key_id": key_id.decode("ascii"), "principals": [value.decode() for value in principals],
                                  "logins_by_server": {SERVER_ID: ["deploy"]}, "valid_after": valid_after.isoformat(),
                                  "valid_before": valid_before.isoformat(),
                                  "renew_after": (valid_after + (valid_before - valid_after) * 0.8).isoformat(),
                                  "ca_fingerprint": state["user_ca"]["fingerprint"], "issuance_entry_hash": _b64(entry_hash)}, status=201)

    async def ca_issued(request: web.Request) -> web.Response:
        if not bearer_ok(request, store):
            return unauthorized()
        if request.match_info["slug"] != TEAM_SLUG:
            return _not_found()
        state = vault._ca.get(TEAM_SLUG)
        if not state or not state.get("enabled"):
            return _error("ca_disabled", "The team SSH certificate authority is disabled", 403)
        rows = [{key: value for key, value in row.items() if key != "entry_hash_raw"} for row in state["issued"]]
        head = state["issued"][-1]["entry_hash"] if state["issued"] else _b64(b"\0" * KEY_BYTES)
        return web.json_response({"data": rows, "meta": {"next_cursor": None, "head_hash": head}})

    async def enrollments_create(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        if request.match_info["slug"] != TEAM_SLUG or not vault._ca.get(TEAM_SLUG, {}).get("enabled"):
            return _not_found()
        body = await json_body(request)
        if body.get("server_id") != SERVER_ID or body.get("kind") not in {"enroll", "refresh", "unenroll"}:
            return _problem("enrollment")
        enrollment_id = str(uuid.uuid4())
        vault._enrolments[enrollment_id] = {"enrollment_id": enrollment_id, "status": "requested",
                                            "kind": body["kind"], "server_id": SERVER_ID,
                                            "executor_user_id": device.user_id, "executor_device_id": device.device_id,
                                            "break_glass_item_id": body.get("break_glass_item_id"), "created_at": _now()}
        return web.json_response({"enrollment_id": enrollment_id, "status": "requested", "executor_user_id": device.user_id, "expires_at": _now()}, status=201)

    def _enrollment(request: web.Request, device: _Device) -> Optional[dict[str, Any]]:
        row = vault._enrolments.get(request.match_info["enrollment_id"])
        if row is None or row["executor_user_id"] != device.user_id:
            return None
        return row

    async def enrollments_list(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        rows = [copy.deepcopy(row) for row in vault._enrolments.values() if row["executor_user_id"] == device.user_id]
        return web.json_response({"data": rows, "meta": {"next_cursor": None}})

    async def enrollment_get(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        row = _enrollment(request, device)
        state = vault._ca.get(TEAM_SLUG)
        if row is None or state is None:
            return _not_found()
        params = {"enrollment_id": row["enrollment_id"], "kind": row["kind"], "script_version": "1",
                  "server": {"id": SERVER_ID, "name": "server-1", "hostname": "server-1.example.test", "port": 22},
                  "connect_via": {"credential_binding": None},
                  "user_ca_public_keys": [state["user_ca"]["public_key"]], "host_ca_public_key": state["host_ca"]["public_key"],
                  "principals_by_login": {"deploy": [f"svn:{SERVER_ID}:deploy"]},
                  "host_principals": ["server-1.example.test", f"{SERVER_ID}.example.test"],
                  "krl": _b64(state["krl"]), "break_glass": None,
                  "managed_dir": "/etc/ssh/servonaut", "drop_in": "/etc/ssh/sshd_config.d/50-servonaut.conf"}
        row["params"] = params
        return web.json_response(params)

    async def enrollment_claim(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        row = _enrollment(request, device)
        if row is None:
            return _not_found()
        if row["status"] not in {"requested", "claimed"}:
            return _error("already_claimed", "Enrollment is no longer claimable", 409)
        row["status"] = "claimed"
        params = row.get("params") or {}
        return web.json_response({"status": "claimed", "params_hash": _b64(hashlib.sha256(json_dumps(params)).digest())})

    async def enrollment_host_cert(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        row = _enrollment(request, device)
        state = vault._ca.get(TEAM_SLUG)
        value = (await json_body(request)).get("host_public_key")
        if row is None or state is None or not isinstance(value, str):
            return _not_found()
        try:
            public = load_ssh_public_key(value.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            return _problem("host_public_key")
        vault._serial += 1
        now = int(time.time())
        valid_before = now + 365 * 24 * 3600
        certificate = (SSHCertificateBuilder().public_key(public).serial(vault._serial).type(SSHCertificateType.HOST)
                       .key_id(f"host:{SERVER_ID}".encode()).valid_principals([b"server-1.example.test"])
                       .valid_after(now).valid_before(valid_before).sign(vault._ca_keys[TEAM_SLUG][1]))
        _log_issuance(state, vault._serial, "host", f"host:{SERVER_ID}", None, None, ["server-1.example.test"], now, valid_before,
                      certificate.public_bytes().decode("ascii"))
        return web.json_response({"host_certificate": certificate.public_bytes().decode("ascii"), "serial": vault._serial,
                                  "valid_before": dt.datetime.fromtimestamp(valid_before, tz=dt.timezone.utc).isoformat()})

    async def enrollment_result(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        row = _enrollment(request, device)
        body = await json_body(request)
        if row is None or body.get("status") not in {"succeeded", "failed", "rolled_back"} or not isinstance(body.get("steps"), list):
            return _problem("result")
        row["status"], row["result"] = body["status"], copy.deepcopy(body)
        state = vault._ca[TEAM_SLUG]
        state["hosts"] = [{"server_id": SERVER_ID, "status": "enrolled" if body["status"] == "succeeded" else "failed",
                           "script_version": "1", "user_ca_generations": [1], "host_cert_serial": vault._serial,
                           "host_cert_valid_before": None, "krl_version_delivered": state["krl_version"],
                           "enrolled_at": _now(), "last_verified_at": _now(), "last_error": body.get("error_code"), "needs_refresh": False}]
        return web.json_response({"status": row["status"]})

    async def ca_krl(request: web.Request) -> web.Response:
        if not bearer_ok(request, store):
            return unauthorized()
        state = vault._ca.get(TEAM_SLUG)
        if state is None:
            return _not_found()
        return web.Response(body=state["krl"], content_type="application/octet-stream", headers={"X-Servonaut-KRL-Version": str(state["krl_version"])})

    async def ca_revocations(request: web.Request) -> web.Response:
        if not bearer_ok(request, store):
            return unauthorized()
        state = vault._ca.get(TEAM_SLUG)
        if state is None:
            return _not_found()
        return web.json_response({"krl_version": state["krl_version"], "generated_at": _now(), "serials": state["revoked_serials"],
                                  "krl": _b64(state["krl"]), "sha256": _b64(hashlib.sha256(state["krl"]).digest())})

    async def ca_delivery(request: web.Request, device: Optional[_Device]) -> web.Response:
        assert device is not None
        state = vault._ca.get(TEAM_SLUG)
        body = await json_body(request)
        if state is None or int(body.get("krl_version", -1)) != state["krl_version"] or not isinstance(body.get("results"), list):
            return _problem("krl_delivery")
        return web.json_response({"accepted": len(body["results"])})

    router = app.router
    # Bootstrap identity read is the only unsigned vault route.
    router.add_get(f"{VAULT}/identity/me", route(identity_me, unsigned=True))
    router.add_post(f"{VAULT}/identity", route(identity_enrol, unsigned=True))
    router.add_post(f"{VAULT}/identity/me/confirmation", route(identity_confirmation))
    router.add_get(f"{VAULT}/identity/me/recovery-wrap", route(recovery_get, pending=True))
    router.add_put(f"{VAULT}/identity/me/recovery-wrap", route(recovery_put))
    # The registering device is not stored yet; its registration signature is
    # verified in ``register_device`` instead of trying generic lookup first.
    router.add_post(f"{VAULT}/devices", device_register_bootstrap)
    router.add_get(f"{VAULT}/devices", route(devices_list))
    router.add_get(f"{VAULT}/devices/me/approval", route(approval_me, pending=True))
    router.add_post(f"{VAULT}/devices/me/approval/reveal", route(reveal, pending=True))
    router.add_post(f"{VAULT}/devices/me/activate", route(device_activate, pending=True))
    router.add_get(f"{VAULT}/devices/{{device_id}}/approval", route(approval_read))
    router.add_post(f"{VAULT}/devices/{{device_id}}/approval/challenge", route(challenge))
    router.add_post(f"{VAULT}/devices/{{device_id}}/approve", route(approve))
    router.add_post(f"{VAULT}/devices/{{device_id}}/reject", route(reject, pending=True))
    router.add_put(f"{VAULT}/devices/{{device_id}}/ssh-key", route(device_ssh_key))
    router.add_get(VAULTS, route(vaults_list))
    router.add_post(f"{VAULT}/personal", route(personal_create))
    router.add_post("/api/v1/teams/{slug}/vaults", route(team_create))
    router.add_get(f"{VAULTS}/{{vault_id}}", route(vault_read))
    router.add_get(f"{VAULTS}/{{vault_id}}/items", route(item_list))
    router.add_get(f"{VAULTS}/{{vault_id}}/items/{{item_id}}", route(item_read))
    router.add_put(f"{VAULTS}/{{vault_id}}/items/{{item_id}}", route(item_put))
    router.add_delete(f"{VAULTS}/{{vault_id}}/items/{{item_id}}", route(item_delete))
    router.add_post(f"{VAULTS}/{{vault_id}}/grants", route(grants))
    router.add_post(f"{VAULTS}/{{vault_id}}/rotate", route(rotate))
    router.add_get(f"{VAULTS}/{{vault_id}}/exposures", route(exposures))
    router.add_post(f"{VAULTS}/{{vault_id}}/exposures/{{exposure_id}}/resolve", route(exposure_resolve))
    router.add_get("/api/v1/me/instances/{provider}/{instance_id}/credential-binding", route(binding_get))
    router.add_put("/api/v1/me/instances/{provider}/{instance_id}/credential-binding", route(binding_put))
    router.add_put("/api/v1/teams/{slug}/servers/{server_id}/credential-binding", route(team_binding_put))
    router.add_get("/api/v1/teams/{slug}/ssh-ca", ca_get_bearer)
    router.add_post("/api/v1/teams/{slug}/ssh-ca", route(ca_enable))
    router.add_put("/api/v1/teams/{slug}/ssh-ca/policy", route(ca_policy_put))
    router.add_post("/api/v1/teams/{slug}/ssh-ca/certs", route(ca_cert))
    router.add_get("/api/v1/teams/{slug}/ssh-ca/issued", ca_issued)
    router.add_post("/api/v1/teams/{slug}/ssh-ca/enrollments", route(enrollments_create))
    router.add_get("/api/v1/teams/{slug}/ssh-ca/enrollments", route(enrollments_list))
    router.add_get("/api/v1/teams/{slug}/ssh-ca/enrollments/{enrollment_id}", route(enrollment_get))
    router.add_post("/api/v1/teams/{slug}/ssh-ca/enrollments/{enrollment_id}/claim", route(enrollment_claim))
    router.add_post("/api/v1/teams/{slug}/ssh-ca/enrollments/{enrollment_id}/host-cert", route(enrollment_host_cert))
    router.add_post("/api/v1/teams/{slug}/ssh-ca/enrollments/{enrollment_id}/result", route(enrollment_result))
    router.add_get("/api/v1/teams/{slug}/ssh-ca/krl", ca_krl)
    router.add_get("/api/v1/teams/{slug}/ssh-ca/revocations", ca_revocations)
    router.add_post("/api/v1/teams/{slug}/ssh-ca/krl-deliveries", route(ca_delivery))


def _approval_state(device: _Device) -> str:
    if device.status == "pending":
        if device.device_nonce is not None:
            return "revealed"
        return "challenged" if device.approver_nonce is not None else "pending"
    if device.status == "active":
        return "approved"
    return device.status


def _verify(public_key: Optional[bytes], message: bytes, signature: bytes) -> bool:
    if public_key is None:
        return False
    try:
        VerifyKey(public_key).verify(message, signature)
    except (BadSignatureError, ValueError):
        return False
    return True


def _valid_binding(vault: VaultCloud, body: dict[str, Any], device: _Device, target: str) -> bool:
    required = {"vault_id", "vault_item_id", "hostname", "port", "login_user", "public_fingerprint", "host_keys", "binder_identity_id", "binding_revision", "signature"}
    if not required <= set(body) or not isinstance(body.get("host_keys"), list):
        return False
    identity = vault._identity(device.user_id)
    stored_vault = vault._vaults.get(str(body.get("vault_id")))
    if identity is None or stored_vault is None or body.get("binder_identity_id") != identity["identity_id"]:
        return False
    try:
        port, revision = int(body["port"]), int(body["binding_revision"])
    except (TypeError, ValueError):
        return False
    signature = _decode(body.get("signature"), SIG_BYTES)
    if signature is None or not 1 <= port <= 65535 or revision < 1 or len(body["host_keys"]) > 8:
        return False
    keys = body["host_keys"]
    if any(not isinstance(key, str) or len(key.split()) != 2 for key in keys):
        return False
    encoded_keys = b"".join(struct.pack(">I", len(key.encode())) + key.encode() for key in sorted(keys))
    list_field = struct.pack(">I", len(keys)) + encoded_keys
    message = _lp("svn-binding-v1", stored_vault["scope"], target, str(body["hostname"]), port,
                  str(body["login_user"]), str(body["vault_id"]), str(body["vault_item_id"]),
                  str(body["public_fingerprint"]), list_field, revision, identity["identity_id"])
    return _verify(_decode(identity["sig_public_key"], KEY_BYTES), message, signature)


def _issuance_hash(prev: bytes, team_id: str, serial: int, key_id: str, user_id: int, device_id: str,
                   principals: list[str], valid_after: int, valid_before: int, certificate_hash: bytes, issued_at: int) -> bytes:
    principal_list = struct.pack(">I", len(principals)) + b"".join(
        struct.pack(">I", len(value.encode())) + value.encode() for value in principals
    )
    return hashlib.sha256(_lp("svn-ca-issuance-v1", prev, team_id, serial, key_id, user_id, device_id,
                              principal_list, valid_after, valid_before, certificate_hash, issued_at)).digest()


def _log_issuance(state: dict[str, Any], serial: int, cert_type: str, key_id: str, user_id: Optional[int],
                  device_id: Optional[str], principals: list[str], valid_after: int, valid_before: int,
                  certificate: str) -> bytes:
    """Append one hash-chained row to the team's issuance log, as the service does."""
    previous = state["issued"][-1]["entry_hash_raw"] if state["issued"] else b"\0" * KEY_BYTES
    # The log hashes the binary blob, not the "<type> <base64>" wire line.
    certificate_hash = hashlib.sha256(base64.b64decode(certificate.split()[1])).digest()
    entry_hash = _issuance_hash(previous, TEAM_ID, serial, key_id, user_id or 0, device_id or "", principals,
                                valid_after, valid_before, certificate_hash, valid_after)
    issued_at = dt.datetime.fromtimestamp(valid_after, tz=dt.timezone.utc).isoformat()
    state["issued"].append({
        "serial": serial, "cert_type": cert_type, "key_id": key_id, "user_id": user_id, "device_id": device_id,
        "server_id": SERVER_ID, "principals": principals, "valid_after": issued_at,
        "valid_before": dt.datetime.fromtimestamp(valid_before, tz=dt.timezone.utc).isoformat(),
        "certificate_sha256": _b64(certificate_hash), "issued_at": issued_at,
        "prev_hash": _b64(previous), "entry_hash": _b64(entry_hash), "entry_hash_raw": entry_hash, "revoked_at": None,
    })
    return entry_hash


def _ca_public(state: dict[str, Any]) -> dict[str, Any]:
    """Drop private/opaque fake-only material from a JSON API response."""
    return {key: copy.deepcopy(value) for key, value in state.items() if key not in {"krl", "issued"}}
