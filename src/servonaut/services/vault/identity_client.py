"""Injectable client operations for Team Vault identity and device lifecycle."""
from __future__ import annotations

import base64
import os
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

from servonaut.services.api_client import APIClient
from servonaut.services.memory.crypto import secure_zero

from .crypto import (
    IntegrityError,
    device_commitment,
    device_registration_message,
    endorsement_message,
    parse_recovery_key,
    open_sealed,
    recovery_kek,
    request_message,
    sas,
    seal,
    seal_wrap,
    self_signature,
    sign,
    verify_identity,
    verify,
    wrap_aad,
)
from .identity_store import IdentityStore, LocalDevice, LocalIdentity


class IdentityProtocolError(RuntimeError):
    """The server response violated a client-side identity invariant."""


class NoLocalIdentityError(IdentityProtocolError):
    """This computer holds no unlocked vault identity, so it cannot sign the request."""


class RecoveryKeyMismatchError(IdentityProtocolError):
    """A well-formed recovery key that does not open this identity's recovery bundle."""


@dataclass(frozen=True)
class PendingDevice:
    """Fresh local material retained while the one-shot approval is pending."""

    device: LocalDevice
    device_nonce: bytearray
    commitment: bytes


def _destroy_pending(pending: PendingDevice) -> None:
    """Zero the keys and nonce of a registration that will never be used."""
    secure_zero(pending.device.signing_seed)
    secure_zero(pending.device.encryption_secret_key)
    secure_zero(pending.device_nonce)


@dataclass(frozen=True)
class ApprovalPin:
    """Values pinned before an approver sends its secret nonce."""

    device_id: str
    device_sig_public_key: bytes
    device_enc_public_key: bytes
    commitment: bytes


class IdentityClient:
    """Perform device identity APIs while keeping UI confirmation outside it."""

    def __init__(self, api_client: APIClient, store: IdentityStore, *, timeout: float) -> None:
        self._api = api_client
        self._store = store
        self._timeout = timeout
        self._pending: PendingDevice | None = None
        self._revealed_to_approver_nonce: bytes | None = None
        self._pending_state: str | None = None

    async def status(self) -> dict[str, Any]:
        """Fetch untrusted identity status; callers verify before acting on it."""
        return await self._api.get("/api/v1/vault/identity/me", timeout=self._timeout)

    async def enroll(
        self,
        *,
        recovery_key: str,
        device_name: str,
        platform: str,
        client: str,
    ) -> dict[str, Any]:
        """Enroll the locally created identity using an explicitly confirmed key."""
        identity = self._required_identity()
        recovery = parse_recovery_key(recovery_key)
        signature = self_signature(
            bytes(identity.signing_seed),
            identity.identity_id,
            identity.user_id,
            identity.signing_public_key,
            identity.encryption_public_key,
        )
        registration_signature = sign(
            bytes(identity.device.signing_seed),
            device_registration_message(
                identity.device.device_id,
                identity.user_id,
                identity.device.signing_public_key,
                identity.device.encryption_public_key,
                b"\0" * 32,
            ),
        )
        endorsement_signature = sign(
            bytes(identity.signing_seed),
            endorsement_message(
                identity.identity_id,
                identity.user_id,
                identity.device.device_id,
                identity.device.signing_public_key,
                identity.device.encryption_public_key,
            ),
        )
        recovery_blob = seal_wrap(
            recovery_kek(recovery, identity.identity_id),
            self._bundle(identity),
            wrap_aad("recovery", identity.identity_id, identity.user_id, identity.fingerprint_raw),
        )
        result = await self._api.request_signed(
            "POST",
            "/api/v1/vault/identity",
            device=identity.device,
            timeout=self._timeout,
            json=self._identity_enrollment_body(
                identity, signature, registration_signature, endorsement_signature, recovery_blob,
                device_name, platform, client,
            ),
        )
        self._store.save(identity)
        return result

    async def request_reset(
        self,
        *,
        replacement: LocalIdentity,
        recovery_key: str,
        reason: str,
        device_name: str,
        platform: str,
        client: str,
    ) -> dict[str, Any]:
        """Request an e-mail-confirmed identity reset without replacing local state."""
        if reason not in {"lost_all_devices", "compromised", "rotate"}:
            raise ValueError("invalid identity reset reason")
        recovery = parse_recovery_key(recovery_key)
        signature = self_signature(bytes(replacement.signing_seed), replacement.identity_id, replacement.user_id, replacement.signing_public_key, replacement.encryption_public_key)
        registration = sign(bytes(replacement.device.signing_seed), device_registration_message(replacement.device.device_id, replacement.user_id, replacement.device.signing_public_key, replacement.device.encryption_public_key, b"\0" * 32))
        endorsement = sign(bytes(replacement.signing_seed), endorsement_message(replacement.identity_id, replacement.user_id, replacement.device.device_id, replacement.device.signing_public_key, replacement.device.encryption_public_key))
        wrapped = seal_wrap(recovery_kek(recovery, replacement.identity_id), self._bundle(replacement), wrap_aad("recovery", replacement.identity_id, replacement.user_id, replacement.fingerprint_raw))
        body = self._identity_enrollment_body(replacement, signature, registration, endorsement, wrapped, device_name, platform, client)
        body["reason"] = reason
        return await self._api.request_signed(
            "POST", "/api/v1/vault/identity/reset", device=replacement.device,
            timeout=self._timeout, json=body,
        )

    def save_confirmed_reset(self, replacement: LocalIdentity) -> None:
        """Persist a replacement only after status proves it is active/confirmed."""
        self._store.save(replacement)

    def finish_confirmed_reset(
        self, *, replacement: LocalIdentity, status: Mapping[str, Any],
    ) -> LocalIdentity:
        """Persist a reset replacement only after a verified REST reread."""
        remote = status.get("identity")
        if status.get("pending_reset") is not None or not isinstance(remote, dict):
            raise IdentityProtocolError("Identity reset is not confirmed")
        identity_id, user_id, sig_public, enc_public, fingerprint = _verified_server_identity(remote)
        if (
            identity_id != replacement.identity_id
            or user_id != replacement.user_id
            or fingerprint != replacement.fingerprint_raw
            or sig_public != replacement.signing_public_key
            or enc_public != replacement.encryption_public_key
        ):
            raise IdentityProtocolError("Confirmed reset identity does not match the replacement")
        self.save_confirmed_reset(replacement)
        return replacement

    @staticmethod
    def discard_reset_replacement(replacement: LocalIdentity) -> None:
        """Zero a replacement that never became the active identity."""
        secure_zero(replacement.signing_seed)
        secure_zero(replacement.encryption_secret_key)
        secure_zero(replacement.device.signing_seed)
        secure_zero(replacement.device.encryption_secret_key)

    def begin_pending_device(self) -> PendingDevice:
        """Generate a registration exactly once; replacement needs a new call."""
        # A registration that was never finished must not outlive its replacement.
        self._discard_pending()
        device = LocalDevice(str(uuid.uuid4()), os.urandom(32), os.urandom(32))
        nonce = bytearray(os.urandom(32))
        pending = PendingDevice(
            device=device,
            device_nonce=nonce,
            commitment=device_commitment(
                device.device_id, device.signing_public_key, device.encryption_public_key, nonce
            ),
        )
        self._pending = pending
        self._pending_state = "pending"
        return pending

    async def register_pending_device(
        self,
        *,
        user_id: int,
        name: str,
        platform: str,
        client: str,
    ) -> dict[str, Any]:
        """Register the pending keys produced by :meth:`begin_pending_device`."""
        if type(user_id) is not int or user_id < 1:
            raise ValueError("user_id must be a positive integer")
        pending = self._required_pending()
        result = await self._api.request_signed(
            "POST",
            "/api/v1/vault/devices",
            device=pending.device,
            timeout=self._timeout,
            json={
                "device_id": pending.device.device_id,
                "name": name,
                "platform": platform,
                "client": client,
                "device_sig_public_key": _b64(pending.device.signing_public_key),
                "device_enc_public_key": _b64(pending.device.encryption_public_key),
                "commitment": _b64(pending.commitment),
                "registration_signature": _b64(sign(
                    bytes(pending.device.signing_seed),
                    device_registration_message(
                        pending.device.device_id, user_id, pending.device.signing_public_key,
                        pending.device.encryption_public_key, pending.commitment,
                    ),
                )),
            },
        )
        return result

    async def pending_approval_status(self) -> dict[str, Any]:
        response = await self._api.request_signed(
            "GET", "/api/v1/vault/devices/me/approval", device=self._required_pending().device,
            timeout=self._timeout,
        )
        if not isinstance(response, dict):
            self._discard_pending()
            raise IdentityProtocolError("Pending approval response is malformed")
        self._observe_pending_state(response)
        return response

    async def reveal_pending_nonce(self, approval: dict[str, Any]) -> dict[str, Any]:
        """Reveal once after a specific challenge; reject state changes locally."""
        pending = self._required_pending()
        self._observe_pending_state(approval)
        if approval.get("state") not in {"challenged", "revealed"} or not isinstance(approval.get("approver_nonce"), str):
            raise IdentityProtocolError("Pending device was not challenged")
        approver_nonce = _decode_b64(approval["approver_nonce"])
        if self._revealed_to_approver_nonce is not None:
            if approver_nonce != self._revealed_to_approver_nonce:
                self._discard_pending()
                raise IdentityProtocolError("Approver nonce changed after disclosure; registration is terminal")
            if approval.get("state") == "revealed":
                return approval
        elif approval.get("state") != "challenged":
            self._discard_pending()
            raise IdentityProtocolError("Pending approval state moved backwards")
        self._revealed_to_approver_nonce = approver_nonce
        response = await self._api.request_signed(
            "POST", "/api/v1/vault/devices/me/approval/reveal", device=pending.device,
            timeout=self._timeout, json={"device_nonce": _b64(pending.device_nonce)},
        )
        if not isinstance(response, dict):
            self._discard_pending()
            raise IdentityProtocolError("Pending reveal response is malformed")
        self._observe_pending_state(response)
        return response

    async def pin_approval(self, device_id: str) -> ApprovalPin:
        """Read and verify the registration before issuing an approver nonce."""
        identity = self._required_identity()
        response = await self._api.request_signed(
            "GET", f"/api/v1/vault/devices/{device_id}/approval", device=identity.device,
            timeout=self._timeout,
        )
        device = response.get("device")
        if not isinstance(device, dict):
            raise IdentityProtocolError("Approval response did not include a device")
        try:
            pinned = ApprovalPin(
                device_id=str(device["device_id"]),
                device_sig_public_key=_decode_b64(str(device["device_sig_public_key"])),
                device_enc_public_key=_decode_b64(str(device["device_enc_public_key"])),
                commitment=_decode_b64(str(response["commitment"])),
            )
            registration = _decode_b64(str(response["registration_signature"]))
        except (KeyError, ValueError) as exc:
            raise IdentityProtocolError("Approval response has invalid key material") from exc
        if pinned.device_id != device_id or not verify(
            pinned.device_sig_public_key,
            device_registration_message(
                pinned.device_id, identity.user_id, pinned.device_sig_public_key,
                pinned.device_enc_public_key, pinned.commitment,
            ),
            registration,
        ):
            raise IdentityProtocolError("Pending device registration signature is invalid")
        return pinned

    async def challenge_approval(self, pin: ApprovalPin, *, approver_nonce: bytes) -> dict[str, Any]:
        if len(approver_nonce) != 32:
            raise ValueError("approver_nonce must be 32 bytes")
        return await self._api.request_signed(
            "POST", f"/api/v1/vault/devices/{pin.device_id}/approval/challenge",
            device=self._required_identity().device, timeout=self._timeout,
            json={"approver_nonce": _b64(approver_nonce), "commitment": _b64(pin.commitment)},
        )

    def pending_sas(self, approval: dict[str, Any], *, identity: dict[str, Any]) -> str:
        """Calculate the SAS locally; caller displays it for explicit comparison."""
        pending = self._required_pending()
        try:
            _identity_id, _user_id, _sig_public, _enc_public, fingerprint = _verified_server_identity(identity)
            nonce = _decode_b64(str(approval.get("approver_nonce", "")))
            return sas(
                pending.device.device_id, fingerprint, pending.device.signing_public_key,
                pending.device.encryption_public_key, pending.device_nonce, nonce,
            )
        except (ValueError, IdentityProtocolError):
            self._discard_pending()
            raise

    async def approve_pinned_device(
        self, pin: ApprovalPin, approval: dict[str, Any], *, approver_nonce: bytes, confirmed_sas: str
    ) -> dict[str, Any]:
        """Approve only after the caller has explicitly confirmed a matching SAS.

        ``approver_nonce`` is the value this device sent with its challenge;
        the approver-side approval read never carries it.
        """
        if len(approver_nonce) != 32:
            raise ValueError("approver_nonce must be 32 bytes")
        identity = self._required_identity()
        device = approval.get("device")
        if not isinstance(device, dict) or str(device.get("device_id")) != pin.device_id:
            raise IdentityProtocolError("Approval device changed after pinning")
        sig_key = _decode_b64(str(device.get("device_sig_public_key", "")))
        enc_key = _decode_b64(str(device.get("device_enc_public_key", "")))
        nonce = _decode_b64(str(approval.get("device_nonce", "")))
        if sig_key != pin.device_sig_public_key or enc_key != pin.device_enc_public_key:
            raise IdentityProtocolError("Approval keys changed after pinning")
        if device_commitment(pin.device_id, sig_key, enc_key, nonce) != pin.commitment:
            raise IdentityProtocolError("Approval commitment mismatch")
        expected = sas(pin.device_id, identity.fingerprint_raw, sig_key, enc_key, nonce, approver_nonce)
        if confirmed_sas != expected:
            raise IdentityProtocolError("Safety number does not match; registration must be rejected")
        sealed_bundle = seal(self._bundle(identity), enc_key)
        endorsement = sign(bytes(identity.signing_seed), endorsement_message(
            identity.identity_id, identity.user_id, pin.device_id, sig_key, enc_key,
        ))
        return await self._api.request_signed(
            "POST", f"/api/v1/vault/devices/{pin.device_id}/approve", device=identity.device,
            timeout=self._timeout,
            json={"sealed_bundle": _b64(sealed_bundle), "endorsement_signature": _b64(endorsement)},
        )

    async def reject_device(self, device_id: str, *, reason: str) -> dict[str, Any]:
        if reason not in {"sas_mismatch", "not_mine", "cancelled"}:
            raise ValueError("invalid terminal rejection reason")
        signer = self._identity_or_pending_signer()
        try:
            return await self._api.request_signed(
                "POST", f"/api/v1/vault/devices/{device_id}/reject", device=signer,
                timeout=self._timeout, json={"reason": reason},
            )
        finally:
            self._discard_pending()

    async def list_devices(self) -> list[dict[str, Any]]:
        response = await self._api.request_signed(
            "GET", "/api/v1/vault/devices", device=self._required_identity().device,
            timeout=self._timeout,
        )
        devices = response.get("devices")
        if not isinstance(devices, list):
            raise IdentityProtocolError("Device list response is malformed")
        return [device for device in devices if isinstance(device, dict)]

    async def revoke_device(self, device_id: str, *, reason: str) -> dict[str, Any]:
        if reason not in {"retired", "lost", "compromised"}:
            raise ValueError("invalid device revocation reason")
        return await self._api.request_signed(
            "DELETE", f"/api/v1/vault/devices/{device_id}", device=self._required_identity().device,
            timeout=self._timeout, json={"reason": reason},
        )

    async def fetch_recovery_wrap(self) -> dict[str, Any]:
        return await self._api.request_signed(
            "GET", "/api/v1/vault/identity/me/recovery-wrap", device=self._identity_or_pending_signer(),
            timeout=self._timeout,
        )

    async def replace_recovery_wrap(self, *, recovery_key: str) -> dict[str, Any]:
        identity = self._required_identity()
        key = parse_recovery_key(recovery_key)
        blob = seal_wrap(recovery_kek(key, identity.identity_id), self._bundle(identity), wrap_aad(
            "recovery", identity.identity_id, identity.user_id, identity.fingerprint_raw,
        ))
        return await self._api.request_signed(
            "PUT", "/api/v1/vault/identity/me/recovery-wrap", device=identity.device,
            timeout=self._timeout, json={"blob": _b64(blob)},
        )

    async def confirm_identity(self) -> dict[str, Any]:
        """Ask the server to re-evaluate a now-fresh bearer MFA confirmation."""
        return await self._api.request_signed(
            "POST", "/api/v1/vault/identity/me/confirmation", device=self._required_identity().device,
            timeout=self._timeout, json={},
        )

    async def cancel_reset(self) -> dict[str, Any]:
        return await self._api.request_signed(
            "POST", "/api/v1/vault/identity/reset/cancel", device=self._required_identity().device,
            timeout=self._timeout, json={},
        )

    async def activate_with_recovery(
        self, *, recovery_key: str, recovery_wrap: dict[str, Any], identity: dict[str, Any]
    ) -> dict[str, Any]:
        """Recover a bundle on a pending device after locally verifying all keys."""
        pending = self._required_pending()
        checked = _verified_server_identity(identity)
        from .crypto import open_wrap, decode_bundle
        try:
            blob = _decode_b64(str(recovery_wrap["blob"]))
            key = parse_recovery_key(recovery_key)
        except (KeyError, ValueError) as exc:
            raise IdentityProtocolError("Recovery bundle could not be verified") from exc
        try:
            plain = open_wrap(
                recovery_kek(key, checked[0]), blob, wrap_aad("recovery", checked[0], checked[1], checked[4]),
            )
        except IntegrityError as exc:
            # The bundle is intact; this key is simply not the one that sealed it.
            raise RecoveryKeyMismatchError("Recovery key does not open this identity's recovery bundle") from exc
        except ValueError as exc:
            raise IdentityProtocolError("Recovery bundle could not be verified") from exc
        try:
            seeds = decode_bundle(plain)
        except ValueError as exc:
            raise IdentityProtocolError("Recovery bundle could not be verified") from exc
        recovered = LocalIdentity(
            identity_id=checked[0], user_id=checked[1], signing_seed=seeds[0], encryption_secret_key=seeds[1],
            device=pending.device,
        )
        if recovered.fingerprint_raw != checked[4]:
            raise IdentityProtocolError("Recovered bundle does not match the server identity")
        endorsement = sign(recovered.signing_seed, endorsement_message(
            recovered.identity_id, recovered.user_id, pending.device.device_id,
            pending.device.signing_public_key, pending.device.encryption_public_key,
        ))
        result = await self._api.request_signed(
            "POST", "/api/v1/vault/devices/me/activate", device=pending.device,
            timeout=self._timeout, json={"endorsement_signature": _b64(endorsement), "method": "recovery_key"},
        )
        self._store.save(recovered)
        self._hand_pending_to_identity()
        return result

    def finish_pending_approval(
        self, *, approval: dict[str, Any], identity: dict[str, Any]
    ) -> LocalIdentity:
        """Verify an approved bundle before it ever becomes local vault state."""
        pending = self._required_pending()
        if approval.get("state") != "approved":
            raise IdentityProtocolError("Pending device approval is not complete")
        identity_id, user_id, sig_public, enc_public, fingerprint = _verified_server_identity(identity)
        try:
            sealed_bundle = _decode_b64(str(approval["sealed_bundle"]))
            endorsement = _decode_b64(str(approval["endorsement_signature"]))
            from .crypto import decode_bundle
            signing_seed, encryption_secret_key = decode_bundle(open_sealed(
                sealed_bundle, pending.device.encryption_public_key,
                bytes(pending.device.encryption_secret_key),
            ))
        except (KeyError, ValueError, IntegrityError) as exc:
            self._discard_pending()
            raise IdentityProtocolError("Approved device bundle is invalid") from exc
        recovered = LocalIdentity(
            identity_id=identity_id, user_id=user_id, signing_seed=signing_seed,
            encryption_secret_key=encryption_secret_key, device=pending.device,
        )
        if (
            recovered.fingerprint_raw != fingerprint
            or recovered.signing_public_key != sig_public
            or recovered.encryption_public_key != enc_public
            or not verify(sig_public, endorsement_message(
                identity_id, user_id, pending.device.device_id,
                pending.device.signing_public_key, pending.device.encryption_public_key,
            ), endorsement)
        ):
            self._discard_pending()
            raise IdentityProtocolError("Approved bundle does not authenticate the server identity")
        self._store.save(recovered)
        self._hand_pending_to_identity()
        return recovered

    def _required_identity(self) -> LocalIdentity:
        if self._store.identity is None:
            raise NoLocalIdentityError("A local Team Vault identity is required")
        return self._store.identity

    def _required_pending(self) -> PendingDevice:
        if self._pending is None:
            raise IdentityProtocolError("No pending Team Vault device is available")
        return self._pending

    def _identity_or_pending_signer(self) -> LocalDevice:
        return self._store.identity.device if self._store.identity else self._required_pending().device

    def _discard_pending(self) -> None:
        if self._pending is not None:
            _destroy_pending(self._pending)
        self._pending = None
        self._revealed_to_approver_nonce = None
        self._pending_state = None

    async def withdraw_pending_device(self) -> None:
        """Cancel this computer's unapproved device at the service, then destroy its keys.

        The request is signed by the pending device itself, which the service
        accepts for its own registration. The keys are destroyed even when the
        service cannot be reached; the request then expires on its own. Only
        the registration current at the call is touched, so a newer one started
        meanwhile keeps its keys.
        """
        pending = self._pending
        if pending is None:
            return
        try:
            await self._api.request_signed(
                "POST", f"/api/v1/vault/devices/{pending.device.device_id}/reject", device=pending.device,
                timeout=self._timeout, json={"reason": "cancelled"},
            )
        finally:
            if self._pending is pending:
                self._discard_pending()
            else:
                _destroy_pending(pending)

    def _hand_pending_to_identity(self) -> None:
        """Forget the pending state once its device belongs to the saved identity.

        The device keys are now the identity's own (the same buffers), so
        they must stay intact; only the approval nonce is destroyed.
        """
        if self._pending is not None:
            secure_zero(self._pending.device_nonce)
        self._pending = None
        self._revealed_to_approver_nonce = None
        self._pending_state = None

    def discard_pending_device(self) -> None:
        """Destroy an unapproved device after cancellation or a terminal error."""
        self._discard_pending()

    def _observe_pending_state(self, approval: dict[str, Any]) -> None:
        state = approval.get("state")
        if state in {"rejected", "expired"}:
            self._discard_pending()
            raise IdentityProtocolError(f"Pending device registration is {state}")
        allowed = {
            None: {"pending", "challenged"},
            "pending": {"pending", "challenged"},
            "challenged": {"challenged", "revealed"},
            "revealed": {"revealed", "approved"},
        }
        if not isinstance(state, str) or state not in allowed.get(self._pending_state, set()):
            self._discard_pending()
            raise IdentityProtocolError("Pending approval entered an invalid or backward state")
        self._pending_state = state

    @staticmethod
    def _identity_enrollment_body(
        identity: LocalIdentity,
        signature: bytes,
        registration_signature: bytes,
        endorsement_signature: bytes,
        recovery_blob: bytes,
        device_name: str,
        platform: str,
        client: str,
    ) -> dict[str, Any]:
        return {
            "identity": {
                "identity_id": identity.identity_id,
                "sig_public_key": _b64(identity.signing_public_key),
                "enc_public_key": _b64(identity.encryption_public_key),
                "self_signature": _b64(signature), "alg": "svn-v1",
            },
            "device": {
                "device_id": identity.device.device_id, "name": _device_name(device_name),
                "platform": _platform_value(platform), "client": _client_value(client),
                "device_sig_public_key": _b64(identity.device.signing_public_key),
                "device_enc_public_key": _b64(identity.device.encryption_public_key),
                "registration_signature": _b64(registration_signature),
                "endorsement_signature": _b64(endorsement_signature),
            },
            "recovery_wrap": {"blob": _b64(recovery_blob)},
        }

    @staticmethod
    def _bundle(identity: LocalIdentity) -> bytes:
        from .crypto import encode_bundle
        return encode_bundle(bytes(identity.signing_seed), bytes(identity.encryption_secret_key))


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_b64(value: str) -> bytes:
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("invalid base64") from exc
    if _b64(raw) != value:
        raise ValueError("non-canonical base64")
    return raw


def _platform() -> str:
    import sys
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("win"):
        return "windows"
    return "other"


def _platform_value(value: str) -> str:
    if value not in {"linux", "macos", "windows", "other"}:
        raise ValueError("invalid device platform")
    return value


def _client_value(value: str) -> str:
    if value not in {"cli", "tui", "desktop"}:
        raise ValueError("invalid device client")
    return value


def _device_name(value: str) -> str:
    cleaned = value.strip()
    if not 1 <= len(cleaned) <= 64 or any(ord(character) < 32 for character in cleaned):
        raise ValueError("device name must contain 1 to 64 printable characters")
    return cleaned


def _verified_server_identity(identity: dict[str, Any]) -> tuple[str, int, bytes, bytes, bytes]:
    try:
        identity_id = str(identity["identity_id"])
        user_id = identity["user_id"]
        sig_public = _decode_b64(str(identity["sig_public_key"]))
        enc_public = _decode_b64(str(identity["enc_public_key"]))
        fingerprint = bytes.fromhex(str(identity["fingerprint"]))
        self_sig = _decode_b64(str(identity["self_signature"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise IdentityProtocolError("Server identity has invalid public fields") from exc
    if type(user_id) is not int or user_id < 1:
        raise IdentityProtocolError("Server identity user_id must be a positive integer")
    if not verify_identity(identity_id, user_id, sig_public, enc_public, fingerprint, self_sig):
        raise IdentityProtocolError("Server identity self-signature is invalid")
    return identity_id, user_id, sig_public, enc_public, fingerprint
