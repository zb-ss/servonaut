"""Composition facade for native-vault CLI, TUI, and SSH consumers.

This module is deliberately the only place that joins local custody, signed
transport, verified vault records and process-private SSH agents.  It exposes
no private key bytes outside the short-lived decryption operation.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as datetime_module
import logging
import os
import platform as platform_module
import secrets
import stat
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Sequence

from servonaut.config.manager import ConfigManager
from servonaut.services.api_client import APIClient
from servonaut.services.api_client import APIError
from servonaut.services.auth_service import AuthService
from servonaut.services.team_service import TeamService
from servonaut.utils.validation import ValidationError, validate_instance_id, validate_provider

from . import crypto
from .bindings import VaultBindingService
from .ca_client import CertificateAuthorityClient
from .ca_enrollment import CaEnrollmentExecutor, EnrollmentResult, deliver_krl, enrollment_error_code
from .errors import NO_LOCAL_IDENTITY, VaultUserError, vault_failure_reason
from .grant_processor import GrantProcessor
from .identity_client import IdentityClient
from .identity_store import IdentityStore
from .items import VaultItemService
from .local_state import VaultLocalState
from .known_hosts import TeamKnownHosts
from servonaut.services.ssh_host_keys import trusted_host_keys
from .roster_pins import RosterPins
from .rotation import RotationService
from .provider import ServonautVaultProvider
from .ssh_agent import PrivateSshAgent
from .team_vault_client import (
    TeamVaultClient,
    VaultStateError,
    _positive_int,
    _uuid,
    current_identity,
    identity_encryption_public,
    identity_signing_seed,
)


logger = logging.getLogger(__name__)


def _normalized_cidrs(values: Sequence[str]) -> list[str]:
    """Validate break-glass source networks; at least one is required."""
    import ipaddress

    networks: list[str] = []
    for value in values:
        try:
            network = str(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError as exc:
            raise VaultUserError(f"break-glass source network is not a valid CIDR: {str(value)[:64]!r}") from exc
        if network not in networks:
            networks.append(network)
    if not networks:
        raise VaultUserError("a break-glass key needs at least one --from-cidr source network")
    return networks


def _enrollment_error_code(error: BaseException) -> str:
    """A short snake_case reason for a failed enrollment report; never server text."""
    return enrollment_error_code(error)


@dataclass
class VaultSshLease:
    """Connection-only metadata for an agent-held native credential."""

    source: str
    identity_agent: str
    certificate_path: str | None
    known_hosts_path: str
    login_user: str
    host_keys: tuple[str, ...]
    public_key: str
    identity_file: str
    vault_id: str | None
    vault_item_id: str | None
    binding: dict[str, Any] | None
    _agent: PrivateSshAgent
    # The destination the pinned known_hosts entry names; connect exactly there.
    target_host: str | None = None
    target_port: int | None = None

    def close(self) -> None:
        try:
            self._agent.close()
        finally:
            try:
                Path(self.identity_file).unlink(missing_ok=True)
            except OSError:
                pass
        # Both files are generated uniquely for this lease.  Removing them
        # after closing the agent prevents later connections from inheriting
        # a stale certificate or host-trust snapshot.
        for value in (self.certificate_path, self.known_hosts_path):
            if value:
                Path(value).unlink(missing_ok=True)


@dataclass
class PendingIdentityReset:
    """Unstored replacement retained until the e-mail confirmation is verified."""

    replacement: Any
    expires_at: str


class VaultCommandService:
    """Concrete facade used by ``servonaut vault`` and ``servonaut ca``."""

    def __init__(
        self,
        api: Any,
        auth: Any,
        config: Any,
        store: IdentityStore | None = None,
        *,
        team_service: TeamService | None = None,
        remote_executor_factory: Callable[[Mapping[str, Any], VaultSshLease | None], Any] | None = None,
        native_provider: Any | None = None,
        secret_references: Mapping[str, Mapping[str, str]] | None = None,
        ssh_service: Any | None = None,
        connection_service: Any | None = None,
        ssh_ref_resolver: Any | None = None,
    ) -> None:
        self.api = api
        self.auth = auth
        self.config = config
        settings = config.vault
        self.store = store or IdentityStore(allow_file_key_store=settings.allow_file_key_store)
        self.identity = IdentityClient(api, self.store, timeout=settings.request_timeout_seconds)
        self.state = VaultLocalState()
        self.pins = RosterPins(self._load_pins, self._save_pins)
        self.vaults = TeamVaultClient(api, self.store, self.pins, self.state)
        self.items = VaultItemService(api, self.vaults)
        self.grants = GrantProcessor(self.vaults, strict_verification=settings.strict_verification)
        self.rotation = RotationService(self.vaults, self.items, strict_verification=settings.strict_verification)
        self.bindings = VaultBindingService(api, self.vaults)
        self.teams = team_service or TeamService(api)
        self.remote_executor_factory = remote_executor_factory
        self._secret_references: dict[str, dict[str, str]] = {}
        for name, reference in (secret_references or {}).items():
            self.cache_secret_reference(name, reference)
        self.native_provider = native_provider or ServonautVaultProvider(
            self.vaults, self.items, self._secret_reference,
        )
        self.ssh_service = ssh_service
        self.connection_service = connection_service
        self.ssh_ref_resolver = ssh_ref_resolver
        self._leases: list[VaultSshLease] = []
        self._pending_identity_reset: PendingIdentityReset | None = None
        self._device_pending_events: list[dict[str, Any]] = []
        self._device_pending_callback: Callable[[Mapping[str, Any]], Any] | None = None

    @classmethod
    def from_local_session(cls) -> "VaultCommandService":
        """Build the default facade after local auth/config have loaded safely."""
        manager = ConfigManager()
        config = manager.load()
        auth = AuthService()
        if not auth.is_authenticated:
            raise VaultUserError("Sign in with servonaut login before using the vault")
        api = APIClient(auth)
        from servonaut.services.bw_ssh_config_service import BwSshConfigService
        from servonaut.services.connection_service import ConnectionService
        from servonaut.services.ssh_ref_resolver import SshRefResolver
        from servonaut.services.ssh_service import SSHService

        ssh_service = SSHService(manager)
        connection_service = ConnectionService(manager)
        service = cls(api, auth, config, ssh_service=ssh_service, connection_service=connection_service)
        service.ssh_ref_resolver = SshRefResolver(
            BwSshConfigService(api), service.teams, ssh_service, vault_runtime=service,
        )
        from .background import unlock_vault_for_startup
        unlock_vault_for_startup(service)
        return service

    @property
    def store_path(self) -> Path:
        return Path(getattr(self.store, "_path", Path.home() / ".servonaut" / "vault" / "vault_keys.json"))

    def unlock_existing_identity(self) -> bool:
        """Unlock persisted custody only after the caller opts into vault use.

        ``False`` means this device has no local Vault identity, so callers
        can still offer setup.  A present but invalid or account-mismatched
        store is a hard failure and must never be treated as a new device.
        """
        local = self.store.identity
        if local is None:
            if not self.store.has_persisted_identity():
                return False
            local = self.store.load()
        account_id = self.auth.user_id
        if isinstance(account_id, bool) or not isinstance(account_id, int) or account_id < 1:
            self.store.lock()
            raise VaultStateError("authenticated account id is unavailable for local vault custody")
        if local.user_id != account_id:
            self.store.lock()
            raise VaultStateError("local vault identity belongs to a different account")
        return True

    def _load_pins(self) -> Mapping[str, str]:
        return self.state.load().get("identity_pins", {})

    def _save_pins(self, pins: dict[str, str]) -> None:
        state = self.state.load()
        state["identity_pins"] = dict(pins)
        self.state.save(state)

    async def _user_id(self) -> int:
        value = self.auth.user_id
        if value is None:
            value = await self.auth.fetch_user_id()
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise VaultUserError("authenticated account id is unavailable")
        return value

    async def status(self) -> dict[str, Any]:
        remote = await self.identity.status()
        fingerprint = self.store.identity.fingerprint if self.store.identity else None
        return {"fingerprint": fingerprint, "remote": remote, "local_identity": fingerprint}

    @property
    def poll_interval_seconds(self) -> int:
        value = self.config.vault.poll_after_seconds
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise VaultStateError("vault poll interval must be a positive integer")
        return value

    @property
    def agent_key_ttl_seconds(self) -> int:
        value = self.config.vault.agent_key_ttl_seconds
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise VaultStateError("vault agent key TTL must be a positive integer")
        return value

    def approval_poll_delay(self, attempt: int) -> float:
        """Return the configured 2→10-style exponential backoff for device UI."""
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 0:
            raise ValueError("approval poll attempt must be a non-negative integer")
        initial = self.config.vault.approval_poll_initial_seconds
        maximum = self.config.vault.approval_poll_max_seconds
        if (
            isinstance(initial, bool) or not isinstance(initial, (int, float)) or initial <= 0
            or isinstance(maximum, bool) or not isinstance(maximum, (int, float)) or maximum < initial
        ):
            raise VaultStateError("vault approval polling configuration is invalid")
        return min(float(initial) * (2 ** attempt), float(maximum))

    def set_device_pending_callback(
        self, callback: Callable[[Mapping[str, Any]], Any] | None,
    ) -> None:
        """Install a UI notification hook fed only by a REST-reread device."""
        self._device_pending_callback = callback

    def drain_device_pending_events(self) -> list[dict[str, Any]]:
        """Return verified pending-device notifications accumulated from event hints."""
        events, self._device_pending_events = self._device_pending_events, []
        return [dict(event) for event in events]

    def _queue_device_pending_event(self, device: Mapping[str, Any]) -> None:
        device_id = device.get("device_id")
        if not isinstance(device_id, str):
            return
        if any(row.get("device_id") == device_id for row in self._device_pending_events):
            return
        self._device_pending_events.append(dict(device))

    async def discover(self) -> bool:
        """Feature-detect vault support without masking authentication failures."""
        try:
            response = await self.identity.status()
        except APIError as exc:
            if exc.status == 404 or (exc.status == 503 and exc.code == "feature_disabled"):
                return False
            raise
        settings = response.get("settings") if isinstance(response, Mapping) else None
        if isinstance(settings, Mapping):
            for field in ("poll_after_seconds", "agent_key_ttl_seconds"):
                value = settings.get(field)
                if value is None:
                    continue
                if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                    raise VaultStateError(f"vault {field} must be a positive integer")
                setattr(self.config.vault, field, value)
        return True

    async def handle_event(self, event: Mapping[str, Any]) -> None:
        """Treat relay events as hints and re-read verified REST state."""
        event_type = event.get("type")
        data = event.get("data")
        if not isinstance(event_type, str) or not isinstance(data, Mapping):
            raise ValueError("vault event has an invalid shape")
        if event_type == "ssh_ca.krl_updated":
            team = data.get("team_slug")
            if isinstance(team, str):
                hosts = await self.ca_hosts(team=team)
                drifted = [
                    row["server_id"] for row in hosts["hosts"]
                    if row.get("krl_drift") is True and row.get("status") == "enrolled"
                ]
                if drifted:
                    await self.ca_deliver_krl(team=team, servers=drifted)
            return
        if event_type == "vault.device_pending":
            device_id = data.get("device_id")
            if not isinstance(device_id, str):
                return
            devices = await self.identity.list_devices()
            device = next(
                (row for row in devices if row.get("device_id") == device_id and row.get("status") == "pending"),
                None,
            )
            if device is None:
                return
            verified = dict(device)
            if self._device_pending_callback is None:
                self._queue_device_pending_event(verified)
            else:
                try:
                    result = self._device_pending_callback(verified)
                    if hasattr(result, "__await__"):
                        await result
                except Exception:
                    self._queue_device_pending_event(verified)
                    raise
            return
        vault_id = data.get("vault_id")
        if not isinstance(vault_id, str):
            return
        vault = await self.vaults.get_vault(vault_id)
        if event_type == "vault.recipient_pending" and self.config.vault.auto_grant is True:
            await self.process_grants(vault_id=vault_id, interactive=False)
        # Rotation/exposure/enrolment events intentionally only refresh verified
        # state.  They never initiate SSH mutations or consume user consent.
        elif event_type == "vault.rotation_required":
            await self.process_grants(vault_id=vault_id, interactive=False)
        elif event_type in {"vault.rotated", "vault.grant_received", "vault.exposure_opened"}:
            _ = vault

    async def setup(
        self, *, device_name: str | None, platform: str | None,
        recovery_confirmation: Callable[[str], bool | Awaitable[bool]],
    ) -> dict[str, Any]:
        if self.store.identity is not None:
            raise VaultUserError("a vault identity is already unlocked")
        # A new facade starts locked. Never replace that ciphertext based on a
        # remote preflight: another device can create the remote identity
        # between requests, while this file remains the user's only custody.
        if self.store.has_persisted_identity():
            self.store.load()
            raise VaultUserError("a local vault identity already exists; unlock or recover it first")
        remote = await self.identity.status()
        if isinstance(remote, Mapping) and isinstance(remote.get("identity"), Mapping):
            raise VaultUserError("a vault identity already exists; add this device instead")
        user_id = await self._user_id()
        local = self.store.create(identity_id=str(uuid.uuid4()), user_id=user_id)
        recovery = crypto.format_recovery_key(secrets.token_bytes(32))
        if not await self._confirmed(recovery_confirmation, recovery):
            self.store.wipe()
            raise VaultUserError("recovery key was not confirmed")
        # Persist before the remote mutation so a successful enrolment cannot
        # leave the only device without durable encrypted custody.
        self.store.save(local)
        try:
            return await self.identity.enroll(
                recovery_key=recovery, device_name=device_name or platform_module.node() or "Servonaut",
                platform=platform or platform_module.system().lower(), client="cli",
            )
        except APIError as exc:
            if exc.code != "identity_exists":
                raise
            # The status preflight can race another first-device enrolment.
            # This store contains only the local identity generated above, so
            # discard it rather than obstructing the real identity's device-add flow.
            self.store.wipe()
            raise VaultUserError(
                "a vault identity was created on another device; add this device instead"
            ) from exc

    async def confirm_identity(self) -> dict[str, Any]:
        return await self.identity.confirm_identity()

    async def list_devices(self) -> list[dict[str, Any]]:
        return await self.identity.list_devices()

    async def revoke_device(self, *, device_id: str, reason: str) -> dict[str, Any]:
        return await self.identity.revoke_device(device_id, reason=reason)

    async def recover(
        self, *, recovery_key: str, device_name: str | None, platform: str | None,
    ) -> dict[str, Any]:
        """Restore an identity bundle into a freshly registered local device."""
        user_id = await self._user_id()
        self.identity.begin_pending_device()
        registered = await self.identity.register_pending_device(
            user_id=user_id,
            name=device_name or platform_module.node() or "Servonaut",
            platform=platform or platform_module.system().lower(),
            client="cli",
        )
        remote_identity = registered.get("identity")
        if not isinstance(remote_identity, dict):
            raise VaultStateError("pending-device registration did not return an identity")
        recovery_wrap = await self.identity.fetch_recovery_wrap()
        result = await self.identity.activate_with_recovery(
            recovery_key=recovery_key,
            recovery_wrap=recovery_wrap,
            identity=remote_identity,
        )
        return {"device": result.get("device", result), "fingerprint": self.store.identity.fingerprint if self.store.identity else None}

    async def add_device(
        self, *, device_name: str | None, platform: str | None,
    ) -> dict[str, Any]:
        """Register a fresh device and return its server-bounded approval state.

        The caller retains only the returned public identity and deadline. The
        new device keys stay in this process until approval succeeds or a
        terminal response destroys them.
        """
        user_id = await self._user_id()
        pending = self.identity.begin_pending_device()
        try:
            registered = await self.identity.register_pending_device(
                user_id=user_id,
                name=device_name or platform_module.node() or "Servonaut",
                platform=platform or platform_module.system().lower(),
                client="cli",
            )
            identity = registered.get("identity") if isinstance(registered, Mapping) else None
            approval = registered.get("approval") if isinstance(registered, Mapping) else None
            if not isinstance(identity, dict) or not isinstance(approval, Mapping):
                raise VaultStateError("pending-device registration response is malformed")
            expires_at = approval.get("expires_at")
            self._approval_deadline(expires_at)
            return {
                "device_id": pending.device.device_id,
                "expires_at": expires_at,
                "identity": identity,
                "state": approval.get("state"),
            }
        except Exception:
            self.identity.discard_pending_device()
            raise

    async def poll_pending_device(
        self, *, identity: Mapping[str, Any], expires_at: str,
    ) -> dict[str, Any]:
        """Read one bounded new-device approval state and reveal its SAS once."""
        self._approval_deadline(expires_at)
        try:
            approval = await self.identity.pending_approval_status()
            state = approval.get("state")
            if state == "challenged":
                safety_number = self.identity.pending_sas(approval, identity=dict(identity))
                revealed = await self.identity.reveal_pending_nonce(approval)
                return {"state": revealed.get("state", "revealed"), "safety_number": safety_number}
            if state in {"pending", "revealed"}:
                return {"state": state}
            if state == "approved":
                return {"state": state, "approval": approval}
            self.identity.discard_pending_device()
            raise VaultStateError("pending device approval ended unexpectedly")
        except Exception:
            self.identity.discard_pending_device()
            raise

    def finish_pending_device(
        self, *, approval: Mapping[str, Any], identity: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Verify and persist the approved bundle returned by polling."""
        local = self.identity.finish_pending_approval(approval=dict(approval), identity=dict(identity))
        return {"device_id": local.device.device_id, "fingerprint": local.fingerprint}

    async def approve_device(
        self, *, device_id: str, confirmation: Callable[[str], bool | Awaitable[bool]],
    ) -> dict[str, Any]:
        """Pin a pending device before the one terminal SAS comparison.

        The approver nonce stays local: the server never echoes it back to the
        approving device, so the SAS is computed from the value this call sent.
        """
        pin = await self.identity.pin_approval(device_id)
        approver_nonce = secrets.token_bytes(32)
        await self.identity.challenge_approval(pin, approver_nonce=approver_nonce)
        approval = await self._approval_after_reveal(device_id)
        try:
            safety_number = self._approval_safety_number(pin, approval, approver_nonce)
        except Exception:
            await self.identity.reject_device(device_id, reason="sas_mismatch")
            raise
        if not await self._confirmed(confirmation, safety_number):
            await self.identity.reject_device(device_id, reason="sas_mismatch")
            raise VaultUserError("device safety number was not confirmed; registration was rejected")
        return await self.identity.approve_pinned_device(
            pin, approval, approver_nonce=approver_nonce, confirmed_sas=safety_number,
        )

    async def rotate_recovery_key(
        self, *, recovery_confirmation: Callable[[str], bool | Awaitable[bool]] | None = None,
    ) -> dict[str, Any]:
        recovery_key = crypto.format_recovery_key(secrets.token_bytes(32))
        if recovery_confirmation is not None and not await self._confirmed(recovery_confirmation, recovery_key):
            raise VaultUserError("recovery key was not confirmed")
        result = await self.identity.replace_recovery_wrap(recovery_key=recovery_key)
        return {"recovery_key": recovery_key, "recovery_wrap": result}

    async def reset_identity(
        self, *, reason: str, recovery_confirmation: Callable[[str], bool | Awaitable[bool]] | None = None,
    ) -> dict[str, Any]:
        """Create a replacement only after its recovery key has been recorded."""
        user_id = await self._user_id()
        replacement = self.store.generate_identity(identity_id=str(uuid.uuid4()), user_id=user_id)
        try:
            recovery_key = crypto.format_recovery_key(secrets.token_bytes(32))
            if recovery_confirmation is not None and not await self._confirmed(recovery_confirmation, recovery_key):
                raise VaultUserError("recovery key was not confirmed")
            result = await self.identity.request_reset(
                replacement=replacement,
                recovery_key=recovery_key,
                reason=reason,
                device_name=platform_module.node() or "Servonaut",
                platform=platform_module.system().lower(),
                client="cli",
            )
            expires_at = result.get("expires_at") if isinstance(result, Mapping) else None
            self._reset_deadline(expires_at)
            self._pending_identity_reset = PendingIdentityReset(replacement, expires_at)
            return {
                "reset": result, "replacement_fingerprint": replacement.fingerprint,
                "recovery_key": recovery_key, "expires_at": expires_at,
            }
        except Exception:
            self.identity.discard_reset_replacement(replacement)
            raise

    async def poll_reset_identity(self) -> dict[str, Any]:
        """Reread reset state and install replacement custody only on confirmation."""
        pending = self._pending_identity_reset
        if pending is None:
            raise VaultStateError("no local identity reset is awaiting confirmation")
        try:
            self._reset_deadline(pending.expires_at)
            status = await self.identity.status()
            remote_pending = status.get("pending_reset") if isinstance(status, Mapping) else None
            if isinstance(remote_pending, Mapping):
                expires_at = remote_pending.get("expires_at", pending.expires_at)
                self._reset_deadline(expires_at)
                return {"state": "pending_reset", "expires_at": expires_at}
            local = self.identity.finish_confirmed_reset(replacement=pending.replacement, status=status)
            self._pending_identity_reset = None
            return {"state": "confirmed", "fingerprint": local.fingerprint, "device_id": local.device.device_id}
        except Exception:
            # A failed/expired/cancelled reset must never replace the current custody.
            self.identity.discard_reset_replacement(pending.replacement)
            self._pending_identity_reset = None
            raise

    async def create_vault(self, *, team: str | None, name: str | None, grant_policy: str) -> dict[str, Any]:
        if team is None:
            return await self.vaults.create_personal(name or "Personal")
        team_id = await self._team_id(team)
        return await self.vaults.create_team(team, team_id, name or "Team vault", grant_policy=grant_policy)

    async def list_vaults(self) -> list[dict[str, Any]]:
        return await self.vaults.list_vaults()

    async def get_vault(self, *, vault_id: str) -> dict[str, Any]:
        return await self.vaults.get_vault(vault_id)

    async def list_items(self, *, vault_id: str, include_deleted: bool = False) -> dict[str, Any]:
        cursor: str | None = None
        seen: set[str] = set()
        data: list[dict[str, Any]] = []
        while True:
            page = await self.items.list_items(
                vault_id, cursor=cursor, include_deleted=include_deleted,
            )
            rows = page.get("data", [])
            if not isinstance(rows, list):
                raise VaultStateError("vault item list has an invalid response shape")
            data.extend(dict(row) for row in rows if isinstance(row, Mapping))
            meta = page.get("meta", {})
            next_cursor = meta.get("next_cursor") if isinstance(meta, Mapping) else None
            if next_cursor is None:
                return {"data": data, "meta": {"next_cursor": None}}
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen:
                raise VaultStateError("vault item list cursor is invalid")
            seen.add(next_cursor)
            cursor = next_cursor

    async def show_item(self, *, vault_id: str, item_id: str, reveal: bool) -> dict[str, Any]:
        item = await self.items.get_item(vault_id, item_id)
        if not reveal:
            return {key: value for key, value in item.items() if key not in {"ciphertext", "nonce", "content_signature", "wrapped_item_key", "wrap_signature"}}
        vault = await self.vaults.get_vault(vault_id)
        plaintext = self.items.read_item(vault, item)
        if item.get("type") == "secret":
            self._cache_verified_secret_item(vault_id, item_id, plaintext)
        return {"metadata": item, "plaintext": plaintext}

    async def process_grants(
        self, *, vault_id: str | None = None, interactive: bool = False,
        approval: Callable[[Mapping[str, Any], str, bool], Any] | None = None,
    ) -> list[dict[str, Any]]:
        if self.store.identity is None:
            return []
        vaults = [await self.vaults.get_vault(vault_id)] if vault_id else [
            await self.vaults.get_vault(row["vault_id"])
            for row in await self.vaults.list_vaults()
            if isinstance(row.get("vault_id"), str)
        ]
        async def no_prompt(_entry: Mapping[str, Any], _sas: str, _changed: bool) -> bool:
            return False
        administrators = [
            vault for vault in vaults
            if vault.get("my_role") in {"owner", "admin"}
        ]
        for vault in administrators:
            rotation = vault.get("rotation", {})
            if isinstance(rotation, Mapping) and rotation.get("required") is True:
                await self.rotation.rotate(str(vault["vault_id"]))
        if self.config.vault.auto_grant is not True:
            return []
        eligible = [vault for vault in administrators if vault.get("permissions", {}).get("grant") is True]
        selected = approval if approval is not None else (no_prompt if interactive else None)
        return [await self.grants.process_auto_grants(vault, approval=selected) for vault in eligible]

    async def rotate(self, *, vault_id: str) -> dict[str, Any]:
        return await self.rotation.rotate(vault_id)

    async def rotate_ssh_key(
        self, *, vault_id: str, item_id: str, team: str, servers: Sequence[str],
    ) -> dict[str, Any]:
        """Rotate one bound SSH item across hosts without resolving exposure state.

        Every target first receives and proves the new key while its old key
        remains usable. The encrypted item and every signed binding are
        persisted before any exact old key line is removed. Any failure keeps
        at least one working key on every prepared host and deliberately
        leaves the server-side exposure open for a user to review.
        """
        _uuid(vault_id, "vault_id")
        _uuid(item_id, "item_id")
        if not servers or any(not isinstance(server, str) or not server for server in servers):
            raise ValueError("at least one canonical shared server is required")
        vault = await self.vaults.get_vault(vault_id)
        item = await self.items.get_item(vault_id, item_id)
        if item.get("type") not in {"ssh_key", "break_glass"}:
            raise VaultStateError("only an SSH vault item can be rotated on hosts")
        payload = self.items.read_item(vault, item)
        old_public_key = payload.get("public_key")
        if not isinstance(old_public_key, str):
            raise VaultStateError("SSH vault item has no public key")
        old_fingerprint = crypto.ssh_public_fingerprint(old_public_key)
        if payload.get("public_fingerprint") != old_fingerprint:
            raise VaultStateError("SSH vault item public fingerprint is invalid")
        new_private = bytearray(self._new_ed25519_private_key())
        try:
            new_public_key = self._public_key_from_private(bytes(new_private), None)
            new_fingerprint = crypto.ssh_public_fingerprint(new_public_key)
            targets = await self._rotation_targets(
                team, servers, vault, vault_id, item_id, old_fingerprint,
            )
            outcomes: list[dict[str, Any]] = []
            prepared: list[tuple[Mapping[str, Any], Mapping[str, Any], Any, VaultSshLease]] = []
            try:
                for shared, binding in targets:
                    server_id = str(shared["id"])
                    lease = executor = None
                    appended = False
                    login = str(binding["login_user"])
                    try:
                        lease = await self.resolve_ssh({**shared, "is_shared": True, "team_slug": team})
                        if lease is None:
                            raise VaultStateError("bound server has no verified SSH route")
                        executor = self._remote_executor(shared, lease)
                        await executor.append_authorized_key(login, new_public_key)
                        appended = True
                        if await executor.verify_new_key(login, bytes(new_private)) is not True:
                            raise VaultStateError("new SSH key login proof failed")
                        prepared.append((shared, binding, executor, lease))
                        outcomes.append({"server_id": server_id, "status": "verified"})
                    except Exception as exc:
                        outcomes.append({"server_id": server_id, "status": "failed", "error": str(exc)})
                        # This host is not in ``prepared``: undo its half-done step here.
                        if appended and executor is not None:
                            try:
                                await executor.remove_authorized_key(login, new_public_key)
                            except Exception:
                                pass
                        if lease is not None:
                            lease.close()
                        raise
            except Exception as exc:
                for _shared, binding, executor, lease in reversed(prepared):
                    try:
                        await executor.remove_authorized_key(str(binding["login_user"]), new_public_key)
                    except Exception:
                        pass
                    lease.close()
                return {"rotated": False, "public_fingerprint": new_fingerprint,
                        "hosts": outcomes, "error": str(exc)}
            try:
                new_payload = dict(payload)
                new_payload.update({
                    "private_key_openssh": bytes(new_private).decode("utf-8"),
                    "public_key": new_public_key,
                    "public_fingerprint": new_fingerprint,
                })
                written = await self.items.write_item(
                    vault_id, item_id, str(item["type"]), new_payload,
                    expected_revision=_positive_int(item.get("revision"), "item.revision"),
                    retry_stale_once=False,
                )
                bindings: list[dict[str, Any]] = []
                for shared, binding, _executor, _lease in prepared:
                    hostname = shared.get("hostname") or shared.get("host") or shared.get("public_ip")
                    port = shared.get("port", 22)
                    if not isinstance(hostname, str) or not hostname or isinstance(port, bool) or not isinstance(port, int):
                        raise VaultStateError("bound server has no valid SSH destination")
                    replacement = self.bindings.build_binding(
                        scope=str(vault["scope"]), target=f"shared_server:{shared['id']}",
                        hostname=hostname, port=port, login_user=str(binding["login_user"]),
                        vault_id=vault_id, vault_item_id=item_id, public_fingerprint=new_fingerprint,
                        host_keys=tuple(binding["host_keys"]),
                        binding_revision=_positive_int(binding.get("binding_revision"), "binding.binding_revision") + 1,
                    )
                    bindings.append(await self.bindings.put_team_binding(team, str(shared["id"]), replacement))
                    for outcome in outcomes:
                        if outcome["server_id"] == str(shared["id"]):
                            outcome["status"] = "rebound"
                            break
                # Removing the old keys is the irreversible final phase. At
                # this point both credentials are persisted and every host is
                # already proven with the new one, so a partial remote failure
                # leaves the new credential usable and the exposure open.
                for shared, binding, executor, _lease in prepared:
                    try:
                        await executor.remove_authorized_key(str(binding["login_user"]), old_public_key)
                    except Exception as exc:
                        for outcome in outcomes:
                            if outcome["server_id"] == str(shared["id"]):
                                outcome.update({"status": "failed", "error": str(exc)})
                                break
                        raise
                    for outcome in outcomes:
                        if outcome["server_id"] == str(shared["id"]):
                            outcome["status"] = "old_key_removed"
                            break
                return {"rotated": True, "public_fingerprint": new_fingerprint,
                        "hosts": outcomes, "item": written, "bindings": bindings}
            except Exception as exc:
                return {"rotated": False, "public_fingerprint": new_fingerprint,
                        "hosts": outcomes, "error": str(exc)}
            finally:
                for _shared, _binding, _executor, lease in prepared:
                    lease.close()
        finally:
            for index in range(len(new_private)):
                new_private[index] = 0

    async def _rotation_targets(
        self, team: str, servers: Sequence[str], vault: Mapping[str, Any], vault_id: str,
        item_id: str, old_fingerprint: str,
    ) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
        targets: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
        seen: set[str] = set()
        for selector in servers:
            shared = await self._shared_server(team, selector)
            server_id = str(shared.get("id", ""))
            if not server_id or server_id in seen:
                raise ValueError("SSH rotation targets must be distinct canonical servers")
            seen.add(server_id)
            hostname = shared.get("hostname") or shared.get("host") or shared.get("public_ip")
            port = shared.get("port", 22)
            binding = shared.get("credential_binding")
            if not isinstance(hostname, str) or not hostname or isinstance(port, bool) or not isinstance(port, int):
                raise VaultStateError("bound server has no valid SSH destination")
            if not isinstance(binding, Mapping):
                raise VaultStateError("SSH rotation target has no native vault binding")
            verified = self.bindings.verify_binding(
                binding, vault, target=f"shared_server:{server_id}", hostname=hostname, port=port,
            )
            if verified.get("vault_id") != vault_id or verified.get("vault_item_id") != item_id:
                raise VaultStateError("SSH rotation target is bound to a different vault item")
            if verified.get("public_fingerprint") != old_fingerprint:
                raise VaultStateError("SSH rotation target binding does not match the current key")
            targets.append((shared, verified))
        return targets

    @staticmethod
    def _new_ed25519_private_key() -> bytes:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

        return Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())

    async def list_exposures(self, *, vault_id: str) -> dict[str, Any]:
        cursor: str | None = None
        seen: set[str] = set()
        data: list[dict[str, Any]] = []
        while True:
            page = await self.rotation.list_exposures(vault_id, cursor=cursor)
            rows = page.get("data", [])
            if not isinstance(rows, list):
                raise VaultStateError("vault exposure list has an invalid response shape")
            data.extend(dict(row) for row in rows if isinstance(row, Mapping))
            meta = page.get("meta", {})
            next_cursor = meta.get("next_cursor") if isinstance(meta, Mapping) else None
            if next_cursor is None:
                return {"data": data, "meta": {"next_cursor": None}}
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen:
                raise VaultStateError("vault exposure list cursor is invalid")
            seen.add(next_cursor)
            cursor = next_cursor

    def cache_secret_reference(self, name: str, reference: Mapping[str, str]) -> None:
        """Cache an explicitly configured opaque native-secret reference.

        Names are never discovered by decrypting arbitrary vault items.  The
        cache keeps only identifiers, and consumers receive the secret value
        only through ``ServonautVaultProvider.get_secret``.
        """
        from servonaut.services.interfaces import _validate_secret_name

        validated_name = _validate_secret_name(name)
        vault_id = reference.get("vault_id")
        item_id = reference.get("item_id")
        if not isinstance(vault_id, str) or not isinstance(item_id, str):
            raise ValueError("native secret reference needs vault_id and item_id")
        _uuid(vault_id, "vault_id")
        _uuid(item_id, "item_id")
        self._secret_references[validated_name] = {"vault_id": vault_id, "item_id": item_id}

    async def _secret_reference(self, name: str) -> Mapping[str, str] | None:
        reference = self._secret_references.get(name)
        if reference is not None:
            return dict(reference)
        # A native secret name is encrypted.  Discover it only by reading
        # items for vaults where this identity has a usable verified grant;
        # retain just its opaque identifiers, never the plaintext value.
        for summary in await self.vaults.list_vaults():
            vault_id = summary.get("vault_id")
            if not isinstance(vault_id, str):
                continue
            vault = await self.vaults.get_vault(vault_id)
            if not isinstance(vault.get("my_grant"), Mapping):
                continue
            cursor: str | None = None
            seen: set[str] = set()
            while True:
                page = await self.items.list_items(vault_id, cursor=cursor)
                rows = page.get("data", [])
                if not isinstance(rows, list):
                    raise VaultStateError("vault item list has an invalid response shape")
                for row in rows:
                    if not isinstance(row, Mapping) or row.get("type") != "secret":
                        continue
                    item_id = row.get("item_id")
                    if not isinstance(item_id, str):
                        raise VaultStateError("secret item metadata has no canonical id")
                    item = await self.items.get_item(vault_id, item_id)
                    payload = self.items.read_item(vault, item)
                    if payload.get("name") == name:
                        self._cache_verified_secret_item(vault_id, item_id, payload)
                        return dict(self._secret_references[name])
                meta = page.get("meta", {})
                next_cursor = meta.get("next_cursor") if isinstance(meta, Mapping) else None
                if next_cursor is None:
                    break
                if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen:
                    raise VaultStateError("vault item list cursor is invalid")
                seen.add(next_cursor)
                cursor = next_cursor
        return None

    def _cache_verified_secret_item(self, vault_id: str, item_id: str, payload: Mapping[str, Any]) -> None:
        from servonaut.services.interfaces import _validate_secret_name

        name = payload.get("name")
        if not isinstance(name, str):
            return
        try:
            validated_name = _validate_secret_name(name)
        except (TypeError, ValueError):
            return
        self._secret_references[validated_name] = {"vault_id": vault_id, "item_id": item_id}

    async def resolve_exposure(self, *, vault_id: str, exposure_id: str, resolution: str, note: str | None = None) -> dict[str, Any]:
        return await self.rotation.resolve_exposure(vault_id, exposure_id, resolution=resolution, note=note or "")

    async def verify_member(self, *, member: str) -> dict[str, Any]:
        """Return one verified roster identity's safety number.

        The CLI supplies a member selector, while identity verification remains
        vault-scoped: every candidate comes from a complete, signed vault
        response before its fingerprint is shown.
        """
        matches: list[dict[str, Any]] = []
        for summary in await self.vaults.list_vaults():
            vault_id = summary.get("vault_id")
            if not isinstance(vault_id, str):
                continue
            vault = await self.vaults.get_vault(vault_id)
            for entry in vault.get("roster", []):
                if not isinstance(entry, Mapping) or not self._member_matches(entry, member):
                    continue
                identity = entry.get("identity")
                if not isinstance(identity, Mapping):
                    continue
                fingerprint = self.pins.verify_identity(identity)
                matches.append({
                    "vault_id": vault_id,
                    "user_id": entry.get("user_id"),
                    "display_name": entry.get("display_name"),
                    "identity_id": identity.get("identity_id"),
                    "fingerprint": fingerprint.hex(),
                    "safety_number": crypto.safety_number(fingerprint),
                    "grantable": identity.get("grantable") is True,
                })
        if not matches:
            raise ValueError("no verified vault member matches that selector")
        if len(matches) != 1:
            raise ValueError("member selector is ambiguous; use the numeric user id")
        return matches[0]

    async def import_keys(
        self,
        *,
        source: str,
        vault_id: str,
        path: str | None = None,
        private_key: str | bytes | None = None,
        passphrase: bytes | None = None,
        source_ref: str | None = None,
        break_glass_from_cidrs: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        """Validate SSH material locally then encrypt it as a fresh vault item.

        File selection and Bitwarden unlocking belong to callers.  Tests and
        other surfaces may provide key bytes directly, keeping this service
        free of terminal input and subprocess credential handling.

        With *break_glass_from_cidrs* the key becomes the team's ``break_glass``
        item: an emergency root key that CA enrollment appends to a host's
        ``authorized_keys``, usable only from those source networks.
        """
        if source not in {"ssh", "bitwarden"}:
            raise ValueError("unsupported SSH import source")
        break_glass = (
            None if break_glass_from_cidrs is None
            else {"logins": ["root"], "from_cidrs": _normalized_cidrs(break_glass_from_cidrs)}
        )
        if private_key is None:
            if source != "ssh" or not path:
                raise ValueError("the selected SSH key material must be supplied by the caller")
            private_key = Path(path).read_bytes()
        private_bytes = bytearray(private_key.encode("utf-8") if isinstance(private_key, str) else private_key)
        try:
            public_key = self._public_key_from_private(bytes(private_bytes), passphrase)
            fingerprint = crypto.ssh_public_fingerprint(public_key)
            item_id = str(uuid.uuid4())
            payload = {
                "name": Path(path).name if path else "Imported SSH key",
                "notes": "",
                "private_key_openssh": bytes(private_bytes).decode("utf-8"),
                "public_key": public_key,
                "public_fingerprint": fingerprint,
                "key_type": public_key.split()[0],
                "comment": " ".join(public_key.split()[2:]) or None,
                "source": {"kind": "imported_file" if source == "ssh" else "imported_bitwarden", "ref": source_ref or path},
            }
            item_type = "ssh_key"
            if break_glass is not None:
                payload.update(break_glass)
                item_type = "break_glass"
            result = await self.items.write_item(vault_id, item_id, item_type, payload, expected_revision=0)
            return {"item_id": item_id, "type": item_type, "public_fingerprint": fingerprint, "item": result}
        finally:
            for index in range(len(private_bytes)):
                private_bytes[index] = 0

    async def bind(
        self,
        *, vault_id: str, server: str, item_id: str, team: str | None,
        login: str | None, pin_host_key: bool, host_keys: Sequence[str] = (),
    ) -> dict[str, Any]:
        """Write a signed binding only after an explicit host-pin decision.

        The first binding pins *host_keys* when given, otherwise the keys this
        machine already trusts for the server (from an earlier SSH login).
        """
        if not team:
            raise ValueError("a team is required to bind a shared server")
        _uuid(vault_id, "vault_id")
        _uuid(item_id, "item_id")
        shared = await self._shared_server(team, server)
        hostname = shared.get("hostname") or shared.get("host") or shared.get("public_ip")
        port = shared.get("port", 22)
        if not isinstance(hostname, str) or not hostname or isinstance(port, bool) or not isinstance(port, int):
            raise VaultStateError("shared server lacks a valid SSH destination")
        vault = await self.vaults.get_vault(vault_id)
        item = await self.items.get_item(vault_id, item_id)
        payload = self.items.read_item(vault, item)
        host_keys, revision = self._binding_pins(shared, vault, hostname, port, pin_host_key, host_keys)
        login_user = login or shared.get("login_user") or shared.get("username")
        if not isinstance(login_user, str) or not login_user:
            raise ValueError("a non-empty SSH login is required")
        target = f"shared_server:{shared['id']}"
        binding = self.bindings.build_binding(
            scope=str(vault["scope"]), target=target, hostname=hostname, port=port,
            login_user=login_user, vault_id=vault_id, vault_item_id=item_id,
            public_fingerprint=str(payload["public_fingerprint"]), host_keys=host_keys,
            binding_revision=revision,
        )
        return await self.bindings.put_team_binding(team, str(shared["id"]), binding)

    async def bind_personal(
        self,
        *, vault_id: str, item_id: str, provider: str, instance_id: str,
        hostname: str, port: int, login: str, host_keys: Sequence[str],
    ) -> dict[str, Any]:
        """Create or update a signed binding for one personal instance.

        Personal inventory deliberately omits bindings, so the existing record
        is read from its signed canonical endpoint before its revision can be
        advanced.  Host pins are explicit caller input and required for use.
        """
        _uuid(vault_id, "vault_id")
        _uuid(item_id, "item_id")
        normalized_provider = validate_provider(provider)
        normalized_instance_id = validate_instance_id(instance_id)
        if (not isinstance(hostname, str) or not hostname or hostname != hostname.strip()
                or any(character.isspace() for character in hostname)
                or any(character in hostname for character in "*!?[]")):
            raise ValueError("personal binding hostname is invalid")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("personal binding port is invalid")
        if not isinstance(login, str) or not login:
            raise ValueError("personal binding login is required")
        if not host_keys:
            raise ValueError("personal binding requires verified host pins")
        self.bindings._validate_host_keys(host_keys)
        vault = await self.vaults.get_vault(vault_id)
        item = await self.items.get_item(vault_id, item_id)
        payload = self.items.read_item(vault, item)
        fingerprint = payload.get("public_fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint.startswith("SHA256:"):
            raise VaultStateError("personal binding item has no verified SSH fingerprint")
        target = f"instance:{normalized_provider}:{normalized_instance_id}"
        existing, existing_target = await self._credential_binding({
            "provider": normalized_provider, "id": normalized_instance_id,
        })
        if existing is None:
            revision = 1
        else:
            verified = self.bindings.verify_binding(
                existing, vault, target=existing_target, hostname=hostname, port=port,
            )
            revision = _positive_int(verified.get("binding_revision"), "binding.binding_revision") + 1
        binding = self.bindings.build_binding(
            scope=str(vault["scope"]), target=target, hostname=hostname, port=port,
            login_user=login, vault_id=vault_id, vault_item_id=item_id,
            public_fingerprint=fingerprint, host_keys=host_keys, binding_revision=revision,
        )
        return await self.bindings.put_personal_binding(
            normalized_provider, normalized_instance_id, binding,
        )

    async def bind_imported_bitwarden_ref(
        self,
        *, vault_id: str, item_id: str, team: str, server_id: str,
        source_ref: str, login: str | None = None, clear_legacy: bool = False,
    ) -> dict[str, Any]:
        """Migrate one matching team Bitwarden SSH ref after a native proof.

        The legacy reference is only cleared after the native binding has
        created a private-agent lease and a strict pinned SSH ``true`` command
        succeeds.  Declining ``clear_legacy`` and every failure retain it.
        """
        if not isinstance(source_ref, str) or not source_ref:
            raise ValueError("the imported Bitwarden source reference is required")
        shared = await self._shared_server(team, server_id)
        canonical_server_id = shared.get("id")
        if not isinstance(canonical_server_id, str) or not canonical_server_id:
            raise VaultStateError("shared server has no canonical id")
        legacy = await self.teams.get_team_server_ssh_ref(team, canonical_server_id)
        legacy_ref = legacy.get("ssh_credential_ref") if isinstance(legacy, Mapping) else None
        if (not isinstance(legacy, Mapping) or legacy.get("ssh_credential_provider") != "bitwarden_pm"
                or not isinstance(legacy_ref, Mapping) or legacy_ref.get("item_id") != source_ref):
            raise VaultStateError("the server's Bitwarden reference does not match the imported key")
        binding = await self.bind(
            vault_id=vault_id, item_id=item_id, team=team, server=canonical_server_id,
            login=login, pin_host_key=True,
        )
        if not isinstance(binding, Mapping) or binding.get("source") != "servonaut_vault":
            raise VaultStateError("native binding was not accepted by the server")
        lease: VaultSshLease | None = None
        try:
            lease = await self.resolve_ssh({
                **shared, "id": canonical_server_id, "is_shared": True,
                "team_slug": team, "credential_binding": dict(binding),
            })
            if lease is None or lease.source != "vault":
                raise VaultStateError("new native binding could not create a verified SSH lease")
            result = await self._remote_executor({**shared, "credential_binding": dict(binding)}, lease).run(("true",))
            if getattr(result, "returncode", None) != 0:
                raise VaultStateError("new native SSH credential proof failed")
        except Exception as exc:
            return {"bound": True, "verified": False, "legacy_cleared": False, "error": str(exc)}
        finally:
            if lease is not None:
                lease.close()
        if clear_legacy is not True:
            return {"bound": True, "verified": True, "legacy_cleared": False}
        deleted = await self.teams.delete_team_server_ssh_ref(team, canonical_server_id)
        return {"bound": True, "verified": True, "legacy_cleared": deleted is True}

    async def setup_escrow(
        self, *, vault_id: str, label: str,
        recovery_confirmation: Callable[[str], bool | Awaitable[bool]] | None = None,
    ) -> dict[str, Any]:
        """Register an offline escrow recipient and return its one-time key."""
        if not isinstance(label, str) or not 1 <= len(label) <= 200:
            raise ValueError("escrow label must contain 1 to 200 characters")
        vault = await self.vaults.get_vault(vault_id)
        identity = current_identity(self.store)
        remote_identity = self._identity_in_vault(vault, str(identity.identity_id))
        if remote_identity is not None and remote_identity.get("grantable") is not True:
            raise VaultStateError("a non-grantable identity cannot register an escrow")
        raw_key = bytearray(secrets.token_bytes(32))
        recovery_key = crypto.format_recovery_key(bytes(raw_key), prefix="SVTR1")
        if recovery_confirmation is not None and not await self._confirmed(recovery_confirmation, recovery_key):
            for index in range(len(raw_key)):
                raw_key[index] = 0
            raise VaultUserError("escrow recovery key was not confirmed")
        try:
            escrow_id = str(uuid.uuid4())
            enc_public_key = crypto.x25519_public(bytes(raw_key))
            signature = crypto.sign(
                identity_signing_seed(identity),
                crypto.escrow_message(vault_id, escrow_id, enc_public_key, label, str(identity.identity_id)),
            )
            result = await self.vaults._signed(
                "POST", f"/api/v1/vaults/{vault_id}/escrow", {
                    "escrow_id": escrow_id,
                    "label": label,
                    "enc_public_key": base64.b64encode(enc_public_key).decode("ascii"),
                    "signature": base64.b64encode(signature).decode("ascii"),
                },
            )
            return {"escrow": result, "escrow_id": escrow_id, "recovery_key": recovery_key}
        finally:
            for index in range(len(raw_key)):
                raw_key[index] = 0

    async def recover_escrow(self, *, vault_id: str, escrow_key: str) -> dict[str, Any]:
        """Use an offline escrow key for the two-step, server-bound recovery."""
        vault = await self.vaults.get_vault(vault_id)
        identity = current_identity(self.store)
        raw_key = bytearray(crypto.parse_recovery_key(escrow_key, prefix="SVTR1"))
        try:
            enc_public_key = crypto.x25519_public(bytes(raw_key))
            escrow = self._matching_escrow(vault, enc_public_key)
            escrow_id = str(escrow["escrow_id"])
            response = await self.vaults._signed(
                "POST", f"/api/v1/vaults/{vault_id}/escrow/{escrow_id}/recovery-challenge", {}
            )
            grant = response.get("escrow_grant")
            challenge = response.get("challenge")
            if not isinstance(grant, Mapping) or not isinstance(challenge, Mapping):
                raise VaultStateError("escrow recovery response is incomplete")
            version = self._version(vault, _positive_int(response.get("version"), "escrow recovery version"))
            vault_key = self._verify_escrow_grant(
                vault, grant, escrow_id, enc_public_key, bytes(raw_key), version
            )
            proof = crypto.open_sealed(
                self._b64(challenge.get("sealed"), "challenge.sealed"), enc_public_key, bytes(raw_key)
            )
            if len(proof) != 40:
                raise VaultStateError("escrow recovery challenge has an invalid proof")
            sealed = crypto.seal(vault_key, identity_encryption_public(identity))
            version_key = self._b64(version.get("public_key"), "version.public_key")
            signature = crypto.sign(
                identity_signing_seed(identity),
                crypto.grant_message(vault_id, str(vault["scope"]), _positive_int(version.get("version"), "version.version"), version_key,
                    int(identity.user_id), str(identity.identity_id), identity.fingerprint_raw, sealed,
                    str(identity.identity_id)),
            )
            return await self.vaults._signed(
                "POST", f"/api/v1/vaults/{vault_id}/escrow/{escrow_id}/recover", {
                    "proof": base64.b64encode(proof).decode("ascii"),
                    "grant": {
                        "recipient_user_id": int(identity.user_id),
                        "recipient_identity_id": str(identity.identity_id),
                        "sealed_private_key": base64.b64encode(sealed).decode("ascii"),
                        "signature": base64.b64encode(signature).decode("ascii"),
                    },
                },
            )
        finally:
            for index in range(len(raw_key)):
                raw_key[index] = 0

    async def _approval_after_reveal(self, device_id: str) -> dict[str, Any]:
        """Poll the pinned approval read until the pending peer reveals once."""
        delay = float(self.config.vault.approval_poll_initial_seconds)
        maximum = float(self.config.vault.approval_poll_max_seconds)
        deadline: datetime_module.datetime | None = None
        while True:
            if deadline is not None and datetime_module.datetime.now(datetime_module.timezone.utc) >= deadline:
                raise VaultStateError("device approval expired before a safety-number comparison")
            response = await self.api.request_signed(
                "GET", f"/api/v1/vault/devices/{device_id}/approval",
                device=self.store.signer(), timeout=self.config.vault.request_timeout_seconds,
            )
            if not isinstance(response, dict):
                raise VaultStateError("device approval response is malformed")
            response_expiry = response.get("expires_at")
            if response_expiry is not None:
                observed = self._approval_deadline(response_expiry)
                deadline = observed if deadline is None else min(deadline, observed)
            state = response.get("state")
            if state == "revealed":
                return response
            if state in {"rejected", "expired", "approved"}:
                raise VaultStateError("device approval ended before a safety-number comparison")
            if state != "challenged":
                raise VaultStateError("device approval entered an invalid state")
            sleep_for = delay
            if deadline is not None:
                remaining = (deadline - datetime_module.datetime.now(datetime_module.timezone.utc)).total_seconds()
                if remaining <= 0:
                    raise VaultStateError("device approval expired before a safety-number comparison")
                sleep_for = min(sleep_for, remaining)
            await asyncio.sleep(sleep_for)
            delay = min(delay * 2, maximum)

    @staticmethod
    def _approval_deadline(value: Any) -> datetime_module.datetime:
        if not isinstance(value, str) or not value:
            raise VaultStateError("pending device approval has no valid expiry")
        try:
            parsed = datetime_module.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise VaultStateError("pending device approval has no valid expiry") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise VaultStateError("pending device approval expiry must include a timezone")
        deadline = parsed.astimezone(datetime_module.timezone.utc)
        if deadline <= datetime_module.datetime.now(datetime_module.timezone.utc):
            raise VaultStateError("pending device approval has expired")
        return deadline

    @staticmethod
    def _reset_deadline(value: Any) -> datetime_module.datetime:
        if not isinstance(value, str) or not value:
            raise VaultStateError("identity reset has no valid expiry")
        try:
            parsed = datetime_module.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise VaultStateError("identity reset has no valid expiry") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise VaultStateError("identity reset expiry must include a timezone")
        deadline = parsed.astimezone(datetime_module.timezone.utc)
        if deadline <= datetime_module.datetime.now(datetime_module.timezone.utc):
            raise VaultStateError("identity reset has expired")
        return deadline

    @staticmethod
    async def _confirmed(
        callback: Callable[[str], bool | Awaitable[bool]], value: str,
    ) -> bool:
        result = callback(value)
        if hasattr(result, "__await__"):
            result = await result
        return result is True

    def _approval_safety_number(
        self, pin: Any, approval: Mapping[str, Any], approver_nonce: bytes,
    ) -> str:
        device = approval.get("device")
        if not isinstance(device, Mapping) or str(device.get("device_id")) != pin.device_id:
            raise VaultStateError("approval device changed after it was pinned")
        sig = self._b64(device.get("device_sig_public_key"), "approval.device_sig_public_key")
        enc = self._b64(device.get("device_enc_public_key"), "approval.device_enc_public_key")
        nonce = self._b64(approval.get("device_nonce"), "approval.device_nonce")
        if sig != pin.device_sig_public_key or enc != pin.device_enc_public_key:
            raise VaultStateError("approval device keys changed after they were pinned")
        if crypto.device_commitment(pin.device_id, sig, enc, nonce) != pin.commitment:
            raise VaultStateError("approval device commitment does not match")
        identity = current_identity(self.store)
        return crypto.sas(pin.device_id, identity.fingerprint_raw, sig, enc, nonce, approver_nonce)

    @staticmethod
    def _member_matches(entry: Mapping[str, Any], selector: str) -> bool:
        return selector in {
            str(entry.get("user_id", "")),
            str(entry.get("display_name", "")),
            str(entry.get("email", "")),
        }

    @staticmethod
    def _public_key_from_private(private_key: bytes, passphrase: bytes | None) -> str:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_ssh_private_key

        try:
            key = load_ssh_private_key(private_key, password=passphrase)
            return key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
        except (TypeError, ValueError, UnicodeDecodeError) as exc:
            raise ValueError("SSH private key is invalid or needs its passphrase supplied by the caller") from exc

    def _binding_pins(
        self, shared: Mapping[str, Any], vault: Mapping[str, Any], hostname: str, port: int, explicit_pin: bool,
        host_keys: Sequence[str] = (),
    ) -> tuple[tuple[str, ...], int]:
        existing = shared.get("credential_binding")
        target = f"shared_server:{shared.get('id')}"
        if isinstance(existing, Mapping) and existing.get("source") == "servonaut_vault":
            verified = self.bindings.verify_binding(existing, vault, target=target, hostname=hostname, port=port)
            return tuple(verified["host_keys"]), _positive_int(verified.get("binding_revision"), "binding.binding_revision") + 1
        if not explicit_pin and not host_keys:
            raise ValueError("--pin-host-key or --host-key is required for the first native-vault binding")
        pins = list(host_keys) or trusted_host_keys(shared, hostname, port)
        if not pins:
            raise VaultUserError(
                "this machine does not trust a host key for the server yet; connect once "
                "with `servonaut ssh` and check its fingerprint, or pass --host-key"
            )
        self.bindings._validate_host_keys(pins)
        return tuple(pins), 1

    @staticmethod
    def _identity_in_vault(vault: Mapping[str, Any], identity_id: str) -> Mapping[str, Any] | None:
        identities = vault.get("identities")
        if isinstance(identities, Mapping):
            identity = identities.get(identity_id)
            return identity if isinstance(identity, Mapping) else None
        return None

    @staticmethod
    def _version(vault: Mapping[str, Any], number: int) -> Mapping[str, Any]:
        for version in vault.get("versions", []):
            if isinstance(version, Mapping) and _positive_int(version.get("version"), "version.version") == number:
                return version
        raise VaultStateError("vault version is absent from its verified chain")

    @staticmethod
    def _b64(value: Any, field: str) -> bytes:
        if not isinstance(value, str):
            raise VaultStateError(f"{field} must be a base64 string")
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, UnicodeError) as exc:
            raise VaultStateError(f"{field} is invalid base64") from exc
        if base64.b64encode(decoded).decode("ascii") != value:
            raise VaultStateError(f"{field} is non-canonical base64")
        return decoded

    def _matching_escrow(self, vault: Mapping[str, Any], enc_public_key: bytes) -> Mapping[str, Any]:
        for escrow in vault.get("escrow", []):
            if isinstance(escrow, Mapping) and self._b64(escrow.get("enc_public_key"), "escrow.enc_public_key") == enc_public_key:
                return escrow
        raise VaultStateError("the supplied escrow key is not registered for this vault")

    def _verify_escrow_grant(
        self, vault: Mapping[str, Any], grant: Mapping[str, Any], escrow_id: str,
        escrow_public: bytes, escrow_secret: bytes, version: Mapping[str, Any],
    ) -> bytes:
        granter_id = grant.get("granter_identity_id")
        identities = vault.get("identities")
        granter = identities.get(granter_id) if isinstance(identities, Mapping) else None
        if not isinstance(granter, Mapping) or not self.pins.is_pinned(granter):
            raise VaultStateError("escrow grant signer is not a pinned vault identity")
        sealed = self._b64(grant.get("sealed_private_key"), "escrow_grant.sealed_private_key")
        version_key = self._b64(version.get("public_key"), "version.public_key")
        message = crypto.grant_message(
            str(vault["vault_id"]), str(vault["scope"]), _positive_int(version.get("version"), "version.version"), version_key,
            0, escrow_id, crypto.sha256(escrow_public), sealed, str(granter_id),
        )
        if not crypto.verify(self._b64(granter.get("sig_public_key"), "granter.sig_public_key"), message,
                             self._b64(grant.get("signature"), "escrow_grant.signature")):
            raise VaultStateError("escrow grant signature is invalid")
        return crypto.open_grant(sealed, escrow_public, escrow_secret, version_key)

    async def resolve_ssh(self, instance: Mapping[str, Any]) -> VaultSshLease | None:
        """Resolve CA first, then a verified native binding into an agent lease."""
        binding = instance.get("credential_binding")
        requires_native = (
            isinstance(binding, Mapping)
            and binding.get("source") == "servonaut_vault"
        )
        # Native status, CA issuance, and personal-binding lookups are all
        # device-signed operations.  An ordinary Bitwarden/local target must
        # not try one of them merely because the Vault runtime is available:
        # without unlocked custody there is no native credential to verify,
        # so return to the resolver chain.  A supplied native binding is the
        # exception; it is authenticated configuration and must fail closed.
        if self.store.identity is None:
            if requires_native:
                raise VaultStateError(
                    "native Vault SSH binding requires an unlocked Team Vault identity"
                )
            return None
        # The personal binding endpoint is limited to managed providers.  It
        # must not pre-empt the resolver's established local-key path for a
        # custom or otherwise unsupported target merely because the user has
        # unlocked a Vault identity.  An explicit native binding remains an
        # authenticated instruction and is allowed to fail closed below.
        if not requires_native and instance.get("is_shared") is not True:
            if instance.get("is_custom") is True:
                return None
            try:
                validate_provider(instance.get("provider", "aws"))
            except ValidationError:
                return None
        ca_lease = await self._resolve_ca_ssh(instance)
        if ca_lease is not None:
            return ca_lease
        binding, target = await self._credential_binding(instance)
        if not isinstance(binding, Mapping) or binding.get("source") != "servonaut_vault":
            return None
        vault_id, item_id = binding.get("vault_id"), binding.get("vault_item_id")
        if not isinstance(vault_id, str) or not isinstance(item_id, str):
            raise VaultStateError("native credential binding is malformed")
        hostname = instance.get("hostname") or instance.get("host") or instance.get("public_ip")
        port = instance.get("port", 22)
        if not isinstance(hostname, str) or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise VaultStateError("bound server has no valid hostname or port")
        vault = await self.vaults.get_vault(vault_id)
        verified = self.bindings.verify_binding(binding, vault, target=target, hostname=hostname, port=port)
        pins = tuple(verified.get("host_keys", ()))
        if not pins:
            raise VaultStateError("native SSH binding has no verified host pins")
        item = await self.items.get_item(vault_id, item_id)
        payload = self.items.read_item(vault, item)
        private = bytearray(payload["private_key_openssh"].encode("utf-8"))
        public_key = crypto.openssh_public_key_from_private(private)
        agent = PrivateSshAgent.start()
        known_hosts: Path | None = None
        identity_file: Path | None = None
        try:
            try:
                agent.add_private_key(bytes(private), ttl_seconds=self.agent_key_ttl_seconds)
            finally:
                for index in range(len(private)):
                    private[index] = 0
            known_hosts = self._write_known_hosts(hostname, pins, port=port)
            identity_file = self._write_identity_file(public_key)
            lease = VaultSshLease("vault", str(agent.socket_path), None, str(known_hosts), str(verified["login_user"]), pins, public_key, str(identity_file), vault_id, item_id, dict(verified), agent, hostname, port)
            self._leases.append(lease)
            return lease
        except BaseException:
            agent.close()
            for path in (identity_file, known_hosts):
                if path is not None:
                    path.unlink(missing_ok=True)
            raise

    async def _credential_binding(
        self, instance: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any] | None, str]:
        """Read the authoritative binding, including personal instances.

        Personal inventory responses do not carry credential bindings.  Fetch
        their signed endpoint after validating route components locally so an
        arbitrary provider/id cannot affect the request path.
        """
        if instance.get("is_shared") is True:
            server_id = instance.get("id") or instance.get("shared_server_id")
            if not isinstance(server_id, str) or not server_id:
                raise VaultStateError("shared server has no canonical id")
            return instance.get("credential_binding") if isinstance(instance.get("credential_binding"), Mapping) else None, f"shared_server:{server_id}"
        provider = validate_provider(instance.get("provider"))
        instance_id = validate_instance_id(instance.get("id"))
        path = f"/api/v1/me/instances/{provider}/{instance_id}/credential-binding"
        try:
            response = await self.api.request_signed("GET", path, json={}, device=self.store.signer())
        except APIError as exc:
            if exc.status == 404:
                return None, f"instance:{provider}:{instance_id}"
            raise
        if not isinstance(response, Mapping):
            raise VaultStateError("personal credential binding response is malformed")
        candidate = response.get("credential_binding", response)
        if candidate is None:
            return None, f"instance:{provider}:{instance_id}"
        if not isinstance(candidate, Mapping):
            raise VaultStateError("personal credential binding response is malformed")
        return candidate, f"instance:{provider}:{instance_id}"

    async def resolve_relay_target(self, identifier: str) -> dict[str, Any] | None:
        """Find a shared-server target for relay commands after local lookup.

        Relay code calls this only when its ordinary provider directory did
        not find a target.  The result carries the canonical team and server
        identifiers required by certificate/native-binding resolution.
        """
        if not isinstance(identifier, str) or not identifier:
            return None
        matches: list[dict[str, Any]] = []
        for team in await self.teams.list_teams():
            if not isinstance(team, Mapping):
                continue
            slug = team.get("slug")
            if not isinstance(slug, str):
                continue
            for server in await self.teams.list_shared_servers(slug):
                if not isinstance(server, Mapping):
                    continue
                if identifier not in {str(server.get("id", "")), str(server.get("name", ""))}:
                    continue
                matches.append({**server, "is_shared": True, "team_slug": slug})
        if len(matches) > 1:
            raise ValueError("relay target is ambiguous; use the canonical server id")
        return matches[0] if matches else None

    async def _resolve_ca_ssh(
        self, instance: Mapping[str, Any], *, purpose: str = "interactive", require_enrolled: bool = True,
        fresh: bool = False,
    ) -> VaultSshLease | None:
        """Issue a pinned, short-lived certificate for an enrolled shared server.

        The shared row's ``ssh_ca`` says whether the host is enrolled; the CA's
        login map lists every team server, enrolled or not. Rows from servers
        that predate the field fall back to the login map. Only the enrollment
        proof (``require_enrolled=False``) targets a host mid-enrollment.
        """
        if instance.get("is_shared") is not True:
            return None
        if require_enrolled and "ssh_ca" in instance:
            ca_row = instance.get("ssh_ca")
            if not (isinstance(ca_row, Mapping) and ca_row.get("enrolled") is True):
                return None
        team = instance.get("team_slug")
        server_id = instance.get("id") or instance.get("shared_server_id")
        if not isinstance(team, str) or not isinstance(server_id, str):
            return None
        client = self._ca(team)
        status = await client.get_status()
        if not status.enabled or status.host_ca_public_key is None:
            return None
        logins = status.logins_by_server.get(server_id)
        if not logins:
            return None
        hostname = instance.get("hostname") or instance.get("host") or instance.get("public_ip")
        if not isinstance(hostname, str) or not hostname:
            raise VaultStateError("enrolled server has no valid hostname")
        requested_login = instance.get("login_user") or instance.get("username")
        if requested_login is None:
            if len(logins) != 1:
                raise VaultStateError("SSH CA server has multiple logins; select one explicitly")
            login = logins[0]
        else:
            login = str(requested_login)
            if login not in logins:
                raise VaultStateError("selected SSH login is not authorised by the team CA")
        # The enrollment proof always uses its own certificate, so it proves the
        # current CA and policy and the issuance log ties a proof to each job.
        certificate = None if fresh else client.load_cached_certificate([server_id], purpose=purpose, status=status)
        if certificate is None:
            device_key = await client.register_device_key()
            certificate = await client.issue_certificate([server_id], purpose=purpose)
        else:
            renewed = await client.renew_if_due(certificate, [server_id], purpose=purpose)
            certificate = renewed or certificate
            device_key = client.ensure_device_ssh_key()
        agent = PrivateSshAgent.start()
        identity_file: Path | None = None
        lease_certificate: Path | None = None
        try:
            private = bytearray(device_key.private_key)
            try:
                agent.add_private_key(private, ttl_seconds=self.agent_key_ttl_seconds)
            finally:
                for index in range(len(private)):
                    private[index] = 0
            public_key = crypto.openssh_public_key_from_private(device_key.private_key)
            if crypto.ssh_public_fingerprint(public_key) != crypto.ssh_public_fingerprint(device_key.public_key):
                raise VaultStateError("CA device key public identity does not match its private key")
            # CA access is independently anchored by the pinned Team host
            # CA.  Do not copy an inventory binding's host keys into a CA
            # lease: that untrusted payload has not passed binding signature,
            # current-admin, and destination verification here.
            binding_pins: tuple[str, ...] = ()
            binding: Mapping[str, Any] | None = None
            port = instance.get("port", 22)
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise VaultStateError("enrolled server has no valid SSH port")
            known_host = hostname if port == 22 else f"[{hostname}]:{port}"
            known_hosts = TeamKnownHosts().write(team, status.host_ca_public_key, [known_host], binding_pins)
            identity_file = self._write_identity_file(public_key)
            lease_certificate = self._write_lease_certificate(certificate.certificate_path)
            lease = VaultSshLease(
                "ca", str(agent.socket_path), str(lease_certificate), str(known_hosts),
                login, binding_pins, public_key, str(identity_file), None, None,
                None, agent, hostname, port,
            )
            self._leases.append(lease)
            return lease
        except BaseException:
            agent.close()
            if identity_file is not None:
                identity_file.unlink(missing_ok=True)
            if lease_certificate is not None:
                lease_certificate.unlink(missing_ok=True)
            raise

    def _write_known_hosts(self, hostname: str, pins: Sequence[str], *, port: int = 22) -> Path:
        """Create a lease-owned native-pin file under a private real directory."""
        if (not isinstance(hostname, str) or not hostname or hostname != hostname.strip()
                or any(character.isspace() for character in hostname)
                or any(character in hostname for character in "*!?[]")):
            raise VaultStateError("native SSH hostname is unsafe for known_hosts")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise VaultStateError("native SSH port is invalid for known_hosts")
        directory = self._vault_known_hosts_directory()
        self._ensure_private_directory(directory, "native known_hosts")
        host_field = hostname if port == 22 else f"[{hostname}]:{port}"
        fd, temporary = tempfile.mkstemp(dir=directory, prefix=".vault-", suffix=".tmp")
        target = directory / ("vault-" + uuid.uuid4().hex)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                for pin in pins:
                    handle.write(f"{host_field} {pin}\n")
                handle.flush(); os.fsync(handle.fileno())
            os.replace(temporary, target); os.chmod(target, 0o600)
            self._assert_private_file(target, "native known_hosts")
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        return target

    @staticmethod
    def _vault_known_hosts_directory() -> Path:
        return Path.home() / ".servonaut" / "known_hosts.d"

    @staticmethod
    def _ensure_private_directory(directory: Path, label: str) -> None:
        """Create private path components without following a hostile link."""
        missing: list[Path] = []
        current = directory
        while True:
            try:
                current.lstat()
                break
            except FileNotFoundError:
                missing.append(current)
                current = current.parent
            except OSError as exc:
                raise VaultStateError(f"could not inspect {label} directory") from exc
        VaultCommandService._assert_private_directory(current, label, allow_home=current == Path.home())
        for path in reversed(missing):
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                pass
            VaultCommandService._assert_private_directory(path, label)
        VaultCommandService._assert_private_directory(directory, label)

    @staticmethod
    def _assert_private_directory(path: Path, label: str, *, allow_home: bool = False) -> None:
        try:
            info = path.lstat()
        except OSError as exc:
            raise VaultStateError(f"could not inspect {label} directory") from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise VaultStateError(f"{label} directory is not a real directory")
        if info.st_uid != os.getuid() or (not allow_home and info.st_mode & 0o077):
            raise VaultStateError(f"{label} directory has unsafe ownership or permissions")

    @staticmethod
    def _assert_private_file(path: Path, label: str) -> None:
        try:
            info = path.lstat()
        except OSError as exc:
            raise VaultStateError(f"could not inspect {label} file") from exc
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise VaultStateError(f"{label} file is not a regular file")
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise VaultStateError(f"{label} file has unsafe ownership or permissions")

    def _write_identity_file(self, public_key: str) -> Path:
        """Persist a lease-scoped public identity for OpenSSH agent selection."""
        try:
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat, load_ssh_public_key,
            )

            parsed = load_ssh_public_key(public_key.encode("ascii"))
            canonical = parsed.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
        except Exception as exc:
            raise VaultStateError("SSH agent public identity is invalid") from exc
        directory = Path.home() / ".servonaut" / "agent-public"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        fd, temporary = tempfile.mkstemp(dir=directory, prefix=".agent-", suffix=".tmp")
        target = directory / f"agent-{uuid.uuid4().hex}.pub"
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(canonical + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            os.chmod(target, 0o600)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        return target

    def _write_lease_certificate(self, cached_certificate: Path) -> Path:
        """Copy a public certificate for one lease without deleting the cache on close."""
        try:
            contents = cached_certificate.read_bytes()
        except OSError as exc:
            raise VaultStateError("cached SSH certificate is unavailable") from exc
        directory = Path.home() / ".servonaut" / "agent-public"
        self._ensure_private_directory(directory, "agent public")
        fd, temporary = tempfile.mkstemp(dir=directory, prefix=".certificate-", suffix=".tmp")
        target = directory / f"certificate-{uuid.uuid4().hex}.pub"
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(contents)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            os.chmod(target, 0o600)
            self._assert_private_file(target, "agent public")
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        return target

    def close(self) -> None:
        for lease in tuple(self._leases):
            lease.close()
        self._leases.clear()
        self.identity.discard_pending_device()
        pending_reset = self._pending_identity_reset
        self._pending_identity_reset = None
        if pending_reset is not None:
            self.identity.discard_reset_replacement(pending_reset.replacement)
        # ``IdentityStore.wipe`` removes durable custody. Normal runtime
        # shutdown only clears decrypted process memory.
        self.store.lock()

    def _ca(self, team: str) -> CertificateAuthorityClient:
        identity = self.store.identity
        if identity is None:
            raise VaultUserError(NO_LOCAL_IDENTITY)
        return CertificateAuthorityClient(self.api, team, identity.device, identity.device.device_id, self.store)

    async def ca_status(self, *, team: str) -> dict[str, Any]:
        return (await self._ca(team).get_status()).to_dict()

    async def ca_enable(self, *, team: str) -> dict[str, Any]:
        return (await self._ca(team).enable()).to_dict()

    async def ca_policy(self, *, team: str, policy: Mapping[str, Any] | None) -> dict[str, Any]:
        client = self._ca(team)
        if policy is None:
            return (await client.get_status()).to_dict()
        status, hosts_needing_refresh = await client.update_policy(policy)
        return {**status.to_dict(), "hosts_needing_refresh": hosts_needing_refresh}

    async def ca_revoke(self, *, team: str, serial: int, note: str | None = None) -> dict[str, Any]:
        response = await self._ca(team).revoke_certificate(serial, note=note)
        certificate = response.get("certificate") if isinstance(response, Mapping) else None
        if not isinstance(certificate, Mapping) or certificate.get("serial") != serial:
            raise VaultStateError("certificate revoke response does not describe the requested serial")
        return {
            "serial": serial,
            "cert_type": certificate.get("cert_type"),
            "key_id": certificate.get("key_id"),
            "revoked_at": certificate.get("revoked_at"),
            "krl_version": response.get("krl_version"),
        }

    async def ca_audit(self, *, team: str) -> dict[str, Any]:
        anchored = self.state.load().get("ca_audit_heads", {}).get(team)
        if anchored is not None and not isinstance(anchored, str):
            raise VaultStateError("stored CA audit anchor is malformed")
        report = await self._ca(team).audit_issuance(expected_head=anchored, team_id=await self._team_id(team))
        self.state.record_ca_audit_head(team, report.head_hash)
        return report.to_dict()

    async def ca_hosts(self, *, team: str) -> dict[str, Any]:
        """Read pinned CA host state so callers can show refresh/KRL drift."""
        status = await self._ca(team).get_status()
        response = await self.api.request_signed(
            "GET", f"/api/v1/teams/{team}/ssh-ca/hosts", device=self.store.signer(),
            timeout=self.config.vault.request_timeout_seconds,
        )
        hosts = response.get("data", response) if isinstance(response, Mapping) else None
        if not isinstance(hosts, list):
            raise VaultStateError("CA host status response is malformed")
        current_krl = status.krl_version
        normalized: list[dict[str, Any]] = []
        for entry in hosts:
            if not isinstance(entry, Mapping) or not isinstance(entry.get("server_id"), str):
                raise VaultStateError("CA host status entry is malformed")
            delivered = entry.get("krl_version_delivered")
            if delivered is not None and (isinstance(delivered, bool) or not isinstance(delivered, int) or delivered < 0):
                raise VaultStateError("CA host KRL version is malformed")
            row = dict(entry)
            row["krl_drift"] = current_krl is not None and (delivered is None or delivered < current_krl)
            normalized.append(row)
        return {"krl_version": current_krl, "hosts": normalized}

    async def ca_enroll(
        self, *, team: str, server: str, break_glass_item_id: str | None,
        confirmation: Callable[[Mapping[str, Any]], str | Awaitable[str]], kind: str = "enroll",
    ) -> dict[str, Any]:
        """Run a confirmed, versioned CA enrollment through an injected transport."""
        client = self._ca(team)
        status = await client.get_status()  # pin CA keys before any remote host write
        shared = await self._shared_server(team, server)
        created = await client.create_enrollment(str(shared["id"]), kind, break_glass_item_id=break_glass_item_id)
        enrollment_id = created.get("enrollment_id") or created.get("id")
        if not isinstance(enrollment_id, str):
            raise RuntimeError("CA enrollment response did not include an id")
        fetched = await client.get_enrollment(enrollment_id)
        params = fetched.get("params") or fetched.get("enrollment") or fetched
        if not isinstance(params, Mapping):
            raise RuntimeError("CA enrollment has invalid parameters")
        self._validate_enrollment_ca_keys(params, status)
        params = await self._fill_break_glass(team, params)
        confirmed = confirmation({"hostname": params.get("server", {}).get("hostname"), "params": params})
        if hasattr(confirmed, "__await__"):
            confirmed = await confirmed
        if confirmed != params.get("server", {}).get("hostname"):
            raise ValueError("host name confirmation did not match")
        claimed = await client.claim_enrollment(enrollment_id)
        try:
            return await self._execute_claimed_enrollment(
                client, status, shared, team, enrollment_id, fetched, claimed, params, confirmed,
            )
        except BaseException as exc:
            # A claimed job stays open until its executor reports; always report.
            failure = EnrollmentResult("failed", (), _enrollment_error_code(exc)).to_dict()
            try:
                await client.report_enrollment_result(enrollment_id, failure)
            except Exception:
                logger.warning("Could not report the failed SSH CA enrollment %s", enrollment_id)
            raise

    async def _execute_claimed_enrollment(
        self, client: Any, status: Any, shared: Mapping[str, Any], team: str, enrollment_id: str,
        fetched: Mapping[str, Any], claimed: Mapping[str, Any], params: Mapping[str, Any], confirmed: str,
    ) -> dict[str, Any]:
        if isinstance(claimed.get("params"), Mapping):
            params = claimed["params"]
        self._validate_enrollment_ca_keys(params, status)
        params = await self._fill_break_glass(team, params)
        executor = self._remote_executor(shared, None)

        async def proof_certificate_supplier() -> VaultSshLease:
            lease = await self._resolve_ca_ssh(
                {**shared, "is_shared": True, "team_slug": team}, purpose="automation", require_enrolled=False,
                fresh=True,
            )
            if lease is None:
                raise VaultStateError("SSH CA could not issue the enrollment proof certificate")
            return lease

        setattr(executor, "proof_certificate_supplier", proof_certificate_supplier)
        proof = getattr(executor, "prove_certificate_login", None)
        if not callable(proof):
            raise RuntimeError("configured remote executor cannot prove the SSH certificate login")

        async def request_host_certificate(public_key: str) -> str:
            response = await client.request_host_certificate(enrollment_id, public_key)
            certificate = response.get("host_certificate")
            if not isinstance(certificate, str):
                raise RuntimeError("CA host certificate response is invalid")
            return certificate

        result = await CaEnrollmentExecutor(
            executor, host_ca_public_key=status.host_ca_public_key, team=team,
        ).execute(
            params,
            confirmed_host_name=confirmed,
            request_host_certificate=request_host_certificate,
            prove_certificate_login=proof,
        )
        reported = await client.report_enrollment_result(enrollment_id, result.to_dict())
        return {"enrollment": dict(fetched), "result": result.to_dict(), "reported": reported}

    async def _fill_break_glass(self, team: str, params: Mapping[str, Any]) -> dict[str, Any]:
        """Complete the server's break-glass reference from the decrypted vault item.

        The server only knows the item id and public fingerprint; the key, its
        login and its source networks are inside the encrypted item.
        """
        spec = params.get("break_glass")
        if not isinstance(spec, Mapping):
            return dict(params)
        item_id, expected = spec.get("item_id"), spec.get("public_fingerprint")
        _uuid(item_id, "break_glass.item_id")
        for row in await self.vaults.list_vaults():
            owner_team = row.get("team")
            if row.get("kind") != "team" or not isinstance(owner_team, Mapping) or owner_team.get("slug") != team:
                continue
            vault_id = str(row.get("vault_id"))
            try:
                item = await self.items.get_item(vault_id, str(item_id))
            except APIError as exc:
                if exc.status in {403, 404}:
                    continue
                raise
            if item.get("type") != "break_glass":
                raise VaultUserError("the selected item is not a break-glass key")
            payload = self.items.read_item(await self.vaults.get_vault(vault_id), item)
            public_key = " ".join(str(payload.get("public_key", "")).split()[:2])
            if (not isinstance(expected, str) or payload.get("public_fingerprint") != expected
                    or crypto.ssh_public_fingerprint(public_key) != expected):
                raise VaultUserError("the break-glass key does not match the fingerprint the server named")
            logins = payload.get("logins")
            if not isinstance(logins, list) or "root" not in logins:
                raise VaultUserError("the break-glass key is not for the root login")
            return {**params, "break_glass": {
                "item_id": str(item_id), "public_fingerprint": expected, "public_key": public_key,
                "login": "root", "from_cidrs": _normalized_cidrs(payload.get("from_cidrs") or []),
            }}
        raise VaultUserError("the break-glass item was not found in this team's vaults")

    async def _team_id(self, team: str) -> str:
        """The canonical id of the team with this slug (vault and CA hashes bind the id)."""
        detail = await self.teams.get_team(team)
        team_id = detail.get("id") or detail.get("team_id")
        if not isinstance(team_id, str):
            raise RuntimeError("team response did not include a canonical id")
        return team_id

    async def _team_break_glass_fingerprints(self, team: str) -> set[str]:
        """Public fingerprints of the team's live break-glass items (metadata only)."""
        fingerprints: set[str] = set()
        for row in await self.vaults.list_vaults():
            owner_team = row.get("team")
            if row.get("kind") != "team" or not isinstance(owner_team, Mapping) or owner_team.get("slug") != team:
                continue
            listed = await self.items.list_items(str(row.get("vault_id")))
            for item in listed.get("data", []) if isinstance(listed, Mapping) else []:
                fingerprint = item.get("public_fingerprint") if isinstance(item, Mapping) else None
                if item.get("type") == "break_glass" and not item.get("deleted") and isinstance(fingerprint, str):
                    fingerprints.add(fingerprint)
        return fingerprints

    async def ca_break_glass_scan(
        self, *, team: str, servers: Sequence[str] | None = None, since_hours: int = 24,
    ) -> dict[str, Any]:
        """Read enrolled hosts' SSH logs for break-glass logins and report new ones.

        Reports are attestations by this device: the server records them and
        e-mails the team owner. Each event is reported once per device.
        """
        if isinstance(since_hours, bool) or not isinstance(since_hours, int) or not 1 <= since_hours <= 720:
            raise VaultUserError("the scan window must be between 1 and 720 hours")
        from .ca_audit import detect_break_glass_usage

        fingerprints = await self._team_break_glass_fingerprints(team)
        if not fingerprints:
            return {"since_hours": since_hours, "servers": [], "reported": 0,
                    "note": "this team's vaults hold no break-glass key"}
        hosts = [host for host in (await self.ca_hosts(team=team))["hosts"] if host.get("status") == "enrolled"]
        if servers:
            wanted = {str((await self._shared_server(team, selector))["id"]) for selector in servers}
            hosts = [host for host in hosts if host["server_id"] in wanted]
        now = datetime_module.datetime.now(datetime_module.timezone.utc)
        window_start = now - datetime_module.timedelta(hours=since_hours)
        known = set(self.state.load().get("break_glass_reported", []))
        results: list[dict[str, Any]] = []
        new_keys: list[str] = []
        for host in hosts:
            server_id = str(host["server_id"])
            try:
                shared = await self._shared_server(team, server_id)
                log = await self._remote_executor(shared, None).read_auth_log(since_hours)
            except Exception as exc:
                results.append({"server_id": server_id, "status": "failed", "error": vault_failure_reason(exc)})
                continue
            events: dict[str, dict[str, str]] = {}
            for fingerprint in sorted(fingerprints):
                for event in detect_break_glass_usage(server_id, log, fingerprint, now=now):
                    if datetime_module.datetime.fromisoformat(event["observed_at"]) < window_start:
                        continue
                    key = f"{server_id}|{event['observed_at']}|{event.get('source_ip', '')}|{fingerprint}"
                    events.setdefault(key, event)
            reported = 0
            for key, event in events.items():
                if key in known:
                    continue
                await self.api.request_signed(
                    "POST", f"/api/v1/teams/{team}/ssh-ca/break-glass-events", device=self.store.signer(),
                    timeout=self.config.vault.request_timeout_seconds,
                    json={"server_id": server_id, "observed_at": event["observed_at"],
                          "source_ip": event.get("source_ip")},
                )
                known.add(key)
                new_keys.append(key)
                reported += 1
            results.append({"server_id": server_id, "status": "scanned", "events": len(events), "reported": reported})
        if new_keys:
            self.state.record_break_glass_reports(new_keys)
        return {"since_hours": since_hours, "servers": results, "reported": len(new_keys)}

    async def ca_refresh(
        self, *, team: str, server: str, confirmation: Callable[[Mapping[str, Any]], str | Awaitable[str]],
    ) -> dict[str, Any]:
        return await self.ca_enroll(
            team=team, server=server, break_glass_item_id=None, confirmation=confirmation, kind="refresh"
        )

    async def ca_unenroll(
        self, *, team: str, server: str, confirmation: Callable[[Mapping[str, Any]], str | Awaitable[str]],
    ) -> dict[str, Any]:
        return await self.ca_enroll(
            team=team, server=server, break_glass_item_id=None, confirmation=confirmation, kind="unenroll"
        )

    async def ca_deliver_krl(self, *, team: str, servers: Sequence[str] | None) -> dict[str, Any]:
        """Fetch the team's KRL with its version and digest, then deliver it atomically."""
        selected = self._krl_targets(await self.teams.list_shared_servers(team), servers)
        raw, digest, version = await self._team_krl(team)
        executors = {str(row["id"]): self._remote_executor(row, None) for row in selected}
        report = await deliver_krl(executors, raw, digest, version)
        delivered = await self.api.request_signed(
            "POST", f"/api/v1/teams/{team}/ssh-ca/krl-deliveries",
            json={"krl_version": version, "results": list(report.to_dict()["results"])},
            device=self.store.signer(), timeout=self.config.vault.request_timeout_seconds,
        )
        return {**report.to_dict(), "reported": delivered}

    @staticmethod
    def _krl_targets(members: Sequence[Mapping[str, Any]], servers: Sequence[str] | None) -> list[Mapping[str, Any]]:
        """Enrolled shared servers to deliver to: the named ones (id or name) or all enrolled."""
        def enrolled(row: Mapping[str, Any]) -> bool:
            ca_row = row.get("ssh_ca")
            return isinstance(ca_row, Mapping) and ca_row.get("enrolled") is True

        if not servers:
            selected = [row for row in members if enrolled(row)]
            if not selected:
                raise VaultUserError("this team has no hosts enrolled in its SSH CA")
            return selected
        selected = []
        for selector in servers:
            row = next((row for row in members if selector in {str(row.get("id")), row.get("name")}), None)
            if row is None:
                raise VaultUserError(f"shared server {selector!r} was not found in this team")
            if not enrolled(row):
                raise VaultUserError(f"shared server {selector!r} is not enrolled in the team's SSH CA")
            selected.append(row)
        return selected

    async def _team_krl(self, team: str) -> tuple[bytes, str, int]:
        """The user-certificate KRL with its version and SHA-256 (``GET …/ssh-ca/revocations``)."""
        payload = await self.api.get(f"/api/v1/teams/{team}/ssh-ca/revocations")
        version = payload.get("krl_version") if isinstance(payload, Mapping) else None
        digest = payload.get("sha256") if isinstance(payload, Mapping) else None
        encoded = payload.get("krl") if isinstance(payload, Mapping) else None
        if isinstance(version, bool) or not isinstance(version, int) or version < 0:
            raise VaultStateError("CA revocation list response has no valid version")
        if not isinstance(digest, str) or not isinstance(encoded, str):
            raise VaultStateError("CA revocation list response is incomplete")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise VaultStateError("CA revocation list is not valid base64") from exc
        return raw, digest, version

    async def _shared_server(self, team: str, server: str) -> Mapping[str, Any]:
        for row in await self.teams.list_shared_servers(team):
            if str(row.get("id")) == server or row.get("name") == server:
                return row
        raise ValueError("shared server was not found in the selected team")

    def _remote_executor(self, server: Mapping[str, Any], lease: VaultSshLease | None) -> Any:
        if self.remote_executor_factory is not None:
            return self.remote_executor_factory(server, lease)
        if self.ssh_service is None or self.connection_service is None or self.ssh_ref_resolver is None:
            raise VaultUserError("no remote executor is configured for SSH CA host changes")
        from .remote_executor import make_remote_executor_factory

        default_username = getattr(self.config, "default_username", "root") or "root"
        factory = make_remote_executor_factory(
            self.ssh_service, self.connection_service, self.ssh_ref_resolver,
            default_username=default_username,
            timeout_seconds=self.config.vault.request_timeout_seconds,
        )
        return factory(server, lease)

    @staticmethod
    def _validate_enrollment_ca_keys(params: Mapping[str, Any], status: Any) -> None:
        """Keep an enrollment response from swapping either pinned CA key."""
        host_key = params.get("host_ca_public_key")
        user_keys = params.get("user_ca_public_keys")
        if not isinstance(host_key, str) or not isinstance(user_keys, Sequence) or not all(isinstance(key, str) for key in user_keys):
            raise VaultStateError("CA enrollment parameters contain invalid CA keys")
        if crypto.ssh_public_fingerprint(host_key) != status.host_ca_fingerprint:
            raise VaultStateError("CA enrollment host CA does not match the pinned team CA")
        trusted_user_fingerprints = {status.user_ca_fingerprint}
        previous = status.raw.get("user_ca_previous", []) if isinstance(status.raw, Mapping) else []
        if isinstance(previous, list):
            for entry in previous:
                if isinstance(entry, Mapping) and isinstance(entry.get("fingerprint"), str):
                    trusted_user_fingerprints.add(entry["fingerprint"])
        if any(crypto.ssh_public_fingerprint(key) not in trusted_user_fingerprints for key in user_keys):
            raise VaultStateError("CA enrollment user CA does not match a pinned team CA")
