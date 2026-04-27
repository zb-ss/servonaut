"""Team memory service for the server memory subsystem.

Handles team-scoped DEK sharing and grant lifecycle (spec §4).

Spec coverage:
- §4.1  GET  /api/v1/teams/{slug}/memory          (list shared instances)
- §4.2  GET  /api/v1/teams/{slug}/memory/{id}/{module}  (read team envelope)
- §4.3  POST /api/v1/teams/{slug}/memory/grant    (share instance)
- §4.4  DELETE /api/v1/teams/{slug}/memory/grant/{id}  (soft-revoke)
- §4.5  POST /api/v1/teams/{slug}/memory/grant/{id}/purge  (hard purge)
- §3.1  GET  /api/v1/memory/keys/team/{slug}      (list member pubkeys)

**Key design decision:**
``share_instance`` accepts ``member_pubkeys: list[TeamMemberKey]`` and performs
the DEK unwrap + per-member re-wrap INTERNALLY.  DEK material never leaves the
service layer.  The caller provides plaintext access (via ``retrieval_service``
and ``key_store_provider``) but does not handle raw key material directly.

**Protocol for retrieval_service (duck-typed):**
The service expects an object with:
- ``list_instance_modules(instance_id: str) -> dict``
  Returns a dict with at minimum ``{"modules": [{"module": str, "envelope_id": str}]}``
- ``get_module_envelope_raw(instance_id: str, module: str) -> dict``
  Returns the raw (encrypted) envelope dict from the server including
  ``id``, ``dek_wraps`` or ``wrapped_dek``, ``iv``, ``tag``, ``ciphertext``,
  ``encryption``.  Used to extract the DEK for re-wrapping.

**Protocol for key_store_provider:**
A callable ``() -> KeyMaterial`` returning an object with:
- ``private_key: bytes``  — raw 32-byte X25519 private key
- ``public_key: bytes``   — raw 32-byte X25519 public key
- ``user_id: int``        — numeric user ID

These contracts are intentionally duck-typed (not requiring an import from
Stream 2) so this service compiles independently.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Protocol, TYPE_CHECKING

import nacl.public

from servonaut.services.memory.interfaces import (
    BackendMaintenance,
    BetaWaitlist,
    MemoryBackendError,
    UpsellRequired,
    ValidationFailed,
)
from servonaut.services.memory.retrieval_service import _validate_instance_id

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient
    from servonaut.services.auth_service import AuthService

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class GrantAlreadyExistsError(MemoryBackendError):
    """Raised when a live grant already covers ``(team, instance)``.

    Maps to server error code ``grant_exists`` (HTTP 409).

    Attributes:
        team_slug: Team slug involved.
        instance_id: Instance identifier that is already shared.
    """

    def __init__(self, team_slug: str, instance_id: str) -> None:
        self.team_slug = team_slug
        self.instance_id = instance_id
        super().__init__(
            f"A live grant already exists for instance {instance_id!r} "
            f"in team {team_slug!r}. Revoke the existing grant first."
        )


class InsufficientWrapsRequired(MemoryBackendError):
    """Raised when the server rejects a grant because some member wraps are
    missing (server error code ``insufficient_wraps``, HTTP 422).

    Renamed from ``InsufficientWrapsError`` to disambiguate from the HTTP
    transport-layer ``api_client.InsufficientWrapsError``. ``InsufficientWrapsError``
    remains as a backwards-compatible alias.

    The caller should refresh member pubkeys and retry.

    Attributes:
        missing: List of ``MissingWrap`` describing which
            ``(envelope_id, recipient_user_id)`` pairs are absent.
    """

    def __init__(self, missing: List["MissingWrap"]) -> None:
        self.missing = missing
        pairs = [(m.envelope_id, m.recipient_user_id) for m in missing]
        super().__init__(f"Insufficient wraps — missing {len(pairs)} wrap(s): {pairs}")


# Backwards-compatible alias so existing imports keep working.
InsufficientWrapsError = InsufficientWrapsRequired


# ---------------------------------------------------------------------------
# Data transfer objects
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TeamMemberKey:
    """A team member's active public key.

    Attributes:
        user_id: Numeric user ID of the team member.
        fingerprint: 64-char hex SHA-256 of the public key.
        public_key_b64: Base64-encoded raw 32-byte X25519 public key.
        role: Member's role in the team (``"owner"`` | ``"admin"`` | ``"member"`` | ``"viewer"``).
    """

    user_id: int
    fingerprint: str
    public_key_b64: str
    role: str

    @property
    def public_key_bytes(self) -> bytes:
        """Decode and return the raw 32-byte X25519 public key."""
        return base64.b64decode(self.public_key_b64)


@dataclass(frozen=True)
class Grant:
    """A team memory sharing grant.

    Attributes:
        id: Server-assigned grant UUID.
        instance_id: The shared instance identifier.
        required_role: Minimum team role required to read.
        modules: Module whitelist (``None`` means all modules).
        status: ``"active"`` | ``"revoked"``.
        granted_by_user_id: Numeric user ID of the granter.
        created_at: Grant creation timestamp.
        revoked_at: Revocation timestamp, or ``None`` if still active.
    """

    id: str
    instance_id: str
    required_role: str
    modules: Optional[List[str]]
    status: str
    granted_by_user_id: int
    created_at: datetime
    revoked_at: Optional[datetime]


@dataclass(frozen=True)
class SharedInstance:
    """A team-shared instance as returned by the list endpoint.

    Attributes:
        grant: The grant that authorises access.
        instance: Raw instance dict from the server.
        readable_modules: Module names the caller can actually decrypt.
    """

    grant: Grant
    instance: Dict[str, Any]
    readable_modules: List[str]


@dataclass(frozen=True)
class WrapEntry:
    """A per-member DEK wrap to be submitted in a grant request.

    Attributes:
        recipient_user_id: Numeric user ID of the wrap recipient.
        envelope_id: UUID of the envelope the DEK belongs to.
        wrapped_dek: Base64-encoded SealedBox-encrypted DEK.
    """

    recipient_user_id: int
    envelope_id: str
    wrapped_dek: str


@dataclass(frozen=True)
class MissingWrap:
    """Describes a missing DEK wrap from a server ``insufficient_wraps`` response.

    Attributes:
        envelope_id: The envelope that needs a wrap for the recipient.
        recipient_user_id: The user ID that must receive the wrap.
    """

    envelope_id: str
    recipient_user_id: int


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class TeamMemoryService:
    """Client for the team memory API endpoints (spec §4).

    All methods are tier-gated on ``memory_team_share``.  The team's owner
    must carry this entitlement — individual members do not need their own
    Teams subscription to read shared instances.

    **Crypto flow for ``share_instance``:**
    1. Fetch existing envelopes for the instance via ``retrieval_service``.
    2. For each envelope, obtain the DEK by calling ``key_store_provider()``
       to get the active key material, then use ``crypto.decrypt_envelope``
       to unwrap the DEK.
    3. For each eligible team member (filtered by role), re-wrap the DEK
       with the member's public key using PyNaCl ``SealedBox``.
    4. POST the full wraps array to the grant endpoint.

    Args:
        api_client: Authenticated API client.
        auth_service: Auth service (used for entitlement checks).
        crypto: Crypto module (``servonaut.services.memory.crypto``).
        key_store_provider: Callable returning the active ``KeyMaterial``.
        retrieval_service: Duck-typed retrieval service (see module docstring).
    """

    _FEATURE = "memory_team_share"

    # Role ordering for minimum-role filtering
    _ROLE_ORDER: Dict[str, int] = {
        "viewer": 0,
        "member": 1,
        "admin": 2,
        "owner": 3,
    }

    def __init__(
        self,
        api_client: "APIClient",
        auth_service: "AuthService",
        crypto: Any,
        key_store_provider: Callable[[], Any],
        retrieval_service: Any,
    ) -> None:
        self._api = api_client
        self._auth = auth_service
        self._crypto = crypto
        self._key_store_provider = key_store_provider
        self._retrieval_service = retrieval_service

    # ------------------------------------------------------------------
    # Entitlement gate helper
    # ------------------------------------------------------------------

    def _require_feature(self) -> None:
        """Raise ``UpsellRequired`` if the user is not entitled."""
        if not self._auth.has_feature(self._FEATURE):
            raise UpsellRequired(self._FEATURE)

    # ------------------------------------------------------------------
    # API methods
    # ------------------------------------------------------------------

    async def list_team_member_keys(self, team_slug: str) -> List[TeamMemberKey]:
        """Fetch the active public keys of all team members with a keypair.

        Members without an active keypair are silently omitted by the server.

        Args:
            team_slug: Team slug identifier.

        Returns:
            List of ``TeamMemberKey`` for each member that has enrolled.

        Raises:
            UpsellRequired: If ``memory_team_share`` is not in the plan.
            BackendMaintenance: On 503.
        """
        self._require_feature()
        try:
            data = await self._api.get(f"/api/v1/memory/keys/team/{team_slug}")
        except Exception as exc:
            raise _translate_api_error(exc, team_slug=team_slug) from exc

        members = []
        for item in data.get("members", []):
            members.append(
                TeamMemberKey(
                    user_id=int(item["user_id"]),
                    fingerprint=item["fingerprint"],
                    public_key_b64=item["public_key_b64"],
                    role=item["role"],
                )
            )
        return members

    async def list_shared_instances(self, team_slug: str) -> List[SharedInstance]:
        """List instances shared with the caller through this team.

        Results are filtered server-side to grants where the caller's role
        >= ``required_role`` and the caller has at least one readable wrap.

        Args:
            team_slug: Team slug identifier.

        Returns:
            List of ``SharedInstance`` visible to the caller.

        Raises:
            UpsellRequired: If ``memory_team_share`` is not in the plan.
            BackendMaintenance: On 503.
        """
        self._require_feature()
        try:
            data = await self._api.get(f"/api/v1/teams/{team_slug}/memory")
        except Exception as exc:
            raise _translate_api_error(exc, team_slug=team_slug) from exc

        result = []
        for item in data.get("instances", []):
            grant = _parse_grant(item["grant"])
            result.append(
                SharedInstance(
                    grant=grant,
                    instance=item.get("instance", {}),
                    readable_modules=item.get("readable_modules", []),
                )
            )
        return result

    async def read_team_envelope(
        self,
        team_slug: str,
        instance_id: str,
        module: str,
    ) -> Dict[str, Any]:
        """Fetch the latest team envelope for a module.

        Returns the canonical envelope shape plus ``grant_id`` and
        ``required_role`` (spec §4.2 / §3.7).

        Args:
            team_slug: Team slug identifier.
            instance_id: Instance identifier.
            module: Module name (e.g. ``"os"``).

        Returns:
            Raw envelope dict from the server.

        Raises:
            UpsellRequired: If ``memory_team_share`` is not in the plan.
            BackendMaintenance: On 503.
        """
        self._require_feature()
        try:
            return await self._api.get(
                f"/api/v1/teams/{team_slug}/memory/{instance_id}/{module}"
            )
        except Exception as exc:
            raise _translate_api_error(exc, team_slug=team_slug) from exc

    async def share_instance(
        self,
        team_slug: str,
        instance_id: str,
        required_role: str,
        modules: Optional[List[str]],
        member_pubkeys: List[TeamMemberKey],
    ) -> Grant:
        """Share an instance with team members, re-wrapping all DEKs internally.

        DEK material never leaves this method.  The flow is:
        1. Tier-gate.
        2. Fetch all existing envelope stubs via ``retrieval_service``.
        3. For each envelope, decrypt to obtain the raw DEK using the active
           key material from ``key_store_provider()``.
        4. Filter members to those whose role >= ``required_role``.
        5. For each eligible member × envelope: wrap DEK with member's pubkey.
        6. POST grant with all wraps.
        7. On ``InsufficientWrapsError``: re-raise typed exception so the
           caller can refresh pubkeys and retry once.
        8. On ``GrantExistsError`` (409): re-raise as ``GrantAlreadyExistsError``.

        Args:
            team_slug: Team slug identifier.
            instance_id: Instance identifier (must be owned by caller).
            required_role: Minimum role for members to read the grant
                (``"viewer"`` | ``"member"`` | ``"admin"`` | ``"owner"``).
            modules: Module whitelist, or ``None`` for all modules.
            member_pubkeys: List of ``TeamMemberKey`` for eligible members.

        Returns:
            The created ``Grant``.

        Raises:
            UpsellRequired: If ``memory_team_share`` is not in the plan.
            InsufficientWrapsError: If the server reports missing wraps.
            GrantAlreadyExistsError: If a live grant already exists for
                ``(team, instance)``.
            BackendMaintenance: On 503.
        """
        self._require_feature()

        # Spec §3.2: GET /memory/{instance_id} returns
        # {"instance": ..., "modules": ["os", "runtimes", ...]}  — strings, not dicts.
        # Each envelope_id is resolved per-module via get_module_envelope_raw inside _build_wraps.
        module_list_data = await self._retrieval_service.list_instance_modules(instance_id)
        raw_modules = module_list_data.get("modules", []) or []
        module_names: List[str] = [m for m in raw_modules if isinstance(m, str)]

        required_order = self._ROLE_ORDER.get(required_role, 0)
        eligible_members = [
            m for m in member_pubkeys
            if self._ROLE_ORDER.get(m.role, 0) >= required_order
        ]

        if not module_names or not eligible_members:
            wraps: List[Dict[str, Any]] = []
        else:
            key_material = self._key_store_provider()
            wraps = await self._build_wraps(
                instance_id=instance_id,
                module_names=module_names,
                eligible_members=eligible_members,
                key_material=key_material,
            )

        body: Dict[str, Any] = {
            "instance_id": instance_id,
            "required_role": required_role,
            "modules": modules,
            "wraps": wraps,
        }

        try:
            data = await self._api.post(
                f"/api/v1/teams/{team_slug}/memory/grant",
                json=body,
            )
        except Exception as exc:
            raise _translate_api_error(exc, team_slug=team_slug, instance_id=instance_id) from exc

        return _parse_grant(data)

    async def _build_wraps(
        self,
        instance_id: str,
        module_names: List[str],
        eligible_members: List[TeamMemberKey],
        key_material: Any,
    ) -> List[Dict[str, Any]]:
        """Build the wraps array for a grant request.

        For each module, fetches the raw envelope from the server (which
        carries the canonical envelope_id), unwraps the DEK addressed to
        the caller, then re-wraps that DEK to every eligible team member.
        DEK material never leaves this service — only the per-recipient
        sealed-box ciphertext is returned to the caller.

        Args:
            instance_id: Target instance identifier.
            module_names: Module names returned by spec §3.2 (e.g. ``["os", "services"]``).
            eligible_members: Members who should receive wraps.
            key_material: Active key material (has ``.private_key``, ``.public_key``,
                ``.user_id`` attributes).

        Returns:
            List of wrap dicts for the grant POST body.
        """
        wraps: List[Dict[str, Any]] = []

        for module_name in module_names:
            if not module_name:
                continue

            # Fetch the raw (encrypted) envelope from the server
            try:
                raw_env = await self._retrieval_service.get_module_envelope_raw(
                    instance_id, module_name
                )
            except Exception as exc:
                logger.warning(
                    "Could not fetch envelope for %r/%r: %s — skipping",
                    instance_id, module_name, exc
                )
                continue

            actual_env_id = raw_env.get("id")
            if not actual_env_id:
                logger.warning(
                    "Server envelope for %r/%r is missing 'id' — skipping",
                    instance_id, module_name,
                )
                continue

            try:
                dek_raw = self._unwrap_dek(raw_env, key_material)
            except Exception as exc:
                logger.warning(
                    "Could not unwrap DEK for %r/%r: %s — skipping",
                    instance_id, module_name, exc
                )
                continue

            # Wrap the DEK for each eligible member
            for member in eligible_members:
                try:
                    member_pk = nacl.public.PublicKey(member.public_key_bytes)
                    sealed = nacl.public.SealedBox(member_pk).encrypt(dek_raw)
                    wraps.append({
                        "recipient_user_id": member.user_id,
                        "envelope_id": actual_env_id,
                        "wrapped_dek": base64.b64encode(sealed).decode(),
                    })
                except Exception as exc:
                    logger.warning(
                        "Failed to wrap DEK for member %d: %s — skipping",
                        member.user_id, exc
                    )

        return wraps

    def _unwrap_dek(self, raw_env: Dict[str, Any], key_material: Any) -> bytes:
        """Extract the raw 32-byte DEK from an envelope's dek_wraps.

        Uses PyNaCl SealedBox to unwrap the DEK addressed to the caller.

        Args:
            raw_env: Raw envelope dict from the server (§3.7 shape).
            key_material: Active key material with ``.user_id``,
                ``.private_key``.

        Returns:
            Raw 32-byte AES DEK.

        Raises:
            KeyError: If no self-wrap is found.
            nacl.exceptions.CryptoError: On decryption failure.
        """
        import base64 as _b64
        user_id = key_material.user_id

        # §3.7 shape: single wrapped_dek pre-addressed to caller
        if "wrapped_dek" in raw_env:
            wrapped_b64 = raw_env["wrapped_dek"]
        elif "dek_wraps" in raw_env:
            wrapped_b64 = None
            for wrap in raw_env["dek_wraps"]:
                if wrap.get("recipient_user_id") == user_id:
                    wrapped_b64 = wrap["wrapped_dek"]
                    break
            if wrapped_b64 is None:
                raise KeyError(f"No self-wrap found for user_id={user_id}")
        else:
            raise KeyError("Envelope has neither 'wrapped_dek' nor 'dek_wraps'")

        wrapped_bytes = _b64.b64decode(wrapped_b64)
        priv_key = nacl.public.PrivateKey(key_material.private_key)
        box = nacl.public.SealedBox(priv_key)
        dek = box.decrypt(wrapped_bytes)
        return dek

    async def revoke_grant(self, team_slug: str, grant_id: str) -> Grant:
        """Soft-revoke a team memory grant.

        Existing wraps are preserved (members can still decrypt) until
        ``purge_grant`` is called.

        Args:
            team_slug: Team slug identifier.
            grant_id: Grant UUID to revoke.

        Returns:
            Updated ``Grant`` with ``status="revoked"`` and ``revoked_at`` set.

        Raises:
            UpsellRequired: If ``memory_team_share`` is not in the plan.
            BackendMaintenance: On 503.
        """
        self._require_feature()
        try:
            data = await self._api.delete(
                f"/api/v1/teams/{team_slug}/memory/grant/{grant_id}"
            )
        except Exception as exc:
            raise _translate_api_error(exc, team_slug=team_slug) from exc
        return _parse_grant(data)

    async def purge_grant(self, team_slug: str, grant_id: str) -> int:
        """Hard-delete all non-granter DEK wraps for a revoked grant.

        After purge, team members get ``404 access_revoked`` on next read.

        Args:
            team_slug: Team slug identifier.
            grant_id: Grant UUID to purge.

        Returns:
            Number of wraps deleted (``wraps_deleted`` from server response).

        Raises:
            UpsellRequired: If ``memory_team_share`` is not in the plan.
            BackendMaintenance: On 503.
        """
        self._require_feature()
        try:
            data = await self._api.post(
                f"/api/v1/teams/{team_slug}/memory/grant/{grant_id}/purge",
                json=None,
            )
        except Exception as exc:
            raise _translate_api_error(exc, team_slug=team_slug) from exc
        return int(data.get("wraps_deleted", 0))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_grant(data: Dict[str, Any]) -> Grant:
    """Parse a raw server grant dict into a ``Grant`` dataclass."""
    revoked_raw = data.get("revoked_at")
    return Grant(
        id=data["id"],
        instance_id=data["instance_id"],
        required_role=data["required_role"],
        modules=data.get("modules"),
        status=data.get("status", "active"),
        granted_by_user_id=int(data.get("granted_by_user_id", 0)),
        created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")),
        revoked_at=(
            datetime.fromisoformat(revoked_raw.replace("Z", "+00:00"))
            if revoked_raw
            else None
        ),
    )


def _translate_api_error(
    exc: Exception,
    team_slug: str = "",
    instance_id: str = "",
) -> Exception:
    """Translate an ``APIError`` into a typed domain exception."""
    from servonaut.services.api_client import (
        APIError,
        ForbiddenEntitlementError,
        FeatureNotAvailableError,
        FeatureDisabledError,
        ValidationFailedError,
        InsufficientWrapsError as APIInsufficientWrapsError,
        GrantExistsError,
    )

    if not isinstance(exc, APIError):
        return exc

    if isinstance(exc, ForbiddenEntitlementError):
        return UpsellRequired("memory_team_share")
    if isinstance(exc, FeatureNotAvailableError):
        return BetaWaitlist()
    if isinstance(exc, FeatureDisabledError):
        return BackendMaintenance()
    if isinstance(exc, ValidationFailedError):
        errors = []
        if exc.details:
            errors = exc.details.get("errors", [])
        return ValidationFailed(errors)
    if isinstance(exc, APIInsufficientWrapsError):
        missing_raw = exc.missing  # list of {envelope_id, recipient_user_id}
        missing = [
            MissingWrap(
                envelope_id=m["envelope_id"],
                recipient_user_id=int(m["recipient_user_id"]),
            )
            for m in missing_raw
        ]
        return InsufficientWrapsError(missing)
    if isinstance(exc, GrantExistsError):
        return GrantAlreadyExistsError(team_slug=team_slug, instance_id=instance_id)
    return exc
