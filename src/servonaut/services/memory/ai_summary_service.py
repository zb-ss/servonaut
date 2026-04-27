"""AI summary service for the server memory subsystem.

Provides tier-gated access to the server-side AI summary pipeline.

Spec coverage:
- §3.6  GET  /api/v1/memory/ai-provider-info
- §3.6  POST /api/v1/memory/summary/{instance_id}/consent
- §3.6  POST /api/v1/memory/summary/{instance_id}
- §3.6  GET  /api/v1/memory/summary/{instance_id}/latest

**Hard rule from spec §3.6 (must be enforced in this module):**
The CLI MUST show ``retention_text`` verbatim to the user before issuing any
consent token request.  ``confirm_provider_disclosure_shown(instance_id)``
MUST be called first; if it is not, ``request_consent_token`` raises
``ConsentNotConfirmedError``.

Rate limits (mirrored client-side):
- ``request_consent_token`` and ``dispatch_summary``: 5/min (``RateLimitKey.SUMMARY``)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING

from servonaut.services.memory.interfaces import (
    BackendMaintenance,
    BetaWaitlist,
    MemoryBackendError,
    UpsellRequired,
    ValidationFailed,
)
from servonaut.services.memory.rate_limiter import RateLimitKey, RateLimiter

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient
    from servonaut.services.auth_service import AuthService
    from servonaut.config.manager import ConfigManager

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class ConsentNotConfirmedError(MemoryBackendError):
    """Raised when ``request_consent_token`` is called before
    ``confirm_provider_disclosure_shown`` for the same instance_id.

    Per spec §3.6, the CLI must display ``retention_text`` verbatim before
    the consent call.  This exception enforces that contract in code.
    """

    def __init__(self, instance_id: str) -> None:
        self.instance_id = instance_id
        super().__init__(
            f"Provider disclosure has not been confirmed for instance {instance_id!r}. "
            "Call confirm_provider_disclosure_shown(instance_id) after showing "
            "the provider's retention_text to the user."
        )


# ---------------------------------------------------------------------------
# Data transfer objects
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProviderInfo:
    """Information about the AI provider handling summaries.

    Attributes:
        provider_name: Human-readable provider name (e.g. ``"Anthropic"``).
        retention_days: How long the provider retains request data.
        retention_text: Verbatim text that MUST be shown to the user before
            requesting a consent token.
        supports_zdr: Whether the provider supports zero-data-retention.
    """

    provider_name: str
    retention_days: int
    retention_text: str
    supports_zdr: bool


@dataclass(frozen=True)
class ConsentToken:
    """A short-lived consent JWT returned by the consent endpoint.

    Attributes:
        token: Raw JWT string.
        expires_at: Expiry timestamp.
        mode: Summary mode — ``"server_60s"`` | ``"client"`` | ``"off"``.
        modules: Module whitelist for this consent scope.
    """

    token: str
    expires_at: datetime
    mode: str
    modules: List[str]


@dataclass(frozen=True)
class SummaryDispatchResult:
    """Result returned by the summary dispatch endpoint (POST /summary/{id}).

    Attributes:
        status: Server-reported status (e.g. ``"queued"``).
        message: Human-readable message from the server.
    """

    status: str
    message: str


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class AISummaryService:
    """Client for the AI summary API endpoints (spec §3.6).

    All methods are tier-gated on ``memory_ai_summary``.  Callers that are
    on a plan without this entitlement will receive ``UpsellRequired`` rather
    than a network error.

    **Consent gate**:
    ``request_consent_token`` MUST NOT be called until
    ``confirm_provider_disclosure_shown(instance_id)`` has been invoked for
    the same ``instance_id`` in the current process lifetime.  The disclosure
    state is in-memory only — it is cleared on process exit, which is
    intentional (the user must confirm anew each session).

    Args:
        api_client: Authenticated API client.
        rate_limiter: Shared rate limiter instance.
        auth_service: Auth service (used for entitlement checks).
        config_manager: Application configuration manager.
    """

    _FEATURE = "memory_ai_summary"

    def __init__(
        self,
        api_client: "APIClient",
        rate_limiter: RateLimiter,
        auth_service: "AuthService",
        config_manager: "ConfigManager",
    ) -> None:
        self._api = api_client
        self._rate_limiter = rate_limiter
        self._auth = auth_service
        self._config_manager = config_manager
        # In-memory set of instance IDs for which the disclosure has been
        # shown and confirmed.  Cleared on process exit.
        self._disclosure_confirmed: Set[str] = set()

    # ------------------------------------------------------------------
    # Entitlement gate helper
    # ------------------------------------------------------------------

    def _require_feature(self) -> None:
        """Raise ``UpsellRequired`` if the user is not entitled to this feature."""
        if not self._auth.has_feature(self._FEATURE):
            raise UpsellRequired(self._FEATURE)

    # ------------------------------------------------------------------
    # Disclosure confirmation
    # ------------------------------------------------------------------

    def confirm_provider_disclosure_shown(self, instance_id: str) -> None:
        """Mark that the provider retention disclosure has been shown to the user.

        This MUST be called (after displaying ``ProviderInfo.retention_text``
        verbatim) before ``request_consent_token`` for the same ``instance_id``.

        Args:
            instance_id: The target instance identifier.
        """
        self._disclosure_confirmed.add(instance_id)
        logger.debug("AI provider disclosure confirmed for instance %r", instance_id)

    # ------------------------------------------------------------------
    # API methods
    # ------------------------------------------------------------------

    async def get_provider_info(self) -> ProviderInfo:
        """Fetch AI provider information.

        Returns:
            A ``ProviderInfo`` describing the provider, retention policy, and ZDR support.

        Raises:
            UpsellRequired: If ``memory_ai_summary`` is not in the user's plan.
            BetaWaitlist: If the feature exists but the user is not on the beta list.
            BackendMaintenance: If the server returns 503 (kill-switch active).
        """
        self._require_feature()
        try:
            data = await self._api.get("/api/v1/memory/ai-provider-info")
            return ProviderInfo(
                provider_name=data["provider_name"],
                retention_days=int(data["retention_days"]),
                retention_text=data["retention_text"],
                supports_zdr=bool(data.get("supports_zdr", False)),
            )
        except Exception as exc:
            raise _translate_api_error(exc) from exc

    async def request_consent_token(
        self,
        instance_id: str,
        mode: str,
        modules: Optional[List[str]] = None,
        *,
        provider_ack: bool = True,
    ) -> ConsentToken:
        """Request a short-lived consent token for AI summary.

        ``confirm_provider_disclosure_shown(instance_id)`` MUST be called
        before this method; otherwise ``ConsentNotConfirmedError`` is raised.

        Args:
            instance_id: Target instance identifier.
            mode: Summary mode — ``"server_60s"`` | ``"client"`` | ``"off"``.
            modules: Optional module whitelist.  ``None`` means all modules.
            provider_ack: Must be ``True`` — the backend rejects without it.

        Returns:
            A ``ConsentToken`` valid until ``expires_at``.

        Raises:
            ConsentNotConfirmedError: If disclosure has not been confirmed.
            UpsellRequired: If the plan doesn't include ``memory_ai_summary``.
            BetaWaitlist: If not on the beta allowlist.
            BackendMaintenance: On 503.
            ValidationFailed: On 422 with per-field errors.
        """
        self._require_feature()
        if instance_id not in self._disclosure_confirmed:
            raise ConsentNotConfirmedError(instance_id)

        await self._rate_limiter.acquire(RateLimitKey.SUMMARY)

        body: Dict[str, Any] = {
            "mode": mode,
            "provider_ack": provider_ack,
        }
        if modules is not None:
            body["modules"] = modules

        try:
            data = await self._api.post(
                f"/api/v1/memory/summary/{instance_id}/consent",
                json=body,
            )
            return ConsentToken(
                token=data["token"],
                expires_at=datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")),
                mode=data["mode"],
                modules=data.get("modules") or [],
            )
        except Exception as exc:
            raise _translate_api_error(exc) from exc

    async def dispatch_summary(
        self,
        instance_id: str,
        consent_token: str,
        mode: str,
        passphrase: str,
    ) -> SummaryDispatchResult:
        """Dispatch an AI summary request to the server.

        The passphrase is sent to the server so it can unwrap the private key
        server-side for the 60-second window.  The server ``sodium_memzero``s
        it after the worker runs.

        Args:
            instance_id: Target instance identifier.
            consent_token: JWT from ``request_consent_token``.
            mode: Summary mode — must match the consent token's mode.
            passphrase: User passphrase (for server-side key unwrap).

        Returns:
            A ``SummaryDispatchResult`` with status and message.

        Raises:
            ConsentNotConfirmedError: If disclosure was not shown for ``instance_id``
                this session — protects against headless replay of a cached token.
            UpsellRequired: If the plan doesn't include ``memory_ai_summary``.
            BackendMaintenance: On 503.
            ValidationFailed: On 422.
        """
        self._require_feature()
        if instance_id not in self._disclosure_confirmed:
            raise ConsentNotConfirmedError(instance_id)
        await self._rate_limiter.acquire(RateLimitKey.SUMMARY)

        try:
            data = await self._api.post(
                f"/api/v1/memory/summary/{instance_id}",
                json={
                    "consent_token": consent_token,
                    "mode": mode,
                    "passphrase": passphrase,
                },
                retry_on_401=False,
            )
            return SummaryDispatchResult(
                status=data.get("status", "queued"),
                message=data.get("message", ""),
            )
        except Exception as exc:
            raise _translate_api_error(exc) from exc

    async def get_latest_summary(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Fetch the latest AI summary envelope for an instance.

        Args:
            instance_id: Target instance identifier.

        Returns:
            The raw envelope dict from the server, or ``None`` if no summary
            has been generated yet (server returns 404 not_found).

        Raises:
            UpsellRequired: If the plan doesn't include ``memory_ai_summary``.
            BackendMaintenance: On 503.
        """
        self._require_feature()
        try:
            data = await self._api.get(
                f"/api/v1/memory/summary/{instance_id}/latest"
            )
            return data
        except Exception as exc:
            from servonaut.services.api_client import NotFoundError
            if isinstance(exc, NotFoundError):
                return None
            raise _translate_api_error(exc) from exc


# ---------------------------------------------------------------------------
# Error translation helper
# ---------------------------------------------------------------------------

def _translate_api_error(exc: Exception) -> Exception:
    """Translate an ``APIError`` into a domain exception.

    Leaves non-API errors untouched so they propagate as-is.
    """
    from servonaut.services.api_client import (
        APIError,
        ForbiddenEntitlementError,
        FeatureNotAvailableError,
        FeatureDisabledError,
        ValidationFailedError,
        NotFoundError,
    )

    if not isinstance(exc, APIError):
        return exc

    if isinstance(exc, ForbiddenEntitlementError):
        return UpsellRequired("memory_ai_summary")
    if isinstance(exc, FeatureNotAvailableError):
        return BetaWaitlist()
    if isinstance(exc, FeatureDisabledError):
        return BackendMaintenance()
    if isinstance(exc, ValidationFailedError):
        errors = []
        if exc.details:
            errors = exc.details.get("errors", [])
        return ValidationFailed(errors)
    # Not-found is handled at call site; pass through here
    return exc
