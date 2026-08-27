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

import asyncio
import logging
import math
from dataclasses import dataclass
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
        previous_summary_id: Stable envelope id that was latest at dispatch.
        queued_at: Server timestamp for the accepted job.
        poll_after_seconds: Initial server-recommended polling delay.
        correlation_supported: Whether the response included the atomic
            ``previous_summary_id`` correlation field.
    """

    status: str
    message: str
    previous_summary_id: Optional[str] = None
    queued_at: str = ""
    poll_after_seconds: Optional[float] = None
    correlation_supported: bool = False


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
            previous_summary_id = data.get("previous_summary_id")
            if previous_summary_id is not None:
                previous_summary_id = str(previous_summary_id)
            poll_after_seconds = data.get("poll_after_seconds")
            try:
                poll_after_seconds = float(poll_after_seconds)
            except (TypeError, ValueError):
                poll_after_seconds = None
            return SummaryDispatchResult(
                status=data.get("status", "queued"),
                message=data.get("message", ""),
                previous_summary_id=previous_summary_id,
                queued_at=str(data.get("queued_at", "") or ""),
                poll_after_seconds=poll_after_seconds,
                correlation_supported="previous_summary_id" in data,
            )
        except Exception as exc:
            raise _translate_api_error(exc) from exc

    async def get_latest_summary(
        self,
        instance_id: str,
        *,
        after: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch the latest AI summary envelope or correlation-pending status.

        Args:
            instance_id: Target instance identifier.
            after: Optional stable envelope id returned by dispatch. When set,
                the backend returns a pending status until a different envelope
                is latest.

        Returns:
            The raw envelope dict, a pending-status dict when ``after`` is
            unchanged, or ``None`` when plain latest returns 404.
        """
        self._require_feature()
        try:
            path = f"/api/v1/memory/summary/{instance_id}/latest"
            if after is None:
                return await self._api.get(path)
            return await self._api.get(path, params={"after": after})
        except Exception as exc:
            from servonaut.services.api_client import NotFoundError
            if isinstance(exc, NotFoundError):
                return None
            raise _translate_api_error(exc) from exc

    async def wait_for_new_summary(
        self,
        instance_id: str,
        previous_envelope_id: Optional[str] = None,
        initial_poll_after_seconds: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """Poll until a newly generated summary envelope is available.

        Poll cadence and timeout come from config.memory. A prior stable
        envelope id prevents an older cached result from being mistaken for
        the request that was just dispatched.

        Returns:
            The new raw encrypted envelope, or None when the configured
            timeout elapses.
        """
        from servonaut.config.schema import (
            DEFAULT_AI_SUMMARY_POLL_INTERVAL_SECONDS,
            DEFAULT_AI_SUMMARY_POLL_TIMEOUT_SECONDS,
        )

        memory_config = self._config_manager.get().memory
        try:
            poll_interval = float(memory_config.ai_summary_poll_interval_seconds)
        except (AttributeError, TypeError, ValueError):
            poll_interval = DEFAULT_AI_SUMMARY_POLL_INTERVAL_SECONDS
        if not math.isfinite(poll_interval) or poll_interval <= 0:
            poll_interval = DEFAULT_AI_SUMMARY_POLL_INTERVAL_SECONDS
        poll_interval = max(0.1, poll_interval)

        try:
            timeout = float(memory_config.ai_summary_poll_timeout_seconds)
        except (AttributeError, TypeError, ValueError):
            timeout = DEFAULT_AI_SUMMARY_POLL_TIMEOUT_SECONDS
        if not math.isfinite(timeout) or timeout <= 0:
            timeout = DEFAULT_AI_SUMMARY_POLL_TIMEOUT_SECONDS
        timeout = max(poll_interval, timeout)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        next_delay = 0.0
        if initial_poll_after_seconds is not None:
            try:
                next_delay = float(initial_poll_after_seconds)
            except (TypeError, ValueError):
                next_delay = poll_interval
            if not math.isfinite(next_delay) or next_delay <= 0:
                next_delay = poll_interval

        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            if next_delay > 0:
                await asyncio.sleep(min(next_delay, remaining))
                if deadline - loop.time() <= 0:
                    return None

            latest = await self.get_latest_summary(
                instance_id,
                after=previous_envelope_id,
            )
            next_delay = poll_interval
            if latest is None:
                continue
            if latest.get("status") == "pending":
                pending_previous_id = latest.get("previous_summary_id")
                if (
                    previous_envelope_id is not None
                    and pending_previous_id is not None
                    and str(pending_previous_id) != previous_envelope_id
                ):
                    raise MemoryBackendError(
                        "Hosted summary pending response has a mismatched envelope id"
                    )
                try:
                    suggested_delay = float(latest.get("poll_after_seconds"))
                except (TypeError, ValueError):
                    suggested_delay = poll_interval
                if math.isfinite(suggested_delay) and suggested_delay > 0:
                    next_delay = suggested_delay
                continue

            latest_id = str(latest.get("id", "") or "")
            if not latest_id:
                raise MemoryBackendError(
                    "Hosted summary response has no stable envelope id"
                )
            if previous_envelope_id is None or latest_id != previous_envelope_id:
                return latest


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
