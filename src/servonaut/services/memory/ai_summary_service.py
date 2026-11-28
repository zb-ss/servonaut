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
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, TYPE_CHECKING

from servonaut.services.memory.interfaces import (
    BackendMaintenance,
    BetaWaitlist,
    MemoryBackendError,
    UpsellRequired,
    ValidationFailed,
)
from servonaut.services.memory.rate_limiter import RateLimitKey, RateLimiter
from servonaut.services.memory.retrieval_service import StaleEnvelopes

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


class SummaryFailed(MemoryBackendError):
    """The service reported the hosted summary job as failed.

    Attributes:
        reason: The service's failure code. For logs only; people read
            :func:`summary_error_message`.
    """

    def __init__(self, reason: str = "") -> None:
        self.reason = reason
        super().__init__("summary_failed")


class HostedSummaryUnavailable(MemoryBackendError):
    """A key kept in the vault cannot be used for hosted summaries on this service yet."""

    def __init__(self) -> None:
        super().__init__("hosted_summary_unavailable")


# Small on purpose: the service's failure codes are not final.
_FAILURE_REASON_TEXT = {
    "request_expired": "the request expired before it could run",
    "consent_invalid": "your consent was no longer valid",
    "account_suspended": "your account is suspended",
    "balance_exhausted": "your AI balance ran out",
    "passphrase_invalid": "the passphrase did not open your Memory Sync key",
    "memory_key_custody_vault": "your Memory Sync key is kept in your vault and could not be used this way",
    "no_active_key": "no active Memory Sync key was found",
    "nothing_to_summarise": "there is no memory to summarise yet",
    "dek_invalid": "the memory could not be opened with the keys that were sent",
    "decryption_failed": "the memory could not be opened with the keys that were sent",
    "stale_envelopes": "the memory changed while the summary was being prepared",
    "provider_error": "the AI provider reported a problem",
    "internal_error": "the service had a problem",
}
_FAILURE_REASON_FALLBACK = "the service reported a problem"
_HOSTED_UNAVAILABLE_TEXT = (
    "Hosted summaries are not available for a key kept in the vault on this "
    "Servonaut service yet. Try again later."
)
_MAX_LOGGED_REASON = 64
# Modules besides the probers that carry synced memory (notes and findings).
_EXTRA_MODULES = frozenset({"annotations", "findings"})


def summary_error_message(exc: BaseException) -> Optional[str]:
    """The text to show for a hosted-summary failure, or ``None`` for any other error.

    Never includes a raw service code or service-provided text.
    """
    if isinstance(exc, SummaryFailed):
        reason = _FAILURE_REASON_TEXT.get(exc.reason, _FAILURE_REASON_FALLBACK)
        return f"The summary could not be created ({reason})."
    if isinstance(exc, HostedSummaryUnavailable):
        return _HOSTED_UNAVAILABLE_TEXT
    from servonaut.services.memory.custody_errors import custody_error_message

    return custody_error_message(exc)


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
        envelope_ids: Newest envelope id per module the summary covers; empty
            for a service that does not list them.
    """

    token: str
    expires_at: datetime
    mode: str
    modules: List[str]
    envelope_ids: Dict[str, str] = field(default_factory=dict)


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
                envelope_ids=_parse_envelope_ids(data.get("envelope_ids")),
            )
        except Exception as exc:
            raise _translate_api_error(exc) from exc

    async def dispatch_summary(
        self,
        instance_id: str,
        consent_token: str,
        mode: str,
        *,
        envelope_keys: Optional[List[Dict[str, str]]] = None,
        passphrase: Optional[str] = None,
    ) -> SummaryDispatchResult:
        """Dispatch an AI summary request to the server.

        Exactly one of ``envelope_keys`` (the data key of each consented
        envelope) or ``passphrase`` (the legacy form: the service unwraps the
        private key itself) is sent. Neither is retried on a token refresh, so
        a secret is never sent twice by the client itself.

        Args:
            instance_id: Target instance identifier.
            consent_token: JWT from ``request_consent_token`` (``.token``).
            mode: Summary mode, which must match the consent token's mode.
            envelope_keys: ``[{"envelope_id", "dek"}]``, ``dek`` base64.
            passphrase: Memory Sync passphrase (legacy form).

        Raises:
            ValueError: If not exactly one of the two is given.
            ConsentNotConfirmedError: If disclosure was not shown for ``instance_id``
                this session — protects against headless replay of a cached token.
            UpsellRequired: If the plan doesn't include ``memory_ai_summary``.
            BackendMaintenance: On 503.
            ValidationFailed: On 422.
        """
        if (envelope_keys is None) == (passphrase is None):
            raise ValueError("Send exactly one of envelope_keys and passphrase")
        self._require_feature()
        if instance_id not in self._disclosure_confirmed:
            raise ConsentNotConfirmedError(instance_id)
        await self._rate_limiter.acquire(RateLimitKey.SUMMARY)

        body: Dict[str, Any] = {"consent_token": consent_token, "mode": mode}
        if envelope_keys is not None:
            body["envelope_keys"] = envelope_keys
        else:
            body["passphrase"] = passphrase

        try:
            data = await self._api.post(
                f"/api/v1/memory/summary/{instance_id}",
                json=body,
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

    async def run_summary(
        self,
        instance_id: str,
        *,
        retrieval: Any,
        key_source: Callable[[], Optional[str]],
        passphrase_provider: Callable[[], Awaitable[str]],
        mode: str = "server_60s",
        modules: Optional[List[str]] = None,
    ) -> SummaryDispatchResult:
        """Ask for consent and dispatch a hosted summary; the order lives here.

        1. A consent that lists ``envelope_ids`` is answered with the keys of
           exactly those envelopes (any custody; Memory Sync must be unlocked).
        2. A stale answer (``stale_envelopes`` or a vanished envelope) asks for
           consent again and retries once, silently; a second one is raised.
        3. A service that refuses the key form (503), or a consent without
           ``envelope_ids``, falls back to the passphrase form for a
           passphrase-custody key only; a vault key gets
           :class:`HostedSummaryUnavailable`.

        Args:
            retrieval: The memory retrieval service (unlocked Memory Sync).
            key_source: Returns ``"vault"`` or ``"passphrase"``.
            passphrase_provider: Asked only for the passphrase fall-back.

        Raises:
            VaultCustodyLocked, StaleEnvelopes, HostedSummaryUnavailable and the
            errors of the consent and dispatch calls.
        """
        stale_retried = False
        while True:
            consent = await self.request_consent_token(
                instance_id, mode, modules, provider_ack=True
            )
            try:
                return await self._dispatch_for_consent(
                    instance_id, consent, retrieval, key_source, passphrase_provider,
                    requested_modules=modules,
                )
            except StaleEnvelopes:
                pass
            except MemoryBackendError:
                raise
            except Exception as exc:
                if getattr(exc, "code", None) != "stale_envelopes":
                    raise
            if stale_retried:
                raise StaleEnvelopes()
            stale_retried = True

    async def _dispatch_for_consent(
        self,
        instance_id: str,
        consent: ConsentToken,
        retrieval: Any,
        key_source: Callable[[], Optional[str]],
        passphrase_provider: Callable[[], Awaitable[str]],
        requested_modules: Optional[List[str]] = None,
    ) -> SummaryDispatchResult:
        if consent.envelope_ids:
            check_envelope_ids(consent, requested_modules)
            keys = await retrieval.envelope_keys(instance_id, consent.envelope_ids)
            try:
                return await self.dispatch_summary(
                    instance_id, consent.token, consent.mode, envelope_keys=keys
                )
            except BackendMaintenance:
                logger.info("Hosted summary: key form refused (feature disabled)")
            finally:
                keys.clear()
        if key_source() != "passphrase":
            raise HostedSummaryUnavailable()
        passphrase = await passphrase_provider()
        try:
            return await self.dispatch_summary(
                instance_id, consent.token, consent.mode, passphrase=passphrase
            )
        finally:
            passphrase = ""

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
        queued_at: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Poll until a newly generated summary envelope is available.

        With *queued_at* (the dispatch answer's timestamp) the poll asks for
        ``after=<timestamp>``, the only form on which the service reports a
        failed job; the first summary envelope it returns is this job's. Without
        it (an older service) the poll compares envelope ids as before.

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
                after=queued_at or previous_envelope_id,
            )
            next_delay = poll_interval
            if latest is None:
                continue
            if latest.get("status") == "failed":
                reason = str(latest.get("reason", "") or "")[:_MAX_LOGGED_REASON]
                logger.warning("Hosted summary failed: reason=%r", reason)
                raise SummaryFailed(reason)
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

            if queued_at and not latest.get("id"):
                # A pending answer on the timestamp form (202) carries no envelope.
                continue
            latest_id = str(latest.get("id", "") or "")
            if not latest_id:
                raise MemoryBackendError(
                    "Hosted summary response has no stable envelope id"
                )
            if queued_at or previous_envelope_id is None or latest_id != previous_envelope_id:
                return latest


def check_envelope_ids(consent: ConsentToken, requested_modules: Optional[List[str]]) -> None:
    """Refuse envelope ids for modules the person did not approve.

    The ids come from the service and each one leads to a data key being
    opened, so they are held to the approved set: the modules the person asked
    for (or, for "all", the consent's own list, or every known module), limited
    to modules this client knows. Count and names are both checked.

    Raises:
        EnvelopeKeyError: ``envelope_not_consented`` when an id falls outside it.
    """
    from servonaut.services.memory.modules import default_module_names
    from servonaut.services.memory.retrieval_service import EnvelopeKeyError

    known = set(default_module_names()) | _EXTRA_MODULES
    wanted = set(requested_modules) if requested_modules else set(consent.modules)
    approved = (wanted & known) if wanted else known
    ids = consent.envelope_ids
    if len(ids) > len(approved) or not set(ids) <= approved:
        raise EnvelopeKeyError("envelope_not_consented")


def _parse_envelope_ids(raw: Any) -> Dict[str, str]:
    """``{module: envelope id}`` from the consent answer; empty when absent or malformed."""
    if not isinstance(raw, dict):
        return {}
    return {str(m): str(e) for m, e in raw.items() if m and e}


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
        if (exc.details or {}).get("field") == "envelope_keys":
            # Kept as is: the custody wording is picked from the field.
            return exc
        errors = []
        if exc.details:
            errors = exc.details.get("errors", [])
        return ValidationFailed(errors)
    # Not-found is handled at call site; pass through here
    return exc
