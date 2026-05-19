"""HTTP client for servonaut.dev API."""
from __future__ import annotations

import logging
import os
import re
from importlib.metadata import version as pkg_version
from typing import Any, AsyncIterator, Dict, Mapping, Optional, Tuple, Type, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.services.auth_service import AuthService

from .interfaces import APIClientInterface

logger = logging.getLogger(__name__)

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore[assignment]
    HAS_HTTPX = False

_DEFAULT_API_BASE = "https://api.servonaut.dev"

DEFAULT_TIMEOUT_SECONDS = 30
LONG_TIMEOUT_SECONDS = 120
EXPORT_TIMEOUT_SECONDS = 300

# Strict shape for team slugs interpolated into URL paths. Matches the
# server-side ``TeamSlug`` constraint (alphanumeric + dash + underscore,
# 1-64 chars). Anything looser exposes a URL-injection vector: a slug of
# ``../admin/users`` would be normalised by the path resolver into a
# different route. We reject before building the URL so the failure
# happens at the call site with a clear message instead of as a
# silent 404 against an unrelated endpoint.
_TEAM_SLUG_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def _api_base() -> str:
    """Read API base URL at call time so secrets loaded after import are picked up."""
    return os.environ.get("SERVONAUT_API_URL", _DEFAULT_API_BASE)


class APIError(Exception):
    """Base error for all non-2xx API responses."""

    def __init__(
        self,
        *,
        code: str,
        message: str,
        status: int,
        details: Optional[Dict[str, Any]] = None,
        response_headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details
        self.response_headers = response_headers

    @property
    def is_retryable(self) -> bool:
        return self.status in (429, 502, 503, 504)


class FeatureDisabledError(APIError):
    """503 — backend kill-switch active."""


class FeatureNotAvailableError(APIError):
    """403 feature_not_available — beta allowlist excludes caller."""


class ForbiddenEntitlementError(APIError):
    """403 forbidden_entitlement — plan doesn't include this feature."""


class RateLimitedError(APIError):
    """429 rate_limited — per-user rate limiter tripped."""


class ValidationFailedError(APIError):
    """400 / 422 validation_failed — bad request shape."""


class QuotaExceededError(APIError):
    """429 quota_exceeded — hard cap hit."""


class BatchTooLargeError(APIError):
    """413 batch_too_large — more than 100 envelopes per /sync call."""


class NotFoundError(APIError):
    """404 not_found — resource missing or not owned by caller."""


class InsufficientWrapsError(APIError):
    """422 insufficient_wraps — grant call missing DEK wraps for some members."""

    @property
    def missing(self) -> list:
        if self.details:
            return self.details.get("missing", [])
        return []


class GrantExistsError(APIError):
    """409 grant_exists — live grant already covers (team, instance)."""


class WeakPassphraseError(APIError):
    """422 weak_passphrase — key blob declares pw_score < 3."""


class PaymentRequiredError(APIError):
    """402 payment_required — feature gated behind a paid plan.

    Used by the secrets-management endpoint (and any future
    entitlement-gated surface) to give the CLI a structured way to
    surface "upgrade your plan" UX rather than a raw 4xx.

    The server-side body shape (locked on agent-bus thread
    ``secrets-management-kickoff``) is the flat-envelope variant::

        {
          "error": "payment_required",
          "message": "Secrets management requires a Solo or Teams subscription.",
          "required_tier": "solo",
          "upgrade_url": "https://servonaut.dev/pricing",
          "doc_url": "https://servonaut.dev/docs/secrets-management"
        }

    ``upgrade_url`` / ``doc_url`` / ``required_tier`` are surfaced via
    properties so consumers don't have to dig through
    :pyattr:`APIError.details`. The header counterpart
    (``Link: <…>; rel="upgrade"``) is also exposed for callers that
    prefer reading it from there.
    """

    @property
    def upgrade_url(self) -> str:
        return str((self.details or {}).get("upgrade_url", ""))

    @property
    def doc_url(self) -> str:
        return str((self.details or {}).get("doc_url", ""))

    @property
    def required_tier(self) -> str:
        return str((self.details or {}).get("required_tier", ""))


class ForbiddenError(APIError):
    """403 forbidden — caller is authenticated but not a member of the resource.

    Distinct from :class:`ForbiddenEntitlementError` (=403 with code
    ``forbidden_entitlement``, "your plan doesn't include this feature")
    so error-screen copy can be precise: "you don't have access to this
    team" vs "upgrade to use this feature".
    """


_CODE_TO_EXC: Dict[str, Type[APIError]] = {
    "feature_disabled": FeatureDisabledError,
    "feature_not_available": FeatureNotAvailableError,
    "forbidden_entitlement": ForbiddenEntitlementError,
    "rate_limited": RateLimitedError,
    "validation_failed": ValidationFailedError,
    "quota_exceeded": QuotaExceededError,
    "batch_too_large": BatchTooLargeError,
    "not_found": NotFoundError,
    "insufficient_wraps": InsufficientWrapsError,
    "grant_exists": GrantExistsError,
    "weak_passphrase": WeakPassphraseError,
    "payment_required": PaymentRequiredError,
    "forbidden": ForbiddenError,
}


class APIClient(APIClientInterface):
    """Authenticated HTTP client for the Servonaut API."""

    def __init__(self, auth_service: 'AuthService') -> None:
        self._auth = auth_service

    def _get_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
        }
        try:
            headers["User-Agent"] = f"servonaut-cli/{pkg_version('servonaut')}"
        except Exception:
            headers["User-Agent"] = "servonaut-cli"
        token = self._auth.access_token
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _parse_error(self, response: Any) -> APIError:
        """Translate a non-2xx httpx response into a typed APIError subclass."""
        status: int = response.status_code
        content_type: str = response.headers.get("content-type", "")
        headers_dict: Dict[str, str] = {k.lower(): v for k, v in response.headers.items()}

        # §7: Symfony PayloadSizeLimitListener emits 413 with HTML, not JSON envelope.
        if status == 413 and "application/json" not in content_type:
            return BatchTooLargeError(
                code="batch_too_large",
                message="Request payload too large",
                status=413,
                response_headers=headers_dict,
            )

        try:
            body = response.json()
            err_obj = body.get("error")
            if isinstance(err_obj, dict):
                # Nested envelope (most servonaut.dev endpoints):
                #   { "error": { "code": "...", "message": "...",
                #                "details": {...} } }
                code = err_obj.get("code", "unknown")
                message = err_obj.get("message", f"HTTP {status}")
                details = err_obj.get("details")
            elif isinstance(err_obj, str):
                # Flat envelope (introduced for the secrets-management
                # 402/403 responses; locked on agent-bus thread
                # ``secrets-management-kickoff``):
                #   { "error": "payment_required",
                #     "message": "...",
                #     "upgrade_url": "...",
                #     ...other top-level extras }
                # The ``error`` scalar IS the code; everything else at
                # the top level (minus ``message``) becomes ``details``
                # so :class:`PaymentRequiredError`'s ``upgrade_url``
                # property has somewhere to read from.
                code = err_obj
                message = body.get("message", f"HTTP {status}")
                details = {
                    k: v for k, v in body.items()
                    if k not in ("error", "message")
                } or None
            else:
                raise ValueError(
                    "error field missing or unsupported envelope shape"
                )
        except Exception:
            return APIError(
                code="unknown",
                message=response.text[:500],
                status=status,
                response_headers=headers_dict,
            )

        exc_class = _CODE_TO_EXC.get(code, APIError)
        return exc_class(
            code=code,
            message=message,
            status=status,
            details=details,
            response_headers=headers_dict,
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        timeout: float,
        json: Optional[Any] = None,
        params: Optional[Dict[str, Any]] = None,
        accept: str = "application/json",
        retry_on_401: bool = True,
    ) -> Any:
        if not HAS_HTTPX:
            raise RuntimeError(
                "httpx not installed. Install with: pip install 'servonaut[pro]'"
            )

        url = f"{_api_base()}{path}"
        headers = self._get_headers()
        if accept != "application/json":
            headers["Accept"] = accept

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.request(
                method, url, headers=headers, json=json, params=params
            )

            # Sensitive-body endpoints (passphrase, wrapped private key) opt out of
            # retry to avoid resending those secrets on a token refresh round-trip.
            if response.status_code == 401 and retry_on_401:
                if await self._auth.refresh_token():
                    headers = self._get_headers()
                    if accept != "application/json":
                        headers["Accept"] = accept
                    response = await client.request(
                        method, url, headers=headers, json=json, params=params
                    )

            if response.status_code >= 400:
                raise self._parse_error(response)

            return response

    async def get(self, path: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS, params: Optional[Dict[str, Any]] = None, retry_on_401: bool = True, **kwargs: Any) -> Dict[str, Any]:
        response = await self._request(
            "GET", path, timeout=timeout, params=params, retry_on_401=retry_on_401
        )
        return response.json()

    async def post(self, path: str, *, json: Optional[Any] = None, timeout: float = DEFAULT_TIMEOUT_SECONDS, retry_on_401: bool = True, **kwargs: Any) -> Dict[str, Any]:
        response = await self._request(
            "POST", path, timeout=timeout, json=json, retry_on_401=retry_on_401
        )
        if response.status_code == 204:
            return {"success": True}
        return response.json()

    async def patch(self, path: str, *, json: Optional[Any] = None, timeout: float = DEFAULT_TIMEOUT_SECONDS, retry_on_401: bool = True, **kwargs: Any) -> Dict[str, Any]:
        response = await self._request(
            "PATCH", path, timeout=timeout, json=json, retry_on_401=retry_on_401
        )
        if response.status_code == 204:
            return {"success": True}
        return response.json()

    async def delete(self, path: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS, params: Optional[Dict[str, Any]] = None, retry_on_401: bool = True, **kwargs: Any) -> Dict[str, Any]:
        response = await self._request(
            "DELETE", path, timeout=timeout, params=params, retry_on_401=retry_on_401
        )
        if response.status_code == 204:
            return {"success": True}
        return response.json()

    async def stream_sse(
        self,
        path: str,
        body: dict,
        *,
        timeout: float = LONG_TIMEOUT_SECONDS,
    ) -> AsyncIterator[Dict[str, Any]]:
        """Stream Server-Sent Events from ``path`` with ``body``.

        Thin wrapper that delegates to
        :func:`servonaut.services.ai_sse.stream_sse` so SSE concerns
        stay in their own module. The lazy import keeps ``ai_sse`` from
        being a load-time dependency of every consumer of this client.

        Yields normalised events of shape ``{"event": str, "data": dict}``.
        ``ping`` events are absorbed inside ``ai_sse``; consumers see only
        the meaningful events.

        Errors:
        - :class:`APIError` (and subclasses) for pre-stream HTTP failures.
        - :class:`servonaut.services.ai_sse.SSEStreamError` for terminal
          ``error`` SSE events.
        - :class:`servonaut.services.ai_sse.SSEStreamDead` when no event
          arrives within the heartbeat window.
        """
        if not HAS_HTTPX:
            raise RuntimeError(
                "httpx not installed. Install with: pip install 'servonaut[pro]'"
            )
        # Lazy import to avoid circular at module load — ai_sse imports
        # this module for ``_api_base`` and ``_parse_error``.
        from servonaut.services.ai_sse import stream_sse as _stream_sse

        async for event in _stream_sse(self, path, body, timeout=timeout):
            yield event

    async def get_bytes(self, path: str, *, timeout: float = EXPORT_TIMEOUT_SECONDS, params: Optional[Dict[str, Any]] = None) -> Tuple[bytes, Dict[str, str]]:
        """Download raw bytes (e.g. export tarball).

        Returns (content, headers) on 200 application/gzip.
        Raises APIError if the server returns application/json (error envelope).
        """
        if not HAS_HTTPX:
            raise RuntimeError(
                "httpx not installed. Install with: pip install 'servonaut[pro]'"
            )

        url = f"{_api_base()}{path}"
        headers = self._get_headers()

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers, params=params)

            if response.status_code == 401:
                if await self._auth.refresh_token():
                    headers = self._get_headers()
                    response = await client.get(url, headers=headers, params=params)

            if response.status_code >= 400:
                raise self._parse_error(response)

            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                # Server returned a JSON body on 2xx — treat as error envelope.
                raise self._parse_error(response)

            response_headers = {k.lower(): v for k, v in response.headers.items()}
            return response.content, response_headers

    # ------------------------------------------------------------------
    # Secrets-management
    # ------------------------------------------------------------------

    async def get_team_secrets_config(
        self,
        slug: str,
    ) -> Optional[Dict[str, Any]]:
        """Fetch the team's effective :class:`SecretsConfig` from the API.

        Wire contract (locked on agent-bus thread
        ``secrets-management-kickoff``; slug-not-id confirmed by
        servonaut-dev's W5 delta at 2026-05-16 17:58 UTC because
        the rest of ``/api/v1/teams/{slug}/*`` already uses slug —
        Team::$id is a UUID anyway):

        - ``GET /api/v1/teams/{slug}/secrets-config``, Bearer auth.
        - ``200`` →  return the parsed JSON body:
          ``{"provider": "...", "config": {...}, "updated_at": "..."}``.
        - ``404`` → return ``None``. The CLI's calling layer falls
          back to the LocalProvider and clears its cached payload.
          ``not_found`` is NOT exceptional here; the kickoff doc
          §API endpoint lists this as the explicit "no team config
          on file" path.
        - ``402`` → raises :class:`PaymentRequiredError`; the CLI
          surfaces the response's ``upgrade_url`` to the user.
        - ``403`` → raises :class:`ForbiddenError` (not a team
          member, OR slug doesn't exist — server collapses the two
          intentionally to prevent slug enumeration via error shape).
        - Everything else → :class:`APIError` propagates per the
          standard ``_request`` contract (refresh-on-401, rate-limit
          retry semantics, etc.).

        Slug normalisation: we reject empty/whitespace-only slugs at
        the call site rather than letting them silently hit
        ``/api/v1/teams//secrets-config`` (which would 404 against a
        non-existent route and obscure the real bug — usually a
        caller forgetting to thread the active team through).
        """
        clean = (slug or "").strip()
        if not clean:
            raise ValueError(
                "get_team_secrets_config requires a non-empty team slug; "
                "got %r" % (slug,)
            )
        # Defence-in-depth: reject anything outside the locked slug
        # shape BEFORE interpolating into the URL path. A malicious
        # slug like ``../admin/users`` would be normalised by the
        # path resolver into a wholly different route; without this
        # guard the only line of defence is the server-side
        # router (which is good but shouldn't be the only check on
        # values we control client-side). Pattern matches the
        # server-side ``TeamSlug`` constraint.
        if not _TEAM_SLUG_RE.match(clean):
            raise ValueError(
                "get_team_secrets_config slug must match "
                f"{_TEAM_SLUG_RE.pattern!r}; got %r" % (slug,)
            )
        path = f"/api/v1/teams/{clean}/secrets-config"
        try:
            return await self.get(path)
        except NotFoundError:
            # Distinguished into ``None`` for the caller's convenience —
            # they were always going to special-case 404 anyway, and
            # raising-then-catching across every consumer would just be
            # ceremony.
            logger.info(
                "get_team_secrets_config(slug=%s): server returned 404 "
                "(no team config on file) — caller should fall back to "
                "LocalProvider",
                clean,
            )
            return None
