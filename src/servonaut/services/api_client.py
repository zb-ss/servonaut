"""HTTP client for servonaut.dev API."""
from __future__ import annotations

import logging
import os
from importlib.metadata import version as pkg_version
from typing import Any, Dict, Mapping, Optional, Tuple, Type, TYPE_CHECKING

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
            err_obj = body.get("error", {})
            if not isinstance(err_obj, dict):
                raise ValueError("error field not a dict")
            code = err_obj.get("code", "unknown")
            message = err_obj.get("message", f"HTTP {status}")
            details = err_obj.get("details")
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
