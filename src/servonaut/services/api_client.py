"""HTTP client for servonaut.dev API."""
from __future__ import annotations

import logging
from importlib.metadata import version as pkg_version
from typing import Any, Dict, Optional, TYPE_CHECKING

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

API_BASE = "https://api.servonaut.dev"


class APIClient(APIClientInterface):
    """Authenticated HTTP client for the Servonaut API."""

    def __init__(self, auth_service: 'AuthService') -> None:
        self._auth = auth_service

    def _get_headers(self) -> Dict[str, str]:
        headers = {
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

    async def get(self, path: str, **kwargs: Any) -> dict:
        """Authenticated GET request with auto-refresh on 401."""
        if not HAS_HTTPX:
            raise RuntimeError("httpx not installed. Install with: pip install 'servonaut[pro]'")

        url = f"{API_BASE}{path}"
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(url, headers=self._get_headers(), **kwargs)

            if response.status_code == 401:
                if await self._auth.refresh_token():
                    response = await client.get(url, headers=self._get_headers(), **kwargs)

            if response.status_code >= 400:
                self._raise_for_status(response)

            return response.json()

    async def post(self, path: str, data: dict = None, **kwargs: Any) -> dict:
        """Authenticated POST request with auto-refresh on 401."""
        if not HAS_HTTPX:
            raise RuntimeError("httpx not installed. Install with: pip install 'servonaut[pro]'")

        url = f"{API_BASE}{path}"
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                url, headers=self._get_headers(), json=data, **kwargs
            )

            if response.status_code == 401:
                if await self._auth.refresh_token():
                    response = await client.post(
                        url, headers=self._get_headers(), json=data, **kwargs
                    )

            if response.status_code >= 400:
                self._raise_for_status(response)

            return response.json()

    async def delete(self, path: str, **kwargs: Any) -> dict:
        """Authenticated DELETE request with auto-refresh on 401."""
        if not HAS_HTTPX:
            raise RuntimeError("httpx not installed. Install with: pip install 'servonaut[pro]'")

        url = f"{API_BASE}{path}"
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.delete(url, headers=self._get_headers(), **kwargs)

            if response.status_code == 401:
                if await self._auth.refresh_token():
                    response = await client.delete(url, headers=self._get_headers(), **kwargs)

            if response.status_code >= 400:
                self._raise_for_status(response)

            # Some DELETE endpoints return 204 No Content
            if response.status_code == 204:
                return {"success": True}
            return response.json()

    def _raise_for_status(self, response: Any) -> None:
        """Raise RuntimeError with API error message."""
        try:
            body = response.json()
            msg = body.get("error", {}).get("message", body.get("message", response.text))
        except Exception:
            msg = response.text
        raise RuntimeError(f"API error ({response.status_code}): {msg}")
