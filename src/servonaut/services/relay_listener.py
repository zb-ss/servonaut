"""Mercure SSE relay listener: subscribes to commands and POSTs results back."""
from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import socket
import time
from dataclasses import asdict, replace
from typing import Any, Awaitable, Callable, Optional, Union

try:
    import httpx
    from httpx_sse import aconnect_sse
    HAS_HTTPX_SSE = True
except ImportError:
    HAS_HTTPX_SSE = False

from servonaut.models.relay_messages import CommandRequest, CommandType, CommandResponse

logger = logging.getLogger(__name__)


# A token source: either a literal string (legacy / headless mode where
# the token is captured from an env var and there's no AuthService to
# refresh it) or a callable returning the current bearer. The callable
# form is what RelayManager passes — it closes over the AuthService so
# every heartbeat/POST/JWT-fetch picks up token rotations performed by
# the OAuth refresh path. Snapshotting a string here would silently use
# a stale bearer for the lifetime of the listener (>=session lifetime).
TokenSource = Union[str, Callable[[], Optional[str]]]


class RelayListener:
    """Subscribes to a Mercure hub topic and dispatches commands to RelayExecutors."""

    # Refresh the Mercure subscriber JWT a bit before the 1h backend TTL.
    _MERCURE_JWT_REFRESH_SECONDS = 3000

    def __init__(self, executors, base_url: str, mercure_url: str,
                 auth_token: TokenSource, user_id: str,
                 heartbeat_interval: int = 30,
                 on_connected=None, on_disconnected=None,
                 on_session_expired=None,
                 refresh_callback: Optional[
                     Callable[[], Awaitable[bool]]
                 ] = None) -> None:
        if not HAS_HTTPX_SSE:
            raise ImportError(
                "httpx-sse required. Install with: pip install 'servonaut[relay]'"
            )
        self._executors = executors
        self._base_url = base_url.rstrip('/')
        self._mercure_url = mercure_url.rstrip('/')
        # Normalise to a provider callable. A bare string gets wrapped in a
        # zero-arg lambda so the rest of the code has one shape to handle.
        if callable(auth_token):
            self._token_provider: Callable[[], Optional[str]] = auth_token
        else:
            captured = auth_token
            self._token_provider = lambda: captured
        self._user_id = user_id
        self._heartbeat_interval = heartbeat_interval
        self._last_event_id: str | None = None
        self._running = False
        self._client: httpx.AsyncClient | None = None
        self._mercure_jwt: str | None = None
        self._mercure_jwt_fetched_at: float = 0.0
        # Stable per-instance client identifier used for heartbeats. Backend
        # constraint: `^[a-zA-Z0-9_\-]+$`, max 64 chars.
        self._client_id = self._derive_client_id()
        # Lifecycle callbacks — optional async hooks fired exactly once each
        # on first successful heartbeat and once on final teardown. Used by
        # the TUI's RelayManager to drive the reactive status indicator.
        self._on_connected = on_connected
        self._on_disconnected = on_disconnected
        self._on_session_expired = on_session_expired
        self._connected_hook_fired = False
        # Fired exactly once per listener lifetime so we don't bombard
        # the manager with repeat session-expired callbacks if the
        # heartbeat loop runs another tick before stop() lands.
        self._session_expired_hook_fired = False
        # Optional callback that exchanges the stored refresh_token for a
        # fresh access_token + refresh_token pair. The listener invokes it
        # on a 401/403 BEFORE declaring the session expired so a
        # locally-stale access_token (the user closed the CLI overnight and
        # came back the next day) is healed transparently. Returns True iff
        # the token provider now serves a fresh bearer. None = legacy
        # behaviour: any 401/403 immediately means session expired.
        self._refresh_callback = refresh_callback

    @property
    def client_id(self) -> str:
        """Hostname-derived client id currently being sent in heartbeats."""
        return self._client_id

    def _get_auth_token(self) -> str:
        """Resolve the current bearer via the token provider.

        Called on every heartbeat, every command-result POST, and every
        Mercure JWT fetch — so a token rotation by the OAuth refresh
        path is picked up immediately without having to recreate the
        listener. Raises if the provider yields an empty token (the
        user has been logged out / refresh failed); the caller's
        try/except converts this to the same warning path as a 401.
        """
        try:
            token = self._token_provider()
        except Exception as exc:
            raise RuntimeError(f"token provider raised: {exc}") from exc
        if not token:
            raise RuntimeError("auth token is empty (logged out or refresh failed)")
        return token

    async def _authed_request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> "httpx.Response":
        """Issue an authenticated request with one refresh-on-401 retry.

        Bypasses :class:`APIClient` because the relay listener owns its
        own ``httpx.AsyncClient`` (it has to — the SSE subscription holds
        the client open for the listener's lifetime). Reimplements the
        same retry-once contract here so a locally-stale access_token
        doesn't surface as a phantom "session expired" — the same bug
        that prompted the OAuth refresh-race fix on
        :class:`servonaut.services.auth_service.AuthService`.

        Retry rules:
        - On 401 or 403 AND a ``refresh_callback`` is configured, invoke
          it once. If it returns True (the provider now serves a fresh
          bearer), re-stamp the Authorization header and retry the
          request exactly once. The caller observes the retry result.
        - Without a ``refresh_callback`` (legacy headless paths), the
          original response is returned as-is. The 401-handler in
          :meth:`_heartbeat_loop` then declares session-expired.
        - Network-layer exceptions propagate to the caller unchanged.
        """
        headers = dict(kwargs.pop("headers", {}) or {})
        headers["Authorization"] = f"Bearer {self._get_auth_token()}"
        # Dispatch via the verb-named attribute (``self._client.post`` /
        # ``self._client.get``) rather than ``self._client.request``
        # because the existing test suite — and any reasonable consumer
        # mocking out the listener — patches those explicit methods.
        verb = method.lower()
        send = getattr(self._client, verb)
        response = await send(url, headers=headers, **kwargs)
        if response.status_code in (401, 403) and self._refresh_callback is not None:
            try:
                refreshed = await self._refresh_callback()
            except Exception as exc:
                logger.warning("Relay refresh_callback raised: %s", exc)
                refreshed = False
            if refreshed:
                # Re-stamp with the now-rotated bearer and retry once.
                try:
                    headers["Authorization"] = f"Bearer {self._get_auth_token()}"
                except RuntimeError:
                    # Token provider went empty even though refresh
                    # reported success — race with logout(). Treat as
                    # session expired by returning the original response.
                    return response
                response = await send(url, headers=headers, **kwargs)
        return response

    @staticmethod
    def _derive_client_id() -> str:
        """Build a backend-compatible client id from hostname + a random suffix."""
        try:
            host = socket.gethostname() or "cli"
        except Exception:
            host = "cli"
        host = re.sub(r"[^a-zA-Z0-9]+", "-", host).strip("-").lower() or "cli"
        return f"{host[:48]}-{secrets.token_hex(4)}"

    async def run(self) -> None:
        """Start listener and heartbeat concurrently."""
        self._running = True
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=None)) as client:
            self._client = client
            try:
                await asyncio.gather(
                    self._listen_forever(),
                    self._heartbeat_loop(),
                )
            except asyncio.CancelledError:
                self._running = False
            finally:
                self._client = None
                await self._safe_fire_disconnected()

    async def _fetch_mercure_jwt(self) -> str:
        """Fetch a short-lived Mercure subscriber JWT from the backend.

        The Mercure hub authenticates subscribers via a JWT with a
        `mercure.subscribe` claim, *not* via the OAuth bearer used for the
        rest of the API. The backend endpoint mints one scoped to this user's
        private topic `/cli/{user_id}/commands`.
        """
        url = f"{self._base_url}/api/cli/mercure-token"
        response = await self._authed_request("GET", url, timeout=10.0)
        response.raise_for_status()
        payload = response.json()
        token = payload.get("token")
        if not isinstance(token, str) or not token:
            raise RuntimeError(
                f"mercure-token endpoint returned no token (payload keys: {list(payload.keys())})"
            )
        self._mercure_jwt = token
        self._mercure_jwt_fetched_at = time.monotonic()
        return token

    async def _ensure_mercure_jwt(self) -> str:
        """Return a cached Mercure JWT, refreshing before it expires."""
        age = time.monotonic() - self._mercure_jwt_fetched_at
        if self._mercure_jwt is None or age >= self._MERCURE_JWT_REFRESH_SECONDS:
            return await self._fetch_mercure_jwt()
        return self._mercure_jwt

    async def _listen_forever(self) -> None:
        """SSE subscribe loop with exponential backoff on failure."""
        backoff = 1
        max_backoff = 30
        topic = f"/cli/{self._user_id}/commands"

        while self._running:
            try:
                mercure_jwt = await self._ensure_mercure_jwt()

                # Mercure accepts the subscriber JWT via the `authorization`
                # query parameter (not HTTP Bearer). Caddy's Mercure module
                # redacts this parameter in access logs (see Caddyfile log
                # filter) so it does not leak to disk.
                params = {"topic": topic, "authorization": mercure_jwt}
                headers = {}
                if self._last_event_id:
                    headers["Last-Event-ID"] = self._last_event_id

                async with aconnect_sse(
                    self._client, "GET", self._mercure_url,
                    params=params,
                    headers=headers,
                ) as event_source:
                    backoff = 1  # Reset on successful connection
                    logger.info("Connected to Mercure hub, topic: %s", topic)
                    print("Connected to relay. Waiting for commands...")  # noqa: foreground only

                    async for event in event_source.aiter_sse():
                        if not self._running:
                            return
                        if event.id:
                            self._last_event_id = event.id
                        if event.data:
                            await self._handle_event(event.data)

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    logger.error(
                        "401 from %s — the Mercure JWT or OAuth token may have expired; "
                        "forcing a JWT refresh",
                        e.request.url,
                    )
                    # Force a fresh subscriber JWT on the next loop
                    self._mercure_jwt = None
                    backoff = max_backoff
                else:
                    logger.error("HTTP error from Mercure: %s", e)
            except Exception as e:
                logger.error("Mercure connection error: %s", e)

            if self._running:
                logger.info("Reconnecting in %ds...", backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)

    async def _handle_event(self, data: str) -> None:
        """Parse an SSE event payload and dispatch to executor."""
        try:
            raw = json.loads(data)

            # Validate user_id matches the authenticated identity (mandatory).
            # The server publishes user_id as a JSON int (User::getId() in PHP)
            # while ``self._user_id`` arrives as a string from
            # ``_extract_user_id``; compare on string form so the int/str split
            # at the wire boundary doesn't reject legitimate events.
            event_user_id = raw.get("user_id", "")
            if str(event_user_id) != str(self._user_id):
                logger.warning(
                    "Rejected event with missing/mismatched user_id (expected %s, got %r)",
                    self._user_id,
                    event_user_id,
                )
                return

            try:
                ttl = int(raw.get("ttl_seconds", 60))
            except (TypeError, ValueError):
                ttl = 60

            # AI tool calls (ssh_exec_readonly, tail_log, etc.) are handled by
            # services/ai_tool_bridge.py via the chat-stream / tool-result HTTP
            # path — NOT by this relay listener. The backend currently mirrors
            # them onto /cli/{user_id}/commands too, so we receive them here and
            # must skip cleanly instead of erroring. CommandType only covers the
            # 8 web-originated relay verbs; anything else belongs elsewhere.
            raw_type = raw.get("type")
            try:
                command_type = CommandType(raw_type)
            except ValueError:
                logger.debug(
                    "Skipping non-relay event type=%r on commands channel "
                    "(handled by ai_tool_bridge): id=%s",
                    raw_type, raw.get("id"),
                )
                return

            request = CommandRequest(
                id=raw["id"],
                user_id=event_user_id,
                type=command_type,
                target_server_id=raw["target_server_id"],
                payload=raw.get("payload", {}),
                ttl_seconds=ttl,
            )
            start = time.monotonic()
            response = await self._executors.execute(request)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            response = replace(response, execution_time_ms=elapsed_ms)

            status_icon = "v" if response.status == "success" else "x"
            msg = (f"[{request.type.value}] {request.target_server_id}: "
                   f"{status_icon} ({elapsed_ms}ms)")
            logger.info("Relay command: %s", msg)
            print(f"  {msg}")

            await self._post_result(response)
        except Exception as e:
            logger.error("Failed to handle event: %s — data length: %d", e, len(data))

    async def _post_result(self, response: CommandResponse) -> None:
        """POST the command result back to the backend."""
        url = f"{self._base_url}/api/cli/command-result/{response.request_id}"
        try:
            resp = await self._authed_request(
                "POST", url, json=asdict(response), timeout=10.0,
            )
            if resp.status_code >= 400:
                logger.warning(
                    "Failed to post result: %s %s",
                    resp.status_code, resp.text[:200],
                )
        except Exception as e:
            logger.warning("Failed to post result for %s: %s", response.request_id, e)

    async def _heartbeat_loop(self) -> None:
        """Send a heartbeat to the backend every N seconds."""
        url = f"{self._base_url}/api/cli/heartbeat"
        while self._running:
            try:
                response = await self._authed_request(
                    "POST", url,
                    json={"client_id": self._client_id},
                    timeout=10.0,
                )
                if response.status_code in (401, 403):
                    # OAuth bearer rejected — refresh-token rotated past
                    # validity, server-side revocation, or user logged
                    # out from another device. Fire the session-expired
                    # hook so the indicator stops claiming "connected"
                    # and the manager can stop the listener instead of
                    # spamming the heartbeat with a known-bad bearer.
                    logger.warning(
                        "Heartbeat auth failure (%d): %s",
                        response.status_code, response.text[:200],
                    )
                    await self._safe_fire_session_expired()
                    return
                if response.status_code >= 400:
                    logger.warning(
                        "Heartbeat rejected: %s %s",
                        response.status_code, response.text[:200],
                    )
                elif not self._connected_hook_fired:
                    # First successful heartbeat — the backend now sees us as
                    # connected, so the UI can flip its indicator to green.
                    self._connected_hook_fired = True
                    await self._safe_fire_connected()
            except Exception as e:
                logger.warning("Heartbeat failed: %s", e)
            await asyncio.sleep(self._heartbeat_interval)

    async def _safe_fire_connected(self) -> None:
        if self._on_connected is None:
            return
        try:
            await self._on_connected()
        except Exception as e:
            logger.warning("on_connected hook raised: %s", e)

    async def _safe_fire_disconnected(self) -> None:
        if self._on_disconnected is None or not self._connected_hook_fired:
            return
        self._connected_hook_fired = False
        try:
            await self._on_disconnected()
        except Exception as e:
            logger.warning("on_disconnected hook raised: %s", e)

    async def _safe_fire_session_expired(self) -> None:
        """Fire ``on_session_expired`` once per listener lifetime."""
        if self._on_session_expired is None or self._session_expired_hook_fired:
            return
        self._session_expired_hook_fired = True
        try:
            await self._on_session_expired()
        except Exception as e:
            logger.warning("on_session_expired hook raised: %s", e)

    def stop(self) -> None:
        """Signal the listener to stop."""
        self._running = False
