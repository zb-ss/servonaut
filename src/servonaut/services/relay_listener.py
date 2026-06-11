"""Mercure SSE relay listener: subscribes to commands and POSTs results back."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import socket
import time
from collections import OrderedDict
from dataclasses import asdict, replace
from typing import Any, Awaitable, Callable, List, Optional, Union

try:
    import httpx
    from httpx_sse import aconnect_sse
    HAS_HTTPX_SSE = True
except ImportError:
    HAS_HTTPX_SSE = False

from servonaut.models.relay_messages import CommandRequest, CommandType, CommandResponse

logger = logging.getLogger(__name__)

_ALLOWED_RELEASE_CHANNELS = frozenset({"stable", "beta", "dev"})


def _resolve_release_channel() -> str:
    """Resolve the CLI release channel.

    Resolution order (wire format v1.0 spec):
    1. ``SERVONAUT_RELEASE_CHANNEL`` env var, if set and a recognised value
       (``stable``, ``beta``, ``dev``).
    2. ``dev`` if ``__file__`` resolves to a symlinked path OR a
       ``.egg-info`` sibling exists next to the package root (editable
       install).
    3. ``stable`` otherwise.
    """
    env_val = os.environ.get("SERVONAUT_RELEASE_CHANNEL", "").strip().lower()
    if env_val in _ALLOWED_RELEASE_CHANNELS:
        return env_val

    # Detect editable / dev install by checking for .egg-info sibling or
    # a symlinked __file__ on the servonaut package.
    try:
        import servonaut as _pkg

        pkg_file = getattr(_pkg, "__file__", None) or ""
        if os.path.islink(pkg_file):
            return "dev"
        # Editable installs place a <name>.egg-info next to the src tree.
        import pathlib

        pkg_path = pathlib.Path(pkg_file).resolve()
        # Walk up to find the package root (src/servonaut → src → project root)
        for ancestor in pkg_path.parents:
            if list(ancestor.glob("*.egg-info")):
                return "dev"
            # Stop searching beyond 4 levels up.
            if len(pkg_path.parents) - list(pkg_path.parents).index(ancestor) > 4:
                break
    except Exception:
        pass

    return "stable"


def _resolve_providers_configured(app: Any) -> List[str]:
    """Return sorted list of provider names that have at least one service wired.

    Per wire format v1.0 spec:
    - ``"aws"``      → aws_service or aws_object_storage_service is not None
    - ``"hetzner"``  → hetzner_service or hetzner_object_storage_service
    - ``"ovh"``      → ovh_service or ovh_object_storage_service

    If ``app`` is None or any attribute is absent the provider is omitted.
    """
    providers: List[str] = []
    if app is not None:
        aws = (
            getattr(app, "aws_service", None) is not None
            or getattr(app, "aws_object_storage_service", None) is not None
        )
        hetzner = (
            getattr(app, "hetzner_service", None) is not None
            or getattr(app, "hetzner_object_storage_service", None) is not None
        )
        ovh = (
            getattr(app, "ovh_service", None) is not None
            or getattr(app, "ovh_object_storage_service", None) is not None
        )
        if aws:
            providers.append("aws")
        if hetzner:
            providers.append("hetzner")
        if ovh:
            providers.append("ovh")
    return sorted(providers)


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

    # Topic suffixes we subscribe to. The Mercure hub accepts repeated
    # ``topic`` query params, so we subscribe to both in a single SSE
    # connection.
    #
    # Dual-publish contract (servonaut.dev 2026-05-24, PR #74):
    # the server publishes the SAME payload to BOTH topics during the
    # transition window. We dedup by ``tool_call_id`` (preferred — the
    # load-bearing idempotency key for AI tool calls) falling back to
    # the top-level ``id`` (CommandRequest events). Two separate
    # ``hub->publish()`` calls server-side generate distinct Mercure
    # event ids, so event.id-based dedup would NOT work — domain-level
    # dedup is the only reliable path.
    _TOPIC_SUFFIXES = ("commands", "ai-tool-calls")

    # Bounded LRU dedup. 256 entries × ~50 bytes ≈ 13 KB worst-case.
    # TTL of 5 minutes is wildly more than enough for the microsecond
    # gap between two dual-publish arrivals; the bound + TTL together
    # ensure a long-lived listener can't accumulate memory.
    _DEDUP_MAX_ENTRIES = 256
    _DEDUP_TTL_SECONDS = 300

    def __init__(self, executors, base_url: str, mercure_url: str,
                 auth_token: TokenSource, user_id: str,
                 heartbeat_interval: int = 30,
                 on_connected=None, on_disconnected=None,
                 on_session_expired=None,
                 refresh_callback: Optional[
                     Callable[[], Awaitable[bool]]
                 ] = None,
                 providers_configured: Optional[List[str]] = None,
                 ai_tool_executor=None) -> None:
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
        # Bounded LRU of idempotency keys we've already processed; entries
        # carry a monotonic "first seen" timestamp so the TTL sweep can
        # evict stale rows even if the size bound never kicks in.
        self._seen_event_keys: "OrderedDict[str, float]" = OrderedDict()
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
        # Wire format v1.0: providers + release channel resolve once at
        # construction time and are embedded in every handshake/heartbeat.
        self._providers_configured: List[str] = sorted(providers_configured or [])
        self._release_channel: str = _resolve_release_channel()
        # Tracks whether the initial handshake has been posted; we fire
        # it exactly once on the first iteration of the heartbeat loop.
        self._handshake_sent: bool = False
        # Optional RelayAIToolExecutor. When set, AI chat tool calls
        # dispatched on /cli/{uid}/ai-tool-calls are executed here
        # (headless `servonaut connect` sessions). When None — the TUI's
        # in-process listener — those events are skipped, because the
        # chat panel already executes them from the chat-stream SSE
        # ``tool_call`` event; wiring both would double-execute.
        self._ai_tool_executor = ai_tool_executor

    @property
    def client_id(self) -> str:
        """Hostname-derived client id currently being sent in heartbeats."""
        return self._client_id

    def _build_handshake(self) -> dict:
        """Build the v1.0 ``cli.handshake`` payload.

        Sent exactly once per listener lifetime on the first heartbeat
        iteration. The server ignores unknown keys for backward compat;
        older servers that don't know the new fields accept the POST silently.
        """
        import servonaut

        return {
            "type": "cli.handshake",
            "version": getattr(servonaut, "__version__", "unknown"),
            "cli_release_channel": self._release_channel,
            "providers_configured": list(self._providers_configured),
            # v2.15.0: capability bit flipped True — CLI now consumes the
            # tool_catalog SSE event and routes all 60 catalog tools via
            # _LOCAL_TOOL_HANDLERS / _RELAY_TOOL_TO_TYPE (PR5').
            "capabilities": {"supports_dynamic_catalog": True},
            "client_id": self._client_id,
        }

    def _build_heartbeat(self) -> dict:
        """Build the v1.0 ``cli.heartbeat`` payload (minimal shape).

        Sent on every heartbeat tick after the initial handshake.
        """
        return {
            "type": "cli.heartbeat",
            "providers_configured": list(self._providers_configured),
            "client_id": self._client_id,
        }

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

    def _topic_urls(self) -> list[str]:
        """Return every Mercure topic URL this listener subscribes to."""
        return [
            f"/cli/{self._user_id}/{suffix}" for suffix in self._TOPIC_SUFFIXES
        ]

    async def _listen_forever(self) -> None:
        """SSE subscribe loop with exponential backoff on failure."""
        backoff = 1
        max_backoff = 30
        topics = self._topic_urls()

        while self._running:
            try:
                mercure_jwt = await self._ensure_mercure_jwt()

                # Mercure accepts the subscriber JWT via the `authorization`
                # query parameter (not HTTP Bearer). Caddy's Mercure module
                # redacts this parameter in access logs (see Caddyfile log
                # filter) so it does not leak to disk.
                # Repeated ``topic`` params subscribe to multiple topics on
                # one connection — list-of-tuples form lets httpx emit two
                # ``topic=...`` query params per the Mercure spec.
                params: list[tuple[str, str]] = [
                    ("topic", topic) for topic in topics
                ]
                params.append(("authorization", mercure_jwt))
                headers = {}
                if self._last_event_id:
                    headers["Last-Event-ID"] = self._last_event_id

                async with aconnect_sse(
                    self._client, "GET", self._mercure_url,
                    params=params,
                    headers=headers,
                ) as event_source:
                    backoff = 1  # Reset on successful connection
                    logger.info("Connected to Mercure hub, topics: %s", topics)
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

    @staticmethod
    def _extract_dedup_key(raw: dict) -> Optional[str]:
        """Return a stable idempotency key for an inbound event, or None.

        Preference order:
        1. ``tool_call_id`` (top-level or nested in ``payload``) — the
           load-bearing key for AI tool calls.
        2. Top-level ``id`` — the request id for CommandRequest events.

        Returning None means "no idempotency basis" — caller should process
        the event without dedup (better one execution than zero).
        """
        tcid = raw.get("tool_call_id")
        if not isinstance(tcid, str) or not tcid:
            payload = raw.get("payload")
            if isinstance(payload, dict):
                nested = payload.get("tool_call_id")
                if isinstance(nested, str) and nested:
                    tcid = nested
        if isinstance(tcid, str) and tcid:
            return f"tcid:{tcid}"
        rid = raw.get("id")
        if isinstance(rid, str) and rid:
            return f"id:{rid}"
        return None

    def _dedup_should_process(self, key: Optional[str]) -> bool:
        """Bounded-LRU dedup check. True if the event is new.

        Side effects:
        - Evicts TTL-expired entries on every call (O(n) scan, n ≤ 256).
        - On hit: returns False; entry stays in the LRU (so a 3rd or
          4th republish during the same window also skips).
        - On miss: records the key, evicts oldest if over the size bound.
        """
        if key is None:
            return True  # Cannot dedup an event with no idempotency key.
        now = time.monotonic()
        # Drop anything past TTL — cheap because OrderedDict iterates in
        # insertion order so we can stop at the first non-expired entry.
        expired_cutoff = now - self._DEDUP_TTL_SECONDS
        while self._seen_event_keys:
            oldest_key, first_seen = next(iter(self._seen_event_keys.items()))
            if first_seen >= expired_cutoff:
                break
            self._seen_event_keys.popitem(last=False)
        if key in self._seen_event_keys:
            return False
        self._seen_event_keys[key] = now
        # Enforce hard cap regardless of TTL — protects against a flood of
        # unique-id events from filling memory between TTL sweeps.
        while len(self._seen_event_keys) > self._DEDUP_MAX_ENTRIES:
            self._seen_event_keys.popitem(last=False)
        return True

    async def _handle_event(self, data: str) -> None:
        """Parse an SSE event payload and dispatch to executor."""
        try:
            raw = json.loads(data)

            # Dual-publish dedup. The server publishes the same payload to
            # /commands AND /ai-tool-calls during the transition window;
            # without this guard a single logical event would dispatch twice.
            dedup_key = self._extract_dedup_key(raw)
            if not self._dedup_should_process(dedup_key):
                logger.debug(
                    "Skipping duplicate event (dedup_key=%s) — dual-publish "
                    "transition window", dedup_key,
                )
                return

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

            raw_type = raw.get("type")

            # AI chat tool calls are discriminated FIRST, before the
            # CommandType parse: the dispatch envelope carries a
            # ``tool_call_id`` (web-console CommandRequests never do), and
            # several AI tool names collide with the 8 relay verbs
            # (run_command, get_logs, transfer_file, deploy, …). Without
            # this check a colliding AI dispatch would execute down the
            # web-console path — skipping the AI guard policy + audit and
            # posting its result to the wrong endpoint (the command-result
            # route only matches web-console v4 ids), so the AI turn would
            # time out despite the command having run.
            #
            # With an executor wired (headless `servonaut connect`), the
            # call executes here; without one (the TUI's in-process
            # listener), it's skipped — the chat panel executes its own
            # conversations from the chat-stream SSE ``tool_call`` event,
            # and executing the Mercure copy too would double-run the tool.
            if self._carries_tool_call_id(raw):
                if self._ai_tool_executor is not None:
                    await self._handle_ai_tool_call(raw)
                else:
                    logger.debug(
                        "Skipping AI tool-call event type=%r (no executor "
                        "wired; chat panel owns execution): id=%s",
                        raw_type, raw.get("id"),
                    )
                return

            try:
                command_type = CommandType(raw_type)
            except ValueError:
                # Legacy (pre-enrichment) AI dispatches carry no
                # tool_call_id; a non-CommandType name + an id is the
                # remaining marker.
                if self._ai_tool_executor is not None:
                    from servonaut.services.relay_tool_executor import (
                        is_ai_tool_call_event,
                    )
                    if is_ai_tool_call_event(raw):
                        await self._handle_ai_tool_call(raw)
                        return
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

    @staticmethod
    def _carries_tool_call_id(raw: dict) -> bool:
        """True when the event carries a ``tool_call_id`` (top-level or in
        payload) — the definitive marker of an AI chat tool dispatch."""
        if isinstance(raw.get("tool_call_id"), str) and raw["tool_call_id"]:
            return True
        payload = raw.get("payload")
        if isinstance(payload, dict):
            nested = payload.get("tool_call_id")
            return isinstance(nested, str) and bool(nested)
        return False

    async def _handle_ai_tool_call(self, raw: dict) -> None:
        """Execute an AI chat tool call via the wired executor.

        The executor owns the parse → bridge → tool-result-POST round
        trip and never raises; this wrapper just adds the foreground
        status line that relay commands already get.
        """
        start = time.monotonic()
        result = await self._ai_tool_executor.execute(raw)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        if result is None:
            return
        status_icon = "v" if result.status == "ok" else "x"
        msg = (f"[ai:{raw.get('tool') or raw.get('type')}] "
               f"{result.status} {status_icon} ({elapsed_ms}ms)")
        logger.info("Relay AI tool call: %s", msg)
        print(f"  {msg}")

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
        """Send a heartbeat to the backend every N seconds.

        The first iteration posts a ``cli.handshake`` (wire format v1.0)
        carrying ``version``, ``cli_release_channel``, ``providers_configured``,
        and ``capabilities``. Subsequent ticks post the minimal
        ``cli.heartbeat`` shape. Both use the same endpoint; the server
        distinguishes via the ``type`` field.
        """
        url = f"{self._base_url}/api/cli/heartbeat"
        while self._running:
            try:
                if not self._handshake_sent:
                    payload = self._build_handshake()
                    self._handshake_sent = True
                else:
                    payload = self._build_heartbeat()
                response = await self._authed_request(
                    "POST", url,
                    json=payload,
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
