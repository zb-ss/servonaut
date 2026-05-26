"""Servonaut hosted AI provider.

Adapter for the hosted Servonaut AI gateway at ``POST /api/ai/chat``.
Ships both the buffered (``stream: false``) path and the streaming
SSE consumer (``stream_chat``).

Auth is via the OAuth bearer token already on ``AuthService``;
no per-provider API key configuration is required. ``is_available()``
reports availability based on local cached entitlement state only —
it never performs a network call.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any, AsyncIterator, Dict, List, Literal, Optional, TYPE_CHECKING

from ..interfaces import AIProviderInterface
from ._guards import require_premium_ai, require_premium_ai_stream

if TYPE_CHECKING:
    from servonaut.config.schema import AIProviderConfig
    from servonaut.services.api_client import APIClient
    from servonaut.services.auth_service import AuthService

logger = logging.getLogger(__name__)

# Wave 2 Agent D / T2 landed: ``stream_chat`` decorated with
# ``require_premium_ai_stream`` (NOT ``require_premium_ai``) — wrapping
# an ``async def`` generator with the plain decorator silently swallows
# every yield, so streams must use the generator-aware variant.


# Allowed task enum values (mirrors backend AiChatController validation).
_VALID_TASKS = frozenset({
    "chat",
    "analyze_logs",
    "security_audit",
    "cost_report",
    "incident_triage",
})

_DEFAULT_TASK = "chat"
_ANALYZE_TASK = "analyze_logs"
_REQUIRED_FEATURE = "premium_ai"
_CHAT_PATH = "/api/ai/chat"
_TOPUP_PATH = "/api/ai/topup/checkout"

# Rate-limit retry budget (T5). Buffered chat retries up to this many
# times when the server returns ``rate_limited``; streaming retries only
# when the failure happens before the first SSE event reaches the caller
# (mid-stream retry would re-send the request body and is unsafe).
_RATE_LIMIT_MAX_ATTEMPTS = 3
_RATE_LIMIT_JITTER_S = 2.0
_VALID_TOPUP_PACKS = frozenset({"small", "medium", "large"})

# A4 — pin the expected Stripe Checkout host. Any other origin in the
# server response means we either talk to a compromised gateway or a
# misconfigured staging — either way, do NOT auto-launch the browser at it.
_STRIPE_CHECKOUT_HOST_PREFIX = "https://checkout.stripe.com/"


def is_valid_stripe_checkout_url(url: str) -> bool:
    """Return True iff *url* is a Stripe-hosted checkout URL.

    Strict prefix match on :data:`_STRIPE_CHECKOUT_HOST_PREFIX` — this is
    deliberately conservative. Any subdomain change or scheme drift
    blocks the auto-open path; the user can still copy-paste the URL
    manually.
    """
    if not isinstance(url, str) or not url:
        return False
    return url.startswith(_STRIPE_CHECKOUT_HOST_PREFIX)


class ServonautProvider(AIProviderInterface):
    """Hosted Servonaut AI provider — buffered + streaming.

    Buffered responses contain the full 11-field payload defined in
    the plan §"Buffered (stream: false) JSON response". Streaming
    yields the SSE event vocabulary defined in §"Streaming (stream: true)"
    plus a synthetic ``done`` terminator.
    """

    # Opaque to clients — server's ModelRouter chooses the actual model.
    DEFAULT_MODEL = "servonaut-auto"

    def __init__(
        self,
        api_client: "APIClient",
        auth_service: "AuthService",
    ) -> None:
        self._api_client = api_client
        self._auth_service = auth_service

    def is_available(self) -> bool:
        """Return True iff caller is authenticated AND has the ``premium_ai`` feature.

        This check is **synchronous** and **never makes a network call** —
        it only reads locally cached ``AuthToken`` state. Callers can poll
        this on every keystroke without latency concern.
        """
        if not self._auth_service.is_authenticated:
            return False
        return self._auth_service.has_feature(_REQUIRED_FEATURE)

    @require_premium_ai
    async def analyze(
        self,
        text: str,
        system_prompt: str,
        config: "AIProviderConfig",
    ) -> dict:
        """Single-shot text analysis.

        Thin wrapper that calls :meth:`chat` with one user message, then
        narrows the result to the keys the ``AIProviderInterface.analyze``
        contract guarantees (``content``, ``tokens_used``, ``model``,
        ``input_tokens``, ``output_tokens``).
        """
        messages = [{"role": "user", "content": text}]
        result = await self._chat_internal(
            messages=messages,
            system_prompt=system_prompt,
            config=config,
            tools=None,
            task=_ANALYZE_TASK,
        )
        return {
            "content": result.get("content", ""),
            "tokens_used": result.get("tokens_used", 0),
            "input_tokens": result.get("input_tokens", 0),
            "output_tokens": result.get("output_tokens", 0),
            "model": result.get("model", ""),
        }

    @require_premium_ai
    async def chat(
        self,
        messages: List[Dict],
        system_prompt: str,
        config: "AIProviderConfig",
        tools: Optional[List[Dict]] = None,
        *,
        task: str = _DEFAULT_TASK,
        allow_tools: bool = True,
        conversation_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> dict:
        """Multi-turn chat (buffered).

        Returns the union of the standard provider-result keys
        (``content``, ``tool_calls``, ``tokens_used``, ``input_tokens``,
        ``output_tokens``, ``model``, ``raw_message``, ``stop_reason``)
        plus the Servonaut-specific extras downstream tasks consume:
        ``conversation_id``, ``fallback_used``, ``quota`` (raw dict),
        ``cached_tokens``, ``tool_calls_count``, ``vendor``, ``warning``.

        Buffered mode never produces ``tool_calls`` — server-side tools
        are dispatched and their results are folded into the buffered
        response; ``tool_calls_count`` summarises how many ran. Only the
        streaming path (T2) surfaces individual ``tool_call`` events.

        Keyword-only extras (C2 fix — public surface widened):

        - ``task``: one of the 5 valid task labels (default ``"chat"``).
        - ``allow_tools``: server emits ``tool_call`` events only when True.
        - ``conversation_id``: continue a previous server-side thread.
        - ``context``: instance / log / time-window context block.
        """
        return await self._chat_internal(
            messages=messages,
            system_prompt=system_prompt,
            config=config,
            tools=tools,
            task=task,
            allow_tools=allow_tools,
            conversation_id=conversation_id,
            context=context,
        )

    async def _chat_internal(
        self,
        *,
        messages: List[Dict],
        system_prompt: str,
        config: "AIProviderConfig",
        tools: Optional[List[Dict]],
        task: str,
        conversation_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        allow_tools: bool = True,
    ) -> dict:
        """Build the request body, POST to ``/api/ai/chat`` (buffered),
        and unmarshal the response into the unified result dict.

        ``APIError`` and subclasses propagate to the caller — the T5
        error handler owns the UX mapping. We do NOT wrap or swallow.
        """
        body = self._build_chat_body(
            messages=messages,
            system_prompt=system_prompt,
            tools=tools,
            task=task,
            conversation_id=conversation_id,
            context=context,
            allow_tools=allow_tools,
            stream=False,
        )

        logger.debug(
            "ServonautProvider buffered chat: task=%s messages=%d allow_tools=%s",
            task, len(body["messages"]), allow_tools,
        )

        # APIClient.post enforces json= keyword-only; positional args raise.
        # T5 rate-limit retry: honour ``retry_after`` + jitter, max 3 attempts.
        data = await self._post_with_rate_limit_retry(_CHAT_PATH, body)
        return self._unmarshal_buffered_response(data)

    async def _post_with_rate_limit_retry(
        self,
        path: str,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        """POST ``body`` with bounded ``rate_limited`` retry.

        Honours :attr:`RateLimitedError.response_headers["retry-after"]`
        (or ``error.details.retry_after``) plus a small uniform jitter
        so a stampede doesn't all retry on the same tick. Re-raises the
        last error after ``_RATE_LIMIT_MAX_ATTEMPTS`` (so the T5 handler
        still sees the typed exception), and re-raises any non-429
        immediately — only ``RateLimitedError`` is retried here.
        """
        from servonaut.services.api_client import RateLimitedError

        last_error: Optional[RateLimitedError] = None
        for attempt in range(_RATE_LIMIT_MAX_ATTEMPTS):
            try:
                return await self._api_client.post(path, json=body)
            except RateLimitedError as exc:
                last_error = exc
                # Don't sleep after the last attempt — surface the error.
                if attempt == _RATE_LIMIT_MAX_ATTEMPTS - 1:
                    break
                delay = self._retry_after_seconds(exc) or 0
                jitter = random.uniform(0, _RATE_LIMIT_JITTER_S)
                wait = max(0.0, delay + jitter)
                logger.info(
                    "rate_limited (attempt %d/%d) — sleeping %.2fs",
                    attempt + 1, _RATE_LIMIT_MAX_ATTEMPTS, wait,
                )
                await asyncio.sleep(wait)
        # Exhausted — surface the last error so the T5 handler can map it.
        # D4 — was an ``assert``; ``python -O`` strips asserts so a stripped
        # build would fall through to ``raise None`` (TypeError). Use a
        # runtime check that raises a typed RuntimeError on the impossible
        # branch so the invariant is preserved under optimisation.
        if last_error is None:
            raise RuntimeError(
                "rate-limit retry loop exited without recording an error"
            )
        raise last_error

    @staticmethod
    def _retry_after_seconds(err: Any) -> Optional[int]:
        """Best-effort ``retry-after`` extraction across header / details."""
        # Header form (RFC 7231 §7.1.3) — preferred when present.
        headers = getattr(err, "response_headers", None) or {}
        raw = headers.get("retry-after")
        if raw is None:
            details = getattr(err, "details", None) or {}
            if isinstance(details, dict):
                raw = details.get("retry_after")
        if raw is None:
            return None
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None

    def _build_chat_body(
        self,
        *,
        messages: List[Dict],
        system_prompt: str,
        tools: Optional[List[Dict]],
        task: str,
        conversation_id: Optional[str],
        context: Optional[Dict[str, Any]],
        allow_tools: bool,
        stream: bool,
    ) -> Dict[str, Any]:
        """Build the request body for ``POST /api/ai/chat``.

        Shared between buffered (``_chat_internal``) and streaming
        (``stream_chat``) paths so both endpoints send identical shapes
        modulo the ``stream`` flag.

        Raises ``ValueError`` for unknown ``task`` values — caller never
        reaches the network.
        """
        if task not in _VALID_TASKS:
            raise ValueError(
                f"Invalid task {task!r}; expected one of {sorted(_VALID_TASKS)!r}"
            )

        # System prompt is sent but the server replaces it from a server-side
        # cache; we still include it for parity with other providers.
        api_messages: List[Dict[str, Any]] = []
        if system_prompt:
            api_messages.append({"role": "system", "content": system_prompt})
        api_messages.extend(messages)

        body: Dict[str, Any] = {
            "task": task,
            "messages": api_messages,
            "allow_tools": allow_tools,
            "stream": stream,
        }
        if conversation_id:
            body["conversation_id"] = conversation_id
        if context:
            body["context"] = context
        if tools:
            # Forwarded for parity; server may ignore in favour of its
            # built-in tool catalogue gated by entitlements.
            body["tools"] = tools
        return body

    @require_premium_ai_stream
    async def stream_chat(
        self,
        messages: List[Dict],
        system_prompt: str,
        config: "AIProviderConfig",
        *,
        conversation_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        allow_tools: bool = True,
        task: str = _DEFAULT_TASK,
    ) -> AsyncIterator[Dict[str, Any]]:
        """Stream a chat turn over Server-Sent Events.

        Yields normalised events the chat panel consumes directly:

        - ``{"event": "token", "data": {"text": ...}}``
        - ``{"event": "tool_call", "data": {"tool_call_id": ..., ...}}``
        - ``{"event": "tool_result", "data": {"tool_call_id": ..., ...}}``
        - ``{"event": "usage", "data": {full usage block}}``
        - ``{"event": "info", "data": {"code": "tool_round_limit"|"wall_clock_cap_exceeded", ...}}``
        - ``{"event": "done", "data": {}}`` — synthesised after the
          stream closes naturally so consumers can detect graceful end-of-turn.

        Surfaces:

        - :class:`servonaut.services.ai_sse.SSEStreamError` — terminal
          server error event (T5 error handler maps to UX action).
        - :class:`servonaut.services.ai_sse.SSEStreamDead` — heartbeat
          watchdog tripped; no event for >35s.
        - :class:`APIError` and subclasses — pre-stream HTTP failures
          (e.g. 429 before the SSE body opens).

        Note: ``ping`` events are absorbed inside the SSE consumer and
        never reach this generator — see :func:`ai_sse.stream_sse`.
        """
        body = self._build_chat_body(
            messages=messages,
            system_prompt=system_prompt,
            tools=None,
            task=task,
            conversation_id=conversation_id,
            context=context,
            allow_tools=allow_tools,
            stream=True,
        )

        logger.debug(
            "ServonautProvider stream chat: task=%s messages=%d "
            "allow_tools=%s conversation_id=%s",
            task,
            len(body["messages"]),
            allow_tools,
            conversation_id or "<new>",
        )

        async for event in self._api_client.stream_sse(_CHAT_PATH, body):
            if event.get("event") == "tool_catalog":
                # PR5' audit-only consumer. The static _LOCAL_TOOL_HANDLERS map
                # in ai_tool_bridge.py is source of truth for dispatch; the
                # received catalog is logged but not used for routing yet.
                # PR6'+ will build the live-catalog consumer on this wire.
                self._handle_tool_catalog_event(event.get("data") or {})
                continue
            yield event

        # Synthesise a terminal ``done`` event so callers can distinguish
        # graceful stream-close from an exception-raising terminal event.
        yield {"event": "done", "data": {}}

    def _handle_tool_catalog_event(self, event_data: Dict[str, Any]) -> None:
        """Audit-only handler for the ``tool_catalog`` SSE event (PR5').

        Receives the catalog envelope emitted by the server at chat-stream
        open. In PR5' we log the receipt to ``~/.servonaut/mcp_audit.jsonl``
        as evidence the wire works, but we do NOT update dispatch state —
        the static ``_LOCAL_TOOL_HANDLERS`` map in ``ai_tool_bridge.py``
        remains the source of truth. PR6'+ will build the live-catalog
        consumer on this wire.

        Degrades gracefully if no audit logger is wired: falls back to a
        standard ``logger.info`` so the event is never silently dropped.
        """
        from datetime import datetime, timezone

        catalog_version = event_data.get("catalog_version")
        surface = event_data.get("surface")
        tools = event_data.get("tools") or []
        tool_count = len(tools)
        # Sample first 5 names only — avoids PII-adjacent info in audit row
        # and keeps the row compact for the audit viewer.
        tool_names_sample = [t.get("name") for t in tools[:5] if isinstance(t, dict)]
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        logger.info(
            "tool_catalog SSE event received: version=%s surface=%s tool_count=%d",
            catalog_version, surface, tool_count,
        )

        audit = getattr(self, "_audit", None)
        if audit is not None and callable(getattr(audit, "log", None)):
            try:
                audit.log(
                    "tool_catalog_received",
                    {},
                    "",
                    True,
                    "tool_catalog_received",
                    catalog_version=catalog_version,
                    surface=surface,
                    tool_count=tool_count,
                    tool_names_sample=tool_names_sample,
                    timestamp=ts,
                )
            except Exception:  # noqa: BLE001
                logger.exception("Failed to audit tool_catalog SSE event")
        # If no audit logger: the logger.info above already captured the event.

    @staticmethod
    def _unmarshal_buffered_response(data: Dict[str, Any]) -> Dict[str, Any]:
        """Map the 11-field buffered JSON to the unified provider-result dict.

        Missing fields fall back to defensive defaults so the caller can
        always assume every key is present. Numeric fields default to 0;
        booleans to False; strings to ""; ``quota`` to None.
        """
        if not isinstance(data, dict):
            data = {}

        content = data.get("content") or ""
        model = data.get("model") or ""
        vendor = data.get("vendor") or ""
        input_tokens = int(data.get("input_tokens") or 0)
        output_tokens = int(data.get("output_tokens") or 0)
        cached_tokens = int(data.get("cached_tokens") or 0)
        tool_calls_count = int(data.get("tool_calls_count") or 0)
        fallback_used = bool(data.get("fallback_used", False))
        conversation_id = data.get("conversation_id") or ""
        warning = data.get("warning") or ""
        # quota may legitimately be None (free user) — preserve that.
        quota = data.get("quota") if "quota" in data else None

        # Buffered responses do not surface individual tool calls — the
        # server has already executed them and their summary lives in
        # tool_calls_count. Streaming (T2) yields per-call events.
        tool_calls: List[Dict[str, Any]] = []
        stop_reason = "tool_use" if tool_calls_count > 0 else "end_turn"

        return {
            # Standard AIProviderInterface contract keys.
            "content": content,
            "tool_calls": tool_calls,
            "tokens_used": input_tokens + output_tokens,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "model": model,
            "raw_message": data,
            "stop_reason": stop_reason,
            # Servonaut-specific extras (consumed by T3 quota widget,
            # T5 error UX, T7 conversations panel, T10 chain awareness).
            "conversation_id": conversation_id,
            "fallback_used": fallback_used,
            "quota": quota,
            "cached_tokens": cached_tokens,
            "tool_calls_count": tool_calls_count,
            "vendor": vendor,
            "warning": warning,
        }

    async def topup_checkout(
        self,
        pack: Literal["small", "medium", "large"],
    ) -> str:
        """Open a Stripe Checkout session for a top-up pack (T8).

        Args:
            pack: Pack name — one of ``"small"``, ``"medium"``, ``"large"``.
                Server is authoritative on the dollar amount per pack;
                the CLI only routes the user to the right SKU.

        Returns:
            The ``checkout_url`` the caller opens in the user's browser
            via :func:`webbrowser.open`. Never empty on success — the
            server contract guarantees a populated URL on 2xx.

        Raises:
            ValueError: ``pack`` is not one of the three valid values.
            RuntimeError: server returned 2xx but omitted ``checkout_url``
                (defensive — should never happen against the live API).
            APIError subclass: any HTTP failure surfaces verbatim so the
                T5 handler maps it (e.g. ``rate_limited`` → backoff).

        Note:
            This is NOT gated by ``@require_premium_ai`` — a free user
            can buy a top-up to convert into the Solo plan. The server
            enforces plan eligibility on its side.
        """
        if pack not in _VALID_TOPUP_PACKS:
            raise ValueError(
                f"Invalid pack: {pack!r}; expected one of {sorted(_VALID_TOPUP_PACKS)!r}"
            )
        body = {"pack": pack}
        response = await self._api_client.post(_TOPUP_PATH, json=body)
        # Defensive: server contract says ``checkout_url`` is always set
        # on 2xx, but we'd rather fail loud than ``webbrowser.open("")``.
        url = response.get("checkout_url", "") if isinstance(response, dict) else ""
        if not url or not isinstance(url, str):
            raise RuntimeError(
                "Top-up server did not return a valid checkout_url"
            )
        return url
