"""Async SSE consumer for the hosted Servonaut AI gateway (T2).

Wraps :func:`httpx_sse.aconnect_sse` to expose a simple
``AsyncIterator[dict]`` of normalised events. The generator owns the
underlying :class:`httpx.AsyncClient` lifetime via ``async with`` so a
caller cancelling the consuming worker (``GeneratorExit``) cleanly
unwinds the connection — see Risk register §8.

Public surface
--------------

- :class:`SSEStreamDead` — raised when the heartbeat watchdog elapses
  without any event arriving.
- :class:`SSEStreamError` — raised for terminal ``error`` SSE events.
- :func:`stream_sse` — the generator itself.

Server event vocabulary (per plan §"Streaming SSE event vocabulary"):

================  ============================================================
Event             Yielded?            Notes
================  ============================================================
``token``         yes                 streaming text delta
``tool_call``     yes                 model wants the CLI to run a tool
``tool_result``   yes                 server-executed tool's result
``usage``         yes                 terminal usage block + quota
``ping``          NO                  absorbed; only resets watchdog
``error``         raised              terminal :class:`SSEStreamError`
``info``          yes (synthesised)   ``tool_round_limit`` / ``wall_clock_cap``
================  ============================================================

Decisions (architect plan §"Critical decisions" item 8)
-------------------------------------------------------

- ``SSE_HEARTBEAT_DEAD_S = 35.0`` — server pings every 15s; 2× + 5s grace.
- ``SSE_DEFAULT_TIMEOUT = 120.0`` — matches server's ``WALL_CLOCK_CAP_S``.
- 401 mid-stream is **not** retried (would resend the body); we surface
  it as a typed :class:`APIError` via :meth:`APIClient._parse_error`.
"""

from __future__ import annotations

import json
import logging
from time import monotonic
from typing import TYPE_CHECKING, Any, AsyncIterator, Dict, Optional

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient

try:
    import httpx
    from httpx_sse import aconnect_sse
    HAS_HTTPX_SSE = True
except ImportError:  # pragma: no cover — httpx-sse is a hard dep
    httpx = None  # type: ignore[assignment]
    aconnect_sse = None  # type: ignore[assignment]
    HAS_HTTPX_SSE = False

logger = logging.getLogger(__name__)

# 15s server-side ping interval × 2 + 5s grace.
SSE_HEARTBEAT_DEAD_S: float = 35.0

# Matches server's ``WALL_CLOCK_CAP_S`` for a single chat turn.
SSE_DEFAULT_TIMEOUT: float = 120.0

# Server-emitted error codes that are NOT terminal failures from the
# user's perspective — they're informational caps the UI renders softly.
_INFO_ERROR_CODES = frozenset({
    "tool_round_limit",
    "wall_clock_cap_exceeded",
})

# Test seam: override to inject an :class:`httpx.MockTransport` without
# patching the global ``httpx.AsyncClient`` constructor. Production code
# leaves this ``None``; tests in ``tests/test_sse_stream.py`` set it via
# ``monkeypatch.setattr``.
_TEST_TRANSPORT: Any = None


class SSEStreamDead(RuntimeError):
    """Raised when no event arrives for >``SSE_HEARTBEAT_DEAD_S`` seconds.

    The server pings every ~15s; if we go silent for >35s the underlying
    connection is presumed dead. Caller should surface this as
    ``upstream_unavailable`` and offer a fallback.
    """


class SSEStreamError(RuntimeError):
    """Raised when the server emits a terminal ``event: error`` SSE event.

    Carries the full error envelope so the T5 error handler can map
    each ``code`` to a deterministic UX action (toast / modal / banner).
    """

    def __init__(
        self,
        code: str,
        message: str,
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_after = retry_after
        self.details = details or {}


async def stream_sse(
    api_client: "APIClient",
    path: str,
    body: Optional[dict],
    *,
    timeout: float = SSE_DEFAULT_TIMEOUT,
    method: str = "POST",
    params: Optional[Dict[str, Any]] = None,
) -> AsyncIterator[Dict[str, Any]]:
    """Stream Server-Sent Events from ``path`` with ``body``.

    ``method``/``params`` support GET streams (e.g. the findings
    scan-progress endpoint) alongside the original POST-with-JSON-body
    chat streams; the defaults preserve the original behaviour.

    Yields normalised events of shape ``{"event": str, "data": dict}``.

    Behaviour:

    - ``ping`` events are absorbed inline and NEVER yielded; they only
      reset the heartbeat watchdog.
    - ``error`` events with code in ``_INFO_ERROR_CODES`` are yielded as
      ``{"event": "info", "data": {"code": ..., "message": ...}}`` so
      the UI can render them softly.
    - Any other ``error`` event raises :class:`SSEStreamError`.
    - Pre-stream HTTP failures (4xx/5xx before the SSE body opens) are
      surfaced via :meth:`APIClient._parse_error` — typed
      :class:`APIError` subclasses.
    - On connection silence >``SSE_HEARTBEAT_DEAD_S`` →
      :class:`SSEStreamDead`.
    - On :class:`GeneratorExit` (caller cancellation) the
      ``async with`` unwinds the underlying ``httpx.AsyncClient``
      cleanly — see Risk register §8.
    """
    if not HAS_HTTPX_SSE:  # pragma: no cover
        raise RuntimeError(
            "httpx-sse not installed. Install with: pip install 'httpx-sse>=0.4'"
        )

    # Lazy import to avoid circular at module load (api_client imports us).
    from servonaut.services.api_client import _api_base

    headers = api_client._get_headers()
    # Streaming responses must NOT request gzip — server emits text/event-stream.
    headers.pop("Content-Length", None)

    url = f"{_api_base()}{path}"

    # The async client lives for the duration of the generator. ``async with``
    # guarantees clean teardown on GeneratorExit, normal completion, or any
    # raised exception (including SSEStreamDead).
    client_kwargs: Dict[str, Any] = {"timeout": timeout}
    if _TEST_TRANSPORT is not None:
        client_kwargs["transport"] = _TEST_TRANSPORT
    elif getattr(api_client, "transport", None) is not None:
        # Same seam the plain requests use (demo-mode chat replay).
        client_kwargs["transport"] = api_client.transport
    async with httpx.AsyncClient(**client_kwargs) as client:
        try:
            async with aconnect_sse(
                client,
                method,
                url,
                headers=headers,
                json=body,
                params=params,
            ) as event_source:
                response = event_source.response

                # If the server returned non-2xx, the body is a JSON error
                # envelope, not SSE. Surface it as a typed APIError exactly
                # like buffered POSTs do.
                if response.status_code >= 400:
                    # httpx streamed responses need explicit aread() before
                    # body access — _parse_error reads .json()/.text.
                    await response.aread()
                    raise api_client._parse_error(response)

                async for normalised in _iterate_with_watchdog(event_source):
                    if normalised is None:
                        continue  # ping absorbed
                    yield normalised
        except GeneratorExit:
            # Caller cancelled (e.g. Textual worker stopped). The async with
            # block above is already unwinding — re-raise so the generator
            # terminates the way Python expects.
            logger.debug("SSE stream cancelled by caller (GeneratorExit)")
            raise


async def _iterate_with_watchdog(
    event_source: Any,
) -> AsyncIterator[Optional[Dict[str, Any]]]:
    """Iterate the SSE stream and enforce the heartbeat watchdog.

    Yields a normalised dict for each event, or ``None`` for an absorbed
    ping. Raises :class:`SSEStreamDead` if no event arrives within
    ``SSE_HEARTBEAT_DEAD_S`` seconds, and :class:`SSEStreamError` for
    terminal error events.
    """
    import asyncio

    last_event_at = monotonic()
    aiter = event_source.aiter_sse().__aiter__()

    while True:
        elapsed = monotonic() - last_event_at
        remaining = SSE_HEARTBEAT_DEAD_S - elapsed
        if remaining <= 0:
            raise SSEStreamDead(
                f"No SSE event received for >{SSE_HEARTBEAT_DEAD_S}s — "
                f"upstream presumed dead"
            )

        try:
            sse = await asyncio.wait_for(aiter.__anext__(), timeout=remaining)
        except asyncio.TimeoutError as exc:
            raise SSEStreamDead(
                f"No SSE event received for >{SSE_HEARTBEAT_DEAD_S}s — "
                f"upstream presumed dead"
            ) from exc
        except StopAsyncIteration:
            # Stream closed gracefully by the server.
            return

        last_event_at = monotonic()
        normalised = _normalise_event(sse)
        if normalised is None:
            # ping — already logged inside _normalise_event.
            yield None
            continue
        yield normalised


def _normalise_event(sse: Any) -> Optional[Dict[str, Any]]:
    """Translate a raw :class:`ServerSentEvent` into our dict shape.

    Returns ``None`` for ``ping`` (absorbed). Raises
    :class:`SSEStreamError` for terminal ``error`` events. Synthesises
    an ``info`` event for ``error`` codes in ``_INFO_ERROR_CODES``.
    """
    event_name = sse.event or "message"

    if event_name == "ping":
        # Absorbed — never yielded. Server emits these every ~15s.
        return None

    # Parse the data payload. Empty data lines are valid (e.g. some
    # heartbeats); fall back to an empty dict.
    raw = sse.data or ""
    data: Dict[str, Any]
    if not raw.strip():
        data = {}
    else:
        try:
            parsed = json.loads(raw)
            data = parsed if isinstance(parsed, dict) else {"value": parsed}
        except json.JSONDecodeError:
            logger.warning(
                "SSE event %r had non-JSON data line; passing through as raw",
                event_name,
            )
            data = {"raw": raw}

    if event_name == "error":
        code = str(data.get("code") or "unknown")
        message = str(data.get("message") or f"Server error: {code}")
        retry_after_raw = data.get("retry_after")
        retry_after: Optional[int] = None
        if retry_after_raw is not None:
            try:
                retry_after = int(retry_after_raw)
            except (TypeError, ValueError):
                retry_after = None
        details = data.get("details") if isinstance(data.get("details"), dict) else None

        if code in _INFO_ERROR_CODES:
            # Plan invariant: tool_round_limit and wall_clock_cap_exceeded
            # are NOT raised — they are informational caps.
            return {
                "event": "info",
                "data": {
                    "code": code,
                    "message": message,
                    **({"details": details} if details else {}),
                },
            }

        raise SSEStreamError(
            code=code,
            message=message,
            retry_after=retry_after,
            details=details,
        )

    return {"event": event_name, "data": data}
