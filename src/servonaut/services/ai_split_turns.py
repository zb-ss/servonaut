"""Split hosted AI chat turns: continue a turn the service paused for its tools.

A chat request that sends ``split_turns: true`` lets the hosted service end a
model round that waits on tools run here with a ``turn_suspended`` event, and
close the stream, instead of holding the stream (and a server worker) open
while the tools run and the user answers their confirmation prompts. Once the
tools' results are posted (``POST /api/ai/chat/tool-result``, unchanged),
``POST /api/ai/chat/continue`` streams the rest of the turn in the same event
vocabulary. A service that does not know the flag ignores it and never
suspends.

``turn_suspended`` data::

    {"continuation_id": "<id>",
     "tool_call_ids": ["<ids of the tool_call events it waits on>"],
     "expires_at": "<ISO 8601>"}

The continuation keeps until ``expires_at``; a call without a result by then
counts as timed out, and ``/continue`` answers 404 from then on. Refusals of
``/continue`` arrive before any stream starts and leave the continuation in
place, so retrying them cannot repeat a tool call.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, AsyncIterator, Dict, List, Optional, Tuple

from servonaut.services.ai_sse import SSEStreamError, coerce_retry_after
from servonaut.services.api_client import APIError

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient

logger = logging.getLogger(__name__)

TURN_SUSPENDED_EVENT = "turn_suspended"
CONTINUE_PATH = "/api/ai/chat/continue"

# Longest window the service gives a paused turn (its setting tops out at
# 900 s). A window that looks longer, or already closed, when the event
# arrives means the two clocks disagree, and is not used for prompt deadlines.
MAX_WINDOW_SECONDS = 900.0

# How long to keep retrying a refused /continue when the window is unknown:
# the shortest window the service uses.
FALLBACK_WINDOW_SECONDS = 60.0

# Kept free at the end of the window to post the last result and continue.
CONTINUE_MARGIN_SECONDS = 5.0

# Most of the window reserved for running a confirmed tool. A tool allowed
# to run longer may still finish in time; the prompt just does not wait for
# that worst case.
RUN_RESERVE_MAX_SECONDS = 60.0

# Wait between /continue attempts when a refusal names no retry-after.
DEFAULT_RETRY_SECONDS = 1.0

# Refusals that leave the continuation in place and are worth retrying.
_RETRYABLE_STATUSES = frozenset({409, 429, 503})

CONTINUATION_LOST_CODE = "continuation_not_found"
CONTINUATION_LOST_MESSAGE = (
    "The AI service stopped waiting for this turn's tools. "
    "Send your message again."
)


@dataclass(frozen=True)
class Suspension:
    """A paused turn, read from a ``turn_suspended`` event.

    ``respond_by`` is a :func:`time.monotonic` deadline for continuing the
    turn, or ``None`` when ``expires_at`` was missing or not believable.
    """

    continuation_id: str
    tool_call_ids: Tuple[str, ...]
    respond_by: Optional[float]
    received_at: float

    @classmethod
    def from_event(cls, data: Any) -> Optional["Suspension"]:
        """Parse the event's data; ``None`` when it names no continuation."""
        if not isinstance(data, dict):
            return None
        continuation_id = data.get("continuation_id")
        if not isinstance(continuation_id, str) or not continuation_id.strip():
            return None
        raw_ids = data.get("tool_call_ids")
        tool_call_ids = tuple(
            i for i in raw_ids if isinstance(i, str) and i
        ) if isinstance(raw_ids, list) else ()
        received_at = time.monotonic()
        window = window_seconds(data.get("expires_at"))
        return cls(
            continuation_id=continuation_id,
            tool_call_ids=tool_call_ids,
            respond_by=None if window is None else received_at + window,
            received_at=received_at,
        )

    def retry_until(self) -> float:
        """Monotonic time after which a refused /continue is not retried."""
        if self.respond_by is not None:
            return self.respond_by
        return self.received_at + FALLBACK_WINDOW_SECONDS


def window_seconds(expires_at: Any, *, now: Optional[float] = None) -> Optional[float]:
    """Seconds from *now* (wall clock) until *expires_at*, if believable.

    ``None`` for a missing or unparsable value, and for one that is already
    past or further away than :data:`MAX_WINDOW_SECONDS`: either means the
    clocks disagree, so the window cannot be measured from here.
    """
    if not isinstance(expires_at, str) or not expires_at.strip():
        return None
    text = expires_at.strip()
    if text.endswith(("Z", "z")):
        # Python 3.10's fromisoformat does not accept the Z suffix.
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    current = time.time() if now is None else now
    seconds = moment.timestamp() - current
    if seconds <= 0 or seconds > MAX_WINDOW_SECONDS:
        logger.warning(
            "turn_suspended expires_at %r is %.0f s away; not using it",
            expires_at, seconds,
        )
        return None
    return seconds


def prompt_deadline(
    respond_by: Optional[float],
    *,
    run_seconds: float,
    now: Optional[float] = None,
) -> Optional[float]:
    """Seconds a confirmation prompt may stay open in a paused turn.

    Leaves time to run the tool (at most :data:`RUN_RESERVE_MAX_SECONDS`),
    post its result and continue before the window closes. ``None`` when
    the window is unknown (the caller falls back to its own limit); ``0.0``
    when no time is left to answer.
    """
    if respond_by is None:
        return None
    current = time.monotonic() if now is None else now
    reserve = min(max(float(run_seconds), 0.0), RUN_RESERVE_MAX_SECONDS)
    return max(respond_by - current - reserve - CONTINUE_MARGIN_SECONDS, 0.0)


def awaited_tool_calls(
    held: List[Dict[str, Any]], suspension: Suspension,
) -> List[Dict[str, Any]]:
    """The held ``tool_call`` events the paused turn waits on, in call order.

    Each carries ``respond_by`` when the window is known. A held call the
    service does not wait on already has its result (a refused call), so it
    is not run here.
    """
    awaited = set(suspension.tool_call_ids)
    calls: List[Dict[str, Any]] = []
    for event in held:
        data = event.get("data") or {}
        call_id = data.get("tool_call_id")
        if call_id not in awaited:
            logger.info("ai stream: tool call %s already has a result; not running it", call_id)
            continue
        if suspension.respond_by is not None:
            data = {**data, "respond_by": suspension.respond_by}
        calls.append({**event, "data": data})
    return calls


def continuation_lost(reason: str, **details: Any) -> SSEStreamError:
    """The error for a paused turn that can no longer be continued."""
    return SSEStreamError(
        code=CONTINUATION_LOST_CODE,
        message=CONTINUATION_LOST_MESSAGE,
        details={"reason": reason, **details},
    )


async def stream_continuation(
    api_client: "APIClient",
    suspension: Suspension,
    *,
    silence_timeout: Optional[float] = None,
) -> AsyncIterator[Dict[str, Any]]:
    """Stream the rest of a paused turn from ``POST /api/ai/chat/continue``.

    Retries refusals that leave the continuation in place (409 while a
    result is still landing, 503 server busy, 429) after their retry-after,
    for as long as the window lasts. A lost continuation raises
    :class:`SSEStreamError` with code ``continuation_not_found``, never a
    bare 404: the chat panel takes a 404 :class:`APIError` for a stale
    conversation and would resend the whole turn.
    """
    body = {"continuation_id": suspension.continuation_id}
    while True:
        stream = api_client.stream_sse(
            CONTINUE_PATH,
            body,
            silence_timeout=silence_timeout,
            drain_terminal_error=True,
        )
        try:
            try:
                first = await stream.__anext__()
            except StopAsyncIteration:
                return
            except APIError as exc:
                delay = _retry_delay(exc, suspension)
                if delay is None:
                    raise _translated(exc) from exc
                logger.info(
                    "ai continue refused (%s %s); retrying in %.1f s",
                    exc.status, exc.code, delay,
                )
                await asyncio.sleep(delay)
                continue
            yield first
            async for event in stream:
                yield event
            return
        finally:
            await stream.aclose()


def _retry_delay(exc: APIError, suspension: Suspension) -> Optional[float]:
    """Seconds to wait before retrying *exc*, or ``None`` to give up."""
    if exc.status not in _RETRYABLE_STATUSES:
        return None
    delay = float(_retry_after(exc) or DEFAULT_RETRY_SECONDS)
    if time.monotonic() + delay > suspension.retry_until():
        return None
    return delay


def _retry_after(exc: APIError) -> Optional[int]:
    """The refusal's retry-after, from the header or the error details."""
    headers = exc.response_headers or {}
    value = coerce_retry_after(headers.get("retry-after"))
    if value is not None:
        return value
    details = exc.details if isinstance(exc.details, dict) else {}
    value = coerce_retry_after(details.get("retry_after_seconds"))
    if value is not None:
        return value
    return coerce_retry_after(details.get("retry_after"))


def _translated(exc: APIError) -> Exception:
    """The error the chat panel should see for a final /continue refusal."""
    if exc.status in (404, 409):
        # 404: unknown, expired or already continued. 409 that outlived the
        # window: the service has timed the tools out, so the turn is gone.
        return continuation_lost("refused", status=exc.status, server_code=exc.code)
    return exc
