"""SSE fixture replay helpers for stream tests.

Turns a ``.sse`` byte fixture into an :class:`httpx.MockTransport` that
:func:`servonaut.services.ai_sse.stream_sse` can consume end-to-end —
no real socket, no real server. This lets the SSE tests exercise the
full ``aconnect_sse`` → :func:`_normalise_event` → consumer pipeline.

Two transports are exposed:

- :func:`build_mock_transport` — replay the fixture as one chunk.
- :func:`build_mock_transport_with_delay` — replay with an ``asyncio.sleep``
  inserted between two events. Used to test the heartbeat watchdog
  without burning real wall-clock time (caller cuts ``SSE_HEARTBEAT_DEAD_S``
  via ``monkeypatch`` to ~0.5s and pairs it with a 1s injected delay).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List, Optional

import httpx

_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sse"


def fixture_for(name: str) -> Path:
    """Resolve a fixture name to its absolute path.

    The ``.sse`` extension is appended automatically if absent.
    """
    if not name.endswith(".sse"):
        name = f"{name}.sse"
    path = _FIXTURES_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"SSE fixture not found: {path}")
    return path


def _split_events(raw: bytes) -> List[bytes]:
    """Split a fixture into individual SSE events on the blank-line boundary.

    Each chunk includes its trailing blank line so the SSE decoder
    sees a complete event per chunk.
    """
    text = raw.decode("utf-8")
    parts: List[bytes] = []
    buffer: List[str] = []
    for line in text.splitlines(keepends=True):
        if line.strip() == "":
            buffer.append(line)
            chunk = "".join(buffer)
            if chunk.strip():
                parts.append(chunk.encode("utf-8"))
            buffer = []
        else:
            buffer.append(line)
    # Trailing event without blank line terminator.
    tail = "".join(buffer)
    if tail.strip():
        parts.append(tail.encode("utf-8"))
    return parts


def build_mock_transport(fixture_path: Path) -> httpx.MockTransport:
    """Return a transport that replays the entire fixture in one response.

    The whole byte stream is delivered as a single ``content`` payload
    with ``content-type: text/event-stream`` — the SSE decoder happily
    chunks it back into individual events.
    """
    raw = fixture_path.read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=raw,
        )

    return httpx.MockTransport(handler)


def build_mock_transport_with_delay(
    fixture_path: Path,
    delay_at_event: int,
    delay_seconds: float,
) -> httpx.MockTransport:
    """Return a transport that pauses between events.

    Streams events one-by-one as an async byte iterator; after emitting
    the ``delay_at_event``-th chunk (0-indexed) it sleeps for
    ``delay_seconds`` before continuing. This is how the heartbeat
    watchdog test injects silence without burning real wall-clock.
    """
    raw = fixture_path.read_bytes()
    chunks = _split_events(raw)

    async def stream_body():
        for idx, chunk in enumerate(chunks):
            yield chunk
            if idx == delay_at_event:
                await asyncio.sleep(delay_seconds)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=stream_body(),
        )

    return httpx.MockTransport(handler)


def build_mock_transport_error(
    status_code: int,
    body: dict,
) -> httpx.MockTransport:
    """Return a transport that returns a JSON error envelope (no SSE body)."""
    import json

    payload = json.dumps(body).encode("utf-8")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            headers={"content-type": "application/json"},
            content=payload,
        )

    return httpx.MockTransport(handler)


def build_cancellable_transport(
    fixture_path: Path,
    on_close_recorder: Optional[List[bool]] = None,
) -> httpx.MockTransport:
    """Replay ``fixture_path`` and never close — caller must cancel.

    The async generator emits each event then awaits forever; the test
    cancels the consumer to prove that the ``async with`` unwinds
    cleanly. ``on_close_recorder`` (a single-element list) is set to
    ``True`` when the body generator's ``finally`` runs.
    """
    raw = fixture_path.read_bytes()
    chunks = _split_events(raw)

    async def stream_body():
        try:
            for chunk in chunks:
                yield chunk
            # Park forever — caller cancels.
            while True:
                await asyncio.sleep(3600)
        finally:
            if on_close_recorder is not None:
                on_close_recorder.append(True)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=stream_body(),
        )

    return httpx.MockTransport(handler)
