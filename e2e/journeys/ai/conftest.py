"""Fixtures for the AI journeys.

``fake_ai`` is the local stand-in for the bring-your-own providers.
``_close_chat_streams`` runs for every AI journey: at teardown it fails the
journey if a hosted chat stream it opened on FakeCloud is still open.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

# How long a stream may take to notice its client left (it checks every 20 ms).
_STREAM_CLOSE_SECONDS = 3.0


@pytest.fixture(scope="session")
def _fake_ai_server() -> Any:
    from e2e.harness.fake_ai import FakeAi

    server = FakeAi().start()
    yield server
    server.stop()


@pytest.fixture
def fake_ai(_fake_ai_server: Any, journey: Any) -> Any:
    """The OpenAI / Anthropic / Ollama stand-in, emptied for this journey.

    Its request log joins the journey's failure artifacts.
    """
    _fake_ai_server.reset()
    yield _fake_ai_server
    rows = _fake_ai_server.requests()
    if rows:
        journey.staging.mkdir(parents=True, exist_ok=True)
        with (journey.staging / "fake_ai_requests.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")


@pytest.fixture(autouse=True)
def _close_chat_streams(journey: Any) -> Any:
    """Backstop: no hosted chat stream outlives its journey."""
    from e2e.harness.waits import wait_for

    yield
    cloud = journey.fake_cloud
    if cloud is None:
        return
    try:
        wait_for(
            lambda: not cloud.ai.open_streams(),
            timeout=_STREAM_CLOSE_SECONDS,
            desc="chat streams to close",
        )
    except AssertionError:
        pytest.fail(f"a chat stream outlived the journey: {cloud.ai.open_streams()}")
