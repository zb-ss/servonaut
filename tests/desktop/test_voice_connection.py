"""Unit tests for VoiceConnection (supervised voice worker process connection).

Tests handshake negotiation, framing transport, request-response matching,
asynchronous event dispatch, timeout handling, and connection termination.
"""

from __future__ import annotations

import concurrent.futures
import io
import os
import threading
import time
from typing import Any, List, Optional
import pytest

from servonaut.desktop.voice.connection import (
    VoiceConnection,
    VoiceConnectionClosedError,
    VoiceConnectionError,
    VoiceConnectionTimeoutError,
    VoiceRemoteError,
)
from servonaut.desktop.voice.protocol import (
    VOICE_PROTOCOL_VERSION,
    HandshakeRequest,
    HandshakeResponsePayload,
    InputPartialEvent,
    InputStartRequest,
    OutputStateEvent,
    PingRequest,
    ProbeRequest,
    ProbeResponsePayload,
    ShutdownRequest,
    VoiceErrorCode,
    VoiceErrorPayload,
    VoiceEvent,
    VoiceResponse,
    read_voice_frame,
    write_voice_frame,
)
from servonaut.desktop.voice.worker import VoiceWorker


class PipeTransport:
    """Creates a pair of bidirectional OS pipes for testing."""

    def __init__(self) -> None:
        # Parent writes to worker_r, worker reads from worker_r
        # Worker writes to parent_r, parent reads from parent_r
        p2w_r, p2w_w = os.pipe()
        w2p_r, w2p_w = os.pipe()

        self.parent_in = os.fdopen(w2p_r, "rb", buffering=0)
        self.parent_out = os.fdopen(p2w_w, "wb", buffering=0)

        self.worker_in = os.fdopen(p2w_r, "rb", buffering=0)
        self.worker_out = os.fdopen(w2p_w, "wb", buffering=0)

    def close(self) -> None:
        for f in (self.parent_in, self.parent_out, self.worker_in, self.worker_out):
            try:
                f.close()
            except Exception:
                pass


@pytest.fixture
def pipes():
    transport = PipeTransport()
    yield transport
    transport.close()


def test_voice_connection_lifecycle_mock_handshake(pipes):
    """Test successful handshake and communication against simulated worker."""
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)

    def mock_worker():
        # Read handshake request
        req = read_voice_frame(pipes.worker_in)
        assert isinstance(req, HandshakeRequest)
        # Send handshake response
        payload = HandshakeResponsePayload(
            worker_version="1.0.0",
            protocol_version=VOICE_PROTOCOL_VERSION,
            manifest_id="test-manifest",
            python_version="3.12.0",
            platform="linux",
            architecture="x86_64",
            capabilities=["stt_batch", "tts"],
            models_status={"whisper": True},
            audio_devices={"input": True, "output": True},
        )
        write_voice_frame(pipes.worker_out, VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload=payload))

    worker_thread = threading.Thread(target=mock_worker, daemon=True)
    worker_thread.start()

    hs = conn.connect(timeout=2.0)
    assert hs.manifest_id == "test-manifest"
    assert list(hs.capabilities) == ["stt_batch", "tts"]
    assert conn.is_connected
    assert conn.handshake_data == hs

    conn.close()
    worker_thread.join(timeout=1.0)


def test_voice_connection_handshake_version_mismatch(pipes):
    """Handshake is rejected if worker reports an incompatible protocol version."""
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)

    def mock_worker():
        req = read_voice_frame(pipes.worker_in)
        payload = HandshakeResponsePayload(
            worker_version="1.0.0",
            protocol_version=999,  # Incompatible version
            manifest_id="test",
            python_version="3.12.0",
            platform="linux",
            architecture="x86_64",
            capabilities=[],
            models_status={},
            audio_devices={},
        )
        write_voice_frame(pipes.worker_out, VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload=payload))

    threading.Thread(target=mock_worker, daemon=True).start()

    with pytest.raises(VoiceConnectionError, match="protocol version mismatch"):
        conn.connect(timeout=2.0)

    assert not conn.is_connected
    conn.close()


def test_voice_connection_handshake_rejected_by_worker(pipes):
    """Handshake fails if worker returns an error response."""
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)

    def mock_worker():
        req = read_voice_frame(pipes.worker_in)
        write_voice_frame(
            pipes.worker_out,
            VoiceResponse(
                id=f"resp-{req.id}",
                ref_id=req.id,
                ok=False,
                error=VoiceErrorPayload(
                    code=VoiceErrorCode.PROTOCOL_VIOLATION,
                    message="Unsupported client version",
                ),
            ),
        )

    threading.Thread(target=mock_worker, daemon=True).start()

    with pytest.raises(VoiceConnectionError, match="Worker rejected handshake"):
        conn.connect(timeout=2.0)

    assert not conn.is_connected
    conn.close()


def test_voice_connection_request_timeout(pipes):
    """Requests raise VoiceConnectionTimeoutError when worker does not reply."""
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)

    def mock_worker():
        req = read_voice_frame(pipes.worker_in)
        payload = HandshakeResponsePayload(
            worker_version="1.0.0",
            protocol_version=VOICE_PROTOCOL_VERSION,
            manifest_id="test",
            python_version="3.12.0",
            platform="linux",
            architecture="x86_64",
            capabilities=["tts"],
            models_status={},
            audio_devices={},
        )
        write_voice_frame(pipes.worker_out, VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload=payload))
        # Ignore subsequent requests to force timeout
        read_voice_frame(pipes.worker_in)

    threading.Thread(target=mock_worker, daemon=True).start()
    conn.connect(timeout=2.0)

    with pytest.raises(VoiceConnectionTimeoutError, match="timed out"):
        conn.send_request(PingRequest(id="req-ping"), timeout=0.1)

    conn.close()


def test_voice_connection_remote_error(pipes):
    """Worker error responses raise VoiceRemoteError."""
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)

    def mock_worker():
        req = read_voice_frame(pipes.worker_in)
        payload = HandshakeResponsePayload(
            worker_version="1.0.0",
            protocol_version=VOICE_PROTOCOL_VERSION,
            manifest_id="test",
            python_version="3.12.0",
            platform="linux",
            architecture="x86_64",
            capabilities=["tts"],
            models_status={},
            audio_devices={},
        )
        write_voice_frame(pipes.worker_out, VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload=payload))

        req2 = read_voice_frame(pipes.worker_in)
        write_voice_frame(
            pipes.worker_out,
            VoiceResponse(
                id=f"resp-{req2.id}",
                ref_id=req2.id,
                ok=False,
                error=VoiceErrorPayload(
                    code=VoiceErrorCode.AUDIO_DEVICE_ERROR,
                    message="No microphone available",
                ),
            ),
        )

    threading.Thread(target=mock_worker, daemon=True).start()
    conn.connect(timeout=2.0)

    with pytest.raises(VoiceRemoteError) as exc_info:
        conn.send_request(InputStartRequest(id="req-start", streaming=False, max_seconds=30.0), timeout=1.0)

    assert exc_info.value.code == VoiceErrorCode.AUDIO_DEVICE_ERROR
    assert "No microphone available" in exc_info.value.message
    conn.close()


def test_voice_connection_event_subscription(pipes):
    """Asynchronous events are dispatched to subscribed callbacks."""
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)

    partial_events: List[InputPartialEvent] = []
    all_events: List[VoiceEvent] = []

    unsub_partial = conn.subscribe(InputPartialEvent, partial_events.append)
    unsub_all = conn.subscribe(None, all_events.append)

    def mock_worker():
        req = read_voice_frame(pipes.worker_in)
        payload = HandshakeResponsePayload(
            worker_version="1.0.0",
            protocol_version=VOICE_PROTOCOL_VERSION,
            manifest_id="test",
            python_version="3.12.0",
            platform="linux",
            architecture="x86_64",
            capabilities=[],
            models_status={},
            audio_devices={},
        )
        write_voice_frame(pipes.worker_out, VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload=payload))

        # Send events
        write_voice_frame(pipes.worker_out, InputPartialEvent(id="ev-1", text="hello"))
        write_voice_frame(pipes.worker_out, OutputStateEvent(id="ev-2", is_speaking=True, current_epoch=1))
        write_voice_frame(pipes.worker_out, InputPartialEvent(id="ev-3", text="world"))

    threading.Thread(target=mock_worker, daemon=True).start()
    conn.connect(timeout=2.0)

    # Wait for events to arrive
    for _ in range(50):
        if len(partial_events) == 2 and len(all_events) == 3:
            break
        time.sleep(0.02)

    assert len(partial_events) == 2
    assert [e.text for e in partial_events] == ["hello", "world"]
    assert len(all_events) == 3

    # Unsubscribe test
    unsub_partial()
    unsub_all()
    conn.close()


def test_voice_connection_eof_aborts_pending(pipes):
    """Stream EOF aborts pending requests with VoiceConnectionClosedError."""
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)

    def mock_worker():
        req = read_voice_frame(pipes.worker_in)
        payload = HandshakeResponsePayload(
            worker_version="1.0.0",
            protocol_version=VOICE_PROTOCOL_VERSION,
            manifest_id="test",
            python_version="3.12.0",
            platform="linux",
            architecture="x86_64",
            capabilities=[],
            models_status={},
            audio_devices={},
        )
        write_voice_frame(pipes.worker_out, VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload=payload))
        # Wait for next request, then abruptly close stdout pipe to simulate worker death
        read_voice_frame(pipes.worker_in)
        pipes.worker_out.close()

    threading.Thread(target=mock_worker, daemon=True).start()
    conn.connect(timeout=2.0)

    closed_notified = threading.Event()
    conn.on_close(closed_notified.set)

    with pytest.raises(VoiceConnectionClosedError):
        conn.send_request(PingRequest(id="req-ping-eof"), timeout=2.0)

    assert closed_notified.wait(timeout=1.0)
    assert not conn.is_connected
    conn.close()


def test_voice_connection_with_real_voice_worker(pipes):
    """End-to-end integration test with a real VoiceWorker instance."""
    # Worker runs in background thread communicating over pipes
    worker = VoiceWorker(stdin=pipes.worker_in, stdout=pipes.worker_out)
    worker_thread = threading.Thread(target=worker.run, daemon=True)
    worker_thread.start()

    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    hs = conn.connect(timeout=3.0)
    assert hs.protocol_version == VOICE_PROTOCOL_VERSION
    assert conn.is_connected

    # Ping
    assert conn.ping(timeout=2.0) is True

    # Probe
    probe = conn.probe(timeout=2.0)
    assert isinstance(probe, ProbeResponsePayload)

    # Clean shutdown
    conn.close(timeout=2.0)
    worker_thread.join(timeout=2.0)
    assert not worker_thread.is_alive()
