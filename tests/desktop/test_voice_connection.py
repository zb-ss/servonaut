"""Unit tests for VoiceConnection (supervised voice worker process connection).

Tests handshake negotiation, framing transport, request-response matching,
asynchronous event dispatch, timeout handling, and connection termination.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
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


# ---------------------------------------------------------------------------
# Dispatcher, restarts, settings hand-over and version skew
# ---------------------------------------------------------------------------

import logging
from pathlib import Path
import subprocess
import sys

import servonaut
from servonaut.desktop.voice.connection import VoiceConnectionPolicy
from servonaut.desktop.voice.protocol import (
    ConfigureRequest,
    VoiceRequest,
    VoiceWorkerConfig,
)

SRC_ROOT = Path(servonaut.__file__).resolve().parents[1]
WORKER_ENV = {"PYTHONPATH": str(SRC_ROOT)}


def _handshake_payload() -> HandshakeResponsePayload:
    return HandshakeResponsePayload(
        worker_version="test",
        protocol_version=VOICE_PROTOCOL_VERSION,
        manifest_id="test",
        python_version="3.12.0",
        platform="linux",
        architecture="x86_64",
        capabilities=(),
        models_status={},
        audio_devices={},
    )


def _serve(pipes, *, seen: Optional[List[VoiceRequest]] = None, after_handshake=None) -> None:
    """Fake worker: answers every request with ok, recording what it saw."""

    def run() -> None:
        while True:
            try:
                req = read_voice_frame(pipes.worker_in)
            except Exception:
                return
            if req is None:
                return
            if seen is not None:
                seen.append(req)
            payload = _handshake_payload() if isinstance(req, HandshakeRequest) else {}
            try:
                write_voice_frame(pipes.worker_out, VoiceResponse(id="r", ref_id=req.id, ok=True, payload=payload))
            except (OSError, ValueError):
                return
            if isinstance(req, HandshakeRequest) and after_handshake is not None:
                after_handshake()

    threading.Thread(target=run, daemon=True).start()


def _script(tmp_path: Path, body: str) -> List[str]:
    path = tmp_path / "worker_script.py"
    path.write_text(body)
    return [sys.executable, str(path)]


CRASH_AFTER_HANDSHAKE = """
import os, sys
from servonaut.desktop.voice.protocol import VoiceFrameReader
from servonaut.desktop.voice.worker import VoiceWorker
reader = VoiceFrameReader(sys.stdin.buffer)
VoiceWorker(sys.stdin.buffer, sys.stdout.buffer)._dispatch(reader.read_frame())
reader.read_frame()
os._exit(3)
"""


class TestEventDispatcher:
    def test_subscriber_may_send_requests(self, pipes, caplog) -> None:
        conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
        answered = threading.Event()
        elapsed: List[float] = []

        def on_event(event) -> None:
            started = time.monotonic()
            conn.send_request(PingRequest(id="from-subscriber"), timeout=3.0)
            elapsed.append(time.monotonic() - started)
            answered.set()

        conn.subscribe(InputPartialEvent, on_event)
        _serve(pipes, after_handshake=lambda: write_voice_frame(
            pipes.worker_out, InputPartialEvent(id="e", text="hi"),
        ))
        with caplog.at_level(logging.WARNING, logger="servonaut.desktop.voice.connection"):
            conn.connect(timeout=2.0)
            assert answered.wait(5.0)
        assert elapsed[0] < 1.0
        assert "event dispatcher" in caplog.text
        conn.close()

    def test_events_keep_their_order(self, pipes) -> None:
        conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
        texts: List[str] = []
        conn.subscribe(InputPartialEvent, lambda e: texts.append(e.text))

        def burst() -> None:
            for index in range(50):
                write_voice_frame(pipes.worker_out, InputPartialEvent(id=str(index), text=str(index)))

        _serve(pipes, after_handshake=burst)
        conn.connect(timeout=2.0)
        deadline = time.monotonic() + 3
        while len(texts) < 50 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert texts == [str(index) for index in range(50)]
        conn.close()


class TestSettingsHandOver:
    def test_handshake_carries_settings_and_epoch(self, pipes) -> None:
        seen: List[VoiceRequest] = []
        config = VoiceWorkerConfig(language="de", barge_in=True)
        conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in, config=config)
        conn.set_epoch_provider(lambda: 4)
        _serve(pipes, seen=seen)
        conn.connect(timeout=2.0)
        handshake = seen[0]
        assert isinstance(handshake, HandshakeRequest)
        assert handshake.config == config
        assert handshake.epoch == 4
        conn.close()

    def test_configure_applies_now_and_at_the_next_handshake(self, pipes) -> None:
        seen: List[VoiceRequest] = []
        conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
        before_connect = VoiceWorkerConfig(tts_voice="bf_emma")
        conn.configure(before_connect)
        _serve(pipes, seen=seen)
        conn.connect(timeout=2.0)
        assert seen[0].config == before_connect  # type: ignore[union-attr]

        live = VoiceWorkerConfig(tts_speed=1.5)
        conn.configure(live, timeout=2.0)
        assert isinstance(seen[1], ConfigureRequest) and seen[1].config == live
        conn.close()

    def test_close_sends_a_shutdown_with_its_reason(self, pipes) -> None:
        seen: List[VoiceRequest] = []
        conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
        _serve(pipes, seen=seen)
        conn.connect(timeout=2.0)
        conn.close()
        deadline = time.monotonic() + 2
        while not any(isinstance(r, ShutdownRequest) for r in seen) and time.monotonic() < deadline:
            time.sleep(0.01)
        shutdowns = [r for r in seen if isinstance(r, ShutdownRequest)]
        assert [r.reason for r in shutdowns] == ["client_close"]


class TestRobustness:
    def test_hostile_frame_does_not_end_the_session(self, pipes) -> None:
        conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
        hostile = (
            '{"version": %d, "msg_type": "event", "id": "x", "name": "output_state", '
            '"payload": {"is_speaking": true, "current_epoch": %s}}\n'
            % (VOICE_PROTOCOL_VERSION, "9" * 5000)
        ).encode()
        _serve(pipes, after_handshake=lambda: pipes.worker_out.write(hostile))
        conn.connect(timeout=2.0)
        assert conn.ping(timeout=2.0) is True
        conn.close()

    def test_default_timeout_comes_from_the_policy(self, pipes) -> None:
        conn = VoiceConnection(
            stdin=pipes.parent_out, stdout=pipes.parent_in,
            policy=VoiceConnectionPolicy(request_timeout_seconds=0.2),
        )

        def handshake_then_silence() -> None:
            req = read_voice_frame(pipes.worker_in)
            write_voice_frame(pipes.worker_out, VoiceResponse(
                id="r", ref_id=req.id, ok=True, payload=_handshake_payload(),
            ))

        threading.Thread(target=handshake_then_silence, daemon=True).start()
        conn.connect(timeout=2.0)
        started = time.monotonic()
        with pytest.raises(VoiceConnectionTimeoutError):
            conn.send_request(PingRequest(id="p"))
        assert time.monotonic() - started < 2.0
        conn.close()

    def test_owner_close_is_permanent(self, pipes) -> None:
        conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
        _serve(pipes)
        conn.connect(timeout=2.0)
        conn.close()
        with pytest.raises(VoiceConnectionClosedError):
            conn.connect(timeout=1.0)

    def test_state_queries_do_not_wait_for_a_slow_spawn(self) -> None:
        release = threading.Event()

        def slow_command() -> List[str]:
            release.wait(5)
            raise OSError("no runtime")

        conn = VoiceConnection(worker_cmd=slow_command)
        errors: List[Exception] = []

        def attempt_connect() -> None:
            try:
                conn.connect()
            except Exception as e:  # noqa: BLE001 — recorded for the assertion below
                errors.append(e)

        attempt = threading.Thread(target=attempt_connect)
        attempt.start()
        time.sleep(0.1)
        started = time.monotonic()
        assert conn.is_connected is False
        assert conn.is_closed is False
        assert time.monotonic() - started < 0.2
        release.set()
        attempt.join(5)
        assert len(errors) == 1 and isinstance(errors[0], VoiceConnectionError)
        assert "not available" in str(errors[0])


class TestWorkerRestarts:
    def test_worker_exit_is_followed_by_a_respawn(self, tmp_path: Path) -> None:
        conn = VoiceConnection(
            worker_cmd=_script(tmp_path, CRASH_AFTER_HANDSHAKE),
            env=WORKER_ENV,
            policy=VoiceConnectionPolicy(restart_initial_backoff_seconds=0.0),
        )
        session_ended = threading.Event()
        conn.on_close(session_ended.set)
        conn.connect(timeout=30.0)

        assert conn.ping(timeout=10.0) is False  # the worker dies on this request
        assert session_ended.wait(5.0)
        assert conn.is_closed is False

        conn.connect(timeout=30.0)
        assert conn.is_connected is True
        conn.close()

    def test_restart_backs_off_then_gives_up_at_the_cap(self, tmp_path: Path) -> None:
        conn = VoiceConnection(
            worker_cmd=_script(tmp_path, "import sys; sys.exit(3)\n"),
            env=WORKER_ENV,
            policy=VoiceConnectionPolicy(
                restart_initial_backoff_seconds=0.0, max_consecutive_restarts=2,
            ),
        )
        for _ in range(2):
            with pytest.raises(VoiceConnectionClosedError, match="exited with status 3"):
                conn.connect(timeout=30.0)
        with pytest.raises(VoiceConnectionError, match="not restarting"):
            conn.connect(timeout=30.0)

        conn.reset_restart_budget()
        with pytest.raises(VoiceConnectionClosedError):
            conn.connect(timeout=30.0)  # allowed to try again (and fail again)
        conn.close()

    def test_respawn_waits_out_the_backoff(self, tmp_path: Path) -> None:
        conn = VoiceConnection(
            worker_cmd=_script(tmp_path, "import sys; sys.exit(3)\n"),
            env=WORKER_ENV,
            policy=VoiceConnectionPolicy(restart_initial_backoff_seconds=30.0),
        )
        with pytest.raises(VoiceConnectionClosedError):
            conn.connect(timeout=30.0)
        with pytest.raises(VoiceConnectionError, match="restarting in"):
            conn.connect(timeout=30.0)
        conn.close()

    def test_version_skew_fails_fast_and_is_not_respawned(self, tmp_path: Path) -> None:
        spawns: List[int] = []
        command = _script(tmp_path, (
            "import sys\n"
            "import servonaut.desktop.voice.protocol as protocol\n"
            "protocol.VOICE_PROTOCOL_VERSION += 1\n"
            "from servonaut.desktop.voice import worker\n"
            "sys.exit(worker.main([]))\n"
        ))

        def resolve() -> List[str]:
            spawns.append(1)
            return command

        conn = VoiceConnection(worker_cmd=resolve, env=WORKER_ENV)
        started = time.monotonic()
        with pytest.raises(VoiceConnectionError, match=r"protocol v\d+, but this app needs"):
            conn.connect(timeout=30.0)
        assert time.monotonic() - started < 15.0  # far below the handshake timeout
        with pytest.raises(VoiceConnectionError, match="Repair the voice runtime"):
            conn.connect(timeout=30.0)
        assert spawns == [1]
        conn.close()


def test_open_connection_does_not_abort_interpreter_exit(tmp_path: Path) -> None:
    """Reader threads still blocked on the worker must not break shutdown."""
    code = (
        "import sys\n"
        "from servonaut.desktop.voice.connection import VoiceConnection\n"
        "conn = VoiceConnection(worker_cmd=[sys.executable, '-m', 'servonaut.desktop.voice.worker'])\n"
        "conn.connect(timeout=30)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60,
        env={**os.environ, **WORKER_ENV},
    )
    assert result.returncode == 0, result.stderr
    assert "Fatal Python error" not in result.stderr


# ---------------------------------------------------------------------------
# Non-blocking writes, hung workers, oversized frames, restart
# ---------------------------------------------------------------------------

import uuid

from servonaut.config.schema import VoiceConfig
from servonaut.desktop.voice.connection import VoiceFrameError
from servonaut.desktop.voice.protocol import OutputEnqueueRequest, OutputSpeakRequest
from servonaut.desktop.voice.service import DesktopVoiceOutputService

WEDGED_AFTER_HANDSHAKE = """
import sys, time
from servonaut.desktop.voice.protocol import VoiceFrameReader
from servonaut.desktop.voice.worker import VoiceWorker
reader = VoiceFrameReader(sys.stdin.buffer)
VoiceWorker(sys.stdin.buffer, sys.stdout.buffer)._dispatch(reader.read_frame())
time.sleep(3600)  # never reads its input again
"""

_BIG_FRAME_TEXT = "a" * 60_000


def _wedged(tmp_path: Path, **policy: Any) -> VoiceConnection:
    conn = VoiceConnection(
        worker_cmd=_script(tmp_path, WEDGED_AFTER_HANDSHAKE),
        env=WORKER_ENV,
        policy=VoiceConnectionPolicy(**policy),
    )
    conn.connect(timeout=30.0)
    return conn


def _flood(conn: VoiceConnection, frames: int = 8) -> float:
    """Queue far more than the worker's pipe holds; return the slowest call."""
    slowest = 0.0
    for _ in range(frames):
        started = time.monotonic()
        conn.notify(OutputEnqueueRequest(id=str(uuid.uuid4()), text=_BIG_FRAME_TEXT, epoch=0))
        slowest = max(slowest, time.monotonic() - started)
    return slowest


class TestWedgedWorker:
    def test_sends_never_block_on_a_full_pipe(self, tmp_path: Path) -> None:
        conn = _wedged(tmp_path, write_queue_frames=4, shutdown_timeout_seconds=0.5)
        assert _flood(conn) < 0.1
        with pytest.raises(VoiceConnectionError, match="not reading"):
            for _ in range(8):
                conn.send_request(PingRequest(id=str(uuid.uuid4())), timeout=0.1)
        conn.kill()

    @pytest.mark.parametrize("method", ["close", "kill"])
    def test_close_and_kill_return_within_the_grace_period(self, tmp_path: Path, method: str) -> None:
        grace = 0.5
        conn = _wedged(tmp_path, write_queue_frames=4, shutdown_timeout_seconds=grace)
        process = conn._session.process  # type: ignore[union-attr]
        _flood(conn)
        started = time.monotonic()
        getattr(conn, method)()
        assert time.monotonic() - started < grace + 1.0
        assert process.poll() is not None

    def test_output_stop_never_blocks(self, tmp_path: Path) -> None:
        conn = _wedged(tmp_path, write_queue_frames=4, shutdown_timeout_seconds=0.5)
        output = DesktopVoiceOutputService(conn, VoiceConfig())
        _flood(conn)
        started = time.monotonic()
        output.stop()
        output.stop()
        assert time.monotonic() - started < 0.1
        conn.kill()

    def test_a_worker_that_stops_answering_is_recycled(self, tmp_path: Path) -> None:
        conn = _wedged(
            tmp_path,
            max_consecutive_timeouts=2,
            restart_initial_backoff_seconds=0.0,
            shutdown_timeout_seconds=0.2,
        )
        first = conn._session.process  # type: ignore[union-attr]
        ended = threading.Event()
        conn.on_close(ended.set)
        for _ in range(2):
            with pytest.raises(VoiceConnectionTimeoutError):
                conn.send_request(PingRequest(id=str(uuid.uuid4())), timeout=0.1)
        assert ended.wait(5.0)
        assert first.poll() is not None
        conn.connect(timeout=30.0)  # a fresh worker replaces it
        assert conn._session.process is not first  # type: ignore[union-attr]
        conn.kill()


class TestOversizedFrames:
    def test_oversized_request_fails_cleanly(self, pipes) -> None:
        conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
        _serve(pipes)
        conn.connect(timeout=2.0)
        with pytest.raises(VoiceFrameError, match="exceeds"):
            conn.send_request(OutputSpeakRequest(id="big", text="a" * 70_000, epoch=0))
        with pytest.raises(VoiceFrameError):
            conn.send_request(OutputSpeakRequest(id="bad", text="\ud800", epoch=0))
        assert conn._pending == {}
        assert conn.ping(timeout=2.0) is True
        conn.close()


class TestConfigureDuringHandshake:
    def test_settings_changed_mid_handshake_are_delivered(self, pipes) -> None:
        seen: List[VoiceRequest] = []
        handshake_seen = threading.Event()

        def slow_worker() -> None:
            req = read_voice_frame(pipes.worker_in)
            seen.append(req)
            handshake_seen.set()
            time.sleep(0.3)  # the handshake is in flight while settings change
            write_voice_frame(pipes.worker_out, VoiceResponse(
                id="r", ref_id=req.id, ok=True, payload=_handshake_payload(),
            ))
            with contextlib.suppress(OSError, ValueError):  # the pipes close at the end
                while (req := read_voice_frame(pipes.worker_in)) is not None:
                    seen.append(req)
                    write_voice_frame(pipes.worker_out, VoiceResponse(id="r", ref_id=req.id, ok=True))

        threading.Thread(target=slow_worker, daemon=True).start()
        conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
        connecting = threading.Thread(target=conn.connect)
        connecting.start()
        assert handshake_seen.wait(2.0)
        conn.configure(VoiceWorkerConfig(language="de"))
        connecting.join(5.0)

        assert seen[0].config.language == "en"  # type: ignore[union-attr]
        configures = [r for r in seen if isinstance(r, ConfigureRequest)]
        assert [r.config.language for r in configures] == ["de"]
        conn.close()


class TestSessionEndHook:
    def test_hook_runs_before_a_busy_dispatcher_catches_up(self, pipes) -> None:
        conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
        hooked = threading.Event()
        closed = threading.Event()
        conn.add_session_end_hook(hooked.set)
        conn.on_close(closed.set)
        conn.subscribe(InputPartialEvent, lambda event: time.sleep(1.0))  # a busy UI
        _serve(pipes, after_handshake=lambda: write_voice_frame(
            pipes.worker_out, InputPartialEvent(id="e", text="hi"),
        ))
        conn.connect(timeout=2.0)
        time.sleep(0.1)  # the dispatcher is now inside the slow subscriber
        pipes.worker_out.close()  # the worker exits
        assert hooked.wait(0.5)
        assert not closed.is_set()
        assert closed.wait(3.0)


class TestRestart:
    def test_restart_replaces_the_worker_with_a_freshly_resolved_command(self, tmp_path: Path) -> None:
        resolutions: List[List[str]] = []

        def resolve() -> List[str]:
            command = [sys.executable, "-m", "servonaut.desktop.voice.worker"]
            resolutions.append(command)
            return command

        conn = VoiceConnection(worker_cmd=resolve, env=WORKER_ENV)
        conn.connect(timeout=30.0)
        first = conn._session.process  # type: ignore[union-attr]
        ended = threading.Event()
        conn.on_close(ended.set)

        conn.restart()

        assert first.poll() == 0  # shut down gracefully, not killed
        assert ended.wait(2.0)
        assert conn.is_closed is False
        assert conn._consecutive_failures == 0
        conn.connect(timeout=30.0)
        assert len(resolutions) == 2
        assert conn._session.process is not first  # type: ignore[union-attr]
        assert conn.ping(timeout=5.0) is True
        conn.close()

    def test_restart_while_disconnected_only_rearms_the_budget(self, tmp_path: Path) -> None:
        resolutions: List[int] = []
        command = _script(tmp_path, "import sys; sys.exit(3)\n")

        def resolve() -> List[str]:
            resolutions.append(1)
            return command

        conn = VoiceConnection(
            worker_cmd=resolve,
            env=WORKER_ENV,
            policy=VoiceConnectionPolicy(max_consecutive_restarts=1, restart_initial_backoff_seconds=0.0),
        )
        with pytest.raises(VoiceConnectionClosedError):
            conn.connect(timeout=30.0)
        with pytest.raises(VoiceConnectionError, match="not restarting"):
            conn.connect(timeout=30.0)

        conn.restart()

        assert resolutions == [1]  # nothing was spawned
        with pytest.raises(VoiceConnectionClosedError):
            conn.connect(timeout=30.0)  # allowed to try again
        assert resolutions == [1, 1]
        conn.close()


class TestWorkerStderrForwarding:
    def test_credentials_are_scrubbed_and_overlong_lines_summarised(self, caplog):
        from servonaut.desktop.voice.connection import VoiceConnection

        stream = io.BytesIO(
            b"download failed via http://user:hunter22@proxy.example:3128\n"  # leak-guard:allow
            + b"x" * (64 * 1024)
            + b"\nlast line\n"
        )
        with caplog.at_level(logging.DEBUG, logger="servonaut.desktop.voice.connection"):
            VoiceConnection._stderr_reader_loop(stream)

        logged = [record.getMessage() for record in caplog.records]
        assert "[voice-worker] download failed via http://***@proxy.example:3128" in logged
        assert any("line omitted" in message for message in logged)
        assert "[voice-worker] last line" in logged
        assert not any("hunter22" in message or "x" * 100 in message for message in logged)
