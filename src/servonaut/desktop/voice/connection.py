"""Supervised companion voice worker process connection and multiplexed IPC.

Manages the lifecycle of the isolated voice companion daemon, serialises
parent-to-worker requests over standard I/O using bounded UTF-8 JSON Lines,
matches responses via request correlation IDs, and dispatches asynchronous
worker events to registered subscribers.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import logging
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import (
    Any,
    BinaryIO,
    Callable,
    Dict,
    Final,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Type,
    Union,
)
import uuid

from servonaut import __version__
from servonaut.desktop.voice.protocol import (
    VOICE_PROTOCOL_VERSION,
    HandshakeRequest,
    HandshakeResponsePayload,
    PingRequest,
    ProbeRequest,
    ProbeResponsePayload,
    ShutdownRequest,
    VoiceErrorCode,
    VoiceErrorPayload,
    VoiceEvent,
    VoiceMessage,
    VoiceProtocolEofError,
    VoiceProtocolError,
    VoiceRequest,
    VoiceResponse,
    read_voice_frame,
    write_voice_frame,
)

logger = logging.getLogger(__name__)

_DEFAULT_STARTUP_TIMEOUT: Final[float] = 10.0
_DEFAULT_REQUEST_TIMEOUT: Final[float] = 15.0
_DEFAULT_SHUTDOWN_TIMEOUT: Final[float] = 2.0


class VoiceConnectionError(RuntimeError):
    """Base error for voice worker connection and communication failures."""


class VoiceConnectionTimeoutError(VoiceConnectionError):
    """Raised when a request to the voice worker times out."""


class VoiceConnectionClosedError(VoiceConnectionError):
    """Raised when an operation is attempted on a closed or dead connection."""


class VoiceRemoteError(VoiceConnectionError):
    """Raised when the worker replies with an operational or protocol error."""

    def __init__(
        self,
        code: VoiceErrorCode,
        message: str,
        *,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(f"[{code.value}] {message}")
        self.code = code
        self.message = message
        self.details = details or {}


class VoiceConnection:
    """Supervised connection to the companion voice worker process.

    Handles subprocess management, protocol handshake, frame serialization,
    correlated request-response dispatch, and asynchronous event routing.
    """

    def __init__(
        self,
        *,
        worker_cmd: Optional[Sequence[str] | Callable[[], Sequence[str]]] = None,
        stdin: Optional[BinaryIO] = None,
        stdout: Optional[BinaryIO] = None,
        stderr: Optional[BinaryIO] = None,
        process: Optional[subprocess.Popen[bytes]] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._worker_cmd = worker_cmd
        self._stdin: Optional[BinaryIO] = stdin
        self._stdout: Optional[BinaryIO] = stdout
        self._stderr: Optional[BinaryIO] = stderr
        self._process: Optional[subprocess.Popen[bytes]] = process
        self._env = dict(env) if env is not None else None

        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._reader_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None

        self._connected = False
        self._closed = False
        self._handshake_payload: Optional[HandshakeResponsePayload] = None

        self._pending: Dict[str, concurrent.futures.Future[VoiceResponse]] = {}
        self._subscribers: Dict[Optional[Type[VoiceEvent]], List[Callable[[VoiceEvent], None]]] = {}
        self._on_close_callbacks: List[Callable[[], None]] = []

    @property
    def is_connected(self) -> bool:
        """Whether the worker is connected, handshaken, and ready."""
        with self._lock:
            if not self._connected or self._closed:
                return False
            if self._process is not None and self._process.poll() is not None:
                return False
            return True

    @property
    def is_closed(self) -> bool:
        """Whether the connection has been closed."""
        with self._lock:
            return self._closed

    @property
    def handshake_data(self) -> Optional[HandshakeResponsePayload]:
        """Handshake response payload received during connection."""
        with self._lock:
            return self._handshake_payload

    def connect(
        self,
        *,
        timeout: float = _DEFAULT_STARTUP_TIMEOUT,
        client_version: str = __version__,
        capabilities_requested: Optional[Sequence[str]] = None,
    ) -> HandshakeResponsePayload:
        """Spawn worker if needed, begin frame I/O, and execute handshake.

        Raises:
            VoiceConnectionError: If startup, I/O, or handshake negotiation fails.
            VoiceConnectionTimeoutError: If handshake times out.
        """
        with self._lock:
            if self._connected and not self._closed:
                if self._handshake_payload is not None:
                    return self._handshake_payload
            if self._closed:
                raise VoiceConnectionClosedError("Cannot connect a closed VoiceConnection")

            self._spawn_if_needed()
            self._start_reader_threads()

        # Send handshake outside lock so reader thread can process response
        req_caps = tuple(capabilities_requested) if capabilities_requested else (
            "stt_batch", "stt_streaming", "tts", "vad", "conversation"
        )
        request = HandshakeRequest(
            id=str(uuid.uuid4()),
            client_version=client_version,
            capabilities_requested=req_caps,
        )

        try:
            response = self.send_request(request, timeout=timeout)
        except VoiceRemoteError as e:
            self.close()
            raise VoiceConnectionError(f"Worker rejected handshake: {e.message}") from e
        except Exception as e:
            self.close()
            if isinstance(e, VoiceConnectionError):
                raise
            raise VoiceConnectionError(f"Failed to complete handshake: {e}") from e

        if not response.ok:
            err_msg = response.error.message if response.error else "Unknown error"
            self.close()
            raise VoiceConnectionError(f"Worker rejected handshake: {err_msg}")

        payload = response.payload
        if isinstance(payload, dict):
            try:
                payload = HandshakeResponsePayload.from_dict(payload)
            except Exception as e:
                self.close()
                raise VoiceConnectionError(f"Failed to parse handshake response: {e}") from e
        elif not isinstance(payload, HandshakeResponsePayload):
            self.close()
            raise VoiceConnectionError(
                f"Unexpected handshake response payload type: {type(payload).__name__}"
            )

        if payload.protocol_version != VOICE_PROTOCOL_VERSION:
            self.close()
            raise VoiceConnectionError(
                f"Worker protocol version mismatch: got {payload.protocol_version}, "
                f"expected {VOICE_PROTOCOL_VERSION}"
            )

        with self._lock:
            self._connected = True
            self._handshake_payload = payload
            return payload

    def _spawn_if_needed(self) -> None:
        """Spawn the worker process if streams were not provided."""
        if self._stdin is not None and self._stdout is not None:
            return

        run_env = os.environ.copy()
        if self._env:
            run_env.update(self._env)
        # Ensure python streams are unbuffered utf-8
        run_env["PYTHONUNBUFFERED"] = "1"
        run_env["PYTHONIOENCODING"] = "utf-8"

        if callable(self._worker_cmd):
            resolved_cmd = list(self._worker_cmd())
        elif self._worker_cmd is not None:
            resolved_cmd = list(self._worker_cmd)
        else:
            resolved_cmd = [sys.executable, "-m", "servonaut.desktop.voice.worker"]

        try:
            self._process = subprocess.Popen(
                resolved_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=run_env,
            )
            self._stdin = self._process.stdin
            self._stdout = self._process.stdout
            self._stderr = self._process.stderr
        except Exception as e:
            raise VoiceConnectionError(f"Failed to spawn voice worker process: {e}") from e

    def _start_reader_threads(self) -> None:
        """Launch background reader threads for stdout frames and stderr logs."""
        if self._reader_thread is None and self._stdout is not None:
            self._reader_thread = threading.Thread(
                target=self._stdout_reader_loop,
                name="ServonautVoiceWorkerStdoutReader",
                daemon=True,
            )
            self._reader_thread.start()

        if self._stderr_thread is None and self._stderr is not None:
            self._stderr_thread = threading.Thread(
                target=self._stderr_reader_loop,
                name="ServonautVoiceWorkerStderrReader",
                daemon=True,
            )
            self._stderr_thread.start()

    def send_request(
        self,
        request: VoiceRequest,
        *,
        timeout: Optional[float] = _DEFAULT_REQUEST_TIMEOUT,
    ) -> VoiceResponse:
        """Send a request frame to the worker and block for its correlated response.

        Raises:
            VoiceConnectionClosedError: If connection is closed or worker process died.
            VoiceConnectionTimeoutError: If the worker did not respond within timeout.
            VoiceRemoteError: If the worker replied with an error response.
        """
        with self._lock:
            if self._closed or self._stdin is None:
                raise VoiceConnectionClosedError("VoiceConnection is closed")

        if not request.id:
            import dataclasses
            request = dataclasses.replace(request, id=str(uuid.uuid4()))

        future: concurrent.futures.Future[VoiceResponse] = concurrent.futures.Future()
        with self._lock:
            self._pending[request.id] = future

        try:
            with self._write_lock:
                if self._stdin is None or self._closed:
                    raise VoiceConnectionClosedError("Connection closed before send")
                write_voice_frame(self._stdin, request)
        except Exception as e:
            with self._lock:
                self._pending.pop(request.id, None)
            if isinstance(e, VoiceConnectionError):
                raise
            raise VoiceConnectionError(f"Failed to write frame to voice worker: {e}") from e

        try:
            response = future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            with self._lock:
                self._pending.pop(request.id, None)
            raise VoiceConnectionTimeoutError(
                f"Request '{request.name}' (id={request.id}) timed out after {timeout}s"
            ) from None

        if not response.ok and response.error is not None:
            raise VoiceRemoteError(
                code=response.error.code,
                message=response.error.message,
                details=response.error.details,
            )

        return response

    def ping(self, *, timeout: float = 5.0) -> bool:
        """Check liveness of the worker process."""
        try:
            resp = self.send_request(PingRequest(id=str(uuid.uuid4())), timeout=timeout)
            return resp.ok
        except Exception as e:
            logger.debug("Voice worker ping failed: %s", e)
            return False

    def probe(self, *, timeout: float = 5.0) -> ProbeResponsePayload:
        """Probe audio devices and model availability without starting streams."""
        resp = self.send_request(ProbeRequest(id=str(uuid.uuid4())), timeout=timeout)
        payload = resp.payload
        if isinstance(payload, dict):
            try:
                return ProbeResponsePayload.from_dict(payload)
            except Exception as e:
                raise VoiceConnectionError(f"Failed to parse probe response: {e}") from e
        if isinstance(payload, ProbeResponsePayload):
            return payload
        raise VoiceConnectionError("Invalid probe response payload")

    def subscribe(
        self,
        event_type: Optional[Type[VoiceEvent]],
        callback: Callable[[VoiceEvent], None],
    ) -> Callable[[], None]:
        """Subscribe to asynchronous worker events.

        Args:
            event_type: Specific event class to listen for, or None for all events.
            callback: Callable accepting the event.

        Returns:
            A zero-argument callable that unregisters the subscriber.
        """
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            self._subscribers[event_type].append(callback)

        def unsubscribe() -> None:
            with self._lock:
                listeners = self._subscribers.get(event_type, [])
                if callback in listeners:
                    listeners.remove(callback)

        return unsubscribe

    def on_close(self, callback: Callable[[], None]) -> None:
        """Register a callback invoked when the connection closes or worker exits."""
        with self._lock:
            self._on_close_callbacks.append(callback)

    def close(self, *, timeout: float = _DEFAULT_SHUTDOWN_TIMEOUT) -> None:
        """Orderly shutdown of the worker connection and underlying process."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._connected = False

        # Attempt graceful shutdown request
        try:
            if self._stdin is not None and not self._stdin.closed:
                with self._write_lock:
                    write_voice_frame(
                        self._stdin,
                        ShutdownRequest(id=str(uuid.uuid4()), reason="client_close"),
                    )
        except Exception as e:
            logger.debug("Failed to send shutdown request: %s", e)

        # Close stdin pipe to signal EOF to worker
        with self._write_lock:
            if self._stdin is not None:
                try:
                    self._stdin.close()
                except Exception:
                    pass
                self._stdin = None

        # Wait for worker process to terminate
        if self._process is not None:
            try:
                self._process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                logger.warning("Voice worker did not exit cleanly; terminating forcefully")
                with contextlib.suppress(Exception):
                    self._process.kill()
                    self._process.wait(timeout=1.0)
            self._process = None

        self._abort_pending(VoiceConnectionClosedError("VoiceConnection has been closed"))
        self._notify_closed()

    def kill(self) -> None:
        """Forcibly kill the worker process immediately."""
        with self._lock:
            self._closed = True
            self._connected = False

        if self._process is not None:
            with contextlib.suppress(Exception):
                self._process.kill()
            self._process = None

        with self._write_lock:
            if self._stdin is not None:
                with contextlib.suppress(Exception):
                    self._stdin.close()
                self._stdin = None

        self._abort_pending(VoiceConnectionClosedError("VoiceConnection was terminated forcefully"))
        self._notify_closed()

    def _abort_pending(self, exc: Exception) -> None:
        """Reject all in-flight pending request futures with an exception."""
        with self._lock:
            pending = list(self._pending.values())
            self._pending.clear()

        for future in pending:
            if not future.done():
                future.set_exception(exc)

    def _notify_closed(self) -> None:
        """Trigger on_close callbacks."""
        with self._lock:
            callbacks = list(self._on_close_callbacks)
            self._on_close_callbacks.clear()

        for cb in callbacks:
            try:
                cb()
            except Exception:
                logger.debug("Error in on_close callback", exc_info=True)

    def _stdout_reader_loop(self) -> None:
        """Read frames from worker stdout and dispatch responses and events."""
        stream = self._stdout
        if stream is None:
            return

        while True:
            try:
                msg = read_voice_frame(stream)
            except VoiceProtocolEofError:
                logger.debug("Voice worker stdout reached EOF")
                break
            except VoiceProtocolError as e:
                logger.warning("Discarded malformed frame from voice worker: %s", e)
                continue
            except Exception as e:
                logger.debug("Voice worker stream read exception: %s", e)
                break

            if msg is None:
                logger.debug("Voice worker stdout reached EOF")
                break

            if isinstance(msg, VoiceResponse):
                self._handle_response(msg)
            elif isinstance(msg, VoiceEvent):
                self._handle_event(msg)
            else:
                logger.debug("Unexpected frame type received: %s", type(msg).__name__)

        # Reader loop exited -> stream closed or process died
        with self._lock:
            was_connected = self._connected
            self._connected = False

        self._abort_pending(VoiceConnectionClosedError("Voice worker stdout disconnected (EOF)"))
        if was_connected and not self._closed:
            self.close()

    def _handle_response(self, response: VoiceResponse) -> None:
        """Resolve the pending future for a response frame."""
        future: Optional[concurrent.futures.Future[VoiceResponse]] = None
        with self._lock:
            future = self._pending.pop(response.ref_id, None)

        if future is not None and not future.done():
            future.set_result(response)
        else:
            logger.debug("Received unhandled or already resolved response: ref_id=%s", response.ref_id)

    def _handle_event(self, event: VoiceEvent) -> None:
        """Dispatch event frame to subscribers."""
        callbacks: List[Callable[[VoiceEvent], None]] = []
        with self._lock:
            # Type-specific listeners
            callbacks.extend(self._subscribers.get(type(event), []))
            # Catch-all listeners
            callbacks.extend(self._subscribers.get(None, []))

        for cb in callbacks:
            try:
                cb(event)
            except Exception:
                logger.debug("Exception in voice event subscriber", exc_info=True)

    def _stderr_reader_loop(self) -> None:
        """Stream worker stderr logs to parent logger."""
        stream = self._stderr
        if stream is None:
            return

        while True:
            try:
                line = stream.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip()
                if text:
                    logger.debug("[voice-worker] %s", text)
            except Exception:
                break
