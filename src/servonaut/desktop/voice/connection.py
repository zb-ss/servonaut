"""Supervised companion voice worker process connection and multiplexed IPC.

Manages the lifecycle of the isolated voice companion daemon, serialises
parent-to-worker requests over standard I/O using bounded UTF-8 JSON Lines,
matches responses via request correlation IDs, and dispatches asynchronous
worker events to registered subscribers.

Threads, per worker session:

* one writer owns the worker's stdin and drains a bounded queue of encoded
  frames — no caller ever blocks on the pipe, so a wedged worker cannot
  hang a UI thread, :meth:`VoiceConnection.close` or
  :meth:`VoiceConnection.kill`;
* one reader resolves responses and queues events — it never runs
  subscriber code, so a subscriber that sends a request can never starve
  the reply it is waiting for;

and one dispatcher per connection delivers events and session-end
notifications to subscribers, strictly in arrival order.

A worker that exits (crash, native abort, handshake failure) or stops
answering is replaced by the next :meth:`VoiceConnection.connect`, after a
bounded backoff and up to a restart cap. Closing the connection is
permanent.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
from dataclasses import dataclass, field
import logging
import os
import queue
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
    Tuple,
    Type,
    Union,
)
import uuid

from servonaut import __version__
from servonaut.desktop.voice.protocol import (
    VOICE_PROTOCOL_VERSION,
    ConfigureRequest,
    HandshakeRequest,
    HandshakeResponsePayload,
    PingRequest,
    ProbeRequest,
    ProbeResponsePayload,
    ShutdownRequest,
    VoiceErrorCode,
    VoiceEvent,
    VoiceFrameReader,
    VoiceProtocolEofError,
    VoiceProtocolError,
    VoiceProtocolVersionError,
    VoiceRequest,
    VoiceResponse,
    VoiceWorkerConfig,
    encode_voice_message,
    raw_chunk_reader,
)
from servonaut.utils.credential_scrub import scrub_credentials

logger = logging.getLogger(__name__)

_DEFAULT_CAPABILITIES: Final = ("stt_batch", "stt_streaming", "tts", "vad", "conversation")
_STDERR_CHUNK_BYTES: Final[int] = 4096
_MAX_STDERR_LINE_BYTES: Final[int] = 16 * 1024
# How often an idle writer checks whether its session is closing.
_WRITER_POLL_SECONDS: Final[float] = 0.2
# Wait for a killed worker to be reaped.
_KILL_WAIT_SECONDS: Final[float] = 1.0
_USE_POLICY: Final = object()
# Windows: start the console-mode worker without a console window, so no
# window flashes up when a windowed app launches it. Spelled out because the
# subprocess constant only exists on Windows.
_CREATE_NO_WINDOW: Final[int] = 0x08000000

WorkerEnv = Union[Mapping[str, str], Callable[[], Mapping[str, str]]]
"""A worker environment, or a callable resolving it at spawn time."""


class VoiceConnectionError(RuntimeError):
    """Base error for voice worker connection and communication failures."""


class VoiceConnectionTimeoutError(VoiceConnectionError):
    """Raised when a request to the voice worker times out."""


class VoiceConnectionClosedError(VoiceConnectionError):
    """Raised when an operation is attempted on a closed or dead connection."""


class VoiceFrameError(VoiceConnectionError):
    """Raised when a request cannot be encoded as a frame (too large, invalid text)."""


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


@dataclass(frozen=True)
class VoiceConnectionPolicy:
    """Timeouts and restart limits for one connection.

    Attributes:
        startup_timeout_seconds: Budget for spawn plus handshake.
        request_timeout_seconds: Default wait for a request's reply.
        model_load_timeout_seconds: Extra budget for requests that may load
            a speech model first (starting capture or the conversation
            loop, transcribing).
        shutdown_timeout_seconds: Grace period before a worker is killed.
        restart_initial_backoff_seconds: Wait before the first respawn
            after an unexpected exit; doubles per consecutive failure.
        restart_max_backoff_seconds: Upper bound of that wait.
        max_consecutive_restarts: Unexpected exits in a row after which
            the connection stops respawning until
            :meth:`VoiceConnection.reset_restart_budget`.
        stable_session_seconds: A session that lived this long clears the
            consecutive-failure count when it ends.
        max_consecutive_timeouts: Requests in a row that got no reply in
            time, after which the worker is treated as hung and recycled.
        write_queue_frames: Frames that may wait for the worker to read
            them; beyond that, sends fail instead of queueing without bound.
    """

    startup_timeout_seconds: float = 10.0
    request_timeout_seconds: float = 15.0
    model_load_timeout_seconds: float = 120.0
    shutdown_timeout_seconds: float = 2.0
    restart_initial_backoff_seconds: float = 0.5
    restart_max_backoff_seconds: float = 30.0
    max_consecutive_restarts: int = 5
    stable_session_seconds: float = 60.0
    max_consecutive_timeouts: int = 3
    write_queue_frames: int = 256


@dataclass(eq=False)
class _WorkerSession:
    """The streams, process and writer of one worker incarnation."""

    stdin: BinaryIO
    stdout: BinaryIO
    stderr: Optional[BinaryIO]
    process: Optional[subprocess.Popen[bytes]]
    outbox: "queue.Queue[Optional[bytes]]"
    started_at: float = field(default_factory=time.monotonic)
    closing: threading.Event = field(default_factory=threading.Event)
    writer: Optional[threading.Thread] = None
    consecutive_timeouts: int = 0


class VoiceConnection:
    """Supervised connection to the companion voice worker process.

    Handles subprocess management, protocol handshake, frame serialization,
    correlated request-response dispatch, asynchronous event routing, and
    respawning the worker after it exits.
    """

    def __init__(
        self,
        *,
        worker_cmd: Optional[Union[Sequence[str], Callable[[], Sequence[str]]]] = None,
        stdin: Optional[BinaryIO] = None,
        stdout: Optional[BinaryIO] = None,
        stderr: Optional[BinaryIO] = None,
        process: Optional[subprocess.Popen[bytes]] = None,
        env: Optional[WorkerEnv] = None,
        inherit_env: bool = True,
        config: Optional[VoiceWorkerConfig] = None,
        policy: Optional[VoiceConnectionPolicy] = None,
    ) -> None:
        """Create a connection; nothing is spawned until :meth:`connect`.

        Args:
            worker_cmd: Worker argv, or a callable resolving it at spawn time.
            stdin/stdout/stderr/process: Pre-opened streams of a worker
                started elsewhere. Such a connection cannot respawn it, so
                the end of that session closes the connection.
            env: Environment for spawned workers, or a callable resolving
                it at each spawn.
            inherit_env: When True, *env* is laid over a copy of this
                process's environment. When False, *env* is the worker's
                complete environment, so nothing else from this process
                (credentials, tokens, loader settings) reaches the worker.
            config: Voice settings handed to the worker in the handshake.
            policy: Timeouts and restart limits.
        """
        self._policy = policy or VoiceConnectionPolicy()
        self._worker_cmd = worker_cmd
        self._injected: Optional[_WorkerSession] = None
        if stdin is not None and stdout is not None:
            self._injected = self._new_session(stdin, stdout, stderr, process)
        self._restartable = self._injected is None
        self._env: Optional[WorkerEnv] = env if env is None or callable(env) else dict(env)
        self._inherit_env = inherit_env
        self._worker_config = config or VoiceWorkerConfig()
        self._epoch_provider: Callable[[], int] = lambda: 0

        self._lock = threading.Lock()
        self._connect_lock = threading.Lock()

        self._session: Optional[_WorkerSession] = None
        self._connected = False
        self._closed = False
        self._handshake_payload: Optional[HandshakeResponsePayload] = None
        self._pending: Dict[str, concurrent.futures.Future[VoiceResponse]] = {}

        self._consecutive_failures = 0
        self._next_attempt_at = 0.0
        self._fatal_message: Optional[str] = None

        self._subscribers: Dict[Optional[Type[Any]], List[Callable[[Any], None]]] = {}
        self._on_close_callbacks: List[Callable[[], None]] = []
        self._session_end_hooks: List[Callable[[], None]] = []
        self._dispatch_queue: "queue.Queue[Optional[Callable[[], None]]]" = queue.Queue()
        self._dispatcher: Optional[threading.Thread] = None

    def _new_session(
        self,
        stdin: BinaryIO,
        stdout: BinaryIO,
        stderr: Optional[BinaryIO],
        process: Optional[subprocess.Popen[bytes]],
    ) -> _WorkerSession:
        return _WorkerSession(
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            process=process,
            outbox=queue.Queue(maxsize=self._policy.write_queue_frames),
        )

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def is_connected(self) -> bool:
        """Whether the worker is connected, handshaken, and ready."""
        with self._lock:
            session = self._session
            if not self._connected or self._closed or session is None:
                return False
        return session.process is None or session.process.poll() is None

    @property
    def is_closed(self) -> bool:
        """Whether the owner closed the connection (permanent)."""
        with self._lock:
            return self._closed

    @property
    def handshake_data(self) -> Optional[HandshakeResponsePayload]:
        """Handshake response payload of the current worker session."""
        with self._lock:
            return self._handshake_payload

    @property
    def policy(self) -> VoiceConnectionPolicy:
        """Timeouts and restart limits this connection runs with."""
        return self._policy

    def set_epoch_provider(self, provider: Callable[[], int]) -> None:
        """Source of the parent's playback epoch sent in each handshake."""
        self._epoch_provider = provider

    def reset_restart_budget(self) -> None:
        """Allow respawning again after the restart cap or a fatal error.

        For after the user repaired or reinstalled the voice runtime.
        """
        with self._lock:
            self._reset_restart_budget_locked()

    def _reset_restart_budget_locked(self) -> None:
        self._consecutive_failures = 0
        self._next_attempt_at = 0.0
        self._fatal_message = None

    # ------------------------------------------------------------------
    # Connect / configure / restart
    # ------------------------------------------------------------------

    def connect(
        self,
        *,
        timeout: Optional[float] = None,
        client_version: str = __version__,
        capabilities_requested: Optional[Sequence[str]] = None,
    ) -> HandshakeResponsePayload:
        """Spawn the worker if needed and run the handshake.

        Only this call's own attempts are serialised: the state lock is
        never held while the worker command resolves or the process starts,
        so :attr:`is_connected` stays instant for other threads.

        Raises:
            VoiceConnectionClosedError: If the owner closed the connection.
            VoiceConnectionError: If spawning or the handshake fails, the
                worker is incompatible, or a respawn is still backing off.
            VoiceConnectionTimeoutError: If the handshake times out.
        """
        with self._connect_lock:
            with self._lock:
                if self._closed:
                    raise VoiceConnectionClosedError("Cannot connect a closed VoiceConnection")
                if self._connected and self._handshake_payload is not None:
                    return self._handshake_payload
                self._check_restart_allowed_locked()
            session = self._open_session()
            self._start_writer(session)
            self._start_reader_threads(session)
            try:
                payload, sent_config = self._handshake(
                    session,
                    timeout=self._policy.startup_timeout_seconds if timeout is None else timeout,
                    client_version=client_version,
                    capabilities=tuple(capabilities_requested or _DEFAULT_CAPABILITIES),
                )
            except Exception as e:
                self._end_session(session, error=e if isinstance(e, VoiceConnectionError) else None)
                if isinstance(e, VoiceConnectionError):
                    raise
                raise VoiceConnectionError(f"Failed to complete handshake: {e}") from e
            with self._lock:
                if self._session is not session:
                    raise VoiceConnectionClosedError("Voice worker exited during the handshake")
                self._connected = True
                self._handshake_payload = payload
                latest_config = self._worker_config
            if latest_config != sent_config:
                # configure() ran while the handshake was in flight and only
                # stored its settings: deliver them now.
                self._send_config(session, latest_config)
            return payload

    def _open_session(self) -> _WorkerSession:
        """Spawn (or take the injected) session and make it current."""
        command = self._resolve_worker_cmd()
        # Resolved outside the failure accounting, like the command: an
        # environment that cannot be built yet is not a worker crash.
        run_env = self._spawn_env() if command is not None else None
        try:
            session = self._spawn_if_needed(command, run_env)
        except VoiceConnectionError:
            with self._lock:
                self._record_failure_locked(lived_seconds=0.0)
            raise
        with self._lock:
            if self._closed:
                self._reap(session)
                raise VoiceConnectionClosedError("Cannot connect a closed VoiceConnection")
            self._session = session
        return session

    def _check_restart_allowed_locked(self) -> None:
        if self._fatal_message is not None:
            raise VoiceConnectionError(self._fatal_message)
        if self._consecutive_failures >= self._policy.max_consecutive_restarts:
            raise VoiceConnectionError(
                f"The voice worker failed {self._consecutive_failures} times in a row; "
                "not restarting it until the voice runtime is repaired"
            )
        wait = self._next_attempt_at - time.monotonic()
        if wait > 0:
            raise VoiceConnectionError(
                f"The voice worker exited unexpectedly; restarting in {wait:.1f}s"
            )

    def _handshake(
        self,
        session: _WorkerSession,
        *,
        timeout: float,
        client_version: str,
        capabilities: Sequence[str],
    ) -> Tuple[HandshakeResponsePayload, VoiceWorkerConfig]:
        with self._lock:
            config = self._worker_config
        request = HandshakeRequest(
            id=str(uuid.uuid4()),
            client_version=client_version,
            config=config,
            epoch=self._epoch_provider(),
            capabilities_requested=tuple(capabilities),
        )
        try:
            response = self._request(session, request, timeout=timeout)
        except VoiceRemoteError as e:
            raise VoiceConnectionError(f"Worker rejected handshake: {e.message}") from e

        try:
            payload = HandshakeResponsePayload.from_dict(response.payload)
        except (VoiceProtocolError, AttributeError) as e:
            raise VoiceConnectionError(f"Failed to parse handshake response: {e}") from e
        if payload.protocol_version != VOICE_PROTOCOL_VERSION:
            raise VoiceConnectionError(
                f"Worker protocol version mismatch: got {payload.protocol_version}, "
                f"expected {VOICE_PROTOCOL_VERSION}"
            )
        return payload, config

    def configure(self, config: VoiceWorkerConfig, *, timeout: Optional[float] = None) -> None:
        """Apply new voice settings: now if connected, else at the next handshake.

        Raises:
            VoiceConnectionError: If a connected worker rejects the settings.
        """
        with self._lock:
            self._worker_config = config
            session = self._session if self._connected else None
        if session is not None:
            self._request(
                session,
                ConfigureRequest(id=str(uuid.uuid4()), config=config),
                timeout=self._policy.request_timeout_seconds if timeout is None else timeout,
            )

    def _send_config(self, session: _WorkerSession, config: VoiceWorkerConfig) -> None:
        try:
            self._request(
                session,
                ConfigureRequest(id=str(uuid.uuid4()), config=config),
                timeout=self._policy.request_timeout_seconds,
            )
        except VoiceConnectionError as e:
            logger.warning("Voice settings changed during startup were not applied: %s", e)

    def restart(self, *, timeout: Optional[float] = None) -> None:
        """Replace the running worker on the next :meth:`connect`.

        For after the voice runtime was installed or repaired: the current
        session (if any) is shut down gracefully and reaped, without closing
        the connection and without counting as a failure. The restart
        budget is re-armed either way, and the next connect resolves the
        worker command afresh, so it starts the new release.
        """
        with self._lock:
            self._reset_restart_budget_locked()
            session = None if self._closed else self._session
        if session is None:
            return
        self._request_shutdown(session, reason="restart")
        self._end_session(
            session,
            error=VoiceConnectionClosedError("The voice worker is restarting"),
            grace=self._policy.shutdown_timeout_seconds if timeout is None else timeout,
            expected=True,
        )

    def _resolve_worker_cmd(self) -> Optional[List[str]]:
        """Worker argv for a spawn, or None when injected streams are used.

        A resolver that fails (no usable runtime yet) is not a worker
        crash, so it does not count toward the restart backoff.
        """
        if self._injected is not None or not self._restartable:
            return None
        if self._worker_cmd is None:
            return [sys.executable, "-m", "servonaut.desktop.voice.worker"]
        if not callable(self._worker_cmd):
            return list(self._worker_cmd)
        try:
            return list(self._worker_cmd())
        except Exception as e:
            raise VoiceConnectionError(f"Voice worker is not available: {e}") from e

    def _spawn_if_needed(
        self,
        resolved_cmd: Optional[List[str]] = None,
        run_env: Optional[Dict[str, str]] = None,
    ) -> _WorkerSession:
        """Return the session to handshake: injected streams, or a new process."""
        if self._injected is not None:
            session, self._injected = self._injected, None
            return session
        if resolved_cmd is None:
            resolved_cmd = self._resolve_worker_cmd() or []
        if run_env is None:
            run_env = self._spawn_env()

        try:
            process = subprocess.Popen(
                resolved_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=run_env,
                **_platform_spawn_options(),
            )
        except (OSError, ValueError, TypeError, subprocess.SubprocessError) as e:
            raise VoiceConnectionError(f"Failed to spawn voice worker process: {e}") from e
        return self._new_session(
            process.stdin,  # type: ignore[arg-type]
            process.stdout,  # type: ignore[arg-type]
            process.stderr,
            process,
        )

    def _spawn_env(self) -> Dict[str, str]:
        """Environment for one spawn, resolved now so it reflects the present."""
        try:
            extra = dict(self._env()) if callable(self._env) else dict(self._env or {})
        except (OSError, ValueError, TypeError) as e:
            raise VoiceConnectionError(f"Voice worker environment is not available: {e}") from e
        run_env = os.environ.copy() if self._inherit_env else {}
        run_env.update(extra)
        run_env["PYTHONUNBUFFERED"] = "1"
        run_env["PYTHONIOENCODING"] = "utf-8"
        return run_env

    def _start_writer(self, session: _WorkerSession) -> None:
        session.writer = threading.Thread(
            target=self._writer_loop,
            args=(session,),
            name="ServonautVoiceWorkerStdinWriter",
            daemon=True,
        )
        session.writer.start()

    def _start_reader_threads(self, session: _WorkerSession) -> None:
        """Launch this session's stdout and stderr readers, and the dispatcher."""
        self._ensure_dispatcher()
        threading.Thread(
            target=self._stdout_reader_loop,
            args=(session,),
            name="ServonautVoiceWorkerStdoutReader",
            daemon=True,
        ).start()
        if session.stderr is not None:
            threading.Thread(
                target=self._stderr_reader_loop,
                args=(session.stderr,),
                name="ServonautVoiceWorkerStderrReader",
                daemon=True,
            ).start()

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------

    def send_request(
        self,
        request: VoiceRequest,
        *,
        timeout: Any = _USE_POLICY,
    ) -> VoiceResponse:
        """Send a request frame to the worker and block for its correlated response.

        Args:
            request: The request to send.
            timeout: Seconds to wait; ``None`` waits until the worker
                answers or the session ends. Defaults to the policy's
                request timeout.

        Raises:
            VoiceConnectionClosedError: If not connected or the worker died.
            VoiceConnectionTimeoutError: If the worker did not respond within timeout.
            VoiceFrameError: If the request cannot be encoded as a frame.
            VoiceRemoteError: If the worker replied with an error response.
        """
        if threading.current_thread() is self._dispatcher:
            logger.warning(
                "Voice request '%s' sent from the event dispatcher; later events "
                "wait until it returns — hand the work to another thread",
                request.name,
            )
        with self._lock:
            # A live session is enough: the worker enforces its own
            # handshake gate, and an event can reach a subscriber before
            # connect() has returned.
            session = self._session
            if self._closed or session is None:
                raise VoiceConnectionClosedError("VoiceConnection is not connected")
        if timeout is _USE_POLICY:
            timeout = self._policy.request_timeout_seconds
        return self._request(session, request, timeout=timeout)

    def notify(self, request: VoiceRequest) -> None:
        """Queue *request* without waiting for its reply; never raises or blocks.

        For compensating requests (a cancel after a timed-out start) and
        stop signals whose outcome the caller cannot act on anyway.
        """
        with self._lock:
            session = None if self._closed else self._session
        if session is None:
            return
        try:
            self._write(session, request)
        except VoiceConnectionError as e:
            logger.debug("Voice request '%s' not delivered: %s", request.name, e)

    def _request(
        self, session: _WorkerSession, request: VoiceRequest, *, timeout: Optional[float]
    ) -> VoiceResponse:
        future: concurrent.futures.Future[VoiceResponse] = concurrent.futures.Future()
        with self._lock:
            if self._session is not session:
                raise VoiceConnectionClosedError("Voice worker session has ended")
            self._pending[request.id] = future
        try:
            self._write(session, request)
            response = future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            self._forget(request.id)
            self._record_timeout(session)
            raise VoiceConnectionTimeoutError(
                f"Request '{request.name}' (id={request.id}) timed out after {timeout}s"
            ) from None
        except BaseException:
            self._forget(request.id)
            raise

        if not response.ok and response.error is not None:
            raise VoiceRemoteError(
                code=response.error.code,
                message=response.error.message,
                details=response.error.details,
            )
        return response

    def _forget(self, request_id: str) -> None:
        with self._lock:
            self._pending.pop(request_id, None)

    def _record_timeout(self, session: _WorkerSession) -> None:
        """Count a missed reply; recycle a worker that keeps missing them."""
        with self._lock:
            session.consecutive_timeouts += 1
            hung = (
                self._session is session
                and session.consecutive_timeouts >= self._policy.max_consecutive_timeouts
            )
        if hung:
            logger.warning(
                "Voice worker missed %d replies in a row; replacing it",
                session.consecutive_timeouts,
            )
            threading.Thread(
                target=self._end_session,
                args=(session,),
                kwargs={"error": VoiceConnectionError("The voice worker stopped responding")},
                name="ServonautVoiceWorkerRecycler",
                daemon=True,
            ).start()

    def _write(self, session: _WorkerSession, request: VoiceRequest) -> None:
        """Encode *request* here, then hand the frame to the session's writer."""
        try:
            frame = encode_voice_message(request)
        except VoiceProtocolError as e:
            raise VoiceFrameError(f"Cannot send '{request.name}' to the voice worker: {e.message}") from e
        if session.closing.is_set():
            raise VoiceConnectionClosedError("Voice worker session has ended")
        try:
            session.outbox.put_nowait(frame)
        except queue.Full:
            raise VoiceConnectionError("The voice worker is not reading its input") from None

    def _writer_loop(self, session: _WorkerSession) -> None:
        """Own the worker's stdin: write queued frames until the session closes."""
        stream = session.stdin
        try:
            while True:
                try:
                    frame = session.outbox.get(timeout=_WRITER_POLL_SECONDS)
                except queue.Empty:
                    if session.closing.is_set():
                        return
                    continue
                if frame is None:
                    return
                stream.write(frame)
                stream.flush()
        except (OSError, ValueError) as e:
            logger.debug("Voice worker input closed: %s", e)
            self._end_session(session, error=VoiceConnectionClosedError("The voice worker stopped reading"))
        finally:
            with contextlib.suppress(OSError, ValueError):
                stream.close()

    def ping(self, *, timeout: Any = _USE_POLICY) -> bool:
        """Check liveness of the worker process."""
        try:
            return self.send_request(PingRequest(id=str(uuid.uuid4())), timeout=timeout).ok
        except VoiceConnectionError as e:
            logger.debug("Voice worker ping failed: %s", e)
            return False

    def probe(self, *, timeout: Any = _USE_POLICY) -> ProbeResponsePayload:
        """Probe audio devices and model availability without starting streams."""
        resp = self.send_request(ProbeRequest(id=str(uuid.uuid4())), timeout=timeout)
        try:
            return ProbeResponsePayload.from_dict(resp.payload)
        except (VoiceProtocolError, AttributeError) as e:
            raise VoiceConnectionError(f"Failed to parse probe response: {e}") from e

    # ------------------------------------------------------------------
    # Subscriptions
    # ------------------------------------------------------------------

    def subscribe(
        self,
        event_type: Optional[Type[Any]],
        callback: Callable[[Any], None],
    ) -> Callable[[], None]:
        """Subscribe to asynchronous worker events.

        Callbacks run on the connection's dispatcher thread, one at a time
        and in arrival order. A callback may send requests, but every later
        event waits until it returns.

        Args:
            event_type: Specific event class to listen for, or None for all events.
            callback: Callable accepting the event.

        Returns:
            A zero-argument callable that unregisters the subscriber.
        """
        with self._lock:
            self._subscribers.setdefault(event_type, []).append(callback)

        def unsubscribe() -> None:
            with self._lock:
                listeners = self._subscribers.get(event_type, [])
                if callback in listeners:
                    listeners.remove(callback)

        return unsubscribe

    def on_close(self, callback: Callable[[], None]) -> None:
        """Register a callback run whenever a worker session ends.

        Fires on the dispatcher thread after the session's last event —
        on worker exit, on a failed handshake, on :meth:`restart` and on
        :meth:`close`.
        """
        with self._lock:
            self._on_close_callbacks.append(callback)

    def add_session_end_hook(self, hook: Callable[[], None]) -> None:
        """Register *hook* to run the instant a worker session ends.

        Unlike :meth:`on_close`, the hook runs synchronously while the
        session is retired, before any replacement worker can be spawned —
        for state the next handshake must already reflect. It runs under
        the connection's state lock, so it must be quick and must not call
        back into the connection.
        """
        with self._lock:
            self._session_end_hooks.append(hook)

    def _ensure_dispatcher(self) -> None:
        with self._lock:
            if self._dispatcher is not None:
                return
            self._dispatcher = threading.Thread(
                target=self._dispatch_loop, name="ServonautVoiceEventDispatcher", daemon=True,
            )
            self._dispatcher.start()

    def _dispatch_loop(self) -> None:
        while (task := self._dispatch_queue.get()) is not None:
            try:
                task()
            except Exception:  # noqa: BLE001 — one subscriber must not stop the others
                logger.debug("Exception in voice event subscriber", exc_info=True)

    def _deliver_event(self, event: Any) -> None:
        with self._lock:
            callbacks = list(self._subscribers.get(type(event), ()))
            callbacks.extend(self._subscribers.get(None, ()))
        for cb in callbacks:
            try:
                cb(event)
            except Exception:  # noqa: BLE001 — isolate subscribers
                logger.debug("Exception in voice event subscriber", exc_info=True)

    def _deliver_session_end(self) -> None:
        with self._lock:
            callbacks = list(self._on_close_callbacks)
        for cb in callbacks:
            try:
                cb()
            except Exception:  # noqa: BLE001 — isolate subscribers
                logger.debug("Error in on_close callback", exc_info=True)

    # ------------------------------------------------------------------
    # Session end
    # ------------------------------------------------------------------

    def close(self, *, timeout: Optional[float] = None) -> None:
        """Orderly, permanent shutdown of the connection and its worker.

        Returns within the shutdown grace period (plus the time to reap a
        killed worker), however stuck the worker is.
        """
        with self._lock:
            self._closed = True
            session = self._session
        if session is not None:
            self._request_shutdown(session, reason="client_close")
            self._end_session(
                session,
                error=VoiceConnectionClosedError("VoiceConnection has been closed"),
                grace=self._policy.shutdown_timeout_seconds if timeout is None else timeout,
            )
        self._stop_dispatcher()

    def kill(self) -> None:
        """Forcibly and permanently terminate the worker process."""
        with self._lock:
            self._closed = True
            session = self._session
        if session is not None:
            self._end_session(
                session,
                error=VoiceConnectionClosedError("VoiceConnection was terminated forcefully"),
                grace=0.0,
            )
        self._stop_dispatcher()

    def _request_shutdown(self, session: _WorkerSession, *, reason: str) -> None:
        with contextlib.suppress(VoiceConnectionError):
            self._write(session, ShutdownRequest(id=str(uuid.uuid4()), reason=reason))

    def _stop_dispatcher(self) -> None:
        with self._lock:
            dispatcher, self._dispatcher = self._dispatcher, None
        if dispatcher is not None:
            # Queued behind every pending event and session-end notice.
            self._dispatch_queue.put(None)

    def _end_session(
        self,
        session: _WorkerSession,
        *,
        error: Optional[Exception] = None,
        grace: Optional[float] = None,
        expected: bool = False,
    ) -> None:
        """Retire *session* once: fail its requests, reap its process, notify.

        A session ending unexpectedly counts as a failure for the restart
        backoff. A session over injected streams cannot be respawned, so its
        end closes the connection.
        """
        with self._lock:
            if self._session is not session:
                return
            self._session = None
            self._connected = False
            self._handshake_payload = None
            if not self._closed and not expected:
                self._record_failure_locked(lived_seconds=time.monotonic() - session.started_at)
            if not self._restartable:
                self._closed = True
            pending = list(self._pending.values())
            self._pending.clear()
            for hook in self._session_end_hooks:
                try:
                    hook()
                except Exception:  # noqa: BLE001 — a hook must not block the retirement
                    logger.debug("Error in voice session-end hook", exc_info=True)

        self._reap(session, grace=self._policy.shutdown_timeout_seconds if grace is None else grace)
        failure = error or VoiceConnectionClosedError(self._exit_description(session))
        for future in pending:
            if not future.done():
                future.set_exception(failure)
        self._dispatch_queue.put(self._deliver_session_end)

    @staticmethod
    def _exit_description(session: _WorkerSession) -> str:
        code = session.process.returncode if session.process is not None else None
        return "Voice worker exited" if code is None else f"Voice worker exited with status {code}"

    def _record_failure_locked(self, *, lived_seconds: float) -> None:
        if lived_seconds >= self._policy.stable_session_seconds:
            self._consecutive_failures = 0
        self._consecutive_failures += 1
        backoff = self._policy.restart_initial_backoff_seconds * (2 ** (self._consecutive_failures - 1))
        self._next_attempt_at = time.monotonic() + min(backoff, self._policy.restart_max_backoff_seconds)
        logger.warning(
            "Voice worker failed or exited unexpectedly (%d in a row)", self._consecutive_failures,
        )

    @staticmethod
    def _reap(session: _WorkerSession, *, grace: float = 0.0) -> None:
        """Stop the session's writer and make sure its process is gone.

        Never waits on the pipe: the writer is asked to finish (it closes
        stdin, which lets a healthy worker exit on EOF); a worker still
        alive at the deadline is killed, which also frees a writer stuck on
        a full pipe.
        """
        deadline = time.monotonic() + grace
        session.closing.set()
        with contextlib.suppress(queue.Full):
            session.outbox.put_nowait(None)
        writer = session.writer
        if writer is None:
            with contextlib.suppress(OSError, ValueError):
                session.stdin.close()
        elif writer is not threading.current_thread():
            writer.join(max(0.0, deadline - time.monotonic()))

        process = session.process
        if process is None:
            return
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            logger.warning("Voice worker did not exit cleanly; terminating forcefully")
            with contextlib.suppress(OSError):
                process.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=_KILL_WAIT_SECONDS)

    # ------------------------------------------------------------------
    # Readers
    # ------------------------------------------------------------------

    def _stdout_reader_loop(self, session: _WorkerSession) -> None:
        """Resolve responses and queue events until the session's output ends."""
        reader = VoiceFrameReader(session.stdout)
        error: Optional[Exception] = None
        while True:
            try:
                msg = reader.read_frame()
            except VoiceProtocolVersionError as e:
                error = self._incompatible_worker(e)
                break
            except VoiceProtocolEofError:
                logger.debug("Voice worker stdout ended mid-frame")
                break
            except VoiceProtocolError as e:
                logger.warning("Discarded malformed frame from voice worker: %s", e)
                continue
            except (OSError, ValueError) as e:
                logger.debug("Voice worker stream read failed: %s", e)
                break
            if msg is None:
                logger.debug("Voice worker stdout reached EOF")
                break
            if isinstance(msg, VoiceResponse):
                self._resolve(session, msg)
            elif isinstance(msg, VoiceEvent):
                self._dispatch_queue.put(lambda event=msg: self._deliver_event(event))
            else:
                logger.debug("Unexpected frame type received: %s", type(msg).__name__)
        self._end_session(session, error=error)
        # Only this thread reads the descriptor, so only it may close it.
        with contextlib.suppress(OSError, ValueError):
            session.stdout.close()

    def _incompatible_worker(self, error: VoiceProtocolVersionError) -> VoiceConnectionError:
        """Fail fast and stop respawning a worker from another protocol version."""
        message = (
            f"The voice runtime speaks protocol v{error.received_version}, but this "
            f"app needs v{VOICE_PROTOCOL_VERSION}. Repair the voice runtime to update it."
        )
        with self._lock:
            self._fatal_message = message
        logger.error("%s", message)
        return VoiceConnectionError(message)

    def _resolve(self, session: _WorkerSession, response: VoiceResponse) -> None:
        with self._lock:
            session.consecutive_timeouts = 0
            future = self._pending.pop(response.ref_id, None)
        if future is not None and not future.done():
            future.set_result(response)
        else:
            logger.debug("Received unhandled or already resolved response: ref_id=%s", response.ref_id)

    @staticmethod
    def _stderr_reader_loop(stream: BinaryIO) -> None:
        """Forward worker stderr to the parent log without buffered-IO locks."""
        read = raw_chunk_reader(stream)
        lines = _StderrLines()
        while True:
            try:
                chunk = read(_STDERR_CHUNK_BYTES)
            except (OSError, ValueError):
                break
            if not chunk:
                break
            for line in lines.feed(chunk):
                _log_worker_stderr_line(line)
        with contextlib.suppress(OSError, ValueError):
            stream.close()


class _StderrLines:
    """Split worker stderr into lines, bounding what is buffered per line.

    A line longer than the cap (a progress bar redrawn with ``\r``, say) is
    reported only by its length, and the rest of it up to its newline is
    dropped: logging its tail as a line of its own could leak part of a
    credential that the scrubber no longer sees whole.
    """

    def __init__(self) -> None:
        self._pending = b""
        self._dropped = 0

    def feed(self, chunk: bytes) -> List[Union[bytes, int]]:
        """Complete lines in *chunk*; an over-long line appears as its length."""
        *lines, self._pending = (self._pending + chunk).split(b"\n")
        complete: List[Union[bytes, int]] = []
        for line in lines:
            complete.append(self._dropped + len(line) if self._dropped else line)
            self._dropped = 0
        if len(self._pending) > _MAX_STDERR_LINE_BYTES:
            self._dropped += len(self._pending)
            self._pending = b""
        return complete


def _log_worker_stderr_line(line: Union[bytes, int]) -> None:
    """Log one worker stderr line, with URL credentials scrubbed.

    An over-long line is summarised instead of logged: truncating it could
    cut a credential before the part the scrubber recognises.
    """
    if isinstance(line, int) or len(line) > _MAX_STDERR_LINE_BYTES:
        size = line if isinstance(line, int) else len(line)
        logger.debug("[voice-worker] <%d-byte line omitted>", size)
        return
    text = line.decode("utf-8", errors="replace").rstrip()
    if text:
        # A failed model download can quote a proxy URL.
        logger.debug("[voice-worker] %s", scrub_credentials(text))

def _platform_spawn_options() -> Dict[str, Any]:
    """Extra ``Popen`` options for this platform (no console window on Windows)."""
    if sys.platform == "win32":
        return {"creationflags": _CREATE_NO_WINDOW}
    return {}
