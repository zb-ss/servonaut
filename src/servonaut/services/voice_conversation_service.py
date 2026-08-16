"""Hands-free conversation loop: listen, transcribe, hand off, speak, repeat.

A state machine composing the existing voice pieces — capture (either
speech-to-text engine), the voice-activity monitor, and speech output.
It contains no audio code of its own: capture stays in the input
services, playback in the output service, and this module only decides
WHEN each runs.

States and edges::

    IDLE ──start()──▶ LISTENING
    LISTENING: mic open, frames feed the voice-activity monitor.
        enough speech then vad_silence_ms of silence ─▶ capture stops,
            transcript fires ─▶ THINKING
        empty transcript ─▶ resume LISTENING silently (no turn burned)
        no speech for conversation_idle_seconds ─▶ IDLE ("idle_timeout")
    THINKING: the UI drives the chat turn; mic fully closed (half-duplex).
        speaking_started() ─▶ SPEAKING
        reply_finished()  ─▶ LISTENING   (nothing to speak)
        interrupt()       ─▶ LISTENING   (abandon the reply)
    SPEAKING: the UI's playback worker runs; mic closed (but see barge-in).
        speaking_finished() ─▶ LISTENING (playback drained)
        interrupt()         ─▶ playback stopped, LISTENING
        reply_started()     ─▶ playback stopped, THINKING (a new turn
            superseded the reply being read; the mic stays closed)
        barge-in only: sustained user speech ─▶ interrupt()
    stop() from any state ─▶ IDLE ("user")

Half-duplex is structural, not best-effort: the microphone stream is
fully stopped before THINKING or SPEAKING is entered, so the assistant's
own audio can never be transcribed as the user's next turn.

The one deliberate exception is opt-in barge-in (``voice.barge_in``,
default off — headphones mode): during SPEAKING a detection-only
capture session runs, feeding the voice-activity monitor and nothing
else. Its audio is never transcribed — sustained speech simply drives
:meth:`~VoiceConversationService.interrupt`, cutting playback and
returning to LISTENING (the first fraction of a second of the barge
utterance is therefore not captured; the user is mid-sentence and the
fresh listening session picks them up). On speakers the microphone
hears the assistant's own playback, which is why the mode is framed as
requiring headphones. Any failure in the barge session (capture,
detection) degrades to barge-in-off for that reply — it never disturbs
the SPEAKING state itself. With the flag off, the strict half-duplex
contract above holds exactly as before.

Threading contract (UI layers, read this):

* All public methods are thread-safe and may be called from any thread.
* ``start()`` validates cheaply and returns; opening the microphone (and
  any first-use model load) happens on an internal daemon thread, so the
  caller is never blocked by a model read.
* Every registered callback — state, transcript, error, stopped — is
  invoked from an internal worker thread or from whichever thread drove
  the transition, NEVER guaranteed to be the UI thread. UI code must
  marshal onto its own event loop (``App.call_from_thread``).
* Methods that close a running capture (``stop``, ``reply_started``,
  ``interrupt`` from SPEAKING) can block briefly while the input service
  tears its stream down; prefer calling them from a worker.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from enum import Enum
from typing import Any, Callable, Optional, TYPE_CHECKING

from .interfaces import VoiceConversationServiceInterface
from .voice_engines import is_silero_vad_model_present
from .voice_input_service import SAMPLE_RATE
from .voice_vad import (
    NO_VAD_MODEL_HINT,
    SPEECH_STARTED,
    UTTERANCE_ENDED,
    VoiceVadError,
    block_sample_count,
    build_voice_activity_monitor,
)

if TYPE_CHECKING:
    from servonaut.config.schema import VoiceConfig

logger = logging.getLogger(__name__)


class ConversationState(Enum):
    """The four states of the hands-free loop."""

    IDLE = "idle"
    LISTENING = "listening"
    THINKING = "thinking"
    SPEAKING = "speaking"


# Reasons handed to the stopped-callback, so the UI can word its notice.
#: The user (or the UI acting for them) called :meth:`stop`.
STOP_REASON_USER = "user"
#: LISTENING saw no speech for ``conversation_idle_seconds``.
STOP_REASON_IDLE_TIMEOUT = "idle_timeout"
#: Capture, detection, or transcription failed; the error callback fired
#: with the details just before this.
STOP_REASON_ERROR = "error"

# How often the listening thread wakes when no frames are arriving, to
# check the idle deadline and the stop flag. Short enough that a stop
# lands promptly, long enough to cost nothing.
_LOOP_POLL_SECONDS = 0.1

# Bound on waiting for the listening thread during shutdown. A thread
# wedged in a model load must not hang the caller; the generation checks
# make its late completion harmless.
_JOIN_TIMEOUT_SECONDS = 5.0

_NO_INPUT_HINT = "Voice input is not available"
_NO_FRAME_TAP_HINT = (
    "The configured capture engine does not support conversation mode"
)


class VoiceConversationError(Exception):
    """Raised when the conversation loop cannot start.

    Runtime failures inside a running loop are reported through the
    error callback instead — there is no caller left on the stack to
    catch them.
    """


class _ListenSession:
    """Everything one listening session owns.

    A fresh object per LISTENING entry: the frame tap enqueues into the
    session's own queue, so a tap invocation racing a shutdown can only
    ever land frames in a retired queue, never in the next session's.
    """

    def __init__(self, monitor: Any) -> None:
        self.monitor = monitor
        self.queue: 'queue.Queue[Any]' = queue.Queue()
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None


class VoiceConversationService(VoiceConversationServiceInterface):
    """Drives the hands-free loop over the existing voice services."""

    def __init__(
        self,
        config: 'VoiceConfig',
        *,
        input_service: Callable[[], Optional[Any]],
        output_service: Callable[[], Optional[Any]],
        vad_factory: Optional[Callable[['VoiceConfig'], Any]] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Build the controller. Cheap — nothing is probed or loaded here.

        Args:
            config: Source of the turn-taking and idle-timeout knobs.
            input_service: Zero-argument callable resolving the CURRENT
                capture service (or None). Resolved fresh on every
                listening cycle so a settings save that rebuilds the
                service is picked up without rebuilding the loop.
            output_service: Same, for the speech-output service.
            vad_factory: Optional replacement for the default
                voice-activity monitor builder; tests inject a scripted
                monitor here so no audio runtime is needed. When set, the
                default factory's model-presence precheck is skipped —
                the injected factory owns its own readiness.
            clock: Monotonic time source for the idle timeout,
                injectable for tests.
        """
        self._config = config
        self._input_provider = input_service
        self._output_provider = output_service
        self._vad_factory = vad_factory
        self._clock = clock
        # RLock: transition helpers are small, but an error path may
        # re-enter (fire-and-transition) while already holding it.
        self._lock = threading.RLock()
        self._state = ConversationState.IDLE
        self._session: Optional[_ListenSession] = None
        # Barge-in (opt-in): a detection-only capture session that runs
        # during SPEAKING. Kept separate from ``_session`` — it is never
        # transcribed and dies on every transition out of SPEAKING.
        self._barge_session: Optional[_ListenSession] = None
        self._on_state_changed: Optional[Callable[[ConversationState], None]] = None
        self._on_transcript: Optional[Callable[[str], None]] = None
        self._on_error: Optional[Callable[[str], None]] = None
        self._on_stopped: Optional[Callable[[str], None]] = None

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def set_state_callback(
        self, callback: Optional[Callable[[ConversationState], None]]
    ) -> None:
        """Register a callback fired on every state transition.

        Invoked from internal threads — the UI must marshal.
        """
        self._on_state_changed = callback

    def set_transcript_callback(
        self, callback: Optional[Callable[[str], None]]
    ) -> None:
        """Register a callback fired when an utterance produced text.

        Fires with the non-empty transcript AFTER the state callback has
        reported THINKING; the mic is already closed. Invoked from the
        listening thread — the UI must marshal.
        """
        self._on_transcript = callback

    def set_error_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        """Register a callback fired when a running loop fails.

        The message is user-fit (no tracebacks). The loop lands in IDLE
        right after, reported via the state and stopped callbacks with
        reason :data:`STOP_REASON_ERROR`. Invoked from internal threads —
        the UI must marshal.
        """
        self._on_error = callback

    def set_stopped_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        """Register a callback fired whenever the loop lands in IDLE.

        Receives one of :data:`STOP_REASON_USER`,
        :data:`STOP_REASON_IDLE_TIMEOUT`, :data:`STOP_REASON_ERROR` so
        the UI can word its notice — an idle timeout deserves different
        copy than a deliberate stop. Invoked from internal threads — the
        UI must marshal.
        """
        self._on_stopped = callback

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def state(self) -> ConversationState:
        """The loop's current state."""
        with self._lock:
            return self._state

    # ------------------------------------------------------------------
    # Public transitions
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Begin the loop: IDLE -> LISTENING.

        Validates the prerequisites synchronously and raises when they
        are not met; the microphone itself opens on an internal thread,
        so a first-use model load never blocks the caller. A failure to
        open the mic after this returns is reported through the error
        callback.

        Raises:
            VoiceConversationError: If the loop is already active, no
                capture service is available, the engine lacks a frame
                tap, or the voice-activity model is missing.
        """
        input_service = self._input_provider()
        if input_service is None:
            raise VoiceConversationError(_NO_INPUT_HINT)
        if not hasattr(input_service, "set_frame_callback"):
            raise VoiceConversationError(_NO_FRAME_TAP_HINT)
        if not input_service.is_available():
            raise VoiceConversationError(
                input_service.unavailable_reason() or _NO_INPUT_HINT
            )
        monitor = self._build_monitor()

        with self._lock:
            if self._state is not ConversationState.IDLE:
                raise VoiceConversationError("Conversation mode is already active")
            self._state = ConversationState.LISTENING
            session = _ListenSession(monitor)
            self._session = session
        self._fire_state(ConversationState.LISTENING)
        self._spawn_listener(session, input_service)

    def stop(self, *, join: bool = True) -> None:
        """End the loop from any state: -> IDLE. Never raises.

        Stops capture and playback, retires the listening thread, and
        reports IDLE with reason :data:`STOP_REASON_USER`. A no-op when
        already idle (no callbacks fire).

        Args:
            join: When True (the default) the call waits briefly for the
                listening thread to finish — which can block for seconds
                if that thread is mid-transcription. Pass False from a UI
                thread (unmount teardown): the session-generation checks
                already make the thread's late completion harmless, so
                skipping the wait loses nothing.
        """
        self._shutdown(STOP_REASON_USER, join=join)

    def interrupt(self) -> None:
        """Cut the assistant short and listen again. Never raises.

        SPEAKING: playback stops mid-word and the mic reopens.
        THINKING: the pending reply is abandoned state-side (the UI owns
        cancelling its own request) and the mic reopens. IDLE and
        LISTENING: no-op.
        """
        with self._lock:
            state = self._state
        if state not in (ConversationState.SPEAKING, ConversationState.THINKING):
            return
        output = self._safe_output()
        if output is not None:
            try:
                output.stop()
            except Exception:  # noqa: BLE001 — the cancel path must not raise
                logger.debug("Output stop failed during interrupt", exc_info=True)
        self._resume_listening(state)

    def reply_started(self) -> None:
        """UI signal: a chat turn is in flight. LISTENING/SPEAKING -> THINKING.

        For sends the loop did not initiate (the user typed a message
        while listening): the mic closes so the half-duplex rule holds.
        From SPEAKING — the user typed a message while the previous reply
        was being read aloud — playback is cut short and the machine
        lands in THINKING with the mic still closed. Without this edge a
        superseded playback's ``speaking_finished`` would reopen the
        microphone under the new turn, and the next reply would then play
        over a hot mic — the exact self-transcription hazard the
        half-duplex rule exists to prevent. A no-op in every other state
        — a transcript-initiated turn is already THINKING.

        Can block briefly while the capture stream tears down.
        """
        session: Optional[_ListenSession] = None
        stop_playback = False
        with self._lock:
            if self._state is ConversationState.LISTENING:
                self._state = ConversationState.THINKING
                session, self._session = self._session, None
            elif self._state is ConversationState.SPEAKING:
                self._state = ConversationState.THINKING
                stop_playback = True
            else:
                return
        if stop_playback:
            # Leaving SPEAKING for a superseding turn: the barge monitor
            # (when one is running) dies with the playback it watched.
            self._retire_barge_session()
            output = self._safe_output()
            if output is not None:
                self._quiet(output.stop)
        self._retire_session(session)
        self._fire_state(ConversationState.THINKING)

    def reply_finished(self) -> None:
        """UI signal: the reply completed with nothing to speak.

        THINKING -> LISTENING. A no-op in every other state — when the
        reply IS being spoken, :meth:`speaking_finished` is the exit.
        """
        self._resume_listening(ConversationState.THINKING)

    def speaking_started(self) -> None:
        """UI signal: playback of the reply has begun. THINKING -> SPEAKING.

        A no-op in every other state. With ``voice.barge_in`` enabled a
        detection-only barge monitor opens alongside the playback (see
        the module docstring); its failure to start degrades to plain
        SPEAKING rather than surfacing an error.
        """
        with self._lock:
            if self._state is not ConversationState.THINKING:
                return
            self._state = ConversationState.SPEAKING
        self._fire_state(ConversationState.SPEAKING)
        if bool(getattr(self._config, "barge_in", False)):
            self._start_barge_monitor()

    def speaking_finished(self) -> None:
        """UI signal: playback has fully drained. SPEAKING -> LISTENING.

        Call it when the speak worker returns — including when playback
        was cut short by a stop the loop did not issue. A no-op in every
        other state.
        """
        self._resume_listening(ConversationState.SPEAKING)

    # ------------------------------------------------------------------
    # Listening thread
    # ------------------------------------------------------------------

    def _spawn_listener(self, session: _ListenSession, input_service: Any) -> None:
        """Start the daemon thread that owns this listening session."""
        session.thread = threading.Thread(
            target=self._listen_loop,
            args=(session, input_service),
            name="voice-conversation",
            daemon=True,
        )
        session.thread.start()

    def _listen_loop(self, session: _ListenSession, input_service: Any) -> None:
        """One listening session: open the mic, watch the VAD, endpoint.

        Runs on the session thread. Every exit path lands the machine in
        a defined state: THINKING (transcript delivered), IDLE (idle
        timeout / error), or silent retirement when a public transition
        already took the session away.
        """
        try:
            if not self._open_capture(session, input_service):
                return
            idle_deadline = self._clock() + self._idle_seconds()
            utterance_samples = 0
            while not session.stop_event.is_set():
                try:
                    block = session.queue.get(timeout=_LOOP_POLL_SECONDS)
                except queue.Empty:
                    block = None
                if session.stop_event.is_set():
                    return
                if block is not None:
                    try:
                        events = session.monitor.feed(block)
                    except VoiceVadError as e:
                        self._fail_from_loop(session, input_service, str(e))
                        return
                    if SPEECH_STARTED in events:
                        idle_deadline = self._clock() + self._idle_seconds()
                        # The capture services budget max_recording_seconds
                        # from mic-open — which here includes every second
                        # of pre-turn silence. Restart that budget when
                        # speech actually begins, so an utterance late in
                        # the idle window is buffered in full rather than
                        # silently truncated at the wall-clock cap.
                        reset_budget = getattr(
                            input_service, "reset_recording_budget", None
                        )
                        if callable(reset_budget):
                            self._quiet(reset_budget)
                    if session.monitor.utterance_in_progress:
                        utterance_samples += block_sample_count(block)
                    ended = UTTERANCE_ENDED in events
                    if (not ended
                            and session.monitor.utterance_in_progress
                            and utterance_samples >= self._max_utterance_samples()):
                        # Speech ran into the recording cap without a
                        # pause — force the endpoint so continuous noise
                        # can never hold the turn (and the mic) open
                        # forever.
                        session.monitor.flush()
                        ended = True
                    if ended:
                        if self._finish_utterance(session, input_service):
                            return
                        # Empty transcript: capture restarted, keep going.
                        idle_deadline = self._clock() + self._idle_seconds()
                        utterance_samples = 0
                        continue
                if (not session.monitor.utterance_in_progress
                        and self._clock() >= idle_deadline):
                    self._stop_from_loop(session, input_service)
                    return
        except Exception as e:  # noqa: BLE001 — the loop must land in a defined state
            logger.error("Conversation loop failed: %s", e)
            self._fail_from_loop(session, input_service, f"Conversation failed: {e}")

    def _open_capture(self, session: _ListenSession, input_service: Any) -> bool:
        """Register the frame tap and open the microphone.

        Returns:
            True when capture is running; False after reporting the
            failure and landing in IDLE.
        """
        try:
            input_service.set_frame_callback(
                lambda block: self._enqueue_frame(session, block)
            )
            input_service.start_recording()
        except Exception as e:  # noqa: BLE001 — VoiceInputError and friends
            self._fail_from_loop(session, input_service, str(e))
            return False
        return True

    def _enqueue_frame(self, session: _ListenSession, block: Any) -> None:
        """Frame tap: audio thread -> session queue. O(1), never raises."""
        if not session.stop_event.is_set():
            session.queue.put(block)

    def _finish_utterance(self, session: _ListenSession, input_service: Any) -> bool:
        """Endpoint reached: close the mic, transcribe, hand off.

        Returns:
            True when the session is over (transcript delivered, error,
            or superseded); False when the transcript was empty and
            capture was reopened for the same session.
        """
        # Tap off FIRST: no frame may arrive between the endpoint
        # decision and the stream teardown.
        self._quiet(input_service.set_frame_callback, None)
        try:
            text = input_service.stop_and_transcribe()
        except Exception as e:  # noqa: BLE001 — VoiceInputError and friends
            self._fail_from_loop(session, input_service, str(e))
            return True
        if session.stop_event.is_set():
            return True

        text = (text or "").strip()
        if not text:
            # A cough, a chair creak: no chat turn burned. Same session,
            # fresh capture.
            session.monitor.reset()
            return not self._open_capture(session, input_service)

        with self._lock:
            if (self._state is not ConversationState.LISTENING
                    or self._session is not session):
                # A public transition (stop / reply_started) won the race;
                # its target state stands and the transcript is dropped.
                return True
            self._state = ConversationState.THINKING
            self._session = None
        self._fire_state(ConversationState.THINKING)
        self._fire_transcript(text)
        return True

    def _stop_from_loop(self, session: _ListenSession, input_service: Any) -> None:
        """Idle timeout: the session thread retires itself to IDLE."""
        self._quiet(input_service.set_frame_callback, None)
        self._quiet(input_service.cancel_recording)
        with self._lock:
            if self._session is not session:
                return  # a public transition already took over
            self._session = None
            self._state = ConversationState.IDLE
        self._fire_state(ConversationState.IDLE)
        self._fire_stopped(STOP_REASON_IDLE_TIMEOUT)

    def _fail_from_loop(
        self, session: _ListenSession, input_service: Any, message: str
    ) -> None:
        """A running session failed: report it and land in IDLE."""
        self._quiet(input_service.set_frame_callback, None)
        self._quiet(input_service.cancel_recording)
        with self._lock:
            if self._session is not session:
                return  # a public transition already took over
            self._session = None
            self._state = ConversationState.IDLE
        self._fire_error(message)
        self._fire_state(ConversationState.IDLE)
        self._fire_stopped(STOP_REASON_ERROR)

    # ------------------------------------------------------------------
    # Barge-in monitor (opt-in, SPEAKING only)
    # ------------------------------------------------------------------

    def _start_barge_monitor(self) -> None:
        """Open the detection-only capture session for SPEAKING.

        Called right after the THINKING -> SPEAKING transition when
        ``voice.barge_in`` is on. Every failure here — no capture
        service, no frame tap, no detection model — degrades to plain
        SPEAKING with a debug log: barge-in is a convenience on top of a
        working reply, and it must never take the reply down.
        """
        try:
            input_service = self._input_provider()
            if input_service is None or not hasattr(
                input_service, "set_frame_callback"
            ):
                logger.debug("Barge-in unavailable: no frame-tap capture service")
                return
            monitor = self._build_monitor()
        except Exception:  # noqa: BLE001 — degrade, never disturb SPEAKING
            logger.debug("Barge-in monitor could not be built", exc_info=True)
            return

        with self._lock:
            if self._state is not ConversationState.SPEAKING:
                return  # playback already over — nothing to watch
            if self._barge_session is not None:
                return
            session = _ListenSession(monitor)
            self._barge_session = session
        session.thread = threading.Thread(
            target=self._barge_loop,
            args=(session, input_service),
            name="voice-barge",
            daemon=True,
        )
        session.thread.start()

    def _barge_loop(self, session: _ListenSession, input_service: Any) -> None:
        """Watch the microphone for sustained speech during playback.

        Runs on the barge session's thread. Frames feed the
        voice-activity monitor and NOTHING else — the buffered audio is
        cancelled, never transcribed. The monitor's
        ``vad_min_speech_ms`` gate is the anti-false-trigger filter: a
        cough or a keyboard clack never opens a turn, so it never cuts a
        reply short either. On :data:`SPEECH_STARTED` the loop closes
        its own capture first, then drives the ordinary
        :meth:`interrupt`. Every failure degrades to barge-in-off for
        this reply.
        """
        try:
            try:
                input_service.set_frame_callback(
                    lambda block: self._enqueue_frame(session, block)
                )
                input_service.start_recording()
            except Exception:  # noqa: BLE001 — VoiceInputError and friends
                logger.debug("Barge-in capture failed to open", exc_info=True)
                self._clear_barge_session(session)
                return
            while not session.stop_event.is_set():
                try:
                    block = session.queue.get(timeout=_LOOP_POLL_SECONDS)
                except queue.Empty:
                    continue
                if session.stop_event.is_set():
                    return
                try:
                    events = session.monitor.feed(block)
                except VoiceVadError:
                    logger.debug("Barge-in detection failed", exc_info=True)
                    self._quiet(input_service.set_frame_callback, None)
                    self._quiet(input_service.cancel_recording)
                    self._clear_barge_session(session)
                    return
                if SPEECH_STARTED in events:
                    self._trigger_barge(session, input_service)
                    return
        except Exception:  # noqa: BLE001 — the loop must degrade, not crash SPEAKING
            logger.debug("Barge-in loop failed", exc_info=True)
            self._quiet(input_service.set_frame_callback, None)
            self._quiet(input_service.cancel_recording)
            self._clear_barge_session(session)

    def _trigger_barge(self, session: _ListenSession, input_service: Any) -> None:
        """Sustained speech heard over playback: interrupt the reply.

        The barge capture closes FIRST (tap off, buffered audio
        discarded) so the fresh listening session :meth:`interrupt`
        opens has sole ownership of the input stream. A transition that
        already moved the machine out of SPEAKING wins — the barge
        simply retires.
        """
        self._quiet(input_service.set_frame_callback, None)
        self._quiet(input_service.cancel_recording)
        with self._lock:
            current = self._barge_session is session
            if current:
                self._barge_session = None
            speaking = self._state is ConversationState.SPEAKING
        if not current or not speaking:
            return
        logger.debug("Barge-in: speech during playback, interrupting the reply")
        self.interrupt()

    def _clear_barge_session(self, session: _ListenSession) -> None:
        """Forget *session* if it is still the registered barge session."""
        with self._lock:
            if self._barge_session is session:
                self._barge_session = None

    def _retire_barge_session(self, *, join: bool = True) -> None:
        """Stop the barge monitor, if one is running. Never raises."""
        with self._lock:
            session, self._barge_session = self._barge_session, None
        if session is not None:
            self._retire_session(session, join=join)

    # ------------------------------------------------------------------
    # Shared transition machinery
    # ------------------------------------------------------------------

    def _resume_listening(self, from_state: ConversationState) -> None:
        """Transition *from_state* -> LISTENING with a fresh session.

        Services and the monitor are re-resolved here, not reused: a
        settings save mid-turn may have rebuilt the capture service, and
        the retired instance must not be reopened.
        """
        # Any road back to LISTENING closes the barge monitor first — the
        # fresh listening session below must own the capture stream alone.
        self._retire_barge_session()
        input_service = self._input_provider()
        error: Optional[str] = None
        monitor: Optional[Any] = None
        if input_service is None:
            error = _NO_INPUT_HINT
        elif not hasattr(input_service, "set_frame_callback"):
            error = _NO_FRAME_TAP_HINT
        else:
            try:
                monitor = self._build_monitor()
            except VoiceConversationError as e:
                error = str(e)

        if error is not None:
            with self._lock:
                if self._state is not from_state:
                    return
                self._state = ConversationState.IDLE
            self._fire_error(error)
            self._fire_state(ConversationState.IDLE)
            self._fire_stopped(STOP_REASON_ERROR)
            return

        with self._lock:
            if self._state is not from_state:
                return  # a concurrent transition won; its state stands
            self._state = ConversationState.LISTENING
            session = _ListenSession(monitor)
            self._session = session
        self._fire_state(ConversationState.LISTENING)
        self._spawn_listener(session, input_service)

    def _shutdown(self, reason: str, *, join: bool = True) -> None:
        """Any state -> IDLE. The single teardown path; never raises."""
        with self._lock:
            if self._state is ConversationState.IDLE:
                return
            self._state = ConversationState.IDLE
            session, self._session = self._session, None
        self._retire_barge_session(join=join)
        self._retire_session(session, join=join)
        output = self._safe_output()
        if output is not None:
            self._quiet(output.stop)
        self._fire_state(ConversationState.IDLE)
        self._fire_stopped(reason)

    def _retire_session(
        self, session: Optional[_ListenSession], *, join: bool = True
    ) -> None:
        """Stop a listening session's capture and wait out its thread.

        With ``join=False`` the thread is signalled but not waited for:
        an unmount-time teardown runs on the UI thread, where a join
        against a thread that is mid-transcription would freeze the whole
        interface. The stop event plus the session-generation checks make
        the thread's late completion harmless either way.
        """
        if session is None:
            return
        session.stop_event.set()
        input_service = self._safe_input()
        if input_service is not None:
            self._quiet(getattr(input_service, "set_frame_callback", lambda _cb: None), None)
            self._quiet(input_service.cancel_recording)
        thread = session.thread
        if join and thread is not None and thread is not threading.current_thread():
            thread.join(timeout=_JOIN_TIMEOUT_SECONDS)
            if thread.is_alive():
                logger.warning("Conversation listener did not stop within %ss",
                               _JOIN_TIMEOUT_SECONDS)

    def _build_monitor(self) -> Any:
        """Build the voice-activity monitor for one listening session.

        Raises:
            VoiceConversationError: When the default detector's model is
                not on disk. An injected factory skips the precheck — it
                owns its own readiness.
        """
        if self._vad_factory is not None:
            return self._vad_factory(self._config)
        if not is_silero_vad_model_present():
            raise VoiceConversationError(NO_VAD_MODEL_HINT)
        return build_voice_activity_monitor(self._config)

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------

    def _idle_seconds(self) -> float:
        """The open-mic bound, floored at one second defensively."""
        return max(1.0, float(getattr(self._config, "conversation_idle_seconds", 60)))

    def _max_utterance_samples(self) -> int:
        """Longest turn the loop lets a single utterance run, in samples.

        Reuses the recording cap so one knob bounds both surfaces. The
        listen loop restarts the capture services' wall-clock budget when
        speech begins (see the SPEECH_STARTED handling), which keeps this
        speech-only counter and the services' buffering cap aligned: both
        run out around the same moment, so the forced endpoint lands
        before (not after) buffering stops.
        """
        return max(1, int(self._config.max_recording_seconds)) * SAMPLE_RATE

    def _safe_input(self) -> Optional[Any]:
        """Resolve the current input service, tolerating provider faults."""
        try:
            return self._input_provider()
        except Exception:  # noqa: BLE001 — a provider fault must not break teardown
            return None

    def _safe_output(self) -> Optional[Any]:
        """Resolve the current output service, tolerating provider faults."""
        try:
            return self._output_provider()
        except Exception:  # noqa: BLE001 — a provider fault must not break teardown
            return None

    @staticmethod
    def _quiet(call: Callable[..., Any], *args: Any) -> None:
        """Invoke a cleanup call, logging instead of raising."""
        try:
            call(*args)
        except Exception:  # noqa: BLE001 — cleanup must never mask the outcome
            logger.debug("Conversation cleanup call failed", exc_info=True)

    # ------------------------------------------------------------------
    # Callback firing (always outside the lock)
    # ------------------------------------------------------------------

    def _fire_state(self, state: ConversationState) -> None:
        callback = self._on_state_changed
        if callback is None:
            return
        try:
            callback(state)
        except Exception:  # noqa: BLE001 — a UI failure must not kill the loop
            logger.debug("State callback failed", exc_info=True)

    def _fire_transcript(self, text: str) -> None:
        callback = self._on_transcript
        if callback is None:
            return
        try:
            callback(text)
        except Exception:  # noqa: BLE001 — a UI failure must not kill the loop
            logger.debug("Transcript callback failed", exc_info=True)

    def _fire_error(self, message: str) -> None:
        callback = self._on_error
        if callback is None:
            return
        try:
            callback(message)
        except Exception:  # noqa: BLE001 — a UI failure must not kill the loop
            logger.debug("Error callback failed", exc_info=True)

    def _fire_stopped(self, reason: str) -> None:
        callback = self._on_stopped
        if callback is None:
            return
        try:
            callback(reason)
        except Exception:  # noqa: BLE001 — a UI failure must not kill the loop
            logger.debug("Stopped callback failed", exc_info=True)
