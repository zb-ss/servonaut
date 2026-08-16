"""Spoken replies: local text-to-speech and playback for the chat panel.

Synthesis runs entirely on the local machine via a Kokoro model under
``sherpa-onnx`` — reply text is never sent to a speech API, the same
privacy stance voice input takes.

All dependencies are optional (``pip install 'servonaut[voice-output]'``)
and the module degrades to a disabled feature when they are missing:
importing it never raises, and :meth:`VoiceOutputService.is_available`
reports the truth so callers can hide the speaker affordance instead of
failing when a reply arrives.

Threading shape: callers hand text to :meth:`speak` (blocking) or
:meth:`enqueue` (fire and forget); two daemon threads pipeline the work.
A synthesis thread drains the bounded text queue and renders PCM; a
playback thread drains a small bounded PCM queue and writes to one
``sounddevice`` ``OutputStream`` that stays open across sentences (and
closes after a short idle). The pipeline exists for pacing: with a
single thread the listener hears the NEXT sentence's whole synthesis
time as dead air between sentences, so sentence N+1 is rendered while
sentence N is still playing. :meth:`stop` cancels from any thread by
bumping an epoch counter the synthesis callback and the playback loop
both watch, so cancellation lands within a chunk rather than at the end
of the sentence. A caller that schedules :meth:`speak` on another
thread should snapshot :meth:`current_epoch` first and pass it along,
so a stop() landing before the hand-off completes still retires the
utterance. A job settles (its ``done`` event, the pending counter, its
session accounting) only after it has left BOTH stages. :meth:`close`
shuts both threads down for good when the service is being replaced.

Streamed replies group their sentences into an :class:`UtteranceSession`
(via :meth:`VoiceOutputService.begin_utterance`): sentences are enqueued
as they complete, and the session's completion callback fires exactly
once — when the last sentence has played after :meth:`UtteranceSession.end`,
or immediately with ``played_to_end=False`` when a :meth:`stop`
supersedes the session. That callback is what lets a conversation loop
hold its SPEAKING state open across a whole streamed reply without
polling.
"""

from __future__ import annotations

import importlib
import logging
import math
import queue
import threading
from typing import Any, Callable, List, Optional, Tuple, TYPE_CHECKING

from servonaut.config.schema import TTS_SPEED_MAX, TTS_SPEED_MIN

from .interfaces import VoiceOutputServiceInterface
from .voice_engines import (
    DEFAULT_TTS_VOICE,
    KOKORO_ESPEAK_DIR,
    KOKORO_LEXICON_FILES,
    KOKORO_MODEL_FILE,
    KOKORO_TOKENS_FILE,
    KOKORO_VOICES_FILE,
    is_kokoro_model_present,
    kokoro_model_dir,
    kokoro_voice_sid,
)
from .voice_text import speakable_text

if TYPE_CHECKING:
    from servonaut.config.schema import VoiceConfig

logger = logging.getLogger(__name__)

try:
    import numpy as np
    import sounddevice as sd
    import sherpa_onnx
    HAS_TTS_DEPS = True
except Exception:  # noqa: BLE001 — a broken PortAudio/onnxruntime build raises OSError, not ImportError
    np = None  # type: ignore[assignment]
    sd = None  # type: ignore[assignment]
    sherpa_onnx = None  # type: ignore[assignment]
    HAS_TTS_DEPS = False


def reload_tts_deps() -> bool:
    """Re-attempt the optional imports and rebind the module globals.

    The flag above is resolved once at import time, so an install done
    while the app is running would otherwise keep reporting the feature
    missing until a restart. When the imports still fail the module is
    left exactly as it was.

    Returns:
        True when the dependencies are importable afterwards.
    """
    global np, sd, sherpa_onnx, HAS_TTS_DEPS  # noqa: PLW0603 — rebinding the cached import state is the point

    importlib.invalidate_caches()
    try:
        import numpy as _np
        import sounddevice as _sd
        import sherpa_onnx as _sherpa
    except Exception as e:  # noqa: BLE001 — same failure surface as the initial import
        logger.debug("Voice output dependencies still unavailable after reload: %s", e)
        return False

    np = _np
    sd = _sd
    sherpa_onnx = _sherpa
    HAS_TTS_DEPS = True
    logger.info("Voice output dependencies loaded without a restart")
    return True


# Playback is written to the device in chunks of this many seconds so a
# stop() lands within a chunk instead of after the whole sentence.
_PLAYBACK_CHUNK_SECONDS = 0.1

# Ceiling on queued utterances. Deep enough that a long streamed reply
# never stalls its producer in practice, shallow enough that a runaway
# producer cannot grow memory without bound.
_QUEUE_MAX_UTTERANCES = 64

# Ceiling on rendered-but-unplayed sentences. Small on purpose: each entry
# is a whole sentence of PCM (~100 KB/s of speech), and one sentence of
# lookahead is all the pacing needs — the bound is backpressure for the
# synthesis thread, not a buffer to fill.
_PCM_QUEUE_MAX = 3

# How long the playback thread keeps the output device open while idle.
# Long enough to bridge every inter-sentence gap in a streamed reply,
# short enough that the device is released promptly once a reply ends.
_STREAM_IDLE_CLOSE_SECONDS = 2.0

_INSTALL_HINT = "Spoken replies need: pip install 'servonaut[voice-output]'"
_NO_DEVICE_HINT = "No audio output device detected"
_NO_MODEL_HINT = "The speech model is not downloaded yet — see Settings > Voice Input"


class VoiceOutputError(Exception):
    """Raised when speech synthesis or playback fails.

    Wraps every backend failure (onnxruntime, PortAudio, model load) so
    callers never have to catch library-specific exception types.
    """


class _SpeechJob:
    """One utterance moving through the queue."""

    __slots__ = ("text", "epoch", "done", "error", "session")

    def __init__(
        self,
        text: str,
        epoch: int,
        session: Optional['UtteranceSession'] = None,
    ) -> None:
        self.text = text
        self.epoch = epoch
        self.done = threading.Event()
        self.error: Optional[str] = None
        # The streamed-utterance session this sentence belongs to, so the
        # worker can report per-sentence completion back to it.
        self.session = session


class UtteranceSession:
    """One streamed reply's sentences, tracked as a unit.

    Built by :meth:`VoiceOutputService.begin_utterance`. The producer
    enqueues sentences as the stream completes them, then calls
    :meth:`end` when the stream is over. The ``on_complete`` callback
    fires EXACTLY ONCE per session:

    * with ``played_to_end=True`` when every enqueued sentence finished
      playing after :meth:`end` was called (a session that ended with
      nothing enqueued completes immediately, still ``True``);
    * with ``played_to_end=False`` the moment a :meth:`VoiceOutputService.stop`
      (or :meth:`~VoiceOutputService.close`) supersedes the session —
      whether or not :meth:`end` was ever called, so an interrupted
      stream can never strand its consumer waiting for a completion.

    The callback is invoked from whichever thread finished the last
    sentence or issued the stop — never guaranteed to be a UI thread;
    UI consumers must marshal. Exceptions it raises are swallowed and
    logged. All methods are thread-safe and never raise.
    """

    def __init__(
        self,
        service: 'VoiceOutputService',
        epoch: int,
        on_complete: Optional[Callable[[bool], None]],
    ) -> None:
        self._service = service
        self._epoch = epoch
        self._on_complete = on_complete
        # All mutable state below is guarded by the SERVICE's lock: the
        # worker thread, the producer and stop() all touch it, and the
        # service already serialises those parties.
        self._outstanding = 0
        self._ended = False
        self._completed = False
        self._stopped = False

    @property
    def epoch(self) -> int:
        """The cancellation epoch this session's sentences are pinned to."""
        return self._epoch

    @property
    def is_settled(self) -> bool:
        """Whether the exactly-once completion has already been claimed.

        True once the session finished playing to the end OR was retired
        by a :meth:`VoiceOutputService.stop`/:meth:`~VoiceOutputService.close`
        (including a session born superseded). A settled session drops
        every further :meth:`enqueue` and its :meth:`end` fires nothing —
        consumers holding one must not treat it as owning any future
        playback-completion signal.
        """
        with self._service._lock:
            return self._completed

    def enqueue(self, sentence: str) -> None:
        """Queue one sentence of this utterance for playback.

        Fire-and-forget like :meth:`VoiceOutputService.enqueue` —
        failures are logged, a superseded session drops the sentence
        silently. Sentences enqueued after :meth:`end` are dropped (the
        completion may already have fired).
        """
        with self._service._lock:
            if self._completed or self._ended:
                return
        try:
            self._service._submit(
                sentence, check_available=True,
                epoch=self._epoch, session=self,
            )
        except VoiceOutputError as e:
            logger.warning("Dropped a spoken sentence: %s", e)
        except Exception as e:  # noqa: BLE001 — fire-and-forget must not leak
            logger.warning("Dropped a spoken sentence: %s", e)

    def end(self) -> None:
        """The stream is over: complete once the queued sentences play.

        Idempotent. When nothing is outstanding the completion fires
        before this returns (on the caller's thread).
        """
        with self._service._lock:
            self._ended = True
            fire = self._completion_due_locked()
        if fire:
            self._fire_completion()

    # -- internals (service + worker side) ------------------------------

    def _job_finished(self) -> None:
        """Worker signal: one of this session's sentences left the queue."""
        with self._service._lock:
            self._outstanding -= 1
            fire = self._completion_due_locked()
        if fire:
            self._fire_completion()

    def _completion_due_locked(self) -> bool:
        """Claim the completion if it is due. Caller holds the lock."""
        if self._completed or not self._ended or self._outstanding > 0:
            return False
        self._completed = True
        # Deregister so the roster only ever holds live sessions.
        try:
            self._service._sessions.remove(self)
        except ValueError:
            pass
        return True

    def _retire_locked(self) -> bool:
        """Claim the completion for a stop/supersede. Caller holds the lock."""
        if self._completed:
            return False
        self._completed = True
        self._stopped = True
        return True

    def _fire_completion(self) -> None:
        """Invoke the callback exactly once, outside the lock."""
        callback = self._on_complete
        if callback is None:
            return
        try:
            callback(not self._stopped)
        except Exception:  # noqa: BLE001 — a consumer failure must not kill the worker
            logger.debug("Utterance completion callback failed", exc_info=True)


class VoiceOutputService(VoiceOutputServiceInterface):
    """Synthesises reply text locally and plays it aloud."""

    def __init__(self, config: 'VoiceConfig') -> None:
        self._config = config
        # Guards the pending counter, the epoch, and worker start against
        # the caller threads, the worker, and stop() arriving from the UI.
        self._lock = threading.Lock()
        # None is the close() sentinel that wakes the worker to exit.
        self._queue: 'queue.Queue[Optional[_SpeechJob]]' = queue.Queue(
            maxsize=_QUEUE_MAX_UTTERANCES
        )
        self._worker: Optional[threading.Thread] = None
        # Rendered sentences waiting to play: (job, buffer, sample_rate)
        # tuples, or the close() sentinel. Bounded so synthesis can run at
        # most a sentence or two ahead of the listener.
        self._pcm_queue: 'queue.Queue[Optional[Tuple[_SpeechJob, Any, int]]]' = (
            queue.Queue(maxsize=_PCM_QUEUE_MAX)
        )
        self._playback: Optional[threading.Thread] = None
        self._tts: Optional[Any] = None
        self._out_stream: Optional[Any] = None
        self._out_stream_rate = 0
        self._pending = 0
        # Bumped by stop(); queued jobs and in-flight synthesis/playback
        # from an older epoch are discarded at the next check.
        self._epoch = 0
        # Set by close(); a closed service accepts no further utterances
        # and its worker thread exits instead of blocking forever.
        self._closed = False
        # Live streamed-utterance sessions, so stop() can retire them
        # (firing their completion with played_to_end=False) instead of
        # leaving a consumer waiting on audio that will never play.
        self._sessions: List[UtteranceSession] = []
        # Device enumeration costs a PortAudio init, so probe once and
        # reuse the verdict for the lifetime of the service.
        self._availability: Optional[Tuple[bool, str]] = None

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Check if spoken replies can be produced right now.

        Returns:
            True only when the optional libraries imported cleanly, the
            speech model is on disk, AND an output device is present.
        """
        available, _ = self._probe()
        return available

    def unavailable_reason(self) -> str:
        """Explain why spoken replies cannot be produced.

        Returns:
            Short, actionable message, or an empty string when available.
            Never contains a traceback or a library-internal message.
        """
        _, reason = self._probe()
        return reason

    def reset_availability(self) -> None:
        """Drop the cached availability verdict so the next check re-probes.

        Call this after installing the dependencies or changing the audio
        setup: without it the service would keep serving the verdict it
        cached at startup for its whole lifetime.
        """
        self._availability = None

    def _probe(self) -> Tuple[bool, str]:
        """Resolve and cache the (available, reason) verdict.

        The missing-deps and missing-model verdicts are deliberately NOT
        cached — an install or a download outside this service can flip
        either at any moment, and a cached negative would keep demanding
        a step that has already happened. Only the device verdict, which
        costs a PortAudio init, is cached.
        """
        if not HAS_TTS_DEPS and not reload_tts_deps():
            return False, _INSTALL_HINT

        if not is_kokoro_model_present():
            return False, _NO_MODEL_HINT

        if self._availability is not None:
            return self._availability

        try:
            devices = sd.query_devices()
            has_output = any(
                int(device.get('max_output_channels', 0)) > 0 for device in devices
            )
        except Exception as e:  # noqa: BLE001 — headless hosts raise OSError from PortAudio
            logger.debug("Audio output probe failed: %s", e)
            self._availability = (False, _NO_DEVICE_HINT)
            return self._availability

        self._availability = (True, "") if has_output else (False, _NO_DEVICE_HINT)
        return self._availability

    # ------------------------------------------------------------------
    # Speaking
    # ------------------------------------------------------------------

    def is_speaking(self) -> bool:
        """Whether anything is being synthesised, played, or queued."""
        with self._lock:
            return self._pending > 0

    def current_epoch(self) -> int:
        """Cancellation token for a :meth:`speak` scheduled on another thread.

        Snapshot this before handing a :meth:`speak`/:meth:`enqueue` call
        off to a thread pool and pass it as ``epoch``: a :meth:`stop`
        landing while the hand-off is still in flight bumps the epoch, so
        the utterance is dropped instead of playing after the stop that
        should have silenced it.
        """
        with self._lock:
            return self._epoch

    def speak(self, text: str, *, epoch: Optional[int] = None) -> None:
        """Synthesise *text* and play it, blocking until playback finishes.

        The text is reduced to prose via
        :func:`~servonaut.services.voice_text.speakable_text` first, so
        code blocks and tables are announced rather than read out; text
        with nothing speakable left is a silent no-op. Blocks for the
        whole synthesis and playback (and, on the first call, the model
        load) — run it in a worker thread, never on the Textual loop.

        Args:
            text: Reply text to read aloud, markdown and all.
            epoch: Cancellation token from :meth:`current_epoch`, captured
                before this call was scheduled. When a :meth:`stop` has
                landed since, the utterance is silently dropped. ``None``
                pins the epoch at entry instead.

        Raises:
            VoiceOutputError: If voice output is unavailable, or synthesis
                or playback fails. A :meth:`stop` that cancels this
                utterance is a normal return, not an error.
        """
        job = self._submit(text, check_available=True, epoch=epoch)
        if job is None:
            return
        job.done.wait()
        if job.error:
            raise VoiceOutputError(job.error)

    def enqueue(self, sentence: str, *, epoch: Optional[int] = None) -> None:
        """Queue *sentence* for playback without waiting for it.

        The streaming counterpart of :meth:`speak`: sentences play in
        order behind whatever is already queued. Never raises — failures
        are logged, because a fire-and-forget path has no caller left to
        catch them.

        Args:
            sentence: Text to read aloud after everything already queued.
            epoch: Cancellation token from :meth:`current_epoch`; see
                :meth:`speak`.
        """
        try:
            self._submit(sentence, check_available=True, epoch=epoch)
        except VoiceOutputError as e:
            logger.warning("Dropped a spoken sentence: %s", e)
        except Exception as e:  # noqa: BLE001 — fire-and-forget must not leak
            logger.warning("Dropped a spoken sentence: %s", e)

    def begin_utterance(
        self,
        *,
        on_complete: Optional[Callable[[bool], None]] = None,
        epoch: Optional[int] = None,
    ) -> UtteranceSession:
        """Open a streamed-utterance session for one reply's sentences.

        The streaming counterpart of one :meth:`speak` call: the caller
        enqueues sentences on the returned session as the stream
        completes them, then calls :meth:`UtteranceSession.end`. See
        :class:`UtteranceSession` for the exactly-once completion
        contract.

        Args:
            on_complete: Fired once with ``played_to_end`` when the
                session finishes or is superseded. Invoked from an
                internal thread — UI consumers must marshal.
            epoch: Cancellation token from :meth:`current_epoch`,
                captured before this call was scheduled; see
                :meth:`speak`. When a :meth:`stop` has landed since, the
                session is born superseded: the completion fires with
                ``False`` before this returns, and every enqueue on it
                is dropped. ``None`` pins the epoch at entry.

        Returns:
            The session. Never raises.
        """
        with self._lock:
            if epoch is None:
                epoch = self._epoch
            live = not self._closed and epoch == self._epoch
            session = UtteranceSession(self, epoch, on_complete)
            if live:
                self._sessions.append(session)
            else:
                retired = session._retire_locked()
        if not live and retired:
            session._fire_completion()
        return session

    def _submit(
        self,
        text: str,
        *,
        check_available: bool,
        epoch: Optional[int] = None,
        session: Optional[UtteranceSession] = None,
    ) -> Optional[_SpeechJob]:
        """Clean *text*, wrap it in a job and hand it to the worker.

        The cancellation epoch is pinned at entry (or taken from *epoch*,
        which the caller captured even earlier), NOT at enqueue time: the
        cleaning pass and the availability probe below take real time on
        a long reply, and a stop() landing inside that window must retire
        this utterance rather than race it into the queue.

        Returns:
            The queued job, or None when nothing speakable remained, the
            utterance was cancelled before it could be queued, or the
            service is closed.

        Raises:
            VoiceOutputError: If voice output is unavailable or the queue
                is full.
        """
        with self._lock:
            if self._closed:
                return None
            if epoch is None:
                epoch = self._epoch
            elif epoch != self._epoch:
                # Stopped after the caller captured the token but before
                # the call reached us: cancelled, not an error.
                return None

        spoken = speakable_text(text)
        if not spoken:
            return None

        if check_available:
            available, reason = self._probe()
            if not available:
                raise VoiceOutputError(reason)

        with self._lock:
            if self._closed or epoch != self._epoch:
                return None
        job = _SpeechJob(spoken, epoch, session)
        self._ensure_worker()
        with self._lock:
            self._pending += 1
            if session is not None:
                session._outstanding += 1
        try:
            self._queue.put_nowait(job)
        except queue.Full:
            # A full queue means playback is minutes behind already;
            # blocking the producer on top of that helps nobody.
            with self._lock:
                self._pending -= 1
                if session is not None:
                    session._outstanding -= 1
            raise VoiceOutputError("Speech queue is full") from None
        return job

    def stop(self) -> None:
        """Discard everything queued and stop playback promptly.

        Safe to call from any thread and never raises. Callers blocked in
        :meth:`speak` return normally — being stopped is an outcome the
        user asked for, not a failure to surface. Live utterance
        sessions are superseded: each fires its completion with
        ``played_to_end=False`` before this returns.
        """
        with self._lock:
            self._epoch += 1
            current_epoch = self._epoch
            # Every registered session is pinned to an older epoch now.
            # Claim their completions under the lock, fire them below —
            # a consumer callback must never run while the lock is held.
            superseded = [s for s in self._sessions if s._retire_locked()]
            self._sessions.clear()

        # Retire everything still queued. The worker skips any job it has
        # already taken once it notices the epoch moved. Jobs pinned to
        # the epoch this stop just created belong to a NEW utterance a
        # concurrent producer started while this drain was running — they
        # are not ours to discard, so they go back on the queue (order
        # among them is preserved; everything older is gone).
        requeue = []
        while True:
            try:
                job = self._queue.get_nowait()
            except queue.Empty:
                break
            if job is None or job.epoch == current_epoch:
                # The close() sentinel, or a fresh job: keep it.
                self._queue.task_done()
                requeue.append(job)
                continue
            with self._lock:
                self._pending -= 1
                if job.session is not None:
                    job.session._outstanding -= 1
            job.done.set()
            self._queue.task_done()
        for job in requeue:
            try:
                self._queue.put_nowait(job)
            except queue.Full:  # pragma: no cover — the drain just made room
                if job is not None:
                    with self._lock:
                        self._pending -= 1
                        if job.session is not None:
                            job.session._outstanding -= 1
                    job.done.set()

        # Same drain for the rendered-but-unplayed stage: sentences whose
        # PCM is waiting on the playback thread are just as much part of
        # the stopped utterance as ones still queued as text.
        pcm_requeue = []
        while True:
            try:
                item = self._pcm_queue.get_nowait()
            except queue.Empty:
                break
            if item is None or item[0].epoch == current_epoch:
                self._pcm_queue.task_done()
                pcm_requeue.append(item)
                continue
            self._retire_job(item[0])
            self._pcm_queue.task_done()
        for item in pcm_requeue:
            try:
                self._pcm_queue.put_nowait(item)
            except queue.Full:  # pragma: no cover — the drain just made room
                if item is not None:
                    self._retire_job(item[0])

        for session in superseded:
            session._fire_completion()

        stream = self._out_stream
        if stream is not None:
            try:
                # abort() drops the buffered audio instead of letting it
                # drain — this is what makes a stop feel immediate. The
                # playback thread notices the failed write (or the epoch)
                # and reopens a fresh stream for the next utterance.
                stream.abort()
            except Exception as e:  # noqa: BLE001 — teardown must never raise here
                logger.debug("Error aborting audio output stream: %s", e)

    def close(self) -> None:
        """Shut the service down for good: stop playback, end the worker.

        For when the service instance is being replaced (a settings save
        rebuilds it): :meth:`stop` alone leaves the worker thread blocked
        on the queue forever, pinning the instance — and the loaded
        synthesis engine — for the life of the process. Safe to call from
        any thread, idempotent, never raises. A closed service silently
        drops any :meth:`speak`/:meth:`enqueue` that still reaches it.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self.stop()
        try:
            # Wake the synthesis thread so it can observe the sentinel and
            # exit.
            self._queue.put_nowait(None)
        except queue.Full:  # pragma: no cover — stop() just drained the queue
            pass
        try:
            # And the playback thread — the synthesis thread also forwards
            # its sentinel, but it may be blocked handing PCM over and bail
            # out on the closed flag without ever reaching that hand-off.
            self._pcm_queue.put_nowait(None)
        except queue.Full:  # pragma: no cover — stop() just drained the queue
            pass
        # Drop the engine reference so its weights can be reclaimed once
        # the worker threads let go of this instance.
        self._tts = None

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------

    def _ensure_worker(self) -> None:
        """Start the synthesis and playback threads if not already running."""
        with self._lock:
            if self._closed:
                return
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(
                    target=self._worker_loop,
                    name="voice-tts-synth",
                    daemon=True,
                )
                self._worker.start()
            if self._playback is None or not self._playback.is_alive():
                self._playback = threading.Thread(
                    target=self._playback_loop,
                    name="voice-tts-playback",
                    daemon=True,
                )
                self._playback.start()

    def _retire_job(self, job: _SpeechJob) -> None:
        """Settle one job: it has left the pipeline, played or not.

        The single place the pending counter, the ``done`` event a
        blocked :meth:`speak` waits on, and the session accounting are
        released — called by whichever stage drops the job.
        """
        with self._lock:
            self._pending -= 1
        job.done.set()
        if job.session is not None:
            job.session._job_finished()

    def _worker_loop(self) -> None:
        """Synthesis thread: render queued text into PCM. Exits on close()."""
        while True:
            with self._lock:
                if self._closed:
                    return
            job = self._queue.get()
            if job is None:
                # close() sentinel: forward it so the playback thread —
                # and with it the last reference to this instance — goes
                # too, then let this thread exit.
                self._queue.task_done()
                self._forward_sentinel()
                return
            rendered: Optional[Tuple[Any, int]] = None
            try:
                with self._lock:
                    cancelled = job.epoch != self._epoch
                if not cancelled:
                    rendered = self._synthesize_job(job)
            except VoiceOutputError as e:
                job.error = str(e)
                logger.error("Spoken reply failed: %s", e)
            except Exception as e:  # noqa: BLE001 — the worker must survive any backend surprise
                job.error = f"Speech synthesis failed: {e}"
                logger.error("Spoken reply failed unexpectedly: %s", e)
            self._queue.task_done()
            if rendered is None:
                # Cancelled, errored, or nothing audible: the job ends here.
                self._retire_job(job)
                continue
            self._hand_to_playback(job, rendered)

    def _synthesize_job(self, job: _SpeechJob) -> Optional[Tuple[Any, int]]:
        """Render one utterance to PCM. Runs on the synthesis thread.

        Returns:
            ``(samples, sample_rate)``, or None when the job was cancelled
            mid-synthesis or produced no audio.
        """
        tts = self._get_engine()
        sid = kokoro_voice_sid(
            getattr(self._config, "tts_voice", DEFAULT_TTS_VOICE)
        )
        speed = self._speed()

        def _keep_generating(_samples: Any, _progress: float) -> int:
            # Consulted by the engine between chunks: 1 continues, 0 stops.
            # This is what lets stop() cancel mid-synthesis rather than
            # after the whole sentence has been rendered.
            with self._lock:
                return 0 if job.epoch != self._epoch else 1

        try:
            audio = tts.generate(
                job.text, sid=sid, speed=speed, callback=_keep_generating
            )
        except Exception as e:  # noqa: BLE001 — onnxruntime raises its own types
            raise VoiceOutputError(f"Speech synthesis failed: {e}") from e

        with self._lock:
            if job.epoch != self._epoch:
                return None

        samples = getattr(audio, "samples", None)
        sample_rate = int(getattr(audio, "sample_rate", 0) or 0)
        if samples is None or len(samples) == 0 or sample_rate <= 0:
            logger.debug("Synthesis produced no audio for %d chars", len(job.text))
            return None
        return samples, sample_rate

    def _hand_to_playback(self, job: _SpeechJob, rendered: Tuple[Any, int]) -> None:
        """Move rendered PCM to the playback stage, honouring cancellation.

        The PCM queue is deliberately shallow, so this blocks when
        synthesis runs ahead — in short waits, re-checking on each one,
        because a stop() or close() landing while blocked must retire the
        job instead of leaving this thread wedged on a full queue.
        """
        samples, sample_rate = rendered
        while True:
            with self._lock:
                if self._closed or job.epoch != self._epoch:
                    self._retire_job(job)
                    return
            try:
                self._pcm_queue.put((job, samples, sample_rate), timeout=0.2)
                return
            except queue.Full:
                continue

    def _forward_sentinel(self) -> None:
        """Pass the close() sentinel on to the playback thread."""
        try:
            self._pcm_queue.put_nowait(None)
        except queue.Full:  # pragma: no cover — close() already drained
            pass

    def _playback_loop(self) -> None:
        """Playback thread: write rendered PCM to the device. Exits on close().

        Keeps the output stream open between sentences — opening the
        device per sentence added an audible gap on every boundary — and
        closes it after a short idle so the device is not held while
        nothing is being said.
        """
        while True:
            timeout = _STREAM_IDLE_CLOSE_SECONDS if self._out_stream is not None else None
            try:
                item = self._pcm_queue.get(timeout=timeout)
            except queue.Empty:
                # Idle with an open device: release it and go back to a
                # plain blocking wait.
                self._drop_stream()
                continue
            if item is None:
                # close() sentinel: retire anything that slipped in behind
                # it so no speak() is left blocked, release the device, go.
                self._pcm_queue.task_done()
                self._drain_pcm_retiring()
                self._drop_stream()
                return
            job, samples, sample_rate = item
            try:
                with self._lock:
                    cancelled = self._closed or job.epoch != self._epoch
                if not cancelled:
                    self._play(samples, sample_rate, job.epoch)
            except VoiceOutputError as e:
                job.error = str(e)
                logger.error("Spoken reply failed: %s", e)
            except Exception as e:  # noqa: BLE001 — the thread must survive any backend surprise
                job.error = f"Audio playback failed: {e}"
                logger.error("Spoken reply failed unexpectedly: %s", e)
            finally:
                self._pcm_queue.task_done()
                self._retire_job(job)

    def _drain_pcm_retiring(self) -> None:
        """Retire every rendered sentence still queued. Close-path only."""
        while True:
            try:
                item = self._pcm_queue.get_nowait()
            except queue.Empty:
                return
            self._pcm_queue.task_done()
            if item is not None:
                self._retire_job(item[0])

    def _speed(self) -> float:
        """Playback rate from config, defensively clamped.

        The schema clamps on load, but the service must not trust that a
        hot-swapped config object went through it.
        """
        try:
            speed = float(getattr(self._config, "tts_speed", 1.0))
        except (TypeError, ValueError):
            return 1.0
        if not math.isfinite(speed):
            # NaN sails through min/max (every comparison is False) and
            # would reach the engine as speed=nan.
            return 1.0
        return min(max(speed, TTS_SPEED_MIN), TTS_SPEED_MAX)

    def _play(self, samples: Any, sample_rate: int, epoch: int) -> None:
        """Play mono float32 samples through the configured output device.

        Runs on the playback thread. The stream persists across calls
        (see :meth:`_playback_loop`); any write failure — including the
        abort() a :meth:`stop` issues — drops it so the next sentence
        opens fresh.
        """
        buffer = np.asarray(samples, dtype='float32').reshape(-1)
        chunk = max(1, int(sample_rate * _PLAYBACK_CHUNK_SECONDS))

        stream = self._ensure_stream(sample_rate)
        try:
            for start in range(0, len(buffer), chunk):
                with self._lock:
                    if epoch != self._epoch:
                        break
                stream.write(buffer[start:start + chunk])
        except Exception as e:  # noqa: BLE001 — an abort() from stop() surfaces here
            with self._lock:
                cancelled = epoch != self._epoch
            # The stream's state is unknown after a failed write (aborted,
            # device gone, …) — never reuse it.
            self._drop_stream()
            if not cancelled:
                logger.error("Audio playback failed: %s", e)
                raise VoiceOutputError(f"Audio playback failed: {e}") from e

    def _ensure_stream(self, sample_rate: int) -> Any:
        """Return an open, started output stream for *sample_rate*.

        Reuses the persistent stream when the rate matches; otherwise
        (first sentence, rate change, or a previous drop) opens a new one.

        Raises:
            VoiceOutputError: If the device cannot be opened or started.
        """
        if self._out_stream is not None:
            if self._out_stream_rate == sample_rate:
                return self._out_stream
            self._drop_stream()

        try:
            stream = sd.OutputStream(
                samplerate=sample_rate,
                channels=1,
                dtype='float32',
                device=self._config.output_device or None,
            )
        except Exception as e:  # noqa: BLE001 — PortAudio raises its own hierarchy
            logger.error("Failed to open audio output stream: %s", e)
            raise VoiceOutputError(f"Could not open the audio output: {e}") from e

        try:
            stream.start()
        except Exception as e:  # noqa: BLE001 — PortAudio raises its own hierarchy
            # The constructor already opened the device, and stop() can
            # never reach an unstarted stream — close it here or the
            # handle leaks until garbage collection.
            try:
                stream.close()
            except Exception:  # noqa: BLE001 — best-effort cleanup
                logger.debug(
                    "Could not close a stream that failed to start",
                    exc_info=True,
                )
            logger.error("Failed to start audio output stream: %s", e)
            raise VoiceOutputError(f"Could not open the audio output: {e}") from e

        self._out_stream = stream
        self._out_stream_rate = sample_rate
        return stream

    def _drop_stream(self) -> None:
        """Close and forget the persistent output stream. Never raises."""
        stream = self._out_stream
        self._out_stream = None
        self._out_stream_rate = 0
        if stream is None:
            return
        try:
            stream.stop()
            stream.close()
        except Exception as e:  # noqa: BLE001 — teardown must not mask the outcome
            logger.debug("Error while closing audio output stream: %s", e)

    # ------------------------------------------------------------------
    # Engine
    # ------------------------------------------------------------------

    def _get_engine(self) -> Any:
        """Load the synthesis engine, caching it on the instance.

        Deferred until the first utterance: constructing the engine reads
        the full on-disk model (``KOKORO_DISK_BYTES``, ~181 MB of weights
        and voice data), and app startup must stay instant for users who
        never enable spoken replies.

        Raises:
            VoiceOutputError: If the engine cannot be loaded.
        """
        if self._tts is not None:
            return self._tts

        if not HAS_TTS_DEPS and not reload_tts_deps():
            raise VoiceOutputError(_INSTALL_HINT)
        if not is_kokoro_model_present():
            raise VoiceOutputError(_NO_MODEL_HINT)

        model_dir = kokoro_model_dir()
        lexicon = ",".join(str(model_dir / name) for name in KOKORO_LEXICON_FILES)
        try:
            kokoro_config = sherpa_onnx.OfflineTtsKokoroModelConfig(
                model=str(model_dir / KOKORO_MODEL_FILE),
                voices=str(model_dir / KOKORO_VOICES_FILE),
                tokens=str(model_dir / KOKORO_TOKENS_FILE),
                lexicon=lexicon,
                data_dir=str(model_dir / KOKORO_ESPEAK_DIR),
            )
            model_config = sherpa_onnx.OfflineTtsModelConfig(
                kokoro=kokoro_config,
                # Measured on a 16-core desktop: 4 is where synthesis
                # stops improving (memory-bound past that), and it is
                # meaningfully faster than 2. Synthesis speed directly
                # bounds the pause between spoken sentences, so this is
                # a latency knob, not a throughput one.
                num_threads=4,
                provider="cpu",
            )
            self._tts = sherpa_onnx.OfflineTts(
                sherpa_onnx.OfflineTtsConfig(model=model_config)
            )
        except Exception as e:  # noqa: BLE001 — engine load failures vary by backend
            self._tts = None
            logger.error("Failed to load the speech model: %s", e)
            raise VoiceOutputError(f"Could not load the speech model: {e}") from e

        logger.info("Loaded speech synthesis model from %s", model_dir)
        return self._tts
