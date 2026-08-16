"""Chat panel widget mounted as a sidebar on the active screen.

Wave-3 additions (T5/T6/T8/T10):

- Servonaut-AI streaming routing via :meth:`_do_send_servonaut`. Routes
  user prompts through ``app.servonaut_provider.stream_chat`` when the
  active provider (per :class:`ProviderPreferenceResolver`) is
  ``"servonaut"``; falls back to the existing chat-service path for
  user-keyed providers (OpenAI / Anthropic / Ollama / Gemini).

- Quota footer + provider header indicator. The footer reads from
  ``app.auth_service`` cached :class:`AIQuota`; the header indicator
  shows S/O/A/G/L for the active provider.

- T5 error matrix routing through
  :func:`ai_error_handler.map_error_to_action`: each error code drives
  a deterministic toast / modal / banner UX action.

- T6 tool-bridge driver: stream events of type ``tool_call`` are dispatched
  through ``app.ai_tool_bridge``, with confirm modals (single-y/n
  for ``standard``; typed-RUN for ``dangerous``) sized by guard level.

- T8 top-up flow: ``MODAL_QUOTA_EXHAUSTED`` and
  ``MODAL_BUDGET_EXHAUSTED`` actions push :class:`AITopUpModal`; on a
  pack pick we call ``ServonautProvider.topup_checkout``, open the URL
  via :func:`webbrowser.open`, then schedule
  ``auth.schedule_post_topup_refresh()``.

- T10 second-upstream-unavailable watcher tracks the timestamps of
  ``upstream_unavailable`` errors; on the second hit within 60s we
  either auto-fall-back (when ``ai.local_fallback_provider`` is set)
  or push :class:`AIFallbackPromptModal`.

The Wave-2 ``_do_send`` path remains as the entry point — it dispatches
to ``_do_send_servonaut`` only when the resolver picks Servonaut.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import webbrowser
from typing import Any, Dict, List, Optional, Tuple

from rich.markup import escape as _rich_escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.widget import Widget
from textual.widgets import Button, Input, Label, Static, TextArea

# D6 — module-level ``logger`` placed AFTER all imports so static analysers
# can verify import ordering and lint rules don't flag the gap.
logger = logging.getLogger(__name__)


# Minimal AI Logo (Matches Website)
SERVONAUT_LOGO = (
    "[bold bright_cyan]🖧[/]  [bold]Servonaut AI Assistant[/]\n"
    "   [bold bright_green]●[/] [dim bright_green]MCP Server Online[/]"
)

# Inline bot marker for assistant messages
BOT_MARKER = "[bold bright_cyan]\u25c9[/]"

# T10 watcher: the second ``upstream_unavailable`` within this window
# triggers either an auto-fallback (when ``ai.local_fallback_provider``
# is set) or the :class:`AIFallbackPromptModal`. Per architect plan
# \u00a7T10 invariants.
_UPSTREAM_FAILURE_WINDOW_S = 60.0

# Single-character provider indicator (Risk register \u00a79). Mirrors
# Servonaut/OpenAI/Anthropic/Gemini/oLlama. Unknown providers render '?'.
# Per-session provider indicator — shown on the header button users
# click to change provider for this chat only. The leading ▾ is a
# safe geometric glyph (U+25BE, no VS16 variant) signalling "click
# to pick"; full names beat the old S/O/A/G/L letters for
# discoverability without overflowing the 12-char button min-width.
_PROVIDER_INDICATORS = {
    "servonaut": "▾ Servonaut",
    "openai":    "▾ OpenAI",
    "anthropic": "▾ Anthropic",
    "gemini":    "▾ Gemini",
    "ollama":    "▾ Ollama",
}
_PROVIDER_INDICATOR_DEFAULT = "▾ Provider"

# Mic button labels. Plain ASCII only — emoji carrying the U+FE0F
# variation selector (the microphone glyph is one) corrupt row rendering
# in several terminals.
# Microphone affordance glyphs. U+1F3A4 is emoji-presentation by default,
# so it needs no VS16 variant selector — the selector is what corrupts row
# rendering in some terminals, so it must never be appended here.
_MIC_IDLE = "\U0001F3A4"
_MIC_RECORDING = "⏹"

# Braille spinner shown on the mic button and in the stats bar while the
# model decodes. Transcription is several seconds of silence otherwise, and
# a frozen button reads as a hang.
_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_SPINNER_INTERVAL = 0.1

# Speaking indicator glyph for the stats bar. U+1F50A is emoji-presentation
# by default, so — exactly like the microphone above — it must never carry
# a VS16 variant selector, which corrupts row rendering in some terminals.
_SPEAKER_ACTIVE = "\U0001F50A"

# Conversation-mode affordance glyphs. The headphone (U+1F3A7) is
# emoji-presentation by default like the microphone and speaker above, so
# it needs — and must never be given — a VS16 variant selector. The state
# glyphs are plain text-presentation characters for the same reason.
_CONVO_IDLE = "\U0001F3A7"
_CONVO_STATE_GLYPHS = {
    "listening": "◉",  # ◉ fisheye — the mic is hot
    "thinking": "◌",   # ◌ dotted circle — a turn is in flight
    "speaking": "♪",   # ♪ eighth note — the reply is playing
}

# Key the conversation toggle is bound to. Named in user-facing copy, so
# one definition keeps the binding and every hint in lockstep.
_CONVO_TOGGLE_KEY = "ctrl+n"


def conversation_button_label(state: str) -> str:
    """The glyph the conversation button should show for *state*.

    Pure so the glyph mapping (and its no-VS16 guarantee) is testable
    without a mounted panel. Unknown states render the idle glyph — a
    wrong label beats a crashed repaint.
    """
    return _CONVO_STATE_GLYPHS.get(state, _CONVO_IDLE)


def conversation_status_markup(state: str) -> str:
    """Stats-bar fragment describing the conversation loop's state.

    Pure for the same reason as :func:`resolve_spoken_reply`: the wording
    per state is a decision worth pinning without widgets. Returns an
    empty string when the loop is idle so the caller can skip the slot.
    Every fragment names the key that leaves the state — an affordance
    nobody can discover is not one.
    """
    glyph = _CONVO_STATE_GLYPHS.get(state, "")
    if state == "listening":
        return f"[green]{glyph} Listening — {_CONVO_TOGGLE_KEY} stops[/green]"
    if state == "thinking":
        return f"[yellow]{glyph} Conversation — waiting for the reply[/yellow]"
    if state == "speaking":
        return (
            f"[cyan]{glyph} Conversation — speaking, "
            f"{_CONVO_TOGGLE_KEY} interrupts[/cyan]"
        )
    return ""


def resolve_conversation_start(
    *,
    voice_enabled: bool,
    input_available: bool,
    input_reason: str = "",
    stt_model_ok: bool = True,
    vad_model_ok: bool = False,
    output_available: bool = False,
    output_reason: str = "",
    tts_enabled: bool = True,
) -> str:
    """Decide whether the hands-free loop may start, or say what is missing.

    Pure: the caller resolves every probe (they block, so they run on a
    worker) and this function only orders the verdicts into the one
    user-fit message worth showing. Returns an empty string when the loop
    may start. The checks are ordered by setup order — capture before
    detection before playback — so the message always names the FIRST
    unmet requirement, mirroring the Settings readiness card.

    With ``tts_enabled`` False the playback checks are skipped entirely:
    replies are never spoken (``resolve_spoken_reply`` gates on the same
    flag), so demanding the synthesis packages and model would force a
    ~126 MB download the session will never use. The loop then runs as a
    hands-free dictation cycle — listen, send, listen.
    """
    if not voice_enabled:
        return (
            "Voice input is switched off — enable it in "
            "Settings > Voice Input first."
        )
    if not input_available:
        reason = input_reason or "Voice input is unavailable"
        return f"{reason} — see Settings > Voice Input."
    if not stt_model_ok:
        return (
            "The speech model is not downloaded yet — "
            "download it in Settings > Voice Input."
        )
    if not vad_model_ok:
        return (
            "The voice-detection model is not downloaded yet — "
            "download it in Settings > Voice Input."
        )
    if tts_enabled and not output_available:
        reason = output_reason or "Speech output is unavailable"
        return f"{reason} — see Settings > Voice Input."
    return ""


def resolve_transcript_action(
    text: Optional[str],
    *,
    modal_blocking: bool,
    thinking: bool,
) -> str:
    """Decide what to do with a conversation-mode transcript.

    Pure so the safety matrix is testable without widgets. Returns one of:

    - ``"drop_empty"``: nothing worth sending; resume listening silently.
    - ``"drop_modal"``: a modal (any confirmation included) is on the
      screen stack. The utterance is dropped, never queued — a transcript
      must not be delivered anywhere near a confirmation flow.
    - ``"drop_busy"``: a chat turn is already streaming; the in-flight
      turn keeps driving the loop, the utterance is dropped.
    - ``"send"``: deliver through the ordinary send path.
    """
    if not text or not text.strip():
        return "drop_empty"
    if modal_blocking:
        return "drop_modal"
    if thinking:
        return "drop_busy"
    return "send"


def is_modal_blocking(screen_stack: Any) -> bool:
    """Whether any modal screen sits on *screen_stack*.

    The generic predicate for "a blocking interaction is up": every
    confirmation surface in the app subclasses ``ModalScreen``, so the
    isinstance check covers all present and future confirms without an
    allowlist that could silently miss a new one. Kept pure (the caller
    passes the stack) so tests can drive it with fake stacks.
    """
    from textual.screen import ModalScreen

    try:
        return any(isinstance(screen, ModalScreen) for screen in screen_stack)
    except Exception:  # noqa: BLE001 — an unreadable stack must fail SAFE
        logger.debug("could not inspect the screen stack", exc_info=True)
        return True


def _stop_orphaned_conversation(service: Any, *, timeout: float = 10.0) -> None:
    """Stop a conversation loop whose start worker was cancelled mid-start.

    Runs on a plain daemon thread. ``service.start()`` keeps running on
    its executor thread after the awaiting worker is cancelled, so the
    orphan may not have reached LISTENING yet — a stop issued too early
    would no-op and the mic would still open afterwards. Poll briefly for
    the start to land (or for the start to have failed, leaving IDLE for
    good), then stop. ``stop()`` is documented never to raise and to
    no-op when idle, so the worst outcome of the timeout path is exactly
    today's behaviour: the idle timeout closes the mic.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            state = getattr(service, "state", None)
        except Exception:  # noqa: BLE001 — a probe fault must not kill the abort
            break
        if getattr(state, "value", state) != "idle":
            break
        time.sleep(0.1)
    try:
        service.stop()
    except Exception:  # noqa: BLE001 — stop() is documented never to raise
        logger.debug("orphaned conversation stop failed", exc_info=True)


def resolve_spoken_reply(
    text: Optional[str],
    *,
    tts_enabled: bool,
    demo_mode: bool = False,
    scrub: Optional[Any] = None,
) -> str:
    """Decide what, if anything, of a finished reply should be spoken.

    Pure so the decision matrix is testable without a mounted panel: no
    widget access, no service probing — availability is the speaking
    worker's concern, this is only about the text.

    Args:
        text: The final assistant message, markdown and all.
        tts_enabled: The ``voice.tts_enabled`` config flag.
        demo_mode: Whether demo-mode redaction is active. Spoken audio is
            an output surface like the screen: an address read aloud
            survives into a recording just as surely as one rendered.
        scrub: The redactor's ``scrub_stream`` callable, when one exists.

    Returns:
        The text to hand to the voice output service, or an empty string
        when nothing should be spoken. Error placeholders (``Error: …``)
        and the parenthetical fallback bubbles (``(no response)``,
        ``(model ran N tools …)``) are never spoken — they are UI
        furniture, not prose. In demo mode a missing or failing redactor
        fails closed: no scrub, no speech.
    """
    if not tts_enabled or not text:
        return ""
    stripped = text.strip()
    if not stripped or stripped.startswith("Error:"):
        return ""
    if stripped.startswith("(") and stripped.endswith(")"):
        return ""
    if demo_mode:
        if not callable(scrub):
            return ""
        try:
            scrubbed = scrub(stripped)
        except Exception:  # noqa: BLE001 — fail closed rather than leak audio
            logger.debug("demo-mode scrub failed before speech", exc_info=True)
            return ""
        if not isinstance(scrubbed, str):
            return ""
        stripped = scrubbed.strip()
    return stripped


def resolve_spoken_sentence(
    sentence: str,
    *,
    demo_mode: bool = False,
    scrub: Optional[Any] = None,
) -> str:
    """Gate one mid-stream sentence before it is enqueued for speech.

    The streaming sibling of :func:`resolve_spoken_reply`, minus the
    checks that only make sense on a finished message: ``tts_enabled``
    was already checked when streaming speech was armed for the turn,
    and the error/placeholder-bubble filters do not apply — token text
    is by definition prose, and error paths silence the whole session
    instead. What every emitted sentence still needs is the demo-mode
    scrub: spoken audio survives into a recording just as surely as a
    rendered address, and a missing or failing redactor fails CLOSED.

    Returns:
        The text to enqueue, or an empty string to skip the sentence.
    """
    if not sentence or not sentence.strip():
        return ""
    stripped = sentence.strip()
    if demo_mode:
        if not callable(scrub):
            return ""
        try:
            scrubbed = scrub(stripped)
        except Exception:  # noqa: BLE001 — fail closed rather than leak audio
            logger.debug("demo-mode scrub failed before speech", exc_info=True)
            return ""
        if not isinstance(scrubbed, str):
            return ""
        stripped = scrubbed.strip()
    return stripped

# Cap on the speech-to-text vocabulary hint. Whisper-family models treat
# the initial prompt as leading context and degrade once it dominates the
# window, so the fleet's server names are truncated at whole-name
# boundaries rather than padded to the limit.
_VOICE_PROMPT_MAX_CHARS = 200


class ChatPanel(Widget):
    """Right-docked sidebar for chatting with the Servonaut DevOps assistant."""

    BINDINGS = [
        # priority=True so this wins over TextArea's own Enter binding
        # (which inserts a newline before the event ever bubbles up).
        # check_action() scopes it to the chat input, so Enter on the
        # panel's buttons still activates them normally.
        Binding("enter", "send_from_input", "Send", show=False, priority=True),
        # A terminal delivers key presses only — there is no key-up event,
        # so this toggles capture rather than holding it. ctrl+t is free
        # across the app and is not printable, so it survives TextArea's
        # key capture while the chat input has focus.
        Binding("ctrl+t", "toggle_mic", "Voice", show=False, priority=True),
        # Interrupts a spoken reply. Chosen for the same reasons as ctrl+t:
        # unused elsewhere in the app, not printable (survives TextArea's
        # key capture with priority=True), and free of terminal-level
        # meaning — unlike ctrl+b (tmux prefix) or ctrl+q (XON). A no-op
        # when nothing is being spoken.
        Binding("ctrl+o", "stop_speaking", "Stop speech", show=False, priority=True),
        # Hands-free conversation toggle. ctrl+n is free across the app
        # and is NOT bound by TextArea (unlike ctrl+k/u/w/d/f/y/z, which
        # are its editing keys), so priority=True cannot shadow an edit
        # while the chat input has focus. ctrl+shift chords were rejected:
        # legacy terminals cannot report them and several emulators eat
        # ctrl+shift+t for their own tab handling. Keep the key in
        # _CONVO_TOGGLE_KEY so the stats-bar hints stay truthful.
        Binding(
            _CONVO_TOGGLE_KEY, "toggle_conversation", "Conversation",
            show=False, priority=True,
        ),
        # Escape interrupts a spoken conversation reply. Gated hard by
        # check_action to conversation-SPEAKING only, so everywhere else
        # the key falls through untouched to whatever screen binding owns
        # it (closing modals, popping screens).
        Binding(
            "escape", "convo_interrupt", "Interrupt reply",
            show=False, priority=True,
        ),
    ]

    # Debounce: stale_modules results cached 2 seconds per (instance_id, provider) key.
    _STALE_CACHE_TTL = 2.0

    # Voice capture flags. ``_recording`` gates the mic toggle;
    # ``_transcribing`` keeps the button disabled while the blocking
    # speech-to-text call runs on a worker thread; ``_starting`` covers the
    # equally blocking device-open worker, which a key binding could
    # otherwise re-enter before the capture is live. ``_mic_unavailable``
    # remembers a failed availability probe so the button is not silently
    # re-enabled by an unrelated repaint. Class-level defaults so the stats
    # bar stays renderable on a panel built without ``__init__``.
    _recording: bool = False
    _transcribing: bool = False
    _starting: bool = False
    _mic_unavailable: bool = False
    # Spinner animation state for the transcription wait. The timer handle is
    # class-defaulted to None so ``_stop_spinner`` is safe on a panel that
    # never started one.
    _spinner_timer: Optional[Any] = None
    _spinner_frame: int = 0
    # Spoken-reply state. ``_speaking`` drives the stats-bar indicator;
    # ``_speak_seq`` lets a superseded speak worker tell that a newer one
    # owns the flag, so its teardown cannot wipe an indicator that the
    # replacement utterance just lit. Class-level defaults so the stats
    # bar stays renderable on a panel built without ``__init__``.
    _speaking: bool = False
    _speak_seq: int = 0
    # Streaming-speech state for the Servonaut SSE path, armed per turn.
    # ``_turn_chunker`` accumulates token deltas into sentences;
    # ``_turn_speech_session`` is the output service's utterance session
    # once the first sentence started it; ``_turn_speech_suppressed``
    # remembers a failed availability probe so a turn does not re-probe
    # on every sentence. Class-level defaults so the decision helpers
    # are safe on a panel built without ``__init__``.
    _turn_chunker: Optional[Any] = None
    _turn_speech_session: Optional[Any] = None
    _turn_speech_suppressed: bool = False
    # Conversation-mode state. ``_conversation_active`` is the session
    # opt-in (the toggle key or the config default flipped it on);
    # ``_conversation_state`` mirrors the loop's state machine as a plain
    # string so the stats bar can render it. Class-level defaults so the
    # stats bar stays renderable on a panel built without ``__init__``.
    _conversation_active: bool = False
    _conversation_state: str = "idle"
    # Text already in the input box when a streaming dictation started.
    # Partials replace each other, so they are rendered after this prefix
    # rather than on top of whatever the user had typed.
    _partial_prefix: str = ""

    def __init__(self, **kwargs) -> None:
        super().__init__(id="chat-panel", **kwargs)
        self._session = None  # type: Optional[object]
        self._thinking = False
        self._total_tokens = 0
        self._total_cost = 0.0
        self._model = ""
        # Cache for stale module lookups: key → (timestamp, result)
        self._stale_cache: Dict[tuple, tuple] = {}

        # Wave-3 (T10) — upstream-unavailable watcher state. Stores
        # monotonic timestamps of every ``upstream_unavailable`` event;
        # pruned to the trailing 60s window on every check.
        self._upstream_failures: List[float] = []
        # Session-only provider override (T10 fallback prompt result).
        # NOT persisted — does not mutate ``ai.provider_preference``.
        self._session_provider_override: Optional[str] = None
        # Last seen quota / fallback flags from a usage event (rendered
        # in the chat-stats line).
        self._last_fallback_used: bool = False
        self._last_soft_capped: bool = False
        # Per-turn counter — incremented for every ``tool_call`` SSE
        # event the server emits during the current turn. Used by
        # :meth:`_finalise_servonaut_turn` to write a more informative
        # fallback when ``accumulated`` is empty (model emitted only
        # tool calls and the server's continuation never produced
        # follow-up text).
        self._turn_tool_calls: int = 0
        self._last_hard_capped: bool = False
        # Track which conversation we're streaming for (Servonaut path).
        self._remote_conversation_id: Optional[str] = None
        # B1 — pinned-error state. When the provider resolver decides
        # there's no usable provider (lapsed sub + nothing else
        # configured), we disable the input and render a banner with
        # /Resubscribe/ + /Add a provider/ buttons. Cleared the moment
        # the resolver returns a healthy provider again.
        self._pinned_error_active: bool = False
        # B2 — one-shot modal push state per session. Once we've shown
        # the first-run / empty-state modal we don't reshow it on
        # subsequent ``_check_provider_decision_events`` calls.
        self._first_run_modal_shown: bool = False
        self._empty_state_modal_shown: bool = False

    def compose(self) -> ComposeResult:
        with Vertical(id="chat-inner"):
            # Header with logo and controls
            with Vertical(id="chat-header"):
                yield Static(SERVONAUT_LOGO, id="chat-logo")
                with Horizontal(id="chat-controls"):
                    yield Button("New Chat", id="btn-chat-new", classes="chat-btn")
                    yield Button("History", id="btn-chat-history", classes="chat-btn")
                    # Per-session provider indicator (S/O/A/G/L). Click
                    # to open the picker and override for this session
                    # only — does NOT mutate ai.provider_preference.
                    yield Button(
                        _PROVIDER_INDICATOR_DEFAULT,
                        id="btn-chat-provider",
                        classes="chat-btn",
                    )
                    yield Button("Close", id="btn-chat-close", classes="chat-btn error")
            # Session history list (hidden by default)
            with VerticalScroll(id="chat-history-list", classes="hidden"):
                yield Static("[dim]No saved chats[/dim]", id="chat-history-empty")
            # Stale-memory banner (hidden until staleness detected)
            yield Static("", id="chat-memory-banner", classes="hidden")
            # T4.5 / T10 banner (paying-twice / capability / upstream flaky).
            # Hidden until the resolver / watcher emits a banner event.
            yield Static("", id="chat-banner", classes="hidden")
            # B1 — pinned-error banner: shown when the resolver can't pick
            # a usable provider (lapsed sub + nothing else configured).
            # Two buttons inside a Horizontal so users can resubscribe or
            # open Settings without leaving the chat panel. Hidden until
            # PINNED_ERROR_NO_PROVIDER fires.
            with Horizontal(id="chat-pinned-error-banner", classes="hidden"):
                yield Static(
                    "[red]Servonaut AI subscription ended and no other "
                    "provider is configured.[/red]\n"
                    "Resubscribe or add an OpenAI / Anthropic / Gemini / "
                    "Ollama provider to keep chatting.",
                    id="chat-pinned-error-text",
                )
                yield Button(
                    "Resubscribe",
                    id="btn-pinned-resubscribe",
                    variant="primary",
                )
                yield Button(
                    "Add a provider",
                    id="btn-pinned-add-provider",
                )
            # Message area
            yield VerticalScroll(id="chat-messages")
            # Stats bar
            yield Static("", id="chat-stats")
            # Quota footer (T3) — Servonaut-only; hidden for user-keyed providers.
            yield Static("", id="chat-quota-footer", classes="hidden")
            # Input row
            with Horizontal(id="chat-input-row"):
                yield TextArea("", id="chat-input", soft_wrap=True, tab_behavior="focus")
                yield Button(
                    _MIC_IDLE, id="btn-chat-mic",
                    tooltip="Voice input (ctrl+t)",
                )
                yield Button(
                    _CONVO_IDLE, id="btn-chat-convo",
                    tooltip=f"Hands-free conversation ({_CONVO_TOGGLE_KEY})",
                )
                yield Button(
                    "➤", id="btn-chat-send", variant="primary",
                    tooltip="Send message (enter)",
                )

    def on_mount(self) -> None:
        """Load or create a chat session when mounted."""
        self._start_or_resume_session()
        self._update_stats()
        self._update_memory_banner()
        # Wave-3: render banners (paying-twice / capability) and update
        # provider indicator once the panel is composed.
        self._check_provider_decision_events()
        self._update_provider_indicator()
        self._update_quota_footer()
        self._sync_mic_affordance()
        self._maybe_autostart_conversation()

    def on_unmount(self) -> None:
        """Drop a live capture so closing the panel can't leave the mic open."""
        # Unconditional: a panel closed while the model was still decoding
        # has no capture to cancel but does have a timer to stop — and a
        # reply still being read aloud must not outlive the panel either.
        self._stop_spinner()
        # The conversation loop first: it owns capture AND playback, and a
        # panel that closes mid-conversation must not leave either running.
        self._teardown_conversation()
        self._interrupt_speech()
        if not self._recording and not self._starting:
            return
        self._recording = False
        self._transcribing = False
        self._starting = False
        try:
            service = getattr(self.app, "voice_input_service", None)
        except Exception:  # noqa: BLE001 — no active app during teardown
            return
        if service is not None:
            service.cancel_recording()

    def close_panel(self) -> None:
        """Hide the panel, then remove it. The only sanctioned close path.

        Removal is asynchronous, and a repaint that reaches the input
        TextArea while its styles are being detached crashes deep in the
        framework (KeyError on the widget's component classes). Voice
        makes that window easy to hit: dictation partials and
        conversation-state updates arrive from worker threads and can
        land mid-removal. Hiding first takes the whole subtree out of
        the render set, so a late write updates state harmlessly instead
        of scheduling the fatal repaint.
        """
        self.display = False
        self.remove()

    def focus_input(self) -> None:
        """Focus the chat input field."""
        self.call_after_refresh(self._do_focus_input)

    def _do_focus_input(self) -> None:
        try:
            self.query_one("#chat-input", TextArea).focus()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Focus failed on chat input", exc_info=True)
        self._update_memory_banner()

    # ------------------------------------------------------------------
    # Memory banner + instance resolution
    # ------------------------------------------------------------------

    def _parse_at_prefix(self, text: str) -> Tuple[Optional[dict], str]:
        """Extract an ``@<id-or-name>`` prefix from *text*.

        If the first whitespace-delimited token starts with ``@``, the token
        (without the ``@``) is looked up via ``self.app.resolve_instance``.
        The prefix is stripped from the returned text only when a match is
        found.

        Args:
            text: Raw input string from the chat input field.

        Returns:
            Tuple of (instance_dict_or_None, effective_text).
        """
        parts = text.split(None, 1)
        if not parts or not parts[0].startswith("@"):
            return None, text
        token = parts[0][1:]  # strip leading @
        rest = parts[1] if len(parts) > 1 else ""
        try:
            resolve = getattr(self.app, "resolve_instance", None)
            if resolve is not None:
                inst = resolve(token)
            else:
                # Fallback: linear scan of self.app.instances
                needle = token.lower()
                inst = next(
                    (
                        i for i in getattr(self.app, "instances", [])
                        if (
                            i.get("id", "").lower() == needle
                            or i.get("name", "").lower() == needle
                        )
                    ),
                    None,
                )
        except Exception:
            return None, text
        if inst is None:
            return None, text
        return inst, rest

    def _resolve_active_instance(self, text: str) -> Tuple[Optional[dict], str]:
        """Determine the active instance and strip any ``@`` prefix from text.

        Resolution order:
        1. ``@<token>`` prefix in *text* → ``_parse_at_prefix``.
        2. ``InstanceTable.get_selected_instance()`` on the current screen.

        Args:
            text: Raw input string.

        Returns:
            Tuple of (instance_dict_or_None, text_to_send).
        """
        inst, stripped = self._parse_at_prefix(text)
        if inst is not None:
            return inst, stripped

        # Fallback 1: selected row in the instance table
        try:
            from servonaut.widgets.instance_table import InstanceTable
            table = self.app.screen.query_one(InstanceTable)
            selected = table.get_selected_instance()
            if selected:
                return selected, text
        except Exception:
            pass

        # Fallback 2: screen's own _instance attribute (e.g. ServerActionsScreen)
        try:
            screen_instance = getattr(self.app.screen, "_instance", None)
            if screen_instance is not None:
                return screen_instance, text
        except Exception:
            pass

        return None, text

    def _update_memory_banner(self) -> None:
        """Show or hide the stale-memory banner based on the current instance."""
        try:
            banner = self.query_one("#chat-memory-banner", Static)
        except Exception:
            return

        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            banner.add_class("hidden")
            return

        # Resolve instance without consuming input text (use empty string for prefix check)
        inst, _ = self._resolve_active_instance("")
        if inst is None:
            banner.add_class("hidden")
            return

        instance_id = inst.get("id") or ""
        instance_name = inst.get("name") or ""
        provider = inst.get("provider") or "custom"

        try:
            config = self.app.config_manager.get()
            config_memory = getattr(config, "memory", None)
        except Exception:
            banner.add_class("hidden")
            return

        if config_memory is None or not config_memory.enabled:
            banner.add_class("hidden")
            return

        # Check by both id and name so name-based overrides fire correctly.
        if config_memory.is_instance_disabled(instance_id, instance_name):
            banner.add_class("hidden")
            return

        # Detect the "no memory yet" case first — this is the user's most
        # common trip-up: they ask a question about a server the agent has
        # never probed, and the chat answers blind.  Offer a one-click build.
        try:
            stored_modules = memory_service.get_all_modules(instance_id, provider)
        except Exception:
            stored_modules = {}
        if not stored_modules:
            banner.update(
                f"[cyan]🧠 No memory yet for[/cyan] "
                f"[bold]{_rich_escape(instance_id)}[/bold]. "
                f"Build one and I can answer instantly without SSH round-trips. "
                f"[@click=action_build_memory]Build now[/]"
            )
            banner.remove_class("hidden")
            return

        cache_key = (instance_id, provider)
        now = time.monotonic()
        cached = self._stale_cache.get(cache_key)
        if cached is not None and (now - cached[0]) < self._STALE_CACHE_TTL:
            stale = cached[1]
        else:
            try:
                stale = memory_service.stale_modules(instance_id, provider)
            except Exception:
                banner.add_class("hidden")
                return
            self._stale_cache[cache_key] = (now, stale)

        if not stale:
            banner.add_class("hidden")
            return

        module_list = ", ".join(_rich_escape(m) for m in stale)
        banner.update(
            f"[yellow]Memory is stale for[/yellow] [bold]{_rich_escape(instance_id)}[/bold] "
            f"(modules: {module_list}). "
            f"[@click=action_refresh_memory]Refresh[/]"
        )
        banner.remove_class("hidden")

    def action_refresh_memory(self) -> None:
        """Refresh stale memory for the currently active instance."""
        inst, _ = self._resolve_active_instance("")
        if inst is None:
            self.app.notify("No active instance selected.", severity="warning")
            return
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            return
        self.run_worker(
            memory_service.refresh(inst),
            name="chat_memory_refresh",
        )

    def action_build_memory(self) -> None:
        """Build memory from scratch for the current instance.

        Triggered from the "No memory yet" banner.  Shares the refresh
        worker group so only one memory probe per chat session runs at a
        time, and clears the stale cache on completion so the banner
        updates to green without waiting for the next render tick.
        """
        inst, _ = self._resolve_active_instance("")
        if inst is None:
            self.app.notify("No active instance selected.", severity="warning")
            return
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            return
        name = inst.get("name") or inst.get("id") or "server"
        self.app.notify(f"🧠 Building memory for {name}…")

        async def _build_then_refresh() -> None:
            try:
                if hasattr(memory_service, "build_report"):
                    report = await memory_service.build_report(inst)
                    if report.has_any_success:
                        self.app.notify(
                            f"Memory built for {name}: {report.count} modules."
                        )
                    else:
                        self.app.notify(
                            f"Memory build failed for {name} "
                            f"({report.overall_reason or 'unknown'}). "
                            "Check SSH connectivity.",
                            severity="warning",
                        )
                else:
                    await memory_service.refresh(inst)
                    self.app.notify(f"Memory built for {name}.")
            except Exception as exc:  # noqa: BLE001
                self.app.notify(
                    f"Memory build failed for {name}: {exc}",
                    severity="error",
                )
            finally:
                self._stale_cache.clear()
                self._update_memory_banner()

        self.run_worker(
            _build_then_refresh(),
            name="chat_memory_build",
            group="memory_refresh",
        )

    # ------------------------------------------------------------------
    # Welcome & stats
    # ------------------------------------------------------------------

    def _show_welcome(self) -> None:
        """Show a welcome message if the session is empty."""
        if self._session is None or len(self._session.messages) > 0:  # type: ignore[union-attr]
            return
        container = self.query_one("#chat-messages", VerticalScroll)
        welcome = Static(
            f"{BOT_MARKER} [bold]Servonaut[/bold]\n\n"
            "Hello! I'm your DevOps assistant. I can help with:\n\n"
            "[dim]\u2022[/dim] Server management & SSH issues\n"
            "[dim]\u2022[/dim] AWS operations & troubleshooting\n"
            "[dim]\u2022[/dim] Log analysis & debugging\n"
            "[dim]\u2022[/dim] Networking & security questions\n"
            "[dim]\u2022[/dim] CI/CD pipelines & containerization\n\n"
            "I can also [bold]interact with your servers directly[/bold] \u2014\n"
            "list instances, check status, run commands, and view logs.\n\n"
            "[dim italic]Type a message below to get started.[/dim italic]",
            classes="chat-message-assistant chat-welcome",
        )
        container.mount(welcome)

    def _update_stats(self) -> None:
        """Update the token/cost stats bar.

        Wave-3 additions:
        - ``[dim]via backup vendor[/dim]`` suffix when ``fallback_used``
          was true on the last usage event (T10 acceptance criterion).
        - Soft / hard cap badges via :func:`format_soft_cap_badge`.
        - Tools-disabled note when active provider != servonaut so the
          user knows why the tools panel is hidden.
        """
        try:
            stats_widget = self.query_one("#chat-stats", Static)
        except Exception:
            return

        if self._model:
            parts = [f"[dim]Model:[/dim] [bold]{self._model}[/bold]"]
        else:
            parts = [f"[dim]Model:[/dim] [dim italic]not configured[/dim italic]"]

        # Voice status is derived from panel state on every repaint: this
        # method rebuilds the whole one-row bar, so an imperatively pushed
        # indicator would be wiped by the next caller.
        if self._recording:
            parts.insert(0, "[bold red]● REC[/bold red]")
        elif self._transcribing:
            frame = _SPINNER_FRAMES[self._spinner_frame % len(_SPINNER_FRAMES)]
            parts.insert(0, f"[yellow]{frame} Transcribing…[/yellow]")
        # Speaking can overlap either capture state, so it gets its own
        # slot rather than the elif chain — and it names the interrupt
        # key, because an affordance nobody can discover is not one.
        # Suppressed while the conversation slot below already says
        # "speaking" — two Speaking badges would read as a glitch.
        if self._speaking and self._conversation_state != "speaking":
            parts.insert(
                0, f"[cyan]{_SPEAKER_ACTIVE} Speaking — ctrl+o stops[/cyan]"
            )
        # Conversation-mode state, derived on every repaint like the rest
        # of the voice slots. Inserted last so it renders first — while
        # the loop runs, its state is the panel's headline.
        convo_marker = conversation_status_markup(self._conversation_state)
        if convo_marker:
            parts.insert(0, convo_marker)

        if self._total_tokens > 0:
            parts.append(f"[dim]Tokens:[/dim] {self._total_tokens:,}")
        if self._total_cost > 0:
            parts.append(f"[dim]Cost:[/dim] ${self._total_cost:.4f}")

        msg_count = 0
        if self._session is not None:
            msg_count = len(self._session.messages)  # type: ignore[union-attr]
        parts.append(f"[dim]Messages:[/dim] {msg_count}")

        # T10 \u2014 fallback-used badge. Only render after we've seen at
        # least one ``usage`` event flagged ``fallback_used: true``.
        if self._last_fallback_used:
            parts.append("[dim]via backup vendor[/dim]")

        # T7 acceptance \u2014 soft / hard cap badges via formatter helper.
        # Lazy import keeps the chat panel import cost low for users
        # who never authenticate.
        try:
            from servonaut.utils.formatting import format_soft_cap_badge
            badge = format_soft_cap_badge(
                self._last_soft_capped,
                self._last_hard_capped,
            )
            if badge:
                colour = "red" if self._last_hard_capped else "yellow"
                parts.append(f"[{colour}]{_rich_escape(badge)}[/{colour}]")
        except Exception:  # pragma: no cover \u2014 defensive
            pass

        # Capability note \u2014 tools require Servonaut AI. Drives the
        # T4.5 acceptance "tools panel hidden / greyed when active
        # provider != servonaut".
        active_provider = self._active_provider_name()
        if active_provider and active_provider != "servonaut":
            parts.append("[dim italic]Tool execution requires Servonaut AI.[/dim italic]")

        stats_widget.update("  \u2502  ".join(parts))
        # Update the quota footer + provider indicator in lockstep so a
        # call from the streaming consumer doesn't leave them out of sync.
        self._update_quota_footer()
        self._update_provider_indicator()

    # ------------------------------------------------------------------
    # Wave-3 helpers — provider selection, quota, banners, T10 watcher
    # ------------------------------------------------------------------

    def _active_provider_name(self) -> str:
        """Resolve the provider name we should route the current turn through.

        Order:
          1. Session-only override (T10 fallback prompt result).
          2. :class:`ProviderPreferenceResolver` decision.
          3. Config-file preference / fallthrough.
          4. ``"servonaut"`` if entitled, else ``""``.
        """
        if self._session_provider_override:
            return self._session_provider_override

        resolver = getattr(self.app, "provider_preference_resolver", None)
        if resolver is not None:
            try:
                decision = resolver.resolve()
                return decision.active_provider or ""
            except Exception:
                logger.debug("provider_preference_resolver.resolve() failed", exc_info=True)

        # Fallback: read config + auth directly.
        try:
            cfg = self.app.config_manager.get().ai_provider
            preference = getattr(cfg, "provider_preference", None) or ""
            if preference:
                return preference
            auth = getattr(self.app, "auth_service", None)
            if auth and auth.is_authenticated and auth.has_feature("premium_ai"):
                return "servonaut"
            return cfg.provider or ""
        except Exception:
            return ""

    def _current_quota(self) -> Optional[Any]:
        """Read the cached :class:`AIQuota`, returning ``None`` for free users."""
        auth = getattr(self.app, "auth_service", None)
        if auth is None or not auth.is_authenticated:
            return None
        token = getattr(auth, "_token", None)
        ents = getattr(token, "entitlements", None) if token is not None else None
        if not isinstance(ents, dict):
            return None
        try:
            from servonaut.services.ai_quota import AIQuota
            return AIQuota.from_dict(ents.get("quota"))
        except Exception:
            return None

    def _update_quota_footer(self) -> None:
        """Render the quota footer if the active provider is Servonaut."""
        try:
            footer = self.query_one("#chat-quota-footer", Static)
        except Exception:
            return

        if self._active_provider_name() != "servonaut":
            footer.add_class("hidden")
            return

        quota = self._current_quota()
        if quota is None:
            # Subscribed but no quota seen yet — hide rather than render
            # zeroes.
            footer.add_class("hidden")
            return

        try:
            from servonaut.utils.formatting import (
                format_resets_at,
                format_tokens_remaining,
            )
            tokens_label = format_tokens_remaining(
                quota.tokens_used, quota.tokens_limit, quota.tokens_topup_remaining,
            )
            resets_label = format_resets_at(quota.resets_at)
        except Exception:
            footer.add_class("hidden")
            return

        parts = [f"[dim]Quota:[/dim] [bold]{_rich_escape(tokens_label)}[/bold]"]
        if resets_label:
            parts.append(f"[dim]resets {_rich_escape(resets_label)}[/dim]")
        footer.update("  │  ".join(parts))
        footer.remove_class("hidden")

    def _update_provider_indicator(self) -> None:
        """Update the single-character provider indicator button label."""
        try:
            btn = self.query_one("#btn-chat-provider", Button)
        except Exception:
            return
        active = self._active_provider_name()
        btn.label = _PROVIDER_INDICATORS.get(active, _PROVIDER_INDICATOR_DEFAULT)

    def _set_banner(self, markup: str) -> None:
        """Show *markup* in the chat-banner Static; empty string hides it."""
        try:
            banner = self.query_one("#chat-banner", Static)
        except Exception:
            return
        if not markup:
            banner.add_class("hidden")
            banner.update("")
            return
        banner.update(markup)
        banner.remove_class("hidden")

    def _check_provider_decision_events(self) -> None:
        """Render banners and push first-run / empty-state modals as needed.

        B1/B2 — this method now owns the full set of UI reactions to a
        :class:`ProviderDecision`:

        - Banners (paying-twice, capability) via :meth:`_set_banner`.
        - First-run modal (one-shot per session) via :meth:`push_screen`.
        - Empty-state modal (one-shot per session) via :meth:`push_screen`.
        - Pinned-error state — banner + disabled input until resolved.

        ``screens/ai_analysis.py`` previously claimed ownership of the
        first-run / empty-state modals but never actually pushed them.
        Centralising here keeps modal lifetime single-sourced.
        """
        resolver = getattr(self.app, "provider_preference_resolver", None)
        if resolver is None:
            return
        try:
            decision = resolver.resolve()
        except Exception:
            return

        from servonaut.services.ai_provider_preference import (
            ProviderPreferenceEvent,
        )

        # Pinned-error state is recomputed on every check — we clear it
        # the moment the resolver picks a healthy provider.
        pinned_now = ProviderPreferenceEvent.PINNED_ERROR_NO_PROVIDER in decision.events
        if pinned_now != self._pinned_error_active:
            self._pinned_error_active = pinned_now
            self._apply_pinned_error_state(pinned_now)

        for event in decision.events:
            if event == ProviderPreferenceEvent.SHOW_PAYING_TWICE_BANNER:
                self._set_banner(
                    "[yellow]You're subscribed to Servonaut AI but using your own key — "
                    "you may be paying twice.[/yellow]"
                )
            elif event == ProviderPreferenceEvent.SHOW_CAPABILITY_BANNER:
                self._set_banner(
                    "[cyan]Servonaut AI unlocks deploy / provision / scan + "
                    "account-level reads (billing, ban status) the local "
                    "chat doesn't touch — try a chat?[/cyan]"
                )
            elif event == ProviderPreferenceEvent.SHOW_FIRST_RUN_MODAL:
                # B2 — push the first-run choice modal exactly once per
                # session. Stomping the user's input by re-pushing on
                # every render would be hostile.
                if not self._first_run_modal_shown:
                    self._first_run_modal_shown = True
                    self._push_first_run_modal()
            elif event == ProviderPreferenceEvent.SHOW_EMPTY_STATE:
                # B2 — empty-state onboarding modal. Same one-shot rule.
                if not self._empty_state_modal_shown:
                    self._empty_state_modal_shown = True
                    self._push_empty_state_modal()

    def _apply_pinned_error_state(self, active: bool) -> None:
        """Toggle the pinned-error banner + disable the input row."""
        try:
            banner = self.query_one("#chat-pinned-error-banner", Horizontal)
            chat_input = self.query_one("#chat-input", TextArea)
            send_btn = self.query_one("#btn-chat-send", Button)
            mic_btn = self.query_one("#btn-chat-mic", Button)
        except Exception:
            return
        if active:
            banner.remove_class("hidden")
            chat_input.disabled = True
            send_btn.disabled = True
            mic_btn.disabled = True
        else:
            banner.add_class("hidden")
            chat_input.disabled = False
            send_btn.disabled = False
            # Re-enabling mid-transcription is cosmetic only: the toggle
            # itself refuses while the decoder is running, and the worker
            # repaints the button when it finishes. An install with no
            # usable microphone stays greyed out, though.
            mic_btn.disabled = self._mic_unavailable

    def _push_first_run_modal(self) -> None:
        """B2 — push :class:`AIProviderFirstRunModal` once per session."""
        from servonaut.screens.ai_picker_modal import AIProviderFirstRunModal

        resolver = getattr(self.app, "provider_preference_resolver", None)
        if resolver is None:
            return

        # The user's actual selected provider is the source of truth for the
        # "Currently configured: [...]" line. The resolver's
        # is_provider_configured() answers "is some non-servonaut config
        # present" but cannot distinguish providers that share the single
        # `api_key` field — iterating it would pick OpenAI whenever any
        # api_key is set, even when the user is on Anthropic / Gemini /
        # Ollama. Read `cfg.provider` instead.
        existing = ""
        base_url = ""
        try:
            cfg = self.app.config_manager.get().ai_provider
            selected = (cfg.provider or "").strip().lower()
            if selected and selected != "servonaut":
                existing = selected
                base_url = getattr(cfg, "base_url", "") or ""
            else:
                # Fallback: selected provider is empty/servonaut but the
                # resolver detected a non-servonaut config (Ollama base_url
                # only, perhaps). Walk the rules to find which one matches
                # so we still render *something* sensible.
                for name in ("ollama", "openai", "anthropic", "gemini"):
                    if resolver.is_provider_configured(name):
                        existing = name
                        base_url = getattr(cfg, "base_url", "") or ""
                        break
        except Exception:
            pass

        def _on_choice(choice: Optional[str]) -> None:
            if not choice:
                return
            try:
                resolver.commit_first_run_choice(choice)  # type: ignore[arg-type]
                self.app.notify(
                    f"Provider preference set to {choice}.",
                    severity="information",
                    markup=False,
                )
                self._check_provider_decision_events()
                self._update_provider_indicator()
                self._update_quota_footer()
            except Exception:
                logger.exception("commit_first_run_choice failed")

        try:
            self.app.push_screen(
                AIProviderFirstRunModal(existing or "ollama", base_url=base_url),
                _on_choice,
            )
        except Exception:
            logger.exception("Failed to push AIProviderFirstRunModal")

    def _push_empty_state_modal(self) -> None:
        """B2 — push :class:`AIEmptyStateModal` once per session."""
        from servonaut.screens.ai_picker_modal import AIEmptyStateModal

        def _on_choice(choice: Optional[str]) -> None:
            if not choice:
                return
            if choice == "subscribe":
                try:
                    webbrowser.open("https://servonaut.dev/pricing")
                except Exception:  # noqa: BLE001
                    pass
            elif choice in ("add_api_key", "ollama"):
                # Defer settings-screen push to the app — chat panel
                # doesn't import the screen module to avoid cycles.
                pusher = getattr(self.app, "open_settings_screen", None)
                if callable(pusher):
                    try:
                        pusher(provider_focus=choice)
                    except Exception:
                        logger.debug(
                            "open_settings_screen raised", exc_info=True,
                        )
                else:
                    self.app.notify(
                        "Open Settings to add a provider.",
                        severity="information",
                        markup=False,
                    )

        try:
            self.app.push_screen(AIEmptyStateModal(), _on_choice)
        except Exception:
            logger.exception("Failed to push AIEmptyStateModal")

    # ------------------------------------------------------------------
    # T10 upstream-unavailable watcher
    # ------------------------------------------------------------------

    def _record_upstream_failure(self) -> None:
        """Append the current monotonic timestamp; prune stale entries."""
        now = time.monotonic()
        self._upstream_failures.append(now)
        cutoff = now - _UPSTREAM_FAILURE_WINDOW_S
        self._upstream_failures = [
            t for t in self._upstream_failures if t >= cutoff
        ]

    def _maybe_offer_fallback(self) -> None:
        """Inspect the failure list; auto-fallback or push the prompt modal.

        Plan §T10 invariant: only on the *second* upstream_unavailable
        within 60s do we even consider acting. First failure: silent.
        """
        if len(self._upstream_failures) < 2:
            return

        # Local fallback configured? Auto-switch session-only.
        try:
            cfg = self.app.config_manager.get().ai_provider
            local_fallback = getattr(cfg, "local_fallback_provider", None) or ""
        except Exception:
            local_fallback = ""

        resolver = getattr(self.app, "provider_preference_resolver", None)

        if local_fallback and resolver is not None:
            try:
                if resolver.is_provider_configured(local_fallback):
                    self._session_provider_override = local_fallback
                    self.app.notify(
                        f"Servonaut AI is unavailable — falling back to "
                        f"{local_fallback} for this session.",
                        severity="warning",
                    )
                    self._update_provider_indicator()
                    self._update_stats()
                    return
            except Exception:
                pass

        # Otherwise, prompt — only if at least one non-Servonaut
        # provider is configured.
        if resolver is None:
            return
        try:
            if not resolver.has_any_non_servonaut_configured():
                return
            available = [
                name for name in ("ollama", "openai", "anthropic", "gemini")
                if resolver.is_provider_configured(name)
            ]
        except Exception:
            return

        from servonaut.screens.ai_fallback_prompt_modal import (
            AIFallbackPromptModal,
        )

        def _on_choice(choice: Optional[str]) -> None:
            if not choice:
                return
            self._session_provider_override = choice
            self.app.notify(
                f"Using {choice} for this session.",
                severity="information",
            )
            self._update_provider_indicator()
            self._update_stats()

        try:
            self.app.push_screen(
                AIFallbackPromptModal(
                    available,
                    reason="Servonaut AI unavailable twice in 60s.",
                ),
                _on_choice,
            )
        except Exception:
            logger.exception("Failed to push AIFallbackPromptModal")

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def _get_chat_service(self) -> Optional[Any]:
        """Get the chat service, returning None if unavailable."""
        try:
            svc = self.app.chat_service  # type: ignore[attr-defined]
        except AttributeError:
            return None
        return svc

    def _start_or_resume_session(self) -> None:
        """Load the most recent session or create a fresh one.

        Demo mode always starts FRESH: stored conversations were captured
        with real data and would render it verbatim — resuming one on a
        recorded screen defeats the redaction guarantee.
        """
        chat_service = self._get_chat_service()
        if chat_service is None:
            return

        if not getattr(self.app, "demo_mode", False):
            sessions = chat_service.list_sessions()
            if sessions:
                self._session = chat_service.load_session(sessions[0]["id"])
        if self._session is None:
            self._session = chat_service.create_session()

        self._refresh_messages()

    def _refresh_messages(self) -> None:
        """Rebuild the message display from the current session."""
        container = self.query_one("#chat-messages", VerticalScroll)
        container.remove_children()

        if self._session is None:
            return

        messages = self._session.messages  # type: ignore[union-attr]
        if not messages:
            self._show_welcome()
            return

        for msg in messages:
            # A2 — escape ``msg.content`` at every interpolation site. A
            # malicious model could inject Rich markup (e.g. a clickable
            # ``[link=evil]`` href) that survives a thread-export round-trip
            # and renders as a real Rich Link on next mount. The user-role
            # path is also escaped because conversations imported from the
            # server may include user-role rows fabricated by the model.
            if msg.role == "tool":
                # Tool rows were rendered with Rich markup at write time
                # (header + body) and stored verbatim — re-render the
                # markup so the styling survives reload. The content
                # comes from CLI-side composition (tool name + status +
                # result_summary, each escaped before storage), not
                # raw model output, so re-rendering is safe.
                # Demo-mode: scrub the stored markup before re-rendering.
                # On-disk session stays raw (ISSUE-1 invariant). The markup
                # has already been escaped so we scrub the pre-escape
                # original embedded in the stored string — calling
                # scrub_stream on already-escaped markup is safe because
                # scrub_stream only replaces data tokens, not Rich tags.
                tool_content = msg.content or ""
                if getattr(self.app, "demo_mode", False) and getattr(self.app, "redaction_service", None) is not None:
                    tool_content = self.app.redaction_service.scrub_stream(tool_content)
                widget = Static(
                    tool_content,
                    classes="chat-message-tool",
                )
                container.mount(widget)
                continue
            # Scrub BEFORE _rich_escape: order must be redact → escape → embed.
            # On-disk session stays raw; redaction is display-only.
            raw_content = msg.content or ""
            if getattr(self.app, "demo_mode", False) and getattr(self.app, "redaction_service", None) is not None:
                raw_content = self.app.redaction_service.scrub_stream(raw_content)
            safe_content = _rich_escape(raw_content)
            if msg.role == "user":
                widget = Static(
                    f"[bold]You[/bold]\n{safe_content}",
                    classes="chat-message-user",
                )
            else:
                widget = Static(
                    f"{BOT_MARKER} [bold]Servonaut[/bold]\n{safe_content}",
                    classes="chat-message-assistant",
                )
            container.mount(widget)

        self.call_after_refresh(self._scroll_to_bottom)
        self._update_stats()

    def _scroll_to_bottom(self) -> None:
        try:
            container = self.query_one("#chat-messages", VerticalScroll)
            container.scroll_end(animate=False)
            # Re-arm follow-tail: the user just acted (sent message,
            # opened a session, refreshed) so they're now at the
            # bottom intentionally.
            self._last_max_scroll_y = container.max_scroll_y
        except Exception:
            pass

    def _follow_tail(self) -> None:
        """Scroll to bottom ONLY if the user was at the previous bottom.

        Streaming tokens, tool results, and skipped-tool rows route
        through this so they keep the viewport pinned to the latest
        message — but only when the user hasn't scrolled up. If they
        have, we leave them alone so they can read earlier messages
        (including the start of the conversation) without being yanked
        back by every token delta.

        Why ``_last_max_scroll_y`` instead of comparing against the
        current ``max_scroll_y``: by the time this callback runs the
        new content has already extended ``max_scroll_y``, so a user
        who WAS at the bottom now looks "scrolled up" by the height of
        the new content. Comparing against the *previous* bottom (the
        one we recorded after the last update) gives us the user's
        intent at the moment the content arrived. Two-row tolerance
        absorbs sub-pixel layout drift.
        """
        try:
            container = self.query_one("#chat-messages", VerticalScroll)
        except Exception:
            return
        last_max = getattr(self, "_last_max_scroll_y", 0)
        if container.scroll_y >= last_max - 2:
            try:
                container.scroll_end(animate=False)
            except Exception:
                pass
        # Record the new bottom for the next call.
        try:
            self._last_max_scroll_y = container.max_scroll_y
        except Exception:
            pass

    def _show_thinking(self, text: str = "Servonaut is thinking...") -> None:
        """Add an animated thinking indicator with customisable text.

        A2 — *text* may originate from a server-controlled status string
        (e.g. SSE token deltas accumulated mid-stream). Escape it before
        interpolation so injected ``[link=...]`` payloads cannot hijack
        the indicator.
        """
        container = self.query_one("#chat-messages", VerticalScroll)
        widget = Static(
            f"{BOT_MARKER} [dim italic]{_rich_escape(text)}[/dim italic]",
            id="chat-thinking",
            classes="chat-message-assistant chat-thinking",
        )
        container.mount(widget)
        self.call_after_refresh(self._scroll_to_bottom)

    def _update_thinking_status(self, text: str) -> None:
        """Update the thinking indicator text (called from worker thread).

        A2 — escape *text* before interpolating into Rich markup. This is
        the primary streaming sink: every token delta we accumulate flows
        through here, so this is the most security-critical escape point.
        """
        try:
            widget = self.query_one("#chat-thinking", Static)
            widget.update(
                f"{BOT_MARKER} [dim italic]{_rich_escape(text)}[/dim italic]"
            )
            # Streaming tokens grow the bubble; without this the viewport
            # stays anchored to the top and the user has to scroll down
            # to see what's being typed. ``_follow_tail`` only scrolls
            # if the user is already at the bottom — scrolling up to
            # re-read earlier turns is preserved.
            self.call_after_refresh(self._follow_tail)
        except Exception:
            pass

    def _hide_thinking(self) -> None:
        """Remove the thinking indicator."""
        try:
            self.query_one("#chat-thinking", Static).remove()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn-chat-new":
            self._new_chat()
        elif button_id == "btn-chat-history":
            self._toggle_history()
        elif button_id == "btn-chat-provider":
            self._toggle_provider_override()
        elif button_id == "btn-chat-mic":
            self._toggle_recording()
        elif button_id == "btn-chat-convo":
            self._toggle_conversation()
        elif button_id == "btn-chat-send":
            self._send()
        elif button_id == "btn-chat-close":
            self.close_panel()
        elif button_id == "btn-pinned-resubscribe":
            # B1 — open pricing in the user's default browser.
            try:
                webbrowser.open("https://servonaut.dev/pricing")
            except Exception:  # noqa: BLE001
                self.app.notify(
                    "Open https://servonaut.dev/pricing to resubscribe.",
                    severity="warning",
                    markup=False,
                )
        elif button_id == "btn-pinned-add-provider":
            # B1 — defer to the app to push the settings screen if it
            # supports the helper; otherwise tell the user where to look.
            pusher = getattr(self.app, "open_settings_screen", None)
            if callable(pusher):
                try:
                    pusher()
                except Exception:
                    logger.debug("open_settings_screen raised", exc_info=True)
            else:
                self.app.notify(
                    "Open Settings to add an AI provider.",
                    severity="information",
                    markup=False,
                )
        elif button_id and button_id.startswith("btn-session-"):
            session_id = button_id.removeprefix("btn-session-")
            self._load_session(session_id)
        elif button_id and button_id.startswith("btn-del-session-"):
            session_id = button_id.removeprefix("btn-del-session-")
            self._delete_session(session_id)
        event.stop()

    def _toggle_provider_override(self) -> None:
        """Open a fallback prompt to override the active provider for this session.

        Reuses :class:`AIFallbackPromptModal` since it's already a
        provider-pick modal — semantically identical to the user-driven
        case (T10 explicitly says the override is session-scoped).
        """
        resolver = getattr(self.app, "provider_preference_resolver", None)
        if resolver is None:
            self.app.notify(
                "Provider switching not available.",
                severity="warning",
            )
            return
        try:
            available = [
                name for name in ("servonaut", "ollama", "openai", "anthropic", "gemini")
                if (
                    (name == "servonaut"
                     and self.app.auth_service.is_authenticated
                     and self.app.auth_service.has_feature("premium_ai"))
                    or resolver.is_provider_configured(name)
                )
            ]
        except Exception:
            available = []

        if not available:
            self.app.notify("No providers configured.", severity="warning")
            return

        from servonaut.screens.ai_fallback_prompt_modal import (
            AIFallbackPromptModal,
        )

        def _on_choice(choice: Optional[str]) -> None:
            if not choice:
                return
            self._session_provider_override = choice
            self.app.notify(
                f"Using {choice} for this session.",
                severity="information",
            )
            self._update_provider_indicator()
            self._update_stats()

        # Manual switcher — distinct copy from the T10 fallback prompt
        # so the user isn't told "Servonaut AI is unavailable" when they
        # clicked the provider button on a perfectly working chat.
        self.app.push_screen(
            AIFallbackPromptModal(
                available,
                title="Switch AI provider",
                body=(
                    "Pick the provider to use for this chat session. "
                    "This won't change your default — only the current chat."
                ),
                keep_label="Cancel",
            ),
            _on_choice,
        )

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        """Gate the priority Enter binding to the chat input.

        Returning False deactivates the binding so the key falls through
        to normal handling (e.g. activating a focused panel button).
        """
        if action == "send_from_input":
            focused = self.app.focused
            return getattr(focused, "id", None) == "chat-input"
        if action == "convo_interrupt":
            # Escape belongs to the screens (closing modals, popping)
            # everywhere except the one moment a conversation reply is
            # playing — only then does the panel claim it.
            return (
                self._conversation_active
                and self._conversation_state == "speaking"
            )
        return True

    def action_send_from_input(self) -> None:
        """Send the current input (Enter while the chat input is focused)."""
        self._send()

    def action_toggle_mic(self) -> None:
        """Start or stop voice capture (ctrl+t anywhere in the panel)."""
        self._toggle_recording()

    def action_stop_speaking(self) -> None:
        """Silence the spoken reply (ctrl+o anywhere in the panel).

        Deliberately not gated by ``check_action``: the whole point of an
        interrupt key is that it works whenever speech is playing, whatever
        has focus. When nothing is being spoken it is a harmless no-op.
        """
        self._interrupt_speech()

    def action_toggle_conversation(self) -> None:
        """Start or stop the hands-free conversation loop."""
        self._toggle_conversation()

    def action_convo_interrupt(self) -> None:
        """Cut a conversation reply short (escape while it is speaking).

        ``check_action`` keeps this binding inert outside conversation
        SPEAKING, so escape retains its ordinary meaning everywhere else.
        """
        self._convo_call("interrupt")

    def _toggle_history(self) -> None:
        """Open the unified Previous Chats screen with Cloud + Local tabs.

        Routing is identical for every user — the screen itself decides
        which tab to start on. Hosted-AI subscribers see Cloud first
        (their hosted history); free / logged-out users land on Cloud
        (which renders an empty / sign-in nudge) and pick Local for
        local-only sessions. The previous behaviour where free users
        got the inline session list inside the chat panel is retired in
        favour of one consistent surface.
        """
        from servonaut.screens.ai_conversations_screen import AIConversationsScreen
        self.app.push_screen(AIConversationsScreen())

    def _populate_history(self) -> None:
        """Populate the history list with saved sessions."""
        chat_service = self._get_chat_service()
        if chat_service is None:
            return

        history_panel = self.query_one("#chat-history-list", VerticalScroll)
        history_panel.remove_children()

        sessions = chat_service.list_sessions()
        if not sessions:
            history_panel.mount(Static("[dim]No saved chats[/dim]", id="chat-history-empty"))
            return

        for s in sessions:
            title = s["title"]
            session_id = s["id"]
            is_current = self._session is not None and self._session.id == session_id
            marker = "[bold cyan]▸[/bold cyan] " if is_current else "  "

            # Parse date for display
            updated = s.get("updated_at", "")
            date_str = ""
            if updated:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(updated)
                    date_str = dt.strftime("%b %d %H:%M")
                except (ValueError, TypeError):
                    pass

            row = Horizontal(classes="chat-history-item")
            load_btn = Button(
                f"{marker}{title[:30]}{'…' if len(title) > 30 else ''} [dim]{date_str}[/dim]",
                id=f"btn-session-{session_id}",
                classes="chat-history-btn",
            )
            del_btn = Button(
                "✕",
                id=f"btn-del-session-{session_id}",
                variant="error",
                classes="chat-history-del",
            )
            history_panel.mount(row)
            row.mount(load_btn)
            row.mount(del_btn)

    def _load_session(self, session_id: str) -> None:
        """Load a session by ID and switch to it."""
        chat_service = self._get_chat_service()
        if chat_service is None:
            return
        session = chat_service.load_session(session_id)
        if session is None:
            self.app.notify("Session not found", severity="error")
            return
        self._session = session
        # If the session is paired with a server-side conversation
        # (ChatSession.remote_conversation_id was stored on disk),
        # restore that pointer so subsequent Servonaut turns continue
        # appending to the same Cloud row instead of starting a new
        # one. Unpaired sessions (None) leave the next turn to create a
        # fresh Cloud thread on first send.
        self._remote_conversation_id = session.remote_conversation_id
        self._total_tokens = 0
        self._total_cost = 0.0
        self._refresh_messages()
        self._update_stats()
        # Hide history panel after selection
        try:
            self.query_one("#chat-history-list", VerticalScroll).add_class("hidden")
        except Exception:
            # Inline history panel may not exist on every layout once we
            # route history through the unified screen.
            pass
        self._do_focus_input()

    def _delete_session(self, session_id: str) -> None:
        """Delete a session and refresh the history list."""
        chat_service = self._get_chat_service()
        if chat_service is None:
            return

        # If deleting the current session, create a new one
        is_current = self._session is not None and self._session.id == session_id
        chat_service.delete_session(session_id)

        if is_current:
            self._session = chat_service.create_session()
            self._remote_conversation_id = None
            self._total_tokens = 0
            self._total_cost = 0.0
            self._refresh_messages()
            self._update_stats()

        # Refresh the history list
        self._populate_history()

    def _new_chat(self) -> None:
        """Create a new session and clear the display."""
        chat_service = self._get_chat_service()
        if chat_service is None:
            return
        self._session = chat_service.create_session()
        # Drop the previous server-side conversation pointer so the next
        # turn creates a fresh /account/ai/conversations row instead of
        # appending to the prior thread. Without this, "New Chat" looks
        # local-only but the server keeps writing to the old thread.
        self._remote_conversation_id = None
        self._total_tokens = 0
        self._total_cost = 0.0
        self._refresh_messages()
        self._update_stats()
        self.query_one("#chat-history-list", VerticalScroll).add_class("hidden")
        self._do_focus_input()

    # ------------------------------------------------------------------
    # Voice input
    # ------------------------------------------------------------------

    def _voice_config(self) -> Optional[Any]:
        """Read the voice settings, or None when they cannot be resolved."""
        try:
            return self.app.config_manager.get().voice
        except Exception:  # noqa: BLE001 — a panel outside the app has no config
            logger.debug("voice config unavailable", exc_info=True)
            return None

    def refresh_voice_affordance(self) -> None:
        """Re-evaluate the mic button after voice setup may have changed.

        Called by the Voice Input settings panel once an install, download
        or re-check completes, so a panel that was mounted while the
        feature was still unusable picks the change up instead of keeping
        a greyed-out button until the app restarts. The output service is
        reset too: it caches its no-output-device verdict just like the
        input service caches its probe, and a re-check that only revived
        the mic would leave spoken replies silently skipped.
        """
        for attr in ("voice_input_service", "voice_output_service"):
            service = getattr(self.app, attr, None)
            reset = getattr(service, "reset_availability", None)
            if callable(reset):
                reset()
        self._sync_mic_affordance()

    def _sync_mic_affordance(self) -> None:
        """Match the mic button to what this install can actually do.

        The entry point disappears when voice is switched off in the
        config, and greys out with the reason on its tooltip when the
        optional audio stack or a microphone is missing — otherwise it
        looks exactly like a working button and only tells the truth
        after the user has clicked it.

        Every path resets the button to its usable state first, so this is
        safe to re-run: setup completing has to be able to undo an earlier
        "unavailable" verdict, not just add to it.
        """
        try:
            mic_btn = self.query_one("#btn-chat-mic", Button)
        except Exception:  # noqa: BLE001 — nothing to style before compose
            return
        try:
            convo_btn = self.query_one("#btn-chat-convo", Button)
        except Exception:  # noqa: BLE001 — nothing to style before compose
            convo_btn = None

        self._mic_unavailable = False
        mic_btn.display = True
        mic_btn.disabled = False
        mic_btn.tooltip = "Voice input (ctrl+t)"
        if convo_btn is not None:
            # The conversation button follows the mic's visibility (no
            # voice, no entry point) but is NOT greyed by the async
            # probes: pressing it runs the full readiness check and
            # names the first missing piece, which a disabled button
            # could never explain.
            convo_btn.display = True
            convo_btn.disabled = False
            convo_btn.tooltip = f"Hands-free conversation ({_CONVO_TOGGLE_KEY})"
            if self._conversation_service() is None:
                convo_btn.disabled = True
                convo_btn.tooltip = "Conversation mode unavailable."

        voice_config = self._voice_config()
        if voice_config is not None and not voice_config.enabled:
            mic_btn.display = False
            if convo_btn is not None:
                convo_btn.display = False
            return

        service = getattr(self.app, "voice_input_service", None)
        if service is None:
            self._mic_unavailable = True
            mic_btn.disabled = True
            mic_btn.tooltip = "Voice input unavailable."
            return

        self.run_worker(
            self._probe_mic_availability(service),
            exclusive=False,
            name="voice_probe",
            group="voice",
        )

    async def _probe_mic_availability(self, service: Any) -> None:
        """Worker: resolve availability without stalling the mount.

        The first probe enumerates capture devices through the audio
        backend, which is not a call the event loop should wait on.

        Setup readiness is folded in here as well: the transcription
        backend fetches missing weights on demand, so a mic that looks
        live while the model is absent would turn the user's first
        dictation into a silent multi-minute download.
        """
        try:
            available = await asyncio.to_thread(service.is_available)
        except Exception:  # noqa: BLE001 — a broken probe must not break the panel
            logger.debug("voice availability probe failed", exc_info=True)
            return

        reason = ""
        if not available:
            reason = service.unavailable_reason() or "Voice input unavailable."
        else:
            reason = await self._model_missing_reason()
            if not reason:
                return

        self._mic_unavailable = True
        try:
            mic_btn = self.query_one("#btn-chat-mic", Button)
        except Exception:  # noqa: BLE001 — the panel was closed mid-probe
            return
        mic_btn.disabled = True
        mic_btn.tooltip = reason

    async def _model_missing_reason(self) -> str:
        """Explain an absent speech model, or return "" when one is cached.

        Returns an empty string whenever the answer cannot be established
        (no setup service, probe error) so an inconclusive check never
        disables a mic that would have worked.
        """
        setup = getattr(self.app, "voice_setup_service", None)
        if setup is None:
            return ""
        try:
            readiness = await asyncio.to_thread(setup.probe)
        except Exception:  # noqa: BLE001 — never let a probe failure gate the mic
            logger.debug("voice readiness probe failed", exc_info=True)
            return ""
        if readiness.model_ok:
            return ""
        return (
            "The speech model is not downloaded yet — "
            "download it in Settings > Voice Input."
        )

    def _toggle_recording(self) -> None:
        """Start voice capture, or stop it and transcribe into the input box."""
        voice_config = self._voice_config()
        if voice_config is not None and not voice_config.enabled:
            self.app.notify(
                "Voice input is switched off in settings.",
                severity="warning",
                markup=False,
            )
            return

        service = getattr(self.app, "voice_input_service", None)
        if service is None:
            self.app.notify(
                "Voice input unavailable.",
                severity="warning",
                markup=False,
            )
            return

        # The hands-free loop owns the capture stream; a push-to-talk
        # toggle poking the same service mid-session would tear down a
        # stream the loop believes it is reading.
        if self._conversation_active:
            self.app.notify(
                "Conversation mode owns the microphone — "
                f"{_CONVO_TOGGLE_KEY} stops it first.",
                severity="warning",
                markup=False,
            )
            return

        # A second toggle while the model is decoding would stop a stream
        # that is already closed, and one while the device is still being
        # opened would race the start worker, so swallow both.
        if self._transcribing or self._starting:
            return

        # One service instance backs every mounted panel, so a panel can
        # be left painting REC over a capture that another panel took over
        # or cancelled. Stopping here would drain a buffer it never owned.
        if self._recording and not service.is_recording:
            self._set_mic_state(recording=False, transcribing=False)
            self.app.notify(
                "That recording was already stopped elsewhere.",
                severity="warning",
                markup=False,
            )
            return

        if self._recording:
            self._set_mic_state(recording=False, transcribing=True)
            self.run_worker(
                self._do_transcribe(service),
                exclusive=False,
                name="voice_transcribe",
                # Dedicated group: the ``ai_chat`` group runs exclusive
                # workers that would cancel a capture mid-sentence.
                group="voice",
            )
            return

        # Recording during a streaming turn would drop the transcript into
        # a box the user has already sent from, so refuse rather than queue.
        if self._thinking:
            self.app.notify(
                "Wait for the current response to finish before recording.",
                severity="warning",
                markup=False,
            )
            return

        # Opening the capture device blocks until the audio backend hands
        # it over — long enough to freeze the TUI when another application
        # already holds the mic — so the start half runs off the event
        # loop exactly like the transcribe half does.
        self._starting = True
        self._set_mic_state(recording=False, transcribing=False)
        self.run_worker(
            self._do_start_recording(service),
            exclusive=False,
            name="voice_start",
            group="voice",
        )

    async def _do_start_recording(self, service: Any) -> None:
        """Worker: probe the device and open the stream off the event loop."""
        started = False
        try:
            if not await asyncio.to_thread(service.is_available):
                self.app.notify(
                    service.unavailable_reason() or "Voice input unavailable.",
                    severity="warning",
                    markup=False,
                )
            else:
                self._capture_partial_prefix()
                self._attach_partial_listener(service)
                await asyncio.to_thread(service.start_recording)
                started = True
        except Exception as exc:  # noqa: BLE001 — a dead mic must not kill the panel
            logger.debug("voice start_recording failed", exc_info=True)
            self.app.notify(
                str(exc) or "Could not start recording.",
                severity="error",
                markup=False,
            )
        finally:
            # Every exit path, cancellation included: a button left
            # disabled would strand the user with no way back to an
            # idle mic.
            self._starting = False
            self._set_mic_state(recording=started, transcribing=False)

    def _capture_partial_prefix(self) -> None:
        """Remember what was typed before a dictation started."""
        try:
            self._partial_prefix = self.query_one("#chat-input", TextArea).text.strip()
        except Exception:  # noqa: BLE001 — nothing typed if the box is not there
            self._partial_prefix = ""

    def _attach_partial_listener(self, service: Any) -> None:
        """Subscribe to partial transcripts when the engine emits them.

        Only the streaming engine does; the batch engine has nothing to
        report until it finishes, so this is a no-op there.
        """
        register = getattr(service, "set_partial_callback", None)
        if not callable(register):
            return
        # The decoder thread invokes this, so hop to the UI thread before
        # touching a widget.
        register(lambda text: self._post_partial(text))

    def _post_partial(self, text: str) -> None:
        """Marshal a partial transcript from the decoder thread to the UI."""
        try:
            self.app.call_from_thread(self._render_partial, text)
        except Exception:  # noqa: BLE001 — app gone, or panel unmounted mid-decode
            logger.debug("Could not deliver a partial transcript", exc_info=True)

    def _render_partial(self, text: str) -> None:
        """Show in-progress dictation in the input box.

        The partial replaces the previous partial rather than appending, so
        the box tracks what has been said instead of accumulating every
        intermediate hypothesis. Anything the user had typed before starting
        is preserved as a prefix.
        """
        if not self._recording:
            return
        try:
            inp = self.query_one("#chat-input", TextArea)
        except Exception:  # noqa: BLE001 — panel closed mid-dictation
            return
        if getattr(self.app, "demo_mode", False):
            redactor = getattr(self.app, "redaction_service", None)
            if redactor is not None:
                text = redactor.scrub_stream(text)
        prefix = self._partial_prefix
        combined = f"{prefix} {text}".strip() if prefix else text
        inp.load_text(combined)
        # Keep the caret at the end so the newest words stay in view.
        try:
            inp.move_cursor(inp.document.end)
        except Exception:  # noqa: BLE001 — cursor API is best-effort here
            pass

    async def _do_transcribe(self, service: Any) -> None:
        """Worker: transcribe the captured audio and append it to the input.

        ``stop_and_transcribe`` loads a local model and decodes audio;
        awaiting it inline would freeze every widget in the TUI, so it
        runs on a worker thread.
        """
        try:
            transcript = await asyncio.to_thread(
                service.stop_and_transcribe,
                self._voice_prompt_hint(),
            )
        except Exception as exc:  # noqa: BLE001 — surface the engine error, stay alive
            logger.debug("voice transcription failed", exc_info=True)
            self.app.notify(
                str(exc) or "Transcription failed.",
                severity="error",
                markup=False,
            )
            return
        finally:
            # Every exit path, cancellation included, leaves the mic idle —
            # a stuck "STOP" button would strand the user.
            self._set_mic_state(recording=False, transcribing=False)

        # The cap drops the tail of a long dictation, which is the part a
        # user scanning a small input box is least likely to notice.
        if getattr(service, "hit_recording_cap", False):
            voice_config = self._voice_config()
            seconds = getattr(voice_config, "max_recording_seconds", None)
            limit = f"{seconds}s" if seconds else "recording"
            self.app.notify(
                f"Recording hit the {limit} limit — only the audio up to "
                "that point was transcribed.",
                severity="warning",
                markup=False,
            )

        transcript = transcript.strip()
        if not transcript:
            self.app.notify(
                "No speech detected.",
                severity="warning",
                markup=False,
            )
            return
        if getattr(service, "supports_streaming", False):
            # The box already shows this dictation from the partials, so
            # appending would duplicate every word.
            self._replace_dictation(transcript)
        else:
            self._append_to_input(transcript)
        self._maybe_auto_submit()

    def _replace_dictation(self, transcript: str) -> None:
        """Swap the live partial for the finished transcript."""
        try:
            inp = self.query_one("#chat-input", TextArea)
        except Exception:  # noqa: BLE001 — panel closed mid-dictation
            return
        if getattr(self.app, "demo_mode", False):
            redactor = getattr(self.app, "redaction_service", None)
            if redactor is not None:
                transcript = redactor.scrub_stream(transcript)
        prefix = self._partial_prefix
        inp.load_text(f"{prefix} {transcript}".strip() if prefix else transcript)
        self._partial_prefix = ""

    def _maybe_auto_submit(self) -> None:
        """Send the dictated text when the user has opted into auto-submit.

        Deliberately routed through the same :meth:`_send` the Enter key
        uses, so an auto-submitted turn is indistinguishable downstream.
        Skipped while a reply is streaming — the transcript stays in the box
        rather than being dropped or queued.
        """
        voice_config = self._voice_config()
        if voice_config is None or not getattr(voice_config, "auto_submit", False):
            return
        if self._thinking:
            self.app.notify(
                "Dictation saved to the input box — a reply is still streaming.",
                severity="warning",
                markup=False,
            )
            return
        self._send()

    def _set_mic_state(self, *, recording: bool, transcribing: bool) -> None:
        """Store the voice flags and repaint the mic button + stats bar."""
        self._recording = recording
        self._transcribing = transcribing
        # The spinner has to start and stop with the transcribing flag, not
        # with any one call site: several paths (success, error, cancel)
        # clear the flag and every one of them must leave the timer stopped.
        if transcribing:
            self._start_spinner()
        else:
            self._stop_spinner()
        try:
            mic_btn = self.query_one("#btn-chat-mic", Button)
        except Exception:
            self._update_stats()
            return
        mic_btn.label = self._mic_label()
        mic_btn.disabled = transcribing or self._starting
        if recording:
            mic_btn.add_class("recording")
        else:
            mic_btn.remove_class("recording")
        self._update_stats()

    def _mic_label(self) -> str:
        """The glyph the mic button should currently show."""
        if self._transcribing:
            return _SPINNER_FRAMES[self._spinner_frame % len(_SPINNER_FRAMES)]
        return _MIC_RECORDING if self._recording else _MIC_IDLE

    def _start_spinner(self) -> None:
        """Begin animating the transcription spinner, if not already running."""
        if self._spinner_timer is not None:
            return
        self._spinner_frame = 0
        try:
            self._spinner_timer = self.set_interval(
                _SPINNER_INTERVAL, self._advance_spinner
            )
        except Exception:  # noqa: BLE001 — no running app (unit tests / teardown)
            self._spinner_timer = None

    def _stop_spinner(self) -> None:
        """Stop the spinner timer. Safe to call when it is not running."""
        timer, self._spinner_timer = self._spinner_timer, None
        if timer is None:
            return
        try:
            timer.stop()
        except Exception:  # noqa: BLE001 — already torn down
            logger.debug("Spinner timer stop failed", exc_info=True)

    def _advance_spinner(self) -> None:
        """Advance one spinner frame on the button and the stats bar."""
        self._spinner_frame += 1
        try:
            self.query_one("#btn-chat-mic", Button).label = self._mic_label()
        except Exception:  # noqa: BLE001 — the panel closed mid-transcription
            self._stop_spinner()
            return
        self._update_stats()

    def _append_to_input(self, transcript: str) -> None:
        """Append a transcript to the input box — never send it.

        Speech recognition is not reliable enough to dispatch a turn
        unreviewed, so the text always lands in the box for the user to
        edit and send.
        """
        try:
            inp = self.query_one("#chat-input", TextArea)
        except Exception:
            return
        # Demo mode redacts every on-screen surface, and a transcript is
        # on-screen content — an address spoken aloud must not survive
        # into a recording.
        if getattr(self.app, "demo_mode", False):
            redactor = getattr(self.app, "redaction_service", None)
            if redactor is not None:
                transcript = redactor.scrub_stream(transcript)
        existing = inp.text
        if existing.strip():
            inp.load_text(f"{existing.rstrip()} {transcript}")
        else:
            inp.load_text(transcript)
        inp.move_cursor(inp.document.end)
        self._do_focus_input()

    def _voice_prompt_hint(self) -> str:
        """Build a vocabulary hint from the fleet's server names.

        Instance names are proper nouns no general speech model has seen;
        passing them as leading context is what keeps ``web-1`` from being
        transcribed as ``web one``. The panel can be mounted before the
        instance list loads, so an empty fleet is normal.
        """
        hint = ""
        for inst in (getattr(self.app, "instances", []) or []):
            name = inst.get("name") or inst.get("id")
            if not name:
                continue
            candidate = f"{hint}, {name}" if hint else str(name)
            # Truncate on a whole-name boundary — a half-written hostname
            # biases the model toward a word that does not exist.
            if len(candidate) > _VOICE_PROMPT_MAX_CHARS:
                break
            hint = candidate
        return hint

    # ------------------------------------------------------------------
    # Spoken replies (voice output)
    # ------------------------------------------------------------------

    def _voice_output_service(self) -> Optional[Any]:
        """The spoken-reply service, or None when it cannot be resolved."""
        try:
            return getattr(self.app, "voice_output_service", None)
        except Exception:  # noqa: BLE001 — no active app during teardown/tests
            return None

    def _speak_last_reply(self) -> bool:
        """Hand the newest session message to the speaker, if it qualifies.

        The generic provider path never holds the reply string itself —
        ``chat_service.send_message`` appends it to the session — so the
        last message IS the reply. Anything that is not an assistant
        message (or is the error placeholder, filtered downstream) stays
        silent.

        Returns:
            True when a speak worker was dispatched (the conversation
            loop then waits for playback), False when nothing will play.
        """
        session = getattr(self, "_session", None)
        messages = getattr(session, "messages", None) or []
        if not messages:
            return False
        last = messages[-1]
        if getattr(last, "role", "") != "assistant":
            return False
        return self._maybe_speak_reply(getattr(last, "content", "") or "")

    def _maybe_speak_reply(self, text: str) -> bool:
        """Speak *text* aloud when spoken replies are switched on.

        All the text-level decisions live in :func:`resolve_spoken_reply`
        (pure); this method only wires the outcome to the service. The
        previous utterance is stopped first — replies must not overlap —
        and playback runs in its own ``voice_speak`` worker group so that
        neither a live capture (``voice``) nor the streaming consumer
        (``ai_chat``) is ever cancelled by speech starting or stopping.

        Returns:
            True when a speak worker was dispatched — the conversation
            loop uses this to decide whether the reply owns a SPEAKING
            phase or listening should resume immediately.
        """
        voice_config = self._voice_config()
        spoken = resolve_spoken_reply(
            text,
            tts_enabled=bool(getattr(voice_config, "tts_enabled", False)),
            demo_mode=bool(getattr(self.app, "demo_mode", False)),
            scrub=getattr(
                getattr(self.app, "redaction_service", None),
                "scrub_stream",
                None,
            ),
        )
        if not spoken:
            return False
        service = self._voice_output_service()
        if service is None:
            return False
        try:
            # A reply that starts speaking while the previous one is still
            # going must supersede it, not queue behind it.
            service.stop()
        except Exception:  # noqa: BLE001 — stop() is documented never to raise
            logger.debug("voice output stop failed", exc_info=True)
        # Pin the cancellation token now, synchronously on the event loop:
        # the worker below reaches service.speak() via thread hops, and a
        # stop() (ctrl+o, a superseding reply, unmount) landing in that
        # window must retire this utterance rather than race it into the
        # queue and play after the stop that should have silenced it.
        epoch_fn = getattr(service, "current_epoch", None)
        epoch = epoch_fn() if callable(epoch_fn) else None
        self.run_worker(
            self._do_speak(service, spoken, epoch=epoch),
            exclusive=True,
            name="voice_speak",
            group="voice_speak",
        )
        return True

    async def _do_speak(
        self, service: Any, text: str, epoch: Optional[int] = None
    ) -> None:
        """Worker: synthesise and play one reply off the event loop.

        An unavailable service (deps not installed, model missing, no
        output device) is a quiet skip rather than a toast: the readiness
        story lives in Settings > Voice Input, and repeating it on every
        reply would nag. Actual synthesis/playback failures do notify.
        """
        self._speak_seq += 1
        seq = self._speak_seq
        try:
            available = await asyncio.to_thread(service.is_available)
        except Exception:  # noqa: BLE001 — a broken probe must not break the panel
            logger.debug("voice output availability probe failed", exc_info=True)
            # The conversation loop was promised a SPEAKING phase; with
            # nothing to play it must resume listening, not hang THINKING.
            self._notify_convo_reply_done(False)
            return
        if not available:
            logger.debug(
                "spoken reply skipped: %s",
                service.unavailable_reason() or "voice output unavailable",
            )
            self._notify_convo_reply_done(False)
            return

        # Bridge the conversation loop into SPEAKING before the first
        # audio plays, inside this coroutine so the ordering against
        # speaking_finished below is structural, not a worker race. The
        # hop through a thread keeps the service's callbacks off the UI
        # thread, where the marshalling helpers expect them.
        convo = self._conversation_service() if self._conversation_active else None
        if convo is not None:
            try:
                await asyncio.to_thread(convo.speaking_started)
            except Exception:  # noqa: BLE001 — a state hiccup must not silence the reply
                logger.debug("conversation speaking_started failed", exc_info=True)

        self._set_speaking(True)
        try:
            if epoch is None:
                await asyncio.to_thread(service.speak, text)
            else:
                await asyncio.to_thread(service.speak, text, epoch=epoch)
        except Exception as exc:  # noqa: BLE001 — surface the failure, stay alive
            logger.debug("spoken reply failed", exc_info=True)
            self.app.notify(
                f"Spoken reply failed: {exc}",
                severity="warning",
                markup=False,
            )
        finally:
            # Only the newest worker owns the indicator: a superseded
            # utterance winding down must not wipe the flag its
            # replacement just set.
            if seq == self._speak_seq:
                self._set_speaking(False)
                if self._conversation_active:
                    # Playback drained (or was cut short): the loop
                    # resumes listening. Dispatched, not awaited — this
                    # finally may be running under a cancellation.
                    self._convo_call("speaking_finished")

    def _set_speaking(self, speaking: bool) -> None:
        """Store the speaking flag and repaint the stats-bar indicator."""
        self._speaking = speaking
        self._update_stats()

    def _interrupt_speech(self) -> None:
        """Stop spoken-reply playback promptly. Never raises.

        Called from the ctrl+o binding, from a new send superseding the
        reply being read, and from unmount teardown — all places where a
        speech failure must not become a panel failure.
        """
        service = self._voice_output_service()
        if service is not None:
            try:
                service.stop()
            except Exception:  # noqa: BLE001 — stop() is documented never to raise
                logger.debug("voice output stop failed", exc_info=True)
        if self._speaking:
            self._set_speaking(False)

    # ------------------------------------------------------------------
    # Streaming speech (Servonaut SSE path)
    # ------------------------------------------------------------------
    #
    # On the streaming provider path speech starts mid-reply: token
    # deltas feed a per-turn sentence chunker, the first complete
    # sentence opens an utterance session on the output service (and, in
    # conversation mode, drives THINKING -> SPEAKING), later sentences
    # queue behind it, and the finalise path flushes the remainder and
    # ends the session. The session's exactly-once completion callback
    # is what closes SPEAKING — never per-sentence events, which would
    # reopen the microphone mid-reply. The generic (non-streaming)
    # providers keep the final-reply path in ``_maybe_speak_reply``.

    def _begin_turn_speech(self) -> None:
        """Arm streaming speech for one Servonaut turn. Cheap, no probes.

        Only the text-level switches are consulted here; availability
        (deps, model, device) blocks, so it is probed off the event loop
        when the first sentence arrives. When spoken replies are off, or
        no output service is wired, the turn simply streams silently.
        """
        self._turn_chunker = None
        self._turn_speech_session = None
        self._turn_speech_suppressed = False
        voice_config = self._voice_config()
        if not bool(getattr(voice_config, "tts_enabled", False)):
            return
        if self._voice_output_service() is None:
            return
        from servonaut.services.voice_stream_chunker import VoiceStreamChunker
        self._turn_chunker = VoiceStreamChunker()

    async def _stream_speech_feed(self, delta: str) -> None:
        """Advance the turn's chunker with one token delta; speak sentences."""
        if self._turn_chunker is None or self._turn_speech_suppressed:
            return
        try:
            sentences = self._turn_chunker.feed(delta)
        except Exception:  # noqa: BLE001 — a chunker fault must not kill the stream
            logger.debug("stream speech chunker failed", exc_info=True)
            self._turn_chunker = None
            return
        for sentence in sentences:
            await self._stream_speech_emit(sentence)

    async def _stream_speech_emit(self, sentence: str) -> None:
        """Gate one sentence and hand it to the utterance session."""
        if self._turn_speech_suppressed:
            return
        spoken = resolve_spoken_sentence(
            sentence,
            demo_mode=bool(getattr(self.app, "demo_mode", False)),
            scrub=getattr(
                getattr(self.app, "redaction_service", None),
                "scrub_stream",
                None,
            ),
        )
        if not spoken:
            return
        if self._turn_speech_session is None:
            if not await self._start_turn_speech_session():
                return
        try:
            self._turn_speech_session.enqueue(spoken)
        except Exception:  # noqa: BLE001 — enqueue is documented never to raise
            logger.debug("stream speech enqueue failed", exc_info=True)

    async def _start_turn_speech_session(self) -> bool:
        """First sentence of the turn: open the session, enter SPEAKING.

        Mirrors :meth:`_maybe_speak_reply`'s ordering rules: the
        availability probe runs off the event loop (the first one does a
        blocking device enumeration), the previous utterance is stopped
        (a reply must supersede, not queue behind, the one being read),
        and the cancellation epoch is pinned synchronously after that
        stop so an interrupt landing mid-turn retires every sentence
        still to come.
        """
        service = self._voice_output_service()
        if service is None:
            self._turn_speech_suppressed = True
            return False
        try:
            available = await asyncio.to_thread(service.is_available)
        except Exception:  # noqa: BLE001 — a broken probe must not break the stream
            logger.debug("voice output availability probe failed", exc_info=True)
            available = False
        if not available:
            # Quiet skip, same as _do_speak: the readiness story lives in
            # Settings, and a toast per streamed turn would nag.
            self._turn_speech_suppressed = True
            return False
        try:
            service.stop()
        except Exception:  # noqa: BLE001 — stop() is documented never to raise
            logger.debug("voice output stop failed", exc_info=True)
        epoch_fn = getattr(service, "current_epoch", None)
        epoch = epoch_fn() if callable(epoch_fn) else None
        # Newest-owner token for the speaking indicator, shared with the
        # final-reply workers so whichever speech surface ran last owns
        # the flag.
        self._speak_seq += 1
        seq = self._speak_seq
        try:
            self._turn_speech_session = service.begin_utterance(
                on_complete=lambda played, seq=seq: (
                    self._post_stream_speech_complete(seq, played)
                ),
                epoch=epoch,
            )
        except Exception:  # noqa: BLE001 — begin_utterance is documented never to raise
            logger.debug("could not open an utterance session", exc_info=True)
            self._turn_speech_suppressed = True
            return False
        # A session can be born superseded: a cross-thread stop() (an
        # interrupt, or a superseding turn) landing between the epoch pin
        # above and begin_utterance retires it on the spot — its
        # completion has already fired, with the CURRENT seq, so the
        # seq-guarded cleanup ran before ``_set_speaking(True)`` would.
        # Entering SPEAKING here would wedge the loop behind a session
        # that can never complete again. Keep the retired session in
        # place (it silently swallows the rest of the turn's sentences,
        # exactly like a live session an interrupt retires) and report
        # failure so no speech state is entered. ``is True``: test
        # doubles must not read as settled.
        if getattr(self._turn_speech_session, "is_settled", False) is True:
            return False
        # Bridge the conversation loop into SPEAKING before the first
        # audio plays. THINKING -> SPEAKING while deltas still arrive is
        # a legal edge — the mic is closed in both states. The thread
        # hop keeps the service's callbacks off the UI thread, where the
        # marshalling helpers expect them.
        convo = self._conversation_service() if self._conversation_active else None
        if convo is not None:
            try:
                await asyncio.to_thread(convo.speaking_started)
            except Exception:  # noqa: BLE001 — a state hiccup must not silence the reply
                logger.debug("conversation speaking_started failed", exc_info=True)
        self._set_speaking(True)
        return True

    def _post_stream_speech_complete(self, seq: int, played: bool) -> None:
        """Utterance completion (any thread) -> UI thread."""
        self._convo_marshal(self._handle_stream_speech_complete, seq, played)

    def _handle_stream_speech_complete(self, seq: int, played: bool) -> None:
        """The streamed utterance finished playing or was cut short.

        Only the newest speech owner may act — a superseded session's
        completion must not wipe the indicator (or reopen the mic) under
        its replacement. ``speaking_finished`` is a strict no-op outside
        conversation SPEAKING, so firing it after an interrupt already
        moved the machine is safe.
        """
        if seq != self._speak_seq:
            return
        self._set_speaking(False)
        if self._conversation_active:
            self._convo_call("speaking_finished")

    def _finish_turn_speech(self) -> Tuple[bool, bool]:
        """Turn finalised: flush the chunker, end the utterance session.

        Returns:
            ``(streamed, owns_edge)``. ``streamed`` is True when a
            streaming session spoke (any of) this reply — the final-reply
            speech path must not run, it would read the reply again.
            ``owns_edge`` is True only when that session is still live,
            i.e. the conversation SPEAKING -> LISTENING edge belongs to
            its completion callback. A session whose exactly-once
            completion has ALREADY fired (an interrupt or a superseding
            turn stopped playback mid-stream) can never fire again, so
            it does not own the edge: the finalise path must resume the
            conversation loop itself, or a transcript dropped as
            ``drop_busy`` while this turn was still streaming leaves the
            loop stranded in THINKING with the microphone closed.
        """
        chunker = self._turn_chunker
        session = self._turn_speech_session
        self._turn_chunker = None
        self._turn_speech_session = None
        self._turn_speech_suppressed = False
        if session is None:
            return (False, False)
        # ``is True``: the session may be a test double whose attribute
        # is not a real bool; only an explicit True means settled.
        settled = getattr(session, "is_settled", False) is True
        if settled:
            # Retired mid-stream: enqueues would be dropped and end()
            # fires nothing, so skip the flush and report the spent edge.
            try:
                session.end()
            except Exception:  # noqa: BLE001 — end() is documented never to raise
                logger.debug("utterance session end failed", exc_info=True)
            return (True, False)
        if chunker is not None:
            try:
                for sentence in chunker.flush():
                    spoken = resolve_spoken_sentence(
                        sentence,
                        demo_mode=bool(getattr(self.app, "demo_mode", False)),
                        scrub=getattr(
                            getattr(self.app, "redaction_service", None),
                            "scrub_stream",
                            None,
                        ),
                    )
                    if spoken:
                        session.enqueue(spoken)
            except Exception:  # noqa: BLE001 — the flush must not break finalise
                logger.debug("stream speech flush failed", exc_info=True)
        try:
            session.end()
        except Exception:  # noqa: BLE001 — end() is documented never to raise
            logger.debug("utterance session end failed", exc_info=True)
        return (True, True)

    def _abort_turn_speech(self) -> None:
        """Error/cancel path: silence mid-reply speech, settle the session.

        A turn that ends as an Error bubble must not keep reading the
        prose it streamed before failing. Stopping the service retires
        the session (its completion fires with ``played_to_end=False``,
        which closes SPEAKING through the normal callback); the
        follow-up ``end()`` is belt-and-braces for a service whose stop
        failed, so the conversation loop can never be stranded.
        """
        session = self._turn_speech_session
        self._turn_chunker = None
        self._turn_speech_session = None
        self._turn_speech_suppressed = False
        if session is None:
            return
        service = self._voice_output_service()
        if service is not None:
            try:
                service.stop()
            except Exception:  # noqa: BLE001 — stop() is documented never to raise
                logger.debug("voice output stop failed", exc_info=True)
        try:
            session.end()
        except Exception:  # noqa: BLE001 — end() is documented never to raise
            logger.debug("utterance session end failed", exc_info=True)

    # ------------------------------------------------------------------
    # Hands-free conversation mode
    # ------------------------------------------------------------------

    def _conversation_service(self) -> Optional[Any]:
        """The conversation-loop controller, or None when not wired up."""
        try:
            return getattr(self.app, "voice_conversation_service", None)
        except Exception:  # noqa: BLE001 — no active app during teardown/tests
            return None

    def _toggle_conversation(self) -> None:
        """The one conversation control: start, interrupt, or stop.

        Idle: start the loop (readiness is checked on a worker — every
        probe blocks). Speaking: cut the reply short and listen again.
        Any other active state: end the session cleanly.
        """
        service = self._conversation_service()
        if service is None:
            self.app.notify(
                "Conversation mode unavailable.",
                severity="warning",
                markup=False,
            )
            return

        if self._conversation_active:
            if self._conversation_state == "speaking":
                self._convo_call("interrupt")
            else:
                self._convo_call("stop")
            return

        voice_config = self._voice_config()
        if voice_config is not None and not voice_config.enabled:
            self.app.notify(
                "Voice input is switched off — enable it in "
                "Settings > Voice Input first.",
                severity="warning",
                markup=False,
            )
            return

        # A push-to-talk capture in flight owns the input service; the
        # loop must not steal the stream from under it.
        if self._recording or self._transcribing or self._starting:
            self.app.notify(
                "Finish the current dictation before starting a conversation.",
                severity="warning",
                markup=False,
            )
            return

        self.run_worker(
            self._do_start_conversation(service),
            exclusive=False,
            name="voice_convo_start",
            # Own group: stop/reply_started can block briefly on stream
            # teardown, and neither the capture group (``voice``) nor the
            # exclusive chat group may be disturbed by loop control.
            group="voice_convo",
        )

    def _maybe_autostart_conversation(self) -> None:
        """Start the loop on mount when the user opted in via Settings.

        ``voice.conversation_mode`` is the default-on-open switch; the
        toggle key remains the per-session control either way. Quietly
        skipped when voice is off or the controller is missing — an
        unconfigured install must not greet every panel open with a toast
        about a feature it never asked for.
        """
        voice_config = self._voice_config()
        if voice_config is None or not getattr(voice_config, "enabled", False):
            return
        if not getattr(voice_config, "conversation_mode", False):
            return
        service = self._conversation_service()
        if service is None or self._conversation_active:
            return
        self.run_worker(
            self._do_start_conversation(service),
            exclusive=False,
            name="voice_convo_autostart",
            group="voice_convo",
        )

    def _vad_model_ok(self) -> bool:
        """Whether the voice-activity model the loop needs is on disk."""
        try:
            from servonaut.services.voice_engines import (
                is_silero_vad_model_present,
            )
            return is_silero_vad_model_present()
        except Exception:  # noqa: BLE001 — a broken probe reads as not ready
            logger.debug("voice-activity model probe failed", exc_info=True)
            return False

    async def _do_start_conversation(self, service: Any) -> None:
        """Worker: probe readiness, then start the loop.

        Every probe here blocks (device enumeration, model stat), so the
        whole readiness pass runs off the event loop. The verdicts feed
        the pure :func:`resolve_conversation_start`, which either clears
        the start or names the FIRST missing piece and where to fix it.
        """
        voice_config = self._voice_config()
        input_service = getattr(self.app, "voice_input_service", None)
        input_available = False
        input_reason = ""
        if input_service is not None:
            try:
                input_available = await asyncio.to_thread(input_service.is_available)
            except Exception:  # noqa: BLE001 — a broken probe reads as unavailable
                logger.debug("voice input probe failed", exc_info=True)
            if not input_available:
                try:
                    input_reason = input_service.unavailable_reason() or ""
                except Exception:  # noqa: BLE001 — the reason is best-effort
                    input_reason = ""

        stt_model_ok = True
        if input_available:
            stt_model_ok = not await self._model_missing_reason()

        vad_model_ok = await asyncio.to_thread(self._vad_model_ok)

        # Spoken replies off means playback never runs this session, so
        # its readiness is irrelevant — probing it anyway would gate a
        # dictation-only loop on a synthesis stack it will never touch.
        tts_enabled = bool(getattr(voice_config, "tts_enabled", False))
        output_available = False
        output_reason = ""
        if tts_enabled:
            output_service = self._voice_output_service()
            if output_service is not None:
                try:
                    output_available = await asyncio.to_thread(
                        output_service.is_available
                    )
                except Exception:  # noqa: BLE001 — a broken probe reads as unavailable
                    logger.debug("voice output probe failed", exc_info=True)
                if not output_available:
                    try:
                        output_reason = output_service.unavailable_reason() or ""
                    except Exception:  # noqa: BLE001 — the reason is best-effort
                        output_reason = ""

        message = resolve_conversation_start(
            voice_enabled=bool(getattr(voice_config, "enabled", False)),
            input_available=input_available,
            input_reason=input_reason,
            stt_model_ok=stt_model_ok,
            vad_model_ok=vad_model_ok,
            output_available=output_available,
            output_reason=output_reason,
            tts_enabled=tts_enabled,
        )
        if message:
            self.app.notify(message, severity="warning", markup=False)
            return

        # Callbacks before start(): the first state transition fires from
        # inside start(), and it must not be lost.
        service.set_state_callback(self._post_convo_state)
        service.set_transcript_callback(self._post_convo_transcript)
        service.set_error_callback(self._post_convo_error)
        service.set_stopped_callback(self._post_convo_stopped)
        try:
            await asyncio.to_thread(service.start)
        except asyncio.CancelledError:
            # The panel went away (unmount cancels its workers) while
            # start() was still running on the executor thread — and that
            # thread WILL finish the start, opening a microphone nobody
            # owns. Retire the orphan from a plain daemon thread: workers
            # are cancelled with us, and the stop must wait for start()
            # to actually land before it can take effect.
            threading.Thread(
                target=_stop_orphaned_conversation,
                args=(service,),
                name="voice-convo-abort",
                daemon=True,
            ).start()
            raise
        except Exception as exc:  # noqa: BLE001 — VoiceConversationError and friends
            logger.debug("conversation start failed", exc_info=True)
            self.app.notify(
                str(exc) or "Could not start conversation mode.",
                severity="error",
                markup=False,
            )
            return

        self._conversation_active = True
        if self._conversation_state == "idle":
            self._conversation_state = "listening"
        self._sync_convo_button()
        self._update_stats()
        self.app.notify(
            f"Conversation mode on — speak when ready. "
            f"{_CONVO_TOGGLE_KEY} stops it.",
            severity="information",
            markup=False,
        )

    def _convo_call(self, method_name: str) -> None:
        """Dispatch one loop-control call on the conversation worker group.

        ``stop`` / ``reply_started`` / ``interrupt`` can block briefly on
        stream teardown, so none of them may run on the event loop; and
        the service fires its callbacks from the calling thread, so the
        thread hop also keeps them where the marshalling helpers expect
        them. Unknown methods and dispatch failures are quietly logged —
        loop control is best-effort by design.
        """
        service = self._conversation_service()
        if service is None:
            return
        method = getattr(service, method_name, None)
        if not callable(method):
            return
        try:
            self.run_worker(
                self._do_convo_call(method, method_name),
                exclusive=False,
                name=f"voice_convo_{method_name}",
                group="voice_convo",
            )
        except Exception:  # noqa: BLE001 — a teardown-time dispatch may find no app
            logger.debug("could not dispatch %s", method_name, exc_info=True)

    async def _do_convo_call(self, method: Any, method_name: str) -> None:
        """Worker: run one (possibly blocking) loop-control call."""
        try:
            await asyncio.to_thread(method)
        except Exception:  # noqa: BLE001 — control calls are documented never to raise
            logger.debug("conversation %s failed", method_name, exc_info=True)

    # -- callback marshalling (service threads -> UI thread) -----------

    def _convo_marshal(self, handler: Any, *args: Any) -> None:
        """Run *handler* on the UI thread, wherever we were called from.

        Service callbacks usually arrive from the loop's worker threads,
        where ``call_from_thread`` is the only safe road to a widget. A
        transition the panel itself drove inline (teardown paths) arrives
        already ON the UI thread — detected by comparing thread identity
        against the app's, NOT by catching ``call_from_thread``'s error:
        that call also re-raises exceptions the handler itself raised
        after running (possibly with side effects) on the UI thread, and
        a blanket catch-and-retry would execute such a handler a second
        time. Handlers guard their widget access, so the no-app case
        degrades to a debug line either way.
        """
        try:
            app = self.app
        except Exception:  # noqa: BLE001 — no active app during teardown/tests
            app = None
        # ``App._thread_id`` is private Textual API (present on the
        # pinned 8.x line). If an upgrade ever renames it, the getattr
        # yields None and the comparison goes False — so a running event
        # loop on THIS thread is accepted as a second signal, keeping
        # UI-thread calls direct instead of routing them into
        # ``call_from_thread`` (which raises when called from its own
        # thread, silently eating every teardown-path update below).
        on_ui_thread = (
            app is None
            or getattr(app, "_thread_id", None) == threading.get_ident()
        )
        if not on_ui_thread:
            try:
                asyncio.get_running_loop()
                on_ui_thread = True
            except RuntimeError:
                pass
        if on_ui_thread:
            try:
                handler(*args)
            except Exception:  # noqa: BLE001 — a UI update must never kill the loop
                logger.debug("conversation UI update failed", exc_info=True)
            return
        try:
            app.call_from_thread(handler, *args)
        except Exception:  # noqa: BLE001 — handler failure, or the app is gone
            logger.debug("conversation UI update failed", exc_info=True)

    def _post_convo_state(self, state: Any) -> None:
        self._convo_marshal(
            self._apply_convo_state, getattr(state, "value", str(state))
        )

    def _post_convo_transcript(self, text: str) -> None:
        self._convo_marshal(self._handle_convo_transcript, text)

    def _post_convo_error(self, message: str) -> None:
        self._convo_marshal(self._handle_convo_error, message)

    def _post_convo_stopped(self, reason: str) -> None:
        self._convo_marshal(self._handle_convo_stopped, reason)

    # -- UI-thread handlers --------------------------------------------

    def _apply_convo_state(self, state_value: str) -> None:
        """Mirror a loop state change into the panel's indicators."""
        self._conversation_state = state_value
        if state_value != "idle":
            # A live transition proves the session is on, whatever the
            # start worker has gotten around to recording.
            self._conversation_active = True
        self._sync_convo_button()
        self._update_stats()

    def _handle_convo_transcript(self, text: str) -> None:
        """Deliver (or safely drop) one finished utterance.

        The loop is already in THINKING with the mic closed when this
        fires. The decision matrix is pure
        (:func:`resolve_transcript_action`); this method wires each
        verdict:

        - ``send``: render the transcript into the input box and go
          through the ordinary :meth:`_send`, so a spoken turn is
          indistinguishable downstream from a typed one.
        - ``drop_modal`` / ``drop_empty``: nothing is sent — the modal
          rule is absolute — and ``reply_finished`` resumes listening.
        - ``drop_busy``: nothing is sent AND the loop is left in
          THINKING: the in-flight turn's completion hooks own the
          machine, and resuming listening early would reopen the mic
          under that turn's spoken reply.
        """
        action = resolve_transcript_action(
            text,
            modal_blocking=self._modal_blocking(),
            thinking=self._thinking,
        )
        if action == "send":
            try:
                self._render_conversation_transcript(text)
                self._send()
            except Exception:  # noqa: BLE001 — a failed send must not strand the loop
                # Render (the demo-mode scrub included — failing here
                # keeps the raw transcript OFF the screen, matching the
                # fail-closed spoken-path helpers) or dispatch raised.
                # Without the guard the exception would die in the
                # marshalling wrapper and leave the loop in THINKING
                # with the microphone closed; the ``_thinking`` check
                # below resumes listening instead whenever no turn
                # actually started.
                logger.debug("conversation send failed", exc_info=True)
            if not self._thinking:
                # _send has silent early-outs after the verdict was
                # decided (input box gone, or demo-mode scrubbing left
                # nothing to send). No turn started, so no completion
                # hook will ever fire reply_finished — resume listening
                # here or the loop is stranded in THINKING.
                self._convo_call("reply_finished")
            return
        if action == "drop_modal":
            # Resume listening BEFORE the toast: if the notify raises on
            # a dying panel the loop must not be left stuck in THINKING.
            self._convo_call("reply_finished")
            self.app.notify(
                "Heard you, but a confirmation dialog is open — "
                "close it and say that again.",
                severity="warning",
                markup=False,
            )
            return
        if action == "drop_busy":
            self.app.notify(
                "Heard you, but a reply is still streaming — "
                "say that again in a moment.",
                severity="warning",
                markup=False,
            )
            return
        # drop_empty — the service filters empty transcripts itself, so
        # this is purely defensive: resume listening, burn nothing.
        self._convo_call("reply_finished")

    def _render_conversation_transcript(self, transcript: str) -> None:
        """Put the utterance into the input box the send will read.

        Replaces the box outright: in a hands-free session the box is the
        loop's staging area, not a draft under composition. Demo mode
        scrubs first — a transcript is on-screen content.
        """
        try:
            inp = self.query_one("#chat-input", TextArea)
        except Exception:  # noqa: BLE001 — panel closed mid-delivery
            return
        if getattr(self.app, "demo_mode", False):
            redactor = getattr(self.app, "redaction_service", None)
            if redactor is not None:
                transcript = redactor.scrub_stream(transcript)
        inp.load_text(transcript)

    def _handle_convo_error(self, message: str) -> None:
        """Surface a loop failure; the stopped callback lands right after."""
        self.app.notify(
            message or "Conversation mode failed.",
            severity="error",
            markup=False,
        )

    def _handle_convo_stopped(self, reason: str) -> None:
        """The loop landed in IDLE: clear the session and word the notice."""
        self._conversation_active = False
        self._conversation_state = "idle"
        if reason == "idle_timeout":
            voice_config = self._voice_config()
            seconds = getattr(voice_config, "conversation_idle_seconds", 60)
            self.app.notify(
                f"Stopped listening — no speech for {seconds}s. "
                f"{_CONVO_TOGGLE_KEY} starts a new conversation.",
                severity="information",
                markup=False,
            )
        elif reason == "user":
            self.app.notify(
                "Conversation mode off.",
                severity="information",
                markup=False,
            )
        # "error": the error callback already explained itself.
        self._sync_convo_button()
        self._update_stats()

    # -- helpers --------------------------------------------------------

    def _modal_blocking(self) -> bool:
        """Whether a modal (any confirmation included) is on the stack."""
        try:
            stack = self.app.screen_stack
        except Exception:  # noqa: BLE001 — no app means nothing safe to send to
            return True
        return is_modal_blocking(stack)

    def _sync_convo_button(self) -> None:
        """Repaint the conversation button for the current state."""
        try:
            btn = self.query_one("#btn-chat-convo", Button)
        except Exception:  # noqa: BLE001 — nothing to paint before compose
            return
        btn.label = conversation_button_label(self._conversation_state)
        if self._conversation_state != "idle":
            btn.add_class("convo-active")
        else:
            btn.remove_class("convo-active")

    def _notify_convo_reply_done(self, spoke: bool) -> None:
        """A chat turn settled: resume listening unless playback owns it.

        When a speak worker was dispatched the SPEAKING -> LISTENING edge
        belongs to :meth:`_do_speak`; calling ``reply_finished`` here too
        would reopen the microphone under the reply being read aloud.
        """
        if not self._conversation_active or spoke:
            return
        self._convo_call("reply_finished")

    def _teardown_conversation(self) -> None:
        """Unmount-time stop: no callbacks, no toasts, no orphan capture.

        Callbacks are unregistered BEFORE the stop so the teardown cannot
        trigger UI work against a panel that is going away.

        Unconditional on purpose — not gated on ``_conversation_active``:
        a start worker cancelled mid-``start()`` never sets that flag even
        though the loop may already be live (or about to be), so the flag
        proves nothing at unmount. ``stop()`` is documented as a safe
        no-op when the loop is idle, and it is called with ``join=False``
        because this runs on the UI thread — joining a listener thread
        that is mid-transcription would freeze the whole interface.
        """
        self._conversation_active = False
        self._conversation_state = "idle"
        service = self._conversation_service()
        if service is None:
            return
        try:
            service.set_state_callback(None)
            service.set_transcript_callback(None)
            service.set_error_callback(None)
            service.set_stopped_callback(None)
            service.stop(join=False)
        except Exception:  # noqa: BLE001 — teardown must never block the unmount
            logger.debug("conversation teardown failed", exc_info=True)

    def _send(self) -> None:
        """Read the input field and dispatch the message as a worker."""
        if self._thinking:
            return
        try:
            inp = self.query_one("#chat-input", TextArea)
        except Exception:
            return

        text = inp.text.strip()
        if not text:
            return

        # The user has moved on: a reply still being read aloud from the
        # previous turn must stop before the next one dispatches.
        self._interrupt_speech()

        inp.load_text("")
        self._thinking = True
        self._show_thinking()

        # Risk register §4: keep the streaming consumer in a dedicated
        # worker group so it doesn't collide with memory probes or
        # other background work. ``ai_chat`` is the chat-panel canonical
        # group name for this and related workers (topup, history load).
        self.run_worker(
            self._do_send(text),
            exclusive=False,
            name="ai_chat_send",
            group="ai_chat",
        )

        # A typed send while the loop listens must close the microphone
        # first (half-duplex): reply_started is a no-op when the turn came
        # from a transcript (the loop is already THINKING) and for plain,
        # non-conversation sends.
        if self._conversation_active:
            self._convo_call("reply_started")

    async def _do_send(self, text: str) -> None:
        """Worker: send message to AI and refresh display.

        Wave-3 dispatch: if the active provider is Servonaut AI we route
        through :meth:`_do_send_servonaut` for streaming + tool-use; for
        any other provider the existing chat-service path runs unchanged.
        """
        active_provider = self._active_provider_name()
        if active_provider == "servonaut":
            await self._do_send_servonaut(text)
            return

        try:
            chat_service = self._get_chat_service()
            if chat_service is None:
                return
            if self._session is None:
                self._session = chat_service.create_session()

            # Resolve active instance and strip any @prefix from the text.
            inst, effective_text = self._resolve_active_instance(text)
            instance_id = inst.get("id") if inst else None
            instance_name = inst.get("name") if inst else None
            instance_provider = (inst.get("provider") or "custom") if inst else "custom"

            result = await chat_service.send_message(
                self._session,
                effective_text,
                status_callback=self._update_thinking_status,
                instance_id=instance_id,
                instance_name=instance_name,
                instance_provider=instance_provider,
                ai_provider=active_provider,
            )
            self._total_tokens += result.get("tokens_used", 0)
            cost = result.get("estimated_cost")
            if cost is not None:
                self._total_cost += cost
            self._model = result.get("model", "") or self._model
        except Exception as exc:
            from servonaut.services.chat_service import ChatMessage
            if self._session is not None:
                self._session.messages.append(  # type: ignore[union-attr]
                    ChatMessage(role="assistant", content=f"Error: {exc}")
                )
        finally:
            self._hide_thinking()
            self._thinking = False
            self._refresh_messages()
            # The reply is the session's newest message by now (appended
            # by send_message on success, or the Error placeholder the
            # speak decision filters out).
            spoke = self._speak_last_reply()
            # Conversation loop: with nothing to speak the turn is over
            # and listening resumes; with playback dispatched the speak
            # worker owns the SPEAKING -> LISTENING edge.
            self._notify_convo_reply_done(bool(spoke))

    # ------------------------------------------------------------------
    # Servonaut streaming path (T5 + T6 + T8 + T10)
    # ------------------------------------------------------------------

    async def _do_send_servonaut(self, text: str) -> None:
        """Worker: stream a Servonaut-AI chat turn, cancellation-safe.

        Every settled path inside :meth:`_run_servonaut_turn` clears
        ``_thinking`` itself, so ``_thinking`` still True in the finally
        means the coroutine exited without settling — in practice a
        worker cancellation (``CancelledError`` is a ``BaseException``
        the streaming body deliberately does not catch; the in-app
        trigger is loading a previous conversation, whose exclusive
        ``ai_chat`` worker cancels an in-flight send). Without this
        cleanup the typed-send guard stays locked, the spinner never
        leaves, and the conversation loop is stranded in THINKING with
        the microphone closed.
        """
        try:
            await self._run_servonaut_turn(text)
        finally:
            if self._thinking:
                self._thinking = False
                # A cancelled turn must not keep speaking sentences it
                # streamed before the cancellation, and its utterance
                # session must settle (completion fires False) so the
                # conversation loop cannot hang in SPEAKING.
                self._abort_turn_speech()
                # Widget work is guarded: an unmount-driven cancellation
                # may find the panel already torn down, and an exception
                # here would swallow the CancelledError this finally is
                # running under.
                try:
                    self._hide_thinking()
                    self._refresh_messages()
                except Exception:  # noqa: BLE001 — cleanup on a dying panel
                    logger.debug("post-cancel chat cleanup failed", exc_info=True)
                # A cancelled turn resumes listening explicitly — the
                # loop must never be stranded in THINKING.
                self._notify_convo_reply_done(False)

    async def _run_servonaut_turn(self, text: str) -> None:
        """Stream one Servonaut-AI chat turn end-to-end.

        C1 — refactored from a 136-LoC monolith into an orchestrator that
        delegates to three focused helpers:

        - :meth:`_servonaut_build_request_body` assembles the SSE request.
        - :meth:`_servonaut_consume_stream` opens the stream and yields events.
        - :meth:`_servonaut_handle_event` dispatches one event at a time.

        Risk register §4: ``ping`` events are absorbed inside ``ai_sse``
        so the UI thread never sees them.
        """
        from servonaut.services.chat_service import ChatMessage

        provider = getattr(self.app, "servonaut_provider", None)
        if provider is None:
            self.app.notify(
                "Servonaut AI not initialised.",
                severity="error",
                markup=False,
            )
            self._hide_thinking()
            self._thinking = False
            # The conversation loop closed the mic for this turn; a turn
            # that never started must hand the floor straight back.
            self._notify_convo_reply_done(False)
            return

        chat_service = self._get_chat_service()
        if chat_service is None:
            self._hide_thinking()
            self._thinking = False
            self._notify_convo_reply_done(False)
            return

        if self._session is None:
            self._session = chat_service.create_session()

        inst, effective_text = self._resolve_active_instance(text)

        self._session.messages.append(  # type: ignore[union-attr]
            ChatMessage(role="user", content=effective_text, provider="servonaut")
        )

        body_kwargs = self._servonaut_build_request_body(
            session_messages=self._session.messages,  # type: ignore[union-attr]
            instance=inst,
            chat_service=chat_service,
        )

        # Reset per-turn tool counter so finalise_turn can tell whether
        # tools ran when accumulated is empty.
        self._turn_tool_calls = 0
        # Arm streaming speech: token deltas feed a sentence chunker so
        # the reply can start being read aloud mid-stream.
        self._begin_turn_speech()
        accumulated = ""
        try:
            async for event in self._servonaut_consume_stream(
                provider, body_kwargs,
            ):
                accumulated = await self._servonaut_handle_event(
                    event, accumulated,
                )
                if event.get("event") == "done":
                    break
        except Exception as exc:
            # Stale conversation_id (deleted from another tab, expired,
            # etc.) → server returns 404 *before* the SSE body opens,
            # which surfaces as NotFoundError pre-stream. Drop the id
            # and retry once with a fresh conversation. We only retry
            # when the original request actually carried an id; a 404
            # without one means something else (route mismatch, etc.)
            # and should fall through to the generic error path.
            if (
                self._is_stale_conversation_404(exc)
                and body_kwargs.get("conversation_id")
                and accumulated == ""
            ):
                logger.info(
                    "ai chat: server 404 on conversation_id=%s — "
                    "dropping stale id and retrying once with a fresh "
                    "conversation",
                    body_kwargs.get("conversation_id"),
                )
                self._remote_conversation_id = None
                body_kwargs["conversation_id"] = None
                self._turn_tool_calls = 0
                try:
                    async for event in self._servonaut_consume_stream(
                        provider, body_kwargs,
                    ):
                        accumulated = await self._servonaut_handle_event(
                            event, accumulated,
                        )
                        if event.get("event") == "done":
                            break
                except Exception as retry_exc:
                    # A turn that ends as an Error bubble must not keep
                    # speaking the prose it streamed before failing.
                    self._abort_turn_speech()
                    self._handle_stream_error(retry_exc, accumulated)
                    self._hide_thinking()
                    self._thinking = False
                    self._refresh_messages()
                    # An errored turn resumes listening explicitly — the
                    # loop must never be stranded in THINKING.
                    self._notify_convo_reply_done(False)
                    return
            else:
                self._abort_turn_speech()
                self._handle_stream_error(exc, accumulated)
                self._hide_thinking()
                self._thinking = False
                self._refresh_messages()
                self._notify_convo_reply_done(False)
                return

        self._finalise_servonaut_turn(chat_service, accumulated)

    @staticmethod
    def _is_stale_conversation_404(exc: BaseException) -> bool:
        """Detect a 404 raised before the stream opens.

        Matches both ``NotFoundError`` (api_client.py exception type)
        and any ``APIError`` carrying ``status == 404``. We don't sniff
        the message text — the server's 404 envelope shape is internal
        and we shouldn't pin to it.
        """
        from servonaut.services.api_client import APIError, NotFoundError

        if isinstance(exc, NotFoundError):
            return True
        if isinstance(exc, APIError) and getattr(exc, "status", None) == 404:
            return True
        return False

    def _servonaut_build_request_body(
        self,
        *,
        session_messages: List[Any],
        instance: Optional[Dict[str, Any]],
        chat_service: Any,
    ) -> Dict[str, Any]:
        """Assemble the kwargs for :meth:`ServonautProvider.stream_chat`.

        Memory injection: when ``config.chat_inject_server_memory`` is on
        and the active turn has at least one in-scope instance with local
        memory, prepend a synthetic ``user``-role message containing one
        ``<CONTEXT name="server_memory:...">`` block per instance.  The
        backend chat system prompt teaches the model to trust these as
        ground truth; without them every turn re-runs SSH discovery.
        """
        max_history = getattr(chat_service, "_max_history", 20)
        recent = session_messages[-max_history:]
        api_messages = [
            {"role": m.role, "content": m.content} for m in recent
        ]
        context: Dict[str, Any] = {}
        instance_id = instance.get("id") if instance else None
        if instance_id:
            context["instance_ids"] = [instance_id]

        last_user_text = next(
            (m.content for m in reversed(recent) if m.role == "user"),
            "",
        )
        memory_block = self._build_memory_injection(
            instance=instance,
            prompt=last_user_text,
        )
        if memory_block:
            api_messages = [{"role": "user", "content": memory_block}] + api_messages

        return {
            "messages": api_messages,
            "system_prompt": "",
            "config": self.app.config_manager.get().ai_provider,
            "conversation_id": self._remote_conversation_id,
            "context": context or None,
            "allow_tools": True,
        }

    def _build_memory_injection(
        self,
        *,
        instance: Optional[Dict[str, Any]],
        prompt: str,
    ) -> str:
        """Return the assembled <CONTEXT> body or empty string.

        Three-state consent gate (config v5+):

        - ``decision == "allowed"`` AND ``chat_inject_server_memory=True``
          → assemble + return body.
        - ``decision == "denied"`` → return "" silently.
        - ``decision == "unset"``  → return "" AND, if there IS an
          in-scope instance with stored memory, schedule the consent
          modal so the user gets prompted exactly when injection would
          have fired.

        Catches every error so a memory-store hiccup never blocks a
        chat send — the model just falls back to today's behaviour
        (calling ``get_server_memory`` / SSH tools if it needs facts).
        """
        try:
            config = self.app.config_manager.get()
        except Exception:
            return ""

        decision = getattr(config, "chat_inject_server_memory_decision", "unset")
        if decision == "denied":
            return ""

        memory_service = getattr(self.app, "memory_service", None)
        config_memory = getattr(config, "memory", None)
        if memory_service is None or config_memory is None:
            return ""

        from servonaut.services.ai_memory_injector import (
            InstanceScope, build_memory_context, resolve_instance_scope,
        )

        explicit: List[Dict[str, Any]] = [instance] if instance else []
        candidates = list(getattr(self.app, "instances", []) or [])
        scopes: List[InstanceScope] = resolve_instance_scope(
            prompt=prompt,
            explicit=explicit,
            candidate_instances=candidates,
        )
        if not scopes:
            return ""

        if decision == "unset":
            # Don't inject — and ask. We push the modal once per in-scope
            # turn so the user is asked exactly when it would have fired,
            # not pre-emptively at app launch.
            self._maybe_push_consent_modal()
            return ""

        if not getattr(config, "chat_inject_server_memory", False):
            # decision=="allowed" but the toggle was flipped off —
            # respect the toggle as the immediate signal.
            return ""

        try:
            body, telemetry = build_memory_context(
                instances=scopes,
                prompt=prompt,
                memory_service=memory_service,
                config_memory=config_memory,
                redaction_enabled=getattr(
                    config_memory, "redaction_enabled", True,
                ),
            )
        except Exception as exc:
            logger.warning("memory injector failed: %s", exc)
            return ""

        if body:
            logger.info(
                "memory_injector chat=servonaut %s",
                telemetry.as_log_kv(),
            )
        return body

    def _maybe_push_consent_modal(self) -> None:
        """Push the consent modal once per session, capture the decision.

        Idempotent within a session (``_consent_modal_open`` flag) so a
        rapid sequence of chat sends doesn't stack modals.
        """
        if getattr(self, "_consent_modal_open", False):
            return
        self._consent_modal_open = True
        try:
            from servonaut.screens.memory_consent_modal import (
                MemoryInjectionConsentModal,
            )
        except Exception:
            self._consent_modal_open = False
            return

        def _on_dismiss(decision: Optional[str]) -> None:
            self._consent_modal_open = False
            if decision in ("allowed", "denied"):
                try:
                    self.app.config_manager.update(
                        chat_inject_server_memory_decision=decision,
                        chat_inject_server_memory=(decision == "allowed"),
                    )
                    self.app.notify(
                        "Memory injection: "
                        + ("enabled — next chat turn will include "
                           "server memory."
                           if decision == "allowed"
                           else "disabled. Change in Settings → AI "
                                "Provider any time."),
                        markup=False,
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to persist consent decision: %s", exc,
                    )

        try:
            self.app.push_screen(MemoryInjectionConsentModal(), _on_dismiss)
        except Exception as exc:
            self._consent_modal_open = False
            logger.warning("Could not push consent modal: %s", exc)

    async def _servonaut_consume_stream(
        self,
        provider: Any,
        body_kwargs: Dict[str, Any],
    ):
        """Open the SSE stream and yield events.

        Wrapping the provider call in its own helper keeps
        :meth:`_do_send_servonaut` short (C1) and gives test code a
        single seam to mock — patch this method, not the underlying
        provider, when exercising the orchestrator.
        """
        async for event in provider.stream_chat(
            body_kwargs["messages"],
            system_prompt=body_kwargs["system_prompt"],
            config=body_kwargs["config"],
            conversation_id=body_kwargs["conversation_id"],
            context=body_kwargs["context"],
            allow_tools=body_kwargs["allow_tools"],
        ):
            yield event

    async def _servonaut_handle_event(
        self,
        event: Dict[str, Any],
        accumulated: str,
    ) -> str:
        """Dispatch one streamed event; return the (possibly mutated)
        accumulated assistant text.

        Splitting this out of the orchestrator keeps the per-event
        decisions testable in isolation (C1).
        """
        etype = event.get("event")
        data = event.get("data") or {}
        if etype == "conversation":
            # Server emits this as the FIRST SSE frame of every
            # /api/ai/chat stream so the CLI learns the conversation_id
            # before any tool_call arrives. Without it, a turn whose
            # first model output is a tool_call would POST
            # /api/ai/chat/tool-result with an empty conversation_id and
            # 404. Older server builds don't emit this event — the
            # existing ``usage`` path below still captures the id as a
            # fallback.
            conv_id = data.get("conversation_id")
            if conv_id:
                self._remote_conversation_id = str(conv_id)
                # Pair the local session with the remote conversation
                # row so the unified history view can show "uploaded"
                # and the Local-tab paired delete can drop the remote
                # row too. Persist via save_session so the link
                # survives a process restart.
                if self._session is not None:
                    self._session.remote_conversation_id = str(conv_id)  # type: ignore[union-attr]
                    chat_service = self._get_chat_service()
                    if chat_service is not None:
                        try:
                            chat_service.save_session(self._session)
                        except Exception:
                            logger.debug(
                                "Failed to persist remote_conversation_id "
                                "on local session",
                                exc_info=True,
                            )
                logger.info(
                    "ai conversation event: conversation_id=%s", conv_id,
                )
            else:
                logger.warning(
                    "ai conversation event missing conversation_id: %r",
                    data,
                )
        elif etype == "token":
            delta = str(data.get("text") or "")
            accumulated += delta
            # Demo-mode: always scrub a DISPLAY COPY on every token;
            # `accumulated` (the raw text) is kept intact so that
            # _finalise_servonaut_turn persists the original content to disk.
            # Redaction is display-only: _refresh_messages applies scrub_stream
            # again at render time over the full stored message.
            # Performance: ~25–40µs × ~10 tokens/sec = 0.4ms/sec — invisible.
            display_accumulated = accumulated
            if getattr(self.app, "demo_mode", False) and getattr(self.app, "redaction_service", None) is not None:
                display_accumulated = self.app.redaction_service.scrub_stream(accumulated)
            # Live-update the thinking bubble with the running text so
            # the user sees streaming output without re-render. A2 —
            # ``_update_thinking_status`` escapes its argument before
            # interpolating into Rich markup.
            self._update_thinking_status(display_accumulated or "Thinking...")
            # Streaming speech: sentences completed by this delta start
            # (or extend) the turn's spoken utterance. After the display
            # update so the render never waits on the first-sentence
            # availability probe.
            await self._stream_speech_feed(delta)
        elif etype == "tool_call":
            await self._handle_streamed_tool_call(data)
        elif etype == "tool_result":
            # Server-executed tool result — render as a soft collapsed
            # row in messages.
            logger.info(
                "ai tool_result received: call=%s status=%s bytes=%s",
                data.get("tool_call_id"), data.get("status"),
                data.get("bytes"),
            )
            self._render_tool_result_row(data)
        elif etype == "usage":
            self._consume_usage_event(data)
        elif etype == "info":
            code = data.get("code", "info")
            message = data.get("message") or code
            # A1 — server-controlled ``code`` and ``message`` flow
            # straight into a notify. ``markup=False`` keeps brackets
            # literal.
            self.app.notify(
                f"{code}: {message}",
                severity="warning",
                timeout=4,
                markup=False,
            )
        elif etype == "done":
            pass  # caller breaks out of the loop
        else:
            logger.debug("Unhandled SSE event %r", etype)
        return accumulated

    def _finalise_servonaut_turn(
        self,
        chat_service: Any,
        accumulated: str,
    ) -> None:
        """Append the final assistant message + persist + refresh display."""
        from servonaut.services.chat_service import ChatMessage

        stripped = accumulated.strip()
        if stripped:
            final_text = stripped
        elif self._turn_tool_calls > 0:
            # Server emitted tool_call(s) but produced no continuation
            # tokens — the model didn't summarise the tool output. The
            # tool_result rows above show what each tool returned; this
            # bubble just acknowledges the model went silent so the
            # user isn't confused by an empty assistant message.
            final_text = (
                f"(model ran {self._turn_tool_calls} tool"
                f"{'s' if self._turn_tool_calls != 1 else ''} but didn't "
                "summarise — see tool output above)"
            )
            logger.info(
                "Servonaut turn finished with empty text after %d tool call(s); "
                "rendering tool-only fallback bubble",
                self._turn_tool_calls,
            )
        else:
            final_text = "(no response)"
            logger.info(
                "Servonaut turn finished with empty text and zero tool calls — "
                "stream closed without emitting any tokens",
            )
        self._session.messages.append(  # type: ignore[union-attr]
            ChatMessage(
                role="assistant", content=final_text, provider="servonaut",
            )
        )

        # Auto-title from first user message (mirrors chat_service).
        if (
            self._session.title == "New Chat"  # type: ignore[union-attr]
            and len(self._session.messages) >= 2  # type: ignore[union-attr]
        ):
            first_msg = self._session.messages[0].content  # type: ignore[union-attr]
            self._session.title = first_msg[:50] + (  # type: ignore[union-attr]
                "..." if len(first_msg) > 50 else ""
            )

        try:
            chat_service.save_session(self._session)
        except Exception:
            logger.debug("save_session failed", exc_info=True)

        self._hide_thinking()
        self._thinking = False
        self._refresh_messages()

        # Streaming speech first: when the turn's session already spoke
        # (or is speaking) the reply, speaking the final text again would
        # repeat the reply. Otherwise fall back to the final-reply path;
        # the ``stripped`` gate keeps the "(no response)" and tool-only
        # fallback bubbles silent (and error paths never reach this
        # method at all).
        streamed, owns_edge = self._finish_turn_speech()
        if not streamed and stripped:
            owns_edge = self._maybe_speak_reply(stripped)
        # Conversation loop: a turn whose speech does not own the
        # SPEAKING -> LISTENING edge resumes listening now — that covers
        # both the unspoken turn AND a streamed session that an interrupt
        # already retired (its completion has fired and can never fire
        # again; ``reply_finished`` is a strict no-op unless the loop is
        # in THINKING, so this can never reopen the mic under playback).
        # A live speech owner (utterance session or speak worker) keeps
        # the edge for its completion callback.
        self._notify_convo_reply_done(bool(owns_edge))

        # T10 watcher — a successful turn proves the upstream is healthy
        # right now, so any failures inside the trailing 60s window are
        # historical noise. Clearing prevents the fallback modal from
        # firing on a single new failure that's only paired with stale
        # entries.
        if self._upstream_failures:
            self._upstream_failures.clear()

    async def _handle_streamed_tool_call(self, data: Dict[str, Any]) -> None:
        """Drive the AI tool-bridge for a single ``tool_call`` SSE event.

        Pushes the right confirm modal (single y/n vs typed RUN) based
        on ``guard_level``, awaits the user's choice, then runs the
        tool via ``app.ai_tool_bridge`` and POSTs the result back.
        """
        bridge = getattr(self.app, "ai_tool_bridge", None)
        if bridge is None:
            self.app.notify("AI tool bridge not available.", severity="error")
            return

        from servonaut.services.ai_tool_bridge import ToolCall, ToolResult

        self._turn_tool_calls += 1

        # Extract args, tolerating known provider-wrapper variants.
        # Per backend contract (ToolCallEvent::payload), args is a flat dict
        # at data["args"]. We tolerate:
        #   - JSON-encoded string (older providers): json.loads it
        #   - Anthropic-style wrapped {"input": {...}}: unwrap input
        # If anything goes wrong, fall back to {} (relay rejects with a
        # readable error rather than the bridge silently dropping the call).
        raw_args = data.get("args")
        parsed_args: Dict[str, Any] = {}
        if isinstance(raw_args, dict):
            # Anthropic-style wrap unwrap; otherwise pass through.
            if "input" in raw_args and isinstance(raw_args["input"], dict) and len(raw_args) == 1:
                parsed_args = dict(raw_args["input"])
            else:
                parsed_args = dict(raw_args)
        elif isinstance(raw_args, str) and raw_args.strip():
            try:
                decoded = json.loads(raw_args)
                if isinstance(decoded, dict):
                    parsed_args = decoded
            except (json.JSONDecodeError, TypeError):
                logger.warning(
                    "tool_call args was a non-JSON string for tool=%s call=%s",
                    data.get("tool"), data.get("tool_call_id"),
                )
        # DEBUG-level dump so re-running with --debug shows what the wire
        # actually delivered, without leaking content in normal logs.
        logger.debug(
            "tool_call raw args type=%s value=%r → parsed=%r",
            type(raw_args).__name__, raw_args, parsed_args,
        )

        call = ToolCall(
            tool_call_id=str(data.get("tool_call_id") or ""),
            tool=str(data.get("tool") or ""),
            args=parsed_args,
            guard_level=str(data.get("guard_level") or "standard"),  # type: ignore[arg-type]
            conversation_id=self._remote_conversation_id or "",
        )

        # INFO-level so users running without --debug can see the flow.
        # Args may carry user data; log only the tool name and ids.
        logger.info(
            "ai tool_call received: tool=%s tool_call_id=%s guard=%s conv=%s",
            call.tool, call.tool_call_id, call.guard_level,
            call.conversation_id or "<empty>",
        )
        if not call.conversation_id:
            logger.warning(
                "tool_call %s arrived before conversation_id was set — POST "
                "to /api/ai/chat/tool-result will be rejected with "
                "validation_failed (empty conversation_id)",
                call.tool_call_id,
            )

        try:
            result = await bridge.handle_tool_call(call)
        except Exception as exc:  # noqa: BLE001
            # C4 — bridge raised before producing a ToolResult. The server's
            # turn stays open until we POST a tool-result back, so synthesise
            # a status="error" envelope and post it before we return. Without
            # this, a single bridge bug could hang every chat that issued a
            # tool_call.
            logger.exception("AIToolBridge.handle_tool_call raised")
            error_message = f"Tool execution failed: {exc}"
            # A1 — exc message is server/runtime-controlled. markup=False.
            self.app.notify(
                error_message, severity="error", markup=False,
            )
            try:
                synthetic = ToolResult(
                    tool_call_id=call.tool_call_id,
                    conversation_id=call.conversation_id,
                    status="error",
                    result=error_message,
                    error=str(exc),
                    bytes=len(error_message.encode("utf-8")),
                )
                await bridge.post_tool_result(synthetic)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "Failed to post synthetic error tool_result for %s",
                    call.tool_call_id,
                )
            return

        # If the bridge couldn't dispatch the tool (unmapped name or
        # missing collaborator), surface a soft note to the user AND a
        # tool_result row to the chat log so the conversation has a
        # record of what happened. The server may also miss its row
        # update in this case (404 swallowed in post_tool_result), but
        # the model still gets the tool_result via the SSE stream the
        # next time it hits the server, OR times out gracefully.
        if getattr(result, "skipped", False):
            # A1 — call.tool is server-controlled. markup=False keeps
            # brackets literal.
            self.app.notify(
                f"Skipped tool: {call.tool} — not available in this CLI build.",
                severity="warning",
                markup=False,
                timeout=5,
            )
            self._render_tool_skipped_row(call.tool, result.error or "")

        try:
            await bridge.post_tool_result(result)
        except Exception as exc:  # noqa: BLE001
            logger.exception("post_tool_result failed")
            # A1 — exc message can carry server-controlled markup.
            self.app.notify(
                f"Posting tool result failed: {exc}",
                severity="error",
                markup=False,
            )

    def _render_tool_result_row(self, data: Dict[str, Any]) -> None:
        """Append a tool-result row to the message scroll for visual context.

        Shows the tool's truncated output (``result_summary`` from the
        server's ``ToolResultEvent``) so the user sees what the tool
        returned even when the model doesn't generate follow-up text.
        Without this, a server that emits a ``tool_result`` and then
        ``done`` (no continuation tokens) leaves the user staring at
        an empty "(no response)" assistant bubble despite the tool
        having succeeded.
        """
        tool_id = _rich_escape(str(data.get("tool_call_id", "")))
        status = _rich_escape(str(data.get("status", "ok")))
        result_summary = data.get("result_summary")
        try:
            container = self.query_one("#chat-messages", VerticalScroll)
        except Exception:
            return

        header = (
            f"[dim italic]Tool result[/dim italic] "
            f"[bold]{tool_id}[/bold] [dim]({status})[/dim]"
        )
        if isinstance(result_summary, str) and result_summary.strip():
            # Demo-mode: scrub tool result content BEFORE escape so IPs /
            # ARNs / secrets are never visible on screen. Order: scrub →
            # escape → embed (avoids Rich-markup injection).
            raw_body = result_summary.strip()
            try:
                _app = self.app
                # getattr defensive access: this row can render before the
                # widget is fully mounted, when `app` may not expose the
                # demo-mode attributes yet.
                if getattr(_app, "demo_mode", False) and getattr(_app, "redaction_service", None):
                    scrubbed = _app.redaction_service.scrub_stream(raw_body)
                    if isinstance(scrubbed, str):
                        raw_body = scrubbed
            except Exception:
                pass  # Not mounted or app not available — skip redaction gracefully
            # Server-controlled string — escape every byte before
            # interpolating into Rich markup (markup-injection guard).
            safe_body = _rich_escape(raw_body)
            body = f"\n{safe_body}"
        else:
            body = ""

        widget = Static(
            header + body,
            classes="chat-message-tool",
        )
        container.mount(widget)
        # Tool-result rows can be quite tall (multi-line summary). Pin
        # the viewport to the bottom so the user sees the latest tool
        # output. ``_follow_tail`` respects manual scroll-up.
        self.call_after_refresh(self._follow_tail)
        # Persist if the user opted to keep tool results in local history.
        # Default True (debug-friendly); toggle off in Settings to drop.
        self._maybe_persist_tool_message(header + body)

    def _render_tool_skipped_row(self, tool_name: str, reason: str) -> None:
        """Append a soft-skip row for tools the bridge couldn't dispatch.

        Distinct from ``_render_tool_result_row`` so the user can tell at
        a glance "this didn't run" vs "this ran with status X". All
        interpolated strings escape via ``_rich_escape`` because the tool
        name and reason are server-controlled.
        """
        try:
            container = self.query_one("#chat-messages", VerticalScroll)
        except Exception:
            return
        safe_tool = _rich_escape(tool_name or "?")
        # Demo-mode: reason comes from result.error which may carry bridge
        # error details (paths, IPs). Scrub before escape. Defense-in-depth:
        # the probability is low but the fix is cheap.
        raw_reason = reason or "tool unavailable"
        try:
            _app = self.app
            if getattr(_app, "demo_mode", False) and getattr(_app, "redaction_service", None):
                scrubbed = _app.redaction_service.scrub_stream(raw_reason)
                if isinstance(scrubbed, str):
                    raw_reason = scrubbed
        except Exception:
            pass
        safe_reason = _rich_escape(raw_reason)
        rendered = (
            f"[yellow]⊘ Skipped tool[/yellow] [bold]{safe_tool}[/bold] "
            f"[dim]— {safe_reason}[/dim]"
        )
        widget = Static(
            rendered,
            classes="chat-message-tool",
        )
        container.mount(widget)
        self.call_after_refresh(self._follow_tail)
        self._maybe_persist_tool_message(rendered)

    def _maybe_persist_tool_message(self, rendered_markup: str) -> None:
        """Append a ``role="tool"`` ChatMessage when the user opted in.

        Toggled by ``config.chat_keep_tool_results`` (default True).
        Writes the same Rich-markup string the transient render uses so
        the reload path can update the Static widget verbatim — no
        re-formatting on the read side. Defensive at every step:
        unmounted-test-panel callers (no .app, no _session) and a
        missing config field all early-return cleanly.
        """
        try:
            cfg = self.app.config_manager.get()
        except Exception:
            return
        if not getattr(cfg, "chat_keep_tool_results", True):
            return
        session = getattr(self, "_session", None)
        if session is None:
            return
        try:
            from servonaut.services.chat_service import ChatMessage
            session.messages.append(  # type: ignore[union-attr]
                ChatMessage(
                    role="tool",
                    content=rendered_markup,
                    provider="servonaut",
                )
            )
            chat_service = self._get_chat_service()
            if chat_service is not None:
                chat_service.save_session(session)
        except Exception:
            logger.debug("Failed to persist tool message", exc_info=True)

    def _consume_usage_event(self, data: Dict[str, Any]) -> None:
        """Update quota / fallback / cap state from a streamed ``usage`` event."""
        # Token totals — accumulate into the existing counters.
        try:
            in_t = int(data.get("input_tokens") or 0)
            out_t = int(data.get("output_tokens") or 0)
            self._total_tokens += (in_t + out_t)
        except (TypeError, ValueError):
            pass
        model = data.get("model")
        if isinstance(model, str) and model:
            self._model = model
        self._last_fallback_used = bool(data.get("fallback_used", False))
        quota_block = data.get("quota")
        if isinstance(quota_block, dict):
            self._last_soft_capped = bool(quota_block.get("soft_capped", False))
            self._last_hard_capped = bool(quota_block.get("hard_capped", False))
            # Persist the fresh quota onto the AuthToken so the footer
            # picks it up on the next render. We only update the
            # ``quota`` slice; other entitlement fields are unchanged.
            auth = getattr(self.app, "auth_service", None)
            if auth is not None:
                token = getattr(auth, "_token", None)
                if token is not None:
                    ents = dict(getattr(token, "entitlements", None) or {})
                    ents["quota"] = quota_block
                    token.entitlements = ents

        conv_id = data.get("conversation_id")
        if isinstance(conv_id, str) and conv_id:
            self._remote_conversation_id = conv_id

        self._update_stats()

    def _handle_stream_error(self, exc: BaseException, accumulated: str) -> None:
        """Route a streaming error through :func:`map_error_to_action`."""
        from servonaut.services.ai_error_handler import (
            UserFacingAction,
            map_error_to_action,
        )
        from servonaut.services.ai_sse import SSEStreamDead, SSEStreamError
        from servonaut.services.api_client import APIError

        if not isinstance(exc, (APIError, SSEStreamError, SSEStreamDead)):
            logger.exception("Unhandled exception in Servonaut stream")
            # A1 — exc may carry server-controlled markup. markup=False.
            self.app.notify(
                f"Stream failed: {exc}", severity="error", markup=False,
            )
            return

        payload = map_error_to_action(exc)

        # T10 watcher — count upstream_unavailable + heartbeat-deads.
        if payload.code == "upstream_unavailable":
            self._record_upstream_failure()
            self._maybe_offer_fallback()

        action = payload.action

        # A1 — `payload.user_message` is sourced from the server error
        # envelope (APIError.message / SSEStreamError.message). Pass
        # ``markup=False`` to every notify path that carries it so a
        # malicious server cannot inject Rich markup (e.g. a clickable
        # ``[link=evil]`` href) into the toast.
        if action == UserFacingAction.MODAL_QUOTA_EXHAUSTED:
            self._push_topup_modal(reason="Out of monthly tokens.")
        elif action == UserFacingAction.MODAL_BUDGET_EXHAUSTED:
            self._push_topup_modal(reason="Budget hard cap reached.")
        elif action == UserFacingAction.MODAL_UPGRADE_REQUIRED:
            # Refresh entitlements first per plan §T5 entitlement_required
            # ("trigger refresh_entitlements first to handle plan staleness").
            auth = getattr(self.app, "auth_service", None)
            if auth is not None and payload.code == "entitlement_required":
                self.run_worker(
                    auth.fetch_entitlements(),
                    name="ai_refresh_entitlements_post_error",
                    group="ai_chat",
                )
            self.app.notify(
                payload.user_message,
                severity="warning",
                markup=False,
            )
        elif action == UserFacingAction.BANNER_FEATURE_OFF:
            self._set_banner(
                f"[yellow]{_rich_escape(payload.user_message)}[/yellow]"
            )
        elif action == UserFacingAction.BANNER_UPSTREAM_FLAKY:
            self._set_banner(
                f"[yellow]{_rich_escape(payload.user_message)}[/yellow]"
            )
        elif action == UserFacingAction.AUTO_RETRY_WITH_BACKOFF:
            self.app.notify(
                payload.user_message,
                severity="information",
                markup=False,
            )
        elif action == UserFacingAction.AUTO_CHUNK_AND_RETRY:
            self.app.notify(
                payload.user_message,
                severity="warning",
                markup=False,
            )
        elif action == UserFacingAction.LOG_ONLY:
            logger.warning(
                "AI %s: %s (details=%r)",
                payload.code, payload.user_message, payload.details,
            )
            self.app.notify(
                payload.user_message, severity="warning", markup=False,
            )
        else:
            self.app.notify(
                payload.user_message, severity="error", markup=False,
            )

    def _push_topup_modal(self, *, reason: str) -> None:
        """Show :class:`AITopUpModal`; on a pack pick, drive checkout."""
        from servonaut.screens.ai_topup_modal import AITopUpModal

        def _on_pack(pack: Optional[str]) -> None:
            if not pack:
                return
            self.run_worker(
                self._do_topup_checkout(pack),
                name="ai_topup_checkout",
                group="ai_chat",
            )

        try:
            self.app.push_screen(AITopUpModal(reason=reason), _on_pack)
        except Exception:
            logger.exception("Failed to push AITopUpModal")

    async def _do_topup_checkout(self, pack: str) -> None:
        """Worker: open the Stripe Checkout URL and schedule entitlements refresh.

        A4 — validates the URL is a Stripe-hosted checkout origin before
        auto-launching the browser. A mismatch logs a warning and shows
        the URL for manual copy-paste rather than potentially redirecting
        to a phishing page.
        """
        from servonaut.services.ai_providers.servonaut_provider import (
            is_valid_stripe_checkout_url,
        )

        provider = getattr(self.app, "servonaut_provider", None)
        if provider is None:
            # A1/A5 — message contains no server-controlled data, but
            # use markup=False uniformly so behaviour is predictable.
            self.app.notify(
                "Servonaut AI not initialised.", severity="error", markup=False,
            )
            return
        try:
            url = await provider.topup_checkout(pack)
        except Exception as exc:  # noqa: BLE001
            # A1 — exc message can carry server-controlled markup (e.g. the
            # APIError message). Pass through markup=False so brackets stay
            # literal.
            self.app.notify(
                f"Top-up failed: {exc}", severity="error", markup=False,
            )
            return

        # A4 — validate the URL host strictly. Anything other than
        # Stripe's checkout origin: log + tell the user to open manually.
        if not is_valid_stripe_checkout_url(url):
            logger.warning(
                "Top-up checkout returned non-Stripe URL %r (pack=%s) — refusing auto-open",
                url, pack,
            )
            self.app.notify(
                f"Open this URL manually: {url}",
                severity="warning",
                markup=False,
            )
        else:
            try:
                webbrowser.open(url)
            except Exception:
                self.app.notify(
                    f"Open this URL in your browser: {url}",
                    severity="warning",
                    markup=False,
                )

        auth = getattr(self.app, "auth_service", None)
        if auth is not None and hasattr(auth, "schedule_post_topup_refresh"):
            try:
                await auth.schedule_post_topup_refresh()
            except Exception:
                logger.debug("schedule_post_topup_refresh failed", exc_info=True)

    # ------------------------------------------------------------------
    # Public hand-offs called from AIConversationsScreen (Local + Cloud
    # tabs). Both pop the conversations screen on success — see callers.
    # ------------------------------------------------------------------

    def load_local_session(self, session_id: str) -> None:
        """Public alias so AIConversationsScreen's Local tab can swap
        the active chat thread to a saved local session.

        ``_load_session`` already does the right thing (clears the
        remote conversation pointer so a new turn starts a fresh
        Cloud row unless the saved session was paired). Wrapping it
        keeps the public surface stable if the implementation moves.
        """
        self._load_session(session_id)

    def load_remote_conversation(self, uuid: str) -> None:
        """Load a remote (hosted) conversation as the active chat thread.

        Fetches the full thread via
        ``app.ai_conversations_client.get(uuid)``, rebuilds a transient
        :class:`ChatSession` from the returned messages, swaps it in as
        the active session, and re-renders.

        The remote conversation_id is stored separately so the next
        :meth:`_do_send_servonaut` call passes it to ``stream_chat``
        for a continuation turn (server re-attaches the same
        conversation row).
        """
        client = getattr(self.app, "ai_conversations_client", None)
        if client is None:
            self.app.notify(
                "Conversations client not available.", severity="warning",
            )
            return

        async def _load() -> None:
            try:
                thread = await client.get(uuid)
            except Exception as exc:  # noqa: BLE001
                logger.exception("load_remote_conversation get failed")
                # A2 — exc may surface a server-controlled APIError.message
                # carrying Rich markup. ``markup=False`` keeps it literal.
                self.app.notify(
                    f"Failed to load conversation: {exc}",
                    severity="error",
                    markup=False,
                )
                return

            from servonaut.services.chat_service import ChatMessage, ChatSession

            messages: List[ChatMessage] = []
            for raw in thread.get("messages") or []:
                role = str(raw.get("role") or "")
                # Tool / system messages are skipped — the local chat UI
                # only renders user / assistant bubbles.
                if role not in ("user", "assistant"):
                    continue
                content = raw.get("content")
                if isinstance(content, list):
                    # Anthropic-style content blocks → join text-only.
                    parts = [
                        b.get("text", "") for b in content
                        if isinstance(b, dict) and b.get("type") == "text"
                    ]
                    content = "\n".join(p for p in parts if p)
                if not isinstance(content, str):
                    content = str(content or "")
                messages.append(
                    ChatMessage(
                        role=role,
                        content=content,
                        timestamp=str(raw.get("timestamp") or "") or "",
                        provider="servonaut",
                    )
                )

            session = ChatSession(
                id=str(thread.get("id") or uuid),
                title=str(thread.get("title") or "Remote conversation"),
                messages=messages,
                remote_conversation_id=str(uuid),
            )
            self._session = session
            self._remote_conversation_id = str(uuid)
            self._total_tokens = 0
            self._total_cost = 0.0
            self.call_after_refresh(self._refresh_messages)

        self.run_worker(
            _load(),
            name="ai_chat_load_remote",
            group="ai_chat",
            exclusive=True,
        )
