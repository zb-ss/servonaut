"""Voice Input settings panel — opt-in switch plus a guided setup card.

Voice input is the one feature that cannot be turned on by flipping a
config value: it needs a few hundred megabytes of Python packages, a
system library pip cannot provide, a microphone, and model weights. So
this panel is built around a readiness card that names each requirement
and offers the action for the first unmet one, instead of a single
button that would silently half-succeed.

Nothing here downloads on its own. Every fetch is behind a button whose
label states the size first — the same opt-in stance the rest of the app
takes toward anything that leaves or enters the machine.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Dict, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, ProgressBar, Select, Static, Switch

from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.services.voice_engines import (
    ENGINES,
    NEMOTRON_LATENCY_OPTIONS,
    engine_spec,
    human_bytes,
)

logger = logging.getLogger(__name__)

# Offered model sizes, ordered fastest → most accurate. Kept to the sizes
# worth choosing from a TUI: the multi-gigabyte ones are reachable by
# editing config.json but do not belong in a dropdown on a laptop.
_MODEL_OPTIONS = [
    ("tiny — fastest, least accurate", "tiny"),
    ("base — fast", "base"),
    ("small — recommended", "small"),
    ("distil-small.en — English only, ~2x faster than small", "distil-small.en"),
    ("medium — slow, most accurate here", "medium"),
]

# Glyphs for the readiness rows. Plain characters only: emoji carrying a
# VS16 variant selector corrupt row rendering in some terminals.
_OK = "[green]OK[/green]"
_MISSING = "[red]--[/red]"

_MAX_RECORDING_CEILING = 600

# Engine choices, ordered so the lighter download comes first.
_ENGINE_OPTIONS = [
    (ENGINES["whisper"].label, "whisper"),
    (ENGINES["nemotron"].label, "nemotron"),
]

# Streaming chunk sizes. Smaller shows words sooner; all are the same
# download, so the only trade is latency against a little accuracy.
_LATENCY_OPTIONS = [
    (f"{ms} ms" + (" — recommended" if ms == 320 else ""), ms)
    for ms in NEMOTRON_LATENCY_OPTIONS
]


def requirement_note(
    requirement: str, readiness: Any, *, download_hint: str = "~200 MB"
) -> str:
    """Short note shown beside a requirement's OK/missing state.

    Kept as a pure function of the readiness verdict because the wording
    has to stay honest about what was actually established: the device
    check only runs once the audio stack imports, so an unmet microphone
    requirement means "not checked yet" until PortAudio resolves — saying
    "none found" there would invent a cause.

    Args:
        requirement: One of ``packages``, ``portaudio``, ``device``.
        readiness: The current :class:`VoiceReadiness`.
        download_hint: Install footprint shown for missing packages. Differs
            per engine, so the caller supplies it.

    Returns:
        The note, or an empty string for an unknown requirement.
    """
    if requirement == "packages":
        return "installed" if readiness.packages_ok else f"{download_hint} download"
    if requirement == "portaudio":
        return "found" if readiness.portaudio_ok else "system package, needs sudo"
    if requirement == "device":
        if readiness.device_ok:
            return "detected"
        if not readiness.portaudio_ok:
            return "not checked yet"
        return "none found — expected when running over SSH"
    return ""


class VoicePanel(SettingsPanel):
    """Settings panel for local speech-to-text.

    Fields covered
    --------------
    - voice.enabled               — bool switch, the opt-in
    - voice.model_size            — select
    - voice.language              — str, ISO 639-1 or "auto"
    - voice.input_device          — Optional[str], capture device name
    - voice.max_recording_seconds — int, hard cap per dictation
    - voice.auto_submit           — bool switch, send without review

    Setup actions (immediate, not saved with the form): install the
    packages, download the model, remove the model, re-check readiness.
    """

    PANEL_ID = "voice"
    TITLE = "Voice Input"

    DEFAULT_CSS = """
    VoicePanel .voice-section-header {
        margin: 1 0 0 0;
        text-style: bold;
        color: $accent;
    }
    VoicePanel .voice-help {
        color: $text-muted;
        height: auto;
        padding: 0 0 0 1;
    }
    VoicePanel #voice_status_banner {
        height: auto;
        padding: 0 1;
        margin-bottom: 1;
    }
    VoicePanel .voice-req-row {
        height: auto;
        margin: 0 0 0 1;
    }
    VoicePanel .voice-req-label {
        width: 22;
    }
    VoicePanel .voice-req-state {
        width: 1fr;
    }
    VoicePanel .voice-command {
        color: $text-muted;
        height: auto;
        padding: 0 0 0 3;
    }
    VoicePanel .voice-action-row {
        height: auto;
        margin: 0 0 1 3;
    }
    VoicePanel .voice-action-row Button {
        margin-right: 1;
    }
    VoicePanel #voice_download_row {
        height: auto;
        margin: 0 0 1 3;
    }
    VoicePanel #voice_download_row.hidden {
        display: none;
    }
    VoicePanel #voice_download_label {
        height: auto;
        color: $text-muted;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        # Last resolved readiness, kept so button handlers do not re-probe
        # (which would re-enumerate audio devices on every click).
        self._readiness: Optional[Any] = None
        # True while an install or download worker is in flight, so the
        # action buttons cannot be double-fired.
        self._busy = False
        # The model the panel was loaded with, so a save can tell whether
        # the user switched away from weights that are still on disk.
        self._loaded_engine = "whisper"
        self._loaded_model_size = "small"
        self._loaded_latency = 320

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield the opt-in switch, the readiness card, and the tunables."""
        yield Static("", id="voice_status_banner")

        yield Horizontal(
            Static("Enable voice input", classes="label"),
            Switch(value=False, id="voice_enabled"),
            classes="setting_row",
        )
        yield Static(
            "Speech is transcribed on this machine — audio is never uploaded. "
            "Turning this on adds a microphone button to the chat panel; it "
            "downloads nothing by itself.",
            classes="voice-help",
        )

        yield Static("Setup", classes="voice-section-header")
        yield Static(
            "These actions run immediately and are not part of Save.",
            classes="voice-help",
        )

        yield Vertical(id="voice_requirements")

        # Hidden until a download starts. A model is hundreds of megabytes,
        # so a silent multi-minute wait is indistinguishable from a hang.
        with Vertical(id="voice_download_row", classes="hidden"):
            yield Static("", id="voice_download_label")
            yield ProgressBar(
                total=None, show_eta=True, id="voice_download_bar"
            )

        yield Horizontal(
            Button("Re-check", id="voice_btn_recheck", variant="default"),
            classes="voice-action-row",
        )

        yield Static("Transcription", classes="voice-section-header")
        yield Horizontal(
            Static("Engine", classes="label"),
            Select(_ENGINE_OPTIONS, id="voice_engine", allow_blank=False),
            classes="setting_row",
        )
        yield Static("", id="voice_engine_summary", classes="voice-help")
        yield Horizontal(
            Static("Model size (Whisper only)", classes="label"),
            Select(_MODEL_OPTIONS, id="voice_model_size", allow_blank=False),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Latency (streaming only)", classes="label"),
            Select(_LATENCY_OPTIONS, id="voice_latency", allow_blank=False),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Language (ISO code, or 'auto')", classes="label"),
            Input(placeholder="en", id="voice_language"),
            classes="setting_row",
        )
        yield Static(
            "Pin the language when you know it — 'auto' costs an extra "
            "detection pass and misfires on short phrases.",
            classes="voice-help",
        )
        yield Horizontal(
            Static("Input device (blank = system default)", classes="label"),
            Input(placeholder="default", id="voice_input_device"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Max seconds per recording", classes="label"),
            Input(placeholder="60", id="voice_max_recording_seconds"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Send dictation automatically", classes="label"),
            Switch(value=False, id="voice_auto_submit"),
            classes="setting_row",
        )
        yield Static(
            "Off by default: the assistant can run commands, and with this on "
            "a misheard word reaches it unedited. Leave it off to review each "
            "transcript in the input box before sending.",
            classes="voice-help",
        )

    # ------------------------------------------------------------------
    # Load / dirty / save
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and render the readiness card."""
        config = self.app.config_manager.get()
        voice = config.voice

        self.query_one("#voice_enabled", Switch).value = bool(voice.enabled)
        self.query_one("#voice_engine", Select).value = engine_spec(voice.engine).id

        latency = int(getattr(voice, "nemotron_latency_ms", 320) or 320)
        latency_select = self.query_one("#voice_latency", Select)
        offered_latencies = {value for _label, value in _LATENCY_OPTIONS}
        if latency not in offered_latencies:
            latency_select.set_options([(f"{latency} ms (from config)", latency),
                                        *_LATENCY_OPTIONS])
        latency_select.value = latency

        size = voice.model_size
        offered = {value for _label, value in _MODEL_OPTIONS}
        # A size set by hand in config.json (or by a newer release) must not
        # be clobbered just because the dropdown does not list it.
        select = self.query_one("#voice_model_size", Select)
        if size in offered:
            select.value = size
        else:
            select.set_options([(f"{size} (from config)", size), *_MODEL_OPTIONS])
            select.value = size

        self.query_one("#voice_language", Input).value = voice.language or ""
        self.query_one("#voice_input_device", Input).value = voice.input_device or ""
        self.query_one("#voice_max_recording_seconds", Input).value = str(
            voice.max_recording_seconds
        )
        self.query_one("#voice_auto_submit", Switch).value = bool(voice.auto_submit)

        # Remembered so persist() can tell whether the user switched away
        # from a model that is still occupying disk.
        self._loaded_engine = engine_spec(voice.engine).id
        self._loaded_model_size = voice.model_size
        self._loaded_latency = latency

        self._sync_engine_rows()
        self._sync_setup_service_config()
        self._refresh_readiness()
        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "enabled": self.query_one("#voice_enabled", Switch).value,
            "model_size": str(self.query_one("#voice_model_size", Select).value),
            "language": self.query_one("#voice_language", Input).value.strip(),
            "input_device": self.query_one("#voice_input_device", Input).value.strip(),
            "max_recording_seconds": self.query_one(
                "#voice_max_recording_seconds", Input
            ).value.strip(),
            "auto_submit": self.query_one("#voice_auto_submit", Switch).value,
            "engine": str(self.query_one("#voice_engine", Select).value),
            "nemotron_latency_ms": int(self.query_one("#voice_latency", Select).value),
        }

    def collect(self) -> Dict[str, Any]:
        """Validate widgets and return the fields to persist.

        Raises:
            ValidationError: On any invalid field value.
        """
        values = self.current_values()

        language = values["language"] or "en"
        # A stray sentence here would be passed straight to the model as a
        # language code and rejected mid-dictation, so bound it to the
        # shapes the backend accepts.
        if language != "auto" and not (2 <= len(language) <= 5):
            raise ValidationError(
                "voice_language",
                "Language must be an ISO code such as 'en', or 'auto'.",
            )

        seconds_raw = values["max_recording_seconds"] or "60"
        try:
            seconds = int(seconds_raw)
        except ValueError:
            raise ValidationError(
                "voice_max_recording_seconds", "Max seconds must be a whole number."
            ) from None
        if not 1 <= seconds <= _MAX_RECORDING_CEILING:
            raise ValidationError(
                "voice_max_recording_seconds",
                f"Max seconds must be between 1 and {_MAX_RECORDING_CEILING}.",
            )

        return {
            "enabled": bool(values["enabled"]),
            "model_size": values["model_size"],
            "language": language,
            "input_device": values["input_device"] or None,
            "max_recording_seconds": seconds,
            "auto_submit": bool(values["auto_submit"]),
            "engine": engine_spec(values["engine"]).id,
            "nemotron_latency_ms": int(values["nemotron_latency_ms"]),
        }

    def persist(self) -> None:
        """Validate, then replace the nested voice config.

        Read-modify-write via :func:`dataclasses.replace` so a field added
        to :class:`~servonaut.config.schema.VoiceConfig` by a later release
        survives a save from this panel.
        """
        fields = self.collect()

        config = self.app.config_manager.get()
        updated = dataclasses.replace(
            config.voice,
            enabled=fields["enabled"],
            model_size=fields["model_size"],
            language=fields["language"],
            input_device=fields["input_device"],
            max_recording_seconds=fields["max_recording_seconds"],
            auto_submit=fields["auto_submit"],
            engine=fields["engine"],
            nemotron_latency_ms=fields["nemotron_latency_ms"],
        )
        self.app.config_manager.update(voice=updated)

        # The running services hold the old config object and a cached
        # availability verdict; both would otherwise describe the settings
        # the user just replaced.
        self._rebind_services(updated)
        self._finish_save()
        self._refresh_readiness(force=True)

        switched = (
            fields["engine"] != self._loaded_engine
            or fields["model_size"] != self._loaded_model_size
            or fields["nemotron_latency_ms"] != self._loaded_latency
        )
        self._loaded_engine = fields["engine"]
        self._loaded_model_size = fields["model_size"]
        self._loaded_latency = fields["nemotron_latency_ms"]
        if switched:
            # Offer to reclaim the previous download rather than leaving
            # several hundred megabytes stranded in a cache nobody checks.
            self._offer_model_cleanup()

    def _offer_model_cleanup(self) -> None:
        """Ask whether to delete models the new configuration no longer uses."""
        service = self._setup_service()
        if service is None:
            return
        try:
            stale = service.stale_models(
                active_engine=self._selected_engine(),
                active_model_size=self._selected_model_size(),
                active_latency_ms=self._selected_latency(),
            )
        except Exception:  # noqa: BLE001 — an inventory failure must not break the save
            logger.debug("Could not inventory voice models", exc_info=True)
            return
        if not stale:
            return

        from servonaut.screens.voice_model_cleanup_modal import VoiceModelCleanupModal

        def _resolve(remove: Optional[bool]) -> None:
            if not remove:
                return
            freed = 0
            failures = []
            for model in stale:
                ok, message = service.remove_installed(model)
                if ok:
                    freed += model.size_bytes
                else:
                    failures.append(message)
            if failures:
                self.app.notify("; ".join(failures), severity="error", markup=False)
            else:
                self.app.notify(
                    f"Removed {len(stale)} unused model(s), freeing {human_bytes(freed)}.",
                    severity="information",
                    markup=False,
                )
            self._refresh_readiness(force=True)

        self.app.push_screen(
            VoiceModelCleanupModal(stale, self._pending_model_label()),
            _resolve,
        )

    def _sync_engine_rows(self) -> None:
        """Show only the rows that apply to the selected engine.

        A latency control means nothing for the batch engine and a model
        size means nothing for the streaming one, so the irrelevant row is
        hidden rather than left to be set and silently ignored.
        """
        try:
            engine_id = str(self.query_one("#voice_engine", Select).value)
            summary = self.query_one("#voice_engine_summary", Static)
            size_row = self.query_one("#voice_model_size", Select).parent
            latency_row = self.query_one("#voice_latency", Select).parent
        except Exception:  # noqa: BLE001 — called before compose completes
            return

        spec = engine_spec(engine_id)
        summary.update(escape(spec.summary))
        if size_row is not None:
            size_row.display = not spec.streaming
        if latency_row is not None:
            latency_row.display = spec.streaming

    def _rebind_services(self, updated: Any) -> None:
        """Point the live voice services at the saved config.

        An engine change replaces the input service outright: the two
        engines are different classes, so reconfiguring the old instance
        would leave the batch engine running under a streaming label.
        """
        if engine_spec(updated.engine).id != self._loaded_engine:
            try:
                from servonaut.services.voice_engines import build_voice_input_service
                self.app.voice_input_service = build_voice_input_service(updated)
            except Exception:  # noqa: BLE001 — a rebuild failure must not fail the save
                logger.error("Could not rebuild the voice input service", exc_info=True)

        for attr in ("voice_input_service", "voice_setup_service"):
            service = getattr(self.app, attr, None)
            if service is None:
                continue
            try:
                service._config = updated  # noqa: SLF001 — services are constructed with the config, not reloaded
                reset = getattr(service, "reset_availability", None)
                if callable(reset):
                    reset()
            except Exception:  # noqa: BLE001 — a stale service must not fail the save
                logger.debug("Could not rebind %s to the new voice config", attr, exc_info=True)

    # ------------------------------------------------------------------
    # Readiness card
    # ------------------------------------------------------------------

    def _setup_service(self) -> Optional[Any]:
        """The voice setup service, or None when it is not wired up."""
        return getattr(self.app, "voice_setup_service", None)

    def _sync_setup_service_config(self) -> None:
        """Point the setup service at the engine/model the dropdowns show.

        Setup actions run immediately and are explicitly not part of Save,
        so they have to act on what is selected rather than what was last
        saved. Without this the service keeps answering for the previous
        engine — pressing Download after picking a different one re-checked
        the old model, found it cached, and reported instant success.
        """
        service = self._setup_service()
        if service is None:
            return
        try:
            saved = self.app.config_manager.get().voice
            pending = dataclasses.replace(
                saved,
                engine=self._selected_engine(),
                model_size=self._selected_model_size(),
                nemotron_latency_ms=self._selected_latency(),
            )
        except Exception:  # noqa: BLE001 — called before compose completes
            return
        service._config = pending  # noqa: SLF001 — services take config at construction
        reset = getattr(service, "reset_availability", None)
        if callable(reset):
            reset()

    def _selected_engine(self) -> str:
        """Engine currently chosen in the dropdown, saved or not."""
        try:
            return engine_spec(str(self.query_one("#voice_engine", Select).value)).id
        except Exception:  # noqa: BLE001 — called before compose finishes
            return engine_spec(self.app.config_manager.get().voice.engine).id

    def _selected_latency(self) -> int:
        """Streaming chunk size currently chosen in the dropdown."""
        try:
            return int(self.query_one("#voice_latency", Select).value)
        except Exception:  # noqa: BLE001 — called before compose finishes
            return int(getattr(self.app.config_manager.get().voice,
                               "nemotron_latency_ms", 320) or 320)

    def _pending_model_label(self) -> str:
        """Name of the model the current dropdown selection would use."""
        from servonaut.services.voice_engines import model_label
        return model_label(
            self._selected_engine(),
            model_size=self._selected_model_size(),
            latency_ms=self._selected_latency(),
        )

    def _selected_model_size(self) -> str:
        """The size currently chosen in the dropdown, saved or not.

        The readiness card tracks the dropdown rather than the saved value
        so picking a different size immediately shows whether *that* one
        needs downloading.
        """
        try:
            return str(self.query_one("#voice_model_size", Select).value)
        except Exception:  # noqa: BLE001 — called before compose finishes
            return self.app.config_manager.get().voice.model_size

    def _notify_chat_panels(self) -> None:
        """Tell any mounted chat panel that voice setup may have changed.

        Without this, a chat panel that was mounted while the feature was
        unusable keeps its greyed-out microphone until the app restarts,
        even though this panel now reports the feature ready.
        """
        # Walk the screen stack rather than calling ``app.query``: the app
        # node does not traverse into screens, so an app-level query finds
        # nothing even when a chat panel is mounted on the active screen.
        # The chat dock also usually lives on the screen *underneath* this
        # one, which an active-screen-only search would miss anyway.
        try:
            from servonaut.widgets.chat_panel import ChatPanel
            for screen in self.app.screen_stack:
                for panel in screen.query(ChatPanel):
                    panel.refresh_voice_affordance()
        except Exception:  # noqa: BLE001 — a chat panel is optional, never required
            logger.debug("Could not refresh a chat panel's mic state", exc_info=True)

    def _refresh_readiness(self, *, force: bool = False) -> None:
        """Re-probe and repaint the banner and requirement rows."""
        service = self._setup_service()
        if service is None:
            self._render_unavailable()
            return

        try:
            self._readiness = service.probe(force=force)
        except Exception as exc:  # noqa: BLE001 — a probe failure must not blank the panel
            logger.error("Voice readiness probe failed: %s", exc)
            self._render_unavailable(str(exc))
            return

        self._render_banner()
        self._render_requirements()
        if force:
            # A forced re-probe follows a setup action or an explicit
            # re-check — exactly the moments a stale mic button matters.
            self._notify_chat_panels()

    def _render_unavailable(self, detail: str = "") -> None:
        """Show that setup cannot be inspected on this build."""
        try:
            banner = self.query_one("#voice_status_banner", Static)
        except Exception:
            return
        message = "Voice setup is unavailable in this build."
        if detail:
            message = f"{message} ({escape(detail)})"
        banner.update(f"[yellow]{message}[/yellow]")

    def _render_banner(self) -> None:
        """Summarise readiness in one line at the top of the panel."""
        readiness = self._readiness
        try:
            banner = self.query_one("#voice_status_banner", Static)
        except Exception:
            return

        if readiness is None:
            banner.update("")
            return

        enabled = self.query_one("#voice_enabled", Switch).value
        if readiness.is_ready and enabled:
            banner.update("[green]Ready — press the microphone in the chat panel, or ctrl+t.[/green]")
        elif readiness.is_ready:
            banner.update("[yellow]Set up, but switched off. Enable it above and save.[/yellow]")
        else:
            labels = {
                "packages": "the Python packages are not installed",
                "portaudio": "the PortAudio system library is missing",
                "device": "no microphone was detected",
                "model": "the speech model is not downloaded yet",
            }
            reason = labels.get(readiness.next_step, "setup is incomplete")
            banner.update(f"[yellow]Not ready — {escape(reason)}.[/yellow]")

    def _render_requirements(self) -> None:
        """Rebuild the per-requirement rows and their action buttons."""
        readiness = self._readiness
        try:
            container = self.query_one("#voice_requirements", Vertical)
        except Exception:
            return
        if readiness is None:
            return

        service = self._setup_service()
        container.remove_children()

        # --- Python packages ---
        container.mount(
            self._requirement_row(
                "Python packages",
                readiness.packages_ok,
                requirement_note(
                    "packages", readiness,
                    download_hint=(
                        service.packages_size_hint(self._selected_engine())
                        if service is not None else "~200 MB"
                    ),
                ),
            )
        )
        if not readiness.packages_ok and service is not None:
            if service.install_command() is not None:
                container.mount(
                    Horizontal(
                        Button(
                            "Install packages (~200 MB)",
                            id="voice_btn_install",
                            variant="primary",
                        ),
                        classes="voice-action-row",
                    )
                )
            else:
                # Source checkout, or pipx we cannot locate: the install is
                # the user's to run, so hand them the exact command.
                container.mount(
                    Static(
                        escape(service.manual_install_command()),
                        classes="voice-command",
                    )
                )
                container.mount(
                    Horizontal(
                        Button("Copy command", id="voice_btn_copy_install"),
                        classes="voice-action-row",
                    )
                )

        # --- PortAudio (system library, cannot be pip-installed) ---
        if readiness.packages_ok or not readiness.portaudio_ok:
            container.mount(
                self._requirement_row(
                    "PortAudio library",
                    readiness.portaudio_ok,
                    requirement_note("portaudio", readiness),
                )
            )
            if not readiness.portaudio_ok and service is not None:
                container.mount(
                    Static(escape(service.portaudio_command()), classes="voice-command")
                )
                container.mount(
                    Horizontal(
                        Button("Copy command", id="voice_btn_copy_portaudio"),
                        classes="voice-action-row",
                    )
                )

        # --- Microphone ---
        container.mount(
            self._requirement_row(
                "Microphone", readiness.device_ok, requirement_note("device", readiness)
            )
        )

        # --- Model weights ---
        engine_id = self._selected_engine()
        size = self._selected_model_size()
        label = self._pending_model_label()
        cached = bool(service and service.is_model_present_for(
            engine_id, model_size=size, latency_ms=self._selected_latency()
        ))
        if cached and service is not None:
            footprint = service.model_bytes_for(
                engine_id, model_size=size, latency_ms=self._selected_latency()
            )
            note = f"cached, {self._human_bytes(footprint)} on disk"
        elif service is not None:
            note = f"{service.download_size_hint_for(engine_id, model_size=size)} download"
        else:
            note = ""
        container.mount(self._requirement_row(label, cached, note))

        self._render_installed_models(container, service)

        if service is not None and readiness.packages_ok:
            buttons = []
            if not cached:
                buttons.append(
                    Button(
                        "Download model "
                        f"({service.download_size_hint_for(engine_id, model_size=size)})",
                        id="voice_btn_download",
                        variant="primary",
                    )
                )
            else:
                buttons.append(Button("Remove model", id="voice_btn_remove_model", variant="error"))
            container.mount(Horizontal(*buttons, classes="voice-action-row"))

    def _render_installed_models(self, container: Vertical, service: Optional[Any]) -> None:
        """List every model on disk so disk use is visible, not a surprise."""
        if service is None:
            return
        try:
            installed = service.installed_models(
                active_engine=self._selected_engine(),
                active_model_size=self._selected_model_size(),
                active_latency_ms=self._selected_latency(),
            )
        except Exception:  # noqa: BLE001 — inventory is informational
            logger.debug("Could not inventory voice models", exc_info=True)
            return
        if not installed:
            return

        total = sum(model.size_bytes for model in installed)
        container.mount(Static(
            f"On disk: {escape(human_bytes(total))} across "
            f"{len(installed)} model(s)",
            classes="voice-section-header",
        ))
        for model in installed:
            suffix = " [dim](in use)[/dim]" if model.in_use else ""
            container.mount(Horizontal(
                Static(escape(model.label), classes="voice-req-label"),
                Static(
                    f"{escape(model.human_size)}{suffix}",
                    classes="voice-req-state",
                ),
                classes="voice-req-row",
            ))
        stale = [model for model in installed if not model.in_use]
        if stale:
            freed = human_bytes(sum(model.size_bytes for model in stale))
            container.mount(Horizontal(
                Button(
                    f"Remove {len(stale)} unused ({freed})",
                    id="voice_btn_prune",
                    variant="warning",
                ),
                classes="voice-action-row",
            ))

    def _requirement_row(self, label: str, ok: bool, note: str = "") -> Horizontal:
        """Build one 'requirement — state — note' row."""
        state = _OK if ok else _MISSING
        suffix = f"  [dim]{escape(note)}[/dim]" if note else ""
        return Horizontal(
            Static(escape(label), classes="voice-req-label"),
            Static(f"{state}{suffix}", classes="voice-req-state"),
            classes="voice-req-row",
        )

    @staticmethod
    def _human_bytes(size: int) -> str:
        """Render a byte count as a short human-readable string."""
        value = float(size)
        for unit in ("B", "KB", "MB", "GB"):
            if value < 1024 or unit == "GB":
                return f"{value:.0f} {unit}" if unit != "GB" else f"{value:.1f} GB"
            value /= 1024
        return f"{value:.1f} GB"

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Dispatch the setup action buttons.

        The base class owns ``save_{PANEL_ID}``; every other button in this
        panel is a setup action, so unrelated ids are left to bubble.
        """
        button_id = event.button.id or ""
        if button_id == "voice_btn_recheck":
            event.stop()
            self._refresh_readiness(force=True)
            self.app.notify("Re-checked voice setup.", severity="information", markup=False)
        elif button_id == "voice_btn_install":
            event.stop()
            self._start_install()
        elif button_id == "voice_btn_download":
            event.stop()
            self._start_download()
        elif button_id == "voice_btn_remove_model":
            event.stop()
            self._remove_model()
        elif button_id == "voice_btn_prune":
            event.stop()
            self._offer_model_cleanup()
        elif button_id == "voice_btn_copy_install":
            event.stop()
            service = self._setup_service()
            if service is not None:
                self._copy(service.manual_install_command())
        elif button_id == "voice_btn_copy_portaudio":
            event.stop()
            service = self._setup_service()
            if service is not None:
                self._copy(service.portaudio_command())

    def _copy(self, text: str) -> None:
        """Put *text* on the clipboard, reporting honestly when that fails."""
        from servonaut.utils.platform_utils import copy_to_clipboard

        if copy_to_clipboard(text):
            self.app.notify("Command copied to the clipboard.", severity="information", markup=False)
        else:
            self.app.notify(
                f"Could not reach the clipboard. Run: {text}",
                severity="warning",
                markup=False,
            )

    def _show_download_progress(self, label: str, total: Optional[int] = None) -> None:
        """Reveal the progress row and set its label."""
        try:
            row = self.query_one("#voice_download_row", Vertical)
            text = self.query_one("#voice_download_label", Static)
            bar = self.query_one("#voice_download_bar", ProgressBar)
        except Exception:  # noqa: BLE001 — panel closed or not composed
            return
        row.remove_class("hidden")
        text.update(escape(label))
        # total=None renders an indeterminate bar, which is the honest
        # display for the batch engine's downloader — it reports nothing.
        bar.update(total=total, progress=0)

    def _hide_download_progress(self) -> None:
        """Hide the progress row once a download settles."""
        try:
            self.query_one("#voice_download_row", Vertical).add_class("hidden")
        except Exception:  # noqa: BLE001 — nothing to hide
            return

    def _on_download_progress(self, label: str, done: int, total: int) -> None:
        """Progress callback for the downloader.

        Called directly rather than marshalled: the streaming download is a
        coroutine awaited on the event loop, not a worker thread, so we are
        already where widgets may be touched.
        """
        self._render_download_progress(label, done, total)

    def _render_download_progress(self, label: str, done: int, total: int) -> None:
        """Repaint the progress row."""
        try:
            text = self.query_one("#voice_download_label", Static)
            bar = self.query_one("#voice_download_bar", ProgressBar)
        except Exception:  # noqa: BLE001 — panel closed mid-download
            return
        if total:
            text.update(escape(f"{label} — {human_bytes(done)} of {human_bytes(total)}"))
            bar.update(total=total, progress=done)
        else:
            text.update(escape(f"{label} — {human_bytes(done)}" if done else label))
            bar.update(total=None)

    def _start_install(self) -> None:
        """Install the voice packages in a worker."""
        service = self._setup_service()
        if service is None or self._busy:
            return
        self._sync_setup_service_config()
        self._busy = True
        self._set_actions_enabled(False)
        self.app.notify(
            "Installing voice packages — this can take a few minutes.",
            severity="information",
            markup=False,
        )
        self.run_worker(
            self._do_install(service),
            name="voice_install",
            group="voice_setup",
            exclusive=False,
        )

    async def _do_install(self, service: Any) -> None:
        """Worker: run the package install and repaint the card."""
        try:
            success, message = await service.install_packages()
        except Exception as exc:  # noqa: BLE001 — the installer surface is broad
            logger.error("Voice package install raised: %s", exc)
            success, message = False, f"Install failed: {exc}"
        finally:
            self._busy = False

        self.app.notify(
            message,
            severity="information" if success else "error",
            markup=False,
        )
        self._refresh_readiness(force=True)
        self._set_actions_enabled(True)

    def _start_download(self) -> None:
        """Download the selected model in a worker."""
        service = self._setup_service()
        if service is None or self._busy:
            return
        # The service must be looking at the dropdown selection before the
        # download starts, or it fetches the previously saved engine's model.
        self._sync_setup_service_config()
        size = self._selected_model_size()
        engine_id = self._selected_engine()
        label = self._pending_model_label()
        hint = service.download_size_hint_for(engine_id, model_size=size)
        self._busy = True
        self._set_actions_enabled(False)
        self._show_download_progress(f"Starting {label} ({hint})")
        self.app.notify(
            f"Downloading {label} ({hint}).",
            severity="information",
            markup=False,
        )
        self.run_worker(
            self._do_download(service, size),
            name="voice_download",
            group="voice_setup",
            exclusive=False,
        )

    async def _do_download(self, service: Any, size: str) -> None:
        """Worker: fetch the model weights and repaint the card."""
        try:
            success, message = await service.download_model(
                size, progress=self._on_download_progress
            )
        except Exception as exc:  # noqa: BLE001 — hub/network/disk errors
            logger.error("Voice model download raised: %s", exc)
            success, message = False, f"Download failed: {exc}"
        finally:
            self._busy = False

        self._hide_download_progress()
        self.app.notify(
            message,
            severity="information" if success else "error",
            markup=False,
        )
        self._refresh_readiness(force=True)
        self._set_actions_enabled(True)

    def _remove_model(self) -> None:
        """Delete the cached weights for the selected size."""
        service = self._setup_service()
        if service is None or self._busy:
            return
        size = self._selected_model_size()
        success, message = service.remove_model(size)
        self.app.notify(
            message,
            severity="information" if success else "error",
            markup=False,
        )
        self._refresh_readiness(force=True)

    def _set_actions_enabled(self, enabled: bool) -> None:
        """Enable or disable every setup button while an action runs."""
        for button in self.query(".voice-action-row Button"):
            button.disabled = not enabled

    # ------------------------------------------------------------------
    # Change handlers
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Refresh the dirty marker on any Input change."""
        self._dirty_watch()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Refresh the dirty marker, and the model row for the new size."""
        self._dirty_watch()
        if event.select.id == "voice_engine":
            # A different engine means different packages and a different
            # model, so the whole card is re-derived, not just one row.
            self._sync_engine_rows()
            self._sync_setup_service_config()
            self._refresh_readiness(force=True)
        elif event.select.id in ("voice_model_size", "voice_latency"):
            self._sync_setup_service_config()
            # The card tracks the dropdowns, so switching must repaint the
            # model row even though nothing has been saved yet.
            self._render_requirements()
            self._render_banner()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Refresh the dirty marker and the banner's enabled/disabled wording."""
        self._dirty_watch()
        if event.switch.id == "voice_enabled":
            self._render_banner()
