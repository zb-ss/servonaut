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
from textual.widgets import Button, Input, Select, Static, Switch

from servonaut.screens.settings.base import SettingsPanel, ValidationError

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


def requirement_note(requirement: str, readiness: Any) -> str:
    """Short note shown beside a requirement's OK/missing state.

    Kept as a pure function of the readiness verdict because the wording
    has to stay honest about what was actually established: the device
    check only runs once the audio stack imports, so an unmet microphone
    requirement means "not checked yet" until PortAudio resolves — saying
    "none found" there would invent a cause.

    Args:
        requirement: One of ``packages``, ``portaudio``, ``device``.
        readiness: The current :class:`VoiceReadiness`.

    Returns:
        The note, or an empty string for an unknown requirement.
    """
    if requirement == "packages":
        return "installed" if readiness.packages_ok else "~200 MB download"
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
    """

    def __init__(self) -> None:
        super().__init__()
        # Last resolved readiness, kept so button handlers do not re-probe
        # (which would re-enumerate audio devices on every click).
        self._readiness: Optional[Any] = None
        # True while an install or download worker is in flight, so the
        # action buttons cannot be double-fired.
        self._busy = False

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

        yield Horizontal(
            Button("Re-check", id="voice_btn_recheck", variant="default"),
            classes="voice-action-row",
        )

        yield Static("Transcription", classes="voice-section-header")
        yield Horizontal(
            Static("Model size", classes="label"),
            Select(_MODEL_OPTIONS, id="voice_model_size", allow_blank=False),
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

    # ------------------------------------------------------------------
    # Load / dirty / save
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and render the readiness card."""
        config = self.app.config_manager.get()
        voice = config.voice

        self.query_one("#voice_enabled", Switch).value = bool(voice.enabled)

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
        )
        self.app.config_manager.update(voice=updated)

        # The running services hold the old config object and a cached
        # availability verdict; both would otherwise describe the settings
        # the user just replaced.
        self._rebind_services(updated)
        self._finish_save()
        self._refresh_readiness()

    def _rebind_services(self, updated: Any) -> None:
        """Point the live voice services at the saved config."""
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
                requirement_note("packages", readiness),
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
        size = self._selected_model_size()
        cached = bool(service and service.is_model_cached(size))
        if cached and service is not None:
            footprint = service.model_cache_bytes(size)
            note = f"cached, {self._human_bytes(footprint)} on disk"
        elif service is not None:
            note = f"{service.download_size_hint(size)} download"
        else:
            note = ""
        container.mount(self._requirement_row(f"Model ({size})", cached, note))

        if service is not None and readiness.packages_ok:
            buttons = []
            if not cached:
                buttons.append(
                    Button(
                        f"Download model ({service.download_size_hint(size)})",
                        id="voice_btn_download",
                        variant="primary",
                    )
                )
            else:
                buttons.append(Button("Remove model", id="voice_btn_remove_model", variant="error"))
            container.mount(Horizontal(*buttons, classes="voice-action-row"))

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

    def _start_install(self) -> None:
        """Install the voice packages in a worker."""
        service = self._setup_service()
        if service is None or self._busy:
            return
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
        size = self._selected_model_size()
        self._busy = True
        self._set_actions_enabled(False)
        self.app.notify(
            f"Downloading the {size} model ({service.download_size_hint(size)}).",
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
            success, message = await service.download_model(size)
        except Exception as exc:  # noqa: BLE001 — hub/network/disk errors
            logger.error("Voice model download raised: %s", exc)
            success, message = False, f"Download failed: {exc}"
        finally:
            self._busy = False

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
        if event.select.id == "voice_model_size":
            # The card tracks the dropdown, so switching size must repaint
            # the model row even though nothing has been saved yet.
            self._render_requirements()
            self._render_banner()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Refresh the dirty marker and the banner's enabled/disabled wording."""
        self._dirty_watch()
        if event.switch.id == "voice_enabled":
            self._render_banner()
