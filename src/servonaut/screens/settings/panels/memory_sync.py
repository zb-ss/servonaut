"""Memory Sync settings panel.

Exposes the four server-side Memory Sync preferences:
- Digest frequency (Select: off / weekly / monthly)
- Mercure push enabled (Switch)
- Auto-sync while Servonaut is running (Switch)
- AI consent mode (Select: off / client / server_60s)

Settings are stored on the servonaut.dev backend, NOT in config.json.
The panel is conditionally shown only when the user has the
``memory_sync`` entitlement AND the device is enrolled (keypair
configured).  When the user is entitled but not enrolled, the widgets
are disabled and a status banner explains what to do.

Persistence flows through ``memory_settings_service.patch_settings``
(an async coroutine) rather than the local ``config_manager``, so the
panel runs its save inside a Textual worker.  Reload reloads from the
backend with ``force_refresh=True``.

Dirty tracking compares current widget values against the last-fetched
``MemorySettings`` object stored in ``self._original_settings``.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import Button, Select, Static, Switch

from servonaut.screens.settings.base import SettingsPanel

logger = logging.getLogger(__name__)

# Digest frequency options — labels shown in the UI.
_DIGEST_OPTIONS: list[tuple[str, str]] = [
    ("Off", "off"),
    ("Weekly", "weekly"),
    ("Monthly", "monthly"),
]

# AI consent mode options.
_AI_CONSENT_OPTIONS: list[tuple[str, str]] = [
    ("Off (no AI summaries)", "off"),
    ("Client-side processing", "client"),
    ("Server-side, 60s window", "server_60s"),
]

_SELECT_BLANK = Select.BLANK  # sentinel for un-set Select values


class MemorySyncPanel(SettingsPanel):
    """Server-side digest, push, auto-sync, and AI-consent settings.

    Conditionally shown only when the user has the ``memory_sync``
    entitlement AND the device keypair is enrolled.  All persistence goes
    through ``memory_settings_service.patch_settings`` — a remote async
    call — not config.json.
    """

    PANEL_ID = "memory_sync"
    TITLE = "Memory Sync"

    DEFAULT_CSS = """
    MemorySyncPanel #msync_info_note {
        color: $text-muted;
        padding: 0 1;
        margin-bottom: 1;
    }
    MemorySyncPanel .msync-disabled-note {
        color: $warning;
        padding: 0 1;
        margin-bottom: 1;
    }
    MemorySyncPanel #btn_msync_reload {
        margin-left: 1;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        # Holds the last-fetched MemorySettings; used for dirty detection
        # and to compute the diff sent to patch_settings.
        self._original_settings: Optional[Any] = None  # MemorySettings | None

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        """Compose title + gated section with the panel's own Save/Reload.

        Overrides the base ``compose`` to drop the shared save-dock: this
        panel owns its Save/Reload buttons inside ``#settings_msync_section``
        because they must be disabled together with the form when the device
        is not enrolled.
        """
        yield Static(escape(self.TITLE), classes="panel-title")
        yield from self.form_rows()
        yield Static("", id=f"status_{self.PANEL_ID}", classes="panel-status")

    def form_rows(self) -> ComposeResult:
        """Yield the Memory Sync form rows wrapped in a gated section.

        The whole form lives inside ``#settings_msync_section`` so the
        entitlement gate can hide it independently of the panel's root
        ``display`` (which the shell owns for active/inactive switching).
        """
        yield Container(
            Static(
                "These settings are stored on your servonaut.dev account, "
                "not in config.json. Set up the encryption keypair via "
                "☁ Memory Sync in the sidebar before editing here.",
                id="msync_info_note",
                classes="note",
            ),
            Static("", id="settings_msync_status", classes="msync-disabled-note"),
            Horizontal(
                Static("Digest Frequency", classes="label"),
                Select(
                    _DIGEST_OPTIONS,
                    prompt="Choose digest cadence",
                    allow_blank=True,
                    id="settings_msync_digest",
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Mercure Push", classes="label"),
                Switch(value=False, id="settings_msync_mercure"),
                classes="setting_row",
            ),
            Horizontal(
                Static("Auto-sync (60s, app open)", classes="label"),
                Switch(value=False, id="settings_msync_auto_sync"),
                classes="setting_row",
            ),
            Horizontal(
                Static("AI Consent Mode", classes="label"),
                Select(
                    _AI_CONSENT_OPTIONS,
                    prompt="Choose AI consent mode",
                    allow_blank=True,
                    id="settings_msync_ai_mode",
                ),
                classes="setting_row",
            ),
            Horizontal(
                Button("Save", id="btn_msync_save", variant="primary"),
                Button("Reload", id="btn_msync_reload", variant="default"),
                classes="setting_row",
            ),
            id="settings_msync_section",
        )

    # ------------------------------------------------------------------
    # Lifecycle: on_mount is handled by the base class (calls self.load())
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets and show/hide based on entitlement + enrollment.

        If entitled and enrolled, kicks off an async worker to fetch
        current settings from the backend.  Otherwise disables the form.
        """
        if not self._is_entitled():
            self._set_panel_display(False)
            self._snapshot_now()
            return

        self._set_panel_display(True)

        if not self._is_enrolled():
            self._disable_widgets(
                "Memory Sync is locked on this device. "
                "Open ☁ Memory Sync from the sidebar and click "
                "Unlock Memory Sync (you will be asked for your passphrase), "
                "then return here to manage these settings."
            )
            self._snapshot_now()
            return

        # Entitled + enrolled: fetch from backend.
        self._set_widgets_enabled(True)
        self.run_worker(
            self._fetch_and_populate(),
            group="memory_settings",
            name="msync_panel_load",
            exclusive=True,
        )

    def collect(self) -> Dict[str, Any]:
        """Read widgets into a field dict; raise ValidationError on bad input.

        For this panel validation is minimal — the server enforces domain
        rules via ``patch_settings``.  We only guard against blank-value
        selects when the panel is active.
        """
        digest = self.query_one("#settings_msync_digest", Select).value
        mercure = self.query_one("#settings_msync_mercure", Switch).value
        auto_sync = self.query_one("#settings_msync_auto_sync", Switch).value
        ai_mode = self.query_one("#settings_msync_ai_mode", Select).value
        return {
            "digest": digest if digest is not _SELECT_BLANK else "off",
            "mercure": bool(mercure),
            "auto_sync": bool(auto_sync),
            "ai_mode": ai_mode if ai_mode is not _SELECT_BLANK else "off",
        }

    def persist(self) -> None:
        """Compute diff and patch settings via async worker."""
        if not self._is_entitled() or not self._is_enrolled():
            return
        self.run_worker(
            self._do_save(),
            group="memory_settings",
            name="msync_panel_save",
            exclusive=True,
        )

    def is_dirty(self) -> bool:
        """Return True when widget values differ from the last-fetched settings."""
        if self._original_settings is None:
            return False
        orig = self._original_settings
        try:
            digest_val = self.query_one("#settings_msync_digest", Select).value
            digest = digest_val if digest_val is not _SELECT_BLANK else "off"
            mercure = bool(self.query_one("#settings_msync_mercure", Switch).value)
            auto_sync = bool(self.query_one("#settings_msync_auto_sync", Switch).value)
            ai_mode_val = self.query_one("#settings_msync_ai_mode", Select).value
            ai_mode = ai_mode_val if ai_mode_val is not _SELECT_BLANK else "off"
        except Exception:
            return False
        return (
            digest != (getattr(orig, "digest_frequency", "off") or "off")
            or mercure != bool(getattr(orig, "mercure_push_enabled", False))
            or auto_sync != bool(getattr(orig, "auto_sync_enabled", False))
            or ai_mode != (getattr(orig, "ai_consent_mode", "off") or "off")
        )

    def current_values(self) -> Dict[str, Any]:
        """Return the current widget values dict for dirty comparison."""
        try:
            digest_val = self.query_one("#settings_msync_digest", Select).value
            ai_val = self.query_one("#settings_msync_ai_mode", Select).value
            return {
                "digest": digest_val if digest_val is not _SELECT_BLANK else "off",
                "mercure": bool(self.query_one("#settings_msync_mercure", Switch).value),
                "auto_sync": bool(self.query_one("#settings_msync_auto_sync", Switch).value),
                "ai_mode": ai_val if ai_val is not _SELECT_BLANK else "off",
            }
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle the panel-owned Save / Reload buttons.

        This panel composes its own buttons (the base save-dock is omitted),
        so Save is routed through the same validate→persist→notify path the
        base class uses, with the same error surfacing.
        """
        from servonaut.screens.settings.base import ValidationError

        if event.button.id == "btn_msync_reload":
            event.stop()
            self._reload()
            return
        if event.button.id == "btn_msync_save":
            event.stop()
            self.clear_field_errors()
            try:
                self.persist()
            except ValidationError as exc:
                self.mark_field_error(exc.field_id, exc.message)
            except Exception as exc:
                logger.error("Memory Sync save failed: %s", exc)
                self.app.notify(
                    f"Could not save {self.TITLE} settings: {exc}",
                    severity="error",
                    markup=False,
                )

    def on_select_changed(self, event: Select.Changed) -> None:
        """Refresh dirty marker when a Select value changes."""
        self._dirty_watch()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Refresh dirty marker when the Switch value changes."""
        self._dirty_watch()

    # ------------------------------------------------------------------
    # Private helpers — entitlement / enrollment checks
    # ------------------------------------------------------------------

    def _is_entitled(self) -> bool:
        """Return True if the user has the memory_sync entitlement."""
        auth = getattr(self.app, "auth_service", None)
        if auth is None:
            return False
        try:
            return bool(auth.has_feature("memory_sync"))
        except Exception:
            return False

    def _is_enrolled(self) -> bool:
        """Return True if the device keypair is configured (enrolled)."""
        sync = getattr(self.app, "memory_sync_service", None)
        if sync is None:
            return False
        return bool(getattr(sync, "is_configured", False))

    # ------------------------------------------------------------------
    # Private helpers — widget state
    # ------------------------------------------------------------------

    def _set_panel_display(self, visible: bool) -> None:
        """Show or hide the gated form section (NOT the panel root).

        The panel root ``display`` is owned by the shell (active/inactive
        switching); the entitlement gate only toggles the inner section so
        the two concerns don't fight.
        """
        try:
            self.query_one("#settings_msync_section").display = visible
        except Exception:
            pass

    def _set_widgets_enabled(self, enabled: bool) -> None:
        """Enable or disable the interactive inputs and Save/Reload buttons."""
        for widget_id in (
            "#settings_msync_digest",
            "#settings_msync_mercure",
            "#settings_msync_auto_sync",
            "#settings_msync_ai_mode",
            "#btn_msync_save",
            "#btn_msync_reload",
        ):
            try:
                self.query_one(widget_id).disabled = not enabled
            except Exception:
                pass

    def _disable_widgets(self, reason: str) -> None:
        """Disable inputs and show *reason* in the status note."""
        self._set_widgets_enabled(False)
        try:
            self.query_one("#settings_msync_status", Static).update(escape(reason))
        except Exception:
            pass

    def _clear_status(self) -> None:
        """Clear the status note and ensure inputs are enabled."""
        try:
            self.query_one("#settings_msync_status", Static).update("")
        except Exception:
            pass

    def _set_status(self, markup: str) -> None:
        """Update the status note with pre-escaped or plain markup."""
        try:
            self.query_one("#settings_msync_status", Static).update(markup)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Private helpers — async workers
    # ------------------------------------------------------------------

    async def _fetch_and_populate(self, force: bool = False) -> None:
        """Fetch settings from the backend and populate widgets."""
        svc = getattr(self.app, "memory_settings_service", None)
        if svc is None:
            self._set_status("[red]Memory settings service unavailable.[/red]")
            return
        try:
            settings = await svc.get_settings(force_refresh=force)
        except Exception as exc:
            logger.error("Memory Sync settings load failed: %s", exc)
            self._set_status(f"[red]Could not load: {escape(str(exc))}[/red]")
            return
        self._populate_from_settings(settings)
        self._set_status("[$success]● Loaded[/$success]")

    def _populate_from_settings(self, settings: Any) -> None:
        """Write MemorySettings values into the widgets and re-snapshot."""
        self._original_settings = settings
        try:
            self.query_one("#settings_msync_digest", Select).value = (
                getattr(settings, "digest_frequency", "off") or "off"
            )
            self.query_one("#settings_msync_mercure", Switch).value = bool(
                getattr(settings, "mercure_push_enabled", False)
            )
            self.query_one("#settings_msync_auto_sync", Switch).value = bool(
                getattr(settings, "auto_sync_enabled", False)
            )
            self.query_one("#settings_msync_ai_mode", Select).value = (
                getattr(settings, "ai_consent_mode", "off") or "off"
            )
        except Exception as exc:
            logger.warning("Memory Sync widget population: %s", exc)
        self._snapshot_now()
        self._refresh_dirty_marker()

    async def _do_save(self) -> None:
        """Build a delta dict and call patch_settings; update status."""
        from servonaut.services.memory.interfaces import ValidationFailed

        svc = getattr(self.app, "memory_settings_service", None)
        if svc is None:
            self._set_status("[red]Memory settings service unavailable.[/red]")
            return
        try:
            digest_val = self.query_one("#settings_msync_digest", Select).value
            digest = digest_val if digest_val is not _SELECT_BLANK else "off"
            mercure = bool(self.query_one("#settings_msync_mercure", Switch).value)
            auto_sync = bool(self.query_one("#settings_msync_auto_sync", Switch).value)
            ai_val = self.query_one("#settings_msync_ai_mode", Select).value
            ai_mode = ai_val if ai_val is not _SELECT_BLANK else "off"
        except Exception as exc:
            self._set_status(f"[red]Could not read form: {escape(str(exc))}[/red]")
            return

        orig = self._original_settings
        delta: Dict[str, Any] = {}
        if digest and (orig is None or getattr(orig, "digest_frequency", None) != digest):
            delta["digest_frequency"] = digest
        if orig is None or bool(getattr(orig, "mercure_push_enabled", False)) != bool(mercure):
            delta["mercure_push_enabled"] = bool(mercure)
        if auto_sync != bool(getattr(orig, "auto_sync_enabled", False) if orig is not None else False):
            delta["auto_sync_enabled"] = auto_sync
        if ai_mode and (orig is None or getattr(orig, "ai_consent_mode", None) != ai_mode):
            delta["ai_consent_mode"] = ai_mode

        if not delta:
            self._set_status("[dim]No changes to save.[/dim]")
            return

        self._set_status("[$accent]⏳ Saving…[/$accent]")
        try:
            updated = await svc.patch_settings(delta)
        except ValidationFailed as exc:
            self._surface_validation_errors(exc)
            self._set_status("[red]Save failed: validation error (see notifications).[/red]")
            return
        except Exception as exc:
            logger.error("Memory Sync settings save failed: %s", exc)
            self._set_status(f"[red]Save failed: {escape(str(exc))}[/red]")
            return

        self._populate_from_settings(updated)
        self._set_status("[$success]● Saved[/$success]")
        self.app.notify("Memory Sync settings saved.", severity="information", markup=False)

        # Re-evaluate the drain loop now that auto_sync_enabled may have changed.
        # guarded with getattr so a test host or older app version can't crash the save.
        refresh_fn = getattr(self.app, "_refresh_memory_sync_loop", None)
        if refresh_fn is not None:
            await refresh_fn()

    def _surface_validation_errors(self, exc: Any) -> None:
        """Notify the user of each per-field validation error from the server."""
        errors = getattr(exc, "errors", []) or []
        for err in errors:
            if isinstance(err, dict):
                key = err.get("key", "?")
                message = err.get("error", str(err))
            else:
                key = "?"
                message = str(err)
            self.app.notify(
                f"Validation error [{escape(key)}]: {escape(message)}",
                severity="error",
                markup=False,
            )

    def _reload(self) -> None:
        """Force-reload settings from the backend."""
        self._set_status("[dim]Reloading…[/dim]")
        self.run_worker(
            self._fetch_and_populate(force=True),
            group="memory_settings",
            name="msync_panel_reload",
            exclusive=True,
        )
