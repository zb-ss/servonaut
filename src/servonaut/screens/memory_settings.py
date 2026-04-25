"""Memory Settings screen — manage cloud memory sync preferences.

Tier-gated on ``memory_sync`` entitlement.  Displays a form for configuring
digest frequency, Mercure push, AI consent mode, and anomaly rules.
Saves via PATCH (delta-only) when the user presses ctrl+s.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Select, Static, Switch

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)

_DIGEST_OPTIONS: List[tuple[str, str]] = [
    ("Off", "off"),
    ("Weekly", "weekly"),
    ("Monthly", "monthly"),
]


class MemorySettingsScreen(Screen):
    """Screen for managing memory cloud-sync settings.

    Tier-gated on ``memory_sync``.  On mount, fetches current settings from
    ``MemorySettingsService``.  Saving (ctrl+s) PATCHes only changed fields.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("ctrl+s", "save", "Save", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def __init__(self) -> None:
        super().__init__()
        self._original_settings: Optional[Any] = None

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield VerticalScroll(
                Container(
                    Static(
                        "[bold cyan]Memory Cloud Settings[/bold cyan]",
                        id="settings-title",
                    ),
                    Container(
                        Label("Digest Frequency"),
                        Select(
                            options=_DIGEST_OPTIONS,
                            value="off",
                            id="settings-digest-select",
                        ),
                        id="settings-digest-row",
                        classes="settings-field-row",
                    ),
                    Container(
                        Label("Enable Mercure Push"),
                        Switch(value=False, id="settings-mercure-switch"),
                        id="settings-mercure-row",
                        classes="settings-field-row",
                    ),
                    Container(
                        Label("AI Summary Mode"),
                        Select(
                            options=[
                                ("Off", "off"),
                                ("Server 60s", "server_60s"),
                                ("Client", "client"),
                            ],
                            value="off",
                            id="settings-ai-mode-select",
                        ),
                        id="settings-ai-mode-row",
                        classes="settings-field-row",
                    ),
                    Static(
                        "",
                        id="settings-status",
                    ),
                    Horizontal(
                        Button("ctrl+s. Save", variant="primary", id="btn-settings-save"),
                        Button("Cancel", variant="default", id="btn-settings-cancel"),
                        id="settings-btn-row",
                    ),
                    id="settings-form",
                ),
                id="settings-scroll",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Mount
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        auth = getattr(self.app, "auth_service", None)
        if auth and not auth.has_feature("memory_sync"):
            from servonaut.widgets.upsell_modal import UpsellModal
            self.app.push_screen(UpsellModal("memory_sync"))
            return
        self._load_settings()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load_settings(self) -> None:
        self.run_worker(
            self._do_load(),
            group="memory_settings",
            name="settings_load",
        )

    async def _do_load(self) -> None:
        settings_service = getattr(self.app, "memory_settings_service", None)
        if settings_service is None:
            self.query_one("#settings-status", Static).update(
                "[dim]Settings service unavailable — showing defaults.[/dim]"
            )
            return
        try:
            settings = await settings_service.get_settings()
            self._original_settings = settings
            self._apply_settings(settings)
        except Exception as exc:
            logger.error("Failed to load settings: %s", exc)
            self.query_one("#settings-status", Static).update(
                f"[red]Failed to load settings: {exc}[/red]"
            )

    def _apply_settings(self, settings: Any) -> None:
        digest = getattr(settings, "digest_frequency", "off") or "off"
        mercure = bool(getattr(settings, "mercure_push_enabled", False))
        ai_mode = getattr(settings, "ai_consent_mode", "off") or "off"
        try:
            self.query_one("#settings-digest-select", Select).value = digest
        except Exception:
            pass
        try:
            self.query_one("#settings-mercure-switch", Switch).value = mercure
        except Exception:
            pass
        try:
            self.query_one("#settings-ai-mode-select", Select).value = ai_mode
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def action_save(self) -> None:
        self.run_worker(
            self._do_save(),
            group="memory_settings",
            name="settings_save",
            exclusive=True,
        )

    async def _do_save(self) -> None:
        settings_service = getattr(self.app, "memory_settings_service", None)
        status = self.query_one("#settings-status", Static)
        if settings_service is None:
            status.update("[red]Settings service unavailable.[/red]")
            return
        try:
            digest = self.query_one("#settings-digest-select", Select).value
            mercure = self.query_one("#settings-mercure-switch", Switch).value
            ai_mode = self.query_one("#settings-ai-mode-select", Select).value
            delta: Dict[str, Any] = {}
            orig = self._original_settings
            if orig is None or getattr(orig, "digest_frequency", None) != digest:
                delta["digest_frequency"] = digest
            if orig is None or bool(getattr(orig, "mercure_push_enabled", False)) != mercure:
                delta["mercure_push_enabled"] = mercure
            if orig is None or getattr(orig, "ai_consent_mode", None) != ai_mode:
                delta["ai_consent_mode"] = ai_mode
            if not delta:
                status.update("[dim]No changes to save.[/dim]")
                return
            await settings_service.patch_settings(delta)
            status.update("[green]Settings saved.[/green]")
            self.app.notify("Memory settings saved.")
        except Exception as exc:
            logger.error("Failed to save settings: %s", exc)
            status.update(f"[red]Save failed: {exc}[/red]")
            self._surface_validation_errors(exc)

    def _surface_validation_errors(self, exc: Exception) -> None:
        from servonaut.services.memory.interfaces import ValidationFailed
        if not isinstance(exc, ValidationFailed):
            return
        errors = getattr(exc, "errors", []) or []
        for err in errors:
            key = err.get("key", "?") if isinstance(err, dict) else "?"
            message = err.get("error", str(err)) if isinstance(err, dict) else str(err)
            self.app.notify(f"Validation error [{key}]: {message}", severity="error")

    # ------------------------------------------------------------------
    # Actions / buttons
    # ------------------------------------------------------------------

    def action_back(self) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-settings-save":
            self.action_save()
        elif event.button.id == "btn-settings-cancel":
            self.action_back()
