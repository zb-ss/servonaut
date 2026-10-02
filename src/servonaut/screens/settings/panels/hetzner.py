"""Hetzner Cloud settings panel.

Holds the provider-wide settings of :class:`~servonaut.config.schema.HetznerConfig`:
whether Hetzner is listed (``enabled``), whether creating a server requires
SSH keys, the cache, the audit log path and the cost alert. Everything that
belongs to one project — API token, SSH defaults, server-creation defaults and
Object Storage keys — is edited in that project's form,
``HetznerSetupScreen``, so each setting has one place. "Setup Hetzner" opens
the primary project's form; the Projects section lists every project and
opens the same form to add or edit one.

The panel saves with ``dataclasses.replace``, so every field the form owns is
kept exactly as saved.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.css.query import NoMatches
from textual.widgets import Button, Input, Static, Switch

from servonaut.screens.settings.accounts import (
    HetznerAccountsSection,
    rebuild_accounts,
    refresh_provider_fleet,
)
from servonaut.screens.settings.base import SettingsPanel, ValidationError

logger = logging.getLogger(__name__)


class HetznerPanel(SettingsPanel):
    """Hetzner Cloud provider-wide settings plus the list of projects."""

    PANEL_ID = "hetzner"
    TITLE = "Hetzner Cloud"

    # Identifiers demo mode hides; see SettingsPanel.DEMO_REDACTED_FIELDS.
    DEMO_REDACTED_FIELDS = {
        "hetzner_cache_path": "redact_path",
        "hetzner_audit_path": "redact_path",
    }

    DEFAULT_CSS = """
    HetznerPanel .hetzner-status {
        height: auto;
        margin: 1 0;
        padding: 0 1;
    }
    HetznerPanel .section-heading {
        height: auto;
        margin: 1 0 0 0;
        color: $accent;
        text-style: bold;
    }
    HetznerPanel .help-note {
        height: auto;
        color: $text-muted;
        padding: 0 1 1 1;
    }
    """

    # ------------------------------------------------------------------
    # Form composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield all Hetzner form rows."""
        # Status + setup launcher
        yield Static("", id="hetzner_status_label", classes="hetzner-status")
        yield Horizontal(
            Button("Setup Hetzner", id="btn_hetzner_setup", variant="primary"),
            classes="setting_row",
        )
        yield Static(
            "API token, SSH and server defaults and Object Storage keys are in "
            "each project's form: Setup Hetzner for the primary project, "
            "Projects below for the others.",
            classes="help-note",
        )

        # Enable switch
        yield Horizontal(
            Static("Enabled", classes="label"),
            Switch(id="hetzner_enabled"),
            classes="setting_row",
        )

        # Server creation policy
        yield Static("Server Creation", classes="section-heading")
        yield Horizontal(
            Static("Require SSH keys on create", classes="label"),
            Switch(id="hetzner_require_ssh_keys"),
            classes="setting_row",
        )

        # Cache / paths / alerts
        yield Static("Cache & Paths", classes="section-heading")
        yield Horizontal(
            Static("Cache TTL (seconds)", classes="label"),
            Input(placeholder="300", id="hetzner_cache_ttl"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Cache path", classes="label"),
            Input(
                placeholder="~/.servonaut/hetzner_cache.json",
                id="hetzner_cache_path",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Audit log path", classes="label"),
            Input(
                placeholder="~/.servonaut/hetzner_audit.jsonl",
                id="hetzner_audit_path",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Cost alert threshold (0 = disabled)", classes="label"),
            Input(placeholder="0.0", id="hetzner_cost_alert_threshold"),
            classes="setting_row",
        )

        # Projects (each one edited in its own form)
        yield HetznerAccountsSection(heading_classes="section-heading")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and set dirty-tracking snapshot."""
        config = self.app.config_manager.get()
        h = config.hetzner

        self._update_status_label(h)

        self.query_one("#hetzner_enabled", Switch).value = h.enabled
        self.query_one("#hetzner_require_ssh_keys", Switch).value = (
            h.require_ssh_keys_on_create
        )
        self.query_one("#hetzner_cache_ttl", Input).value = str(h.cache_ttl_seconds)
        self._show_field("hetzner_cache_path", h.cache_path)
        self._show_field("hetzner_audit_path", h.audit_path)
        self.query_one("#hetzner_cost_alert_threshold", Input).value = str(
            h.cost_alert_threshold
        )

        self.query_one(HetznerAccountsSection).refresh_accounts()
        self._snapshot_now()

    def refresh_external_state(self) -> None:
        """Show what the project form saved.

        The project form can enable Hetzner and add, edit or rename projects.
        An untouched panel reloads, so a later Save never writes back the
        values from before the form; unsaved edits are kept and only the
        status and the projects are redrawn.
        """
        try:
            if not self.is_dirty():
                self.load()
                return
            self._update_status_label(self.app.config_manager.get().hetzner)
            self.query_one(HetznerAccountsSection).refresh_accounts()
        except NoMatches:
            # Settings resumes while this panel is still being built; its
            # own mount loads it.
            return

    def refresh_after_demo_toggle(self) -> None:
        """Re-show the redacted fields and redraw the projects table."""
        super().refresh_after_demo_toggle()
        self.query_one(HetznerAccountsSection).refresh_after_demo_toggle()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "enabled": self.query_one("#hetzner_enabled", Switch).value,
            "require_ssh_keys_on_create": self.query_one(
                "#hetzner_require_ssh_keys", Switch
            ).value,
            "cache_ttl": self.query_one("#hetzner_cache_ttl", Input).value.strip(),
            "cache_path": self._field_value("hetzner_cache_path").strip(),
            "audit_path": self._field_value("hetzner_audit_path").strip(),
            "cost_alert_threshold": self.query_one(
                "#hetzner_cost_alert_threshold", Input
            ).value.strip(),
        }

    def collect(self) -> Dict[str, Any]:
        """Validate widget values and return a field dict.

        Raises:
            ValidationError: On invalid cache TTL or cost threshold.
        """
        cache_ttl_raw = self.query_one("#hetzner_cache_ttl", Input).value.strip()
        try:
            cache_ttl = int(cache_ttl_raw)
        except ValueError as exc:
            raise ValidationError(
                "hetzner_cache_ttl", "Cache TTL must be a whole number"
            ) from exc
        if cache_ttl < 0:
            raise ValidationError(
                "hetzner_cache_ttl", "Cache TTL must be zero or greater"
            )

        cost_raw = self.query_one(
            "#hetzner_cost_alert_threshold", Input
        ).value.strip()
        try:
            cost_threshold = float(cost_raw) if cost_raw else 0.0
        except ValueError as exc:
            raise ValidationError(
                "hetzner_cost_alert_threshold",
                "Cost alert threshold must be a number (e.g. 50.0)",
            ) from exc
        if cost_threshold < 0:
            raise ValidationError(
                "hetzner_cost_alert_threshold",
                "Cost alert threshold must be zero or greater",
            )

        return {
            "enabled": self.query_one("#hetzner_enabled", Switch).value,
            "require_ssh_keys_on_create": self.query_one(
                "#hetzner_require_ssh_keys", Switch
            ).value,
            "cache_ttl_seconds": cache_ttl,
            "cache_path": self._field_value("hetzner_cache_path").strip(),
            "audit_path": self._field_value("hetzner_audit_path").strip(),
            "cost_alert_threshold": cost_threshold,
        }

    def persist(self) -> None:
        """Validate via :meth:`collect` and write the provider-wide fields.

        ``dataclasses.replace`` keeps every project field (API token, SSH and
        server-creation defaults, Object Storage) exactly as the project form
        saved it.
        """
        fields = self.collect()

        existing = self.app.config_manager.get().hetzner
        new_hetzner = dataclasses.replace(
            existing,
            enabled=fields["enabled"],
            require_ssh_keys_on_create=fields["require_ssh_keys_on_create"],
            cache_ttl_seconds=fields["cache_ttl_seconds"],
            cache_path=fields["cache_path"],
            audit_path=fields["audit_path"],
            cost_alert_threshold=fields["cost_alert_threshold"],
        )

        self.app.config_manager.update(hetzner=new_hetzner)
        # The switch decides whether Hetzner is listed at all.
        if rebuild_accounts(self.app) and new_hetzner.enabled != existing.enabled:
            refresh_provider_fleet(self.app, "hetzner")
        self.query_one(HetznerAccountsSection).refresh_accounts()
        self._update_status_label(new_hetzner)
        self._finish_save("Hetzner settings saved")

    # ------------------------------------------------------------------
    # Button handling (extends base on_button_pressed)
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Route Save and Setup buttons; delegate unknowns to base."""
        if event.button.id == "btn_hetzner_setup":
            event.stop()
            self._open_hetzner_setup()
            return
        super().on_button_pressed(event)

    # ------------------------------------------------------------------
    # Dirty-marker refresh
    # ------------------------------------------------------------------

    def on_input_changed(self, _event: Input.Changed) -> None:
        """Refresh the dirty marker on any input edit."""
        self._dirty_watch()

    def on_switch_changed(self, _event: Switch.Changed) -> None:
        """Refresh the dirty marker on switch toggle."""
        self._dirty_watch()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _update_status_label(self, h: Any) -> None:
        """Update the status label to reflect current Hetzner config state."""
        try:
            label = self.query_one("#hetzner_status_label", Static)
        except Exception:
            return
        if h is None or not h.enabled:
            label.update("Status: Not configured")
        elif h.api_token:
            label.update("Status: Configured and enabled")
        else:
            label.update("Status: Enabled but no token — run Setup Hetzner")

    def _open_hetzner_setup(self) -> None:
        """Push the primary project's form onto the navigation stack."""
        try:
            from servonaut.screens.hetzner_setup import HetznerSetupScreen

            self.app.push_screen(HetznerSetupScreen())
        except Exception as exc:
            logger.error("Could not open Hetzner setup: %s", exc)
            self.app.notify(
                "Could not open Hetzner setup screen.",
                severity="error",
                markup=False,
            )
