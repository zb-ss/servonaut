"""OVHcloud settings panel.

Holds the provider-wide settings of :class:`~servonaut.config.schema.OVHConfig`:
whether OVHcloud is listed (``enabled``), the audit log path and the cost
alert. Everything that belongs to one account — API endpoint and
credentials, Public Cloud projects, resource types, SSH defaults and Object
Storage keys — is edited in that account's form,
:class:`~servonaut.screens.ovh_setup.OVHSetupScreen`, so each setting has one
place. "Setup OVHcloud" opens the primary account's form; the Accounts
section lists every account and opens the same form to add or edit one.

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
    OvhAccountsSection,
    rebuild_accounts,
    refresh_provider_fleet,
)
from servonaut.screens.settings.base import SettingsPanel, ValidationError

logger = logging.getLogger(__name__)


class OvhPanel(SettingsPanel):
    """OVHcloud provider-wide settings plus the list of accounts."""

    PANEL_ID = "ovh"
    TITLE = "OVHcloud"

    # Identifiers demo mode hides; see SettingsPanel.DEMO_REDACTED_FIELDS.
    DEMO_REDACTED_FIELDS = {
        "ovh_audit_path": "redact_path",
    }

    DEFAULT_CSS = """
    OvhPanel .ovh-status {
        height: auto;
        padding: 0 1;
        margin: 0 0 1 0;
    }
    OvhPanel .ovh-section-header {
        height: auto;
        padding: 1 0 0 0;
        color: $accent;
        text-style: bold;
    }
    OvhPanel .ovh-note {
        height: auto;
        color: $text-muted;
        padding: 0 1 1 1;
    }
    OvhPanel .ovh-setup-row {
        height: auto;
        margin: 0 0 1 0;
    }
    """

    # ------------------------------------------------------------------
    # Form rows
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield OVHcloud form rows."""
        # Status line (updated on load)
        yield Static("", id="ovh_status_display", classes="ovh-status")

        # The account form
        yield Static("Account settings", classes="ovh-section-header")
        yield Static(
            "Credentials, projects, SSH defaults and Object Storage keys are "
            "in each account's form: Setup OVHcloud for the primary account, "
            "Accounts below for the others.",
            classes="ovh-note",
        )
        yield Horizontal(
            Button("Setup OVHcloud", id="ovh_btn_setup", variant="primary"),
            classes="ovh-setup-row",
        )

        # Provider toggle
        yield Static("Provider", classes="ovh-section-header")
        yield Horizontal(
            Static("Enable OVHcloud", classes="label"),
            Switch(value=False, id="ovh_enabled"),
            classes="setting_row",
        )

        # Audit + cost
        yield Static("Audit & cost alerts", classes="ovh-section-header")
        yield Horizontal(
            Static("Audit log path", classes="label"),
            Input(
                placeholder="~/.servonaut/ovh_audit.json",
                id="ovh_audit_path",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Cost alert threshold", classes="label"),
            Input(placeholder="0.0", id="ovh_cost_threshold"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Cost alert currency", classes="label"),
            Input(placeholder="EUR", id="ovh_cost_currency"),
            classes="setting_row",
        )

        # Accounts (each one edited in its own form)
        yield OvhAccountsSection(heading_classes="ovh-section-header")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        ovh = self.app.config_manager.get().ovh

        self._set_status(ovh)
        self.query_one("#ovh_enabled", Switch).value = ovh.enabled
        self._show_field("ovh_audit_path", ovh.ovh_audit_path)
        self.query_one("#ovh_cost_threshold", Input).value = str(ovh.cost_alert_threshold)
        self.query_one("#ovh_cost_currency", Input).value = ovh.cost_alert_currency

        self.query_one(OvhAccountsSection).refresh_accounts()
        self._snapshot_now()

    def refresh_external_state(self) -> None:
        """Show what the account form saved.

        The form can enable OVHcloud and add, edit or rename accounts. An
        untouched panel reloads, so a later Save never writes back the values
        from before the form; unsaved edits are kept and only the status and
        the accounts are redrawn.
        """
        try:
            if not self.is_dirty():
                self.load()
                return
            self._set_status(self.app.config_manager.get().ovh)
            self.query_one(OvhAccountsSection).refresh_accounts()
        except NoMatches:
            # Settings resumes while this panel is still being built; its
            # own mount loads it.
            return

    def refresh_after_demo_toggle(self) -> None:
        """Re-show the redacted fields and redraw the accounts table."""
        super().refresh_after_demo_toggle()
        self.query_one(OvhAccountsSection).refresh_after_demo_toggle()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "enabled": self.query_one("#ovh_enabled", Switch).value,
            "ovh_audit_path": self._field_value("ovh_audit_path").strip(),
            "cost_alert_threshold": self.query_one(
                "#ovh_cost_threshold", Input
            ).value.strip(),
            "cost_alert_currency": self.query_one(
                "#ovh_cost_currency", Input
            ).value.strip(),
        }

    def collect(self) -> Dict[str, Any]:
        """Validate and return the fields to persist.

        Raises:
            ValidationError: When cost_alert_threshold is not a valid number.
        """
        vals = self.current_values()

        threshold_raw = vals["cost_alert_threshold"]
        try:
            threshold = float(threshold_raw) if threshold_raw else 0.0
        except ValueError as exc:
            raise ValidationError(
                "ovh_cost_threshold", "Cost alert threshold must be a number (e.g. 50.0)"
            ) from exc
        if threshold < 0:
            raise ValidationError(
                "ovh_cost_threshold", "Cost alert threshold must be zero or greater"
            )

        return {
            "enabled": vals["enabled"],
            "ovh_audit_path": vals["ovh_audit_path"] or "~/.servonaut/ovh_audit.json",
            "cost_alert_threshold": threshold,
            "cost_alert_currency": vals["cost_alert_currency"] or "EUR",
        }

    def persist(self) -> None:
        """Validate via :meth:`collect` and write the provider-wide fields.

        ``dataclasses.replace`` keeps every account field (credentials,
        projects, SSH defaults, Object Storage) exactly as the account form
        saved it.
        """
        fields = self.collect()

        existing_ovh = self.app.config_manager.get().ovh
        new_ovh = dataclasses.replace(
            existing_ovh,
            enabled=fields["enabled"],
            ovh_audit_path=fields["ovh_audit_path"],
            cost_alert_threshold=fields["cost_alert_threshold"],
            cost_alert_currency=fields["cost_alert_currency"],
        )

        self.app.config_manager.update(ovh=new_ovh)
        # The switch decides whether OVHcloud is listed at all.
        if rebuild_accounts(self.app) and new_ovh.enabled != existing_ovh.enabled:
            refresh_provider_fleet(self.app, "ovh")
        self.query_one(OvhAccountsSection).refresh_accounts()

        self._set_status(new_ovh)
        self._finish_save("OVHcloud settings saved")

    # ------------------------------------------------------------------
    # Dirty marker refresh
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Refresh the dirty marker on any input edit."""
        self._dirty_watch()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Refresh the dirty marker on any switch toggle."""
        self._dirty_watch()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Open the primary account's form when the setup button is pressed."""
        if event.button.id == "ovh_btn_setup":
            event.stop()
            self._open_ovh_setup()
            return
        # Delegate save-button handling to base class.
        super().on_button_pressed(event)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _set_status(self, ovh: Any) -> None:
        """Update the status line based on the OVH config state."""
        try:
            label = self.query_one("#ovh_status_display", Static)
        except Exception:
            return
        if not ovh.enabled:
            label.update("Status: Not configured")
        elif ovh.application_key or ovh.client_id:
            label.update("Status: Configured (enabled)")
        else:
            label.update("Status: Enabled but no credentials set")

    def _open_ovh_setup(self) -> None:
        """Push the primary account's form."""
        from servonaut.screens.ovh_setup import OVHSetupScreen

        self.app.push_screen(OVHSetupScreen())
