"""OVHcloud settings panel.

Exposes the non-secret scalars of :class:`~servonaut.config.schema.OVHConfig`
(enabled, endpoint, client_id, default_ssh_key, default_username,
cloud_project_ids, include_dedicated/vps/cloud switches, ovh_audit_path,
cost_alert_threshold, cost_alert_currency) plus the object-storage S3 fields
(access_key, secret_key, region, endpoint_url).

Credential fields owned by the OVH setup wizard
(application_key, application_secret, consumer_key, client_secret) are
intentionally NOT shown here.  The panel uses ``dataclasses.replace`` when
saving so those wizard-owned secrets are always preserved.

A "Setup OVHcloud" button opens :class:`~servonaut.screens.ovh_setup.OVHSetupScreen`
for credential entry, mirroring the legacy behaviour.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, Input, Select, Static, Switch

from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.screens.settings.widgets import EnvVarInput, StringListEditor

logger = logging.getLogger(__name__)

_ENDPOINT_OPTIONS = [
    ("OVH EU (ovh-eu)", "ovh-eu"),
    ("OVH US (ovh-us)", "ovh-us"),
    ("OVH CA (ovh-ca)", "ovh-ca"),
    ("Kimsufi EU (kimsufi-eu)", "kimsufi-eu"),
    ("Kimsufi CA (kimsufi-ca)", "kimsufi-ca"),
    ("So You Start EU (soyoustart-eu)", "soyoustart-eu"),
    ("So You Start CA (soyoustart-ca)", "soyoustart-ca"),
]

_KNOWN_ENDPOINTS = {ep for _, ep in _ENDPOINT_OPTIONS}


class OvhPanel(SettingsPanel):
    """OVHcloud provider settings: non-secret scalars + object storage S3."""

    PANEL_ID = "ovh"
    TITLE = "OVHcloud"

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

        # Setup wizard launcher
        yield Static("Credentials", classes="ovh-section-header")
        yield Static(
            "API keys and S3 credentials are managed in the setup wizard.",
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
        yield Horizontal(
            Static("API endpoint", classes="label"),
            Select(
                _ENDPOINT_OPTIONS,
                value="ovh-eu",
                allow_blank=False,
                id="ovh_endpoint",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("OAuth2 client ID", classes="label"),
            Input(placeholder="(optional — set in wizard)", id="ovh_client_id"),
            classes="setting_row",
        )

        # SSH / connection defaults
        yield Static("Connection defaults", classes="ovh-section-header")
        yield Horizontal(
            Static("Default SSH key", classes="label"),
            Input(placeholder="~/.ssh/id_rsa", id="ovh_default_ssh_key"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Default username", classes="label"),
            Input(placeholder="ubuntu", id="ovh_default_username"),
            classes="setting_row",
        )

        # Instance filters
        yield Static("Instance filters", classes="ovh-section-header")
        yield Horizontal(
            Static("Include dedicated servers", classes="label"),
            Switch(value=True, id="ovh_include_dedicated"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Include VPS", classes="label"),
            Switch(value=True, id="ovh_include_vps"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Include Public Cloud", classes="label"),
            Switch(value=True, id="ovh_include_cloud"),
            classes="setting_row",
        )
        yield Static("Cloud project IDs", classes="label")
        yield StringListEditor(
            placeholder="project-id",
            id="ovh_cloud_project_ids",
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

        # Object storage (S3)
        yield Static("Object Storage (S3-compatible)", classes="ovh-section-header")
        yield Static(
            "Access key and secret key support $ENV_VAR syntax.",
            classes="ovh-note",
        )
        yield Horizontal(
            Static("Access key", classes="label"),
            EnvVarInput(
                placeholder="$OVH_S3_ACCESS_KEY or literal",
                id="ovh_s3_access_key",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Secret key", classes="label"),
            EnvVarInput(
                placeholder="$OVH_S3_SECRET_KEY or literal",
                password=True,
                id="ovh_s3_secret_key",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Region", classes="label"),
            Input(placeholder="gra", id="ovh_s3_region"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Endpoint URL", classes="label"),
            Input(
                placeholder="https://s3.gra.io.cloud.ovh.net",
                id="ovh_s3_endpoint_url",
            ),
            classes="setting_row",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()
        ovh = config.ovh

        self._set_status(ovh)

        self.query_one("#ovh_enabled", Switch).value = ovh.enabled

        endpoint = ovh.endpoint if ovh.endpoint in _KNOWN_ENDPOINTS else "ovh-eu"
        self.query_one("#ovh_endpoint", Select).value = endpoint

        self.query_one("#ovh_client_id", Input).value = ovh.client_id
        self.query_one("#ovh_default_ssh_key", Input).value = ovh.default_ssh_key
        self.query_one("#ovh_default_username", Input).value = ovh.default_username

        self.query_one("#ovh_include_dedicated", Switch).value = ovh.include_dedicated
        self.query_one("#ovh_include_vps", Switch).value = ovh.include_vps
        self.query_one("#ovh_include_cloud", Switch).value = ovh.include_cloud

        self.query_one("#ovh_cloud_project_ids", StringListEditor).set_values(
            ovh.cloud_project_ids
        )

        self.query_one("#ovh_audit_path", Input).value = ovh.ovh_audit_path
        self.query_one("#ovh_cost_threshold", Input).value = str(ovh.cost_alert_threshold)
        self.query_one("#ovh_cost_currency", Input).value = ovh.cost_alert_currency

        s3 = ovh.object_storage
        self.query_one("#ovh_s3_access_key", EnvVarInput).value = s3.access_key
        self.query_one("#ovh_s3_secret_key", EnvVarInput).value = s3.secret_key
        self.query_one("#ovh_s3_region", Input).value = s3.region
        self.query_one("#ovh_s3_endpoint_url", Input).value = s3.endpoint_url

        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "enabled": self.query_one("#ovh_enabled", Switch).value,
            "endpoint": str(self.query_one("#ovh_endpoint", Select).value),
            "client_id": self.query_one("#ovh_client_id", Input).value.strip(),
            "default_ssh_key": self.query_one("#ovh_default_ssh_key", Input).value.strip(),
            "default_username": self.query_one("#ovh_default_username", Input).value.strip(),
            "include_dedicated": self.query_one("#ovh_include_dedicated", Switch).value,
            "include_vps": self.query_one("#ovh_include_vps", Switch).value,
            "include_cloud": self.query_one("#ovh_include_cloud", Switch).value,
            "cloud_project_ids": self.query_one(
                "#ovh_cloud_project_ids", StringListEditor
            ).get_values(),
            "ovh_audit_path": self.query_one("#ovh_audit_path", Input).value.strip(),
            "cost_alert_threshold": self.query_one(
                "#ovh_cost_threshold", Input
            ).value.strip(),
            "cost_alert_currency": self.query_one(
                "#ovh_cost_currency", Input
            ).value.strip(),
            "s3_access_key": self.query_one("#ovh_s3_access_key", EnvVarInput).value,
            "s3_secret_key": self.query_one("#ovh_s3_secret_key", EnvVarInput).value,
            "s3_region": self.query_one("#ovh_s3_region", Input).value.strip(),
            "s3_endpoint_url": self.query_one("#ovh_s3_endpoint_url", Input).value.strip(),
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
            "endpoint": vals["endpoint"],
            "client_id": vals["client_id"],
            "default_ssh_key": vals["default_ssh_key"],
            "default_username": vals["default_username"],
            "include_dedicated": vals["include_dedicated"],
            "include_vps": vals["include_vps"],
            "include_cloud": vals["include_cloud"],
            "cloud_project_ids": vals["cloud_project_ids"],
            "ovh_audit_path": vals["ovh_audit_path"] or "~/.servonaut/ovh_audit.json",
            "cost_alert_threshold": threshold,
            "cost_alert_currency": vals["cost_alert_currency"] or "EUR",
            "s3_access_key": vals["s3_access_key"],
            "s3_secret_key": vals["s3_secret_key"],
            "s3_region": vals["s3_region"],
            "s3_endpoint_url": vals["s3_endpoint_url"],
        }

    def persist(self) -> None:
        """Validate via :meth:`collect` and write OVH config via replace.

        Wizard-owned secrets (application_key, application_secret,
        consumer_key, client_secret) are preserved via
        ``dataclasses.replace`` — they are never touched here.
        """

        fields = self.collect()

        config = self.app.config_manager.get()
        existing_ovh = config.ovh

        new_s3 = dataclasses.replace(
            existing_ovh.object_storage,
            access_key=fields["s3_access_key"],
            secret_key=fields["s3_secret_key"],
            region=fields["s3_region"],
            endpoint_url=fields["s3_endpoint_url"],
        )

        new_ovh = dataclasses.replace(
            existing_ovh,
            enabled=fields["enabled"],
            endpoint=fields["endpoint"],
            client_id=fields["client_id"],
            default_ssh_key=fields["default_ssh_key"],
            default_username=fields["default_username"],
            include_dedicated=fields["include_dedicated"],
            include_vps=fields["include_vps"],
            include_cloud=fields["include_cloud"],
            cloud_project_ids=fields["cloud_project_ids"],
            ovh_audit_path=fields["ovh_audit_path"],
            cost_alert_threshold=fields["cost_alert_threshold"],
            cost_alert_currency=fields["cost_alert_currency"],
            object_storage=new_s3,
            # Wizard-owned secrets preserved via replace — not changed here:
            # application_key, application_secret, consumer_key, client_secret
        )

        self.app.config_manager.update(ovh=new_ovh)

        # Rebuild OVH object storage service after saving so the new
        # credentials take effect without a restart.
        self._rebuild_ovh_object_storage()

        self._set_status(new_ovh)
        self._finish_save("OVHcloud settings saved")

    # ------------------------------------------------------------------
    # Dirty marker refresh
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Refresh the dirty marker on any input edit."""
        self._dirty_watch()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Refresh the dirty marker on endpoint change."""
        self._dirty_watch()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Refresh the dirty marker on any switch toggle."""
        self._dirty_watch()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Open the OVH setup wizard when the setup button is pressed."""
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
        """Push the OVH credential setup screen."""
        from servonaut.screens.ovh_setup import OVHSetupScreen

        self.app.push_screen(OVHSetupScreen())

    def _rebuild_ovh_object_storage(self) -> None:
        """Rebuild the OVH object storage service on the app after saving.

        Mirrors the side-effect in the legacy settings save path
        (settings.py:2025-2038) so the new credentials are live
        immediately without a restart.
        """
        try:
            from servonaut.services.object_storage_factory import (
                build_object_storage_services,
            )

            config = self.app.config_manager.get()
            _aws, _hetzner, ovh_oss = build_object_storage_services(config)
            self.app.ovh_object_storage_service = ovh_oss
        except Exception as exc:
            logger.warning("Could not rebuild OVH object storage service: %s", exc)
