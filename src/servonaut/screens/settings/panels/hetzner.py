"""Hetzner Cloud settings panel.

Edits all NON-secret scalars on :class:`~servonaut.config.schema.HetznerConfig`
plus the nested :class:`~servonaut.config.schema.ObjectStorageConfig` for
Hetzner Object Storage. The API token (``api_token``) is owned exclusively by
the ``HetznerSetupScreen`` wizard — this panel preserves it via
``dataclasses.replace`` but never displays or stores it.

A status row shows whether Hetzner is configured (token set) or needs setup,
and a "Setup Hetzner" launcher opens the wizard for credential entry.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, Input, Static, Switch

from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.screens.settings.widgets import EnvVarInput

logger = logging.getLogger(__name__)


class HetznerPanel(SettingsPanel):
    """Hetzner Cloud provider settings — scalars + Object Storage.

    Credentials (``api_token``) are managed in the Hetzner setup wizard.
    This panel edits only non-secret scalar fields and the S3 object-storage
    settings, preserving ``api_token`` via ``dataclasses.replace``.
    """

    PANEL_ID = "hetzner"
    TITLE = "Hetzner Cloud"

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
            "API token and Object Storage credentials live in the setup wizard above.",
            classes="help-note",
        )

        # Enable switch
        yield Horizontal(
            Static("Enabled", classes="label"),
            Switch(id="hetzner_enabled"),
            classes="setting_row",
        )

        # SSH keys
        yield Static("SSH Keys", classes="section-heading")
        yield Horizontal(
            Static("Default Hetzner SSH key", classes="label"),
            Input(
                placeholder="my-key (Hetzner-side name or ID)",
                id="hetzner_default_hetzner_ssh_key",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Default local SSH key", classes="label"),
            Input(
                placeholder="~/.ssh/id_rsa",
                id="hetzner_default_local_ssh_key",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Default username", classes="label"),
            Input(placeholder="root", id="hetzner_default_username"),
            classes="setting_row",
        )

        # Server defaults
        yield Static("Server Defaults", classes="section-heading")
        yield Horizontal(
            Static("Default image", classes="label"),
            Input(placeholder="ubuntu-22.04", id="hetzner_default_image"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Default server type", classes="label"),
            Input(placeholder="cx23", id="hetzner_default_server_type"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Default location", classes="label"),
            Input(
                placeholder="fsn1 / nbg1 / hel1 / ash / hil",
                id="hetzner_default_location",
            ),
            classes="setting_row",
        )
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

        # Object Storage (S3-compatible)
        yield Static("Object Storage (S3-compatible)", classes="section-heading")
        yield Static(
            "Supports $ENV_VAR and file: prefix syntax for credentials.",
            classes="help-note",
        )
        yield Horizontal(
            Static("Access key", classes="label"),
            EnvVarInput(
                placeholder="access key or $ENV_VAR",
                password=False,
                id="hetzner_s3_access_key",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Secret key", classes="label"),
            EnvVarInput(
                placeholder="$HETZNER_SECRET_KEY",
                password=True,
                id="hetzner_s3_secret_key",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Region", classes="label"),
            Input(
                placeholder="eu-central-1",
                id="hetzner_s3_region",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Endpoint URL", classes="label"),
            Input(
                placeholder="https://fsn1.your-objectstorage.com",
                id="hetzner_s3_endpoint_url",
            ),
            classes="setting_row",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and set dirty-tracking snapshot."""
        config = self.app.config_manager.get()
        h = config.hetzner

        self._update_status_label(h)

        self.query_one("#hetzner_enabled", Switch).value = h.enabled
        self.query_one("#hetzner_default_hetzner_ssh_key", Input).value = (
            h.default_hetzner_ssh_key
        )
        self.query_one("#hetzner_default_local_ssh_key", Input).value = (
            h.default_local_ssh_key
        )
        self.query_one("#hetzner_default_username", Input).value = h.default_username
        self.query_one("#hetzner_default_image", Input).value = h.default_image
        self.query_one("#hetzner_default_server_type", Input).value = (
            h.default_server_type
        )
        self.query_one("#hetzner_default_location", Input).value = h.default_location
        self.query_one("#hetzner_require_ssh_keys", Switch).value = (
            h.require_ssh_keys_on_create
        )
        self.query_one("#hetzner_cache_ttl", Input).value = str(h.cache_ttl_seconds)
        self.query_one("#hetzner_cache_path", Input).value = h.cache_path
        self.query_one("#hetzner_audit_path", Input).value = h.audit_path
        self.query_one("#hetzner_cost_alert_threshold", Input).value = str(
            h.cost_alert_threshold
        )

        s3 = h.object_storage
        self.query_one("#hetzner_s3_access_key", EnvVarInput).value = s3.access_key
        self.query_one("#hetzner_s3_secret_key", EnvVarInput).value = s3.secret_key
        self.query_one("#hetzner_s3_region", Input).value = s3.region
        self.query_one("#hetzner_s3_endpoint_url", Input).value = s3.endpoint_url

        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "enabled": self.query_one("#hetzner_enabled", Switch).value,
            "default_hetzner_ssh_key": self.query_one(
                "#hetzner_default_hetzner_ssh_key", Input
            ).value.strip(),
            "default_local_ssh_key": self.query_one(
                "#hetzner_default_local_ssh_key", Input
            ).value.strip(),
            "default_username": self.query_one(
                "#hetzner_default_username", Input
            ).value.strip(),
            "default_image": self.query_one(
                "#hetzner_default_image", Input
            ).value.strip(),
            "default_server_type": self.query_one(
                "#hetzner_default_server_type", Input
            ).value.strip(),
            "default_location": self.query_one(
                "#hetzner_default_location", Input
            ).value.strip(),
            "require_ssh_keys_on_create": self.query_one(
                "#hetzner_require_ssh_keys", Switch
            ).value,
            "cache_ttl": self.query_one("#hetzner_cache_ttl", Input).value.strip(),
            "cache_path": self.query_one(
                "#hetzner_cache_path", Input
            ).value.strip(),
            "audit_path": self.query_one(
                "#hetzner_audit_path", Input
            ).value.strip(),
            "cost_alert_threshold": self.query_one(
                "#hetzner_cost_alert_threshold", Input
            ).value.strip(),
            "s3_access_key": self.query_one(
                "#hetzner_s3_access_key", EnvVarInput
            ).value.strip(),
            "s3_secret_key": self.query_one(
                "#hetzner_s3_secret_key", EnvVarInput
            ).value.strip(),
            "s3_region": self.query_one(
                "#hetzner_s3_region", Input
            ).value.strip(),
            "s3_endpoint_url": self.query_one(
                "#hetzner_s3_endpoint_url", Input
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
            "default_hetzner_ssh_key": self.query_one(
                "#hetzner_default_hetzner_ssh_key", Input
            ).value.strip(),
            "default_local_ssh_key": self.query_one(
                "#hetzner_default_local_ssh_key", Input
            ).value.strip(),
            "default_username": self.query_one(
                "#hetzner_default_username", Input
            ).value.strip() or "root",
            "default_image": self.query_one(
                "#hetzner_default_image", Input
            ).value.strip(),
            "default_server_type": self.query_one(
                "#hetzner_default_server_type", Input
            ).value.strip(),
            "default_location": self.query_one(
                "#hetzner_default_location", Input
            ).value.strip(),
            "require_ssh_keys_on_create": self.query_one(
                "#hetzner_require_ssh_keys", Switch
            ).value,
            "cache_ttl_seconds": cache_ttl,
            "cache_path": self.query_one(
                "#hetzner_cache_path", Input
            ).value.strip(),
            "audit_path": self.query_one(
                "#hetzner_audit_path", Input
            ).value.strip(),
            "cost_alert_threshold": cost_threshold,
            "s3_access_key": self.query_one(
                "#hetzner_s3_access_key", EnvVarInput
            ).value.strip(),
            "s3_secret_key": self.query_one(
                "#hetzner_s3_secret_key", EnvVarInput
            ).value.strip(),
            "s3_region": self.query_one(
                "#hetzner_s3_region", Input
            ).value.strip(),
            "s3_endpoint_url": self.query_one(
                "#hetzner_s3_endpoint_url", Input
            ).value.strip(),
        }

    def persist(self) -> None:
        """Validate via :meth:`collect`, preserve secret fields, and write config.

        Uses ``dataclasses.replace`` on the existing ``HetznerConfig`` so that
        ``api_token`` (owned by the setup wizard) is never touched or cleared.
        The nested ``ObjectStorageConfig`` is similarly replaced field-by-field,
        preserving any other future fields the wizard may own.
        """
        fields = self.collect()

        config = self.app.config_manager.get()
        existing = config.hetzner


        new_s3 = dataclasses.replace(
            existing.object_storage,
            access_key=fields["s3_access_key"],
            secret_key=fields["s3_secret_key"],
            region=fields["s3_region"],
            endpoint_url=fields["s3_endpoint_url"],
        )

        new_hetzner = dataclasses.replace(
            existing,
            enabled=fields["enabled"],
            default_hetzner_ssh_key=fields["default_hetzner_ssh_key"],
            default_local_ssh_key=fields["default_local_ssh_key"],
            default_username=fields["default_username"],
            default_image=fields["default_image"],
            default_server_type=fields["default_server_type"],
            default_location=fields["default_location"],
            require_ssh_keys_on_create=fields["require_ssh_keys_on_create"],
            cache_ttl_seconds=fields["cache_ttl_seconds"],
            cache_path=fields["cache_path"],
            audit_path=fields["audit_path"],
            cost_alert_threshold=fields["cost_alert_threshold"],
            object_storage=new_s3,
            # api_token preserved implicitly via dataclasses.replace default
        )

        self.app.config_manager.update(hetzner=new_hetzner)
        self._rebuild_object_storage()
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
        """Push the Hetzner setup wizard screen onto the navigation stack."""
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

    def _rebuild_object_storage(self) -> None:
        """Rebuild and reassign the Hetzner Object Storage service after save.

        Mirrors the side-effect performed in the legacy settings screen
        (``settings.py:2025-2038``) so live sessions pick up credential
        changes without a restart.
        """
        try:
            from servonaut.services.object_storage_factory import (
                build_object_storage_services,
            )

            refreshed_config = self.app.config_manager.get()
            _aws, hetzner_svc, _ovh = build_object_storage_services(refreshed_config)
            self.app.hetzner_object_storage_service = hetzner_svc
        except Exception as exc:
            logger.warning("Could not rebuild Hetzner Object Storage service: %s", exc)
