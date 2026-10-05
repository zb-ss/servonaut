"""Settings panel for local Team Vault safety and polling policy."""
from __future__ import annotations

import dataclasses
from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Input, Static, Switch

from servonaut.screens.settings.base import SettingsPanel, ValidationError


class VaultPanel(SettingsPanel):
    """Expose the local vault policy without weakening server-side controls."""

    PANEL_ID = "vault"
    TITLE = "Team Vault"

    DEFAULT_CSS = """
    VaultPanel .settings-help {
        color: $text-muted;
        height: auto;
        margin: 0 0 1 0;
    }

    VaultPanel .setting_row Switch {
        width: auto;
        margin-right: 1;
    }
    """

    def form_rows(self) -> ComposeResult:
        yield Static(
            "These settings control this device only. Team membership, grants, and server policy remain verified by the service.",
            classes="settings-help",
        )
        for label, field_id in (
            ("Require strict verification", "vault_strict_verification"),
            ("Process eligible grants automatically", "vault_auto_grant"),
            ("Allow encrypted file key storage", "vault_allow_file_key_store"),
        ):
            yield Horizontal(Static(label, classes="label"), Switch(id=field_id), classes="setting_row")
        yield Static(
            "File key storage is off by default. Enable it only where the local filesystem is an approved custody mechanism.",
            classes="settings-help",
        )
        for label, field_id, placeholder in (
            ("Private SSH agent key lifetime (seconds)", "vault_agent_key_ttl_seconds", "3600"),
            ("Background vault poll interval (seconds)", "vault_poll_after_seconds", "300"),
            ("Approval poll initial delay (seconds)", "vault_approval_poll_initial_seconds", "2"),
            ("Approval poll maximum delay (seconds)", "vault_approval_poll_max_seconds", "10"),
            ("Vault request timeout (seconds)", "vault_request_timeout_seconds", "30"),
        ):
            yield Horizontal(Static(label, classes="label"), Input(placeholder=placeholder, id=field_id), classes="setting_row")

    def load(self) -> None:
        vault = self.app.config_manager.get().vault
        for field_id, value in (
            ("vault_strict_verification", vault.strict_verification),
            ("vault_auto_grant", vault.auto_grant),
            ("vault_allow_file_key_store", vault.allow_file_key_store),
        ):
            self.query_one(f"#{field_id}", Switch).value = value
        for field_id, value in (
            ("vault_agent_key_ttl_seconds", vault.agent_key_ttl_seconds),
            ("vault_poll_after_seconds", vault.poll_after_seconds),
            ("vault_approval_poll_initial_seconds", vault.approval_poll_initial_seconds),
            ("vault_approval_poll_max_seconds", vault.approval_poll_max_seconds),
            ("vault_request_timeout_seconds", vault.request_timeout_seconds),
        ):
            self.query_one(f"#{field_id}", Input).value = str(value)
        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        return self.collect()

    def collect(self) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        for key in ("strict_verification", "auto_grant", "allow_file_key_store"):
            values[key] = self.query_one(f"#vault_{key}", Switch).value
        for key in ("agent_key_ttl_seconds", "poll_after_seconds"):
            field_id = f"vault_{key}"
            try:
                value = int(self.query_one(f"#{field_id}", Input).value.strip())
            except ValueError as exc:
                raise ValidationError(field_id, "Enter a whole number.") from exc
            if value < 1:
                raise ValidationError(field_id, "Enter a value of at least 1.")
            values[key] = value
        for key in ("approval_poll_initial_seconds", "approval_poll_max_seconds", "request_timeout_seconds"):
            field_id = f"vault_{key}"
            try:
                value = float(self.query_one(f"#{field_id}", Input).value.strip())
            except ValueError as exc:
                raise ValidationError(field_id, "Enter a positive number.") from exc
            if value <= 0:
                raise ValidationError(field_id, "Enter a positive number.")
            values[key] = value
        if values["approval_poll_initial_seconds"] > values["approval_poll_max_seconds"]:
            raise ValidationError("vault_approval_poll_max_seconds", "Maximum delay must be at least the initial delay.")
        return values

    def persist(self) -> None:
        values = self.collect()
        config = self.app.config_manager.get()
        self.app.config_manager.update(vault=dataclasses.replace(config.vault, **values))
        self._finish_save()

    def on_input_changed(self, _event: Input.Changed) -> None:
        self._dirty_watch()

    def on_switch_changed(self, _event: Switch.Changed) -> None:
        self._dirty_watch()
