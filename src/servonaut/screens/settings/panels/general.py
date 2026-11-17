"""General settings panel — REFERENCE implementation for all other panels.

Demonstrates the full :class:`SettingsPanel` contract: ``form_rows`` builds the
widgets, ``load`` populates them from config and snapshots, ``collect``
validates + returns a field dict (raising :class:`ValidationError` on bad
input), and ``persist`` writes through ``config_manager.update(...)`` then
``_finish_save``. Dirty tracking is driven by ``current_values`` +
``_dirty_watch``. The other panels follow the same lifecycle contract.
"""

from __future__ import annotations

from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Input, Static

from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.screens.settings.forms import setting_row


class GeneralPanel(SettingsPanel):
    """Top-level scalar settings: username, key, cache TTL, terminal."""

    PANEL_ID = "general"
    TITLE = "General"
    DESCRIPTION = "Defaults for new connections and this application."

    # Identifiers demo mode hides; see SettingsPanel.DEMO_REDACTED_FIELDS.
    DEMO_REDACTED_FIELDS = {
        "general_username": "redact_username",
        "general_default_key": "redact_key_name",
    }

    def form_rows(self) -> ComposeResult:
        """Group the existing defaults by their role in the application."""
        with Vertical(classes="settings-form-section"):
            yield Static("Connection defaults", classes="settings-group-title", markup=False)
            yield setting_row(
                "Default username",
                Input(placeholder="ec2-user", id="general_username"),
            )
            yield setting_row(
                "Default SSH key",
                Input(placeholder="~/.ssh/id_rsa", id="general_default_key"),
            )
        with Vertical(classes="settings-form-section"):
            yield Static("Application", classes="settings-group-title", markup=False)
            yield setting_row(
                "Cache TTL (seconds)",
                Input(placeholder="3600", id="general_cache_ttl"),
            )
            yield setting_row(
                "Terminal emulator",
                Input(placeholder="auto", id="general_terminal"),
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()
        self._show_field("general_username", config.default_username)
        self._show_field("general_default_key", config.default_key)
        self.query_one("#general_cache_ttl", Input).value = str(config.cache_ttl_seconds)
        self.query_one("#general_terminal", Input).value = config.terminal_emulator
        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "default_username": self._field_value("general_username").strip(),
            "default_key": self._field_value("general_default_key").strip(),
            "cache_ttl_seconds": self.query_one("#general_cache_ttl", Input).value.strip(),
            "terminal_emulator": self.query_one("#general_terminal", Input).value.strip(),
        }

    def collect(self) -> Dict[str, Any]:
        """Validate and return the fields to persist.

        Raises:
            ValidationError: On empty username or invalid cache TTL.
        """
        username = self._field_value("general_username").strip()
        if not username:
            raise ValidationError("general_username", "Username cannot be empty")

        cache_ttl_raw = self.query_one("#general_cache_ttl", Input).value.strip()
        try:
            cache_ttl = int(cache_ttl_raw)
        except ValueError as exc:
            raise ValidationError(
                "general_cache_ttl", "Cache TTL must be a whole number"
            ) from exc
        if cache_ttl < 0:
            raise ValidationError(
                "general_cache_ttl", "Cache TTL must be zero or greater"
            )

        return {
            "default_username": username,
            "default_key": self._field_value("general_default_key").strip(),
            "cache_ttl_seconds": cache_ttl,
            "terminal_emulator": (
                self.query_one("#general_terminal", Input).value.strip() or "auto"
            ),
        }

    def persist(self) -> None:
        """Validate via :meth:`collect` then write top-level scalar fields."""
        fields = self.collect()
        self.app.config_manager.update(**fields)
        self._finish_save()

    # ------------------------------------------------------------------
    # Dirty marker refresh
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Refresh the dirty marker on any input edit."""
        self._dirty_watch()

