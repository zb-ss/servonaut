"""General settings panel — REFERENCE implementation for all other panels.

Demonstrates the full :class:`SettingsPanel` contract: ``form_rows`` builds the
widgets, ``load`` populates them from config and snapshots, ``collect``
validates + returns a field dict (raising :class:`ValidationError` on bad
input), and ``persist`` writes through ``config_manager.update(...)`` then
``_finish_save``. Dirty tracking is driven by ``current_values`` +
``_dirty_watch``. Other panel agents should copy this structure.
"""

from __future__ import annotations

from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Input, Select, Static

from servonaut.screens.settings.base import SettingsPanel, ValidationError

_THEME_OPTIONS = [("Dark", "dark"), ("Light", "light")]


class GeneralPanel(SettingsPanel):
    """Top-level scalar settings: username, key, cache TTL, terminal, theme."""

    PANEL_ID = "general"
    TITLE = "General"

    def form_rows(self) -> ComposeResult:
        """Yield the General form rows."""
        yield Horizontal(
            Static("Default username", classes="label"),
            Input(placeholder="ec2-user", id="general_username"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Default SSH key", classes="label"),
            Input(placeholder="~/.ssh/id_rsa", id="general_default_key"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Cache TTL (seconds)", classes="label"),
            Input(placeholder="3600", id="general_cache_ttl"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Terminal emulator", classes="label"),
            Input(placeholder="auto", id="general_terminal"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Theme", classes="label"),
            Select(
                _THEME_OPTIONS,
                value="dark",
                allow_blank=False,
                id="general_theme",
            ),
            classes="setting_row",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()
        self.query_one("#general_username", Input).value = config.default_username
        self.query_one("#general_default_key", Input).value = config.default_key
        self.query_one("#general_cache_ttl", Input).value = str(config.cache_ttl_seconds)
        self.query_one("#general_terminal", Input).value = config.terminal_emulator
        theme = config.theme if config.theme in ("dark", "light") else "dark"
        self.query_one("#general_theme", Select).value = theme
        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "default_username": self.query_one("#general_username", Input).value.strip(),
            "default_key": self.query_one("#general_default_key", Input).value.strip(),
            "cache_ttl_seconds": self.query_one("#general_cache_ttl", Input).value.strip(),
            "terminal_emulator": self.query_one("#general_terminal", Input).value.strip(),
            "theme": str(self.query_one("#general_theme", Select).value),
        }

    def collect(self) -> Dict[str, Any]:
        """Validate and return the fields to persist.

        Raises:
            ValidationError: On empty username or invalid cache TTL.
        """
        username = self.query_one("#general_username", Input).value.strip()
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

        theme = str(self.query_one("#general_theme", Select).value)
        return {
            "default_username": username,
            "default_key": self.query_one("#general_default_key", Input).value.strip(),
            "cache_ttl_seconds": cache_ttl,
            "terminal_emulator": (
                self.query_one("#general_terminal", Input).value.strip() or "auto"
            ),
            "theme": theme,
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

    def on_select_changed(self, event: Select.Changed) -> None:
        """Refresh the dirty marker on theme change."""
        self._dirty_watch()
