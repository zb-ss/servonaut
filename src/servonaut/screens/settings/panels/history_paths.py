"""History & Paths settings panel.

Exposes the four path/history fields from :class:`~servonaut.config.schema.AppConfig`:

- ``keyword_store_path`` — on-disk path for the scan keyword store.
- ``command_history_path`` — on-disk path for saved command history.
- ``max_command_history`` — maximum number of commands retained.
- ``chat_history_path`` — directory used to store local chat sessions.

All four are top-level scalar fields so persistence goes through
``config_manager.update(**fields)`` with no nested-dataclass replace needed.
"""

from __future__ import annotations

from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Input, Static

from servonaut.screens.settings.base import SettingsPanel, ValidationError


class HistoryPathsPanel(SettingsPanel):
    """Edit keyword store, command history, and chat history paths."""

    PANEL_ID = "history_paths"
    TITLE = "History & Paths"

    def form_rows(self) -> ComposeResult:
        """Yield the form rows for history and path settings."""
        yield Horizontal(
            Static("Keyword store path", classes="label"),
            Input(
                placeholder="~/.servonaut/keywords.json",
                id="hp_keyword_store_path",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Command history path", classes="label"),
            Input(
                placeholder="~/.servonaut/command_history.json",
                id="hp_command_history_path",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Max command history", classes="label"),
            Input(
                placeholder="50",
                id="hp_max_command_history",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Chat history path", classes="label"),
            Input(
                placeholder="~/.servonaut/chats",
                id="hp_chat_history_path",
            ),
            classes="setting_row",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()
        self.query_one("#hp_keyword_store_path", Input).value = (
            config.keyword_store_path
        )
        self.query_one("#hp_command_history_path", Input).value = (
            config.command_history_path
        )
        self.query_one("#hp_max_command_history", Input).value = str(
            config.max_command_history
        )
        self.query_one("#hp_chat_history_path", Input).value = config.chat_history_path
        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "keyword_store_path": self.query_one(
                "#hp_keyword_store_path", Input
            ).value.strip(),
            "command_history_path": self.query_one(
                "#hp_command_history_path", Input
            ).value.strip(),
            "max_command_history": self.query_one(
                "#hp_max_command_history", Input
            ).value.strip(),
            "chat_history_path": self.query_one(
                "#hp_chat_history_path", Input
            ).value.strip(),
        }

    def collect(self) -> Dict[str, Any]:
        """Validate widget values and return the fields to persist.

        Raises:
            ValidationError: When ``keyword_store_path``, ``command_history_path``,
                or ``chat_history_path`` is empty, or ``max_command_history`` is
                not a positive integer.
        """
        keyword_store_path = self.query_one(
            "#hp_keyword_store_path", Input
        ).value.strip()
        if not keyword_store_path:
            raise ValidationError(
                "hp_keyword_store_path", "Keyword store path cannot be empty"
            )

        command_history_path = self.query_one(
            "#hp_command_history_path", Input
        ).value.strip()
        if not command_history_path:
            raise ValidationError(
                "hp_command_history_path", "Command history path cannot be empty"
            )

        max_history_raw = self.query_one(
            "#hp_max_command_history", Input
        ).value.strip()
        try:
            max_command_history = int(max_history_raw)
        except ValueError as exc:
            raise ValidationError(
                "hp_max_command_history",
                "Max command history must be a whole number",
            ) from exc
        if max_command_history < 1:
            raise ValidationError(
                "hp_max_command_history",
                "Max command history must be at least 1",
            )

        chat_history_path = self.query_one(
            "#hp_chat_history_path", Input
        ).value.strip()
        if not chat_history_path:
            raise ValidationError(
                "hp_chat_history_path", "Chat history path cannot be empty"
            )

        return {
            "keyword_store_path": keyword_store_path,
            "command_history_path": command_history_path,
            "max_command_history": max_command_history,
            "chat_history_path": chat_history_path,
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
