"""Relay settings panel.

Exposes :class:`~servonaut.config.schema.RelayConfig` fields:

- ``base_url`` — REST API base URL for the relay listener
- ``mercure_url`` — Mercure hub URL for SSE subscriptions
- ``heartbeat_interval`` — integer seconds between heartbeat posts
- ``ai_tool_auto_approve`` — Select (readonly / standard / dangerous),
  with an inline warning when 'dangerous' is selected

Uses ``dataclasses.replace`` to preserve any future ``RelayConfig`` fields
not exposed in this panel.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Dict, List

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Input, Select, Static

from servonaut.screens.settings.base import SettingsPanel, ValidationError

logger = logging.getLogger(__name__)

_AUTO_APPROVE_OPTIONS: List[tuple] = [
    ("Read-only", "readonly"),
    ("Standard", "standard"),
    ("Dangerous", "dangerous"),
]

# Shown inline when ai_tool_auto_approve is set to 'dangerous'.
_WARN_DANGEROUS_AUTO_APPROVE = (
    "Warning: 'Dangerous' auto-approve grants the relay executor elevated "
    "tool access without human confirmation. Use only when you fully trust "
    "the AI agent dispatching commands over the relay."
)

_VALID_AUTO_APPROVE_TIERS = frozenset({"readonly", "standard", "dangerous"})


class RelayPanel(SettingsPanel):
    """Settings panel for the relay listener configuration.

    Fields map directly to :class:`~servonaut.config.schema.RelayConfig`.
    ``dataclasses.replace`` is used on persist so any future schema additions
    are preserved.
    """

    PANEL_ID = "relay"
    TITLE = "Relay"

    DEFAULT_CSS = """
    RelayPanel .relay-warn {
        color: $warning;
        padding: 0 0 0 1;
        height: auto;
    }
    RelayPanel .relay-help {
        color: $text-muted;
        padding: 0 0 0 1;
        height: auto;
    }
    """

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield the Relay form rows."""
        yield Static(
            "Configure the relay listener that executes AI tool calls dispatched "
            "from the cloud. Leave URLs empty to use the defaults from environment.",
            classes="relay-help",
        )

        # base_url
        yield Horizontal(
            Static("API base URL", classes="label"),
            Input(
                placeholder="https://api.servonaut.dev",
                id="relay_base_url",
            ),
            classes="setting_row",
        )

        # mercure_url
        yield Horizontal(
            Static("Mercure hub URL", classes="label"),
            Input(
                placeholder="https://servonaut.dev/.well-known/mercure",
                id="relay_mercure_url",
            ),
            classes="setting_row",
        )

        # heartbeat_interval
        yield Horizontal(
            Static("Heartbeat interval (seconds)", classes="label"),
            Input(placeholder="30", id="relay_heartbeat_interval"),
            classes="setting_row",
        )

        # ai_tool_auto_approve
        yield Horizontal(
            Static("AI tool auto-approve tier", classes="label"),
            Select(
                _AUTO_APPROVE_OPTIONS,
                value="standard",
                allow_blank=False,
                id="relay_ai_tool_auto_approve",
            ),
            classes="setting_row",
        )
        yield Static(
            "",
            id="relay_auto_approve_warn",
            classes="relay-warn",
        )
        yield Static(
            "Maximum guard tier the relay listener will auto-approve when executing "
            "AI tool calls without human confirmation. Tools above this tier are refused.",
            classes="relay-help",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()
        relay = config.relay

        self.query_one("#relay_base_url", Input).value = relay.base_url
        self.query_one("#relay_mercure_url", Input).value = relay.mercure_url
        self.query_one("#relay_heartbeat_interval", Input).value = str(relay.heartbeat_interval)

        tier = (
            relay.ai_tool_auto_approve
            if relay.ai_tool_auto_approve in _VALID_AUTO_APPROVE_TIERS
            else "standard"
        )
        self.query_one("#relay_ai_tool_auto_approve", Select).value = tier
        self._update_auto_approve_warn(tier)

        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "base_url": self.query_one("#relay_base_url", Input).value.strip(),
            "mercure_url": self.query_one("#relay_mercure_url", Input).value.strip(),
            "heartbeat_interval": self.query_one("#relay_heartbeat_interval", Input).value.strip(),
            "ai_tool_auto_approve": str(
                self.query_one("#relay_ai_tool_auto_approve", Select).value
            ),
        }

    def collect(self) -> Dict[str, Any]:
        """Validate and return the relay fields to persist.

        Raises:
            ValidationError: When heartbeat_interval is not a positive integer.
        """
        base_url = self.query_one("#relay_base_url", Input).value.strip()
        mercure_url = self.query_one("#relay_mercure_url", Input).value.strip()

        heartbeat_raw = self.query_one("#relay_heartbeat_interval", Input).value.strip()
        try:
            heartbeat = int(heartbeat_raw)
        except ValueError as exc:
            raise ValidationError(
                "relay_heartbeat_interval",
                "Heartbeat interval must be a whole number of seconds",
            ) from exc
        if heartbeat < 1:
            raise ValidationError(
                "relay_heartbeat_interval",
                "Heartbeat interval must be at least 1 second",
            )

        tier = str(self.query_one("#relay_ai_tool_auto_approve", Select).value)

        return {
            "base_url": base_url,
            "mercure_url": mercure_url,
            "heartbeat_interval": heartbeat,
            "ai_tool_auto_approve": tier,
        }

    def persist(self) -> None:
        """Validate via :meth:`collect` then write through config_manager.

        Uses ``dataclasses.replace`` so future ``RelayConfig`` fields not
        exposed by this panel are preserved.
        """
        fields = self.collect()

        config = self.app.config_manager.get()
        updated_relay = dataclasses.replace(
            config.relay,
            base_url=fields["base_url"],
            mercure_url=fields["mercure_url"],
            heartbeat_interval=fields["heartbeat_interval"],
            ai_tool_auto_approve=fields["ai_tool_auto_approve"],
        )
        self.app.config_manager.update(relay=updated_relay)
        self._finish_save()

    # ------------------------------------------------------------------
    # Dirty marker refresh
    # ------------------------------------------------------------------

    def on_input_changed(self, _event: Input.Changed) -> None:
        """Refresh the dirty marker on any text input edit."""
        self._dirty_watch()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Refresh the dirty marker and update the auto-approve warning."""
        self._dirty_watch()
        if event.select.id == "relay_ai_tool_auto_approve":
            self._update_auto_approve_warn(str(event.value))

    # ------------------------------------------------------------------
    # Inline security warning
    # ------------------------------------------------------------------

    def _update_auto_approve_warn(self, tier: str) -> None:
        """Show or hide the dangerous auto-approve warning."""
        try:
            warn = self.query_one("#relay_auto_approve_warn", Static)
        except Exception:
            return
        if tier == "dangerous":
            warn.update(escape(_WARN_DANGEROUS_AUTO_APPROVE))
        else:
            warn.update("")
