"""CloudWatch settings panel.

Covers the three top-level CloudWatch scalars exposed in :class:`AppConfig`:

- ``cloudwatch_default_region`` — default AWS region for log browsing.
- ``cloudwatch_max_events``     — maximum events fetched per query (int ≥ 1).
- ``cloudwatch_log_group_prefix`` — optional prefix filter pre-applied when
  listing log groups.

All three are top-level scalar fields on :class:`AppConfig`, so they are
persisted via ``config_manager.update(...)`` with no nested-dataclass replace
needed.
"""

from __future__ import annotations

from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Input, Static

from servonaut.screens.settings.base import SettingsPanel, ValidationError


class CloudwatchPanel(SettingsPanel):
    """Settings for the CloudWatch log browser.

    Exposes the three CloudWatch scalar fields from :class:`AppConfig`:
    ``cloudwatch_default_region``, ``cloudwatch_max_events``, and
    ``cloudwatch_log_group_prefix``.
    """

    PANEL_ID = "cloudwatch"
    TITLE = "CloudWatch"

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield the CloudWatch form rows."""
        yield Horizontal(
            Static("Default region", classes="label"),
            Input(
                placeholder="e.g. us-east-1 (leave blank to use AWS default)",
                id="cloudwatch_default_region",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Max events", classes="label"),
            Input(
                placeholder="500",
                id="cloudwatch_max_events",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Log group prefix", classes="label"),
            Input(
                placeholder="e.g. /aws/lambda/ (leave blank to list all groups)",
                id="cloudwatch_log_group_prefix",
            ),
            classes="setting_row",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()
        self.query_one("#cloudwatch_default_region", Input).value = (
            config.cloudwatch_default_region
        )
        self.query_one("#cloudwatch_max_events", Input).value = str(
            config.cloudwatch_max_events
        )
        self.query_one("#cloudwatch_log_group_prefix", Input).value = (
            config.cloudwatch_log_group_prefix
        )
        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "cloudwatch_default_region": self.query_one(
                "#cloudwatch_default_region", Input
            ).value.strip(),
            "cloudwatch_max_events": self.query_one(
                "#cloudwatch_max_events", Input
            ).value.strip(),
            "cloudwatch_log_group_prefix": self.query_one(
                "#cloudwatch_log_group_prefix", Input
            ).value.strip(),
        }

    def collect(self) -> Dict[str, Any]:
        """Validate and return the fields to persist.

        Raises:
            ValidationError: When ``cloudwatch_max_events`` is not a positive
                integer.
        """
        region = self.query_one("#cloudwatch_default_region", Input).value.strip()

        max_events_raw = self.query_one("#cloudwatch_max_events", Input).value.strip()
        try:
            max_events = int(max_events_raw)
        except ValueError as exc:
            raise ValidationError(
                "cloudwatch_max_events",
                "Max events must be a whole number",
            ) from exc
        if max_events < 1:
            raise ValidationError(
                "cloudwatch_max_events",
                "Max events must be at least 1",
            )

        log_group_prefix = self.query_one(
            "#cloudwatch_log_group_prefix", Input
        ).value.strip()

        return {
            "cloudwatch_default_region": region,
            "cloudwatch_max_events": max_events,
            "cloudwatch_log_group_prefix": log_group_prefix,
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
