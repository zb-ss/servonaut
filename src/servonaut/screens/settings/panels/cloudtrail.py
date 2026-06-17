"""CloudTrail settings panel.

Exposes the four top-level CloudTrail scalar fields from :class:`AppConfig`:

- ``cloudtrail_default_region``
- ``cloudtrail_max_events``
- ``cloudtrail_default_lookback_hours``
- ``cloudtrail_default_lookback_minutes``

All are top-level scalars, so persistence goes through
``config_manager.update(**fields)`` without any nested-dataclass replacement.
"""

from __future__ import annotations

from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Input, Static

from servonaut.screens.settings.base import SettingsPanel, ValidationError


class CloudtrailPanel(SettingsPanel):
    """Settings panel for AWS CloudTrail event browsing defaults."""

    PANEL_ID = "cloudtrail"
    TITLE = "CloudTrail"

    def form_rows(self) -> ComposeResult:
        """Yield the CloudTrail form rows."""
        yield Horizontal(
            Static("Default region", classes="label"),
            Input(
                placeholder="us-east-1  (leave blank to use AWS default)",
                id="cloudtrail_default_region",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Max events", classes="label"),
            Input(placeholder="100", id="cloudtrail_max_events"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Default lookback hours", classes="label"),
            Input(placeholder="24", id="cloudtrail_default_lookback_hours"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Default lookback minutes", classes="label"),
            Input(placeholder="0", id="cloudtrail_default_lookback_minutes"),
            classes="setting_row",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()
        self.query_one("#cloudtrail_default_region", Input).value = (
            config.cloudtrail_default_region
        )
        self.query_one("#cloudtrail_max_events", Input).value = str(
            config.cloudtrail_max_events
        )
        self.query_one("#cloudtrail_default_lookback_hours", Input).value = str(
            config.cloudtrail_default_lookback_hours
        )
        self.query_one("#cloudtrail_default_lookback_minutes", Input).value = str(
            config.cloudtrail_default_lookback_minutes
        )
        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "cloudtrail_default_region": self.query_one(
                "#cloudtrail_default_region", Input
            ).value.strip(),
            "cloudtrail_max_events": self.query_one(
                "#cloudtrail_max_events", Input
            ).value.strip(),
            "cloudtrail_default_lookback_hours": self.query_one(
                "#cloudtrail_default_lookback_hours", Input
            ).value.strip(),
            "cloudtrail_default_lookback_minutes": self.query_one(
                "#cloudtrail_default_lookback_minutes", Input
            ).value.strip(),
        }

    def collect(self) -> Dict[str, Any]:
        """Validate and return the fields to persist.

        Raises:
            ValidationError: When any integer field is non-numeric or negative.
        """
        region = self.query_one("#cloudtrail_default_region", Input).value.strip()

        max_events_raw = self.query_one(
            "#cloudtrail_max_events", Input
        ).value.strip()
        try:
            max_events = int(max_events_raw)
        except ValueError as exc:
            raise ValidationError(
                "cloudtrail_max_events", "Max events must be a whole number"
            ) from exc
        if max_events < 1:
            raise ValidationError(
                "cloudtrail_max_events", "Max events must be at least 1"
            )

        lookback_hours_raw = self.query_one(
            "#cloudtrail_default_lookback_hours", Input
        ).value.strip()
        try:
            lookback_hours = int(lookback_hours_raw)
        except ValueError as exc:
            raise ValidationError(
                "cloudtrail_default_lookback_hours",
                "Lookback hours must be a whole number",
            ) from exc
        if lookback_hours < 0:
            raise ValidationError(
                "cloudtrail_default_lookback_hours",
                "Lookback hours must be zero or greater",
            )

        lookback_minutes_raw = self.query_one(
            "#cloudtrail_default_lookback_minutes", Input
        ).value.strip()
        try:
            lookback_minutes = int(lookback_minutes_raw)
        except ValueError as exc:
            raise ValidationError(
                "cloudtrail_default_lookback_minutes",
                "Lookback minutes must be a whole number",
            ) from exc
        if lookback_minutes < 0:
            raise ValidationError(
                "cloudtrail_default_lookback_minutes",
                "Lookback minutes must be zero or greater",
            )

        return {
            "cloudtrail_default_region": region,
            "cloudtrail_max_events": max_events,
            "cloudtrail_default_lookback_hours": lookback_hours,
            "cloudtrail_default_lookback_minutes": lookback_minutes,
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
