"""Azure settings panel.

Covers :class:`~servonaut.config.schema.AzureConfig` fields:
``enabled``, ``subscription_ids`` (list), ``resource_groups`` (list).

Persistence uses ``dataclasses.replace`` on the whole nested object so
that any fields this panel does not expose are left untouched.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Dict, List

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static, Switch

from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.screens.settings.widgets import PreviewBanner, StringListEditor

logger = logging.getLogger(__name__)


class AzurePanel(SettingsPanel):
    """Settings panel for the Azure VM provider.

    Edits :pyattr:`AppConfig.azure` — specifically ``enabled``,
    ``subscription_ids``, and ``resource_groups``. All other
    ``AzureConfig`` fields are preserved via ``dataclasses.replace`` so
    future schema additions are never silently discarded.
    """

    PANEL_ID = "azure"
    TITLE = "Azure"

    DEFAULT_CSS = """
    AzurePanel .section-label {
        padding: 1 0 0 0;
        color: $accent;
        text-style: bold;
    }
    AzurePanel StringListEditor {
        margin: 0 0 1 0;
    }
    """

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield the Azure form rows."""
        yield PreviewBanner("Azure integration")
        yield Horizontal(
            Static("Azure enabled", classes="label"),
            Switch(id="azure_enabled"),
            classes="setting_row",
        )

        yield Static("Subscription IDs", classes="section-label")
        yield Static(
            "One subscription ID per entry (e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)",
            classes="panel-status",
        )
        yield StringListEditor(
            placeholder="subscription-id",
            id="azure_subscription_ids",
        )

        yield Static("Resource Groups", classes="section-label")
        yield Static(
            "Limit discovery to these resource groups (leave empty for all)",
            classes="panel-status",
        )
        yield StringListEditor(
            placeholder="resource-group-name",
            id="azure_resource_groups",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        azure = self.app.config_manager.get().azure

        self.query_one("#azure_enabled", Switch).value = azure.enabled

        self.query_one("#azure_subscription_ids", StringListEditor).set_values(
            list(azure.subscription_ids)
        )
        self.query_one("#azure_resource_groups", StringListEditor).set_values(
            list(azure.resource_groups)
        )

        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "enabled": self.query_one("#azure_enabled", Switch).value,
            "subscription_ids": self.query_one(
                "#azure_subscription_ids", StringListEditor
            ).get_values(),
            "resource_groups": self.query_one(
                "#azure_resource_groups", StringListEditor
            ).get_values(),
        }

    def collect(self) -> Dict[str, Any]:
        """Validate and return the fields to persist.

        Returns:
            Dict with ``enabled``, ``subscription_ids``, and
            ``resource_groups`` keys ready for ``dataclasses.replace``.

        Raises:
            ValidationError: When a subscription ID contains a space
                (a common paste error for UUIDs).
        """
        enabled: bool = self.query_one("#azure_enabled", Switch).value

        subscription_ids: List[str] = self.query_one(
            "#azure_subscription_ids", StringListEditor
        ).get_values()

        for sid in subscription_ids:
            if " " in sid:
                raise ValidationError(
                    "azure_subscription_ids",
                    f"Subscription ID '{sid}' must not contain spaces",
                )

        resource_groups: List[str] = self.query_one(
            "#azure_resource_groups", StringListEditor
        ).get_values()

        return {
            "enabled": enabled,
            "subscription_ids": subscription_ids,
            "resource_groups": resource_groups,
        }

    def persist(self) -> None:
        """Validate via :meth:`collect` and write the azure nested config.

        Uses ``dataclasses.replace`` on the existing ``AzureConfig``
        object so that any fields not shown in this panel are preserved
        verbatim.
        """
        fields = self.collect()
        config = self.app.config_manager.get()
        new_azure = dataclasses.replace(
            config.azure,
            enabled=fields["enabled"],
            subscription_ids=fields["subscription_ids"],
            resource_groups=fields["resource_groups"],
        )
        self.app.config_manager.update(azure=new_azure)
        self._finish_save()

    # ------------------------------------------------------------------
    # Dirty-marker refresh
    # ------------------------------------------------------------------

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Refresh the dirty marker when the enabled toggle changes."""
        self._dirty_watch()

    def on_button_pressed(self, event) -> None:  # type: ignore[override]
        """Delegate save button to base; let StringListEditor handle its own."""
        super().on_button_pressed(event)
        # StringListEditor's add/remove buttons bubble up but are already
        # stopped inside the widget; we just need the dirty marker refresh.
        self._dirty_watch()

    def is_dirty(self) -> bool:
        """Override to handle list editors whose equality is order-sensitive."""
        try:
            current = self.current_values()
            snap = self._snapshot
            if current.get("enabled") != snap.get("enabled"):
                return True
            if sorted(current.get("subscription_ids", [])) != sorted(
                snap.get("subscription_ids", [])
            ):
                return True
            if sorted(current.get("resource_groups", [])) != sorted(
                snap.get("resource_groups", [])
            ):
                return True
            return False
        except Exception:  # pragma: no cover - defensive
            return False
