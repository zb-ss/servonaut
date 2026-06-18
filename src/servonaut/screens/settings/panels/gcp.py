"""GCP settings panel — Google Cloud Platform provider configuration.

Covers :class:`~servonaut.config.schema.GCPConfig`:
  - ``enabled`` (Switch)
  - ``project_ids`` (StringListEditor)
  - ``credentials_path`` (Input — local filesystem path to a service-account JSON)
  - ``zones`` (StringListEditor — empty list means all zones)

Persistence uses ``dataclasses.replace`` on the existing ``GCPConfig`` so any
future fields added to the dataclass are not silently zeroed out by a partial
save from this panel.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Input, Static, Switch

from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.screens.settings.widgets import PreviewBanner, StringListEditor


class GcpPanel(SettingsPanel):
    """GCP Compute Engine provider settings panel.

    Fields:
        enabled: master switch to activate the GCP provider.
        project_ids: list of GCP project IDs to query for instances.
        credentials_path: local path to a service-account JSON key file.
        zones: list of zones to scope queries (empty = all zones).
    """

    PANEL_ID = "gcp"
    TITLE = "GCP (Google Cloud)"

    DEFAULT_CSS = """
    GcpPanel .gcp-section-label {
        color: $accent;
        text-style: bold;
        margin: 1 0 0 0;
    }
    GcpPanel .gcp-help {
        color: $text-muted;
        padding: 0 0 0 1;
        height: auto;
    }
    """

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield the GCP form rows."""
        yield PreviewBanner("Google Cloud integration")
        yield Horizontal(
            Static("Enabled", classes="label"),
            Switch(value=False, id="gcp_enabled"),
            classes="setting_row",
        )
        yield Static("Project IDs", classes="gcp-section-label")
        yield Static(
            "One GCP project ID per entry. Leave empty to disable.",
            classes="gcp-help",
        )
        yield StringListEditor(
            placeholder="my-project-id",
            id="gcp_project_ids",
        )
        yield Horizontal(
            Static("Credentials path", classes="label"),
            Input(
                placeholder="~/.config/gcloud/application_default_credentials.json",
                id="gcp_credentials_path",
            ),
            classes="setting_row",
        )
        yield Static(
            "Path to a service-account JSON key file. Leave empty to use"
            " Application Default Credentials (ADC).",
            classes="gcp-help",
        )
        yield Static("Zones", classes="gcp-section-label")
        yield Static(
            "One zone per entry (e.g. us-central1-a). Leave empty to query all zones.",
            classes="gcp-help",
        )
        yield StringListEditor(
            placeholder="us-central1-a",
            id="gcp_zones",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        gcp = self.app.config_manager.get().gcp
        self.query_one("#gcp_enabled", Switch).value = gcp.enabled
        self.query_one("#gcp_credentials_path", Input).value = gcp.credentials_path
        self.query_one("#gcp_project_ids", StringListEditor).set_values(
            list(gcp.project_ids)
        )
        self.query_one("#gcp_zones", StringListEditor).set_values(list(gcp.zones))
        self._snapshot_now()

    # ------------------------------------------------------------------
    # Dirty tracking
    # ------------------------------------------------------------------

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "enabled": self.query_one("#gcp_enabled", Switch).value,
            "credentials_path": (
                self.query_one("#gcp_credentials_path", Input).value.strip()
            ),
            "project_ids": self.query_one("#gcp_project_ids", StringListEditor).get_values(),
            "zones": self.query_one("#gcp_zones", StringListEditor).get_values(),
        }

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Refresh the dirty marker when the enabled switch is toggled."""
        self._dirty_watch()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Refresh the dirty marker on any text input change."""
        self._dirty_watch()

    def on_button_pressed(self, event) -> None:
        """Delegate to base for Save; also refresh dirty on list edits."""
        # StringListEditor buttons (add / remove) change the list but do not
        # fire Input.Changed on the panel level — so we refresh here first.
        self._dirty_watch()
        super().on_button_pressed(event)

    # ------------------------------------------------------------------
    # Validation + persistence
    # ------------------------------------------------------------------

    def collect(self) -> Dict[str, Any]:
        """Read and validate widgets, returning a field dict.

        Raises:
            ValidationError: When credentials_path is non-empty but looks
                suspicious (contains newlines or null bytes — a basic sanity
                check on the locally-owned path input).
        """
        credentials_path = (
            self.query_one("#gcp_credentials_path", Input).value.strip()
        )
        if credentials_path and (
            "\n" in credentials_path or "\x00" in credentials_path
        ):
            raise ValidationError(
                "gcp_credentials_path",
                "Credentials path contains invalid characters.",
            )

        return {
            "enabled": self.query_one("#gcp_enabled", Switch).value,
            "credentials_path": credentials_path,
            "project_ids": (
                self.query_one("#gcp_project_ids", StringListEditor).get_values()
            ),
            "zones": self.query_one("#gcp_zones", StringListEditor).get_values(),
        }

    def persist(self) -> None:
        """Validate via :meth:`collect` then write the GCP nested config.

        Uses ``dataclasses.replace`` on the existing :class:`GCPConfig`
        so any fields not exposed by this panel are preserved verbatim.
        """
        fields = self.collect()
        existing_gcp = self.app.config_manager.get().gcp
        updated_gcp = dataclasses.replace(
            existing_gcp,
            enabled=fields["enabled"],
            credentials_path=fields["credentials_path"],
            project_ids=fields["project_ids"],
            zones=fields["zones"],
        )
        self.app.config_manager.update(gcp=updated_gcp)
        state = "enabled" if fields["enabled"] else "disabled"
        self._finish_save(f"GCP settings saved (provider {state})")
