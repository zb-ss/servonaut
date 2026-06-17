"""IP Lookup settings panel — AbuseIPDB API key configuration.

Surfaces the ``abuseipdb_api_key`` field clearly with a help line explaining
where it is used (CloudWatch Top IPs → 'i' key) and where to obtain a free
key. The field is a top-level scalar on :class:`~servonaut.config.schema.AppConfig`,
so ``config_manager.update(abuseipdb_api_key=...)`` is all that is needed.

The key supports ``$ENV_VAR`` syntax; :class:`~servonaut.screens.settings.widgets.EnvVarInput`
shows a resolution hint (name + set/MISSING) without ever printing the secret.
"""

from __future__ import annotations

from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Input, Static

from servonaut.screens.settings.base import SettingsPanel
from servonaut.screens.settings.widgets import EnvVarInput


class IpLookupPanel(SettingsPanel):
    """Settings panel for IP lookup integrations (AbuseIPDB)."""

    PANEL_ID = "ip_lookup"
    TITLE = "IP Lookup"

    DEFAULT_CSS = """
    IpLookupPanel .ip-lookup-help {
        height: auto;
        color: $text-muted;
        margin: 0 0 1 0;
        padding: 0 1;
    }
    IpLookupPanel .ip-lookup-subhelp {
        height: auto;
        color: $text-muted;
        margin: 0 0 1 0;
        padding: 0 1;
    }
    """

    def form_rows(self) -> ComposeResult:
        """Yield the IP Lookup form rows."""
        yield Static(
            "AbuseIPDB enriches IP addresses with abuse report data. "
            "Press 'i' on any IP in the CloudWatch Top IPs view to look it up.",
            classes="ip-lookup-help",
        )
        yield Static(
            "A free API key (up to 1000 checks/day) is available at abuseipdb.com. "
            "Supports $ENV_VAR syntax (e.g. $ABUSEIPDB_API_KEY).",
            classes="ip-lookup-subhelp",
        )
        yield Horizontal(
            Static("AbuseIPDB API key", classes="label"),
            EnvVarInput(
                placeholder="your-api-key or $ABUSEIPDB_API_KEY",
                id="ip_lookup_abuseipdb_key",
                password=True,
            ),
            classes="setting_row",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()
        self.query_one("#ip_lookup_abuseipdb_key", EnvVarInput).value = (
            config.abuseipdb_api_key
        )
        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "abuseipdb_api_key": self.query_one(
                "#ip_lookup_abuseipdb_key", EnvVarInput
            ).value.strip(),
        }

    def collect(self) -> Dict[str, Any]:
        """Read and return the field to persist.

        The API key is optional — an empty string disables AbuseIPDB lookups.
        No validation errors can be raised here: any string (including empty)
        is valid for this field.
        """
        return {
            "abuseipdb_api_key": self.query_one(
                "#ip_lookup_abuseipdb_key", EnvVarInput
            ).value.strip(),
        }

    def persist(self) -> None:
        """Validate via :meth:`collect` then write the top-level scalar field."""
        fields = self.collect()
        self.app.config_manager.update(**fields)
        self._finish_save()

    # ------------------------------------------------------------------
    # Dirty marker refresh
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Refresh the dirty marker on any input edit."""
        self._dirty_watch()
