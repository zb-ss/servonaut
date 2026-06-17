"""Custom Servers settings panel.

This panel is a launcher: all CRUD for custom (non-AWS) servers lives in
:class:`~servonaut.screens.custom_servers.CustomServersScreen`, which already
provides a full add/edit/remove workflow.  This panel's job is to surface the
current count and give the user a clear entry-point button from within the
Settings master/detail view.

Because the panel owns no editable fields it is always clean (``is_dirty``
returns ``False``) and the Save button is intentionally disabled — nothing to
save here.
"""

from __future__ import annotations

from typing import Any, Dict

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, Static

from servonaut.screens.settings.base import SettingsPanel


class CustomServersPanel(SettingsPanel):
    """Settings panel: launcher to the Custom Servers CRUD screen.

    Shows the current count of configured custom servers and a button that
    pushes :class:`~servonaut.screens.custom_servers.CustomServersScreen`
    onto the screen stack so the user can add, edit, or remove servers.
    """

    PANEL_ID = "custom_servers"
    TITLE = "Custom Servers"

    DEFAULT_CSS = """
    CustomServersPanel .custom-servers-note {
        color: $text-muted;
        margin-bottom: 1;
    }

    CustomServersPanel .custom-servers-count {
        margin-bottom: 1;
    }

    CustomServersPanel #panel_save_dock_custom_servers {
        display: none;
    }
    """

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield the launcher row and count note."""
        yield Static(
            "Manage non-AWS servers (DigitalOcean, Hetzner, bare-metal, etc.).",
            classes="custom-servers-note",
        )
        yield Static("", id="custom_servers_count", classes="custom-servers-count")
        yield Horizontal(
            Button(
                "Open Custom Servers",
                id="open_custom_servers",
                variant="primary",
            ),
            classes="setting_row",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate the server count label from config and snapshot."""
        self._refresh_count()
        self._snapshot_now()

    def _refresh_count(self) -> None:
        """Update the count label from the current config."""
        try:
            config = self.app.config_manager.get()
            count = len(config.custom_servers)
        except Exception:
            count = 0
        try:
            label = self.query_one("#custom_servers_count", Static)
            noun = "server" if count == 1 else "servers"
            label.update(escape(f"{count} custom {noun} configured."))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Panel contract (no editable fields — always clean)
    # ------------------------------------------------------------------

    def current_values(self) -> Dict[str, Any]:
        """Return an empty snapshot — no editable fields in this panel."""
        return {}

    def collect(self) -> Dict[str, Any]:
        """Nothing to collect — no editable fields."""
        return {}

    def persist(self) -> None:
        """Nothing to persist — all changes happen in CustomServersScreen."""
        self._finish_save("Custom server changes are saved from the Custom Servers screen.")

    def is_dirty(self) -> bool:
        """Always clean — this panel owns no editable fields."""
        return False

    # ------------------------------------------------------------------
    # Button handler
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Delegate Save to base; handle the launcher button here."""
        if event.button.id == "open_custom_servers":
            event.stop()
            # Import here to avoid circular-import at module load time.
            from servonaut.screens.custom_servers import CustomServersScreen  # noqa: PLC0415

            self.app.push_screen(CustomServersScreen())
            return
        # Let the base class handle the Save button (no-op persist above).
        super().on_button_pressed(event)

    # ------------------------------------------------------------------
    # Dirty marker refresh (no inputs — nothing to track)
    # ------------------------------------------------------------------
