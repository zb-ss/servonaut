"""SSH Keys settings panel.

Launcher panel for the :class:`~servonaut.screens.key_management.KeyManagementScreen`
which owns the full CRUD workflow for instance-specific SSH key mappings and the
default SSH key. This panel shows a summary count of configured per-instance key
overrides and a single button to open that screen.

There are no editable fields here — all key management happens in
``KeyManagementScreen``. Because of this the panel's :meth:`collect` and
:meth:`persist` are no-ops and :meth:`is_dirty` always returns ``False``.
The Save dock inherited from :class:`SettingsPanel` is hidden via CSS to keep
the UI clean.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, Static

from servonaut.screens.settings.base import SettingsPanel

logger = logging.getLogger(__name__)

_INFO_TEXT = (
    "Per-instance SSH key overrides let you map a specific server ID to a "
    "key file, bypassing the default key. Manage them in the Key Management screen."
)


class SshKeysPanel(SettingsPanel):
    """Launcher panel for SSH key management.

    Shows the count of configured per-instance key overrides and a button to
    open :class:`~servonaut.screens.key_management.KeyManagementScreen`.
    """

    PANEL_ID = "ssh_keys"
    TITLE = "SSH Keys"

    DEFAULT_CSS = """
    SshKeysPanel .ssh-keys-info {
        color: $text-muted;
        height: auto;
        padding: 0 0 1 0;
    }
    SshKeysPanel .ssh-keys-count {
        height: auto;
        padding: 0 0 1 0;
    }
    SshKeysPanel #panel_save_dock_ssh_keys {
        display: none;
    }
    """

    def form_rows(self) -> ComposeResult:
        """Yield the SSH keys summary and launcher button."""
        yield Static(escape(_INFO_TEXT), classes="ssh-keys-info")
        yield Static("", id="ssh_keys_count", classes="ssh-keys-count")
        yield Horizontal(
            Button(
                "Open Key Management",
                id="ssh_keys_open",
                variant="primary",
            ),
            classes="setting_row",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Refresh the instance-key count from config and snapshot."""
        config = self.app.config_manager.get()
        count = len(config.instance_keys)
        label = _format_count(count)
        try:
            self.query_one("#ssh_keys_count", Static).update(label)
        except Exception:
            pass
        self._snapshot_now()

    # ------------------------------------------------------------------
    # Contract — no editable fields; nothing to validate or save
    # ------------------------------------------------------------------

    def collect(self) -> Dict[str, Any]:
        """Return an empty dict — this panel has no editable fields."""
        return {}

    def persist(self) -> None:
        """No-op — all edits happen inside KeyManagementScreen."""

    def current_values(self) -> Dict[str, Any]:
        """Return an empty dict — dirty state is always clean."""
        return {}

    def is_dirty(self) -> bool:
        """Always ``False`` — this panel exposes no editable fields."""
        return False

    # ------------------------------------------------------------------
    # Button handler
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Open KeyManagementScreen on the launcher button; delegate others."""
        if event.button.id == "ssh_keys_open":
            event.stop()
            self._open_key_management()
            return
        # Delegate save-dock button to base class handler.
        super().on_button_pressed(event)

    def _open_key_management(self) -> None:
        """Push KeyManagementScreen and reload the count on return."""
        from servonaut.screens.key_management import KeyManagementScreen

        def _on_dismiss(result: object) -> None:
            """Refresh the key count after the management screen closes."""
            try:
                self.load()
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("ssh_keys reload after KeyManagementScreen: %s", exc)

        self.app.push_screen(KeyManagementScreen(), _on_dismiss)


# ------------------------------------------------------------------
# Private helpers
# ------------------------------------------------------------------

def _format_count(count: int) -> str:
    """Return a human-readable label for the number of per-instance key overrides."""
    if count == 0:
        return "Per-instance key overrides: none configured"
    noun = "override" if count == 1 else "overrides"
    return f"Per-instance key overrides: {count} {noun} configured"
