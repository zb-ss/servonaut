"""Backups settings panel.

This panel is a launcher hub for config backup and restore workflows:

* **Manage Snapshots** — pushes
  :class:`~servonaut.screens.snapshot_manager.SnapshotManagerScreen` to browse
  and manage encrypted cloud config snapshots.  The button is gated on
  ``config_sync_service`` being available (requires the matching plan).
* **Restore Local Backup** — pushes
  :class:`~servonaut.screens.backup_restore.BackupRestoreScreen` to recover
  from a locally kept config snapshot (the 5 most recent saves are retained).

Neither launcher edits config fields directly, so the panel owns no editable
widgets, ``is_dirty`` always returns ``False``, and the Save dock is hidden.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, Static

from servonaut.screens.settings.base import SettingsPanel

logger = logging.getLogger(__name__)

_SNAPSHOT_INFO = (
    "Manage encrypted config snapshots stored in the cloud. "
    "Push from one machine, pull from another. Label each snapshot "
    "(e.g. by hostname) so you can tell them apart."
)

_BACKUP_INFO = (
    "Every config save is automatically snapshotted locally. "
    "The 5 most recent are kept — use this to recover from a bad "
    "sync pull or a misconfiguration."
)


class BackupsPanel(SettingsPanel):
    """Settings panel: launchers for snapshot management and local backup restore.

    The panel contains two action buttons only — no editable fields. All
    substantive interaction happens inside the dedicated screens that are pushed
    when the user clicks a button.
    """

    PANEL_ID = "backups"
    TITLE = "Backups"

    DEFAULT_CSS = """
    BackupsPanel .backups-section-label {
        text-style: bold;
        margin-top: 1;
        margin-bottom: 0;
    }

    BackupsPanel .backups-note {
        color: $text-muted;
        height: auto;
        padding: 0 0 1 0;
    }

    BackupsPanel #panel_save_dock_backups {
        display: none;
    }
    """

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield the snapshot and local-backup launcher rows."""
        yield Static("Config Sync", classes="backups-section-label")
        yield Static(_SNAPSHOT_INFO, classes="backups-note")
        yield Horizontal(
            Button(
                "Manage Snapshots",
                id="backups_open_snapshots",
                variant="primary",
            ),
            classes="setting_row",
        )

        yield Static("Local Backups", classes="backups-section-label")
        yield Static(_BACKUP_INFO, classes="backups-note")
        yield Horizontal(
            Button(
                "Restore Local Backup",
                id="backups_open_restore",
                variant="default",
            ),
            classes="setting_row",
        )

    # ------------------------------------------------------------------
    # Lifecycle — nothing to load; snapshot baseline is the empty dict
    # ------------------------------------------------------------------

    def load(self) -> None:
        """No config fields to populate; snapshot the (empty) baseline."""
        self._snapshot_now()

    # ------------------------------------------------------------------
    # Panel contract — no editable fields, always clean
    # ------------------------------------------------------------------

    def current_values(self) -> Dict[str, Any]:
        """Return an empty dict — this panel owns no editable fields."""
        return {}

    def collect(self) -> Dict[str, Any]:
        """Nothing to collect — all changes occur inside the launched screens."""
        return {}

    def persist(self) -> None:
        """Nothing to persist — all edits happen in the dedicated screens."""

    def is_dirty(self) -> bool:
        """Always ``False`` — this panel exposes no editable fields."""
        return False

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Route launcher buttons; delegate the Save button to base."""
        btn_id = event.button.id
        if btn_id == "backups_open_snapshots":
            event.stop()
            self._open_snapshot_manager()
            return
        if btn_id == "backups_open_restore":
            event.stop()
            self._open_backup_restore()
            return
        # Delegate the (hidden) Save-dock button to the base handler.
        super().on_button_pressed(event)

    def _open_snapshot_manager(self) -> None:
        """Push SnapshotManagerScreen, gated on config_sync_service availability."""
        sync = getattr(self.app, "config_sync_service", None)
        if sync is None:
            self.app.notify(
                "Config sync is not available on this plan.",
                severity="warning",
                markup=False,
            )
            return
        from servonaut.screens.snapshot_manager import SnapshotManagerScreen  # noqa: PLC0415

        self.app.push_screen(SnapshotManagerScreen())

    def _open_backup_restore(self) -> None:
        """Push BackupRestoreScreen to browse locally kept config snapshots."""
        from servonaut.screens.backup_restore import BackupRestoreScreen  # noqa: PLC0415

        self.app.push_screen(BackupRestoreScreen())
