"""Local config backup browser and restore screen."""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Static

from servonaut.screens._compact_actions import sync_compact_buttons
from servonaut.config.manager import MAX_BACKUPS, MAX_UPGRADE_BACKUPS, describe_backup
from servonaut.widgets.action_button import ActionButton, ActionRow
from servonaut.widgets.dialogs import (
    DialogActions,
    DialogBody,
    DialogFrame,
    DialogNotificationSpace,
)
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

logger = logging.getLogger(__name__)


class BackupConfirmModal(ModalScreen[bool]):
    """Yes/No modal for restore confirmation."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("y", "confirm", "Yes", show=False),
        Binding("n", "cancel", "No", show=False),
    ]

    AUTO_FOCUS = "#btn_bkp_no"

    def __init__(self, message: str) -> None:
        super().__init__(classes="dialog-screen")
        self._message = message

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static(
                "[bold $text-accent]Restore local backup[/bold $text-accent]",
                id="bkp_confirm_title",
            ),
            body=DialogBody(Static(self._message, id="bkp_confirm_message")),
            actions=DialogActions(
                Button("Restore", variant="primary", id="btn_bkp_yes"),
                Button("Cancel", id="btn_bkp_no"),
                id="bkp_confirm_buttons",
            ),
            id="bkp_confirm_container",
            size="compact",
            severity="warning",
        )

    def on_mount(self) -> None:
        self.query_one("#btn_bkp_no", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "btn_bkp_yes")

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class BackupRestoreScreen(WorkspaceScreen):
    """List local config backups and restore one."""

    AUTO_FOCUS = "#backups_container"

    CHAT_REFLOW = True
    CHAT_MIN_CONTENT_WIDTH = 56
    CONTENT_NARROW_WIDTH = 88

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "restore", "Restore", show=True),
        Binding("f5", "refresh", "Refresh", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._backups: List[Dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield WorkspaceControls("Local backups")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            yield VerticalScroll(
                Container(
                    Static("[bold $text-accent]Local config backups[/bold $text-accent]", id="backups_header"),
                    id="backups_context",
                ),
                Horizontal(
                    VerticalScroll(
                        Static(
                            "[dim]Every time the config is saved (settings edit, sync pull, "
                            "setup wizard…) the previous version is snapshotted here. The "
                            f"{MAX_BACKUPS} most recent are kept, plus the copies taken before "
                            f"the last {MAX_UPGRADE_BACKUPS} config format upgrades.[/dim]",
                            id="backups_hint",
                        ),
                        Static("", id="backups_status"),
                        Container(
                            Static("Selected backup", classes="backup-panel-heading"),
                            ActionRow(
                                ActionButton("Restore", "r", role="primary", id="btn_bkp_restore"),
                                ActionButton("Refresh", "F5", id="btn_bkp_refresh"),
                                id="backups_actions",
                            ),
                            classes="backup-action-panel",
                        ),
                        id="backups_tools",
                    ),
                    Container(
                        Static("Local backup history", classes="backup-panel-heading"),
                        Static("Loading local backup history…", id="backups_empty"),
                        DataTable(id="backups_table", zebra_stripes=True, cursor_type="row"),
                        id="backups_records",
                    ),
                    id="backups_workspace",
                ),
                id="backups_container",
                classes="workspace-content",
            )
        yield Footer()

    def sync_workspace_controls(self) -> None:
        super().sync_workspace_controls()
        sync_compact_buttons(self)

    def on_mount(self) -> None:
        sync_compact_buttons(self)
        table = self.query_one("#backups_table", DataTable)
        table.add_columns("#", "Timestamp", "Kind", "Size", "Custom servers", "OVH enabled")
        self._refresh()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        cm = getattr(self.app, "config_manager", None)
        if cm is None:
            self._set_status("[$text-error]Config manager unavailable.[/$text-error]")
            return
        try:
            self._backups = cm.list_backups()
        except Exception as exc:
            logger.error("Failed to list backups: %s", exc)
            self._set_status(f"[$text-error]Failed to list backups: {exc}[/$text-error]")
            return
        self._render_table()
        n = len(self._backups)
        if n == 0:
            self._set_status(
                "[dim]No backups yet. Backups are created automatically "
                "whenever the config is saved.[/dim]"
            )
        else:
            self._set_status(f"[dim]{n} backup{'s' if n != 1 else ''}.[/dim]")

    def _render_table(self) -> None:
        table = self.query_one("#backups_table", DataTable)
        table.clear()
        for idx, entry in enumerate(self._backups, start=1):
            summary = self._summarize(entry["path"])
            table.add_row(
                str(idx),
                self._format_timestamp(entry["timestamp"]),
                describe_backup(entry),
                self._format_size(entry["size_bytes"]),
                str(summary.get("custom_servers_count", "?")),
                "yes" if summary.get("ovh_enabled") else "no",
                key=str(entry["path"]),
            )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_bkp_restore":
            self.action_restore()
        elif event.button.id == "btn_bkp_refresh":
            self.action_refresh()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._refresh()

    def action_restore(self) -> None:
        entry = self._selected()
        if not entry:
            return
        path: Path = entry["path"]
        ts = self._format_timestamp(entry["timestamp"])
        summary = self._summarize(path)
        detail = (
            f"[bold]{ts}[/bold] ({describe_backup(entry)})\n"
            f"Custom servers: {summary.get('custom_servers_count', '?')}\n"
            f"OVH enabled: {'yes' if summary.get('ovh_enabled') else 'no'}\n\n"
            "Your current config will itself be backed up before the restore, "
            "so you can undo."
        )
        self.app.push_screen(
            BackupConfirmModal(message=detail),
            callback=lambda ok: self._restore_after_confirm(path, ok),
        )

    def _restore_after_confirm(self, path: Path, ok: Optional[bool]) -> None:
        if not ok:
            return
        cm = getattr(self.app, "config_manager", None)
        if cm is None:
            return
        try:
            cm.restore_backup(path)
            self.notify(
                "Config restored. Restart Servonaut to ensure everything picks up the change.",
                severity="information",
            )
            self._refresh()
        except Exception as exc:
            logger.error("Restore failed: %s", exc)
            self.notify(f"Restore failed: {exc}", severity="error", markup=False)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _selected(self) -> Optional[Dict[str, Any]]:
        table = self.query_one("#backups_table", DataTable)
        row = table.cursor_row
        if row is None or row < 0 or row >= len(self._backups):
            self.notify("Select a backup first.", severity="warning")
            return None
        return self._backups[row]

    def _set_status(self, msg: str) -> None:
        try:
            self.query_one("#backups_status", Static).update(msg)
            empty = self.query_one("#backups_empty", Static)
            empty.update(msg)
            empty.display = not self._backups
        except Exception:
            pass

    @staticmethod
    def _summarize(path: Path) -> Dict[str, Any]:
        """Extract a few quick-look fields from the backup JSON."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            return {}
        return {
            "custom_servers_count": len(data.get("custom_servers") or []),
            "ovh_enabled": bool(data.get("ovh", {}).get("enabled")),
            "scan_rules_count": len(data.get("scan_rules") or []),
            "connection_profiles_count": len(data.get("connection_profiles") or []),
        }

    @staticmethod
    def _format_timestamp(ts: datetime) -> str:
        try:
            return ts.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(ts)

    @staticmethod
    def _format_size(n: int) -> str:
        if n < 1024:
            return f"{n} B"
        if n < 1024 * 1024:
            return f"{n / 1024:.1f} KB"
        return f"{n / (1024 * 1024):.1f} MB"
