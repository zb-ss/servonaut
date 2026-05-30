"""Snapshot manager screen — list, restore, rename, delete, push config snapshots."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from servonaut.widgets.sidebar import Sidebar
from servonaut.services import config_crypto

logger = logging.getLogger(__name__)


class LabelInputModal(ModalScreen[Optional[str]]):
    """Plain text input for a snapshot label (rename + push-new).

    Dismisses with the trimmed label string (1–100 chars) or None on cancel.
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    def __init__(self, title: str, initial: str = "", placeholder: str = "") -> None:
        super().__init__()
        self._title = title
        self._initial = initial
        self._placeholder = placeholder or "e.g. MacBook Pro"

    def compose(self) -> ComposeResult:
        yield Container(
            Static(f"[bold cyan]{self._title}[/bold cyan]", id="label_modal_title"),
            Static(
                "[dim]1–100 characters. Visible server-side.[/dim]",
                id="label_modal_hint",
            ),
            Input(
                value=self._initial,
                placeholder=self._placeholder,
                id="label_input",
            ),
            Static("", id="label_modal_error"),
            Horizontal(
                Button("Save", variant="primary", id="btn_label_save"),
                Button("Cancel", id="btn_label_cancel"),
                id="label_modal_buttons",
            ),
            id="label_modal_container",
        )

    def on_mount(self) -> None:
        self.query_one("#label_input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "label_input":
            self._submit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_label_save":
            self._submit()
        else:
            self.dismiss(None)

    def _submit(self) -> None:
        value = self.query_one("#label_input", Input).value.strip()
        error = self.query_one("#label_modal_error", Static)
        if not value:
            error.update("[red]Label cannot be empty[/red]")
            return
        if len(value) > 100:
            error.update("[red]Label must be 100 characters or fewer[/red]")
            return
        self.dismiss(value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ConfirmModal(ModalScreen[bool]):
    """Yes/No confirmation modal. Dismisses with True (confirm) or False."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("y", "confirm", "Yes", show=False),
        Binding("n", "cancel", "No", show=False),
    ]

    def __init__(self, title: str, message: str, danger: bool = False) -> None:
        super().__init__()
        self._title = title
        self._message = message
        self._danger = danger

    def compose(self) -> ComposeResult:
        yield Container(
            Static(f"[bold cyan]{self._title}[/bold cyan]", id="confirm_modal_title"),
            Static(self._message, id="confirm_modal_message"),
            Horizontal(
                Button(
                    "Confirm",
                    variant="error" if self._danger else "primary",
                    id="btn_confirm_yes",
                ),
                Button("Cancel", id="btn_confirm_no"),
                id="confirm_modal_buttons",
            ),
            id="confirm_modal_container",
        )

    def on_mount(self) -> None:
        self.query_one("#btn_confirm_no", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "btn_confirm_yes")

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class SnapshotManagerScreen(Screen):
    """List and manage cloud config snapshots."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "restore", "Restore", show=True),
        Binding("l", "pull_latest", "Pull Latest", show=True),
        Binding("n", "rename", "Rename", show=True),
        Binding("d", "delete", "Delete", show=True),
        Binding("p", "push_new", "Push New", show=True),
        Binding("f5", "refresh", "Refresh", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._snapshots: List[Dict[str, Any]] = []
        self._loading: bool = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static("[bold cyan]Config Snapshots[/bold cyan]", id="snapshots_header"),
                Static(
                    "[dim]Click a row, then use the keys below or the buttons. "
                    "Restore pulls a snapshot and replaces your local config. "
                    "Snapshots are client-encrypted; decryption needs the sync passphrase.[/dim]",
                    id="snapshots_hint",
                ),
                DataTable(id="snapshots_table", zebra_stripes=True, cursor_type="row"),
                Static("", id="snapshots_status"),
                Horizontal(
                    Button("Pull Latest (l)", variant="primary", id="btn_pull_latest"),
                    Button("Push New (p)", variant="primary", id="btn_push_new"),
                    Button("Restore (r)", id="btn_restore"),
                    Button("Rename (n)", id="btn_rename"),
                    Button("Delete (d)", variant="error", id="btn_delete"),
                    Button("Refresh (F5)", id="btn_refresh"),
                    id="snapshots_actions",
                ),
                id="snapshots_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#snapshots_table", DataTable)
        table.add_columns("#", "Label", "Version", "Created", "Hash")
        self._refresh()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if self._loading:
            return
        self._loading = True
        self._set_status("[dim]Loading snapshots…[/dim]")
        self.run_worker(self._load_snapshots(), exclusive=True, name="load_snapshots")

    async def _load_snapshots(self) -> None:
        try:
            sync = self._sync_service()
            if sync is None:
                self._set_status("[red]Config sync is not available on this plan.[/red]")
                return
            snapshots = await sync.list_snapshots(limit=100)
            self._snapshots = snapshots
            self._render_table()
            n = len(snapshots)
            if n == 0:
                self._set_status(
                    "[dim]No snapshots yet. Push one with [bold]p[/bold] to get started.[/dim]"
                )
            else:
                self._set_status(f"[dim]{n} snapshot{'s' if n != 1 else ''}.[/dim]")
        except Exception as exc:
            logger.error("Failed to list snapshots: %s", exc)
            self._set_status(f"[red]Failed to load snapshots: {self._short_err(exc)}[/red]")
        finally:
            self._loading = False

    def _render_table(self) -> None:
        table = self.query_one("#snapshots_table", DataTable)
        table.clear()
        def _s(x: str) -> str:
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.scrub_stream(x)
            return x

        for idx, snap in enumerate(self._snapshots, start=1):
            table.add_row(
                str(idx),
                _s(str(snap.get("label") or snap.get("name") or "—")),
                str(snap.get("version", "—")),
                self._format_date(snap.get("created_at")),
                str(snap.get("hash", ""))[:16],
                key=str(snap.get("id", idx)),
            )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        mapping = {
            "btn_pull_latest": self.action_pull_latest,
            "btn_restore": self.action_restore,
            "btn_rename": self.action_rename,
            "btn_delete": self.action_delete,
            "btn_push_new": self.action_push_new,
            "btn_refresh": self.action_refresh,
        }
        action = mapping.get(event.button.id or "")
        if action:
            action()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._refresh()

    def action_restore(self) -> None:
        snap = self._selected()
        if not snap:
            return
        self._confirm_and_restore(snap)

    def action_pull_latest(self) -> None:
        """One-click restore of the most recent snapshot.

        list_snapshots returns server-side newest-first, so index 0 is the
        latest. Skips the row-selection step but still confirms — restore
        overwrites local config and is hard to reverse.
        """
        if not self._snapshots:
            self.notify(
                "No snapshots to pull yet. Push one first with 'p'.",
                severity="warning",
            )
            return
        self._confirm_and_restore(self._snapshots[0])

    def _confirm_and_restore(self, snap: Dict[str, Any]) -> None:
        label = snap.get("label") or snap.get("version") or "this snapshot"
        self.app.push_screen(
            ConfirmModal(
                title="Restore Snapshot",
                message=(
                    f"Replace your local config with snapshot [bold]{label}[/bold]?\n"
                    "Local-only fields (instance keys, paths) will be preserved."
                ),
            ),
            callback=lambda ok: self._restore_after_confirm(snap, ok),
        )

    def _restore_after_confirm(self, snap: Dict[str, Any], ok: Optional[bool]) -> None:
        if not ok:
            return
        self._prompt_passphrase_then(
            lambda pp: self.run_worker(
                self._do_restore(snap, pp), exclusive=True, name="restore_snapshot"
            )
        )

    async def _do_restore(self, snap: Dict[str, Any], passphrase: str) -> None:
        sync = self._sync_service()
        if sync is None:
            return
        snapshot_id = snap.get("id") or snap.get("version")
        self._set_status("[dim]Downloading and decrypting…[/dim]")
        try:
            config_data = await sync.restore_by_id(str(snapshot_id), passphrase=passphrase)
            sync.apply_remote_config(config_data)
            self.notify("Snapshot restored. Restart Servonaut to apply fully.",
                        severity="information")
            self._set_status("[green]Snapshot restored.[/green]")
        except config_crypto.DecryptionError:
            self.notify("Wrong passphrase or corrupted snapshot.", severity="error")
            self._set_status("[red]Decryption failed.[/red]")
        except Exception as exc:
            logger.error("Restore failed: %s", exc)
            self.notify(f"Restore failed: {self._short_err(exc)}", severity="error")
            self._set_status(f"[red]Restore failed: {self._short_err(exc)}[/red]")

    def action_rename(self) -> None:
        snap = self._selected()
        if not snap:
            return
        current = str(snap.get("label") or "")
        self.app.push_screen(
            LabelInputModal(title="Rename Snapshot", initial=current),
            callback=lambda new_label: self._rename_after_input(snap, new_label),
        )

    def _rename_after_input(self, snap: Dict[str, Any], new_label: Optional[str]) -> None:
        if not new_label:
            return
        self.run_worker(self._do_rename(snap, new_label), exclusive=True, name="rename_snapshot")

    async def _do_rename(self, snap: Dict[str, Any], new_label: str) -> None:
        sync = self._sync_service()
        if sync is None:
            return
        snapshot_id = snap.get("id")
        if not snapshot_id:
            self.notify("Cannot rename: snapshot id missing.", severity="error")
            return
        self._set_status("[dim]Renaming…[/dim]")
        try:
            await sync.rename_snapshot(str(snapshot_id), new_label)
            self.notify(f"Renamed to {new_label}", severity="information")
            await self._load_snapshots()
        except Exception as exc:
            logger.error("Rename failed: %s", exc)
            self.notify(f"Rename failed: {self._short_err(exc)}", severity="error")
            self._set_status(f"[red]Rename failed: {self._short_err(exc)}[/red]")

    def action_delete(self) -> None:
        snap = self._selected()
        if not snap:
            return
        label = snap.get("label") or snap.get("version") or "this snapshot"
        self.app.push_screen(
            ConfirmModal(
                title="Delete Snapshot",
                message=(
                    f"Permanently delete [bold]{label}[/bold]?\n"
                    "This cannot be undone."
                ),
                danger=True,
            ),
            callback=lambda ok: self._delete_after_confirm(snap, ok),
        )

    def _delete_after_confirm(self, snap: Dict[str, Any], ok: Optional[bool]) -> None:
        if not ok:
            return
        self.run_worker(self._do_delete(snap), exclusive=True, name="delete_snapshot")

    async def _do_delete(self, snap: Dict[str, Any]) -> None:
        sync = self._sync_service()
        if sync is None:
            return
        snapshot_id = snap.get("id")
        if not snapshot_id:
            self.notify("Cannot delete: snapshot id missing.", severity="error")
            return
        self._set_status("[dim]Deleting…[/dim]")
        try:
            await sync.delete_snapshot(str(snapshot_id))
            self.notify("Snapshot deleted", severity="information")
            await self._load_snapshots()
        except Exception as exc:
            logger.error("Delete failed: %s", exc)
            self.notify(f"Delete failed: {self._short_err(exc)}", severity="error")
            self._set_status(f"[red]Delete failed: {self._short_err(exc)}[/red]")

    def action_push_new(self) -> None:
        import socket
        default_label = socket.gethostname() or "servonaut"
        self.app.push_screen(
            LabelInputModal(
                title="Push New Snapshot",
                initial=default_label,
                placeholder="e.g. MacBook Pro",
            ),
            callback=lambda label: self._push_after_label(label),
        )

    def _push_after_label(self, label: Optional[str]) -> None:
        if not label:
            return
        # Only the very first push (account has no snapshots yet) lets the user
        # choose a brand-new passphrase. Subsequent pushes must reuse the
        # existing account passphrase so all snapshots share one key.
        self._prompt_passphrase_then(
            lambda pp: self.run_worker(
                self._do_push(label, pp), exclusive=True, name="push_snapshot"
            ),
            allow_set=not self._snapshots,
        )

    async def _do_push(self, label: str, passphrase: str) -> None:
        sync = self._sync_service()
        if sync is None:
            return
        self._set_status("[dim]Encrypting and uploading…[/dim]")
        try:
            await sync.push(passphrase=passphrase, label=label)
            self.notify(f"Pushed snapshot: {label}", severity="information")
            await self._load_snapshots()
        except config_crypto.CryptoUnavailableError:
            self.notify("Install cryptography: pip install 'servonaut[sync]'",
                        severity="error")
        except ValueError as exc:
            self.notify(f"{exc}", severity="error")
        except Exception as exc:
            logger.error("Push failed: %s", exc)
            self.notify(f"Push failed: {self._short_err(exc)}", severity="error")
            self._set_status(f"[red]Push failed: {self._short_err(exc)}[/red]")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _sync_service(self):
        sync = getattr(self.app, "config_sync_service", None)
        if sync is None:
            self.notify("Config sync is not available on this plan.", severity="warning")
        return sync

    def _selected(self) -> Optional[Dict[str, Any]]:
        table = self.query_one("#snapshots_table", DataTable)
        row = table.cursor_row
        if row is None or row < 0 or row >= len(self._snapshots):
            self.notify("Select a snapshot first.", severity="warning")
            return None
        return self._snapshots[row]

    def _set_status(self, msg: str) -> None:
        try:
            self.query_one("#snapshots_status", Static).update(msg)
        except Exception:
            pass

    def _prompt_passphrase_then(self, then, *, allow_set: bool = False) -> None:
        """Prompt the user for the sync passphrase, then run `then(passphrase)`.

        If the passphrase is cached on the service, uses it without prompting.

        The "Set Sync Passphrase" (type-it-twice) mode is ONLY correct when the
        user is choosing the passphrase for the very first time — i.e. an
        initial push to an account that has zero snapshots. In every other case
        the passphrase is account-global and must EXACTLY match the key the
        target snapshot was encrypted with, so we prompt to *enter* it.

        Keying this off the local probe file (as the old code did) was wrong: a
        brand-new machine restoring an existing snapshot has no probe yet, so it
        was mis-prompted to "Set" a new passphrase — which then could never
        decrypt the existing snapshot. ``allow_set`` is passed True only by the
        first-push path; restores always pass False.
        """
        sync = self._sync_service()
        if sync is None:
            return
        cached = getattr(sync, "_cached_passphrase", None)
        if cached:
            then(cached)
            return
        # Lazy import to avoid circular imports with login.py
        from servonaut.screens.login import PassphraseModal
        # A local probe means a passphrase was already established on this
        # device, so never offer "Set" even if the caller allows it.
        is_set = allow_set and not sync.has_probe()
        title = "Set Sync Passphrase" if is_set else "Enter Sync Passphrase"
        self.app.push_screen(
            PassphraseModal(confirm=is_set, title=title),
            callback=lambda pp: then(pp) if pp else None,
        )

    @staticmethod
    def _format_date(value: Any) -> str:
        if not value:
            return "—"
        try:
            if isinstance(value, str):
                # Accept common ISO 8601 variants
                value_clean = value.replace("Z", "+00:00")
                dt = datetime.fromisoformat(value_clean)
                return dt.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            pass
        return str(value)[:19]

    @staticmethod
    def _short_err(exc: Exception) -> str:
        msg = str(exc)
        return msg[:200] if len(msg) > 200 else msg
