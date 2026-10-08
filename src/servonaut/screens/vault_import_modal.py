"""Private-key import wizard for native Team Vault SSH items.

The modal owns only source selection, local file parsing, and Bitwarden access.
It delegates encryption and persistence to ``VaultCommandService.import_keys``.
No decrypted material is rendered, stored by the modal, or put in a subprocess
argument list.
"""

from __future__ import annotations

import asyncio
from functools import partial
from pathlib import Path
from typing import Any, Callable

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, SelectionList, Static
from textual.widgets.selection_list import Selection

from servonaut.screens._busy_work import BusyWork
from servonaut.screens.bw_passphrase_modal import BwPassphraseModal
from servonaut.screens.bw_unlock_modal import BwUnlockModal
from servonaut.services.bw_errors import BwError
from servonaut.services.bw_key_import import (
    DecryptedKey,
    KeyImportError,
    ScannedKey,
    WrongPassphraseError,
    decrypt_private_key,
    load_unencrypted_key,
    read_key_bytes,
    scan_directory,
)
from servonaut.services.bw_resolver import BwResolver
from servonaut.services.bw_session_service import BwItemSummary, BwSessionService
from servonaut.widgets.busy_indicator import BusyIndicator


ImportSummary = dict[str, Any]

# Loading a source holds both source buttons back; an import also holds Import.
_SOURCE_BUTTONS = ("#vault_import_local", "#vault_import_bitwarden")
_IMPORT_HOLDS = (*_SOURCE_BUTTONS, "#vault_import_confirm")


def _which_key(position: int, total: int) -> str:
    return "the key" if total == 1 else f"key {position} of {total}"


class VaultImportModal(ModalScreen[ImportSummary | None]):
    """Choose a local or Bitwarden SSH key and import it into one vault.

    The dismissal result is deliberately metadata-only. ``references`` carries
    the new vault item id plus source metadata, allowing the caller to offer a
    separate, explicit binding confirmation.
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    VaultImportModal { align: center middle; }
    VaultImportModal #vault_import_modal {
        width: 76;
        max-width: 92%;
        height: 86%;
        max-height: 32;
        padding: 1 2;
        border: round $accent;
        overflow: hidden;
    }
    VaultImportModal #vault_import_choices { height: auto; margin-top: 1; }
    VaultImportModal #vault_import_actions { height: 3; min-height: 3; margin-top: 1; }
    VaultImportModal #vault_import_title { color: $accent; text-style: bold; }
    VaultImportModal #vault_import_intro { color: $text-muted; }
    VaultImportModal #vault_import_local,
    VaultImportModal #vault_import_bitwarden,
    VaultImportModal #vault_import_cancel,
    VaultImportModal #vault_import_confirm { width: 1fr; }
    VaultImportModal #vault_import_list { height: 1fr; min-height: 3; margin-top: 1; }
    VaultImportModal #vault_import_status { height: auto; min-height: 1; margin-top: 1; }
    VaultImportModal #vault_import_busy { margin: 0; }
    """

    def __init__(
        self,
        service: Any,
        vault_id: str,
        directory: Path | None = None,
        *,
        session_service: BwSessionService | None = None,
        resolver: BwResolver | None = None,
    ) -> None:
        super().__init__()
        self._service = service
        self._vault_id = vault_id
        self._directory = directory or Path.home() / ".ssh"
        self._session_service = session_service
        self._resolver = resolver
        self._source: str | None = None
        self._local_keys: list[ScannedKey] = []
        self._bw_items: list[BwItemSummary] = []
        self._loading = False
        self._importing = False
        self._status_raw = "Choose a source to begin."
        self._busy = BusyWork(self, "#vault_import_busy", display=self._display)

    def _bw_service(self) -> BwSessionService | None:
        return self._session_service or getattr(self.app, "bw_session_service", None)

    def _display(self, value: str) -> str:
        redactor = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redactor is not None:
            return str(redactor.scrub_stream(value))
        return value

    def _set_status(self, value: str) -> None:
        self._status_raw = value
        if getattr(self.app, "demo_mode", False) and getattr(self.app, "redaction_service", None) is not None:
            value = str(self.app.redaction_service.scrub_stream(value))
        self.query_one("#vault_import_status", Static).update(escape(value))

    def refresh_after_demo_toggle(self) -> None:
        """Redraw source metadata from cached summaries after a mode switch."""
        # A list still loading is drawn under the current mode once it arrives.
        if self._source == "ssh" and not self._loading:
            self._show_local_options()
        elif self._source == "bitwarden" and not self._loading:
            self._show_bitwarden_options()
        self._set_status(self._status_raw)
        self._busy.redraw()

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("[bold]Import SSH key into encrypted vault[/bold]", id="vault_import_title"),
            Static(
                "Choose a source. Existing files and Bitwarden items are never deleted.",
                id="vault_import_intro",
            ),
            Horizontal(
                Button("Local SSH files", id="vault_import_local"),
                Button("Bitwarden", id="vault_import_bitwarden"),
                id="vault_import_choices",
            ),
            SelectionList(id="vault_import_list"),
            Static("Choose a source to begin.", id="vault_import_status"),
            BusyIndicator(id="vault_import_busy"),
            Horizontal(
                Button("Cancel", id="vault_import_cancel"),
                Button("Import selected", variant="primary", id="vault_import_confirm", disabled=True),
                id="vault_import_actions",
            ),
            id="vault_import_modal",
        )

    def _list(self) -> SelectionList:
        return self.query_one("#vault_import_list", SelectionList)

    def _confirm(self) -> Button:
        return self.query_one("#vault_import_confirm", Button)

    def _show_options(self, options: list[Selection], message: str) -> None:
        listing = self._list()
        listing.clear_options()
        listing.add_options(options)
        # A running import holds Import back and gives its state back when it ends.
        if not self._busy.holds("#vault_import_confirm"):
            self._confirm().disabled = not bool(options)
        self._set_status(message)

    def _directory_label(self) -> str:
        """The scanned directory as the user knows it: under ``~`` when it is in their home."""
        try:
            return "~/" + self._directory.relative_to(Path.home()).as_posix()
        except ValueError:
            return str(self._directory)

    async def _load_local(self) -> None:
        self._loading = True
        self._confirm().disabled = True
        self._set_status("")
        try:
            with self._busy.running(f"Reading SSH keys in {self._directory_label()}…", hold=_SOURCE_BUTTONS):
                self._local_keys = await asyncio.to_thread(scan_directory, self._directory)
        except KeyImportError:
            self._show_options([], "Could not scan the selected SSH directory.")
            return
        finally:
            self._loading = False

        self._show_local_options()

    def _show_local_options(self) -> None:
        options: list[Selection] = []
        for index, key in enumerate(self._local_keys):
            label = escape(self._display(key.filename))
            if key.resolved_target:
                label += f"  [dim]→ {escape(self._display(key.resolved_target))}[/dim]"
            if key.encrypted:
                label += "  [dim]encrypted — select to enter its passphrase[/dim]"
            if key.error:
                label += "  [dim]unreadable or unsupported[/dim]"
            options.append(
                Selection(label, index, initial_state=not key.encrypted and not key.error, disabled=bool(key.error))
            )
        self._show_options(options, f"Found {len(self._local_keys)} local SSH key candidate(s).")

    async def _load_bitwarden(self) -> None:
        service = self._bw_service()
        if service is None:
            self._set_status("Bitwarden session service is unavailable.")
            return
        self._loading = True
        self._confirm().disabled = True
        self._set_status("")
        try:
            with self._busy.running("Unlocking Bitwarden…", hold=_SOURCE_BUTTONS) as job:
                unlocked = await self.app.push_screen_wait(BwUnlockModal(service))
                if unlocked is not True:
                    self._set_status("Bitwarden remained locked; no items were read.")
                    return
                self._busy.say(job, "Loading Bitwarden SSH items…")
                self._bw_items = await service.list_items(folder_id=None, ssh_only=True)
        except BwError as exc:
            self._set_status(exc.message)
            return
        except Exception:
            self._set_status("Could not list Bitwarden SSH items.")
            return
        finally:
            self._loading = False

        self._show_bitwarden_options()

    def _show_bitwarden_options(self) -> None:
        options = [
            Selection(
                f"{escape(self._display(item.name or 'Unnamed SSH key'))}"
                f"  [dim]{escape(self._display(item.fingerprint or item.id))}[/dim]",
                index,
            )
            for index, item in enumerate(self._bw_items)
            if item.id
        ]
        self._show_options(options, f"Found {len(options)} Bitwarden SSH item(s).")

    async def _local_private_key(self, key: ScannedKey) -> bytearray | None:
        try:
            raw = bytearray(await asyncio.to_thread(read_key_bytes, key.path))
        except KeyImportError:
            self.app.notify("Could not read the selected SSH key file.", severity="warning", markup=False)
            return None
        try:
            if not key.encrypted:
                decrypted = await asyncio.to_thread(load_unencrypted_key, bytes(raw))
            else:
                decrypted = await self._decrypt_with_prompt(bytes(raw), key.filename)
            if decrypted is None:
                return None
            return bytearray(decrypted.private_key.encode("utf-8"))
        except KeyImportError as exc:
            self.app.notify(exc.message, severity="warning", markup=False)
            return None
        finally:
            for index in range(len(raw)):
                raw[index] = 0

    async def _decrypt_with_prompt(self, data: bytes, filename: str) -> DecryptedKey | None:
        while True:
            passphrase = await self.app.push_screen_wait(BwPassphraseModal(self._display(filename)))
            if passphrase is None:
                return None
            try:
                return await asyncio.to_thread(decrypt_private_key, data, passphrase)
            except WrongPassphraseError:
                self.app.notify("Wrong passphrase. Try again or skip this key.", severity="warning", markup=False)
            except KeyImportError as exc:
                self.app.notify(exc.message, severity="warning", markup=False)
                return None

    async def _import_local(self, index: int, summary: ImportSummary) -> None:
        if not 0 <= index < len(self._local_keys):
            return
        key = self._local_keys[index]
        private = await self._local_private_key(key)
        if private is None:
            summary["skipped"] += 1
            return
        try:
            result = await self._service.import_keys(
                source="ssh", vault_id=self._vault_id, path=str(key.path), private_key=private,
            )
        except Exception:
            summary["failed"] += 1
            self.app.notify("Could not import the selected SSH key.", severity="error", markup=False)
            return
        finally:
            for position in range(len(private)):
                private[position] = 0
        self._record_import(summary, result, "ssh", key.filename)

    async def _import_bitwarden(
        self, index: int, summary: ImportSummary, say: Callable[[str], None] = lambda _message: None,
        which: str = "the key",
    ) -> None:
        if not 0 <= index < len(self._bw_items):
            return
        item = self._bw_items[index]
        resolver = self._resolver
        if resolver is None:
            session = self._bw_service()
            if session is None:
                summary["failed"] += 1
                return
            resolver = BwResolver(session_getter=session.session)
        say(f"Reading {which} from Bitwarden…")
        try:
            private_text = await asyncio.to_thread(resolver.resolve_ssh_key, item.id)
            private = bytearray(private_text.encode("utf-8"))
        except BwError as exc:
            summary["failed"] += 1
            self.app.notify(exc.message, severity="error", markup=False)
            return
        except Exception:
            summary["failed"] += 1
            self.app.notify("Could not read the selected Bitwarden SSH key.", severity="error", markup=False)
            return
        say(f"Importing {which}…")
        try:
            result = await self._service.import_keys(
                source="bitwarden", vault_id=self._vault_id, private_key=private, source_ref=item.id,
            )
        except Exception:
            summary["failed"] += 1
            self.app.notify("Could not import the selected Bitwarden SSH key.", severity="error", markup=False)
            return
        finally:
            for position in range(len(private)):
                private[position] = 0
        self._record_import(summary, result, "bitwarden", item.id)

    @staticmethod
    def _record_import(summary: ImportSummary, result: Any, source: str, source_ref: str) -> None:
        if not isinstance(result, dict) or not isinstance(result.get("item_id"), str):
            summary["failed"] += 1
            return
        item_id = result["item_id"]
        summary["imported"] += 1
        summary["imported_ids"].append(item_id)
        summary["references"].append({"vault_item_id": item_id, "source": source, "source_ref": source_ref})

    async def _import_selected(self) -> None:
        if self._source is None:
            self.app.notify("Choose an import source first.", severity="warning", markup=False)
            return
        selected = list(self._list().selected)
        if not selected:
            self.app.notify("Select at least one SSH key.", severity="warning", markup=False)
            return
        self._importing = True
        summary: ImportSummary = {"imported": 0, "skipped": 0, "failed": 0, "imported_ids": [], "references": []}
        total = len(selected)
        try:
            with self._busy.running(f"Importing {_which_key(1, total)}…", hold=_IMPORT_HOLDS) as job:
                for position, index in enumerate(selected, start=1):
                    which = _which_key(position, total)
                    if self._source == "ssh":
                        self._busy.say(job, f"Importing {which}…")
                        await self._import_local(index, summary)
                    else:
                        await self._import_bitwarden(index, summary, partial(self._busy.say, job), which)
            self.dismiss(summary)
        finally:
            self._importing = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "vault_import_cancel":
            self.action_cancel()
        elif button_id == "vault_import_local" and not self._loading and not self._importing:
            self._source = "ssh"
            self.run_worker(self._load_local(), group="vault_import", exclusive=True)
        elif button_id == "vault_import_bitwarden" and not self._loading and not self._importing:
            self._source = "bitwarden"
            self.run_worker(self._load_bitwarden(), group="vault_import", exclusive=True)
        elif button_id == "vault_import_confirm" and not self._loading and not self._importing:
            self.run_worker(self._import_selected(), group="vault_import", exclusive=True)

    def action_cancel(self) -> None:
        # Closing the dialog cancels its work: an import stopped midway is half done.
        if self._importing:
            self._set_status("The import is still running: wait for it to finish before closing.")
        elif self._loading:
            self._set_status("Still loading the key list: wait for it to finish before closing.")
        else:
            self.dismiss(None)
