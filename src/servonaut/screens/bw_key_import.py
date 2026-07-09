"""Bitwarden key-import modal — scan a directory and upload keys to the vault.

Scans the chosen directory (via :func:`servonaut.services.bw_key_import.scan_directory`)
for SSH private keys, renders them in a :class:`SelectionList` (unencrypted keys
pre-selected, encrypted keys deliberate opt-in, already-in-vault / unreadable
rows disabled), and imports the selected keys as native Bitwarden SSH items.

Semantics (honest wording, mirrored in the docs): imported copies are protected
by the Bitwarden vault's encryption — NOT the original file passphrase; the
original files are untouched; keys are uploaded to the user's Bitwarden vault.

Security: private-key material and passphrases never appear on a subprocess
argv, in a log call, in an exception message, or on disk — decryption is
in-process and the vault upload is piped to ``bw`` via stdin by
:meth:`BwSessionService.create_ssh_key_item`.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List, Optional, Tuple

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, SelectionList, Static
from textual.widgets.selection_list import Selection

from servonaut.screens.bw_passphrase_modal import BwPassphraseModal
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
from servonaut.services.bw_session_service import BwSessionService

# NOTE: U+1F512 has no VS16 variant selector — safe in labels per project rule.
_ENCRYPTED_MARKER = "🔒 encrypted"

_SEMANTICS_TEXT = (
    "Imported keys become native Bitwarden SSH items protected by your vault's "
    "encryption — the original file passphrase is NOT kept on the copy. Your "
    "local key files are left untouched. Selected keys are uploaded to your "
    "Bitwarden vault."
)


class BwKeyImportModal(ModalScreen[Optional[dict]]):
    """Scan-and-import modal for local SSH private keys.

    Dismisses a summary dict ``{"imported", "skipped", "duplicates", "failed"}``
    after an import, or ``None`` on cancel.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    DEFAULT_CSS = ""  # styling lives in the styles bundle (secrets.tcss)

    def __init__(
        self,
        directory: Path,
        session_service: Optional[BwSessionService] = None,
    ) -> None:
        super().__init__()
        self._directory = directory
        self._svc = session_service
        self._keys: List[ScannedKey] = []
        # Fingerprints already present in the vault (whole vault, not folder-scoped).
        self._existing: set = set()
        # True only when the vault listing succeeded — dedupe is trustworthy.
        # Import is blocked while False so a failed listing can never produce
        # silent duplicate items.
        self._existing_ok: bool = False
        self._scan_complete: bool = False
        self._importing: bool = False

    def _service(self) -> Optional[BwSessionService]:
        return self._svc or getattr(self.app, "bw_session_service", None)

    # ------------------------------------------------------------------
    # Compose / mount
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                "[bold cyan]Import SSH keys into Bitwarden[/bold cyan]",
                id="bw_import_title",
            ),
            Static(escape(_SEMANTICS_TEXT), id="bw_import_semantics"),
            SelectionList(id="bw_import_list"),
            Static("[dim]Scanning…[/dim]", id="bw_import_status"),
            Horizontal(
                Button("Cancel", variant="default", id="bw_import_cancel_btn"),
                Button("Import", variant="primary", id="bw_import_btn"),
                classes="bw_import_actions",
            ),
            id="bw_import_container",
        )

    def on_mount(self) -> None:
        # Own group: the import worker's exclusive=True must never cancel a
        # still-running scan (which would strand the modal at "Scanning…").
        self.run_worker(self._scan(), group="bw_key_import_scan", exclusive=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _display_name(self, text: str) -> str:
        """Demo-mode scrub for file-origin names before they hit the screen."""
        if getattr(self.app, "demo_mode", False) and getattr(self.app, "redaction_service", None):
            return self.app.redaction_service.scrub_stream(text)
        return text

    def _set_status(self, text: str) -> None:
        """Update the status line (demo-scrubbed and escaped — never raw markup)."""
        if getattr(self.app, "demo_mode", False) and getattr(self.app, "redaction_service", None):
            text = self.app.redaction_service.scrub_stream(text)
        try:
            self.query_one("#bw_import_status", Static).update(escape(text))
        except Exception:  # noqa: BLE001
            pass

    def _selected_indices(self) -> List[int]:
        try:
            return list(self.query_one("#bw_import_list", SelectionList).selected)
        except Exception:  # noqa: BLE001
            return []

    @staticmethod
    def _short_fp(fingerprint: Optional[str]) -> str:
        if not fingerprint:
            return ""
        return fingerprint if len(fingerprint) <= 19 else fingerprint[:19] + "…"

    # ------------------------------------------------------------------
    # Scan pipeline
    # ------------------------------------------------------------------

    async def _scan(self) -> None:
        """Scan the directory and fetch existing vault fingerprints, then render."""
        try:
            self._keys = await asyncio.to_thread(scan_directory, self._directory)
        except KeyImportError:
            # An unreadable directory must not masquerade as an empty one —
            # "no keys found" would send the user down the wrong path.
            self._scan_complete = True
            self._set_status(
                f"Could not read directory {self._directory} — check permissions, "
                "then cancel and retry."
            )
            return

        svc = self._service()
        existing: set = set()
        listing_ok = False
        if svc is None:
            self.app.notify(
                "Bitwarden session service unavailable.", severity="error", markup=False
            )
        else:
            try:
                # Whole-vault listing so a key living outside the Servonaut
                # folder still counts as a duplicate.
                items = await svc.list_items(folder_id=None, ssh_only=True)
                existing = {i.fingerprint for i in items if i.fingerprint}
                listing_ok = True
            except BwError as exc:
                self.app.notify(exc.message, severity="warning", markup=False)
            except Exception as exc:  # noqa: BLE001
                self.app.notify(
                    f"Could not list vault items: {exc}", severity="warning", markup=False
                )
        self._existing = existing
        self._existing_ok = listing_ok
        self._scan_complete = True
        self._populate()

    def _populate(self) -> None:
        """Fill the SelectionList: one row per scanned key."""
        try:
            sel_list = self.query_one("#bw_import_list", SelectionList)
        except Exception:  # noqa: BLE001
            return
        sel_list.clear_options()

        options: List[Selection] = []
        in_vault = 0
        for idx, key in enumerate(self._keys):
            label, selectable, initial = self._row_for(key)
            if key.fingerprint and key.fingerprint in self._existing:
                in_vault += 1
            options.append(
                Selection(label, idx, initial_state=initial, disabled=not selectable)
            )
        sel_list.add_options(options)

        if not self._keys:
            self._set_status(f"No SSH private keys found in {self._directory}.")
        elif not self._existing_ok:
            self._set_status(
                f"{len(self._keys)} key(s) found — could not check the vault for "
                "duplicates, import is blocked. Cancel and retry."
            )
        else:
            self._set_status(
                f"{len(self._keys)} key(s) found — {in_vault} already in vault."
            )

    def _row_for(self, key: ScannedKey) -> Tuple[str, bool, bool]:
        """Build ``(label, selectable, initially_selected)`` for one scanned key."""
        name = escape(self._display_name(key.filename))
        if key.resolved_target:
            # Symlink provenance: the basename alone would hide that the key
            # bytes actually come from elsewhere on disk.
            name += f" [dim]→ {escape(self._display_name(key.resolved_target))}[/dim]"
        if key.error:
            return f"[dim]{name} — {escape(key.error)}[/dim]", False, False

        parts = [name]
        if key.key_type:
            parts.append(escape(key.key_type))
        if key.fingerprint:
            parts.append(escape(self._short_fp(key.fingerprint)))
        if key.encrypted:
            parts.append(_ENCRYPTED_MARKER)
        label = "  ".join(parts)

        if key.fingerprint and key.fingerprint in self._existing:
            return f"[dim]{label} — already in vault[/dim]", False, False
        # Encrypted keys are deliberate opt-in; unencrypted default ON.
        return label, True, not key.encrypted

    # ------------------------------------------------------------------
    # Import pipeline
    # ------------------------------------------------------------------

    async def _resolve_key(
        self, key: ScannedKey
    ) -> Tuple[str, Optional[DecryptedKey]]:
        """Load (and if needed decrypt) one key. Returns (outcome, decrypted).

        ``outcome`` is one of ``"ok"``, ``"skipped"`` (user skipped the
        passphrase prompt), ``"failed"``.
        """
        try:
            # Bounded re-read: the file may have been replaced/grown since the
            # scan, so the scan-time size cap must be re-enforced here.
            data = await asyncio.to_thread(read_key_bytes, key.path)
        except KeyImportError:
            self.app.notify(
                f"{self._display_name(key.filename)}: could not read file.",
                severity="warning",
                markup=False,
            )
            return "failed", None

        if not key.encrypted:
            try:
                return "ok", await asyncio.to_thread(load_unencrypted_key, data)
            except KeyImportError as exc:
                self.app.notify(
                    f"{self._display_name(key.filename)}: {exc.message}",
                    severity="warning",
                    markup=False,
                )
                return "failed", None

        # Encrypted: prompt-decrypt-retry loop; Skip returns None.
        while True:
            passphrase = await self.app.push_screen_wait(
                BwPassphraseModal(self._display_name(key.filename))
            )
            if passphrase is None:
                return "skipped", None
            try:
                return "ok", await asyncio.to_thread(
                    decrypt_private_key, data, passphrase
                )
            except WrongPassphraseError as exc:
                self.app.notify(
                    f"{self._display_name(key.filename)}: {exc.message}",
                    severity="warning",
                    markup=False,
                )
            except KeyImportError as exc:
                self.app.notify(
                    f"{self._display_name(key.filename)}: {exc.message}",
                    severity="warning",
                    markup=False,
                )
                return "failed", None

    async def _do_import(self) -> None:
        svc = self._service()
        if svc is None:
            self.app.notify(
                "Bitwarden session service unavailable.", severity="error", markup=False
            )
            return
        if not self._existing_ok:
            # A failed vault listing silently disables fingerprint dedupe —
            # importing anyway would create duplicate items, contradicting the
            # documented "duplicates are skipped" guarantee. Block instead.
            self.app.notify(
                "Could not check the vault for existing keys — import is blocked "
                "to avoid duplicates. Cancel and reopen to retry.",
                severity="error",
                markup=False,
            )
            return
        indices = self._selected_indices()
        if not indices:
            self.app.notify("Select at least one key to import.", severity="warning", markup=False)
            return

        self._importing = True
        try:
            from servonaut.utils.bw_folder import resolved_bw_vault_folder
            folder_name = resolved_bw_vault_folder(self.app)
            try:
                folder_id = await svc.ensure_servonaut_folder(folder_name)
            except BwError as exc:
                self.app.notify(exc.message, severity="error", markup=False)
                return

            counts = {"imported": 0, "skipped": 0, "duplicates": 0, "failed": 0}
            for idx in indices:
                if idx < 0 or idx >= len(self._keys):
                    continue
                key = self._keys[idx]
                self._set_status(f"Importing {self._display_name(key.filename)}…")

                # Pre-decrypt dedupe when the scan already knows the fingerprint.
                if key.fingerprint and key.fingerprint in self._existing:
                    counts["duplicates"] += 1
                    continue

                outcome, decrypted = await self._resolve_key(key)
                if outcome != "ok" or decrypted is None:
                    counts[outcome] += 1
                    continue

                # Post-decrypt dedupe (encrypted keys reveal it only now).
                if decrypted.fingerprint in self._existing:
                    counts["duplicates"] += 1
                    continue

                # Prefer the scanned public line (carries the .pub comment) —
                # but only while it still matches the private key just re-read
                # from disk (the file may have been rotated between the scan
                # and the import; a stale public line would produce a vault
                # item whose publicKey does not match its privateKey).
                if key.public_key and key.fingerprint == decrypted.fingerprint:
                    public_key = key.public_key
                else:
                    public_key = decrypted.public_key
                try:
                    await svc.create_ssh_key_item(
                        name=key.filename,
                        private_key=decrypted.private_key,
                        public_key=public_key,
                        key_fingerprint=decrypted.fingerprint,
                        folder_id=folder_id,
                    )
                except BwError as exc:
                    counts["failed"] += 1
                    self.app.notify(
                        f"{self._display_name(key.filename)}: {exc.message}",
                        severity="error",
                        markup=False,
                    )
                    continue
                self._existing.add(decrypted.fingerprint)
                counts["imported"] += 1
                self._set_status(f"Imported {self._display_name(key.filename)}.")

            self._set_status("Syncing vault…")
            await svc.sync_now()
            self.dismiss(counts)
        finally:
            self._importing = False

    # ------------------------------------------------------------------
    # Events / actions
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "bw_import_cancel_btn":
            self.action_cancel()
        elif event.button.id == "bw_import_btn":
            if self._importing:
                return
            if not self._scan_complete:
                self.app.notify(
                    "Scan in progress — please wait.", severity="warning", markup=False
                )
                return
            self.run_worker(self._do_import(), group="bw_key_import", exclusive=True)

    def action_cancel(self) -> None:
        if self._importing:
            self.app.notify("Import in progress — please wait.", severity="warning", markup=False)
            return
        self.dismiss(None)
