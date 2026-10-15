"""DbCredentialScanScreen — find a server's database settings and store them.

The TUI twin of ``servonaut db setup <instance>``. It wraps the SAME
agent pipeline — :meth:`ServonautTools.db_scan_stage` (read-only on-box
scan + server-side staging) then :meth:`ServonautTools.db_setup_save`
(commit the chosen token into the active secret store + write a
DBProfile). After a save, ``db_processlist`` / ``db_top_queries`` resolve
the stored secret BY NAME — no re-SSH to read.

Security invariant (pinned by test): the plaintext password is held
server-side in staging and NEVER rendered here — only ``redact()``
previews (``****xyz``) and the opaque staging token cross this
boundary.

The CLI prints not even that masked preview, because its output outlives
the run (scrollback, logs, ``--json`` piped into scripts). Nothing on this
screen is written anywhere, and the last characters are what tell two
settings files for the same database apart (a stale copy next to the
live one), so the list keeps them.

The highlighted row is the selection: the Store button and Enter both act
on it, and a finished scan highlights the first database not stored yet.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, Input, Static
from textual.widgets import OptionList
from textual.widgets.option_list import Option

from servonaut.services.db_credential_scanner import (
    connection_text,
    engine_display_name,
)
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar
from servonaut.screens._demo_resolve import connection_instance

logger = logging.getLogger(__name__)

# Plain-text marker on a row whose database is in the secret store.
_STORED_BADGE = "✓ stored  "


def _store_error(out: str) -> str:
    """Turn a db_setup_save refusal into the end of a sentence for a person."""
    text = str(out).strip()
    if "staging token" in text:
        # The staged password expired (or was evicted) before it was stored.
        return "the scan result expired before it was stored. Press s to scan again."
    text = text.removeprefix("Error: ")
    return text.splitlines()[0] if text else "unknown error"


class _DbLabelPromptModal(ModalScreen[Optional[str]]):
    """Confirm/override the name (site label) a database is stored under.

    Pre-filled with the auto-derived label (from the config path). The user can
    accept it, edit it (e.g. to separate prod vs staging DBs on one site), or
    clear it to store the instance's single/default DB unlabelled. Dismisses
    with the trimmed label (``""`` allowed = unlabelled) or ``None`` on cancel.
    """

    DEFAULT_CSS = """
    _DbLabelPromptModal { align: center middle; }
    _DbLabelPromptModal #db_label_modal_container {
        width: 64; height: auto; max-width: 90%;
        padding: 1 2; border: round $primary; background: $surface;
    }
    _DbLabelPromptModal #db_label_modal_buttons { height: auto; margin-top: 1; }
    _DbLabelPromptModal Button { margin-right: 1; }
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    def __init__(self, initial: str = "") -> None:
        super().__init__()
        self._initial = initial

    def compose(self) -> ComposeResult:
        yield Container(
            Static("[bold]Name this database[/bold]", id="db_label_modal_title"),
            Static(
                "[dim]A short name, such as the site it belongs to. Leave it "
                "blank if this server has only one database. Storing another "
                "database under the same name replaces it.[/dim]",
                id="db_label_modal_hint",
            ),
            Input(
                value=self._initial,
                placeholder="e.g. shop",
                id="db_label_input",
            ),
            Horizontal(
                Button("Store", variant="success", id="btn_db_label_store"),
                Button("Cancel", id="btn_db_label_cancel"),
                id="db_label_modal_buttons",
            ),
            id="db_label_modal_container",
        )

    def on_mount(self) -> None:
        self.query_one("#db_label_input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "db_label_input":
            self._submit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_db_label_store":
            self._submit()
        else:
            self.dismiss(None)

    def _submit(self) -> None:
        self.dismiss(self.query_one("#db_label_input", Input).value.strip())

    def action_cancel(self) -> None:
        self.dismiss(None)


class DbCredentialScanScreen(Screen):
    """Scan a server for database settings, review masked rows, store them."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("s", "rescan", "Rescan", show=True),
        Binding("p", "edit_roots", "Scan roots", show=True),
    ]

    def __init__(self, instance: dict) -> None:
        super().__init__()
        self._instance = instance
        self._candidates: List[Dict[str, Any]] = []
        self._selected_token: str = ""
        # Token → the lowercased name its database is stored under, for every
        # row marked stored (found in config by the scan, or stored here).
        # db_setup_save keeps one database per (instance, name), so storing
        # under a row's name replaces that row's database.
        self._stored: Dict[str, str] = {}

    def _instance_ref(self) -> str:
        real = connection_instance(self.app, self._instance)
        return str(real.get("id") or real.get("name") or "")

    def _display_name(self) -> str:
        return str(self._instance.get("name") or self._instance.get("id") or "?")

    def _custom_roots(self) -> List[str]:
        """Per-instance extra scan roots from config, if any."""
        try:
            config = self.app.config_manager.get()
            return list(config.db_scan_roots.get(self._instance_ref(), []))
        except Exception:  # noqa: BLE001
            return []

    def _stored_label_info(self) -> tuple:
        """Cross-reference config for labels already vaulted on this instance.

        Returns ``(labels, has_default)`` where ``labels`` is a set of
        lowercased stored site labels and ``has_default`` is True when an
        empty-label (single/default) profile is stored for the instance. Used
        to flag re-scanned candidates that were saved in a prior session.
        """
        try:
            config = self.app.config_manager.get()
            real = connection_instance(self.app, self._instance)
            instance_id = str(real.get("id") or "")
            instance_name = str(real.get("name") or "")
            profiles = config.db_profiles_for(instance_id, instance_name)
        except Exception:  # noqa: BLE001
            return set(), False
        labels = set()
        has_default = False
        for profile in profiles:
            label = (getattr(profile, "label", "") or "").strip().lower()
            if label:
                labels.add(label)
            else:
                has_default = True
        return labels, has_default

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        name = escape(self._display_name())
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static("🔐 Scan for DB credentials", id="db_scan_title"),
                Static(
                    f"Finds the database settings of the apps on [b]{name}[/b], "
                    "without changing anything. Passwords stay hidden: you see "
                    "at most their last 3 characters.",
                    id="db_scan_subtitle",
                ),
                VerticalScroll(
                    Static("", id="db_scan_roots_line"),
                    Static("Scanning…", id="db_scan_status"),
                    OptionList(id="db_scan_candidates"),
                    Horizontal(
                        Button("Store", id="db_scan_store", variant="success"),
                        Button("Rescan", id="db_scan_rescan"),
                        Button("Scan roots…", id="db_scan_roots_btn"),
                        id="db_scan_buttons",
                    ),
                    id="db_scan_body",
                ),
                id="db_scan_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        self._render_roots_line()
        self._start_scan()

    def _render_roots_line(self) -> None:
        roots = self._custom_roots()
        line = self.query_one("#db_scan_roots_line", Static)
        if roots:
            joined = ", ".join(roots[:3])
            # Demo mode: root paths can reveal real infra structure — scrub
            # before rendering, same guard the scan status line uses.
            if self.app.demo_mode and self.app.redaction_service:
                joined = self.app.redaction_service.scrub_stream(joined)
            shown = escape(joined) + (
                f" +{len(roots) - 3}" if len(roots) > 3 else ""
            )
            line.update(f"[dim]Looks in: {shown} ([b]p[/b] to change).[/dim]")
        else:
            line.update(
                "[dim]Looks in the usual web folders. App somewhere else? Add "
                "its folder with [b]p[/b] (Scan roots).[/dim]"
            )

    # ------------------------------------------------------------------
    # Status helper
    # ------------------------------------------------------------------

    def _set_status(self, message: str, *, error: bool = False) -> None:
        # Demo mode: scrub any IP/host/path that leaked into a status/error
        # string before it renders (server-origin identifiers must not appear
        # in a demo recording).
        if self.app.demo_mode and self.app.redaction_service:
            message = self.app.redaction_service.scrub_stream(message)
        colour = "$text-error" if error else ""
        markup = f"[{colour}]{escape(message)}[/{colour}]" if colour else escape(message)
        try:
            self.query_one("#db_scan_status", Static).update(markup)
        except Exception:  # noqa: BLE001
            pass

    def _tools(self):
        return getattr(self.app, "servonaut_tools", None)

    def _store_name(self) -> str:
        """Where a stored password lands, named like the CLI names it."""
        describe = getattr(self._tools(), "describe_secret_store", None)
        name = describe() if callable(describe) else None
        return name if isinstance(name, str) and name else "your secret store"

    # ------------------------------------------------------------------
    # Rows
    # ------------------------------------------------------------------

    def _candidate(self, token: str) -> Optional[Dict[str, Any]]:
        if not token:
            return None
        return next((c for c in self._candidates if c.get("token") == token), None)

    @staticmethod
    def _row_prompt(candidate: Dict[str, Any], *, stored: bool) -> str:
        """One list row: name, engine, connection, masked password, file.

        The whole row is escaped (it carries server-controlled strings); only
        the neutral, plain-text stored badge is prepended.
        """
        source = str(candidate.get("source") or "")
        parts = [
            str(candidate.get("label") or "").strip(),
            engine_display_name(str(candidate.get("engine") or "?")),
            connection_text(candidate),
            f"password {candidate.get('password_preview') or '****'}",
            f"from {source}" if source else "",
        ]
        row = "  ".join(part for part in parts if part)
        return (_STORED_BADGE if stored else "") + escape(row)

    def _render_row(self, token: str) -> None:
        candidate = self._candidate(token)
        if candidate is None:
            return
        self.query_one("#db_scan_candidates", OptionList).replace_option_prompt(
            token, self._row_prompt(candidate, stored=token in self._stored),
        )

    def _first_unstored_index(self) -> Optional[int]:
        return next(
            (i for i, c in enumerate(self._candidates)
             if c.get("token") not in self._stored),
            None,
        )

    def _highlight(self, index: int) -> None:
        """Highlight a row and make it the selection."""
        option_list = self.query_one("#db_scan_candidates", OptionList)
        option_list.highlighted = index
        self._selected_token = str(self._candidates[index].get("token") or "")
        option_list.focus()

    def _found_status(self) -> str:
        count = len(self._candidates)
        stored = sum(1 for c in self._candidates if c.get("token") in self._stored)
        if count == 1:
            if stored:
                return "Found 1 database; it is already stored. Press Enter to store it again."
            return "Found 1 database. Press Enter to store it."
        found = f"Found {count} databases"
        if stored == count:
            return f"{found}; all are already stored. Pick one to store it again."
        if stored:
            found += f", {stored} already stored"
        return f"{found}. Pick one and press Enter to store it; each is saved under its own name."

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    def _start_scan(self) -> None:
        self.run_worker(
            self._scan_worker(),
            group="db_scan", exclusive=True, name="db_scan",
        )

    async def _scan_worker(self) -> None:
        tools = self._tools()
        if tools is None:
            self._set_status(
                "Database setup is unavailable. Sign in with a Solo or Teams "
                "plan (they include a secret store) and try again.",
                error=True,
            )
            return
        name = self._display_name()
        self._set_status(f"Scanning {name} for database settings (read-only)…")
        option_list = self.query_one("#db_scan_candidates", OptionList)
        option_list.clear_options()
        self._candidates = []
        self._stored = {}
        self._selected_token = ""
        # Custom roots (if configured) are passed as a space-separated
        # search_path; the scanner iterates each. Empty → built-in defaults.
        search_path = " ".join(self._custom_roots())
        try:
            result = await tools.db_scan_stage(
                self._instance_ref(), search_path=search_path,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("db_scan_stage failed: %s", exc)
            self._set_status(f"Could not scan {name}: {exc}", error=True)
            return
        if result.get("error"):
            kind, _, detail = str(result["error"]).partition(": ")
            message = (
                f"Could not scan {name} over SSH: {detail}" if kind == "ssh_error"
                else str(result["error"])
            )
            self._set_status(message, error=True)
            return
        candidates = result.get("candidates") or []
        if not candidates:
            self._set_status(
                f"No database settings found on {name}. If the app lives "
                "somewhere else, add its folder with p (Scan roots).",
            )
            return
        self._candidates = candidates
        stored_labels, has_default = self._stored_label_info()
        for c in candidates:
            label = (c.get("label") or "").strip().lower()
            if (label in stored_labels) if label else has_default:
                self._stored[str(c.get("token"))] = label
            option_list.add_option(Option(
                self._row_prompt(c, stored=str(c.get("token")) in self._stored),
                id=c.get("token"),
            ))
        first = self._first_unstored_index()
        self._highlight(0 if first is None else first)
        self._set_status(self._found_status())

    async def _store_worker(self, token: str, label: str = "") -> None:
        candidate = self._candidate(token)
        if candidate is None:
            self._set_status("Pick a database first.", error=True)
            return
        tools = self._tools()
        if tools is None:
            self._set_status("Database setup is unavailable.", error=True)
            return
        name = label or connection_text(candidate)
        self._set_status(f"Storing {name}…")
        try:
            out = await tools.db_setup_save(
                token, instance_id=self._instance_ref(), label=label,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("db_setup_save failed: %s", exc)
            self._set_status(f"Could not store {name}: {exc}", error=True)
            return
        # db_setup_save returns a human string starting with "Saved" on success.
        if not (isinstance(out, str) and out.startswith("Saved")):
            self._set_status(f"Could not store {name}: {_store_error(out)}", error=True)
            return
        self._mark_stored(token, label)
        remaining = sum(
            1 for c in self._candidates if c.get("token") not in self._stored
        )
        more = f" {remaining} more to store." if remaining else ""
        self._set_status(f"Stored {name}. Agents and the TUI can now use it.{more}")
        # markup=False: the name comes from a config file on the server.
        self.notify(
            f"Stored {name} in {self._store_name()}.",
            severity="information", markup=False,
        )
        # Keep storing the OTHER sites on this instance (one box can host
        # several databases): move on to the next row not stored yet.
        following = self._first_unstored_index()
        if following is not None:
            self._highlight(following)

    def _mark_stored(self, token: str, label: str) -> None:
        """Badge the stored row; un-badge a row whose database it replaced."""
        key = label.strip().lower()
        replaced = [
            other for other, other_key in self._stored.items()
            if other != token and other_key == key
        ]
        for other in replaced:
            del self._stored[other]
            self._render_row(other)
        self._stored[token] = key
        self._render_row(token)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def on_option_list_option_highlighted(
        self, event: OptionList.OptionHighlighted,
    ) -> None:
        # The highlighted row IS the selection: arrowing to a row and then
        # pressing the Store button stores that row.
        if event.option_list.id == "db_scan_candidates":
            token = str(event.option.id or "")
            if self._candidate(token) is not None:
                self._selected_token = token

    def on_option_list_option_selected(
        self, event: OptionList.OptionSelected,
    ) -> None:
        # Enter (or a click) on a row goes straight to the store prompt.
        if event.option_list.id == "db_scan_candidates":
            token = str(event.option.id or "")
            if self._candidate(token) is not None:
                self._selected_token = token
                self._open_store_prompt()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "db_scan_store":
            self._open_store_prompt()
        elif event.button.id == "db_scan_rescan":
            self._start_scan()
        elif event.button.id == "db_scan_roots_btn":
            self.action_edit_roots()

    def _open_store_prompt(self) -> None:
        """Ask for the name (pre-filled with the derived label), then store
        the selected row under it."""
        token = self._selected_token
        candidate = self._candidate(token)
        if candidate is None:
            self._set_status("Pick a database first.", error=True)
            return
        derived = (candidate.get("label") or "").strip()

        def _after(label: Optional[str]) -> None:
            if label is None:
                return  # cancelled
            self.run_worker(
                self._store_worker(token, label.strip()),
                group="db_scan", exclusive=True, name="db_scan_store",
            )

        self.app.push_screen(_DbLabelPromptModal(initial=derived), _after)

    def action_rescan(self) -> None:
        self._start_scan()

    def action_edit_roots(self) -> None:
        """Open the scan-roots editor; rescan with the new roots on save."""
        from servonaut.screens.db_scan_roots import DbScanRootsScreen

        def _after(saved) -> None:
            # saved is the new roots list on Save, or None on Cancel.
            if saved is None:
                return
            self._render_roots_line()
            self._start_scan()

        self.app.push_screen(
            DbScanRootsScreen(self._instance, roots=self._custom_roots()),
            _after,
        )

    def action_back(self) -> None:
        self.app.pop_screen()
