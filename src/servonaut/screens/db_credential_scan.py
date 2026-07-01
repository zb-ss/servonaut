"""DbCredentialScanScreen — human scan→store surface (Layer B2).

The TUI twin of ``servonaut db setup <instance>``. It wraps the SAME
agent pipeline — :meth:`ServonautTools.db_scan_stage` (read-only on-box
scan + server-side staging) then :meth:`ServonautTools.db_setup_save`
(commit the chosen token into the active secret store + write a
DBProfile). After a save, ``db_processlist`` / ``db_top_queries`` resolve
the stored secret BY NAME — no re-SSH to read.

Security invariant (pinned by test): the plaintext password is held
server-side in staging and NEVER rendered here — only ``redact()``
previews (``pw=****xyz``) and the opaque staging token cross this
boundary.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static
from textual.widgets import OptionList
from textual.widgets.option_list import Option

from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


class DbCredentialScanScreen(Screen):
    """Scan a server for DB credentials, review redacted candidates, store one."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("s", "rescan", "Rescan", show=True),
    ]

    def __init__(self, instance: dict) -> None:
        super().__init__()
        self._instance = instance
        self._candidates: List[Dict[str, Any]] = []
        self._selected_token: str = ""

    def _instance_ref(self) -> str:
        return str(self._instance.get("id") or self._instance.get("name") or "")

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        name = escape(str(self._instance.get("name") or self._instance.get("id") or "?"))
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static("🔐 Scan for DB credentials", id="db_scan_title"),
                Static(
                    f"Read-only scan of [b]{name}[/b] for .env / DATABASE_URL / "
                    "wp-config / configuration.php. Passwords are held "
                    "server-side — only masked previews are shown. Store one to "
                    "make db_processlist resolve it by name.",
                    id="db_scan_subtitle",
                ),
                VerticalScroll(
                    Static("Scanning…", id="db_scan_status"),
                    OptionList(id="db_scan_candidates"),
                    Horizontal(
                        Button("Store in vault", id="db_scan_store", variant="success"),
                        Button("Rescan", id="db_scan_rescan"),
                        id="db_scan_buttons",
                    ),
                    id="db_scan_body",
                ),
                id="db_scan_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        self._start_scan()

    # ------------------------------------------------------------------
    # Status helper
    # ------------------------------------------------------------------

    def _set_status(self, message: str, *, error: bool = False) -> None:
        # Demo mode: scrub any IP/host/path that leaked into a status/error
        # string before it renders (server-origin identifiers must not appear
        # in a demo recording).
        if self.app.demo_mode and self.app.redaction_service:
            message = self.app.redaction_service.scrub_stream(message)
        colour = "red" if error else ""
        markup = f"[{colour}]{escape(message)}[/{colour}]" if colour else escape(message)
        try:
            self.query_one("#db_scan_status", Static).update(markup)
        except Exception:  # noqa: BLE001
            pass

    def _tools(self):
        return getattr(self.app, "servonaut_tools", None)

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
                "DB tooling unavailable — sign in (secret store is a "
                "Solo/Teams feature) and retry.",
                error=True,
            )
            return
        self._set_status("Scanning (read-only over SSH)…")
        option_list = self.query_one("#db_scan_candidates", OptionList)
        option_list.clear_options()
        self._candidates = []
        self._selected_token = ""
        try:
            result = await tools.db_scan_stage(self._instance_ref())
        except Exception as exc:  # noqa: BLE001
            logger.exception("db_scan_stage failed: %s", exc)
            self._set_status(f"Scan failed: {exc}", error=True)
            return
        if result.get("error"):
            self._set_status(str(result["error"]), error=True)
            return
        candidates = result.get("candidates") or []
        if not candidates:
            self._set_status(
                "No DB credentials found. Try a different search path or "
                "confirm the app config lives under a standard web root.",
            )
            return
        self._candidates = candidates
        for c in candidates:
            db = c.get("database") or "?"
            label = (
                f"{c.get('engine', '?')}  {c.get('user', '?')}@{c.get('host', '?')}:"
                f"{c.get('port', '?')}/{db}  pw={c.get('password_preview', '****')}  "
                f"(from {c.get('source', '?')})"
            )
            option_list.add_option(Option(escape(label), id=c.get("token")))
        self._set_status(
            f"Found {len(candidates)} candidate(s). Select one and Store in vault."
        )

    async def _store_worker(self) -> None:
        if not self._selected_token:
            self._set_status("Select a candidate first.", error=True)
            return
        tools = self._tools()
        if tools is None:
            self._set_status("DB tooling unavailable.", error=True)
            return
        self._set_status("Storing in your secret vault…")
        try:
            out = await tools.db_setup_save(
                self._selected_token, instance_id=self._instance_ref(),
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("db_setup_save failed: %s", exc)
            self._set_status(f"Store failed: {exc}", error=True)
            return
        # db_setup_save returns a human string starting with "Saved" on success.
        if isinstance(out, str) and out.startswith("Saved"):
            self._set_status(
                "Stored. db_processlist / db_top_queries now resolve this "
                "credential by name."
            )
            self.notify("DB credential stored in vault.", severity="information")
            # The token is consumed; disable a second store of the same row.
            self._selected_token = ""
        else:
            self._set_status(str(out), error=True)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def on_option_list_option_selected(
        self, event: OptionList.OptionSelected,
    ) -> None:
        if event.option_list.id == "db_scan_candidates":
            self._selected_token = str(event.option.id or "")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "db_scan_store":
            self.run_worker(
                self._store_worker(),
                group="db_scan", exclusive=True, name="db_scan_store",
            )
        elif event.button.id == "db_scan_rescan":
            self._start_scan()

    def action_rescan(self) -> None:
        self._start_scan()

    def action_back(self) -> None:
        self.app.pop_screen()
