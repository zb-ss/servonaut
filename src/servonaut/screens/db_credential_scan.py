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
from typing import Any, Dict, List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, Header, Input, Static
from textual.widgets import OptionList
from textual.widgets.option_list import Option

from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


class _DbLabelPromptModal(ModalScreen[Optional[str]]):
    """Confirm/override the site label before a candidate is stored.

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
            Static("[bold]Label this DB credential[/bold]", id="db_label_modal_title"),
            Static(
                "[dim]Names the site so you can load it by name later. Leave "
                "blank for the instance's single/default DB. Give each site on "
                "a multi-DB box its own label.[/dim]",
                id="db_label_modal_hint",
            ),
            Input(
                value=self._initial,
                placeholder="e.g. shop.example.com",
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
    """Scan a server for DB credentials, review redacted candidates, store one."""

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

    def _instance_ref(self) -> str:
        return str(self._instance.get("id") or self._instance.get("name") or "")

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
            instance_id = str(self._instance.get("id") or "")
            instance_name = str(self._instance.get("name") or "")
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
                    Static("", id="db_scan_roots_line"),
                    Static("Scanning…", id="db_scan_status"),
                    OptionList(id="db_scan_candidates"),
                    Horizontal(
                        Button("Store in vault", id="db_scan_store", variant="success"),
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
            line.update(f"[dim]Custom scan roots ([b]p[/b] to edit): {shown}[/dim]")
        else:
            line.update(
                "[dim]Scanning built-in web roots. Missing an app? Add its path "
                "with [b]p[/b] (Scan roots).[/dim]"
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
        # Custom roots (if configured) are passed as a space-separated
        # search_path; the scanner iterates each. Empty → built-in defaults.
        search_path = " ".join(self._custom_roots())
        try:
            result = await tools.db_scan_stage(
                self._instance_ref(), search_path=search_path,
            )
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
        self._stored_tokens: set = getattr(self, "_stored_tokens", set())
        stored_labels, has_default = self._stored_label_info()
        multi = len(candidates) > 1
        vaulted_count = 0
        for c in candidates:
            label = (c.get("label") or "").strip()
            already_stored = (
                label.lower() in stored_labels if label else has_default
            )
            if already_stored:
                vaulted_count += 1
            db = c.get("database") or "?"
            site = f"[{c['label']}] " if c.get("label") else ""
            row = (
                f"{site}{c.get('engine', '?')}  {c.get('user', '?')}@"
                f"{c.get('host', '?')}:{c.get('port', '?')}/{db}  "
                f"pw={c.get('password_preview', '****')}  (from {c.get('source', '?')})"
            )
            # Prepend a neutral, plain-text badge so the whole prompt (which
            # carries server-controlled strings) stays escaped — no markup on
            # the dynamic content.
            badge = "✓ stored  " if already_stored else ""
            option_list.add_option(Option(badge + escape(row), id=c.get("token")))
        hint = (
            "Store each site you want — they're saved under their own labels."
            if multi else "Select the candidate and Store in vault."
        )
        vaulted = (
            f" {vaulted_count} already vaulted." if vaulted_count else ""
        )
        self._set_status(
            f"Found {len(candidates)} candidate(s).{vaulted} {hint}"
        )

    async def _store_worker(self, label: str = "") -> None:
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
                label=label,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("db_setup_save failed: %s", exc)
            self._set_status(f"Store failed: {exc}", error=True)
            return
        # db_setup_save returns a human string starting with "Saved" on success.
        if isinstance(out, str) and out.startswith("Saved"):
            # Remember which rows are stored so the user can keep storing the
            # OTHER sites on this instance (one box can host several DBs).
            stored = getattr(self, "_stored_tokens", set())
            stored.add(self._selected_token)
            self._stored_tokens = stored
            remaining = len(self._candidates) - len(stored)
            more = (
                f" Select another site to store ({remaining} left)."
                if remaining > 0 else ""
            )
            self._set_status(
                "Stored. db_processlist / db_top_queries now resolve it by "
                "site name." + more
            )
            self.notify("DB credential stored in vault.", severity="information")
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
            self._open_store_prompt()
        elif event.button.id == "db_scan_rescan":
            self._start_scan()
        elif event.button.id == "db_scan_roots_btn":
            self.action_edit_roots()

    def _open_store_prompt(self) -> None:
        """Prompt for the site label (pre-filled with the derived one), then
        store the selected candidate under it."""
        if not self._selected_token:
            self._set_status("Select a candidate first.", error=True)
            return
        derived = ""
        for c in self._candidates:
            if c.get("token") == self._selected_token:
                derived = (c.get("label") or "").strip()
                break

        def _after(label: Optional[str]) -> None:
            if label is None:
                return  # cancelled
            self.run_worker(
                self._store_worker(label.strip()),
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
