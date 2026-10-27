"""Auto-bind: give each server the vault SSH key named like it, after one review.

The screen lists every server of the user's own (not a team's) with the key
from their personal vault that would be bound to it, the login and address
SSH uses, and the host keys this machine already trusts for it. Servers that
cannot be bound say why. Nothing is bound until the user has ticked that they
checked the host-key fingerprints and pressed Bind.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Mapping, Optional, Sequence

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Checkbox, DataTable, Footer, Select, Static

from servonaut.screens._busy_work import BusyWork
from servonaut.screens._demo_resolve import connection_instance, display_text, team_rows
from servonaut.services.vault import crypto
from servonaut.services.vault.auto_bind import (
    FETCH_FAILED,
    FETCHED,
    HOST_KEY_MISMATCH,
    NO_HOST_KEYS,
    READY,
    AutoBindRow,
    apply_auto_bind,
    fetch_host_keys_for_rows,
    plan_auto_bind,
)
from servonaut.services.vault.ec2_host_keys import key_family_from_public_key
from servonaut.services.vault.errors import vault_failure_reason
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)

# Held back while the review loads or the keys are being bound.
_ACTIONS = ("#auto_bind_apply", "#auto_bind_fetch_keys", "#auto_bind_all", "#auto_bind_none", "#auto_bind_trust")

INTRO = (
    "Each of your servers gets the key from your personal vault that is named like its "
    "key pair (an AWS server's key pair name) or like the server. The host keys pinned are "
    "the ones this computer already trusts from earlier SSH connections. A server that "
    "already has a vault key is left alone."
)


class AutoBindFetchConfirmModal(ModalScreen[bool]):
    """Confirm connecting once to record host keys."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="auto_bind_confirm_container"):
            yield Static(escape(self._message), id="auto_bind_confirm_message")
            with Horizontal(id="auto_bind_confirm_actions"):
                yield Button("Cancel", id="auto_bind_confirm_no")
                yield Button("Connect", variant="primary", id="auto_bind_confirm_yes")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "auto_bind_confirm_yes":
            self.dismiss(True)
        elif event.button.id == "auto_bind_confirm_no":
            self.dismiss(False)

    def action_cancel(self) -> None:
        self.dismiss(False)


class VaultAutoBindReviewModal(ModalScreen[bool]):
    """Review host keys and fingerprints before binding."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(
        self,
        rows: Sequence[AutoBindRow],
        *,
        server_name_fn: Callable[[AutoBindRow], str],
        scrub_fn: Callable[[object], str],
        team: Optional[str] = None,
        team_name: Optional[str] = None,
    ) -> None:
        super().__init__()
        self._review_rows = list(rows)
        self._server_name = server_name_fn
        self._scrub = scrub_fn
        self._team = team
        self._team_name = team_name
        self._all_verified = bool(self._review_rows) and all(row.verified for row in self._review_rows)

    def compose(self) -> ComposeResult:
        with Vertical(id="auto_bind_review_container"):
            yield Static("Review host keys before binding", id="auto_bind_review_title")
            if self._team:
                team_display = self._scrub(self._team_name or self._team)
                yield Static(
                    f"Everyone in {escape(team_display)} will connect with these keys.",
                    id="auto_bind_review_team_note",
                )
            with VerticalScroll(id="auto_bind_review_scroll"):
                for row in self._review_rows:
                    with Vertical(classes="auto_bind_review_item"):
                        s_name = self._scrub(self._server_name(row))
                        addr = f"{row.host}:{row.port}" if row.host and row.port != 22 else (row.host or "")
                        login_addr = f"{row.login}@{addr}" if row.login else addr
                        yield Static(f"[bold]{escape(s_name)}[/bold] ({escape(self._scrub(login_addr))})")
                        if row.host_keys:
                            for key in row.host_keys:
                                family = key_family_from_public_key(key)
                                try:
                                    fp = crypto.ssh_public_fingerprint(key)
                                except Exception:
                                    fp = "unknown fingerprint"
                                yield Static(f"  {escape(family)} · {escape(self._scrub(fp))}")
                        source = row.verification_source or ("verified by AWS console output" if row.verified else "trusted by this computer")
                        if not row.verified or "not verified" in source:
                            yield Static(f"  [dim]Verification:[/dim]\n    [dim]{escape(self._scrub(source))}[/dim]", classes="auto_bind_review_source")
                        else:
                            yield Static(f"  [dim]Source: {escape(self._scrub(source))}[/dim]", classes="auto_bind_review_source")

            yield Checkbox(
                "I checked these fingerprints: pin them",
                value=self._all_verified,
                id="vault_auto_bind_review_use_trusted",
                disabled=False,
            )
            with Horizontal(id="auto_bind_review_actions"):
                yield Button("Cancel", id="vault_auto_bind_review_cancel")
                yield Button(
                    "Bind",
                    variant="primary",
                    id="vault_auto_bind_review_confirm",
                    disabled=not self._all_verified,
                )

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "vault_auto_bind_review_use_trusted":
            btn = self.query_one("#vault_auto_bind_review_confirm", Button)
            btn.disabled = not (event.value or self._all_verified)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "vault_auto_bind_review_confirm":
            self.dismiss(True)
        elif event.button.id == "vault_auto_bind_review_cancel":
            self.dismiss(False)

    def action_cancel(self) -> None:
        self.dismiss(False)


class VaultAutoBindScreen(Screen):
    """Review and bind vault SSH keys to the servers named like them."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("space", "toggle_row", "Select", show=True),
        Binding("f", "fetch_host_keys", "Fetch host keys", show=True),
        Binding("r", "reload", "Check again", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._rows: list[AutoBindRow] = []
        self._selected: set[int] = set()
        self._vault_id: Optional[str] = None
        self._team: Optional[str] = None
        self._team_name: Optional[str] = None
        self._selected_target: str = "personal"
        self._has_personal_vault: bool = True
        self._team_vault_options_raw: list[tuple[str, str, str]] = []
        self._team_vault_map: dict[str, tuple[str, str, str]] = {}
        self._vault_options: list[tuple[str, str]] = [("Personal vault: binds for you", "personal")]
        # Real record (by identity) -> the row as the instance list shows it,
        # so demo mode shows its stand-in names while the real ones are bound.
        self._shown_as: dict[int, Mapping[str, Any]] = {}
        self._status_raw = ""
        self._busy = BusyWork(self, "#auto_bind_busy", display=self.scrub_for_display)

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        with Horizontal(id="auto_bind_layout"):
            yield Sidebar()
            with Vertical(id="auto_bind_content"):
                yield Static("[bold]Auto-bind vault keys[/bold]", id="auto_bind_title")
                yield Select[str](
                    [(Text("Personal vault: binds for you"), "personal")],
                    value="personal",
                    prompt="Select vault…",
                    id="auto_bind_vault_select",
                    allow_blank=False,
                    compact=True,
                )
                yield Static(INTRO, id="auto_bind_intro", markup=False)
                yield BusyIndicator(id="auto_bind_busy")
                yield Static("", id="auto_bind_status", markup=False)
                yield DataTable(id="auto_bind_table", cursor_type="row", zebra_stripes=True)
                yield Static("", id="auto_bind_detail", markup=False)
                yield Checkbox("I checked these host-key fingerprints: pin them", id="auto_bind_trust")
                with Horizontal(id="auto_bind_actions"):
                    yield Button("Bind selected", variant="primary", id="auto_bind_apply")
                    yield Button("Fetch host keys", id="auto_bind_fetch_keys")
                    yield Button("Select all", id="auto_bind_all")
                    yield Button("Select none", id="auto_bind_none")
                    yield Button("Back", id="auto_bind_back")
        yield Footer()

    def on_mount(self) -> None:
        self._sync_compact_layout()
        table = self.query_one("#auto_bind_table", DataTable)
        table.add_columns("Bind", "Server", "Status", "Vault key", "Matched by", "Login", "Address")
        self._sync_apply()
        self._sync_fetch()
        self.action_reload()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "auto_bind_vault_select":
            if event.value != event.select.value:
                return
            val = str(event.value) if event.value is not Select.NULL else "personal"
            if val != self._selected_target:
                self._selected_target = val
                self.action_reload()

    def on_resize(self) -> None:
        self._sync_compact_layout()

    def _sync_compact_layout(self) -> None:
        """Two buttons to a row once four labels no longer fit; no intro on a short terminal."""
        self.set_class(self.size.width <= 110, "-narrow")
        self.set_class(self.size.height <= 32, "-short")

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def scrub_for_display(self, value: object) -> str:
        """Demo-safe text: key names, logins and addresses are hidden in demo mode."""
        text = str(value)
        if not getattr(self.app, "demo_mode", False):
            return text
        return display_text(self.app, text)

    def _build_picker_options(self) -> list[tuple[Text, str]]:
        options: list[tuple[Text, str]] = []
        if self._has_personal_vault:
            options.append((Text("Personal vault: binds for you"), "personal"))
        for key, slug, raw_name in self._team_vault_options_raw:
            clean_name = self.scrub_for_display(raw_name)
            options.append((
                Text(f"Team vault: {clean_name} (binds for everyone in it)"),
                key,
            ))
        return options

    def _sync_intro(self) -> None:
        try:
            intro = self.query_one("#auto_bind_intro", Static)
        except NoMatches:
            return
        if self._team:
            clean_team = self.scrub_for_display(self._team_name or self._team)
            intro.update(
                f"Each shared server of {clean_team} gets the key from the team vault that is named like its "
                "key pair (an AWS server's key pair name) or like the server. The host keys pinned are "
                "the ones this computer already trusts from earlier SSH connections. A server that "
                "already has a team key is left alone."
            )
        else:
            intro.update(INTRO)

    def refresh_after_demo_toggle(self) -> None:
        self._render_rows()
        self._status(self._status_raw)
        self._sync_intro()
        self._busy.redraw()
        try:
            select = self.query_one("#auto_bind_vault_select", Select)
        except NoMatches:
            return
        options = self._build_picker_options()
        new_tuples = [(str(opt[0]), opt[1]) for opt in options]
        if self._vault_options != new_tuples:
            current_val = select.value
            select.set_options(options)
            self._vault_options = new_tuples
            if current_val in {opt[1] for opt in options}:
                select.value = current_val

    def _status(self, message: str) -> None:
        self._status_raw = message
        try:
            self.query_one("#auto_bind_status", Static).update(self.scrub_for_display(message))
        except NoMatches:
            pass

    def _server_name(self, row: AutoBindRow) -> str:
        shown = self._shown_as.get(id(row.instance), row.instance)
        return str(shown.get("name") or shown.get("id") or "server")

    def _render_rows(self) -> None:
        try:
            table = self.query_one("#auto_bind_table", DataTable)
        except NoMatches:
            return
        cursor = table.cursor_row
        table.clear()
        for index, row in enumerate(self._rows):
            if index in self._selected:
                mark = "[x]"
            elif row.ready and row.result is None:
                mark = "[ ]"
            else:
                mark = ""
            key_name = row.match.name if row.match is not None else ""
            matched_by = row.match.matched_by if row.match is not None else ""
            address = f"{row.host}:{row.port}" if row.host and row.port != 22 else (row.host or "")
            # Every value comes from a provider, the vault or the user: inert text.
            table.add_row(
                Text(mark),
                Text(self._server_name(row)),
                Text(row.status_label),
                Text(self.scrub_for_display(key_name)),
                Text(matched_by),
                Text(self.scrub_for_display(row.login or "")),
                Text(self.scrub_for_display(address)),
                key=str(index),
            )
        if self._rows:
            table.move_cursor(row=min(max(cursor, 0), len(self._rows) - 1))
        self._show_detail()
        self._sync_apply()
        self._sync_fetch()

    def _can_fetch_host_keys(self) -> tuple[bool, str]:
        if self._busy.is_busy:
            return False, ""
        has_no_host_keys = any(row.status == NO_HOST_KEYS for row in self._rows)
        if not has_no_host_keys:
            return False, "None of the servers need a host key fetched."
        service = self._service()
        if service is None:
            return False, "Vault services are unavailable."
        records = getattr(service, "records_new_host_keys", None)
        can_record = bool(records()) if callable(records) else False
        if not can_record:
            mode = "yes"
            conn_svc = getattr(service, "connection_service", None)
            if conn_svc is not None and hasattr(conn_svc, "host_key_policy"):
                try:
                    mode = conn_svc.host_key_policy().mode
                except Exception:
                    pass
            reason = (
                f"Connecting does not record new host keys with ssh.host_key_checking = {mode}: "
                "fetch them one by one with Use Vault Key, or paste verified keys."
            )
            return False, reason
        return True, ""

    def _sync_fetch(self) -> None:
        try:
            btn = self.query_one("#auto_bind_fetch_keys", Button)
        except Exception:
            return
        if self._busy.holds("#auto_bind_fetch_keys"):
            return
        can_fetch, reason = self._can_fetch_host_keys()
        btn.disabled = not can_fetch
        btn.tooltip = (
            reason if not can_fetch and reason else "Connect once to record host keys for servers missing them (f)"
        )

    def _show_detail(self) -> None:
        detail = self.query_one("#auto_bind_detail", Static)
        table = self.query_one("#auto_bind_table", DataTable)
        if not self._rows or not 0 <= table.cursor_row < len(self._rows):
            detail.update("")
            return
        row = self._rows[table.cursor_row]
        text = f"{self._server_name(row)}: {row.status_text_for('tui')}"
        if row.host_keys:
            prints = "\n".join(f"  {crypto.ssh_public_fingerprint(key)}" for key in row.host_keys)
            if row.status == READY and not row.verification_source:
                text += f"\nHost keys this computer trusts for {row.host}:\n{prints}"
            else:
                source_label = f" ({row.verification_source})" if row.verification_source else ""
                text += f"\nHost keys for {row.host}{source_label}:\n{prints}"
        elif row.status == NO_HOST_KEYS:
            can_fetch, reason = self._can_fetch_host_keys()
            if not can_fetch and reason and "No servers" not in reason:
                text += f"\n{reason}"
        detail.update(self.scrub_for_display(text))

    def _sync_apply(self) -> None:
        apply = self.query_one("#auto_bind_apply", Button)
        if self._busy.holds("#auto_bind_apply"):
            return  # running work gives the button back its state when it ends
        count = len(self._selected)
        apply.label = f"Bind selected ({count})" if count else "Bind selected"
        apply.disabled = count == 0

    # ------------------------------------------------------------------
    # Loading the review
    # ------------------------------------------------------------------

    def _service(self) -> Any:
        return getattr(self.app, "vault_command_service", None)

    def _servers(self) -> list[Mapping[str, Any]]:
        """The real records of the servers the instance list shows."""
        has_real = getattr(self.app, "has_real_record", None)
        self._shown_as = {}
        servers = []
        for shown in getattr(self.app, "instances", None) or []:
            if not isinstance(shown, dict):
                continue
            if callable(has_real) and has_real(shown) is False:
                continue  # a demo stand-in with no real server behind it is never bound
            real = connection_instance(self.app, shown)
            self._shown_as[id(real)] = shown
            servers.append(real)
        return servers

    def action_reload(self) -> None:
        if self._busy.is_busy:
            return
        self.run_worker(self._load, group="vault_auto_bind", exclusive=True)

    async def _load(self) -> None:
        service = self._service()
        if service is None:
            self._status("Vault services are unavailable: sign in, then open the Vault screen.")
            return
        with self._busy.running("Finding your personal vault…", hold=_ACTIONS) as job:
            try:
                vaults = await service.list_vaults()
            except Exception as exc:
                self._status(f"Could not load your vaults ({vault_failure_reason(exc)}).")
                return

            personal = [vault for vault in vaults if vault.get("kind") == "personal"]
            personal_vault_id = str(personal[0]["vault_id"]) if personal else None

            # Team role and name come from the team's real shared rows (team_rows(self.app))
            shared = team_rows(self.app)
            shared_by_slug: dict[str, list[dict[str, Any]]] = {}
            for row in shared:
                slug = row.get("team_slug")
                if slug:
                    shared_by_slug.setdefault(str(slug), []).append(row)

            team_vault_map: dict[str, tuple[str, str, str]] = {}
            team_vault_options_raw: list[tuple[str, str, str]] = []
            for v in vaults:
                if v.get("kind") == "team" and v.get("my_grant") is not None:
                    team_info = v.get("team") if isinstance(v.get("team"), Mapping) else {}
                    slug = str(team_info.get("slug") or v.get("team_slug") or "")
                    if not slug:
                        continue
                    team_shared = shared_by_slug.get(slug, [])
                    if not team_shared:
                        continue
                    role = str(team_shared[0].get("team_role") or "").lower()
                    if role in {"owner", "admin"}:
                        raw_name = str(team_shared[0].get("team_name") or team_info.get("name") or slug)
                        key = f"team:{slug}"
                        team_vault_options_raw.append((key, slug, raw_name))
                        team_vault_map[key] = (str(v["vault_id"]), slug, raw_name)

            self._has_personal_vault = bool(personal_vault_id)
            self._team_vault_options_raw = team_vault_options_raw
            self._team_vault_map = team_vault_map

            options = self._build_picker_options()
            if not options:
                self._status(
                    "You have no personal vault yet: create one on the Vault screen and import your SSH keys into it."
                )
                return

            select = self.query_one("#auto_bind_vault_select", Select)
            new_options = [(str(opt[0]), opt[1]) for opt in options]
            if self._vault_options != new_options:
                select.set_options(options)
                self._vault_options = new_options
            if self._selected_target not in {opt[1] for opt in options}:
                self._selected_target = options[0][1]
            if select.value != self._selected_target:
                select.value = self._selected_target

            if self._selected_target == "personal":
                if not personal_vault_id:
                    self._status(
                        "You have no personal vault yet: create one on the Vault screen and import your SSH keys into it."
                    )
                    return
                self._vault_id = personal_vault_id
                self._team = None
                self._team_name = None
            else:
                self._vault_id, self._team, self._team_name = self._team_vault_map[self._selected_target]

            self._sync_intro()

            # Every key's name is decrypted locally to compare it.
            if self._team:
                clean_team = self.scrub_for_display(self._team_name or self._team)
                self._busy.say(job, f"Reading the names of team vault SSH keys for {clean_team}…")
            else:
                self._busy.say(job, "Reading the names of your vault's SSH keys… this can take a few seconds")
            try:
                keys = await service.ssh_key_choices(vault_id=self._vault_id, name_limit=None)
            except Exception as exc:
                self._status(f"Could not read your vault's SSH keys ({vault_failure_reason(exc)}).")
                return
            if not keys:
                if self._team:
                    clean_team = self.scrub_for_display(self._team_name or self._team)
                    self._status(f"Team vault for {clean_team} has no SSH key yet: import keys with Import SSH on the Vault screen.")
                else:
                    self._status("Your personal vault has no SSH key yet: import your keys with Import SSH on the Vault screen.")
                return
            self._busy.say(job, "Checking each server's vault key, login and trusted host keys…")
            try:
                if self._team:
                    rows = await plan_auto_bind(service, self._servers(), keys, team=self._team)
                else:
                    rows = await plan_auto_bind(service, self._servers(), keys)
            except Exception as exc:
                logger.warning("Auto-bind review failed: %s", type(exc).__name__)
                self._status(f"Could not check your servers ({vault_failure_reason(exc)}).")
                return
        self._rows = rows
        self._selected = {index for index, row in enumerate(rows) if row.ready}
        self._render_rows()
        self._sync_fetch()
        ready = len(self._selected)
        if not rows:
            if self._team:
                clean_team = self.scrub_for_display(self._team_name or self._team)
                self._status(f"Team {clean_team} has no shared servers to bind a key to.")
            else:
                self._status("You have no servers of your own to bind a key to.")
        elif ready:
            self._status(
                f"{ready} of {len(rows)} servers can get a vault key. Check their host-key fingerprints "
                "(shown for the highlighted server), tick the box and press Bind selected."
            )
        else:
            if self._team:
                clean_team = self.scrub_for_display(self._team_name or self._team)
                if len(rows) == 1:
                    self._status(f"The 1 shared server of {clean_team} can't get a vault key automatically: see its status.")
                else:
                    self._status(f"None of the {len(rows)} shared servers of {clean_team} can get a vault key automatically: see each status.")
            else:
                if len(rows) == 1:
                    self._status("Your 1 server can't get a vault key automatically: see its status.")
                else:
                    self._status(f"None of your {len(rows)} servers can get a vault key automatically: see each status.")

    # ------------------------------------------------------------------
    # Choosing, fetching, and binding
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.action_toggle_row()

    def action_toggle_row(self) -> None:
        if self._busy.is_busy or not self._rows:
            return
        index = self.query_one("#auto_bind_table", DataTable).cursor_row
        if not 0 <= index < len(self._rows):
            return
        row = self._rows[index]
        if not row.ready or row.result is not None:
            return
        self._selected.symmetric_difference_update({index})
        self._render_rows()

    def action_fetch_host_keys(self) -> None:
        can_fetch, reason = self._can_fetch_host_keys()
        if not can_fetch or self._busy.is_busy:
            if reason and any(row.status == NO_HOST_KEYS for row in self._rows):
                self._status(reason)
            return
        target_rows = [row for row in self._rows if row.status == NO_HOST_KEYS]
        if not target_rows:
            return
        n = len(target_rows)
        msg = (
            f"Connect once to each of {n} servers to record its host key? Nothing is bound yet."
            if n > 1
            else "Connect once to this server to record its host key? Nothing is bound yet."
        )

        def on_confirmed(confirmed: bool) -> None:
            if confirmed:
                self.run_worker(
                    self._run_fetch_host_keys(target_rows),
                    group="vault_auto_bind_host_keys",
                    exclusive=True,
                )

        self.app.push_screen(AutoBindFetchConfirmModal(msg), on_confirmed)

    async def _run_fetch_host_keys(self, target_rows: list[AutoBindRow]) -> None:
        service = self._service()
        if service is None or not target_rows:
            return
        total = len(target_rows)
        with self._busy.running(f"Fetching host keys (1 of {total})…", hold=_ACTIONS) as job:
            def progress(index: int, row: AutoBindRow) -> None:
                self._busy.say(job, f"Fetching host keys ({index} of {total})…")

            await fetch_host_keys_for_rows(
                service,
                target_rows,
                on_progress=progress,
                accounts=getattr(self.app, "accounts", None),
            )

        newly_ready = {i for i, row in enumerate(self._rows) if row.status == FETCHED and row.result is None}
        self._selected |= newly_ready
        self._render_rows()
        self._sync_fetch()

        fetched_count = sum(row.status == FETCHED for row in target_rows)
        failed_count = sum(row.status in {FETCH_FAILED, HOST_KEY_MISMATCH} for row in target_rows)
        message = f"Fetched host keys for {fetched_count} of {total} servers."
        if failed_count:
            message += f" {failed_count} failed or mismatched: see status."
        self._status(message)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button = event.button.id
        if button == "auto_bind_back":
            self.action_back()
        elif button == "auto_bind_fetch_keys":
            self.action_fetch_host_keys()
        elif button == "auto_bind_all":
            self._selected = {i for i, row in enumerate(self._rows) if row.ready and row.result is None}
            self._render_rows()
        elif button == "auto_bind_none":
            self._selected.clear()
            self._render_rows()
        elif button == "auto_bind_apply":
            self._start_binding()

    def _start_binding(self) -> None:
        if self._busy.is_busy or not self._selected:
            return
        chosen = [self._rows[index] for index in sorted(self._selected) if self._rows[index].ready]
        if not chosen:
            return

        needs_review = any(row.status == FETCHED or row.verified for row in chosen)
        if needs_review:
            def on_reviewed(confirmed: bool) -> None:
                if confirmed:
                    self.run_worker(self._bind(chosen, reviewed_fetched=True), group="vault_auto_bind", exclusive=True)

            self.app.push_screen(
                VaultAutoBindReviewModal(
                    chosen,
                    server_name_fn=self._server_name,
                    scrub_fn=self.scrub_for_display,
                    team=self._team,
                    team_name=self._team_name,
                ),
                on_reviewed,
            )
            return

        if not self.query_one("#auto_bind_trust", Checkbox).value:
            self._status("Check the host-key fingerprints of the selected servers, then tick the box to pin them.")
            return
        self.run_worker(self._bind(chosen, reviewed_fetched=False), group="vault_auto_bind", exclusive=True)

    async def _bind(self, chosen: Sequence[AutoBindRow] | None = None, *, reviewed_fetched: bool = False) -> None:
        service = self._service()
        if chosen is None:
            chosen = [self._rows[index] for index in sorted(self._selected) if self._rows[index].ready]
        if service is None or self._vault_id is None or not chosen:
            return
        if self._team:
            clean_team = self.scrub_for_display(self._team_name or self._team)
            busy_msg = f"Binding vault keys to {clean_team} shared servers ({len(chosen)} servers)…"
        else:
            busy_msg = f"Binding vault keys ({len(chosen)} servers)…"
        with self._busy.running(busy_msg, hold=_ACTIONS) as job:
            def progress(index: int, row: AutoBindRow) -> None:
                self._busy.say(job, f"Binding {index + 1} of {len(chosen)}: {self._server_name(row)}…")

            await apply_auto_bind(
                service,
                chosen,
                vault_id=self._vault_id,
                team=self._team,
                reviewed_fetched=reviewed_fetched,
                on_progress=progress,
            )
        self._selected.clear()
        self.query_one("#auto_bind_trust", Checkbox).value = False
        self._render_rows()
        bound = sum(row.result == "bound" for row in chosen)
        failed = len(chosen) - bound
        message = f"Bound vault keys to {bound} of {len(chosen)} servers."
        if failed:
            message += f" {failed} failed: see their status."
        self._status(message)
        self.app.notify(message, severity="warning" if failed else "information", markup=False)

    def action_back(self) -> None:
        # Leaving while binding stops the servers not reached yet; those bound stay bound.
        self.app.pop_screen()
