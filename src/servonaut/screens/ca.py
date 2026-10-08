"""SSH certificate authority status and audit screen."""
from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable, Coroutine, Mapping, Sequence
from typing import Any

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, Input, Select, Static

from servonaut.services.vault.ca_enrollment import BREAK_GLASS_AUTHORIZED_KEYS, MANAGED_PATHS_SUMMARY
from servonaut.services.vault.display import terminal_safe
from servonaut.services.vault.errors import SSH_CA_COMING_SOON, is_feature_disabled, vault_failure_reason
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar

_CHOOSE_TEAM_STATUS = "Choose a team to inspect its CA status."
_NO_TEAMS_HINT = "You are not in a team yet: create or join one from Team Management."
_NO_SERVERS_HINT = "No shared servers in this team yet: share one from Team Management."
_EVERY_ENROLLED_SERVER_LABEL = "All enrolled servers (KRL delivery and scan only)"
_NO_BREAK_GLASS = "No break-glass key"


class _EveryEnrolledServer:
    """The server picker's explicit "every enrolled server" choice.

    A blank, loading or failed picker never means every server: KRL delivery
    and the break-glass scan reach all enrolled hosts only when this is chosen.
    """

    def __repr__(self) -> str:
        return "EVERY_ENROLLED_SERVER"


_EVERY_ENROLLED_SERVER = _EveryEnrolledServer()


def _fingerprint(public_line: str) -> str:
    """Compute a displayed OpenSSH fingerprint instead of trusting wire text."""
    try:
        from servonaut.services.vault.crypto import openssh_fingerprint
        parts = public_line.split()
        if len(parts) < 2:
            raise ValueError("missing public key")
        return openssh_fingerprint(base64.b64decode(parts[1], validate=True))
    except Exception:
        return "invalid public key"


class CaEnrollmentConfirmModal(ModalScreen[str]):
    """Show verified enrollment consequences before accepting a host name."""

    def __init__(self, summary: Mapping[str, Any]) -> None:
        super().__init__()
        self._summary = summary

    def compose(self) -> ComposeResult:
        params = self._summary.get("params") if isinstance(self._summary.get("params"), Mapping) else {}
        server = params.get("server") if isinstance(params.get("server"), Mapping) else {}
        hostname = terminal_safe(server.get("hostname") or self._summary.get("hostname") or "")
        principals = params.get("principals_by_login") if isinstance(params.get("principals_by_login"), Mapping) else {}
        break_glass = params.get("break_glass") if isinstance(params.get("break_glass"), Mapping) else None
        kind = str(self._summary.get("kind") or params.get("kind") or "enroll")
        roles = self._summary.get("user_ca_roles") if isinstance(self._summary.get("user_ca_roles"), Mapping) else {}
        user_cas = [_fingerprint(str(key)) for key in params.get("user_ca_public_keys") or []]
        details = [
            f"Job: {kind}",
            f"Host: {hostname}",
            "User CA fingerprints: " + (", ".join(
                f"{fingerprint} ({roles.get(fingerprint, 'not a known team CA')})" for fingerprint in user_cas
            ) or "missing"),
            f"Host CA fingerprint: {_fingerprint(str(params.get('host_ca_public_key') or ''))}",
            f"Managed paths: {MANAGED_PATHS_SUMMARY}",
            (
                f"Break-glass: {break_glass.get('public_fingerprint') or break_glass.get('item_id')} for root, from "
                f"{', '.join(map(str, break_glass.get('from_cidrs') or [])) or 'anywhere'} "
                f"(appended to {BREAK_GLASS_AUTHORIZED_KEYS})"
                if break_glass else "Break-glass: none"
            ),
        ]
        details.extend(
            f"Login {terminal_safe(login)}: {', '.join(map(terminal_safe, values))}" for login, values in principals.items()
        )
        yield SafeHeader()
        yield Vertical(
            Static(f"[bold]Confirm SSH CA {escape(kind)}[/bold]"),
            *(Static(escape(detail)) for detail in details),
            Input(placeholder=f"Type {hostname}", id="ca_confirm_host"),
            Horizontal(Button("Cancel", id="ca_cancel"), Button("Enroll", id="ca_confirm")),
            id="ca_confirm_modal",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ca_confirm":
            self.dismiss(self.query_one("#ca_confirm_host", Input).value.strip())
        else:
            self.dismiss("")


class CaScreen(Screen):
    """Read-only CA state with an explicit audit action.

    Enrollment and policy changes remain in their command/modal flows because
    they require typed confirmation and a selected team/server.
    """

    DEFAULT_CSS = """
    CaScreen #ca_hint {
        color: $text-muted;
        margin-top: 1;
    }
    """

    BINDINGS = [Binding("escape", "back", "Back", show=True), Binding("r", "refresh", "Refresh", show=True)]

    # The team picker focuses itself once its teams load. Auto focus would land on
    # the first enabled button instead and scroll the pickers away on short terminals.
    AUTO_FOCUS = ""

    # Actions that need the team's CA; Refresh stays usable to re-check it.
    _CA_ACTION_IDS = ("ca_audit", "ca_enroll", "ca_krl", "ca_break_glass_scan")
    _PICKER_IDS = ("ca_team", "ca_server", "ca_break_glass")
    _SERVER_LIST_NOT_READY = {
        "loading": "Wait for this team's servers to load.",
        "failed": "This team's servers did not load: Refresh to try again.",
        "empty": _NO_SERVERS_HINT,
    }

    def __init__(self) -> None:
        super().__init__()
        self._status_raw = _CHOOSE_TEAM_STATUS
        # The team whose CA the service reported as not switched on yet.
        self._switched_off_team: str | None = None
        # The team the server and break-glass pickers were last filled for.
        self._active_team = ""
        # Whether the team picker offers at least one team; Refresh lists them again otherwise.
        self._teams_listed = False
        # Picker options as loaded, ``(value, label)``, so a demo toggle can relabel them.
        self._picker_options: dict[str, list[tuple[object, str]]] = {}
        self._hints: dict[str, str] = {}
        # "loading", "ready" (options offered), "empty" or "failed" for the active team, per picker.
        self._picker_state: dict[str, str] = {}
        # One CA action runs at a time, so another action cannot cancel an enrollment or KRL
        # delivery midway; Back waits for it too (leaving the screen cancels its workers).
        self._action_running = False

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        with Horizontal(id="ca_layout"):
            yield Sidebar()
            with Vertical(id="ca_content"):
                yield Static("SSH Certificate Authority", id="ca_title")
                yield Select[str]([], prompt="Loading teams…", id="ca_team", disabled=True)
                yield Select[str]([], prompt="Choose a team first", id="ca_server", disabled=True)
                yield Select[str]([], prompt="Choose a team first", id="ca_break_glass", disabled=True)
                yield Static("", id="ca_hint")
                yield Static(_CHOOSE_TEAM_STATUS, id="ca_status")
                yield Button("Refresh status", id="ca_refresh")
                yield Button("Audit issuance chain", id="ca_audit")
                yield Button("Enroll server", id="ca_enroll")
                yield Button("Deliver KRL", id="ca_krl")
                yield Button("Scan break-glass use", id="ca_break_glass_scan")
        yield Footer()

    def on_mount(self) -> None:
        self._sync_actions()
        self._start_teams_load()

    def _service(self) -> Any:
        return getattr(self.app, "vault_command_service", None)

    def _service_method(self, name: str) -> Callable[..., Any] | None:
        service = self._service()
        return getattr(service, name, None) if service is not None else None

    @staticmethod
    async def _call(method: Callable[..., Any], **kwargs: Any) -> Any:
        result = method(**kwargs)
        return await result if hasattr(result, "__await__") else result

    def scrub_for_display(self, value: object) -> str:
        """Return a demo-safe representation without changing service results."""
        text = str(value)
        redactor = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redactor is not None:
            return str(redactor.scrub_stream(text))
        return text

    def _set_status(self, value: object) -> None:
        self._status_raw = str(value)
        self.query_one("#ca_status", Static).update(escape(self.scrub_for_display(value)))

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the cached status, guidance and picker labels under the current demo redaction mode."""
        self._set_status(self._status_raw)
        self._render_hints()
        for picker_id, options in self._picker_options.items():
            select = self.query_one(f"#{picker_id}", Select)
            self._fill_picker(picker_id, options, prompt=select.prompt, keep=select.value)

    # -- pickers ---------------------------------------------------------

    def _picked(self, picker_id: str) -> str | None:
        """The chosen id; None for a blank picker and for the every-enrolled-server choice."""
        value = self.query_one(f"#{picker_id}", Select).value
        return value if isinstance(value, str) and value else None

    def _team(self) -> str:
        return self._picked("ca_team") or ""

    def _break_glass_item(self) -> str | None:
        return self._picked("ca_break_glass")

    def _chosen_servers(self) -> list[str] | None:
        """What KRL delivery and the scan target: ``[]`` for every enrolled server, None when nothing is chosen."""
        if self.query_one("#ca_server", Select).value is _EVERY_ENROLLED_SERVER:
            return []
        server = self._picked("ca_server")
        return [server] if server else None

    def _fill_picker(
        self, picker_id: str, options: Sequence[tuple[object, str]], *, prompt: str, keep: object = None,
    ) -> None:
        """Offer *options* as ``(value, label)``, keeping *keep* selected while it is still offered."""
        self._picker_options[picker_id] = list(options)
        select = self.query_one(f"#{picker_id}", Select)
        select.prompt = prompt
        # Text, not markup: labels carry names other people chose.
        select.set_options(
            (Text(self.scrub_for_display(terminal_safe(label))), value) for value, label in options
        )
        select.disabled = not options
        if keep is not None and any(value == keep for value, _ in options):
            select.value = keep

    def _set_picker_state(self, picker_id: str, state: str) -> None:
        self._picker_state[picker_id] = state
        self._sync_actions()

    def _set_hint(self, picker_id: str, text: str) -> None:
        if text:
            self._hints[picker_id] = text
        else:
            self._hints.pop(picker_id, None)
        self._render_hints()

    def _render_hints(self) -> None:
        lines = [self._hints[picker_id] for picker_id in self._PICKER_IDS if picker_id in self._hints]
        hint = self.query_one("#ca_hint", Static)
        hint.update(escape(self.scrub_for_display("\n".join(lines))))
        hint.display = bool(lines)

    @staticmethod
    def _choice_options(rows: Any, key: str) -> list[tuple[str, str]]:
        """``(value, label)`` pairs from a service picker method's ``[{key, "label"}]`` rows."""
        options = []
        for row in rows if isinstance(rows, list) else []:
            value = row.get(key) if isinstance(row, Mapping) else None
            if isinstance(value, str) and value:
                options.append((value, str(row.get("label") or value)))
        return options

    def _start_teams_load(self) -> None:
        self._teams_listed = False
        self._fill_picker("ca_team", [], prompt="Loading teams…")
        self._set_hint("ca_team", "")
        self.run_worker(self._load_teams(), group="ca_teams", exclusive=True)

    async def _load_teams(self) -> None:
        if self._service() is None:
            self._fill_picker("ca_team", [], prompt="No teams")
            self._set_status("CA services are unavailable in this session.")
            return
        method = self._service_method("team_choices")
        if method is None:
            self._fill_picker("ca_team", [], prompt="No teams")
            self._set_hint("ca_team", "Your teams cannot be listed in this session.")
            return
        try:
            options = self._choice_options(await self._call(method), "slug")
        except Exception as exc:
            self._fill_picker("ca_team", [], prompt="Teams unavailable")
            self._set_hint("ca_team", f"Could not load your teams ({vault_failure_reason(exc)}). Refresh to try again.")
            return
        self._teams_listed = bool(options)
        self._fill_picker("ca_team", options, prompt="Choose a team" if options else "No teams")
        self._set_hint("ca_team", "" if options else _NO_TEAMS_HINT)
        team = self.query_one("#ca_team", Select)
        if len(options) == 1:
            team.value = options[0][0]
        if options and self.focused is None:
            team.focus()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "ca_team":
            return
        # Read the picker, not the event: refilling options posts a blank value before the kept one.
        team = self._team()
        if team == self._active_team:
            return
        self._active_team = team
        if self._switched_off_team is not None and team != self._switched_off_team:
            self._clear_switched_off()
        self._load_team(team)

    def _load_team(self, team: str, *, keep_server: object = None, keep_break_glass: object = None) -> None:
        """Load *team*'s CA status and the servers and break-glass keys it offers.

        Status and options load in their own worker groups, so a team change
        never cancels a CA action that is already writing to hosts. Actions
        that use a picker stay disabled until its options are back.
        """
        self.workers.cancel_group(self, "ca_status")
        self.workers.cancel_group(self, "ca_options")
        self._set_hint("ca_server", "")
        self._set_hint("ca_break_glass", "")
        if not team:
            self._fill_picker("ca_server", [], prompt="Choose a team first")
            self._fill_picker("ca_break_glass", [], prompt="Choose a team first")
            self._set_picker_state("ca_server", "empty")
            self._set_picker_state("ca_break_glass", "empty")
            self._set_status(_CHOOSE_TEAM_STATUS)
            return
        self._fill_picker("ca_server", [], prompt="Loading servers…")
        self._fill_picker("ca_break_glass", [], prompt="Loading break-glass keys…")
        self._set_picker_state("ca_server", "loading")
        self._set_picker_state("ca_break_glass", "loading")
        self.run_worker(self._load(team), group="ca_status", exclusive=True)
        self.run_worker(
            self._load_team_options(team, keep_server, keep_break_glass), group="ca_options", exclusive=True,
        )

    async def _load_team_options(self, team: str, keep_server: object, keep_break_glass: object) -> None:
        await asyncio.gather(self._load_servers(team, keep_server), self._load_break_glass_keys(team, keep_break_glass))

    async def _load_servers(self, team: str, keep: object) -> None:
        method = self._service_method("shared_server_choices")
        if method is None:
            self._fill_picker("ca_server", [], prompt="Servers unavailable")
            self._set_hint("ca_server", "Shared servers cannot be listed in this session.")
            self._set_picker_state("ca_server", "failed")
            return
        try:
            servers = self._choice_options(await self._call(method, team=team), "server_id")
        except Exception as exc:
            self._fill_picker("ca_server", [], prompt="Servers unavailable")
            self._set_hint(
                "ca_server", f"Could not load this team's servers ({vault_failure_reason(exc)}). Refresh to try again.",
            )
            self._set_picker_state("ca_server", "failed")
            return
        if not servers:
            self._fill_picker("ca_server", [], prompt="No shared servers")
            self._set_hint("ca_server", _NO_SERVERS_HINT)
            self._set_picker_state("ca_server", "empty")
            return
        options: list[tuple[object, str]] = [(_EVERY_ENROLLED_SERVER, _EVERY_ENROLLED_SERVER_LABEL), *servers]
        self._fill_picker("ca_server", options, prompt="Choose a server", keep=keep)
        self._set_picker_state("ca_server", "ready")

    async def _load_break_glass_keys(self, team: str, keep: object) -> None:
        list_vaults, list_items = self._service_method("vault_choices"), self._service_method("list_items")
        if list_vaults is None or list_items is None:
            self._fill_picker("ca_break_glass", [], prompt=_NO_BREAK_GLASS)
            self._set_hint("ca_break_glass", "Break-glass keys cannot be listed in this session.")
            self._set_picker_state("ca_break_glass", "failed")
            return
        try:
            options = await self._break_glass_options(list_vaults, list_items, team)
        except Exception as exc:
            self._fill_picker("ca_break_glass", [], prompt=_NO_BREAK_GLASS)
            self._set_hint("ca_break_glass", f"Could not load break-glass keys ({vault_failure_reason(exc)}).")
            self._set_picker_state("ca_break_glass", "failed")
            return
        self._fill_picker(
            "ca_break_glass", options, prompt=_NO_BREAK_GLASS if options else "No break-glass keys in this team",
            keep=keep,
        )
        self._set_picker_state("ca_break_glass", "ready" if options else "empty")

    async def _break_glass_options(
        self, list_vaults: Callable[..., Any], list_items: Callable[..., Any], team: str,
    ) -> list[tuple[str, str]]:
        """The team vaults' live break-glass items, labelled by public fingerprint.

        Only item metadata is listed: nothing is decrypted to fill the picker.
        """
        listed_vaults = await self._call(list_vaults, team=team)
        vaults = [
            vault for vault in (listed_vaults if isinstance(listed_vaults, list) else [])
            if isinstance(vault, Mapping) and isinstance(vault.get("vault_id"), str)
        ]
        options = []
        for vault in vaults:
            listed = await self._call(list_items, vault_id=vault["vault_id"])
            rows = listed.get("data") if isinstance(listed, Mapping) else None
            for row in rows if isinstance(rows, list) else []:
                if not isinstance(row, Mapping) or row.get("type") != "break_glass" or row.get("deleted"):
                    continue
                item_id = row.get("item_id")
                if not isinstance(item_id, str) or not item_id:
                    continue
                label = f"Break-glass key {row.get('public_fingerprint') or item_id}"
                if len(vaults) > 1:
                    label += f" · {vault.get('label') or vault['vault_id']}"
                options.append((item_id, label))
        return sorted(options, key=lambda option: option[1].lower())

    # -- CA state and actions -------------------------------------------

    def _sync_actions(self) -> None:
        """Enable each CA action only while it can run on what the pickers show.

        Every action waits for a team, a switched-on CA and no other running
        action. Actions that name servers also wait for the server list (a
        list still loading or failed must never be read as "all servers"),
        and enrollment waits for the break-glass keys so a choice made before
        a refresh is not dropped while they reload.
        """
        servers_ready = self._picker_state.get("ca_server") == "ready"
        allowed = {
            "ca_audit": True,
            "ca_enroll": servers_ready and self._picker_state.get("ca_break_glass") != "loading",
            "ca_krl": servers_ready,
            "ca_break_glass_scan": servers_ready,
        }
        held_back = not self._team() or self._switched_off_team is not None or self._action_running
        for button_id in self._CA_ACTION_IDS:
            self.query_one(f"#{button_id}", Button).disabled = held_back or not allowed[button_id]

    def _show_switched_off(self, team: str) -> None:
        """Present certificates that are not switched on yet as information, not a failure."""
        selected = self._team()
        if selected and selected != team:
            return  # a late answer about a team no longer selected must not hold back this one
        self._switched_off_team = team
        self._sync_actions()
        self._set_status(SSH_CA_COMING_SOON)

    def _clear_switched_off(self) -> None:
        self._switched_off_team = None
        self._sync_actions()

    def _notify_failure(self, team: str, action: str, exc: Exception) -> None:
        if is_feature_disabled(exc, "ssh_ca"):
            self._show_switched_off(team)
            self.app.notify(SSH_CA_COMING_SOON, severity="information", markup=False)
            return
        self.app.notify(f"{action} failed ({vault_failure_reason(exc)}).", severity="error", markup=False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "ca_refresh":
            self.action_refresh()
            return
        if button_id not in self._CA_ACTION_IDS:
            return
        # The buttons are disabled in these cases; a press already queued must not slip through.
        team = self._team()
        if self._action_running:
            self.app.notify("Another CA action is still running.", severity="warning", markup=False)
        elif not team:
            self.app.notify("Choose a team first.", severity="warning", markup=False)
        elif button_id == "ca_audit":
            self._start_action(self._audit(team))
        elif self._picker_state.get("ca_server") != "ready":
            self.app.notify(self._SERVER_LIST_NOT_READY.get(
                self._picker_state.get("ca_server", ""), "Choose a team first.",
            ), severity="warning", markup=False)
        elif button_id == "ca_enroll":
            server = self._picked("ca_server")
            if server is None:
                self.app.notify("Choose a server to enroll first.", severity="warning", markup=False)
            elif self._picker_state.get("ca_break_glass") == "loading":
                self.app.notify("Wait for this team's break-glass keys to load.", severity="warning", markup=False)
            else:
                self._start_action(self._enroll(team, server, self._break_glass_item()))
        else:
            servers = self._chosen_servers()
            if servers is None:
                self.app.notify("Choose a server, or all enrolled servers, first.", severity="warning", markup=False)
                return
            work = self._deliver_krl(team, servers) if button_id == "ca_krl" else self._scan_break_glass(team, servers)
            self._start_action(work)

    def _start_action(self, work: Coroutine[Any, Any, None]) -> None:
        """Run one CA action, with every action held back until it ends.

        Its worker group is not exclusive, so neither another action nor a
        team change or Refresh can cancel a host write midway.
        """
        self._action_running = True
        self._sync_actions()
        self.run_worker(self._run_action(work), group="ca_action")

    async def _run_action(self, work: Coroutine[Any, Any, None]) -> None:
        try:
            await work
        finally:
            self._action_running = False
            if self.is_attached:
                self._sync_actions()

    def action_refresh(self) -> None:
        team = self._team()
        if team:
            self._load_team(
                team, keep_server=self.query_one("#ca_server", Select).value, keep_break_glass=self._break_glass_item(),
            )
        elif not self._teams_listed:
            self._start_teams_load()
        else:
            self.app.notify("Choose a team first.", severity="warning", markup=False)

    async def _load(self, team: str) -> None:
        service = self._service()
        if service is None:
            self._set_status("CA services are unavailable in this session.")
            return
        method = getattr(service, "ca_status", None)
        if method is None:
            self._set_status("CA status service is unavailable.")
            return
        try:
            result = await self._call(method, team=team)
        except Exception as exc:
            if is_feature_disabled(exc, "ssh_ca"):
                self._show_switched_off(team)
                return
            self._set_status(f"Could not load CA status ({vault_failure_reason(exc)}).")
            return
        self._clear_switched_off()
        if isinstance(result, Mapping):
            summary = ", ".join(
                f"{key}: {value}" for key, value in result.items()
                if not isinstance(value, (dict, list))
            )
        else:
            summary = str(result)
        self._set_status(summary or "No CA status returned.")

    async def _audit(self, team: str) -> None:
        method = self._service_method("ca_audit")
        if method is None:
            self.app.notify("CA audit service is unavailable.", severity="warning", markup=False)
            return
        try:
            result = await self._call(method, team=team)
        except Exception as exc:
            self._notify_failure(team, "CA audit", exc)
            return
        self._set_status(self.scrub_for_display(result))

    async def _enroll(self, team: str, server: str, break_glass_item: str | None = None) -> None:
        method = self._service_method("ca_enroll")
        if method is None:
            self.app.notify("CA enrollment service is unavailable.", severity="warning", markup=False)
            return

        async def confirmation(summary: Mapping[str, Any]) -> str:
            return str(await self.app.push_screen_wait(CaEnrollmentConfirmModal(summary)) or "")

        try:
            result = await self._call(
                method, team=team, server=server, break_glass_item_id=break_glass_item, confirmation=confirmation,
            )
        except Exception as exc:
            self._notify_failure(team, "CA enrollment", exc)
            return
        self._set_status(self.scrub_for_display(result))

    async def _deliver_krl(self, team: str, servers: list[str]) -> None:
        method = self._service_method("ca_deliver_krl")
        if method is None:
            self.app.notify("KRL delivery service is unavailable.", severity="warning", markup=False)
            return
        try:
            result = await self._call(method, team=team, servers=servers)
        except Exception as exc:
            self._notify_failure(team, "KRL delivery", exc)
            return
        self._set_status(self.scrub_for_display(result))

    async def _scan_break_glass(self, team: str, servers: list[str]) -> None:
        method = self._service_method("ca_break_glass_scan")
        if method is None:
            self.app.notify("Break-glass scanning is unavailable.", severity="warning", markup=False)
            return
        try:
            result = await self._call(method, team=team, servers=servers or None)
        except Exception as exc:
            self._notify_failure(team, "Break-glass scan", exc)
            return
        reported = result.get("reported", 0) if isinstance(result, Mapping) else 0
        self._set_status(self.scrub_for_display(result))
        if reported:
            self.app.notify(
                f"Reported {reported} break-glass login(s) to the team.", severity="warning", markup=False,
            )

    def action_back(self) -> None:
        if self._action_running:
            self.app.notify("An SSH certificate action is still running: wait for it to finish.",
                            severity="warning", markup=False)
            return
        self.app.pop_screen()
