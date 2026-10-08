"""SSH certificate authority status and audit screen."""
from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import Any

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, Input, Static

from servonaut.services.vault.ca_enrollment import BREAK_GLASS_AUTHORIZED_KEYS, MANAGED_PATHS_SUMMARY
from servonaut.services.vault.errors import SSH_CA_COMING_SOON, is_feature_disabled, vault_failure_reason
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar


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
        hostname = str(server.get("hostname") or self._summary.get("hostname") or "")
        principals = params.get("principals_by_login") if isinstance(params.get("principals_by_login"), Mapping) else {}
        break_glass = params.get("break_glass") if isinstance(params.get("break_glass"), Mapping) else None
        details = [
            f"Host: {hostname}",
            f"User CA fingerprints: {', '.join(_fingerprint(str(key)) for key in params.get('user_ca_public_keys') or []) or 'missing'}",
            f"Host CA fingerprint: {_fingerprint(str(params.get('host_ca_public_key') or ''))}",
            f"Managed paths: {MANAGED_PATHS_SUMMARY}",
            (
                f"Break-glass: {break_glass.get('public_fingerprint') or break_glass.get('item_id')} for root, from "
                f"{', '.join(map(str, break_glass.get('from_cidrs') or [])) or 'anywhere'} "
                f"(appended to {BREAK_GLASS_AUTHORIZED_KEYS})"
                if break_glass else "Break-glass: none"
            ),
        ]
        details.extend(f"Login {login}: {', '.join(map(str, values))}" for login, values in principals.items())
        yield SafeHeader()
        yield Vertical(
            Static("[bold]Confirm SSH CA enrollment[/bold]"),
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

    BINDINGS = [Binding("escape", "back", "Back", show=True), Binding("r", "refresh", "Refresh", show=True)]

    # Actions that need the team's CA; Refresh stays usable to re-check it.
    _CA_ACTION_IDS = ("ca_audit", "ca_enroll", "ca_krl", "ca_break_glass_scan")

    def __init__(self) -> None:
        super().__init__()
        self._status_raw = "Enter a team slug to inspect its CA status."
        # The team whose CA the service reported as not switched on yet.
        self._switched_off_team: str | None = None

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        with Horizontal(id="ca_layout"):
            yield Sidebar()
            with Vertical(id="ca_content"):
                yield Static("SSH Certificate Authority", id="ca_title")
                yield Input(placeholder="Team slug", id="ca_team")
                yield Input(placeholder="Server name or id", id="ca_server")
                yield Input(placeholder="Break-glass item id for enrollment (optional)", id="ca_break_glass")
                yield Static("Enter a team slug to inspect its CA status.", id="ca_status")
                yield Button("Refresh status", id="ca_refresh")
                yield Button("Audit issuance chain", id="ca_audit")
                yield Button("Enroll server", id="ca_enroll")
                yield Button("Deliver KRL", id="ca_krl")
                yield Button("Scan break-glass use", id="ca_break_glass_scan")
        yield Footer()

    def _service(self) -> Any:
        return getattr(self.app, "vault_command_service", None)

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
        """Redraw the cached status under the current demo redaction mode."""
        self._set_status(self._status_raw)

    def _team(self) -> str:
        return self.query_one("#ca_team", Input).value.strip()

    def _set_ca_actions_enabled(self, enabled: bool) -> None:
        for button_id in self._CA_ACTION_IDS:
            self.query_one(f"#{button_id}", Button).disabled = not enabled

    def _show_switched_off(self, team: str) -> None:
        """Present certificates that are not switched on yet as information, not a failure."""
        self._switched_off_team = team
        self._set_ca_actions_enabled(False)
        self._set_status(SSH_CA_COMING_SOON)

    def _clear_switched_off(self) -> None:
        self._switched_off_team = None
        self._set_ca_actions_enabled(True)

    def _notify_failure(self, team: str, action: str, exc: Exception) -> None:
        if is_feature_disabled(exc, "ssh_ca"):
            self._show_switched_off(team)
            self.app.notify(SSH_CA_COMING_SOON, severity="information", markup=False)
            return
        self.app.notify(f"{action} failed ({vault_failure_reason(exc)}).", severity="error", markup=False)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "ca_team" and self._switched_off_team is not None:
            if event.value.strip() != self._switched_off_team:
                self._clear_switched_off()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ca_refresh":
            self.action_refresh()
        elif event.button.id == "ca_audit":
            team = self._team()
            if not team:
                self.app.notify("Enter a team slug first.", severity="warning", markup=False)
                return
            self.run_worker(self._audit(team), group="vault", exclusive=True)
        elif event.button.id == "ca_enroll":
            team, server = self._team(), self.query_one("#ca_server", Input).value.strip()
            if not team or not server:
                self.app.notify("Enter a team slug and server first.", severity="warning", markup=False)
                return
            self.run_worker(self._enroll(team, server), group="vault", exclusive=True)
        elif event.button.id == "ca_krl":
            team, server = self._team(), self.query_one("#ca_server", Input).value.strip()
            if not team:
                self.app.notify("Enter a team slug first.", severity="warning", markup=False)
                return
            self.run_worker(self._deliver_krl(team, [server] if server else []), group="vault", exclusive=True)
        elif event.button.id == "ca_break_glass_scan":
            team, server = self._team(), self.query_one("#ca_server", Input).value.strip()
            if not team:
                self.app.notify("Enter a team slug first.", severity="warning", markup=False)
                return
            self.run_worker(self._scan_break_glass(team, [server] if server else []), group="vault", exclusive=True)

    def action_refresh(self) -> None:
        team = self._team()
        if not team:
            self.app.notify("Enter a team slug first.", severity="warning", markup=False)
            return
        self.run_worker(self._load(team), group="vault", exclusive=True)

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
            result = method(team=team)
            result = await result if hasattr(result, "__await__") else result
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
        service = self._service()
        method = getattr(service, "ca_audit", None) if service is not None else None
        if method is None:
            self.app.notify("CA audit service is unavailable.", severity="warning", markup=False)
            return
        try:
            result = method(team=team)
            result = await result if hasattr(result, "__await__") else result
        except Exception as exc:
            self._notify_failure(team, "CA audit", exc)
            return
        self._set_status(self.scrub_for_display(result))

    async def _enroll(self, team: str, server: str) -> None:
        service = self._service()
        method = getattr(service, "ca_enroll", None) if service is not None else None
        if method is None:
            self.app.notify("CA enrollment service is unavailable.", severity="warning", markup=False)
            return

        async def confirmation(summary: Mapping[str, Any]) -> str:
            return str(await self.app.push_screen_wait(CaEnrollmentConfirmModal(summary)) or "")

        break_glass_item = self.query_one("#ca_break_glass", Input).value.strip() or None
        try:
            result = method(team=team, server=server, break_glass_item_id=break_glass_item, confirmation=confirmation)
            result = await result if hasattr(result, "__await__") else result
        except Exception as exc:
            self._notify_failure(team, "CA enrollment", exc)
            return
        self._set_status(self.scrub_for_display(result))

    async def _deliver_krl(self, team: str, servers: list[str]) -> None:
        service = self._service()
        method = getattr(service, "ca_deliver_krl", None) if service is not None else None
        if method is None:
            self.app.notify("KRL delivery service is unavailable.", severity="warning", markup=False)
            return
        try:
            result = method(team=team, servers=servers)
            result = await result if hasattr(result, "__await__") else result
        except Exception as exc:
            self._notify_failure(team, "KRL delivery", exc)
            return
        self._set_status(self.scrub_for_display(result))

    async def _scan_break_glass(self, team: str, servers: list[str]) -> None:
        service = self._service()
        method = getattr(service, "ca_break_glass_scan", None) if service is not None else None
        if method is None:
            self.app.notify("Break-glass scanning is unavailable.", severity="warning", markup=False)
            return
        try:
            result = method(team=team, servers=servers or None)
            result = await result if hasattr(result, "__await__") else result
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
        self.app.pop_screen()
