"""Native encrypted-vault TUI surface.

This screen deliberately renders only metadata until a user confirms a reveal.
The application injects ``vault_command_service`` during paid-service setup;
the screen never constructs cryptographic or HTTP services itself.
"""
from __future__ import annotations

import asyncio
import math
import secrets
from collections.abc import Mapping
from typing import Any, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Input, Select, SelectionList, Static
from textual.widgets.selection_list import Selection

from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.services.vault import onboarding
from servonaut.services.vault.errors import vault_failure_reason
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar


async def _invoke(service: Any, method: str, /, **kwargs: Any) -> Any:
    target = getattr(service, method, None)
    if target is None and isinstance(service, Mapping):
        target = service.get(method)
    if target is None:
        raise RuntimeError(f"Vault service does not provide {method}().")
    result = target(**kwargs)
    return await result if hasattr(result, "__await__") else result


def _approval_poll_delay(service: Any, attempt: int) -> float:
    """Read a validated approval/reset backoff from the injected facade."""
    delay_for = getattr(service, "approval_poll_delay", None)
    if not callable(delay_for):
        raise RuntimeError("Vault approval polling is not configured.")
    delay = delay_for(attempt)
    if isinstance(delay, bool) or not isinstance(delay, (int, float)) or not math.isfinite(delay) or delay <= 0:
        raise RuntimeError("Vault approval polling is not configured.")
    return float(delay)


class VaultRevealModal(ModalScreen[None]):
    """Show one explicitly requested plaintext value without Rich interpolation."""

    BINDINGS = [Binding("escape", "dismiss_modal", "Close", show=True)]

    def __init__(self, item: Mapping[str, Any]) -> None:
        super().__init__()
        self._item = item

    def compose(self) -> ComposeResult:
        plaintext = self._item.get("plaintext")
        plaintext = plaintext if isinstance(plaintext, Mapping) else self._item
        value = plaintext.get("value") or plaintext.get("private_key_openssh") or ""
        yield SafeHeader()
        yield Vertical(
            Static("[bold]Revealed vault item[/bold]"),
            Static(escape(str(value)), id="vault_revealed_value"),
            Button("Close", id="vault_reveal_close"),
            id="vault_reveal_modal",
        )

    def on_button_pressed(self, _event: Button.Pressed) -> None:
        self.dismiss()

    def action_dismiss_modal(self) -> None:
        self.dismiss()


class VaultSecretPromptModal(ModalScreen[Optional[str]]):
    """Collect one secret through a masked Textual input without displaying it."""

    def __init__(self, title: str, prompt: str) -> None:
        super().__init__()
        self._title = title
        self._prompt = prompt

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield Vertical(
            Static(escape(self._title)),
            Static(escape(self._prompt)),
            Input(password=True, id="vault_secret_input"),
            Horizontal(Button("Cancel", id="vault_secret_cancel"), Button("Continue", id="vault_secret_continue")),
            id="vault_secret_modal",
        )

    def on_mount(self) -> None:
        self.query_one("#vault_secret_input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "vault_secret_continue":
            self.dismiss(self.query_one("#vault_secret_input", Input).value or None)
        else:
            self.dismiss(None)


def _grouped_key(key: str, per_line: int = 6) -> str:
    """Break a recovery key only between groups, so no group is split across lines."""
    groups = [group for group in key.split("-") if group]
    lines = ["-".join(groups[index : index + per_line]) for index in range(0, len(groups), per_line)]
    return "-\n".join(lines)


class VaultRecoveryConfirmModal(ModalScreen[bool]):
    """Show a recovery key once and require two randomly selected groups."""

    def __init__(self, recovery_key: str) -> None:
        super().__init__()
        self._recovery_key = recovery_key
        self._groups = [part for part in recovery_key.replace(" ", "-").split("-") if part]
        # The leading format marker is public; proving it does not prove that
        # the user recorded any recovery-key material. Retain original indexes
        # so the displayed group numbers match the key the user wrote down.
        secret_indices = [
            index for index, group in enumerate(self._groups)
            if group.upper() not in {"SVRK1", "SVTR1"}
        ]
        self._checks = sorted(secrets.SystemRandom().sample(secret_indices, 2)) if len(secret_indices) >= 2 else []

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        fields = [
            Static("[bold]Record this recovery key offline. It will not be shown again.[/bold]"),
            Static(escape(_grouped_key(self._recovery_key)), id="vault_recovery_key"),
            Static("Groups are counted from the left; the first group is group 1.", id="vault_recovery_hint"),
        ]
        for index in self._checks:
            fields.append(Input(placeholder=f"Re-enter group {index + 1}", password=True, id=f"vault_recovery_group_{index}"))
        yield Vertical(*fields, Horizontal(Button("Cancel", id="vault_recovery_cancel"), Button("Confirm", id="vault_recovery_confirm")), id="vault_recovery_confirm_modal")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "vault_recovery_confirm" or len(self._checks) != 2:
            self.dismiss(False)
            return
        valid = all(
            self.query_one(f"#vault_recovery_group_{index}", Input).value.strip().upper() == self._groups[index].upper()
            for index in self._checks
        )
        self.dismiss(valid)


class VaultSasConfirmModal(ModalScreen[bool]):
    """Hold the one approval comparison at the UI boundary."""

    def __init__(self, sas: str) -> None:
        super().__init__()
        self._sas = sas

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield Vertical(
            Static("[bold]Compare this safety number on both devices[/bold]"),
            Static(escape(self._sas), id="vault_sas"),
            Horizontal(Button("Mismatch", id="vault_sas_no"), Button("Matches", id="vault_sas_yes")),
            id="vault_sas_modal",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "vault_sas_yes")


class VaultPendingDeviceModal(ModalScreen[bool]):
    """Offer an approver the verified pending-device review path."""

    def __init__(self, device: Mapping[str, Any]) -> None:
        super().__init__()
        self._device = device

    def compose(self) -> ComposeResult:
        name = str(self._device.get("device_name") or self._device.get("name") or "New device")
        platform = str(self._device.get("platform") or "unknown platform")
        yield SafeHeader()
        yield Vertical(
            Static("[bold]A device is waiting for vault approval[/bold]"),
            Static(escape(f"{name} · {platform}")),
            Static("Review the device and compare its safety number before approving."),
            Horizontal(Button("Later", id="vault_pending_device_later"), Button("Review devices", id="vault_pending_device_review")),
            id="vault_pending_device_modal",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "vault_pending_device_review")


async def show_pending_device(app: Any, service: Any, device: Mapping[str, Any]) -> None:
    """Present a verified pending-device review from whichever screen is active."""
    if not isinstance(device, Mapping):
        return

    def reviewed(open_devices: bool) -> None:
        if not open_devices:
            return
        current = getattr(app, "screen", None)
        if isinstance(current, VaultScreen):
            current.action_devices()
            return
        app.push_screen(VaultScreen())

    app.push_screen(VaultPendingDeviceModal(device), reviewed)


class VaultExposureActionModal(ModalScreen[Optional[dict[str, str]]]):
    """Collect an explicit exposure resolution or per-host rotation request."""

    def __init__(self, *, rotation: bool) -> None:
        super().__init__()
        self._rotation = rotation

    def compose(self) -> ComposeResult:
        fields: list[Any] = [Static("[bold]Rotate exposed SSH key[/bold]" if self._rotation else "[bold]Resolve exposure[/bold]")]
        if self._rotation:
            fields.extend((Input(placeholder="Team slug", id="vault_exposure_team"), Input(placeholder="Server IDs, comma separated", id="vault_exposure_servers")))
        else:
            fields.extend((Input(placeholder="rotated, accepted_risk, or not_deployed", id="vault_exposure_resolution"), Input(placeholder="Note (optional)", id="vault_exposure_note")))
        fields.append(Horizontal(Button("Cancel", id="vault_exposure_cancel"), Button("Continue", id="vault_exposure_confirm")))
        yield SafeHeader()
        yield Vertical(*fields, id="vault_exposure_modal")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "vault_exposure_confirm":
            self.dismiss(None)
            return
        if self._rotation:
            team = self.query_one("#vault_exposure_team", Input).value.strip()
            servers = self.query_one("#vault_exposure_servers", Input).value.strip()
            self.dismiss({"team": team, "servers": servers} if team and servers else None)
            return
        resolution = self.query_one("#vault_exposure_resolution", Input).value.strip()
        note = self.query_one("#vault_exposure_note", Input).value.strip()
        self.dismiss({"resolution": resolution, "note": note} if resolution in {"rotated", "accepted_risk", "not_deployed"} else None)


class VaultImportedReferenceModal(ModalScreen[Optional[dict[str, str]]]):
    """Choose one imported Bitwarden reference for an explicit migration."""

    def __init__(self, references: list[dict[str, str]]) -> None:
        super().__init__()
        self._references = references

    def compose(self) -> ComposeResult:
        options = [
            Selection(f"Imported Bitwarden SSH key {index}", index - 1, initial_state=index == 1)
            for index, _reference in enumerate(self._references, 1)
        ]
        yield SafeHeader()
        yield Vertical(
            Static("[bold]Bind an imported Bitwarden SSH key[/bold]"),
            Static(
                "Select one imported key to connect to a matching team server. "
                "Personal servers stay manual: open the server and choose Use vault key. "
                "No server binding or Bitwarden reference will change until you confirm later steps."
            ),
            SelectionList(*options, id="vault_import_bind_list"),
            Horizontal(
                Button("Keep references", id="vault_import_bind_cancel"),
                Button("Choose server", id="vault_import_bind_continue"),
            ),
            id="vault_import_bind_reference_modal",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "vault_import_bind_continue":
            self.dismiss(None)
            return
        selected = list(self.query_one("#vault_import_bind_list", SelectionList).selected)
        if len(selected) != 1 or not isinstance(selected[0], int):
            self.dismiss(None)
            return
        self.dismiss(self._references[selected[0]] if 0 <= selected[0] < len(self._references) else None)


class VaultImportedTeamBindingModal(ModalScreen[Optional[dict[str, str]]]):
    """Collect an explicit team target for a matching imported reference."""

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield Vertical(
            Static("[bold]Connect imported key to team server[/bold]"),
            Static(
                "Enter the team slug and server ID that currently use the selected Bitwarden key. "
                "The service checks that exact legacy reference before creating a native binding."
            ),
            Input(placeholder="Team slug", id="vault_import_bind_team"),
            Input(placeholder="Shared server ID", id="vault_import_bind_server"),
            Input(placeholder="SSH login (optional)", id="vault_import_bind_login"),
            Horizontal(
                Button("Cancel", id="vault_import_bind_target_cancel"),
                Button("Review binding", id="vault_import_bind_target_continue"),
            ),
            id="vault_import_bind_target_modal",
        )

    def on_mount(self) -> None:
        self.query_one("#vault_import_bind_team", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "vault_import_bind_target_continue":
            self.dismiss(None)
            return
        team = self.query_one("#vault_import_bind_team", Input).value.strip()
        server_id = self.query_one("#vault_import_bind_server", Input).value.strip()
        login = self.query_one("#vault_import_bind_login", Input).value.strip()
        self.dismiss({"team": team, "server_id": server_id, "login": login} if team and server_id else None)


class VaultCreateModal(ModalScreen[Optional[Mapping[str, Any]]]):
    """Pick which vault to create: a personal one, or one for a team you run."""

    def __init__(self, options: list[Mapping[str, Any]]) -> None:
        super().__init__()
        self._options = list(options)

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield Vertical(
            Static("[bold]Create a vault[/bold]", id="vault_create_title"),
            Static(
                "Your Servonaut creates the vault key on this device and encrypts everything with it; "
                "the service only stores what it cannot read.",
                id="vault_create_text",
            ),
            Select(
                [(escape(str(option.get("label") or "")), index) for index, option in enumerate(self._options)],
                value=0, allow_blank=False, id="vault_create_target",
            ),
            Horizontal(Button("Cancel", id="vault_create_cancel"), Button("Create", id="vault_create_confirm")),
            id="vault_create_modal",
        )

    def on_mount(self) -> None:
        self.query_one("#vault_create_target", Select).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "vault_create_confirm":
            self.dismiss(None)
            return
        index = self.query_one("#vault_create_target", Select).value
        self.dismiss(self._options[index] if isinstance(index, int) and 0 <= index < len(self._options) else None)


class VaultScreen(Screen):
    """Full-screen vault metadata, device state, and exposure entry point."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("v", "reveal", "Reveal selected", show=True),
        Binding("e", "exposures", "Exposures", show=True),
        Binding("d", "devices", "Devices", show=True),
        Binding("g", "grants", "Process grants", show=True),
    ]

    _READY_ACTIONS = (
        "vault_confirm_identity", "vault_create", "vault_items", "vault_reveal", "vault_exposures", "vault_resolve_exposure",
        "vault_rotate_exposure", "vault_devices", "vault_approve", "vault_recovery_rotate",
        "vault_reset", "vault_import", "vault_roster", "vault_grants", "vault_rotate",
    )

    def __init__(self) -> None:
        super().__init__()
        self._setup_running = False
        self._vaults: list[dict[str, Any]] = []
        self._items: list[dict[str, Any]] = []
        self._devices: list[dict[str, Any]] = []
        self._exposures: list[dict[str, Any]] = []
        self._selected_vault_id: Optional[str] = None
        self._identity_state = "loading"
        self._status_raw = "Loading encrypted vault metadata…"
        self._table_mode = "vaults"
        self._roster: list[dict[str, Any]] = []
        self._rotation_hosts: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        with Horizontal(id="vault_layout"):
            yield Sidebar()
            with Vertical(id="vault_content"):
                yield Static("Vault", id="vault_title")
                yield Static("Loading encrypted vault metadata…", id="vault_status")
                yield DataTable(id="vault_table", cursor_type="row")
                with VerticalScroll(id="vault_action_scroll"):
                    with Horizontal(id="vault_actions"):
                        yield Button("Refresh", id="vault_refresh")
                        yield Button("Setup", id="vault_setup")
                        yield Button("Confirm identity", id="vault_confirm_identity")
                        yield Button("Create vault", id="vault_create")
                        yield Button("Items", id="vault_items")
                        yield Button("Reveal", id="vault_reveal")
                        yield Button("Exposures", id="vault_exposures")
                        yield Button("Resolve exposure", id="vault_resolve_exposure")
                        yield Button("Rotate exposed SSH key", id="vault_rotate_exposure")
                        yield Button("Devices", id="vault_devices")
                        yield Button("Add device", id="vault_add_device")
                        yield Button("Approve device", id="vault_approve")
                        yield Button("Recover", id="vault_recover")
                        yield Button("Rotate recovery key", id="vault_recovery_rotate")
                        yield Button("Reset identity", id="vault_reset")
                        yield Button("Import SSH", id="vault_import")
                        yield Button("Roster", id="vault_roster")
                        yield Button("Grants", id="vault_grants")
                        yield Button("Rotate vault key", id="vault_rotate")
        yield Footer()

    def on_mount(self) -> None:
        self._sync_compact_layout()
        table = self.query_one("#vault_table", DataTable)
        table.add_columns("Name", "Kind", "Items", "Open exposures", "Vault ID")
        self._set_identity_state("loading")
        service = self._service()
        if callable(getattr(service, "drain_device_pending_events", None)):
            self.run_worker(self._drain_pending_device_events(), group="vault-events", exclusive=True)
        self.run_worker(self._load(), group="vault", exclusive=True)

    def on_resize(self) -> None:
        """Use the compact action layout once the terminal cannot fit four labels."""
        self._sync_compact_layout()

    def _sync_compact_layout(self) -> None:
        self.set_class(self.size.width <= 110, "-narrow")
        self.set_class(self.size.height <= 32, "-short")

    def _service(self) -> Any:
        return getattr(self.app, "vault_command_service", None)

    def scrub_for_display(self, value: object) -> str:
        """Redact rendered server/user metadata while preserving local state."""
        text = str(value)
        redactor = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redactor is not None:
            return str(redactor.scrub_stream(text))
        return text

    def _status(self, message: str) -> None:
        self._status_raw = message
        self.query_one("#vault_status", Static).update(escape(self.scrub_for_display(message)))

    def refresh_after_demo_toggle(self) -> None:
        """Repaint cached metadata after demo mode changes without re-fetching."""
        render = getattr(self, f"_render_{self._table_mode}", None)
        if callable(render):
            render()
        self._status(self._status_raw)

    def _render_vaults(self) -> None:
        table = self.query_one("#vault_table", DataTable)
        table.clear(columns=True)
        table.add_columns("Name", "Kind", "Items", "Open exposures", "Vault ID")
        for row in self._vaults:
            counts = row.get("counts") if isinstance(row.get("counts"), Mapping) else {}
            table.add_row(
                escape(self.scrub_for_display(row.get("name") or "Unnamed vault")),
                escape(self.scrub_for_display(row.get("kind") or "")),
                str(counts.get("items", 0)), str(counts.get("open_exposures", 0)),
                escape(self.scrub_for_display(row.get("vault_id") or "")),
            )

    def _render_items(self) -> None:
        table = self.query_one("#vault_table", DataTable)
        table.clear(columns=True); table.add_columns("Type", "Revision", "Fingerprint", "Item ID")
        for row in self._items:
            table.add_row(escape(self.scrub_for_display(row.get("type") or "unsupported")), str(row.get("revision") or ""), escape(self.scrub_for_display(row.get("public_fingerprint") or "")), escape(self.scrub_for_display(row.get("item_id") or "")))

    def _render_exposures(self) -> None:
        table = self.query_one("#vault_table", DataTable)
        table.clear(columns=True); table.add_columns("Subject", "Reason", "Item ID", "Exposure ID")
        for row in self._exposures:
            table.add_row(escape(self.scrub_for_display(row.get("subject") or row.get("public_fingerprint") or "")), escape(self.scrub_for_display(row.get("reason") or "")), escape(self.scrub_for_display(row.get("item_id") or "")), escape(self.scrub_for_display(row.get("exposure_id") or "")))

    def _render_rotation(self) -> None:
        table = self.query_one("#vault_table", DataTable)
        table.clear(columns=True); table.add_columns("Server", "Status", "Detail")
        for host in self._rotation_hosts:
            table.add_row(escape(self.scrub_for_display(host.get("server_id") or host.get("server") or "")), escape(self.scrub_for_display(host.get("status") or "unknown")), escape(self.scrub_for_display(host.get("error") or "")))

    def _render_devices(self) -> None:
        table = self.query_one("#vault_table", DataTable)
        table.clear(columns=True); table.add_columns("Name", "Platform", "Status", "Device ID")
        for row in self._devices:
            table.add_row(escape(self.scrub_for_display(row.get("name") or "")), escape(self.scrub_for_display(row.get("platform") or "")), escape(self.scrub_for_display(row.get("status") or "")), escape(self.scrub_for_display(row.get("device_id") or "")))

    def _render_roster(self) -> None:
        table = self.query_one("#vault_table", DataTable)
        table.clear(columns=True); table.add_columns("Member", "Role", "Status", "Fingerprint")
        for member in self._roster:
            identity = member.get("identity") if isinstance(member.get("identity"), Mapping) else {}
            table.add_row(escape(self.scrub_for_display(member.get("display_name") or member.get("user_id") or "")), escape(self.scrub_for_display(member.get("role") or "")), escape(self.scrub_for_display(member.get("status") or "")), escape(self.scrub_for_display(identity.get("fingerprint") or "")))

    def _set_identity_state(self, state: str) -> None:
        """Make only the safe next identity action available for this state."""
        self._identity_state = state
        ready = state == "ready"
        for button_id in self._READY_ACTIONS:
            self.query_one(f"#{button_id}", Button).disabled = not ready
        self.query_one("#vault_setup", Button).disabled = state != "first_user"
        remote_identity = state == "remote_identity"
        self.query_one("#vault_recover", Button).disabled = not remote_identity
        self.query_one("#vault_add_device", Button).disabled = not remote_identity

    def _allows_identity_action(self, *states: str) -> bool:
        """Keep keyboard actions from bypassing the disabled-button state."""
        if self._identity_state in states:
            return True
        self.app.notify(
            "Complete the vault identity step shown above before using this action.",
            severity="warning",
            markup=False,
        )
        return False

    async def _identity_readiness(self, service: Any, status: Any) -> str:
        """Classify custody from a status read before any signed vault request."""
        if not isinstance(status, Mapping):
            return "unverified"
        remote = status.get("remote")
        if not isinstance(remote, Mapping):
            return "unverified"
        remote_identity = remote.get("identity")
        if remote_identity is not None and not isinstance(remote_identity, Mapping):
            return "unverified"
        local_identity = status.get("local_identity") or status.get("fingerprint")
        if isinstance(local_identity, str) and local_identity:
            return "ready"
        unlock = getattr(service, "unlock_existing_identity", None)
        if callable(unlock):
            try:
                if await _invoke(service, "unlock_existing_identity"):
                    return "ready"
            except Exception:
                # A persisted but locked, corrupt, or foreign identity must
                # never be mistaken for an empty first-user store.
                return "custody_unavailable"
        return "remote_identity" if isinstance(remote_identity, Mapping) else "first_user"

    async def _drain_pending_device_events(self) -> None:
        service = self._service()
        if service is None:
            return
        try:
            events = await _invoke(service, "drain_device_pending_events")
        except Exception:
            return
        for event in events or []:
            if isinstance(event, Mapping):
                await self._on_pending_device_event(event)

    async def _on_pending_device_event(self, device: Mapping[str, Any]) -> None:
        """Present only a REST-reread pending-device summary to the approver."""
        self._status("A new device is waiting for approval.")
        await show_pending_device(self.app, self._service(), device)

    async def _load(self) -> None:
        service = self._service()
        if service is None:
            self._status("Vault services are unavailable in this session.")
            return
        try:
            status = await _invoke(service, "status")
        except Exception as exc:
            self._set_identity_state("unverified")
            self._status(f"Could not check vault identity state ({vault_failure_reason(exc)}).")
            return
        readiness = await self._identity_readiness(service, status)
        if readiness == "first_user":
            self._set_identity_state(readiness)
            self._status("No vault identity exists yet. Choose Setup to create one and record its recovery key.")
            return
        if readiness == "remote_identity":
            self._set_identity_state(readiness)
            self._status("This account has a vault identity on another device. Choose Recover or Add device.")
            return
        if readiness == "custody_unavailable":
            self._set_identity_state(readiness)
            self._status("Existing local vault custody could not be unlocked. Setup and device enrollment are unavailable.")
            return
        if readiness != "ready":
            self._set_identity_state("unverified")
            self._status("Vault identity state could not be verified. Review account and local vault custody before continuing.")
            return
        try:
            vaults = await _invoke(service, "list_vaults")
        except Exception as exc:
            self._set_identity_state("unverified")
            self._status(f"Could not load vault metadata ({vault_failure_reason(exc)}).")
            return
        self._set_identity_state("ready")
        self._vaults = [dict(row) for row in vaults or []]
        fingerprint = getattr(status, "fingerprint", None)
        if fingerprint is None and isinstance(status, Mapping):
            fingerprint = status.get("fingerprint") or status.get("local_identity")
        line = f"Identity fingerprint: {fingerprint or 'not enrolled'}"
        if isinstance(status, Mapping):
            step = onboarding.next_step(
                status, self._vaults, can_create_personal=await self._can_create_personal(service)
            )
            if step.code != "ready":
                line += f" · {step.message}"
        self._status(line)
        self._table_mode = "vaults"
        self._render_vaults()

    @staticmethod
    async def _can_create_personal(service: Any) -> bool:
        try:
            return bool(await _invoke(service, "can_create_personal_vault"))
        except Exception:
            return False

    def _refuse_without_access(self, vault: Mapping[str, Any]) -> bool:
        """Explain a team vault this user holds no key for, instead of a server refusal."""
        if not onboarding.is_awaiting_access(vault):
            return False
        self._status(onboarding.AWAITING_ACCESS.message)
        return True

    def _selected_vault(self) -> Optional[dict[str, Any]]:
        table = self.query_one("#vault_table", DataTable)
        row = table.cursor_row
        if 0 <= row < len(self._vaults):
            return self._vaults[row]
        return None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        actions = {
            "vault_refresh": self.action_refresh,
            "vault_setup": self.action_setup,
            "vault_confirm_identity": self.action_confirm_identity,
            "vault_create": self.action_create,
            "vault_items": self.action_items,
            "vault_reveal": self.action_reveal,
            "vault_exposures": self.action_exposures,
            "vault_resolve_exposure": self.action_resolve_exposure,
            "vault_rotate_exposure": self.action_rotate_exposure,
            "vault_devices": self.action_devices,
            "vault_add_device": self.action_add_device,
            "vault_approve": self.action_approve,
            "vault_recover": self.action_recover,
            "vault_recovery_rotate": self.action_recovery_rotate,
            "vault_reset": self.action_reset,
            "vault_import": self.action_import,
            "vault_roster": self.action_roster,
            "vault_grants": self.action_grants,
            "vault_rotate": self.action_rotate,
        }
        handler = actions.get(event.button.id or "")
        if handler:
            handler()

    def action_refresh(self) -> None:
        self.run_worker(self._load(), group="vault", exclusive=True)

    def action_setup(self) -> None:
        if not self._allows_identity_action("first_user"):
            return
        # A second press would cancel the running setup while its recovery-key
        # dialog is open (vault workers are exclusive), stranding that dialog.
        if self._setup_running:
            return
        self._setup_running = True
        async def confirm(recovery_key: str) -> bool:
            return bool(await self.app.push_screen_wait(VaultRecoveryConfirmModal(recovery_key)))
        self.run_worker(self._setup(confirm), group="vault", exclusive=True)

    async def _setup(self, confirmation: Any) -> None:
        try:
            await self._run_setup(confirmation)
        finally:
            self._setup_running = False

    async def _run_setup(self, confirmation: Any) -> None:
        service = self._service()
        if service is None:
            return
        try:
            await _invoke(service, "setup", device_name=None, platform=None, recovery_confirmation=confirmation)
        except Exception as exc:
            self.app.notify(f"Vault setup failed ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        self._set_identity_state("ready")
        self.app.notify("Vault identity created.", markup=False)
        # Reload so the status line shows the next step (confirm, create a vault…).
        await self._load()

    def action_confirm_identity(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        self.run_worker(self._confirm_identity(), group="vault", exclusive=True)

    async def _confirm_identity(self) -> None:
        service = self._service()
        if service is None:
            return
        try:
            result = await _invoke(service, "confirm_identity")
        except Exception as exc:
            self.app.notify(f"Could not confirm the vault identity ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        confirmation = result.get("confirmation") if isinstance(result, Mapping) else None
        state = confirmation.get("state") if isinstance(confirmation, Mapping) else None
        if state == "email_sent":
            self._status(
                "We e-mailed you a new confirmation link. Open it, then choose Refresh. "
                "To confirm here instead, sign in again with two-factor and choose Confirm identity."
            )
            return
        self.app.notify("Your vault identity is confirmed.", markup=False)
        await self._load()

    def action_create(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        self.run_worker(self._create_vault(), group="vault", exclusive=True)

    async def _create_vault(self) -> None:
        service = self._service()
        if service is None:
            return
        try:
            options = await _invoke(service, "creatable_vaults", vaults=self._vaults)
        except Exception as exc:
            self.app.notify(f"Could not check which vaults you can create ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        if not options:
            self._status(
                "There is no vault to create: you already have a personal vault or your plan does not include one, "
                "and each team you own or administer already has a vault."
            )
            return
        choice = await self.app.push_screen_wait(VaultCreateModal(options))
        if not isinstance(choice, Mapping):
            return
        try:
            await _invoke(service, "create_vault", team=choice.get("team"), name=None, grant_policy="auto")
        except Exception as exc:
            self.app.notify(f"Could not create the vault ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        self.app.notify("Vault created.", markup=False)
        await self._load()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_items(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        selected = self._selected_vault()
        if selected is None:
            self.app.notify("Select a vault first.", severity="warning", markup=False)
            return
        if self._refuse_without_access(selected):
            return
        self._selected_vault_id = str(selected.get("vault_id") or "")
        self.run_worker(self._load_items(), group="vault", exclusive=True)

    async def _load_items(self) -> None:
        if not self._selected_vault_id:
            return
        service = self._service()
        if service is None:
            return
        try:
            response = await _invoke(service, "list_items", vault_id=self._selected_vault_id)
        except Exception as exc:
            self.app.notify(f"Could not load item metadata ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        rows = response.get("data", []) if isinstance(response, Mapping) else response
        self._items = [dict(row) for row in rows or []]
        self._table_mode = "items"
        self._render_items()
        self._status("Item metadata loaded. Press V to reveal a selected item.")

    def _selected_item(self) -> Optional[dict[str, Any]]:
        table = self.query_one("#vault_table", DataTable)
        row = table.cursor_row
        if 0 <= row < len(self._items):
            return self._items[row]
        return None

    def action_reveal(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        item = self._selected_item()
        if item is None or not self._selected_vault_id:
            self.app.notify("Load a vault's items and select one first.", severity="warning", markup=False)
            return
        item_id = str(item.get("item_id") or "")
        if not item_id:
            return

        async def reveal_after_confirmation(confirmed: bool) -> None:
            if not confirmed:
                return
            service = self._service()
            if service is None:
                return
            try:
                revealed = await _invoke(service, "show_item", vault_id=self._selected_vault_id, item_id=item_id, reveal=True)
            except Exception as exc:
                self.app.notify(f"Could not reveal item ({vault_failure_reason(exc)}).", severity="error", markup=False)
                return
            if not isinstance(revealed, Mapping):
                self.app.notify("The selected item cannot be revealed.", severity="warning", markup=False)
                return
            self.app.push_screen(VaultRevealModal(revealed))

        def callback(confirmed: bool) -> None:
            self.run_worker(reveal_after_confirmation(confirmed), group="vault", exclusive=True)

        self.app.push_screen(
            ConfirmActionScreen(
                "Reveal vault item",
                "The value will be shown in this terminal session.",
                ["The item read is recorded in the vault audit trail."],
                "REVEAL",
                "Reveal",
                severity="warning",
            ),
            callback,
        )

    def action_exposures(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        if not self._selected_vault_id:
            self.app.notify("Select a vault first.", severity="warning", markup=False)
            return
        self.run_worker(self._load_exposures(), group="vault", exclusive=True)

    async def _load_exposures(self) -> None:
        service = self._service()
        if service is None or not self._selected_vault_id:
            return
        try:
            exposures = await _invoke(service, "list_exposures", vault_id=self._selected_vault_id)
        except Exception as exc:
            self.app.notify(f"Could not load exposures ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        rows = exposures.get("data", exposures) if isinstance(exposures, Mapping) else exposures or []
        self._exposures = [dict(row) for row in rows if isinstance(row, Mapping)]
        self._table_mode = "exposures"
        self._render_exposures()
        self._status(f"{len(self._exposures)} open exposure{'s' if len(self._exposures) != 1 else ''} for this vault.")

    def _selected_exposure(self) -> Optional[dict[str, Any]]:
        row = self.query_one("#vault_table", DataTable).cursor_row
        return self._exposures[row] if 0 <= row < len(self._exposures) else None

    def action_resolve_exposure(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        exposure = self._selected_exposure()
        if exposure is None or not self._selected_vault_id:
            self.app.notify("Load exposures and select one first.", severity="warning", markup=False)
            return
        def callback(values: Optional[dict[str, str]]) -> None:
            if values:
                self.run_worker(self._resolve_exposure(exposure, values), group="vault", exclusive=True)
        self.app.push_screen(VaultExposureActionModal(rotation=False), callback)

    async def _resolve_exposure(self, exposure: Mapping[str, Any], values: Mapping[str, str]) -> None:
        service = self._service()
        if service is None or not self._selected_vault_id:
            return
        try:
            result = await _invoke(service, "resolve_exposure", vault_id=self._selected_vault_id, exposure_id=str(exposure.get("exposure_id") or ""), resolution=values["resolution"], note=values.get("note"))
        except Exception as exc:
            self.app.notify(f"Exposure resolution failed ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        self._status(f"Exposure resolved: {escape(str(result))}")

    def action_rotate_exposure(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        exposure = self._selected_exposure()
        if exposure is None or not self._selected_vault_id or not exposure.get("item_id"):
            self.app.notify("Select an SSH-key exposure first.", severity="warning", markup=False)
            return
        def callback(values: Optional[dict[str, str]]) -> None:
            if not values:
                return

            def confirmed(accepted: bool) -> None:
                if accepted:
                    self.run_worker(self._rotate_exposure(exposure, values), group="vault", exclusive=True)

            self.app.push_screen(
                ConfirmActionScreen(
                    "Rotate exposed SSH key",
                    "A replacement key will be installed and proven on each selected host before the old key is removed.",
                    ["A host failure leaves the exposure open.", "Review the per-host result before resolving the exposure."],
                    "ROTATE",
                    "Rotate key",
                    severity="warning",
                ),
                confirmed,
            )
        self.app.push_screen(VaultExposureActionModal(rotation=True), callback)

    async def _rotate_exposure(self, exposure: Mapping[str, Any], values: Mapping[str, str]) -> None:
        service = self._service()
        if service is None or not self._selected_vault_id:
            return
        servers = [server.strip() for server in values["servers"].split(",") if server.strip()]
        try:
            result = await _invoke(service, "rotate_ssh_key", vault_id=self._selected_vault_id, item_id=str(exposure["item_id"]), team=values["team"], servers=servers)
        except Exception as exc:
            self.app.notify(f"SSH-key rotation failed ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        hosts = result.get("hosts", []) if isinstance(result, Mapping) else []
        self._rotation_hosts = [dict(host) for host in hosts if isinstance(host, Mapping)]
        self._table_mode = "rotation"
        self._render_rotation()
        rotated = result.get("rotated") if isinstance(result, Mapping) else False
        if rotated:
            self._status("SSH key rotation completed on all selected hosts.")
            return
        message = (
            "SSH key rotation did not finish. The exposed key may still log in to the hosts "
            "not marked old_key_removed: treat the exposure as open even if it shows as "
            "resolved, remove the old key there, then rotate again."
        )
        self._status(message)
        self.app.notify(message, severity="error", markup=False)

    def action_devices(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        self.run_worker(self._load_devices(), group="vault", exclusive=True)

    def action_add_device(self) -> None:
        if not self._allows_identity_action("remote_identity"):
            return
        self.run_worker(self._add_device(), group="vault", exclusive=True)

    async def _add_device(self) -> None:
        service = self._service()
        if service is None:
            return
        try:
            pending = await _invoke(service, "add_device", device_name=None, platform=None)
            identity = pending.get("identity") if isinstance(pending, Mapping) else None
            expires_at = pending.get("expires_at") if isinstance(pending, Mapping) else None
            if not identity or not expires_at:
                raise RuntimeError("missing pending-device approval state")
            self._status("Waiting for approval on an active device. Compare the safety number when it appears.")
            attempt = 0
            while True:
                approval = await _invoke(service, "poll_pending_device", identity=identity, expires_at=expires_at)
                state = approval.get("state") if isinstance(approval, Mapping) else None
                if state == "revealed":
                    self._status(f"Safety number: {escape(str(approval.get('safety_number') or ''))}")
                if state == "approved":
                    approved_payload = approval.get("approval") if isinstance(approval, Mapping) else None
                    if not isinstance(approved_payload, Mapping):
                        raise RuntimeError("pending-device approval payload is malformed")
                    result = await _invoke(
                        service,
                        "finish_pending_device",
                        approval=approved_payload,
                        identity=identity,
                    )
                    self._status(f"Device approved: {escape(str(result))}")
                    return
                await asyncio.sleep(_approval_poll_delay(service, attempt))
                attempt += 1
        except Exception as exc:
            self.app.notify(f"Device registration failed ({vault_failure_reason(exc)}).", severity="error", markup=False)

    async def _load_devices(self) -> None:
        service = self._service()
        if service is None:
            return
        try:
            devices = await _invoke(service, "list_devices")
        except Exception as exc:
            self.app.notify(f"Could not load devices ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        rows = list(devices or [])
        self._devices = [dict(row) for row in rows if isinstance(row, Mapping)]
        self._table_mode = "devices"
        self._render_devices()
        self._status("Device list loaded. Approve a pending device from `servonaut vault devices approve` after comparing its safety number.")

    def action_approve(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        table = self.query_one("#vault_table", DataTable)
        row = table.cursor_row
        if not (0 <= row < len(self._devices)):
            self.app.notify("Load devices and select a pending device first.", severity="warning", markup=False)
            return
        device_id = str(self._devices[row].get("device_id") or "")
        if not device_id:
            return

        async def confirm(sas: str) -> bool:
            return bool(await self.app.push_screen_wait(VaultSasConfirmModal(sas)))

        self.run_worker(self._approve_device(device_id, confirm), group="vault", exclusive=True)

    async def _approve_device(self, device_id: str, confirmation: Any) -> None:
        service = self._service()
        if service is None:
            return
        try:
            result = await _invoke(service, "approve_device", device_id=device_id, confirmation=confirmation)
        except Exception as exc:
            self.app.notify(f"Device approval failed ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        self._status(f"Device approval completed: {escape(str(result))}")

    def action_recover(self) -> None:
        if not self._allows_identity_action("remote_identity"):
            return
        def callback(recovery_key: Optional[str]) -> None:
            if recovery_key:
                self.run_worker(self._recover(recovery_key), group="vault", exclusive=True)

        self.app.push_screen(VaultSecretPromptModal("Recover vault identity", "Enter the offline recovery key."), callback)

    async def _recover(self, recovery_key: str) -> None:
        service = self._service()
        if service is None:
            return
        try:
            result = await _invoke(service, "recover", recovery_key=recovery_key, device_name=None, platform=None)
        except Exception as exc:
            self.app.notify(f"Vault recovery failed ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        self._status(f"Vault recovery completed: {escape(str(result))}")

    def action_recovery_rotate(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        async def confirm(recovery_key: str) -> bool:
            return bool(await self.app.push_screen_wait(VaultRecoveryConfirmModal(recovery_key)))
        self.run_worker(self._rotate_recovery_key(confirm), group="vault", exclusive=True)

    async def _rotate_recovery_key(self, confirmation: Any) -> None:
        service = self._service()
        if service is None:
            return
        try:
            result = await _invoke(service, "rotate_recovery_key", recovery_confirmation=confirmation)
        except Exception as exc:
            self.app.notify(f"Recovery-key rotation failed ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        self._status(f"Recovery key replaced: {escape(str(result))}")

    def action_reset(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        async def confirm_recovery(recovery_key: str) -> bool:
            return bool(await self.app.push_screen_wait(VaultRecoveryConfirmModal(recovery_key)))
        def confirmed(accepted: bool) -> None:
            if accepted:
                self.run_worker(self._reset_identity(confirm_recovery), group="vault", exclusive=True)
        self.app.push_screen(ConfirmActionScreen("Reset vault identity", "This starts a replacement identity request.", ["Existing team grants require approval again.", "Personal items may be unreadable without the prior recovery key."], "RESET", "Reset", severity="danger"), confirmed)

    async def _reset_identity(self, confirmation: Any) -> None:
        service = self._service()
        if service is None:
            return
        try:
            result = await _invoke(service, "reset_identity", reason="rotate", recovery_confirmation=confirmation)
        except Exception as exc:
            self.app.notify(f"Identity reset failed ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        self._status("Identity reset requested. Confirm it through the e-mail, then this screen will verify and save the replacement identity.")
        attempt = 0
        try:
            while True:
                status = await _invoke(service, "poll_reset_identity")
                if isinstance(status, Mapping) and status.get("state") == "confirmed":
                    self._status(
                        f"Identity reset confirmed for device {escape(str(status.get('device_id') or ''))}."
                    )
                    return
                await asyncio.sleep(_approval_poll_delay(service, attempt))
                attempt += 1
        except Exception as exc:
            self.app.notify(f"Identity reset confirmation failed ({vault_failure_reason(exc)}).", severity="error", markup=False)

    def action_import(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        selected = self._selected_vault()
        if selected is None:
            self.app.notify("Select a vault first.", severity="warning", markup=False)
            return
        if self._refuse_without_access(selected):
            return
        vault_id = str(selected.get("vault_id") or "")
        service = self._service()
        if service is None or not vault_id:
            self.app.notify("Vault services are unavailable in this session.", severity="warning", markup=False)
            return
        from servonaut.screens.vault_import_modal import VaultImportModal

        def imported(summary: Optional[Mapping[str, Any]]) -> None:
            if summary is None:
                return
            self._handle_import_result(vault_id, summary)

        self.app.push_screen(
            VaultImportModal(
                service,
                vault_id,
                session_service=getattr(self.app, "bw_session_service", None),
            ),
            imported,
        )

    def _handle_import_result(self, vault_id: str, summary: Mapping[str, Any]) -> None:
        """Refresh signed vault metadata after import before offering a migration."""
        imported = summary.get("imported")
        failed = summary.get("failed")
        imported_count = imported if isinstance(imported, int) and not isinstance(imported, bool) else 0
        failed_count = failed if isinstance(failed, int) and not isinstance(failed, bool) else 0
        references = summary.get("references")
        safe_references = references if isinstance(references, list) else []
        self._selected_vault_id = vault_id
        self._status(f"SSH key import complete: {imported_count} imported, {failed_count} failed.")
        self.run_worker(
            self._refresh_imported_vault_metadata(
                vault_id, imported_count, failed_count, safe_references,
            ),
            group="vault",
            exclusive=True,
        )

    async def _refresh_imported_vault_metadata(
        self,
        vault_id: str,
        imported_count: int,
        failed_count: int,
        references: list[Any],
    ) -> None:
        """Re-read counts and retain the imported vault's selected table row."""
        message = f"SSH key import complete: {imported_count} imported, {failed_count} failed."
        service = self._service()
        if service is None:
            return
        try:
            vaults = await _invoke(service, "list_vaults")
        except Exception as exc:
            self._status(f"{message} Vault metadata could not be refreshed ({vault_failure_reason(exc)}).")
        else:
            self._vaults = [dict(row) for row in vaults or []]
            self._table_mode = "vaults"
            self._render_vaults()
            for row, vault in enumerate(self._vaults):
                if vault.get("vault_id") == vault_id:
                    self.query_one("#vault_table", DataTable).move_cursor(row=row)
                    break
            self._status(message)
        if any(
            isinstance(reference, Mapping) and reference.get("source") == "bitwarden"
            for reference in references
        ):
            await self._offer_imported_bitwarden_binding(vault_id, references)

    async def _offer_imported_bitwarden_binding(self, vault_id: str, references: list[Any]) -> None:
        """Offer a user-selected, proof-backed team migration after import.

        Local SSH imports have no remote Bitwarden reference to migrate.  For
        imported Bitwarden keys this surface never guesses a target from the
        inventory: the user supplies the shared-server route, and the facade
        verifies the old reference, native binding, and SSH login before a
        separate explicit request can clear the legacy pointer.
        """
        normalized: list[dict[str, str]] = []
        for reference in references:
            if not isinstance(reference, Mapping) or reference.get("source") != "bitwarden":
                continue
            item_id = reference.get("vault_item_id")
            source_ref = reference.get("source_ref")
            if isinstance(item_id, str) and item_id and isinstance(source_ref, str) and source_ref:
                normalized.append({"vault_item_id": item_id, "source_ref": source_ref})
        if not normalized:
            return
        selected = await self.app.push_screen_wait(VaultImportedReferenceModal(normalized))
        if not selected:
            return
        target = await self.app.push_screen_wait(VaultImportedTeamBindingModal())
        if not target:
            return
        team = target["team"]
        server_id = target["server_id"]
        approved = await self.app.push_screen_wait(
            ConfirmActionScreen(
                "Bind imported vault key",
                "The selected team server must still point at this imported Bitwarden key.",
                [
                    "Create a signed native-vault binding with the server's verified host keys.",
                    "Prove a pinned native SSH connection before changing any legacy reference.",
                    "Keep the Bitwarden item and its server reference for now.",
                ],
                "BIND",
                "Bind and verify",
                severity="warning",
            )
        )
        if not approved:
            return
        service = self._service()
        if service is None:
            return
        try:
            result = await _invoke(
                service,
                "bind_imported_bitwarden_ref",
                vault_id=vault_id,
                item_id=selected["vault_item_id"],
                team=team,
                server_id=server_id,
                source_ref=selected["source_ref"],
                login=target["login"] or None,
                clear_legacy=False,
            )
        except Exception as exc:
            self.app.notify(
                f"Native binding was not created; the Bitwarden reference remains ({vault_failure_reason(exc)}).",
                severity="error",
                markup=False,
            )
            return
        if not isinstance(result, Mapping) or result.get("verified") is not True:
            self.app.notify(
                "Native SSH proof did not succeed; the Bitwarden reference remains available.",
                severity="error",
                markup=False,
            )
            return
        clear = await self.app.push_screen_wait(
            ConfirmActionScreen(
                "Clear legacy Bitwarden server reference",
                "The native binding completed a pinned SSH proof. The Bitwarden item itself will not be deleted.",
                [
                    "Remove only this team's legacy server reference.",
                    "Keep the imported encrypted vault key and the Bitwarden item.",
                ],
                "CLEAR",
                "Clear legacy reference",
                severity="warning",
            )
        )
        if not clear:
            self._status("Native SSH binding verified. The legacy Bitwarden server reference remains by choice.")
            return
        try:
            cleared = await _invoke(
                service,
                "bind_imported_bitwarden_ref",
                vault_id=vault_id,
                item_id=selected["vault_item_id"],
                team=team,
                server_id=server_id,
                source_ref=selected["source_ref"],
                login=target["login"] or None,
                clear_legacy=True,
            )
        except Exception as exc:
            self.app.notify(
                f"Legacy reference was retained ({vault_failure_reason(exc)}).",
                severity="error",
                markup=False,
            )
            return
        if isinstance(cleared, Mapping) and cleared.get("legacy_cleared") is True:
            self._status("Native SSH binding verified and the legacy Bitwarden server reference was cleared.")
        else:
            self.app.notify(
                "Legacy Bitwarden reference was retained; review the server before trying again.",
                severity="warning",
                markup=False,
            )

    def action_roster(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        selected = self._selected_vault()
        if selected is None:
            self.app.notify("Select a vault first.", severity="warning", markup=False)
            return
        self.run_worker(self._load_roster(str(selected.get("vault_id") or "")), group="vault", exclusive=True)

    async def _load_roster(self, vault_id: str) -> None:
        service = self._service()
        if service is None or not vault_id:
            return
        try:
            vault = await _invoke(service, "get_vault", vault_id=vault_id)
        except Exception as exc:
            self.app.notify(f"Could not load vault roster ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        roster = vault.get("roster", []) if isinstance(vault, Mapping) else []
        self._roster = [dict(member) for member in roster if isinstance(member, Mapping)]
        self._table_mode = "roster"
        self._render_roster()
        self._status("Roster loaded. Compare safety numbers before approving a changed identity.")

    def action_grants(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        selected = self._selected_vault()
        if selected is None:
            self.app.notify("Select a vault first.", severity="warning", markup=False)
            return
        self.run_worker(self._process_grants(str(selected.get("vault_id") or "")), group="vault", exclusive=True)

    async def _process_grants(self, vault_id: str) -> None:
        service = self._service()
        if service is None:
            return
        try:
            result = await _invoke(service, "process_grants", vault_id=vault_id, interactive=True)
        except Exception as exc:
            self.app.notify(f"Could not process grants ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        self._status(f"Grant processing finished: {escape(str(result))}")

    def action_rotate(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        selected = self._selected_vault()
        if selected is None:
            self.app.notify("Select a vault first.", severity="warning", markup=False)
            return
        vault_id = str(selected.get("vault_id") or "")

        def callback(confirmed: bool) -> None:
            if confirmed:
                self.run_worker(self._rotate(vault_id), group="vault", exclusive=True)

        self.app.push_screen(
            ConfirmActionScreen(
                "Rotate vault key",
                "A new vault key version will replace every current grant.",
                ["Pending members may remain ungranted until verified.", "Open exposures remain until their deployed keys are changed."],
                "ROTATE",
                "Rotate",
                severity="warning",
            ),
            callback,
        )

    async def _rotate(self, vault_id: str) -> None:
        service = self._service()
        if service is None:
            return
        try:
            result = await _invoke(service, "rotate", vault_id=vault_id)
        except Exception as exc:
            self.app.notify(f"Vault rotation failed ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        self._status(f"Vault rotation finished: {escape(str(result))}")
