"""Native encrypted-vault TUI surface.

This screen deliberately renders only metadata until a user confirms a reveal.
The application injects ``vault_command_service`` during paid-service setup;
the screen never constructs cryptographic or HTTP services itself.
"""
from __future__ import annotations

import asyncio
import contextlib
import math
import secrets
from pathlib import Path
from collections.abc import AsyncIterator, Callable, Mapping
from typing import Any, Optional

from rich.markup import escape
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.message import Message
from textual.screen import ModalScreen, Screen
from textual.widget import Widget
from textual.widgets import Button, DataTable, Footer, Input, Select, SelectionList, Static
from textual.widgets.selection_list import Selection
from textual.worker import Worker

from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.services.vault import onboarding
from servonaut.services.vault.errors import vault_failure_reason
from servonaut.widgets.busy_indicator import BusyIndicator
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


def scrub_for_demo(app: Any, value: object) -> str:
    """Redact rendered server/user metadata in demo mode; values stay real."""
    text = str(value)
    redactor = getattr(app, "redaction_service", None)
    if getattr(app, "demo_mode", False) and redactor is not None:
        return str(redactor.scrub_stream(text))
    return text


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


_NO_SHARED_SERVERS = "No shared servers in this team: share one from Team Management."


class VaultSharedServerPicker(Vertical):
    """A team picker and that team's shared servers, loaded from the vault service.

    With ``multiple`` the servers are a checklist; otherwise one server is
    chosen. A list with a single entry is chosen for the user. Labels are shown
    as plain text, never as markup. Posts :class:`VaultSharedServerPicker.Changed`
    whenever the choice or the loaded lists change.
    """

    DEFAULT_CSS = """
    VaultSharedServerPicker {
        height: auto;
    }
    VaultSharedServerPicker SelectionList {
        height: auto;
        max-height: 8;
    }
    """

    class Changed(Message):
        """The chosen team or servers changed."""

        def __init__(self, picker: "VaultSharedServerPicker") -> None:
            super().__init__()
            self.picker = picker

        @property
        def control(self) -> "VaultSharedServerPicker":
            return self.picker

    def __init__(self, service: Any, *, team_id: str, server_id: str, message_id: str, multiple: bool) -> None:
        super().__init__()
        self._service = service
        self._team_id = team_id
        self._server_id = server_id
        self._message_id = message_id
        self._multiple = multiple
        # The team whose servers are listed: a choice only counts for that team,
        # even before this picker has handled a newer team change.
        self._servers_team: Optional[str] = None
        # The team whose servers were last asked for. A redraw re-posts
        # Select.Changed for the same team; this keeps it from reloading.
        self._servers_requested: Optional[str] = None
        # Unredacted labels and message, so a demo-mode toggle can redraw them.
        self._team_choices: list[tuple[str, str]] = []
        self._server_choices: list[tuple[str, str]] = []
        self._message: Optional[str] = None
        # Counts server loads; only the newest one may end the loading indicator.
        self._servers_load = 0

    def compose(self) -> ComposeResult:
        yield Select([], prompt="Loading teams…", disabled=True, id=self._team_id)
        if self._multiple:
            servers = SelectionList[str](id=self._server_id, disabled=True)
            servers.display = False
            yield servers
        else:
            yield Select([], prompt="Choose a team first", disabled=True, id=self._server_id)
        yield BusyIndicator()
        yield Static("", markup=False, id=self._message_id)

    def on_mount(self) -> None:
        self._say(None)
        self._loading("Loading your teams…")
        self.run_worker(self._load_teams(), group="vault-picker-teams", exclusive=True)

    def _loading(self, message: Optional[str]) -> None:
        """Show what the picker is waiting for; ``None`` when it has its answer."""
        try:
            busy = self.query_one(BusyIndicator)
        except NoMatches:
            return  # the dialog is closing
        if message:
            busy.start(message)
        else:
            busy.stop()

    @property
    def team(self) -> Optional[str]:
        value = self._team_select().value
        return value if isinstance(value, str) else None

    @property
    def server_ids(self) -> list[str]:
        if self._servers_team is None or self._servers_team != self.team:
            return []
        servers = self._servers()
        if isinstance(servers, SelectionList):
            return [value for value in servers.selected if isinstance(value, str)]
        return [servers.value] if isinstance(servers.value, str) else []

    def _team_select(self) -> Select[str]:
        return self.query_one(f"#{self._team_id}", Select)

    def _servers(self) -> Select[str] | SelectionList[str]:
        return self.query_one(f"#{self._server_id}")  # type: ignore[return-value]

    def refresh_after_demo_toggle(self) -> None:
        """Redraw names and the message under the current demo mode, keeping the choices."""
        if self._team_choices:
            self._relabel(self._team_select(), self._team_choices)
        servers = self._servers()
        if isinstance(servers, SelectionList):
            for index, (label, _value) in enumerate(self._server_choices):
                servers.replace_option_prompt_at_index(index, self._label(label))
        elif self._server_choices:
            self._relabel(servers, self._server_choices)
        self._say(self._message)

    def _relabel(self, select: Select[str], choices: list[tuple[str, str]]) -> None:
        kept = select.value
        select.set_options(self._labelled(choices))
        if any(value == kept for _label, value in choices):
            select.value = kept

    def _say(self, message: Optional[str]) -> None:
        self._message = message
        note = self.query_one(f"#{self._message_id}", Static)
        note.update(scrub_for_demo(self.app, message or ""))
        note.display = bool(message)

    def _label(self, label: str) -> Text:
        return Text(scrub_for_demo(self.app, label))

    def _labelled(self, choices: list[tuple[str, str]]) -> list[tuple[Text, str]]:
        return [(self._label(label), value) for label, value in choices]

    @staticmethod
    def _choices(rows: Any, key: str) -> list[tuple[str, str]]:
        """Unredacted ``(label, value)`` pairs, without blank or repeated values."""
        choices: list[tuple[str, str]] = []
        seen: set[str] = set()
        for row in rows or []:
            value = row.get(key) if isinstance(row, Mapping) else None
            if not isinstance(value, str) or not value or value in seen:
                continue
            seen.add(value)
            choices.append((str(row.get("label") or value), value))
        return choices

    async def _load_teams(self) -> None:
        try:
            await self._load_teams_now()
        finally:
            self._loading(None)

    async def _load_teams_now(self) -> None:
        select = self._team_select()
        if self._service is None:
            select.prompt = "No teams"
            self._say("Vault services are unavailable in this session.")
            return
        try:
            choices = self._choices(await _invoke(self._service, "team_choices"), "slug")
        except Exception as exc:
            select.prompt = "Teams unavailable"
            self._say(f"Could not load your teams ({vault_failure_reason(exc)}).")
            return
        if not choices:
            select.prompt = "No teams"
            self._say("No teams yet: create or join one from Team Management.")
            return
        self._team_choices = choices
        select.prompt = "Choose a team"
        select.set_options(self._labelled(choices))
        select.disabled = False
        self._say(None)
        if self.screen.focused is None:
            select.focus()
        if len(choices) == 1:
            select.value = choices[0][1]

    @on(Select.Changed)
    def _choice_changed(self, event: Select.Changed) -> None:
        event.stop()
        if event.select.id == self._team_id and self.team != self._servers_requested:
            self._reload_servers(self.team)
        self.post_message(self.Changed(self))

    @on(SelectionList.SelectedChanged)
    def _servers_toggled(self, event: SelectionList.SelectedChanged) -> None:
        event.stop()
        self.post_message(self.Changed(self))

    def _reload_servers(self, team: Optional[str]) -> None:
        self._servers_requested = team
        self._clear_servers("Loading servers…" if team else "Choose a team first")
        if team is None:
            self._say(None)
            self._loading(None)
            return
        self._say(None)
        self._loading("Loading this team's shared servers…")
        self._servers_load += 1
        self.run_worker(self._load_servers(team, self._servers_load), group="vault-picker-servers", exclusive=True)

    def _clear_servers(self, prompt: str) -> None:
        self._servers_team = None
        self._server_choices = []
        servers = self._servers()
        if isinstance(servers, SelectionList):
            servers.clear_options()
            servers.display = False
        else:
            servers.prompt = prompt
            servers.set_options([])
        servers.disabled = True

    async def _load_servers(self, team: str, load: int) -> None:
        try:
            await self._load_servers_now(team)
        finally:
            # A newer load may still be running; it ends its own indicator.
            if load == self._servers_load:
                self._loading(None)

    async def _load_servers_now(self, team: str) -> None:
        try:
            choices = self._choices(await _invoke(self._service, "shared_server_choices", team=team), "server_id")
        except Exception as exc:
            if self.team == team:
                self._clear_servers("Servers unavailable")
                self._say(f"Could not load this team's servers ({vault_failure_reason(exc)}).")
            return
        if self.team != team:  # the user chose another team meanwhile
            return
        if not choices:
            self._clear_servers("No shared servers")
            self._say(_NO_SHARED_SERVERS)
            return
        self._say(None)
        self._show_servers(team, choices)
        self.post_message(self.Changed(self))

    def _show_servers(self, team: str, choices: list[tuple[str, str]]) -> None:
        self._servers_team = team
        self._server_choices = choices
        servers = self._servers()
        only_one = len(choices) == 1
        if isinstance(servers, SelectionList):
            servers.add_options([Selection(label, value, only_one) for label, value in self._labelled(choices)])
            servers.display = True
        else:
            servers.prompt = "Choose a server"
            servers.set_options(self._labelled(choices))
            if only_one:
                servers.value = choices[0][1]
        servers.disabled = False
        if self.screen.focused in (None, self._team_select()):
            servers.focus()


_EXPOSURE_RESOLUTIONS: tuple[tuple[str, str], ...] = (
    ("Rotated: the key has been replaced", "rotated"),
    ("Accepted risk: keep using this key", "accepted_risk"),
    ("Not deployed: the key is not on any server", "not_deployed"),
)


class VaultExposureActionModal(ModalScreen[Optional[dict[str, str]]]):
    """Collect an explicit exposure resolution or per-host rotation request.

    Dismisses with ``{"resolution", "note"}``, or for a rotation with
    ``{"team", "servers"}`` where ``servers`` is the chosen server IDs joined
    by commas; ``None`` when cancelled.
    """

    AUTO_FOCUS = ""  # the pickers focus themselves once their options load
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]
    DEFAULT_CSS = """
    VaultExposureActionModal #vault_exposure_modal > Horizontal {
        height: auto;
    }
    VaultExposureActionModal #vault_exposure_message {
        color: $text-muted;
    }
    """

    def __init__(self, *, rotation: bool, service: Any = None) -> None:
        super().__init__()
        self._rotation = rotation
        self._service = service

    def compose(self) -> ComposeResult:
        fields: list[Any] = [Static("[bold]Rotate exposed SSH key[/bold]" if self._rotation else "[bold]Resolve exposure[/bold]")]
        if self._rotation:
            fields.append(VaultSharedServerPicker(
                self._service, team_id="vault_exposure_team", server_id="vault_exposure_servers",
                message_id="vault_exposure_message", multiple=True,
            ))
        else:
            fields.extend((
                Select(_EXPOSURE_RESOLUTIONS, prompt="Choose how it was resolved", id="vault_exposure_resolution"),
                Input(placeholder="Note (optional)", id="vault_exposure_note"),
            ))
        fields.append(Horizontal(Button("Cancel", id="vault_exposure_cancel"), Button("Continue", id="vault_exposure_confirm", disabled=True)))
        yield SafeHeader()
        yield Vertical(*fields, id="vault_exposure_modal")

    def on_mount(self) -> None:
        if not self._rotation:
            self.query_one("#vault_exposure_resolution", Select).focus()

    def _values(self) -> Optional[dict[str, str]]:
        if self._rotation:
            picker = self.query_one(VaultSharedServerPicker)
            team, servers = picker.team, picker.server_ids
            return {"team": team, "servers": ",".join(servers)} if team and servers else None
        resolution = self.query_one("#vault_exposure_resolution", Select).value
        note = self.query_one("#vault_exposure_note", Input).value.strip()
        valid = isinstance(resolution, str) and resolution in {value for _label, value in _EXPOSURE_RESOLUTIONS}
        return {"resolution": resolution, "note": note} if valid else None

    @on(Select.Changed)
    @on(VaultSharedServerPicker.Changed)
    def _sync_confirm(self) -> None:
        self.query_one("#vault_exposure_confirm", Button).disabled = self._values() is None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "vault_exposure_confirm":
            self.dismiss(None)
        elif (values := self._values()) is not None:
            self.dismiss(values)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def refresh_after_demo_toggle(self) -> None:
        """Redraw team and server names under the current demo mode."""
        for picker in self.query(VaultSharedServerPicker):
            picker.refresh_after_demo_toggle()


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
    """Collect an explicit team target for a matching imported reference.

    Dismisses with ``{"team", "server_id", "login"}``, or ``None`` when cancelled.
    """

    AUTO_FOCUS = ""  # the pickers focus themselves once their options load
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]
    DEFAULT_CSS = """
    VaultImportedTeamBindingModal #vault_import_bind_message {
        color: $text-muted;
    }
    """

    def __init__(self, service: Any) -> None:
        super().__init__()
        self._service = service

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield Vertical(
            Static("[bold]Connect imported key to team server[/bold]"),
            Static("Choose the team server that still uses this Bitwarden key."),
            VaultSharedServerPicker(
                self._service, team_id="vault_import_bind_team", server_id="vault_import_bind_server",
                message_id="vault_import_bind_message", multiple=False,
            ),
            Input(placeholder="SSH login (optional)", id="vault_import_bind_login"),
            Horizontal(
                Button("Cancel", id="vault_import_bind_target_cancel"),
                Button("Review binding", id="vault_import_bind_target_continue", disabled=True),
            ),
            id="vault_import_bind_target_modal",
        )

    def _values(self) -> Optional[dict[str, str]]:
        picker = self.query_one(VaultSharedServerPicker)
        team, servers = picker.team, picker.server_ids
        login = self.query_one("#vault_import_bind_login", Input).value.strip()
        return {"team": team, "server_id": servers[0], "login": login} if team and servers else None

    @on(VaultSharedServerPicker.Changed)
    def _sync_continue(self) -> None:
        self.query_one("#vault_import_bind_target_continue", Button).disabled = self._values() is None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "vault_import_bind_target_continue":
            self.dismiss(None)
        elif (values := self._values()) is not None:
            self.dismiss(values)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def refresh_after_demo_toggle(self) -> None:
        """Redraw team and server names under the current demo mode."""
        self.query_one(VaultSharedServerPicker).refresh_after_demo_toggle()


def _rotation_summary(exposures: Any) -> str:
    """Status text after a rotation finished on every host."""
    done = "SSH key rotation completed on all selected hosts."
    if not isinstance(exposures, Mapping):
        return done
    failed = [entry for entry in exposures.get("failed") or [] if isinstance(entry, Mapping)]
    if failed:
        return f"{done} The exposure could not be marked resolved ({failed[0].get('reason')}); resolve it from Exposures."
    if exposures.get("needs_owner"):
        return f"{done} Ask an owner or admin to resolve the exposure."
    resolved = exposures.get("resolved") or []
    if resolved:
        return f"{done} {len(resolved)} exposure{'s' if len(resolved) != 1 else ''} resolved as rotated."
    return done


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


class VaultAddDeviceModal(ModalScreen[Optional[str]]):
    """Say who approves this computer before it asks, and offer Recover instead.

    Dismisses with ``"start"``, ``"recover"`` or ``None``.
    """

    DEFAULT_CSS = """
    VaultAddDeviceModal { align: center middle; }
    #vault_add_device_modal {
        width: 78; max-width: 94%; height: auto; max-height: 90%;
        border: round $primary; background: $surface; padding: 1 2; overflow-y: auto;
    }
    #vault_add_device_title { text-style: bold; }
    #vault_add_device_steps { margin-top: 1; }
    #vault_add_device_other { margin-top: 1; color: $text-muted; }
    #vault_add_device_modal > Horizontal { height: auto; margin-top: 1; }
    #vault_add_device_cancel, #vault_add_device_recover, #vault_add_device_start { width: 1fr; min-width: 0; }
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def __init__(self, device_name: str, *, key_file_missing: bool) -> None:
        super().__init__()
        self._device_name = device_name
        self._key_file_missing = key_file_missing

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("Add this computer as a vault device", id="vault_add_device_title"),
            Static(self._steps(self._shown_name()), id="vault_add_device_steps"),
            Static(self._other_way(), id="vault_add_device_other"),
            Horizontal(
                Button("Cancel", id="vault_add_device_cancel"),
                Button("Use Recover instead", id="vault_add_device_recover"),
                Button("Start", variant="primary", id="vault_add_device_start"),
            ),
            id="vault_add_device_modal",
        )

    def on_mount(self) -> None:
        preferred = "#vault_add_device_recover" if self._key_file_missing else "#vault_add_device_start"
        self.query_one(preferred, Button).focus()

    def _steps(self, name: str) -> Text:
        return Text(
            "A device where your vault is already unlocked has to approve this computer.\n"
            "  1. Choose Start. This computer then waits for the approval.\n"
            f"  2. On the other device, open Vault, choose Devices, select “{name}” and choose Approve device.\n"
            "  3. Check that both screens show the same safety number."
        )

    def _other_way(self) -> str:
        if self._key_file_missing:
            return (
                "This computer used your vault before, but its vault key file is missing. Unless another "
                "device still has your vault unlocked, choose Recover and enter your recovery key."
            )
        return "No other device with your vault unlocked? Use Recover with your recovery key instead."

    def _shown_name(self) -> str:
        return _hide_device_name(self.app, scrub_for_demo(self.app, self._device_name), self._device_name)

    def refresh_after_demo_toggle(self) -> None:
        name = _hide_device_name(self.app, scrub_for_demo(self.app, self._device_name), self._device_name)
        self.query_one("#vault_add_device_steps", Static).update(self._steps(name))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        choices = {"vault_add_device_start": "start", "vault_add_device_recover": "recover"}
        self.dismiss(choices.get(event.button.id or ""))

    def action_cancel(self) -> None:
        self.dismiss(None)


class _RunningWork:
    """One running piece of work the Vault screen shows; its message can change."""

    def __init__(self, screen: "VaultScreen", message: str, *, holds_screen: bool = False) -> None:
        self._screen = screen
        self.message = message
        # A change that leaving the screen would cut off halfway.
        self.holds_screen = holds_screen

    def say(self, message: str) -> None:
        self.message = message
        self._screen._show_busy()


def _hide_device_name(app: Any, text: str, device_name: Optional[str]) -> str:
    """In demo mode, name this computer generically: its host name is personal."""
    if device_name and getattr(app, "demo_mode", False):
        return text.replace(device_name, "this computer")
    return text


def _key_file_label(service: Any) -> str:
    """Where this computer keeps its vault keys, home-relative when it can be."""
    path = getattr(getattr(service, "store", None), "path", None)
    if not isinstance(path, Path):
        return "~/.servonaut/vault/vault_keys.json"
    try:
        return f"~/{path.relative_to(Path.home())}"
    except ValueError:
        return str(path)


def _device_name(service: Any) -> str:
    """The name this computer registers under, as the approving device lists it."""
    name_for = getattr(service, "default_device_name", None)
    name = name_for() if callable(name_for) else None
    return name if isinstance(name, str) and name else "this computer"


async def _cancel_pending_device(service: Any) -> None:
    """Withdraw this computer's unapproved device and destroy its keys.

    Shielded, so leaving the screen (which cancels its worker) cannot cut the
    withdrawal short.
    """
    cancel = getattr(service, "cancel_pending_device", None)
    if not callable(cancel):
        return
    with contextlib.suppress(Exception):
        result = cancel()
        if hasattr(result, "__await__"):
            await asyncio.shield(result)


# The identity states in which this computer has no usable identity of an existing account.
_NEEDS_THIS_DEVICE = ("remote_identity", "custody_missing")


class VaultScreen(Screen):
    """Full-screen vault metadata, device state, and exposure entry point."""

    DEFAULT_CSS = """
    VaultScreen #vault_busy_row { height: auto; }
    VaultScreen #vault_busy { width: 1fr; }
    VaultScreen #vault_cancel_wait { display: none; min-width: 16; }
    VaultScreen #vault_cancel_wait.-shown { display: block; }
    """

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
        # Work in progress, newest last; actions stay disabled while any runs.
        self._busy_work: list[_RunningWork] = []
        # Set while a wait can be stopped from the screen (Add device).
        self._stop_waiting: Optional[Callable[[], None]] = None
        self._add_device_worker: Optional[Worker[None]] = None
        self._approve_worker: Optional[Worker[None]] = None
        # This computer's name once Add device is used (hidden in demo mode).
        self._device_name: Optional[str] = None
        self._focus_before_busy: Optional[Widget] = None
        # The action the status line names, focused (and so scrolled into view) once work ends.
        self._next_action: Optional[str] = None

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        with Horizontal(id="vault_layout"):
            yield Sidebar()
            with Vertical(id="vault_content"):
                yield Static("Vault", id="vault_title")
                yield Static("Loading encrypted vault metadata…", id="vault_status")
                with Horizontal(id="vault_busy_row"):
                    yield BusyIndicator(id="vault_busy")
                    yield Button("Stop waiting", id="vault_cancel_wait", disabled=True)
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
                        yield Button("Recover", id="vault_recover")
                        yield Button("Approve device", id="vault_approve")
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
        return _hide_device_name(self.app, scrub_for_demo(self.app, value), self._device_name)

    def _status(self, message: str) -> None:
        self._status_raw = message
        self.query_one("#vault_status", Static).update(escape(self.scrub_for_display(message)))

    def refresh_after_demo_toggle(self) -> None:
        """Repaint cached metadata after demo mode changes without re-fetching."""
        render = getattr(self, f"_render_{self._table_mode}", None)
        if callable(render):
            render()
        self._status(self._status_raw)
        self._show_busy()

    @contextlib.asynccontextmanager
    async def _busy(
        self, message: str, *, stop: Optional[Callable[[], None]] = None, holds_screen: bool = False,
    ) -> AsyncIterator[_RunningWork]:
        """Show *message* while the block runs and hold every action until it ends.

        Vault workers are exclusive, so a second action would cancel this one;
        the block also ends when its worker is cancelled. *stop*, when given,
        is offered as "Stop waiting". *holds_screen* also holds Back, for
        changes that leaving would cut off halfway. (The other vault dialogs
        share ``BusyWork``; this screen's actions instead follow an identity
        state that can change while work runs, so it keeps its own.)
        """
        work = _RunningWork(self, message, holds_screen=holds_screen)
        if not self._busy_work:
            # Disabled buttons lose focus; give it back once the work is done.
            self._focus_before_busy = self.focused
        self._busy_work.append(work)
        if stop is not None:
            self._stop_waiting = stop
        self._show_busy()
        try:
            yield work
        finally:
            self._busy_work.remove(work)
            if stop is not None:
                self._stop_waiting = None
            self._show_busy()
            if not self._busy_work:
                self._restore_focus()

    def _restore_focus(self) -> None:
        widget, self._focus_before_busy = self._focus_before_busy, None
        button_id, self._next_action = self._next_action, None
        # The table takes focus when the screen opens; focus moved elsewhere (the sidebar) stays.
        if button_id and self.app.screen is self and (self.focused is None or isinstance(self.focused, DataTable)):
            with contextlib.suppress(NoMatches):
                button = self.query_one(f"#{button_id}", Button)
                if button.focusable:
                    button.focus()
                    return
        if self.focused is None and widget is not None and widget.is_attached and widget.focusable:
            widget.focus()

    def _show_busy(self) -> None:
        try:
            indicator = self.query_one("#vault_busy", BusyIndicator)
            stop = self.query_one("#vault_cancel_wait", Button)
        except NoMatches:
            return  # the screen is closing
        if self._busy_work:
            indicator.start(self.scrub_for_display(self._busy_work[-1].message))
        else:
            indicator.stop()
        stop.set_class(self._stop_waiting is not None, "-shown")
        stop.disabled = self._stop_waiting is None
        self._apply_action_state()

    def _refuse_while_busy(self) -> bool:
        """Explain instead of starting work that would cancel what is running."""
        if not self._busy_work:
            return False
        self.app.notify(
            f"Please wait: {self.scrub_for_display(self._busy_work[-1].message)}",
            severity="warning",
            markup=False,
        )
        return True

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
        table.clear(columns=True); table.add_columns("Subject", "Reason", "Note", "Item ID", "Exposure ID")
        for row in self._exposures:
            note = "Key replaced in vault; old key may still be on servers" if row.get("key_replaced") is True else ""
            table.add_row(escape(self.scrub_for_display(row.get("subject") or row.get("public_fingerprint") or "")), escape(self.scrub_for_display(row.get("reason") or "")), note, escape(self.scrub_for_display(row.get("item_id") or "")), escape(self.scrub_for_display(row.get("exposure_id") or "")))

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
        self._apply_action_state()

    def _apply_action_state(self) -> None:
        """Enable the actions this identity state allows, none while work runs."""
        idle = not self._busy_work
        state = self._identity_state
        try:
            for button_id in self._READY_ACTIONS:
                self.query_one(f"#{button_id}", Button).disabled = not (idle and state == "ready")
            self.query_one("#vault_setup", Button).disabled = not (idle and state == "first_user")
            needs_device = idle and state in _NEEDS_THIS_DEVICE
            self.query_one("#vault_recover", Button).disabled = not needs_device
            self.query_one("#vault_add_device", Button).disabled = not needs_device
            self.query_one("#vault_refresh", Button).disabled = not idle
        except NoMatches:
            return  # the screen is closing

    def _allows_identity_action(self, *states: str) -> bool:
        """Keep keyboard actions from bypassing the disabled-button state."""
        if self._refuse_while_busy():
            return False
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
        if not isinstance(remote_identity, Mapping):
            return "first_user"
        return "custody_missing" if status.get("custody_missing") is True else "remote_identity"

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
        async with self._busy("Checking your vault…"):
            await self._load_now()

    async def _load_now(self) -> None:
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
            self._next_action = "vault_add_device"
            self._status(
                "Your vault identity is not on this computer. Choose Recover and enter your recovery key, "
                "or Add device to have a device where your vault is unlocked approve this one."
            )
            return
        if readiness == "custody_missing":
            self._set_identity_state(readiness)
            self._next_action = "vault_recover"
            self._status(f"{onboarding.RECOVER_DEVICE.message} (Expected at {_key_file_label(service)}.)")
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
            "vault_cancel_wait": self.action_stop_waiting,
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
        if self._refuse_while_busy():
            return
        self.run_worker(self._load(), group="vault", exclusive=True)

    def action_stop_waiting(self) -> None:
        if self._stop_waiting is not None:
            self._stop_waiting()

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
            async with self._busy('Creating your vault identity…', holds_screen=True):
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
            async with self._busy('Confirming your vault identity…'):
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
            async with self._busy('Checking which vaults you can create…'):
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
            async with self._busy('Creating the vault…', holds_screen=True):
                await _invoke(service, "create_vault", team=choice.get("team"), name=None, grant_policy="auto")
        except Exception as exc:
            self.app.notify(f"Could not create the vault ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        self.app.notify("Vault created.", markup=False)
        await self._load()

    def action_back(self) -> None:
        holding = next((work for work in self._busy_work if work.holds_screen), None)
        if holding is not None:
            self.app.notify(
                f"Wait for this to finish: {self.scrub_for_display(holding.message)} Leaving now would stop it halfway.",
                severity="warning",
                markup=False,
            )
            return
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
            async with self._busy("Loading the vault's items…"):
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
                async with self._busy('Decrypting the item…'):
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
            async with self._busy('Loading exposures…'):
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
            async with self._busy('Resolving the exposure…'):
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
        self.app.push_screen(VaultExposureActionModal(rotation=True, service=self._service()), callback)

    async def _rotate_exposure(self, exposure: Mapping[str, Any], values: Mapping[str, str]) -> None:
        service = self._service()
        if service is None or not self._selected_vault_id:
            return
        servers = [server.strip() for server in values["servers"].split(",") if server.strip()]
        try:
            servers_text = f"{len(servers)} server{'s' if len(servers) != 1 else ''}"
            async with self._busy(
                f"Rotating the SSH key on {servers_text}: this connects to each one and can take a few minutes…",
                holds_screen=True,
            ):
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
            self._status(_rotation_summary(result.get("exposures")))
            return
        message = (
            "SSH key rotation did not finish. The exposed key may still log in to the hosts "
            "not marked old_key_removed, so the exposure stays open: remove the old key "
            "there, then rotate again."
        )
        self._status(message)
        self.app.notify(message, severity="error", markup=False)

    def action_devices(self) -> None:
        if not self._allows_identity_action("ready"):
            return
        self.run_worker(self._load_devices(), group="vault", exclusive=True)

    def action_add_device(self) -> None:
        if not self._allows_identity_action(*_NEEDS_THIS_DEVICE):
            return
        service = self._service()
        if service is None:
            return
        name = _device_name(service)
        self._device_name = name

        def chosen(choice: Optional[str]) -> None:
            if choice == "start":
                self._add_device_worker = self.run_worker(self._add_device(name), group="vault", exclusive=True)
            elif choice == "recover":
                self.action_recover()

        self.app.push_screen(
            VaultAddDeviceModal(name, key_file_missing=self._identity_state == "custody_missing"), chosen,
        )

    def _stop_add_device(self) -> None:
        worker, self._add_device_worker = self._add_device_worker, None
        if worker is not None:
            worker.cancel()

    async def _add_device(self, name: str) -> None:
        service = self._service()
        if service is None:
            return
        try:
            async with self._busy("Asking to add this computer…", stop=self._stop_add_device) as work:
                pending = await _invoke(service, "add_device", device_name=name, platform=None)
                identity = pending.get("identity") if isinstance(pending, Mapping) else None
                expires_at = pending.get("expires_at") if isinstance(pending, Mapping) else None
                if not identity or not expires_at:
                    raise RuntimeError("missing pending-device approval state")
                work.say(f"Waiting for another device to approve “{name}”…")
                self._status(
                    f"On a device where your vault is unlocked, open Vault, choose Devices, select “{name}” "
                    "and choose Approve device. No other device? Choose Stop waiting, then Recover."
                )
                await self._wait_for_approval(service, work, identity, expires_at)
        except asyncio.CancelledError:
            with contextlib.suppress(NoMatches):
                self._status("Stopped waiting: this computer was not added. Choose Add device to try again, or Recover.")
            await _cancel_pending_device(service)
            raise
        except Exception as exc:
            await _cancel_pending_device(service)
            reason = vault_failure_reason(exc)
            self._status(f"This computer was not added ({reason}). Choose Add device to try again, or Recover.")
            self.app.notify(f"Device registration failed ({reason}).", severity="error", markup=False)
            return
        self.app.notify("This computer is now a vault device.", markup=False)
        await self._load()

    async def _wait_for_approval(
        self, service: Any, work: _RunningWork, identity: Mapping[str, Any], expires_at: str,
    ) -> None:
        """Poll until another device approves this one, then save its keys here."""
        attempt = 0
        while True:
            approval = await _invoke(service, "poll_pending_device", identity=identity, expires_at=expires_at)
            state = approval.get("state") if isinstance(approval, Mapping) else None
            if state == "revealed" and approval.get("safety_number"):
                self._status(
                    f"Safety number: {approval.get('safety_number')}. Check that the other device shows "
                    "exactly this number, then approve it there."
                )
                work.say("Waiting for the other device to approve…")
            if state == "approved":
                approved_payload = approval.get("approval") if isinstance(approval, Mapping) else None
                if not isinstance(approved_payload, Mapping):
                    raise RuntimeError("pending-device approval payload is malformed")
                work.say("Saving this computer's vault keys…")
                await _invoke(service, "finish_pending_device", approval=approved_payload, identity=identity)
                return
            await asyncio.sleep(_approval_poll_delay(service, attempt))
            attempt += 1

    async def _load_devices(self) -> None:
        service = self._service()
        if service is None:
            return
        try:
            async with self._busy('Loading devices…'):
                devices = await _invoke(service, "list_devices")
        except Exception as exc:
            self.app.notify(f"Could not load devices ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        rows = list(devices or [])
        self._devices = [dict(row) for row in rows if isinstance(row, Mapping)]
        self._table_mode = "devices"
        self._render_devices()
        self._status("Device list loaded. To approve a pending device, select it and choose Approve device, then compare its safety number.")
        pending = next((row for row, device in enumerate(self._devices) if device.get("status") == "pending"), None)
        if pending is not None:
            # Select the waiting device and bring Approve device into view.
            self.query_one("#vault_table", DataTable).move_cursor(row=pending)
            self.query_one("#vault_approve", Button).focus()

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

        self._approve_worker = self.run_worker(self._approve_device(device_id, confirm), group="vault", exclusive=True)

    def _stop_approving(self) -> None:
        worker, self._approve_worker = self._approve_worker, None
        if worker is not None:
            worker.cancel()

    async def _approve_device(self, device_id: str, confirmation: Any) -> None:
        service = self._service()
        if service is None:
            return
        try:
            async with self._busy(
                "Approving the device: waiting for it to show its safety number…", stop=self._stop_approving,
            ):
                result = await _invoke(service, "approve_device", device_id=device_id, confirmation=confirmation)
        except asyncio.CancelledError:
            with contextlib.suppress(NoMatches):
                self._status("Stopped approving. The device is still waiting: choose Devices to approve it again.")
            raise
        except Exception as exc:
            self.app.notify(f"Device approval failed ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        self._status("Device approved: it can open your vaults now.")

    def action_recover(self) -> None:
        if not self._allows_identity_action(*_NEEDS_THIS_DEVICE):
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
            async with self._busy("Restoring your vault identity on this computer…", holds_screen=True):
                await _invoke(service, "recover", recovery_key=recovery_key, device_name=None, platform=None)
        except Exception as exc:
            self.app.notify(f"Vault recovery failed ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        self.app.notify("Your vault identity is restored on this computer.", markup=False)
        await self._load()

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
            async with self._busy('Replacing your recovery key…', holds_screen=True):
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
            async with self._busy('Requesting a new vault identity…', holds_screen=True):
                result = await _invoke(service, "reset_identity", reason="rotate", recovery_confirmation=confirmation)
        except Exception as exc:
            self.app.notify(f"Identity reset failed ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        self._status("Identity reset requested. Confirm it through the e-mail, then this screen will verify and save the replacement identity.")
        attempt = 0
        try:
            async with self._busy("Waiting for you to confirm the reset from the e-mail…"):
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
            async with self._busy('Refreshing the vault…'):
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
        inventory: the user picks the team and shared server, and the facade
        verifies the old reference, native binding, and SSH login before a
        separate explicit request can clear the legacy pointer.
        """
        service = self._service()
        if service is None:
            return
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
        target = await self.app.push_screen_wait(VaultImportedTeamBindingModal(service))
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
        try:
            async with self._busy('Binding the imported key and checking the SSH login…', holds_screen=True):
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
            async with self._busy('Clearing the legacy Bitwarden reference…', holds_screen=True):
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
            async with self._busy("Loading the vault's members…"):
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
            async with self._busy('Processing access requests…', holds_screen=True):
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
            async with self._busy('Rotating the vault key…', holds_screen=True):
                result = await _invoke(service, "rotate", vault_id=vault_id)
        except Exception as exc:
            self.app.notify(f"Vault rotation failed ({vault_failure_reason(exc)}).", severity="error", markup=False)
            return
        self._status(f"Vault rotation finished: {escape(str(result))}")
