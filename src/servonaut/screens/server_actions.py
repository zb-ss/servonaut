"""Server actions screen for Servonaut v2.0."""

from __future__ import annotations

import logging
import subprocess
from collections.abc import Mapping
from typing import Any, Dict, Optional

from rich.markup import escape
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.css.query import NoMatches
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button, Checkbox, Footer, Input, Label, OptionList, Select, Static,
)
from textual.widgets.option_list import Option

from servonaut.services.ssh_host_keys import (
    OFF_OPTIONS_KEEP_KNOWN_HOSTS,
    HostKeyPolicy,
    HostKeyTarget,
    detect_host_key_problem,
    host_key_alias_options,
    identity_file_args,
    trusted_host_keys,
)
from servonaut.utils.instance_resolver import is_aws_row
from servonaut.utils.ssh_utils import run_ssh
from servonaut.services.live_stats_service import LiveStatsError
from servonaut.utils.live_stats_panel import format_live_stats
from servonaut.utils.memory_panel import render_memory_panel
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar
from servonaut.screens._busy_work import BusyJob, BusyWork
from servonaut.services.vault.auto_bind import MATCHED_BY_KEY_FILE, MATCHED_BY_KEY_PAIR, match_ssh_key
from servonaut.screens._demo_resolve import (
    connection_instance,
    display_text,
    fleet_rows,
    display_username,
    hide_login,
    refuse_unresolved,
    replace_instances,
    team_rows,
)
from servonaut.screens._provider_accounts import ServerAccountMixin
from servonaut.utils.instance_resolver import display_name

#: Per-action one-line help shown in the detail pane on focus.
_ACTION_HELP: dict[str, str] = {
    "btn_browse": "Browse the remote filesystem in a tree view (over SSH).",
    "btn_command": "Run a one-off command on this server in an overlay panel.",
    "btn_ssh": "Open a full SSH session in a new terminal window.",
    "btn_memory": "Build / view the AI-queryable fact cache for this server.",
    "btn_findings": "View proactive monitoring findings for this server and trigger a scan.",
    "btn_logs": "Stream live log files via SSH (tail -f).",
    "btn_scan": "View keyword scan results collected from this server.",
    "btn_db_creds": "Scan this server for DB credentials and store them in your secret vault.",
    "btn_ai_analysis": "Analyze log text with AI (OpenAI, Anthropic, or Ollama).",
    "btn_scp": "Upload or download files via SCP.",
    "btn_ban_ip": "Ban this server's public IP via WAF, Security Group, or NACL.",
    "btn_manage_ssh_ref": "Add, edit, or remove the Bitwarden SSH item ref.",
    "btn_use_vault_key": "Bind a verified native-vault SSH key to this server.",
    "btn_verify_ssh": "Run a local SSH probe and report the result.",
    "btn_ovh_reinstall": "Reinstall this OVH server with a new OS image.",
    "btn_ovh_resize": "Change the VPS model or Cloud flavor.",
    "btn_ovh_snapshots": "Create, restore, or delete snapshots.",
    "btn_ovh_firewall": "Manage VPS firewall rules.",
    "btn_back": "Return to the instance list.",
}

logger = logging.getLogger(__name__)

#: Display names of the credential sources a binding can name.
_CREDENTIAL_SOURCE_LABELS: dict[str, str] = {
    "servonaut_vault": "Servonaut Vault",
    "bitwarden": "Bitwarden",
}

#: Binding source of a native Servonaut Vault key.
_VAULT_SOURCE = "servonaut_vault"


def credential_source_label(source: object) -> Optional[str]:
    """The name shown for a binding's credential source, or None if unknown."""
    return _CREDENTIAL_SOURCE_LABELS.get(source) if isinstance(source, str) else None


def scrub_for_display(app: Any, value: object) -> str:
    """Hide names held outside the displayed fleet when demo mode is on."""
    text = display_text(app, str(value))
    redactor = getattr(app, "redaction_service", None)
    if getattr(app, "demo_mode", False) and redactor is not None:
        return str(redactor.scrub_stream(text))
    return text


def log_safe(app: Any, value: object) -> str:
    """*value* for the log: one line, and demo-safe like the screen."""
    from servonaut.services.vault.display import terminal_safe

    return terminal_safe(scrub_for_display(app, value))


def _can_bind_team(row: Mapping[str, Any]) -> bool:
    """Whether this user's team role permits setting a shared key."""
    return row.get("team_role") in ("owner", "admin")


def _team_key_label(row: Mapping[str, Any]) -> str:
    """The unescaped scope label; callers scrub and escape it for display."""
    return f"Team key for {row.get('team_name') or row.get('team_slug') or 'team'}"


class VaultBindingScopeModal(ModalScreen[Optional[str]]):
    """Choose a sharing team, personal access (''), or cancel (None)."""

    DEFAULT_CSS = """
    VaultBindingScopeModal { align: center middle; }
    #vault_scope_modal {
        width: 76; max-width: 92%; height: auto; max-height: 88%;
        border: round $primary; background: $surface; padding: 1 2;
    }
    #vault_scope_choices { max-height: 12; margin: 1 0; }
    #vault_scope_cancel { dock: bottom; }
    """
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def __init__(self, teams: list[dict[str, Any]]) -> None:
        super().__init__()
        self._teams = teams
        self._scopes: dict[Option, str] = {}

    def _options(self) -> list[Option]:
        options: list[Option] = []
        self._scopes.clear()
        for row in self._teams:
            name = scrub_for_display(self.app, row.get("team_name") or row["team_slug"])
            allowed = _can_bind_team(row)
            binding = row.get("credential_binding")
            has_vault_binding = isinstance(binding, Mapping) and binding.get("source") == _VAULT_SOURCE
            if not allowed:
                reason = "Only a team owner or admin can set the team's key."
            elif has_vault_binding:
                reason = f"Replaces the key everyone in {name} uses now."
            else:
                reason = "Team members connect to this server with this key."
            option = Option(
                Text(f"Everyone in team {name}\n{reason}"),
                disabled=not allowed,
            )
            options.append(option)
            if allowed:
                self._scopes[option] = row["team_slug"]
        personal = Option(Text("Just me\nOnly you use this key; the team is not affected."))
        options.append(personal)
        self._scopes[personal] = ""
        return options

    def compose(self) -> ComposeResult:
        yield Container(
            Static("[bold]Who is this key for?[/bold]"),
            OptionList(*self._options(), id="vault_scope_choices"),
            Button("Cancel", id="vault_scope_cancel"),
            id="vault_scope_modal",
        )

    def on_mount(self) -> None:
        # Enter alone keeps access personal; team-wide changes are deliberate.
        self.query_one(OptionList).highlighted = len(self._teams)

    def refresh_after_demo_toggle(self) -> None:
        choices = self.query_one(OptionList)
        highlighted = choices.highlighted
        choices.clear_options().add_options(self._options())
        choices.highlighted = highlighted

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        scope = self._scopes.get(event.option)
        if scope is not None and not event.option.disabled:
            self.dismiss(scope)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.action_cancel()

    def action_cancel(self) -> None:
        self.dismiss(None)


class OwnKeyUpdateModal(ModalScreen[bool]):
    """After a team key is set on the user's own server: also move their own binding to it?

    Keep is the default (Escape and Enter): the user's binding only changes
    on an explicit Update.
    """

    DEFAULT_CSS = """
    OwnKeyUpdateModal { align: center middle; }
    #own_key_modal {
        width: 76; max-width: 92%; height: auto; max-height: 88%;
        border: round $primary; background: $surface; padding: 1 2;
    }
    #own_key_body { margin: 1 0; }
    #own_key_buttons { height: auto; }
    #own_key_keep, #own_key_update { min-width: 12; margin-right: 1; }
    """
    BINDINGS = [Binding("escape", "keep", "Keep mine", show=False)]

    def __init__(self, body: str) -> None:
        super().__init__()
        self._body = body

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("[bold]Also update your own key for this server?[/bold]"),
            # Logins and names come from servers and other users: inert text.
            Static(Text(self._body), id="own_key_body"),
            Horizontal(
                Button("Keep mine", id="own_key_keep"),
                Button("Update mine", id="own_key_update", variant="primary"),
                id="own_key_buttons",
            ),
            id="own_key_modal",
        )

    def on_mount(self) -> None:
        self.query_one("#own_key_keep", Button).focus()

    def action_keep(self) -> None:
        self.dismiss(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "own_key_update")


class ConfirmSshVerifyModal(ModalScreen[bool]):
    """Brief blocking confirmation for the SSH probe action.

    Returns True on Confirm, False on Cancel (including Escape).
    Per the project convention: ModalScreen for brief blocking prompts.
    Per style constraints: round $accent border, fixed height, Cancel button.
    """

    BINDINGS = [
        Binding("escape", "action_cancel", "Cancel", show=False),
    ]

    def __init__(self, host: str, has_ref: bool, *, vault: bool = False) -> None:
        """Initialize the modal.

        Args:
            host: Target host name / IP (cloud-origin — must be escaped).
            has_ref: True if a BW SSH ref is stored for this instance. When
                False the modal offers "Add SSH ref" instead of the probe prompt.
            vault: True when the server is bound to a Servonaut Vault key;
                the probe then uses that key and ``has_ref`` is ignored.
        """
        super().__init__()
        self._host = host
        self._has_ref = has_ref
        self._vault = vault

    def compose(self) -> ComposeResult:
        """Compose the confirm modal."""
        safe_host = escape(self._host)
        if self._vault:
            body_text = (
                f"About to check SSH to [bold]{safe_host}[/bold] with this "
                "server's Servonaut Vault key.\n\n"
                "This will:\n"
                "  (1) load the key into a private, short-lived SSH agent\n"
                "  (2) run ssh -o BatchMode=yes to test connectivity"
            )
            confirm_label = "Verify"
        elif self._has_ref:
            body_text = (
                f"About to run a local SSH probe against [bold]{safe_host}[/bold].\n\n"
                "This will:\n"
                "  (1) resolve the Bitwarden item ref\n"
                "  (2) run ssh -o BatchMode=yes to test connectivity\n"
                "  (3) report the result to the server audit log"
            )
            confirm_label = "Verify"
        else:
            body_text = (
                f"No SSH ref is stored for [bold]{safe_host}[/bold].\n\n"
                "Would you like to add one so Servonaut can verify "
                "SSH connectivity via Bitwarden?"
            )
            confirm_label = "Add SSH Ref"

        yield Container(
            Static("[bold]Verify SSH[/bold]", id="ssh_verify_modal_title"),
            Static(body_text, id="ssh_verify_modal_body"),
            Horizontal(
                Button("Cancel", variant="default", id="btn_ssh_verify_cancel"),
                Button(confirm_label, variant="primary", id="btn_ssh_verify_confirm"),
                classes="ssh_verify_actions_row",
            ),
            id="ssh_verify_modal_container",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Dismiss with the appropriate result."""
        if event.button.id == "btn_ssh_verify_confirm":
            self.dismiss(True)
        else:
            self.dismiss(False)

    def action_action_cancel(self) -> None:
        """Escape — dismiss False."""
        self.dismiss(False)


# Bind is held back while the dialog loads the choices it binds.
_BIND_BUTTON = ("#vault_bind_confirm",)


class VaultBindingModal(ModalScreen[Optional[dict]]):
    """Pick the vault SSH key for this server from what the user can read.

    A shared server belongs to its team, so only that team's vault is offered;
    any other server is bound for the user alone. Nothing secret is shown: keys
    are listed by name and fingerprint, and the result carries identifiers only.
    """

    DEFAULT_CSS = """
    #vault_bind_scope { color: $text-muted; }
    #vault_bind_trusted { margin: 1 0 0 0; }
    #vault_bind_use_trusted { margin: 0 0 1 0; }
    #vault_bind_message { color: $warning; margin: 1 0 0 0; }
    #vault_bind_match { color: $text-muted; display: none; }
    /* Bind stays in reach, and what is loading in view, however far the form scrolls. */
    #vault_bind_footer { dock: bottom; height: auto; margin-top: 1; }
    #vault_bind_footer > Horizontal { height: auto; }
    #vault_bind_busy { margin: 0; }
    #vault_bind_use_trusted.-hidden { display: none; }
    #vault_bind_fetch_host_key { margin: 0 0 1 0; }
    #vault_bind_fetch_host_key.-hidden { display: none; }
    #vault_bind_message { display: none; }
    """
    AUTO_FOCUS = ""
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def __init__(
        self, service: Any, instance: Dict[str, Any], own_instance: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__()
        self._service = service
        self._instance = instance
        self._team = instance.get("team_slug") if instance.get("is_shared") is True else None
        # A team's first key for a server the user also lists as their own: its
        # host keys are found, and fetched, through the own row, which is where
        # connecting to it records them. A team key that replaces another keeps
        # the pins it already has.
        binding = instance.get("credential_binding")
        rebinding = isinstance(binding, Mapping) and binding.get("source") == _VAULT_SOURCE
        self._own = own_instance if self._team and not rebinding else None
        self._trusted_keys: list[str] = []
        # What is on screen, kept raw so a demo-mode toggle can redraw it.
        self._vault_choices: list[dict[str, str]] = []
        self._key_choices: list[dict[str, str]] = []
        self._keys_for: str | None = None
        self._message = ""
        self._match_text = ""
        # The key the dialog chose by name; the hint saying why goes once another is chosen.
        self._matched_item: str | None = None
        self._trusted_text = ""
        # Whether a first connection records the host key (accept-new), so the dialog can make one.
        self._can_fetch_host_key = False
        self._busy = BusyWork(self, "#vault_bind_busy")
        # The real login, and what the login field was given for it: in demo
        # mode the stand-in the server details show. An untouched stand-in
        # binds the real login; once the user types, the field holds theirs.
        self._login = ""
        self._login_shown = ""
        self._login_written: set[str] = set()
        self._login_edited = False

    def compose(self) -> ComposeResult:
        login = str(self._instance.get("login_user") or self._instance.get("username") or "")
        if not login and not self._team:
            login = self._suggested_login()
        self._login = login
        rows: list[Any] = [
            Static("[bold]Use vault key[/bold]"),
            Static(escape(self.scrub_for_display(self._scope_text())), id="vault_bind_scope"),
            Label("Vault"),
            Input(placeholder="Search vaults…", id="vault_bind_vault_search"),
            Select([], prompt="Loading vaults…", id="vault_bind_vault", disabled=True),
            Label("SSH key"),
            Input(placeholder="Search keys by name or fingerprint…", id="vault_bind_item_search"),
            Select([], prompt="Choose a vault first", id="vault_bind_item", disabled=True),
            Static("", id="vault_bind_match"),
            Label("Login user"),
            Input(value=self._login_for_display(), placeholder="Login user", id="vault_bind_login"),
        ]
        if not self._shows_host_keys:
            rows.append(Input(placeholder="Verified OpenSSH host keys, comma separated (optional)", id="vault_bind_host_keys"))
        else:
            rows.extend((
                Static("Checking the host keys this machine trusts…", id="vault_bind_trusted"),
                Button("Fetch host key", id="vault_bind_fetch_host_key", classes="-hidden"),
            ))
            if not self._team:
                rows.append(Checkbox("I checked these fingerprints: pin them", value=False, id="vault_bind_use_trusted",
                                     disabled=True, classes="-hidden"))
            rows.append(
                Input(placeholder="Or paste verified OpenSSH host keys, comma separated", id="vault_bind_host_keys"),
            )
        rows.extend((
            Static("", id="vault_bind_message"),
            Vertical(
                BusyIndicator(id="vault_bind_busy"),
                Horizontal(
                    Button("Cancel", id="vault_bind_cancel"),
                    Button("Bind", variant="primary", id="vault_bind_confirm"),
                ),
                id="vault_bind_footer",
            ),
        ))
        yield Container(*rows, id="vault_bind_modal")

    def on_mount(self) -> None:
        self.run_worker(self._load_vaults(), group="vault_bind_choices", exclusive=True)
        if self._shows_host_keys:
            self.run_worker(self._load_trusted_host_keys(), group="vault_bind_host_keys")

    @property
    def _shows_host_keys(self) -> bool:
        """Whether the dialog lists the host keys this machine trusts (and can fetch them)."""
        return not self._team or self._own is not None

    def _suggested_login(self) -> str:
        """The login SSH would use for this server today, so a binding keeps it."""
        suggest = getattr(self._service, "ssh_login", None)
        try:
            login = suggest(self._instance) if callable(suggest) else None
        except Exception:  # a guess only: the field stays editable and empty
            logger.debug("Could not work out the login user for the vault binding", exc_info=True)
            return ""
        return login if isinstance(login, str) else ""

    def _login_for_display(self) -> str:
        """The value the login field shows for the real login, remembered as ours."""
        self._login_shown = display_username(self.app, self._login) or ""
        self._login_written.add(self._login_shown)
        return self._login_shown

    def _show_login(self) -> None:
        """Put the login back in its field for the current demo mode, unless the user typed one."""
        if self._login_edited:
            return
        self.query_one("#vault_bind_login", Input).value = self._login_for_display()

    def _login_value(self) -> str:
        """The login the form names: an untouched demo stand-in is the real login."""
        value = self.query_one("#vault_bind_login", Input).value.strip()
        if not self._login_edited and value == self._login_shown.strip():
            return self._login
        return value

    def _scope_text(self) -> str:
        if self._team:
            return f"Shared server in team {self._team}: everyone in the team uses this key."
        return "Your server: the key is used only by you."

    def action_cancel(self) -> None:
        self.dismiss(None)

    def scrub_for_display(self, value: object) -> str:
        """Demo-safe text: vault, key, host and login names are hidden in demo mode."""
        text = str(value)
        redactor = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redactor is not None:
            # ssh's own messages quote the login ("login@host: Permission denied").
            return str(redactor.scrub_stream(hide_login(self.app, text, self._login)))
        return text

    def refresh_after_demo_toggle(self) -> None:
        """Redraw names and messages under the current demo mode, keeping the choices."""
        self._show_login()
        self._show_options("#vault_bind_vault", self._vault_choices, "vault_id")
        self._show_options("#vault_bind_item", self._key_choices, "item_id")
        self.query_one("#vault_bind_scope", Static).update(escape(self.scrub_for_display(self._scope_text())))
        self._say(self._message)
        self._show_match(self._match_text)
        if self._shows_host_keys:
            self._show_trusted(self._trusted_text)

    # Each picker's search box.
    _SEARCH_BOX = {"#vault_bind_vault": "#vault_bind_vault_search", "#vault_bind_item": "#vault_bind_item_search"}

    def _show_options(self, selector: str, choices: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
        """Offer the *choices* that match the picker's search box; return them."""
        select = self.query_one(selector, Select)
        kept = select.value
        query = self.query_one(self._SEARCH_BOX[selector], Input).value.strip().lower()
        # Searched as shown, so demo mode's hidden names cannot be probed.
        labels = [(choice, self.scrub_for_display(choice["label"])) for choice in choices]
        shown = [(choice, label) for choice, label in labels if query in label.lower()]
        # Names come from other team members: inert text, never parsed as markup.
        select.set_options([(Text(label), choice[key]) for choice, label in shown])
        if any(choice[key] == kept for choice, _ in shown):
            select.value = kept
        return [choice for choice, _ in shown]

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "vault_bind_login":
            # Our own writes echo back as Changed events; anything else is the user typing.
            if event.value not in self._login_written:
                self._login_edited = True
            return
        pickers = {
            "vault_bind_vault_search": ("#vault_bind_vault", self._vault_choices, "vault_id", "vaults"),
            "vault_bind_item_search": ("#vault_bind_item", self._key_choices, "item_id", "keys"),
        }
        picker = pickers.get(event.input.id or "")
        if picker is None:
            return
        selector, choices, key, noun = picker
        if not choices:
            return  # nothing loaded yet: the picker keeps saying what it waits for
        shown = self._show_options(selector, choices, key)
        select = self.query_one(selector, Select)
        query = event.value.strip()
        select.prompt = f"No {noun} match “{query}”" if query and not shown else f"Choose {'a vault' if noun == 'vaults' else 'an SSH key'}"
        if query and len(shown) == 1 and select.value != shown[0][key]:
            select.value = shown[0][key]

    def on_input_submitted(self, event: Input.Submitted) -> None:
        targets = {"vault_bind_vault_search": "#vault_bind_vault", "vault_bind_item_search": "#vault_bind_item"}
        target = targets.get(event.input.id or "")
        if target is not None:
            event.stop()
            self.query_one(target, Select).focus()

    def _show_match(self, text: str) -> None:
        self._match_text = text
        line = self.query_one("#vault_bind_match", Static)
        line.update(escape(self.scrub_for_display(text)))
        line.display = bool(text)

    def _records_new_host_keys(self) -> bool:
        check = getattr(self._service, "records_new_host_keys", None)
        try:
            return bool(check()) if callable(check) else False
        except Exception:  # unknown: the user can still connect once or paste keys
            logger.debug("Could not read the host-key policy for the vault binding", exc_info=True)
            return False

    def _no_trusted_keys_text(self, failure: str | None) -> str:
        if failure:
            # ssh's own last line may lack the full stop the next sentence needs.
            reason = failure.strip().rstrip(".")
            return (f"Could not record this server's host key: {reason}. Connect to it once with SSH "
                    "and check its fingerprint, or paste verified host keys below.")
        if self._can_fetch_host_key:
            return ("This machine has no host key for this server yet. Fetch host key connects to it "
                    "once, as SSH does, and records it; then check its fingerprint here. Or paste "
                    "verified host keys below.")
        return ("This machine has no host key for this server yet: connect to it once with SSH, then "
                "open this dialog again to check and pin its fingerprint, or paste verified host keys below.")

    async def _fetch_host_key(self) -> None:
        """Connect to the server once so its host key is recorded, then show it."""
        visit = getattr(self._service, "visit_for_host_key", None)
        if not callable(visit):
            return
        # A server of your own is visited as you connect to it, with your own login.
        target = self._own if self._own is not None else self._instance
        login = None if self._own is not None else self._login_value() or None
        self._say("")
        try:
            with self._busy.running("Connecting once to record the server's host key…",
                                    hold=(*_BIND_BUTTON, "#vault_bind_fetch_host_key")):
                failure = await visit(target, login=login)
        except Exception:
            logger.debug("Recording the host key for the vault binding failed", exc_info=True)
            failure = "Could not connect to the server."
        await self._load_trusted_host_keys(
            failure=failure or "the connection worked, but no host key was recorded for it.",
        )
        if self._trusted_keys:
            try:
                self.query_one("#vault_bind_use_trusted" if not self._team else "#vault_bind_confirm").focus()
            except NoMatches:
                pass  # the dialog closed meanwhile

    def _missing_host_keys_text(self) -> str:
        """What pins a server of your own, given what this machine trusts for it."""
        if self._trusted_keys:
            return ("A server of your own needs its host keys pinned: tick \"I checked these fingerprints\" "
                    "or paste verified host keys.")
        if self._can_fetch_host_key:
            return ("A server of your own needs its host keys pinned: use Fetch host key and check its "
                    "fingerprint, or paste verified host keys.")
        return ("A server of your own needs its host keys pinned: connect to it once with SSH first, "
                "or paste verified host keys.")

    def _show_trusted(self, text: str) -> None:
        self._trusted_text = text
        self.query_one("#vault_bind_trusted", Static).update(escape(self.scrub_for_display(text)))

    def _say(self, text: str) -> None:
        self._message = text
        message = self.query_one("#vault_bind_message", Static)
        message.update(escape(self.scrub_for_display(text)))
        message.display = bool(text)

    async def _load_vaults(self) -> None:
        select = self.query_one("#vault_bind_vault", Select)
        try:
            with self._busy.running("Loading your vaults…", hold=_BIND_BUTTON):
                choices = await self._service.vault_choices(team=self._team)
        except Exception as exc:
            from servonaut.services.vault.errors import vault_failure_reason

            select.set_options([])
            select.prompt = "Vaults could not be loaded"
            self._say(f"Could not load your vaults ({vault_failure_reason(exc)}).")
            return
        if not choices:
            select.prompt = "No vault available"
            self._say(
                f"Team {self._team} has no vault you can read yet: an owner or admin creates it, "
                "or grants your access, on the Vault screen."
                if self._team else "You have no vault yet: create one on the Vault screen first."
            )
            return
        self._vault_choices = choices
        self._show_options("#vault_bind_vault", choices, "vault_id")
        select.prompt = "Choose a vault"
        select.disabled = False
        personal = [choice for choice in choices if choice.get("kind") == "personal"]
        obvious = choices[0] if self._team and len(choices) == 1 else (personal[0] if not self._team and personal else None)
        if obvious is not None:
            select.value = obvious["vault_id"]
        else:
            select.focus()

    async def _load_keys(self, vault_id: str) -> None:
        self._keys_for = vault_id
        self._key_choices = []
        self._matched_item = None
        self._show_match("")
        select = self.query_one("#vault_bind_item", Select)
        select.set_options([])
        select.prompt = "Loading SSH keys…"
        select.disabled = True
        try:
            # Each key's name is decrypted locally, so a full vault takes a moment.
            with self._busy.running(
                "Loading this vault's SSH keys… this can take a few seconds", hold=_BIND_BUTTON,
            ):
                choices = await self._service.ssh_key_choices(vault_id=vault_id)
        except Exception as exc:
            from servonaut.services.vault.errors import vault_failure_reason

            select.prompt = "SSH keys could not be loaded"
            self._keys_for = None
            # Clear the vault so choosing it again (even the only one) retries.
            self.query_one("#vault_bind_vault", Select).clear()
            self._say(f"Could not load the SSH keys ({vault_failure_reason(exc)}). Choose the vault again to retry.")
            return
        if not choices:
            select.prompt = "No SSH key in this vault"
            self._say("This vault has no SSH key yet: import one with Import SSH on the Vault screen.")
            return
        self._say("")
        self._key_choices = choices
        shown = self._show_options("#vault_bind_item", choices, "item_id")
        select.prompt = "Choose an SSH key"
        select.disabled = False
        match = match_ssh_key(self._instance, choices)
        if match is not None and match.ambiguous:
            self._show_match(f"Several different keys are named “{match.name}”: choose the right one.")
        elif match is not None and any(choice["item_id"] == match.item_id for choice in shown):
            self._matched_item = match.item_id
            select.value = match.item_id
            named_like = {
                MATCHED_BY_KEY_PAIR: "the server's key pair", MATCHED_BY_KEY_FILE: "the server's key file",
            }.get(match.matched_by, "the server")
            self._show_match(f"Chose “{match.name}”: it is named like {named_like}.")
        elif len(choices) == 1:
            select.value = choices[0]["item_id"]
        select.focus()

    async def _load_trusted_host_keys(self, failure: str | None = None) -> None:
        """Show the host keys this machine trusts for the server, or how to get them.

        *failure* says why the dialog's own connection recorded none.
        """
        import asyncio

        from servonaut.services.vault import crypto

        # The address SSH reaches (the private one behind a bastion) is the one pinned.
        destination = getattr(self._service, "ssh_destination", None)
        if callable(destination):
            host, port = destination(self._instance)
        else:
            host = self._instance.get("hostname") or self._instance.get("host") or self._instance.get("public_ip")
            port = self._instance.get("port")
        host = str(host or "")
        port = port if isinstance(port, int) and not isinstance(port, bool) else None
        try:
            with self._busy.running("Reading the host keys this machine trusts…", hold=_BIND_BUTTON):
                keys = await asyncio.to_thread(trusted_host_keys, self._instance, host, port) if host else []
                if not keys and host and self._own is not None:
                    keys = await asyncio.to_thread(trusted_host_keys, self._own, host, port)
                self._can_fetch_host_key = bool(host) and await asyncio.to_thread(self._records_new_host_keys)
        except Exception:
            keys = []
        try:
            fetch = self.query_one("#vault_bind_fetch_host_key", Button)
        except NoMatches:
            return  # the dialog closed while the keys were read
        # Only a server of your own asks to tick the fingerprints: a team's key
        # pins them unless other keys are pasted.
        box = next(iter(self.query("#vault_bind_use_trusted").results(Checkbox)), None)
        if not keys:
            self._trusted_keys = []
            if box is not None:
                box.value = False
                box.disabled = True
                box.add_class("-hidden")
            fetch.set_class(not self._can_fetch_host_key, "-hidden")
            self._show_trusted(self._no_trusted_keys_text(failure))
            return
        fetch.add_class("-hidden")
        self._trusted_keys = list(keys)
        heading = (f"Host keys this machine trusts for {host}, pinned for the team unless you paste others:"
                   if self._team else f"Host keys this machine trusts for {host}:")
        self._show_trusted(heading + "\n" + "\n".join(
            f"  {crypto.ssh_public_fingerprint(key)}" for key in keys
        ))
        if box is not None:
            box.disabled = False
            box.remove_class("-hidden")

    def on_select_changed(self, event: Select.Changed) -> None:
        # A redraw that restores the same vault is not a new choice.
        if event.select.id == "vault_bind_vault" and isinstance(event.value, str) and event.value != self._keys_for:
            self.run_worker(self._load_keys(event.value), group="vault_bind_choices", exclusive=True)
        if event.select.id == "vault_bind_item" and self._matched_item is not None and event.value != self._matched_item:
            self._matched_item = None
            self._show_match("")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "vault_bind_fetch_host_key":
            event.stop()
            self.run_worker(self._fetch_host_key(), group="vault_bind_host_keys", exclusive=True)
            return
        if event.button.id != "vault_bind_confirm":
            self.dismiss(None)
            return
        vault_id = self.query_one("#vault_bind_vault", Select).value
        item_id = self.query_one("#vault_bind_item", Select).value
        offered_vaults = {choice["vault_id"] for choice in self._vault_choices}
        offered_keys = {choice["item_id"] for choice in self._key_choices}
        if (
            not isinstance(vault_id, str) or not isinstance(item_id, str)
            or vault_id not in offered_vaults or vault_id != self._keys_for or item_id not in offered_keys
        ):
            self._say("Choose a vault and an SSH key first.")
            return
        login = self._login_value()
        if not self._team and not login:
            self._say("A server of your own needs the login user the key is for.")
            return
        port = self._instance.get("port", 22)
        if not self._team and (isinstance(port, bool) or not isinstance(port, int)):
            self._say("This server's SSH port is not a number: fix it in Custom Servers first.")
            return
        typed = [key.strip() for key in self.query_one("#vault_bind_host_keys", Input).value.split(",") if key.strip()]
        if self._team:
            # Pasted keys win; otherwise the trusted keys shown for a server of your own.
            host_keys = typed or list(self._trusted_keys)
        else:
            use_trusted = self.query_one("#vault_bind_use_trusted", Checkbox).value
            host_keys = [*(self._trusted_keys if use_trusted else []), *typed]
        if not self._team and not host_keys:
            self._say(self._missing_host_keys_text())
            return
        self.dismiss({
            "team": self._team or "",
            "vault_id": vault_id,
            "item_id": item_id,
            "login": login or None,
            "host_keys": ",".join(host_keys),
        })


class ServerActionsScreen(ServerAccountMixin, Screen):
    """Screen displaying available actions for a selected EC2 instance.

    Shows server information and action buttons:
    1. Browse Files - File browser with RemoteTree
    2. Run Command - Command execution overlay
    3. SSH Connect - Launch external SSH terminal
    4. SCP Transfer - File transfer
    5. View Scan Results - Show keyword scan results
    6. View Logs - Real-time remote log viewer
    7. AI Analysis - AI-powered log analysis
    8. Ban IP - Ban this instance's public IP
    9. Back - Return to instance list
    """

    BINDINGS = [
        Binding("1", "action_1", "Browse Files", show=True),
        Binding("2", "action_2", "Run Command", show=True),
        Binding("3", "action_3", "SSH Connect", show=True),
        Binding("4", "action_4", "SCP Transfer", show=True),
        Binding("5", "action_5", "Scan Results", show=True),
        Binding("6", "action_6", "View Logs", show=True),
        Binding("7", "action_7", "AI Analysis", show=True),
        Binding("8", "action_8", "Ban IP", show=True),
        Binding("m", "open_memory", "Memory", show=True),
        Binding("d", "scan_db_creds", "Scan DB", show=True),
        Binding("f", "open_findings", "Findings", show=True),
        Binding("l", "toggle_live", "Live", show=True),
        Binding("L", "toggle_live", "Live", show=False),
        Binding("r", "manage_ssh_ref", "SSH Ref", show=True),
        Binding("v", "verify_ssh", "Verify SSH", show=True),
        Binding("9", "back", "Back", show=True),
        Binding("escape", "back", "Back", show=False),
    ]

    # The screen gets -narrow / -wide and -short / -tall classes by terminal
    # size; the stylesheet lays the action rail out two to a row only when
    # there is room for it and the detail pane beside it.
    HORIZONTAL_BREAKPOINTS = [(0, "-narrow"), (130, "-wide")]
    VERTICAL_BREAKPOINTS = [(0, "-short"), (44, "-tall")]

    def __init__(self, instance: dict) -> None:
        """Initialize server actions screen.

        Args:
            instance: Instance dictionary with connection details.
        """
        super().__init__()
        # The row as displayed: demo-mode stand-ins when demo mode is on (the
        # app redacts and restores it in place). Anything that reaches a
        # provider, SSH or a store resolves the real record through
        # ``connection_instance`` first.
        self._instance = instance
        self._reverse_dns = ""
        self._live_on = False
        # Id of the action button the focus-help line currently describes, so a
        # click on that (otherwise passive) line can re-dispatch to the button.
        self._focused_action_id: Optional[str] = None
        # Which read-only view is mounted inline in the detail pane, if any:
        # None | "browse" | "logs".
        self._inline_view: Optional[str] = None
        # Markup source of #server_info, so later additions (reverse DNS)
        # edit the text we wrote instead of reading it back from the widget.
        self._server_info_text: str = ""
        # Slow work started here (binding a vault key, preparing SSH) and the
        # button that would restart it, held back until it ends.
        self._busy = BusyWork(self, "#sa_busy")
        # Source of the personal binding the vault service holds for this
        # server. Personal bindings are not part of the row (only a team's
        # shared servers carry theirs), so it is looked up after mount.
        self._vault_binding_source: Optional[str] = None

    def on_mount(self) -> None:
        """Focus the first action button and populate the detail pane."""
        self.query_one("#btn_browse", Button).focus()
        if self._vault_runtime_for_lookup() is not None:
            self.run_worker(
                self._refresh_vault_binding(), group="vault_binding_lookup", exclusive=True
            )
        # Fetch reverse DNS for OVH VPS instances
        if self._instance.get('is_ovh') and self._instance.get('provider_type') == 'vps':
            if self._instance.get('public_ip'):
                self.run_worker(self._fetch_rdns(), exclusive=False)
        # Dynamically add OVH action buttons for OVH instances
        if self._instance.get('is_ovh'):
            action_buttons = self.query_one("#action_buttons")
            action_buttons.mount(
                Static("OVH", classes="section_label"),
                Button("Reinstall OS", id="btn_ovh_reinstall", variant="error"),
                Button("Resize / Upgrade", id="btn_ovh_resize"),
                Button("Snapshots", id="btn_ovh_snapshots"),
                Button("Firewall", id="btn_ovh_firewall"),
                before=self.query_one("#btn_back"),
            )
        # Populate the cached-memory snapshot pane.
        self._render_memory_panel()

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the identity and memory panes for the new demo-mode state."""
        self._render_server_info()
        self._render_memory_panel()

    def on_key(self, event) -> None:
        """Handle arrow key navigation between buttons.

        Args:
            event: Key event.
        """
        if event.key in ("up", "down"):
            # Only cycle the action rail when a rail button already has focus.
            # When focus is inside the inline view (file tree) or elsewhere,
            # leave arrow keys alone so that widget can handle them.
            buttons = list(self.query("#action_buttons Button"))
            if not buttons:
                return
            focused = self.focused
            if focused not in buttons:
                return
            idx = buttons.index(focused)
            if event.key == "down":
                next_idx = (idx + 1) % len(buttons)
            else:
                next_idx = (idx - 1) % len(buttons)
            buttons[next_idx].focus()

    def compose(self) -> ComposeResult:
        """Compose the server actions UI (narrow action rail + detail pane)."""
        yield SafeHeader()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with Horizontal(id="sa-body"):
                # --- Left: sectioned action rail ---
                yield Vertical(
                    Static("CONNECT", classes="section_label"),
                    Button("1. Browse Files", id="btn_browse", variant="primary"),
                    Button("2. Run Command", id="btn_command"),
                    Button("3. SSH Connect", id="btn_ssh"),
                    Static("INSPECT", classes="section_label"),
                    # Memory promoted to the top of INSPECT — highest-leverage
                    # feature for AI / MCP workflows.
                    Button("M. Memory", id="btn_memory"),
                    Button("F. Findings", id="btn_findings"),
                    Button("6. View Logs", id="btn_logs"),
                    Button("5. Scan Results", id="btn_scan"),
                    Button("D. Scan DB Creds", id="btn_db_creds"),
                    Button("7. AI Analysis", id="btn_ai_analysis"),
                    Static("OPERATE", classes="section_label"),
                    Button("4. SCP Transfer", id="btn_scp"),
                    Button("8. Ban IP", id="btn_ban_ip"),
                    Static("MANAGE", classes="section_label"),
                    Button("Use Vault Key", id="btn_use_vault_key"),
                    Button("R. Manage SSH Ref", id="btn_manage_ssh_ref"),
                    Button("V. Verify SSH", id="btn_verify_ssh"),
                    Button("9. Back", id="btn_back", variant="error"),
                    id="action_buttons",
                )
                # --- Right: identity + live + memory + focus help + inline view ---
                self._server_info_text = self._build_server_info()
                yield Vertical(
                    Static(self._server_info_text, id="server_info"),
                    Static(self._live_stats_idle_text(), id="live_stats"),
                    Static("", id="memory_panel"),
                    Static("", id="action_help"),
                    # Mount target for inline read-only views (Browse / Logs).
                    # Hidden until an action opens it (see _open_inline).
                    Vertical(id="sa-inline"),
                    # Pinned to the pane's bottom; hidden while nothing runs.
                    BusyIndicator(id="sa_busy"),
                    id="sa-detail",
                )
        yield Footer()

    def _build_server_info(self) -> str:
        """Build server information display string.

        Every value comes from a provider or from the user's server list, so
        each is markup-escaped: a name like ``web-[b]1`` shows as typed.

        Returns:
            Rich-formatted string with server details.
        """
        def field(key: str, default: str) -> str:
            return escape(str(self._instance.get(key) or default))

        name = escape(display_name(self._instance) or 'Unnamed')
        public_ip = field('public_ip', 'N/A')
        # With several accounts of this provider, say which one it is in.
        account_line = (
            f"[dim]Account:[/dim] {field('account', '-')}\n"
            if self._instance.get('account_qualified') else ""
        )
        credential_line = self._credential_source_line() + self._shared_with_line()

        if self._instance.get('is_shared') is True:
            port = escape(str(self._instance.get('port') or 22))
            return (
                f"[bold $text-accent]Team server: {name}[/bold $text-accent]\n\n"
                f"[dim]Team:[/dim] {field('team_name', '-')}\n"
                f"[dim]Host:[/dim] {public_ip}\n"
                f"[dim]Port:[/dim] {port}\n"
                f"[dim]Team login:[/dim] {field('login_user', '-')}\n"
                f"[dim]State:[/dim] [dim]N/A (shared by the team)[/dim]\n\n"
                f"{credential_line}"
                f"[$text-accent]Direct Connection[/$text-accent]\n"
                f"[dim]Target:[/dim] {public_ip}"
            )

        if self._instance.get('is_ovh'):
            provider_type = escape(str(self._instance.get('provider_type', 'unknown')))
            region = field('region', '-')
            state = self._instance.get('state', 'unknown')
            instance_id = field('id', 'unknown')
            private_ip = field('private_ip', 'N/A')
            server_type = field('type', '-')
            os_label = field('os', '-')
            ram = field('ram_gb', '-')
            reverse_dns = self._display_reverse_dns()
            rdns_line = (
                f"[dim]Reverse DNS:[/dim] {escape(reverse_dns)}\n" if reverse_dns else ""
            )
            return (
                f"[bold $text-accent]OVH Server: {name}[/bold $text-accent]\n\n"
                f"{account_line}"
                f"[dim]ID:[/dim] {instance_id}\n"
                f"[dim]Type:[/dim] {provider_type.upper()} — {server_type}\n"
                f"[dim]Public IP:[/dim] {public_ip}\n"
                f"{rdns_line}"
                f"[dim]Private IP:[/dim] {private_ip}\n"
                f"[dim]Region:[/dim] {region}\n"
                f"[dim]State:[/dim] {self._colorize_state(state)}\n"
                f"[dim]OS:[/dim] {os_label}\n"
                f"[dim]RAM:[/dim] {ram} GB\n\n"
                f"{credential_line}"
                f"[$text-accent]Direct Connection[/$text-accent]\n"
                f"[dim]Target:[/dim] {public_ip}"
            )

        if self._instance.get('is_custom'):
            provider = field('provider', 'custom')
            group = field('group', '-')
            port = escape(str(self._instance.get('port', 22)))
            username = field('username', 'root')
            return (
                f"[bold $text-accent]Server: {name}[/bold $text-accent]\n\n"
                f"[dim]Host:[/dim] {public_ip}\n"
                f"[dim]Port:[/dim] {port}\n"
                f"[dim]Username:[/dim] {username}\n"
                f"[dim]Provider:[/dim] {provider}\n"
                f"[dim]Group:[/dim] {group}\n"
                f"[dim]State:[/dim] [dim]N/A (custom server)[/dim]\n\n"
                f"{credential_line}"
                f"[$text-accent]Direct Connection[/$text-accent]\n"
                f"[dim]Target:[/dim] {public_ip}"
            )

        instance_id = field('id', 'unknown')
        private_ip = field('private_ip', 'N/A')
        region = field('region', 'unknown')
        state = self._instance.get('state', 'unknown')

        # Resolve connection method for AWS instances. Connection rules match
        # the real record (names, tags); the bastion is shown redacted.
        profile = self.app.connection_service.resolve_profile(
            connection_instance(self.app, self._instance)
        )
        if profile and profile.bastion_host:
            bastion = str(profile.bastion_host)
            if self.app.demo_mode and self.app.redaction_service:
                bastion = self.app.redaction_service.redact_host(bastion)
            connection_info = f"[$text-accent]via Bastion:[/$text-accent] {escape(bastion)}"
            target_ip = private_ip
        else:
            connection_info = "[$text-accent]Direct Connection[/$text-accent]"
            target_ip = public_ip

        return (
            f"[bold $text-accent]Server: {name}[/bold $text-accent]\n\n"
            f"{account_line}"
            f"[dim]Instance ID:[/dim] {instance_id}\n"
            f"[dim]Public IP:[/dim] {public_ip}\n"
            f"[dim]Private IP:[/dim] {private_ip}\n"
            f"[dim]Region:[/dim] {region}\n"
            f"[dim]State:[/dim] {self._colorize_state(state)}\n\n"
            f"{credential_line}"
            f"{connection_info}\n"
            f"[dim]Target:[/dim] {target_ip}"
        )

    def _shared_with_line(self) -> str:
        """``Also shared with: team …`` for one of the user's own servers a team shares too."""
        teams = [
            str(row.get("team_name") or row["team_slug"])
            for row in self._sharing_teams()
        ]
        if not teams:
            return ""
        label = escape(scrub_for_display(self.app, ", ".join(teams)))
        return f"[dim]Also shared with:[/dim] {label}\n"

    def _sharing_teams(self) -> list[dict[str, Any]]:
        """The real shared row for each team also sharing this own server."""
        from servonaut.services.shared_servers import is_same_server

        own = connection_instance(self.app, self._instance)
        if own.get("is_shared") is True:
            return []
        teams: dict[str, dict[str, Any]] = {}
        for row in team_rows(self.app):
            slug = row.get("team_slug")
            if isinstance(slug, str) and slug and is_same_server(row, own):
                teams.setdefault(slug, row)
        return list(teams.values())

    def _credential_source_line(self) -> str:
        """Describe the configured SSH credential without exposing its reference."""
        label = credential_source_label(self._binding_source()) or "Automatic resolution"
        if self._binding_source() == _VAULT_SOURCE:
            scope = (
                _team_key_label(self._instance)
                if self._instance.get("is_shared") is True else "Your key"
            )
            label += f" · {scrub_for_display(self.app, scope)}"
        for row in self._sharing_teams():
            binding = row.get("credential_binding")
            if isinstance(binding, Mapping) and binding.get("source") == _VAULT_SOURCE:
                scope = scrub_for_display(self.app, _team_key_label(row))
                label += f"; {scope} (Servonaut Vault)"
        return f"[dim]SSH credential:[/dim] {escape(label)}\n"

    def _binding_source(self) -> Optional[str]:
        """The credential source this screen bound or looked up, else the row's (team servers)."""
        bound = getattr(self, "_vault_binding_source", None)
        if bound:
            return bound
        binding = self._instance.get("credential_binding")
        source = binding.get("source") if isinstance(binding, dict) else None
        return source if isinstance(source, str) and source else None

    def _vault_runtime_for_lookup(self) -> Any:
        """The vault service, when a personal binding could exist and be read.

        A team's shared server carries its binding on the row. A personal
        binding is read with the unlocked vault identity; without one this
        device has no vault credential to use, so nothing is looked up.
        """
        if isinstance(self._instance.get("credential_binding"), dict):
            return None
        service = getattr(self.app, "vault_command_service", None)
        if service is None or getattr(getattr(service, "store", None), "identity", None) is None:
            return None
        return service

    async def _lookup_vault_binding_source(self) -> Optional[str]:
        """The source of this server's personal binding; None when there is none or it is unreadable."""
        service = self._vault_runtime_for_lookup()
        if service is None:
            return None
        instance = connection_instance(self.app, self._instance)
        try:
            binding = await service.personal_binding(instance)
        except Exception as exc:  # noqa: BLE001 - the panel keeps its default label
            logger.debug("Personal vault binding lookup failed: %s", type(exc).__name__)
            return None
        if not isinstance(binding, Mapping) or not binding:
            return None
        source = binding.get("source")
        # Personal bindings are native vault bindings; older answers may omit the source.
        return source if isinstance(source, str) and source else _VAULT_SOURCE

    async def _refresh_vault_binding(self) -> None:
        """Show the personal binding's source once the vault service has answered."""
        previous = self._vault_binding_source
        source = await self._lookup_vault_binding_source()
        # An answer that started before a bind on this screen must not undo it.
        if self._vault_binding_source != previous or source is None or source == previous:
            return
        self._vault_binding_source = source
        if self.is_mounted:
            self._render_server_info()

    def _colorize_state(self, state: str) -> str:
        """Add color markup to instance state.

        Args:
            state: Instance state string.

        Returns:
            Colorized state string with markup.
        """
        state_colors = {
            'running': '[$text-success]running[/$text-success]',
            'stopped': '[$text-error]stopped[/$text-error]',
            'stopping': '[$text-warning]stopping[/$text-warning]',
            'pending': '[$text-accent]pending[/$text-accent]',
            'terminated': '[dim]terminated[/dim]',
        }
        return state_colors.get(state, escape(str(state)))

    async def _fetch_rdns(self) -> None:
        """Fetch the VPS's reverse DNS and show it in the server info pane.

        OVH is asked about the real VPS and address: in demo mode the row
        holds stand-ins OVH has never heard of. Only what is drawn is
        redacted (see ``_display_reverse_dns``). The VPS is looked up in
        the OVH account it belongs to.
        """
        has_real = getattr(self.app, "has_real_record", None)
        if callable(has_real) and has_real(self._instance) is False:
            return  # a stand-in with no real VPS behind it is never sent to OVH
        vps_service = self._ovh_service("vps")
        if vps_service is None:
            return
        real = connection_instance(self.app, self._instance)
        vps_name = real.get('id', '')
        public_ip = real.get('public_ip', '')
        if not vps_name or not public_ip:
            return
        reverse = await vps_service.get_reverse_dns(vps_name, public_ip)
        if reverse:
            self._reverse_dns = reverse
            self._render_server_info()

    def _display_reverse_dns(self) -> str:
        reverse = getattr(self, "_reverse_dns", "")
        if reverse and self.app.demo_mode and self.app.redaction_service:
            return self.app.redaction_service.redact_hostname(reverse)
        return reverse

    def _render_server_info(self) -> None:
        """Redraw the identity pane from the row (and any reverse DNS known).

        Rebuilt from its source rather than edited in place, so a demo-mode
        toggle and a late reverse-DNS answer both land in one consistent text.
        """
        self._server_info_text = self._build_server_info()
        self.query_one("#server_info", Static).update(self._server_info_text)

    # ------------------------------------------------------------------
    # Detail pane: focus help, cached memory snapshot, live stats
    # ------------------------------------------------------------------

    def on_descendant_focus(self, event: events.DescendantFocus) -> None:
        """Update the focus-driven help line when an action button gains focus.

        The line is also a clickable proxy for the focused button (see
        :meth:`on_click`), so it reads as actionable rather than a dead label.
        """
        widget_id = getattr(event.widget, "id", None)
        if not widget_id:
            return
        help_text = _ACTION_HELP.get(widget_id)
        if help_text is None:
            return
        self._focused_action_id = widget_id
        try:
            self.query_one("#action_help", Static).update(
                f"[dim]▸[/dim] [u]{escape(help_text)}[/u]  [dim]· click to run[/dim]"
            )
        except Exception:  # noqa: BLE001 — pane may not be mounted yet
            pass

    def on_click(self, event: events.Click) -> None:
        """Treat a click on the focus-help line as activating the focused action."""
        widget = getattr(event, "widget", None)
        if widget is None or getattr(widget, "id", None) != "action_help":
            return
        btn_id = self._focused_action_id
        if not btn_id:
            return
        try:
            self.query_one(f"#{btn_id}", Button).press()
        except Exception:  # noqa: BLE001
            pass

    def _provider_for_memory(self) -> str:
        """Best-effort provider slug for memory lookups.

        Passing an empty string makes ``get_all_modules`` scan every provider
        sub-directory, so the snapshot is found regardless of which slug it was
        stored under (custom / aws / ovh / hetzner).
        """
        return ""

    def _render_memory_panel(self) -> None:
        """Render the cached server-memory snapshot into the detail pane."""
        try:
            panel = self.query_one("#memory_panel", Static)
        except Exception:  # noqa: BLE001
            return

        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            panel.update("[dim]Server memory is unavailable.[/dim]")
            return

        instance_id = str(self._instance.get("id") or "")
        instance_name = self._instance.get("name") or ""
        try:
            if memory_service.is_memory_disabled(instance_id, instance_name):
                panel.update("[dim]Memory is disabled for this server.[/dim]")
                return
        except Exception:  # noqa: BLE001
            pass

        try:
            modules = memory_service.get_all_modules(instance_id, self._provider_for_memory())
        except Exception as exc:  # noqa: BLE001
            logger.debug("get_all_modules failed for %s: %s", instance_id, exc)
            modules = {}

        text = render_memory_panel(modules)
        # Demo mode: the snapshot can embed paths / hostnames / versions from
        # the probed server — scrub before rendering, same posture as the
        # Memory screen and log viewer.
        if self.app.demo_mode and getattr(self.app, "redaction_service", None):
            text = self.app.redaction_service.scrub_stream(text)
        panel.update(text)

    # ------------------------------------------------------------------
    # Inline read-only views (Browse / Logs) — mounted in #sa-inline
    # ------------------------------------------------------------------

    def _safe_focus(self, selector: str) -> None:
        """Focus the widget matching *selector*, swallowing query failures."""
        try:
            self.query_one(selector).focus()
        except Exception:  # noqa: BLE001
            pass

    def _clear_inline(self) -> None:
        """Tear down whatever is mounted in the inline region and hide it."""
        try:
            inline = self.query_one("#sa-inline", Vertical)
        except Exception:  # noqa: BLE001
            self._inline_view = None
            return
        inline.remove_children()
        inline.remove_class("visible")
        self._inline_view = None

    def _open_inline_browse(self) -> None:
        """Mount the remote file tree inline in the detail pane."""
        from servonaut.screens.file_browser import build_remote_tree

        if self._inline_view == "browse":
            self._safe_focus("#remote_tree")
            return
        self._clear_inline()

        try:
            inline = self.query_one("#sa-inline", Vertical)
        except Exception:  # noqa: BLE001
            return

        try:
            tree = build_remote_tree(self.app, self._instance, tree_id="remote_tree")
        except Exception as exc:  # noqa: BLE001
            logger.error("Could not build inline file tree: %s", exc, exc_info=True)
            self.app.notify("Could not open file browser.", severity="error", markup=False)
            return

        self._inline_view = "browse"
        inline.mount(
            Static(
                "[b]📁 Files[/b]  [dim]· Esc to close[/dim]",
                classes="inline_title",
            ),
            tree,
            Static(
                "[dim]Root folders come from [b]Settings → Default Scan Paths[/b] "
                "(plus any matching Scan Rule).[/dim]",
                classes="inline_note",
            ),
        )
        inline.add_class("visible")
        self.call_after_refresh(lambda: self._safe_focus("#remote_tree"))

    # ------------------------------------------------------------------
    # Live stats (opt-in, SSH-polled)
    # ------------------------------------------------------------------

    def _live_stats_idle_text(self) -> str:
        """Text shown in the live-stats pane while polling is off."""
        return "[dim]Live stats: off — press [b]L[/b] to start (SSH-polled).[/dim]"

    def action_toggle_live(self) -> None:
        """Toggle the live resource-stats poller on/off."""
        if self._live_on:
            self._stop_live_stats()
            return

        if getattr(self.app, "live_stats_service", None) is None:
            self.app.notify(
                "SSH monitoring is unavailable.",
                severity="warning",
                markup=False,
            )
            return
        if not self._validate_instance_connection():
            return

        self._live_on = True
        try:
            self.query_one("#live_stats", Static).update("[$text-accent]Live stats: connecting…[/$text-accent]")
        except Exception:  # noqa: BLE001
            pass
        self.run_worker(
            self._live_stats_worker(),
            group="live_stats",
            exclusive=True,
        )

    def _stop_live_stats(self) -> None:
        """Stop the poller and reset the pane to its idle text."""
        self._live_on = False
        self.workers.cancel_group(self, "live_stats")
        try:
            self.query_one("#live_stats", Static).update(self._live_stats_idle_text())
        except Exception:  # noqa: BLE001
            pass

    async def _live_stats_worker(self) -> None:
        """Poll live resource stats over SSH until toggled off or screen left."""
        service = self.app.live_stats_service
        if service is None:
            return
        try:
            async for stats in service.watch(self._instance):
                self._set_live_text(format_live_stats(stats))
        except LiveStatsError as exc:
            self._set_live_text(f"[$text-error]{escape(str(exc))}[/$text-error]\n[dim]Press L to retry.[/dim]")
            self._live_on = False

    def _set_live_text(self, markup: str) -> None:
        """Update the live-stats pane defensively (screen may be torn down)."""
        try:
            self.query_one("#live_stats", Static).update(markup)
        except Exception:  # noqa: BLE001
            pass

    def on_screen_suspend(self) -> None:
        """Stop live polling when navigating away (no background SSH traffic)."""
        if self._live_on:
            self._stop_live_stats()

    def on_unmount(self) -> None:
        """Ensure the poller is cancelled and inline views torn down on teardown."""
        self._live_on = False
        try:
            self.workers.cancel_group(self, "live_stats")
        except Exception:  # noqa: BLE001
            pass
        if self._inline_view is not None:
            self._clear_inline()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events.

        Args:
            event: Button pressed event.
        """
        button_id = event.button.id

        if button_id == "btn_browse":
            self.action_action_1()
        elif button_id == "btn_command":
            self.action_action_2()
        elif button_id == "btn_ssh":
            self.action_action_3()
        elif button_id == "btn_scp":
            self.action_action_4()
        elif button_id == "btn_scan":
            self.action_action_5()
        elif button_id == "btn_logs":
            self.action_action_6()
        elif button_id == "btn_ai_analysis":
            self.action_action_7()
        elif button_id == "btn_ban_ip":
            self.action_action_8()
        elif button_id == "btn_memory":
            self.action_open_memory()
        elif button_id == "btn_db_creds":
            self.action_scan_db_creds()
        elif button_id == "btn_findings":
            self.action_open_findings()
        elif (button_id or "").startswith("btn_ovh_") and self._refuse_if_unresolved():
            return
        elif button_id == "btn_ovh_reinstall":
            from servonaut.screens.ovh_reinstall import OVHReinstallScreen
            self.app.push_screen(OVHReinstallScreen(self._instance))
        elif button_id == "btn_ovh_resize":
            from servonaut.screens.ovh_resize import OVHResizeScreen
            self.app.push_screen(OVHResizeScreen(self._instance))
        elif button_id == "btn_ovh_snapshots":
            from servonaut.screens.ovh_snapshots import OVHSnapshotsScreen
            self.app.push_screen(OVHSnapshotsScreen(self._instance))
        elif button_id == "btn_ovh_firewall":
            from servonaut.screens.ovh_firewall import OVHFirewallScreen
            self.app.push_screen(OVHFirewallScreen(self._instance))
        elif button_id == "btn_manage_ssh_ref":
            self.action_manage_ssh_ref()
        elif button_id == "btn_use_vault_key":
            self.action_use_vault_key()
        elif button_id == "btn_verify_ssh":
            self.action_verify_ssh()
        elif button_id == "btn_back":
            self.action_back()

    def _refuse_if_unresolved(self) -> bool:
        """True (and the user is told) when demo mode cannot name the real server."""
        try:
            app = self.app
        except Exception:  # noqa: BLE001 — not attached to an app: nothing to resolve
            return False
        return refuse_unresolved(app, self._instance)

    def _validate_instance_connection(self) -> bool:
        """Validate instance has required data for connection.

        Returns:
            True if instance can be connected to, False otherwise.
        """
        if self._refuse_if_unresolved():
            return False
        import logging
        logger = logging.getLogger(__name__)

        # Only EC2 instances have a running state to check: custom servers,
        # OVH and Hetzner instances and team shared servers connect as they are.
        if is_aws_row(self._instance):
            state = self._instance.get('state', 'unknown')
            if state != 'running':
                self.app.notify(
                    f"Instance is {state}. Only running instances can be connected to.",
                    severity="warning"
                )
                logger.warning("Attempted connection to non-running instance: %s", state)
                return False

        # Check if we have a target IP
        public_ip = self._instance.get('public_ip')
        private_ip = self._instance.get('private_ip')
        if not public_ip and not private_ip:
            self.app.notify(
                "Instance has no IP address available.",
                severity="error"
            )
            logger.error("Instance missing both public and private IP")
            return False

        return True

    def action_action_1(self) -> None:
        """Browse Files — open the remote file tree inline in the detail pane."""
        if not self._validate_instance_connection():
            return
        self._open_inline_browse()

    def action_action_2(self) -> None:
        """Open Command Overlay as modal."""
        if not self._validate_instance_connection():
            return
        from servonaut.screens.command_overlay import CommandOverlay
        self.app.push_screen(CommandOverlay(self._instance))

    def action_action_3(self) -> None:
        """SSH Connect — walk SshRefResolver chain then launch in external terminal.

        Dispatches to a worker so a double-click or rapid key press cannot
        double-launch: a press while the connection is still being prepared
        is refused rather than restarting it.  The 'ssh_connect' group is
        distinct from 'ssh_verify' so the two flows don't cancel each other.
        """
        if self._busy.holds("#btn_ssh"):
            self.app.notify(
                "Still preparing the SSH connection: wait for it to finish.",
                severity="warning",
                markup=False,
            )
            return
        if not self._validate_instance_connection():
            return

        self.run_worker(
            self._ssh_connect_flow(),
            group="ssh_connect",
            exclusive=True,
        )

    async def _ssh_connect_flow(self) -> None:
        """Async SSH connect: resolve credentials via three-tier chain, launch.

        Resolution order (mirrors the CLI ``servonaut ssh <id>`` surface):
          1. Personal Bitwarden ref  (requires Servonaut account)
          2. Team Bitwarden ref      (requires Servonaut Teams plan)
          3. Local ~/.ssh discovery  (existing TUI behaviour)
          4. None → notify user, stop

        BW tiers (source == 'personal' | 'team')
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        ``launch_ssh_in_terminal`` spawns a detached external window — the
        ephemeral key context manager would exit before SSH finishes reading
        the key.  We therefore use ``persistent_bw_ssh_key()`` (Option A):
        the file is written to ``~/.servonaut/tmp/bw-<random>.key`` with 0600
        perms and an ``atexit`` cleanup so normal TUI exit removes it.
        ``cleanup_stale_bw_keys()`` is called by ``ServonautApp`` on startup to
        catch crash-left files older than 24 h.
        """
        # Resolving can unlock a vault key or ask Bitwarden: seconds, not instant.
        with self._busy.running("Preparing the SSH connection…", hold=("#btn_ssh",)) as job:
            await self._resolve_and_launch_ssh(job)

    async def _ssh_ref_resolver(self) -> Any:
        """The SSH credential resolver Connect and Verify share (mirrors ``servonaut ssh``)."""
        from servonaut.services.ssh_ref_resolver import SshRefResolver

        teams_supplier = None
        team_service = getattr(self.app, "team_service", None)
        if team_service is not None:
            teams: list = []
            try:
                teams = await team_service.list_teams()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not load teams list for SSH connect: %s", exc)

            def _teams_supplier_fn() -> list:
                return teams

            teams_supplier = _teams_supplier_fn

        # Null stubs stand in for services that are unavailable.
        bw_ssh_config_service = getattr(self.app, "bw_ssh_config_service", None)
        if bw_ssh_config_service is None:
            bw_ssh_config_service = _NullBwService()
        if team_service is None:
            team_service = _NullTeamService()

        return SshRefResolver(
            bw_ssh_config_service=bw_ssh_config_service,
            team_service=team_service,
            ssh_service=self.app.ssh_service,
            teams_supplier=teams_supplier,
            vault_runtime=getattr(self.app, "vault_command_service", None),
        )

    async def _bastion_hop(self, instance: Dict[str, Any]) -> tuple[bool, Any]:
        """``(ok, hop)``: the vault lease of the bastion *instance*'s rule routes it through.

        *hop* is None when the bastion has no vault key here (the hop uses
        the user's own SSH setup); *ok* is False, after saying why, when the
        bastion's vault key must not be used.
        """
        from servonaut.services.ssh_credentials import VaultCredentialError, bastion_lease

        connection_service = self.app.connection_service
        try:
            profile = connection_service.resolve_profile(instance)
            hop = await bastion_lease(
                profile, fleet_rows(self.app),
                vault_runtime=getattr(self.app, "vault_command_service", None),
                connection_service=connection_service,
                cache=getattr(self.app, "vault_lease_cache", None),
            )
        except VaultCredentialError as exc:
            self.app.notify(scrub_for_display(self.app, str(exc)), severity="error", markup=False)
            return False, None
        return True, hop

    def _native_ssh_command(
        self,
        instance: Dict[str, Any],
        resolved: Any,
        *,
        remote_command: Optional[str] = None,
        options: tuple[str, ...] = (),
        hop: Any = None,
    ) -> Optional[list[str]]:
        """The ssh argv for a Vault or certificate credential, or None after saying why.

        It connects exactly where the pinned known_hosts entry points, through
        the resolved private agent. *options* are extra ``KEY=VALUE`` entries;
        *hop* is the bastion's own vault lease (:meth:`_bastion_hop`).
        """
        if (
            not resolved.identity_agent
            or not getattr(resolved, "identity_file", None)
            or not resolved.known_hosts_path
        ):
            self.app.notify(
                "The configured Vault SSH credential is incomplete.",
                severity="error",
                markup=False,
            )
            return None
        profile = self.app.connection_service.resolve_profile(instance)
        host = self.app.connection_service.get_target_host(instance, profile)
        host = host or instance.get("public_ip") or instance.get("private_ip") or instance.get("host") or instance.get("hostname")
        # Connect exactly where the pinned known_hosts entry points.
        host = getattr(resolved.lease, "target_host", None) or host
        if not host:
            self.app.notify("No IP address available for this instance.", severity="error")
            return None
        proxy_args = self.app.connection_service.get_proxy_args(profile, hop=hop) if profile else []
        username = (
            resolved.login_user
            or (profile.username if profile else None)
            or instance.get("username")
            or self.app.config_manager.get().default_username
            or "ubuntu"
        )
        return self.app.ssh_service.build_ssh_command(
            host=host,
            username=username,
            remote_command=remote_command,
            proxy_args=proxy_args,
            port=getattr(resolved.lease, "target_port", None) or instance.get("port"),
            extra_options=[*self.app.connection_service.get_extra_options(instance, profile), *options],
            identity_agent=resolved.identity_agent,
            identity_file=getattr(resolved, "identity_file", None),
            certificate_file=resolved.certificate_path,
            known_hosts_file=resolved.known_hosts_path,
        )

    async def _resolve_and_launch_ssh(self, job: BusyJob) -> None:
        """The connect flow of :meth:`_ssh_connect_flow`; *job* is its busy line."""
        from rich.markup import escape as rich_escape

        from servonaut.services.bw_resolver import (
            BwResolver,
            BwCliMissingError,
            BwSessionMissingError,
            BwItemNotFoundError,
            BwItemShapeError,
        )
        from servonaut.services.ssh_ref_resolver import resolve_target, team_key_hint
        from servonaut.utils.ephemeral_key import persistent_bw_ssh_key

        # Demo mode redacts the row we display; connect to the real record.
        instance = connection_instance(self.app, self._instance)
        name = instance.get("name") or instance.get("id", "instance")

        resolver = await self._ssh_ref_resolver()
        own_row = instance.get("is_shared") is not True

        try:
            # Without a key of the user's own, a team's key for the same
            # server is used (the connection then targets the team's row).
            instance, resolved = await resolve_target(resolver, instance, team_rows(self.app))
        except Exception as exc:  # Configured native credentials fail closed.
            logger.warning("Native Vault SSH resolution failed: %s", type(exc).__name__)
            from servonaut.services.vault.errors import vault_failure_reason

            self.app.notify(
                f"The configured Vault SSH credential could not be used ({vault_failure_reason(exc)}).",
                severity="error",
                markup=False,
            )
            return

        if resolved is None:
            hint = team_key_hint(
                instance, team_rows(self.app), getattr(self.app, "vault_command_service", None),
            )
            self.app.notify(
                hint or "No SSH key configured for this instance.",
                severity="warning",
                markup=False,
            )
            return

        # ------------------------------------------------------------------
        # Build the SSH command depending on the resolution source
        # ------------------------------------------------------------------
        source = resolved.source
        # Only the paths that go through a connection rule's bastion lease
        # the bastion's vault key (Bitwarden, OVH, custom and Hetzner servers
        # connect directly).
        hop = None
        uses_rule_route = source in ("ca", "vault") or (
            source == "local"
            and not (instance.get("is_ovh") or instance.get("is_custom") or instance.get("is_hetzner"))
        )
        if uses_rule_route:
            ok, hop = await self._bastion_hop(instance)
            if not ok:
                return
        via_team = ""
        if own_row and instance.get("is_shared") is True:
            team = instance.get("team_name") or instance.get("team_slug") or ""
            via_team = f" with team {rich_escape(str(team))}'s key"

        if source in ("ca", "vault"):
            ssh_cmd = self._native_ssh_command(instance, resolved, hop=hop)
            if ssh_cmd is None:
                return
            if self.app.terminal_service.launch_ssh_in_terminal(ssh_cmd):
                # The terminal is detached. The runtime owns this lease and
                # keeps its private agent alive until process shutdown/TTL.
                self.app.notify(
                    f"Connected{via_team} (resolution tier: {source}): {rich_escape(name)}",
                    markup=True,
                )
            else:
                self.app.notify("Could not launch the terminal.", severity="error", markup=False)
            return

        if source in ("personal", "team"):
            # BW path — resolve key body via bw CLI, write persistent tmpfile
            if not resolved.item_id:
                self.app.notify(
                    "Bitwarden ref is missing item_id — re-register via Settings.",
                    severity="error",
                    markup=False,
                )
                return

            bw_session = getattr(self.app, "bw_session_service", None)
            bw_resolver = BwResolver(
                session_getter=bw_session.session if bw_session is not None else None
            )
            self._busy.say(job, "Reading the SSH key from Bitwarden…")
            try:
                import asyncio
                key_body = await asyncio.to_thread(
                    bw_resolver.resolve_ssh_key, resolved.item_id
                )
            except BwCliMissingError:
                self.app.notify(
                    "Bitwarden CLI (bw) not found. Install it and ensure it is on your PATH.",
                    severity="error",
                    markup=False,
                )
                return
            except BwSessionMissingError:
                self.app.notify(
                    "Bitwarden vault is locked. Run 'bw unlock' and export BW_SESSION, then retry.",
                    severity="error",
                    markup=False,
                )
                return
            except BwItemNotFoundError:
                self.app.notify(
                    "Bitwarden item not found. Verify the item UUID or re-register via Settings.",
                    severity="error",
                    markup=False,
                )
                return
            except BwItemShapeError:
                self.app.notify(
                    "Bitwarden item shape unexpected — ensure it is a native SSH item (BW 2023.10+).",
                    severity="error",
                    markup=False,
                )
                return
            except Exception as exc:  # noqa: BLE001
                logger.error("BW key resolution failed: %s", exc, exc_info=True)
                self.app.notify(
                    "Bitwarden key resolution failed. See logs for details.",
                    severity="error",
                    markup=False,
                )
                return

            # Write a long-lived tmpfile (see docstring for rationale).
            key_path = persistent_bw_ssh_key(key_body)
            logger.debug(
                "Persistent BW SSH key written to %s for instance %s",
                key_path,
                instance.get("id"),
            )

            host = (
                instance.get("public_ip")
                or instance.get("private_ip")
                or instance.get("host")
                or instance.get("id", "")
            )
            username = (
                instance.get("username")
                or self.app.config_manager.get().default_username
                or "ubuntu"
            )
            port = instance.get("port")

            ssh_cmd = self.app.ssh_service.build_ssh_command(
                host=host,
                username=username,
                key_path=key_path,
                port=port,
                # Pin a cloud instance by its alias, as every other path does.
                extra_options=host_key_alias_options(
                    instance, self.app.connection_service.host_key_policy(),
                ),
            )

            tier_label = "personal" if source == "personal" else "team"
            if self.app.terminal_service.launch_ssh_in_terminal(ssh_cmd):
                self.app.notify(
                    f"Connected via BW (resolution tier: {tier_label}): {rich_escape(name)}",
                    markup=True,
                )
                logger.info(
                    "SSH connect (BW %s): host=%s, user=%s, item=%s",
                    tier_label, host, username, resolved.item_id,
                )
            else:
                terminal_error = getattr(self.app.terminal_service, "last_error", None)
                self.app.notify(
                    terminal_error
                    if isinstance(terminal_error, str) and terminal_error
                    else "Could not detect terminal emulator. Set 'terminal_emulator' in settings.",
                    severity="error",
                    markup=False,
                )

        else:
            # source == "local" — existing per-provider logic
            try:
                if instance.get("is_ovh"):
                    options = self.app.connection_service.resolve_ovh_connection(
                        instance, resolved.local_key_path,
                    )
                    host = options["host"]
                    username = options["username"]
                    key_path = options["key_path"]
                    ssh_cmd = self.app.ssh_service.build_ssh_command(**options)

                elif instance.get("is_custom"):
                    host = instance.get("public_ip") or instance.get("private_ip")
                    username = instance.get("username") or "root"
                    port = instance.get("port", 22)
                    key_path = resolved.local_key_path or instance.get("ssh_key") or None
                    proxy_args = []
                    extra_options = self.app.connection_service.get_extra_options(instance, None)
                    ssh_cmd = self.app.ssh_service.build_ssh_command(
                        host=host, username=username, key_path=key_path,
                        proxy_args=proxy_args, port=port, extra_options=extra_options,
                    )
                    logger.info(
                        "SSH connect (custom): host=%s, user=%s, port=%s", host, username, port,
                    )

                elif instance.get("is_shared") is True:
                    # A team's shared server with no team key here: the
                    # team's login and port, a key from ~/.ssh.
                    profile = self.app.connection_service.resolve_profile(instance)
                    host = self.app.connection_service.get_target_host(instance, profile)
                    username = (
                        (profile.username if profile else None)
                        or instance.get("username")
                        or self.app.config_manager.get().default_username
                    )
                    key_path = resolved.local_key_path
                    proxy_args = (
                        self.app.connection_service.get_proxy_args(profile, hop=hop) if profile else []
                    )
                    extra_options = self.app.connection_service.get_extra_options(instance, profile)
                    ssh_cmd = self.app.ssh_service.build_ssh_command(
                        host=host, username=username, key_path=key_path,
                        proxy_args=proxy_args, port=instance.get("port"),
                        extra_options=extra_options,
                    )
                    logger.info(
                        "SSH connect (team shared): host=%s, user=%s", host, username,
                    )

                elif instance.get("is_hetzner"):
                    host = instance.get("public_ip") or instance.get("private_ip")
                    username = instance.get("username") or "root"
                    config = self.app.config_manager.get()
                    key_path = (
                        resolved.local_key_path
                        or instance.get("ssh_key")
                        or config.default_key
                        or None
                    )
                    proxy_args = []
                    extra_options = self.app.connection_service.get_extra_options(instance, None)
                    ssh_cmd = self.app.ssh_service.build_ssh_command(
                        host=host, username=username, key_path=key_path,
                        proxy_args=proxy_args, port=None, extra_options=extra_options,
                    )
                    logger.info(
                        "SSH connect (hetzner): host=%s, user=%s, key=%s",
                        host, username, key_path,
                    )

                else:
                    # AWS / generic — resolve bastion profile
                    profile = self.app.connection_service.resolve_profile(instance)
                    host = self.app.connection_service.get_target_host(instance, profile)

                    if not host:
                        self.app.notify(
                            "No IP address available for this instance.", severity="error",
                        )
                        return

                    proxy_args = []
                    if profile:
                        proxy_args = self.app.connection_service.get_proxy_args(profile, hop=hop)

                    username = (
                        (profile.username if profile else None)
                        or self.app.config_manager.get().default_username
                    )
                    key_path = resolved.local_key_path

                    extra_options = self.app.connection_service.get_extra_options(instance, profile)
                    ssh_cmd = self.app.ssh_service.build_ssh_command(
                        host=host, username=username, key_path=key_path,
                        proxy_args=proxy_args, extra_options=extra_options,
                    )
                    via = f" via {profile.bastion_host}" if profile and profile.bastion_host else ""
                    logger.info(
                        "SSH connect: host=%s, user=%s, key=%s, proxy=%s, profile=%s",
                        host, username, key_path,
                        "yes" if proxy_args else "no",
                        profile.name if profile else "direct",
                    )

                if self.app.terminal_service.launch_ssh_in_terminal(ssh_cmd):
                    self.app.notify(
                        f"Local SSH fallback selected (resolution tier: local): {rich_escape(name)}",
                        severity="warning",
                        markup=True,
                    )
                    if not is_aws_row(instance):
                        self.app.notify(
                            f"Connected via local ~/.ssh: {rich_escape(name)}",
                            markup=True,
                        )
                    else:
                        via_str = via if not instance.get("is_ovh") and not instance.get("is_custom") and not instance.get("is_hetzner") else ""  # noqa: E501
                        self.app.notify(
                            f"Connected via local ~/.ssh: {rich_escape(name)}{via_str}",
                            markup=True,
                        )
                else:
                    terminal_error = getattr(self.app.terminal_service, "last_error", None)
                    self.app.notify(
                        terminal_error
                        if isinstance(terminal_error, str) and terminal_error
                        else "Could not detect terminal emulator. Set 'terminal_emulator' in settings.",
                        severity="error",
                        markup=False,
                    )

            except Exception as exc:
                logger.error("Error launching SSH terminal: %s", exc, exc_info=True)
                self.app.notify(
                    f"Error launching SSH: {rich_escape(str(exc))}",
                    markup=True,
                    severity="error",
                )

    def action_action_4(self) -> None:
        """SCP Transfer."""
        if not self._validate_instance_connection():
            return
        from servonaut.screens.scp_transfer import SCPTransferScreen
        self.app.push_screen(SCPTransferScreen(self._instance))

    def action_action_5(self) -> None:
        """View Scan Results."""
        if self._refuse_if_unresolved():
            return
        from servonaut.screens.scan_results import ScanResultsScreen
        self.app.push_screen(ScanResultsScreen(self._instance))

    def action_action_6(self) -> None:
        """View Logs — open real-time log viewer with tail -f."""
        if not self._validate_instance_connection():
            return
        from servonaut.screens.log_viewer import LogViewerScreen
        self.app.push_screen(LogViewerScreen(self._instance))

    def action_action_7(self) -> None:
        """AI Analysis — open AI log analysis screen."""
        if self._refuse_if_unresolved():
            return
        from servonaut.screens.ai_analysis import AIAnalysisScreen
        self.app.push_screen(AIAnalysisScreen(text="", instance=self._instance))

    def action_action_8(self) -> None:
        """Ban IP — open IP ban manager pre-filled with this instance's public IP."""
        if self._refuse_if_unresolved():
            return
        from servonaut.screens.ip_ban import IPBanScreen
        # Pre-fill what the screen shows; a ban of it targets the real address.
        shown_ip = self._instance.get('public_ip') or ""
        real_ip = connection_instance(self.app, self._instance).get('public_ip') or ""
        self.app.push_screen(IPBanScreen(prefill_ip=shown_ip, prefill_real_ip=real_ip))

    def action_open_memory(self) -> None:
        """Open MemoryScreen for this instance."""
        if self._refuse_if_unresolved():
            return
        from servonaut.screens.memory import MemoryScreen
        self.app.push_screen(MemoryScreen(self._instance))

    def action_scan_db_creds(self) -> None:
        """Open the DB-credential scan → review → store surface (B2)."""
        if self._refuse_if_unresolved():
            return
        from servonaut.screens.db_credential_scan import DbCredentialScanScreen
        self.app.push_screen(DbCredentialScanScreen(self._instance))

    def action_open_findings(self) -> None:
        """Open the findings inbox scoped to this instance."""
        if self._refuse_if_unresolved():
            return
        from servonaut.screens.findings import FindingsScreen
        self.app.push_screen(FindingsScreen(instance=self._instance))

    def _display_host(self) -> str:
        """The address as shown on this screen — a demo-mode fake when redacted."""
        return (
            self._instance.get("public_ip")
            or self._instance.get("private_ip")
            or self._instance.get("id", "")
        )

    def action_manage_ssh_ref(self) -> None:
        """Push SshRefEditorModal directly to add/edit/delete the BW SSH ref."""
        if self._refuse_if_unresolved():
            return
        self.run_worker(
            self._manage_ssh_ref_flow(),
            group="ssh_verify",
            exclusive=True,
        )

    def action_use_vault_key(self) -> None:
        """Bind a native-vault SSH item with the server's verified host pins."""
        # Starting again would cancel the binding midway (the worker is exclusive).
        if self._busy.holds("#btn_use_vault_key"):
            self.app.notify(
                "The vault key is still being bound: wait for it to finish.",
                severity="warning",
                markup=False,
            )
            return
        if self._refuse_if_unresolved():
            return

        async def flow() -> None:
            service = getattr(self.app, "vault_command_service", None)
            if service is None:
                self.app.notify("Vault services are unavailable.", severity="warning", markup=False)
                return
            instance = connection_instance(self.app, self._instance)
            # Set when a team's key is bound to this server of your own.
            own: Optional[dict[str, Any]] = None
            teams = self._sharing_teams()
            selected_team = ""
            if teams:
                selected_team = await self.app.push_screen_wait(
                    VaultBindingScopeModal(teams)
                )
                if selected_team is None:
                    return
                if selected_team:
                    target = self._team_binding_target(selected_team)
                    if target is None:
                        return
                    own, instance = instance, target
            server = str(instance.get("id") or "")
            if not server:
                self.app.notify("This server has no usable identifier.", severity="error", markup=False)
                return
            values = await self.app.push_screen_wait(VaultBindingModal(service, instance, own_instance=own))
            if not values:
                return
            if selected_team and self._team_binding_target(
                selected_team, server=server,
            ) is None:
                return
            host_keys = [key.strip() for key in values["host_keys"].split(",") if key.strip()]
            job = self._busy.begin("Binding the vault key to this server…", hold=("#btn_use_vault_key",))
            try:
                if values["team"]:
                    # Without typed keys, the keys this machine already trusts are pinned.
                    result = await service.bind(
                        vault_id=values["vault_id"], server=server, item_id=values["item_id"],
                        team=values["team"], login=values["login"], pin_host_key=True,
                        host_keys=tuple(host_keys), own_rows=[own] if own is not None else [],
                    )
                else:
                    if not host_keys:
                        self.app.notify(
                            "Personal-server binding requires verified OpenSSH host keys.",
                            severity="warning",
                            markup=False,
                        )
                        return
                    from servonaut.services.vault.personal_targets import instance_provider

                    # A custom server is addressed by name (provider "custom").
                    custom = instance.get("is_custom") is True
                    provider = instance_provider(instance)
                    # Pin the address SSH reaches: the private one behind a bastion.
                    destination, port = service.ssh_destination(instance)
                    hostname = str(destination or "")
                    login = values["login"] or instance.get("username")
                    if not hostname:
                        self.app.notify(
                            "This server has no address to connect to, so no vault key can be bound to it.",
                            severity="warning",
                            markup=False,
                        )
                        return
                    if not isinstance(port, int) or not isinstance(login, str) or not login:
                        self.app.notify(
                            "The personal server needs a numeric port and login user.",
                            severity="warning",
                            markup=False,
                        )
                        return
                    result = await service.bind_personal(
                        vault_id=values["vault_id"],
                        item_id=values["item_id"],
                        provider=provider,
                        instance_id=str(instance.get("name") or "") if custom else server,
                        hostname=hostname,
                        port=port,
                        login=login,
                        host_keys=host_keys,
                    )
            except Exception as exc:
                from servonaut.services.vault.errors import HostKeysNeeded, vault_failure_reason

                reason = (
                    "this machine does not trust a host key for the server yet: use Fetch host key "
                    "(or connect to it once) and check its fingerprint, or paste verified host keys"
                    if isinstance(exc, HostKeysNeeded) else vault_failure_reason(exc)
                )
                # Kept for later: the notice goes once it is closed.
                logger.warning(
                    "Vault key binding failed for %s: %s",
                    log_safe(self.app, display_name(instance) or "server"), log_safe(self.app, reason),
                )
                self.app.notify(f"Vault key binding failed: {reason}", severity="error", markup=False)
                return
            finally:
                self._busy.end(job)
            source = result.get("source") if isinstance(result, dict) else None
            source = source if isinstance(source, str) and source else _VAULT_SOURCE
            label = credential_source_label(source) or "Servonaut Vault"
            if values["team"]:
                self._remember_team_binding(instance, result)
                scope = _team_key_label(instance)
            else:
                self._vault_binding_source = source
                scope = "Your key"
            # The other SSH paths must not reuse a lease for the previous key.
            leases = getattr(self.app, "vault_lease_cache", None)
            if leases is not None:
                leases.forget(instance)
                if values["team"]:
                    leases.forget(connection_instance(self.app, self._instance))
            if self.is_mounted:
                self._render_server_info()
            scope = scrub_for_display(self.app, scope)
            message = f"Vault key bound. {scope}: {label}."
            if selected_team and self._instance.get("is_shared") is not True:
                own = await self._own_binding_after_team_bind(service, values, result)
                if own:
                    message += f" {scrub_for_display(self.app, own)}"
            self.app.notify(message, markup=False)

        self.run_worker(flow(), group="vault", exclusive=True)

    async def _own_binding_after_team_bind(
        self, service: Any, values: Mapping[str, Any], result: object,
    ) -> Optional[str]:
        """Offer to move the user's own binding to the team key just set on their own server.

        The own row connects with the user's personal binding first, so a
        team key with another key or login changes nothing for the user
        until they agree to update their own. Returns the sentence to add to
        the outcome; None when they have no personal binding or it matches.
        """
        from servonaut.services.vault.errors import vault_failure_reason
        from servonaut.services.vault.personal_targets import instance_provider

        own = connection_instance(self.app, self._instance)
        try:
            personal = await service.personal_binding(own)
        except Exception:  # noqa: BLE001 — unknown, so nothing is offered or claimed
            logger.debug("Could not read the own binding after a team bind", exc_info=True)
            return None
        if not isinstance(personal, Mapping):
            return None
        team = result.get("credential_binding", result) if isinstance(result, Mapping) else None
        team = team if isinstance(team, Mapping) else {}
        own_login = str(personal.get("login_user") or "")
        team_login = str(team.get("login_user") or values.get("login") or "")
        same_key = bool(team.get("public_fingerprint")) and (
            personal.get("public_fingerprint") == team.get("public_fingerprint")
        )
        kept = f"You still connect with your own key, as {own_login}." if own_login else (
            "You still connect with your own key."
        )
        if same_key and own_login == team_login:
            return "You keep connecting with your key."
        host_keys = [key for key in team.get("host_keys") or [] if isinstance(key, str) and key]
        destination, port = service.ssh_destination(own)
        if not team_login or not host_keys or not destination or not isinstance(port, int):
            return kept
        changes = [
            change for change, differs in (
                ("the team's key", not same_key), (f"the login {team_login}", own_login != team_login),
            ) if differs
        ]
        body = (
            f"You connect to this server with your own vault key{f', as {own_login}' if own_login else ''}. "
            f"The team key you just set logs in as {team_login}.\n\n"
            f"Update your own binding to {' and '.join(changes)}? "
            "It pins the same host keys as the team key."
        )
        if not await self.app.push_screen_wait(OwnKeyUpdateModal(scrub_for_display(self.app, body))):
            return kept
        custom = own.get("is_custom") is True
        try:
            await service.bind_personal(
                vault_id=values["vault_id"], item_id=values["item_id"],
                provider=instance_provider(own),
                instance_id=str(own.get("name") or "") if custom else str(own.get("id") or ""),
                hostname=str(destination), port=port, login=team_login, host_keys=host_keys,
            )
        except Exception as exc:  # noqa: BLE001 — the team key is bound either way
            return f"Your own key was not updated ({vault_failure_reason(exc)}). {kept}"
        leases = getattr(self.app, "vault_lease_cache", None)
        if leases is not None:
            leases.forget(own)
        return f"Your own key now uses the team's key, as {team_login}."

    def _team_binding_target(
        self, slug: str, *, server: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """Check the selected team is still shared and the user can set its key."""
        target = next(
            (row for row in self._sharing_teams() if row["team_slug"] == slug), None,
        )
        if (
            target is not None and _can_bind_team(target)
            and (server is None or target.get("id") == server)
        ):
            return target
        self.app.notify(
            "This team is no longer available for binding. "
            "Only a team owner or admin can set its key.",
            severity="warning", markup=False,
        )
        return None

    def _remember_team_binding(
        self, target: dict[str, Any], result: object,
    ) -> None:
        """Keep the team's row current without changing the own row's credential."""
        if not isinstance(result, Mapping):
            return
        binding = result.get("credential_binding", result)
        # This cache is authoritative for SSH: a write receipt must not replace it.
        if (
            not isinstance(binding, Mapping) or binding.get("source") != _VAULT_SOURCE
            or binding.get("valid") is not True or not binding.get("signature")
        ):
            return
        binding = dict(binding)
        rows = team_rows(self.app)
        target_id = (target.get("team_slug"), target.get("id"))
        for row in rows:
            if (row.get("team_slug"), row.get("id")) != target_id:
                continue
            row["credential_binding"] = binding
            if binding.get("login_user"):
                row["login_user"] = binding["login_user"]
        replace_instances(self.app, "shared", rows)
        if self._instance.get("is_shared") is True:
            self._instance["credential_binding"] = binding

    async def _manage_ssh_ref_flow(self) -> None:
        """Fetch existing ref then open SshRefEditorModal in add or edit mode."""
        if not getattr(self.app, "bw_ssh_config_service", None):
            self.app.notify(
                "BW SSH service not available (sign in required)",
                severity="warning",
                markup=False,
            )
            return

        conn = connection_instance(self.app, self._instance)
        provider = conn.get("provider", "aws").lower()
        instance_id = conn.get("id")

        try:
            existing = await self.app.bw_ssh_config_service.get_personal_instance_ref(
                provider, instance_id
            )
        except Exception as exc:
            from servonaut.services.api_client import APIError
            if (
                isinstance(exc, APIError)
                and exc.status == 500
                and exc.code == "decrypt_failed"
            ):
                # A ref IS stored, but the server couldn't decrypt it — don't
                # collapse this to "no ref" and open the editor in add mode.
                self.app.notify(
                    "An SSH ref is stored for this instance, but the server "
                    "could not decrypt it (the vault key or enrollment likely "
                    "changed). Re-enroll this device or re-save the ref to fix.",
                    severity="error",
                    markup=False,
                )
                return
            logger.debug("Failed to load existing SSH ref: %s", exc)
            existing = None

        from servonaut.screens.ssh_ref_editor import SshRefEditorModal
        saved = await self.app.push_screen_wait(
            SshRefEditorModal(self._instance, existing_ref=existing)
        )
        if saved:
            # Refresh SSH verify column in instance list if possible.
            if hasattr(self.app, "_refresh_ssh_verify_status"):
                self.app.run_worker(
                    self.app._refresh_ssh_verify_status(),
                    group="memory_io",
                )

    def action_verify_ssh(self) -> None:
        """Launch the Verify SSH flow: show confirm modal, then run worker."""
        if self._refuse_if_unresolved():
            return
        self.run_worker(
            self._verify_ssh_flow(),
            group="ssh_verify",
            exclusive=True,
        )

    async def _verify_ssh_flow(self) -> None:
        """Async flow: modal → BW resolve → probe → report → refresh.

        A server bound to a Servonaut Vault key is checked with that key
        instead; it needs no Bitwarden ref.
        """
        if self._binding_source() != _VAULT_SOURCE:
            looked_up = await self._lookup_vault_binding_source()
            if looked_up is not None and looked_up != self._vault_binding_source:
                self._vault_binding_source = looked_up
                if self.is_mounted:
                    self._render_server_info()
        if self._binding_source() == _VAULT_SOURCE:
            await self._verify_with_vault()
            return

        bw_service = getattr(self.app, "bw_ssh_config_service", None)
        if bw_service is None:
            self.app.notify(
                "SSH verify requires a Servonaut account. Sign in via Settings → Login.",
                severity="warning",
                markup=False,
            )
            return

        conn = connection_instance(self.app, self._instance)
        provider = conn.get("provider", "aws").lower()
        instance_id = conn.get("id", "")
        host = (
            conn.get("public_ip")
            or conn.get("private_ip")
            or instance_id
        )
        # The confirm dialog is on screen: it shows the row as displayed
        # (a demo-mode fake); the probe itself uses the real host above.
        shown_host = self._display_host()

        # Check if a BW ref is stored for this instance.
        try:
            ref_row = await bw_service.get_personal_instance_ref(provider, instance_id)
        except Exception as exc:
            from servonaut.services.api_client import APIError
            if (
                isinstance(exc, APIError)
                and exc.status == 500
                and exc.code == "decrypt_failed"
            ):
                # A ref IS stored, but the server couldn't decrypt it — don't
                # collapse this to "no ref" and reopen the editor.
                self.app.notify(
                    "An SSH ref is stored for this instance, but the server "
                    "could not decrypt it (the vault key or enrollment likely "
                    "changed). Re-enroll this device or re-save the ref to fix.",
                    severity="error",
                    markup=False,
                )
                return
            logger.debug("SSH verify ref lookup failed: %s", exc)
            ref_row = None

        has_ref = ref_row is not None

        # Push the confirm modal and await user's choice.
        confirmed = await self.app.push_screen_wait(
            ConfirmSshVerifyModal(host=shown_host, has_ref=has_ref)
        )
        if not confirmed:
            return

        # No ref stored → open SshRefEditorModal so the user can add one.
        if not has_ref:
            from servonaut.screens.ssh_ref_editor import SshRefEditorModal
            await self.app.push_screen_wait(
                SshRefEditorModal(self._instance, existing_ref=None)
            )
            return

        # Resolve BW item and run the SSH probe.
        ssh_credential_ref = ref_row.get("ssh_credential_ref", {})
        item_id: Optional[str] = ssh_credential_ref.get("item_id") if isinstance(ssh_credential_ref, dict) else None
        if item_id is None:
            # Partial row: the server confirmed a ref exists but this device
            # holds no local copy of the item id (see get_personal_instance_ref
            # fallbacks). Probe still runs with local keys; say so.
            self.app.notify(
                "A stored SSH ref exists but its vault item isn't available on "
                "this device — using the local fallback (resolution tier: local) "
                "for verification. Re-save the ref here to enable Bitwarden-backed verify.",
                severity="warning",
                markup=False,
            )

        resolution_tier = "personal" if item_id is not None else "local"
        status = await self._run_ssh_probe(item_id, host)

        # Report the result to the server.
        try:
            import servonaut as _sn_pkg
            client_version = f"servonaut-cli/{getattr(_sn_pkg, '__version__', 'unknown')}"
            await bw_service.report_personal_instance_verify(
                provider=provider,
                instance_id=instance_id,
                status=status,
                checked_by_client=client_version,
                resolution_tier=resolution_tier,
            )
        except Exception as exc:
            from servonaut.services.api_client import APIError
            if isinstance(exc, APIError) and exc.status == 402:
                self.app.notify(
                    "SSH verify reporting requires a paid Servonaut plan.",
                    severity="warning",
                    markup=False,
                )
            else:
                logger.warning("SSH verify report POST failed: %s", exc)
            # Don't abort — update local state anyway.

        # Update the instance dict in memory and re-render the table.
        from datetime import datetime, timezone
        self._instance["ssh_verify_status"] = status
        if status == "verified":
            self._instance["ssh_verified_at"] = (
                datetime.now(timezone.utc).isoformat()
            )
        else:
            self._instance.pop("ssh_verified_at", None)

        # Propagate into app.instances so the table refresh picks it up.
        for inst in self.app.instances:
            if inst.get("id") == instance_id:
                inst["ssh_verify_status"] = status
                if status == "verified":
                    inst["ssh_verified_at"] = self._instance.get("ssh_verified_at")
                else:
                    inst.pop("ssh_verified_at", None)
                break

        # Surface the result.
        _status_labels = {
            "verified": "SSH verified successfully.",
            "not_found": "SSH probe: host not found or unreachable.",
            "auth_failed": "SSH probe: authentication failed.",
        }
        host_key_message = getattr(self, "_ssh_probe_host_key_message", None)
        if host_key_message:
            # A refused host key is reported as such, not as "unreachable".
            self.app.notify(
                host_key_message, severity="error", markup=False, timeout=20,
            )
        else:
            label = _status_labels.get(status, f"SSH probe status: {status}")
            self.app.notify(label, markup=False)

        # Refresh the instance list table if it's behind this screen.
        try:
            from servonaut.screens.instance_list import InstanceListScreen
            for screen in self.app.screen_stack:
                if isinstance(screen, InstanceListScreen):
                    screen._update_table()
                    break
        except Exception:
            pass

    async def _verify_with_vault(self) -> None:
        """Check SSH with this server's Servonaut Vault key and say how it went."""
        import asyncio

        confirmed = await self.app.push_screen_wait(
            ConfirmSshVerifyModal(host=self._display_host(), has_ref=False, vault=True)
        )
        if not confirmed:
            return
        instance = connection_instance(self.app, self._instance)
        resolver = await self._ssh_ref_resolver()
        try:
            resolved = await resolver.resolve(instance)
        except Exception as exc:  # Configured native credentials fail closed.
            from servonaut.services.vault.errors import vault_failure_reason

            self.app.notify(
                f"The configured Vault SSH credential could not be used ({vault_failure_reason(exc)}).",
                severity="error",
                markup=False,
            )
            return
        if resolved is None or resolved.source not in ("ca", "vault"):
            self.app.notify(
                "This server's Servonaut Vault key could not be loaded, so SSH was not checked.",
                severity="error",
                markup=False,
            )
            return
        ok, hop = await self._bastion_hop(instance)
        if not ok:
            return
        cmd = self._native_ssh_command(
            instance, resolved, remote_command="true",
            options=("BatchMode=yes", "ConnectTimeout=5"), hop=hop,
        )
        if cmd is None:
            return
        try:
            # No terminal to prompt on; ssh's messages go to a private log.
            proc = await asyncio.to_thread(run_ssh, cmd, capture_output=True, timeout=15)
        except subprocess.TimeoutExpired:
            self.app.notify(
                "The SSH check with the Servonaut Vault key timed out.", severity="error", markup=False
            )
            return
        except FileNotFoundError:
            self.app.notify("ssh binary not found on PATH — cannot run probe.", severity="error", markup=False)
            return
        if proc.returncode == 0:
            self.app.notify("SSH verified with the Servonaut Vault key.", markup=False)
        elif proc.returncode == 255:
            self.app.notify(
                "SSH with the Servonaut Vault key failed: the server could not be reached, "
                "or its host key does not match the pinned one.",
                severity="error",
                markup=False,
            )
        else:
            self.app.notify(
                f"SSH with the Servonaut Vault key failed (exit {proc.returncode}).",
                severity="error",
                markup=False,
            )

    async def _run_ssh_probe(self, item_id: Optional[str], host: str) -> str:
        """Resolve BW item and run BatchMode SSH probe. Returns status string."""
        import asyncio

        # Resolve the private key from Bitwarden (synchronous CLI call — run in thread).
        private_key_body: Optional[str] = None
        if item_id:
            try:
                from servonaut.services.bw_resolver import (
                    BwResolver,
                )
                bw_session = getattr(self.app, "bw_session_service", None)
                resolver = BwResolver(
                    session_getter=bw_session.session if bw_session is not None else None
                )
                private_key_body = await asyncio.to_thread(
                    resolver.resolve_ssh_key, item_id
                )
            except Exception as exc:
                logger.debug("BW item resolution failed for %s: %s", item_id, exc)
                return "not_found"

        # Write the key to a temp file so ssh can use it.
        import tempfile
        import os
        import stat
        if private_key_body:
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    suffix=".pem",
                    delete=False,
                    prefix="servonaut_sshverify_",
                ) as tf:
                    tf.write(private_key_body)
                    tmp_key_path: Optional[str] = tf.name
                os.chmod(tmp_key_path, stat.S_IRUSR | stat.S_IWUSR)
            except Exception as exc:
                logger.debug("Temp key write failed: %s", exc)
                return "not_found"
        else:
            tmp_key_path = None

        self._ssh_probe_host_key_message = None
        try:
            conn = connection_instance(self.app, self._instance)
            host_key_policy = HostKeyPolicy.from_ssh_config(
                self.app.config_manager.get().ssh
            )
            cmd = [
                "ssh",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=5",
                # ``off`` keeps this probe's previous argv (no /dev/null).
                *host_key_policy.ssh_options(off_options=OFF_OPTIONS_KEEP_KNOWN_HOSTS),
            ]
            for option in host_key_alias_options(conn, host_key_policy):
                cmd += ["-o", option]
            if tmp_key_path:
                cmd += [*identity_file_args(tmp_key_path), "-o", "IdentitiesOnly=yes"]
            port = self.app.connection_service.get_target_port(conn)
            if port is not None and port != 22:
                cmd += ["-p", str(port)]
            # Use the configured username or default.
            username = (
                self._instance.get("username")
                or self.app.config_manager.get().default_username
                or "root"
            )
            # "--" ends option parsing before the destination.
            cmd += ["--", f"{username}@{host}", "true"]

            # No terminal to prompt on; ssh's messages go to a private log.
            proc = await asyncio.to_thread(
                run_ssh,
                cmd,
                capture_output=True,
                timeout=15,
            )
            rc = proc.returncode
            if rc == 0:
                return "verified"
            problem = detect_host_key_problem(
                getattr(proc, "diagnostics", "") or "", rc,
                HostKeyTarget.for_connection(host, port, instance=conn),
                host_key_policy, stdout=proc.stdout,
            )
            if problem is not None:
                self._ssh_probe_host_key_message = problem.message
            # Exit code 255: SSH layer failure (host unreachable, key mismatch)
            # Exit code 1–254: auth issues or remote command failure
            return "auth_failed" if rc != 255 else "not_found"
        except subprocess.TimeoutExpired:
            return "not_found"
        except FileNotFoundError:
            # ssh binary not on PATH
            self.app.notify(
                "ssh binary not found on PATH — cannot run probe.",
                severity="error",
                markup=False,
            )
            return "not_found"
        except Exception as exc:
            logger.debug("SSH probe subprocess error: %s", exc)
            return "not_found"
        finally:
            if tmp_key_path:
                try:
                    os.unlink(tmp_key_path)
                except OSError:
                    pass

    def action_back(self) -> None:
        """Close an open inline view, or navigate back to the instance list.

        When a file tree / log view is open inline, Esc (and "9") first closes
        it and returns focus to the rail; a second press leaves the screen.
        """
        if self._inline_view is not None:
            self._clear_inline()
            self._safe_focus("#btn_browse")
            return
        self.app.pop_screen()


# ---------------------------------------------------------------------------
# Null-object stubs used by _ssh_connect_flow when API services are absent
# ---------------------------------------------------------------------------

class _NullBwService:
    """Drop-in for BwSshConfigService when the user is not logged in.

    Every method the resolver calls returns ``None`` immediately so the
    personal tier silently passes through to the local fallback.
    """

    async def get_personal_instance_ref(
        self, provider: str, instance_id: str
    ) -> None:
        return None


class _NullTeamService:
    """Drop-in for TeamService when the user is not logged in."""

    async def get_team_server_ssh_ref(
        self, slug: str, server_id: str
    ) -> None:
        return None

    async def list_teams(self) -> list:
        return []
