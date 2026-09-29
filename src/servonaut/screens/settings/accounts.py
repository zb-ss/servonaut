"""Provider accounts in the settings panels and setup wizards.

Each provider panel (AWS, Hetzner, OVH) ends with an Accounts section: the
primary account (the provider block itself) and any extra accounts, with
actions to add, edit and remove them. AWS accounts carry no secrets and are
edited inline (see ``aws_accounts.py``); Hetzner and OVH accounts are edited
in their setup wizards, which own every credential of those providers.

The helpers below are shared by the sections and the wizards: label rules,
demo-mode display, and moving the fleet to the saved accounts.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Optional, Tuple

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Static

from servonaut.config.accounts import (
    PROVIDER_TITLES,
    PROVIDERS,
    account_problems,
    describe_account_problems,
    label_problem,
    primary_label,
    primary_label_problems,
)
from servonaut.screens._provider_accounts import shown_label

logger = logging.getLogger(__name__)

# AWS region names: "eu-west-1", "us-gov-west-1", "ap-southeast-3".
_AWS_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d{1,2}$")

# Characters an account label may not contain (see LABEL_RE).
_LABEL_INVALID_RE = re.compile(r"[^A-Za-z0-9_.-]+")


@dataclass(frozen=True)
class AccountRow:
    """One row of an accounts table: the primary account or extra *index*."""

    label: str
    index: Optional[int] = None  # None: the primary account

    @property
    def primary(self) -> bool:
        return self.index is None


# ---------------------------------------------------------------------------
# Label rules
# ---------------------------------------------------------------------------


def provider_block(config: Any, provider: str) -> Any:
    """The provider's config block (the primary account)."""
    return getattr(config, provider)


def taken_labels(
    config: Any, *, skip: Optional[Tuple[str, Optional[int]]] = None
) -> Dict[str, str]:
    """Every account label in use, lower-cased, mapped to its account's title.

    *skip* leaves one account out, ``(provider, None)`` for a primary and
    ``(provider, index)`` for an extra, so an account can keep its own label.
    """
    taken: Dict[str, str] = {}
    for provider in PROVIDERS:
        block = provider_block(config, provider)
        title = PROVIDER_TITLES[provider]
        if skip != (provider, None):
            label = primary_label(provider, block)
            taken.setdefault(label.lower(), f"{title} · {label}")
        for index, extra in enumerate(block.accounts):
            label = (extra.label or "").strip()
            if label and skip != (provider, index):
                taken.setdefault(label.lower(), f"{title} · {label}")
    return taken


def label_error(
    config: Any, provider: str, label: str, *, index: Optional[int] = None
) -> Optional[str]:
    """Why *label* cannot name an account, as a sentence, or None when it can.

    ``index`` None is the primary account, whose empty label means the
    provider name. Labels are unique across every provider, ignoring case.
    """
    label = (label or "").strip()
    effective = label or (provider if index is None else "")
    problem = label_problem(effective)
    if problem is not None:
        return f"{problem[0].upper()}{problem[1:]}."
    holder = taken_labels(config, skip=(provider, index)).get(effective.lower())
    if holder is not None:
        return f"The label {effective!r} is already used by {holder}."
    return None


def suggest_label(name: str, config: Any) -> str:
    """A free, valid label derived from *name* (a profile name, say)."""
    from servonaut.config.schema import ACCOUNT_LABEL_MAX_LENGTH

    base = _LABEL_INVALID_RE.sub("-", name or "").strip("._-") or "account"
    base = base[:ACCOUNT_LABEL_MAX_LENGTH]
    if label_problem(base) is not None:  # "custom" is reserved
        base = f"{base[:ACCOUNT_LABEL_MAX_LENGTH - 8]}-account"
    taken = taken_labels(config)
    candidate, number = base, 2
    while candidate.lower() in taken:
        suffix = f"-{number}"
        candidate = f"{base[:ACCOUNT_LABEL_MAX_LENGTH - len(suffix)]}{suffix}"
        number += 1
    return candidate


def parse_regions(text: str) -> List[str]:
    """Regions typed as ``eu-west-1, us-east-1`` (commas or spaces).

    Raises:
        ValueError: A name that is not an AWS region name.
    """
    regions: List[str] = []
    for item in re.split(r"[,\s]+", text or ""):
        region = item.strip().lower()
        if not region:
            continue
        if not _AWS_REGION_RE.match(region):
            raise ValueError(f"{item.strip()!r} is not an AWS region name (e.g. eu-west-1).")
        if region not in regions:
            regions.append(region)
    return regions


# ---------------------------------------------------------------------------
# Demo mode
# ---------------------------------------------------------------------------


def demo_redaction(app: Any) -> Any:
    """The redaction service while demo mode is on, else None."""
    if not getattr(app, "demo_mode", False):
        return None
    return getattr(app, "redaction_service", None)


def shown_profile(app: Any, profile: str) -> str:
    """An AWS profile name as the screen shows it (a stand-in in demo mode)."""
    redaction = demo_redaction(app)
    if redaction is None or not profile:
        return profile
    return redaction.redact_name(profile)


def shown_text(app: Any, config: Any, text: str) -> str:
    """*text* with every account label and AWS profile hidden in demo mode.

    Problem sentences and refresh errors name accounts; one pass replaces
    all of them, so a stand-in is never itself replaced again.
    """
    redaction = demo_redaction(app)
    if redaction is None or not text:
        return text
    names: Dict[str, str] = {}
    for provider in PROVIDERS:
        block = provider_block(config, provider)
        names[primary_label(provider, block)] = shown_label(app, primary_label(provider, block))
        for extra in block.accounts:
            label = (extra.label or "").strip()
            if label:
                names[label] = shown_label(app, label)
    profiles = [config.aws.profile] + [extra.profile for extra in config.aws.accounts]
    for profile in profiles:
        profile = (profile or "").strip()
        if profile and profile not in names:
            names[profile] = shown_profile(app, profile)
    # Case-insensitive: some messages carry an account's lower-cased key.
    hidden = {real.lower(): fake for real, fake in names.items() if real != fake}
    if hidden:
        pattern = re.compile(
            r"(?<![A-Za-z0-9_.-])("
            + "|".join(re.escape(n) for n in sorted(hidden, key=len, reverse=True))
            + r")(?![A-Za-z0-9_.-])",
            re.IGNORECASE,
        )
        text = pattern.sub(lambda match: hidden[match.group(1).lower()], text)
    return redaction.scrub_stream(text)


# ---------------------------------------------------------------------------
# Status and problems
# ---------------------------------------------------------------------------


def _unavailable(app: Any) -> Dict[str, str]:
    registry = getattr(app, "accounts", None)
    return dict(getattr(registry, "unavailable", None) or {})


def provider_off(config: Any, provider: str) -> bool:
    """True when *provider* is switched off (Hetzner and OVH only).

    The AWS provider is always listed: its switch predates the account
    registry and has never stopped the fleet from loading.
    """
    return provider != "aws" and not provider_block(config, provider).enabled


def account_status(app: Any, config: Any, provider: str, row: AccountRow) -> str:
    """A one-word state for the table; the reasons are listed under it."""
    if provider_off(config, provider):
        return "provider off"
    if row.primary:
        own = f"{PROVIDER_TITLES[provider]} primary"
        if any(p.startswith(own) for p in primary_label_problems(config)):
            return "check label"
    elif (provider, row.index) in account_problems(config):
        return "skipped"
    if f"{provider}:{row.label.lower()}" in _unavailable(app):
        return "unavailable"
    return "primary" if row.primary else "active"


def provider_problems(app: Any, config: Any, provider: str) -> List[str]:
    """Every sentence about *provider*'s accounts: skipped, unusable, doubled."""
    title = PROVIDER_TITLES[provider]
    messages = [m for m in describe_account_problems(config) if m.startswith(f"{title} ")]
    if not provider_off(config, provider):
        block = provider_block(config, provider)
        labels = {primary_label(provider, block).lower(): primary_label(provider, block)}
        labels.update(
            ((a.label or "").strip().lower(), (a.label or "").strip()) for a in block.accounts
        )
        for key, reason in sorted(_unavailable(app).items()):
            owner, _, label_key = key.partition(":")
            if owner == provider:
                label = labels.get(label_key, label_key)
                messages.append(f"{title} account {label!r} is not available: {reason}")
    inventory = _inventory(app, provider)
    duplicates = getattr(inventory, "duplicate_accounts", None) or {}
    for later, earlier in sorted(duplicates.items()):
        messages.append(
            f"{title} account {later!r} lists the same servers as {earlier!r}; "
            f"remove one of them."
        )
    return messages


# ---------------------------------------------------------------------------
# Saving
# ---------------------------------------------------------------------------


def _inventory(app: Any, provider: str) -> Any:
    lookup = getattr(app, "provider_inventory", None)
    if not callable(lookup):
        return None
    try:
        return lookup(provider)
    except Exception as exc:  # a broken registry must not break Settings
        logger.warning("Reading the %s inventory failed: %s", provider, exc)
        return None


def rebuild_accounts(app: Any) -> bool:
    """Move every surface to the saved accounts; False when that failed."""
    rebuild = getattr(app, "rebuild_accounts", None)
    if not callable(rebuild) or getattr(app, "accounts", None) is None:
        return False
    try:
        rebuild()
    except Exception as exc:  # the config is saved; the next start picks it up
        logger.error("Rebuilding provider accounts failed: %s", exc)
        app.notify(
            f"Saved, but the accounts could not be reloaded: {exc}. "
            "Restart Servonaut to use them.",
            severity="error",
            markup=False,
        )
        return False
    return True


def _replace_slice(app: Any, provider: str, rows: Iterable[dict]) -> None:
    from servonaut.screens._demo_resolve import replace_instances

    replace_instances(app, provider, rows)


async def reload_provider_fleet(app: Any, provider: str) -> Tuple[List[dict], Optional[str]]:
    """Refresh every account of *provider* and make its rows the fleet's slice.

    Returns the rows and the refresh error (labelled per account when the
    provider has several); raises only when every account failed.
    """
    inventory = _inventory(app, provider)
    if inventory is None:
        _replace_slice(app, provider, [])
        return [], None
    rows = await inventory.fetch_instances_cached(force_refresh=True)
    rows = list(rows or [])
    _replace_slice(app, provider, rows)
    error = getattr(inventory, "last_fetch_error", None)
    return rows, error if isinstance(error, str) and error else None


def refresh_provider_fleet(app: Any, provider: str) -> None:
    """Show the saved accounts in the fleet now, then refresh them.

    The cached rows are re-tagged at once, so a renamed or removed account
    never lingers in the server list; the refresh then lists a new account's
    servers and picks up a changed profile, token or region list.
    """
    inventory = _inventory(app, provider)
    try:
        cached = inventory.get_cached_instances() if inventory is not None else []
        _replace_slice(app, provider, cached)
    except Exception as exc:  # the refresh below still runs
        logger.warning("Re-listing cached %s servers failed: %s", provider, exc)
    if inventory is None or not callable(getattr(app, "run_worker", None)):
        return
    app.run_worker(
        _refresh_in_background(app, provider),
        name=f"{provider}_accounts_refresh",
        group=f"{provider}_accounts_refresh",
        exclusive=True,
        exit_on_error=False,
    )


async def _refresh_in_background(app: Any, provider: str) -> None:
    title = PROVIDER_TITLES[provider]
    config = app.config_manager.get()
    try:
        rows, error = await reload_provider_fleet(app, provider)
    except Exception as exc:  # any provider SDK error; nothing to keep
        logger.warning("%s refresh after an accounts change failed: %s", title, exc)
        app.notify(
            f"{title} refresh failed: {shown_text(app, config, str(exc))}",
            severity="warning",
            markup=False,
        )
        return
    if error:
        app.notify(
            f"{title} refresh incomplete. {shown_text(app, config, error)}",
            severity="warning",
            markup=False,
        )
        return
    accounts = len(getattr(_inventory(app, provider), "refs", None) or []) or 1
    plural = "s" if accounts != 1 else ""
    app.notify(
        f"{title}: {len(rows)} server(s) from {accounts} account{plural}.",
        severity="information",
        markup=False,
    )


def save_extra_accounts(app: Any, provider: str, accounts: List[Any]) -> None:
    """Write *accounts* as *provider*'s extra accounts (keeps everything else)."""
    config = app.config_manager.get()
    block = provider_block(config, provider)
    app.config_manager.update(**{provider: replace(block, accounts=accounts)})


# ---------------------------------------------------------------------------
# Section widget
# ---------------------------------------------------------------------------


class AccountsSection(Vertical):
    """The Accounts section of one provider's settings panel.

    Lists the primary account and the extra ones with their state, the
    reasons an account is skipped or unusable, and actions on them.
    Subclasses name the columns, draw a row and add or edit accounts;
    removing an extra account is shared.
    """

    PROVIDER: str = ""
    # What one account of this provider is called ("project" for Hetzner).
    NOUN: str = "account"
    HEADING: str = "Accounts"
    HELP: str = ""
    COLUMNS: Tuple[str, ...] = ("Label",)

    # Unscoped: the narrow-terminal rule below starts from the Settings
    # screen's -narrow class. Every rule names AccountsSection itself or
    # the section's own classes. Button rules end in a class of their own,
    # so Textual rejects every other button without walking its ancestors.
    SCOPED_CSS = False

    DEFAULT_CSS = """
    AccountsSection {
        height: auto;
        margin: 1 0 0 0;
    }
    AccountsSection .accounts-heading {
        height: auto;
    }
    AccountsSection .accounts-help {
        height: auto;
        color: $text-muted;
        padding: 0 1 1 0;
    }
    AccountsSection .accounts-table {
        height: auto;
        max-height: 10;
    }
    AccountsSection .accounts-problems {
        height: auto;
        color: $warning;
        padding: 1 1 0 0;
    }
    AccountsSection .accounts-actions {
        height: auto;
        margin: 1 0 0 0;
    }
    .accounts-action {
        width: auto;
        margin: 0 1 0 0;
    }
    /* A narrow panel cannot hold every action in one row: two per row,
       each column as wide as its longest label so no label is cut. */
    SettingsScreen.-narrow AccountsSection .accounts-actions {
        layout: grid;
        grid-size: 2;
        grid-columns: auto 1fr;
        grid-rows: auto;
        grid-gutter: 0 1;
    }
    SettingsScreen.-narrow .accounts-action {
        margin: 0;
    }
    """

    def __init__(self, *, heading_classes: str = "") -> None:
        super().__init__(id=f"{self.PROVIDER}_accounts", classes="accounts-section")
        self._heading_classes = heading_classes
        self._rows: List[AccountRow] = []

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        p = self.PROVIDER
        yield Static(self.HEADING, classes=f"accounts-heading {self._heading_classes}".strip())
        yield Static(self.HELP, classes="accounts-help")
        yield DataTable(id=f"{p}_accounts_table", classes="accounts-table")
        yield Static("", id=f"{p}_accounts_problems", classes="accounts-problems")
        yield Horizontal(*self.action_buttons(), classes="accounts-actions")
        yield from self.form_rows()

    def action_buttons(self) -> List[Button]:
        """The Add / Edit / Remove buttons (subclasses may add more)."""
        p = self.PROVIDER
        return [
            Button(
                f"Add {self.NOUN}",
                id=f"btn_{p}_account_add",
                variant="primary",
                classes="accounts-action",
            ),
            Button("Edit", id=f"btn_{p}_account_edit", classes="accounts-action"),
            Button(
                "Remove",
                id=f"btn_{p}_account_remove",
                variant="error",
                classes="accounts-action",
            ),
        ]

    def form_rows(self) -> ComposeResult:
        """Extra rows under the actions (the AWS inline form)."""
        return iter(())

    def on_mount(self) -> None:
        self.query_one(DataTable).cursor_type = "row"
        self.refresh_accounts()

    # ------------------------------------------------------------------
    # Drawing
    # ------------------------------------------------------------------

    def rows(self, config: Any) -> List[AccountRow]:
        """The primary account, then every extra account, in config order."""
        block = provider_block(config, self.PROVIDER)
        rows = [AccountRow(primary_label(self.PROVIDER, block))]
        rows.extend(
            AccountRow((extra.label or "").strip() or f"#{index + 1}", index)
            for index, extra in enumerate(block.accounts)
        )
        return rows

    def redacted_cells(self, config: Any, row: AccountRow) -> Tuple[str, ...]:
        """The row's cells, one per column, with stand-ins in demo mode."""
        return (shown_label(self.app, row.label),)

    def refresh_accounts(self) -> None:
        """Redraw the table and the problem list from the saved config."""
        config = self.app.config_manager.get()
        table = self.query_one(DataTable)
        cursor = table.cursor_row
        table.clear(columns=True)
        # Status second: on a narrow terminal the table scrolls sideways,
        # and whether an account works matters more than its details.
        label, *details = self.COLUMNS
        table.add_columns(label, "Status", *details)
        self._rows = self.rows(config)
        for row in self._rows:
            status = account_status(self.app, config, self.PROVIDER, row)
            shown, *rest = self.redacted_cells(config, row)
            table.add_row(shown, status, *rest)
        if 0 < cursor < table.row_count:
            table.move_cursor(row=cursor)

        problems = self.query_one(f"#{self.PROVIDER}_accounts_problems", Static)
        messages = [
            shown_text(self.app, config, message)
            for message in provider_problems(self.app, config, self.PROVIDER)
        ]
        problems.update("\n".join(f"• {escape(m)}" for m in messages))
        problems.display = bool(messages)

    def refresh_after_demo_toggle(self) -> None:
        """Redraw with (or without) stand-ins for the new demo-mode state."""
        self.refresh_accounts()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        p = self.PROVIDER
        handlers = {
            f"btn_{p}_account_add": self.add_account,
            f"btn_{p}_account_edit": self._edit_selected,
            f"btn_{p}_account_remove": self._remove_selected,
        }
        handler = handlers.get(event.button.id or "") or self.button_handler(event.button.id)
        if handler is None:
            return
        event.stop()
        handler()

    def button_handler(self, button_id: Optional[str]) -> Any:
        """Subclass hook for extra buttons; None leaves the event alone."""
        return None

    def selected_row(self) -> Optional[AccountRow]:
        table = self.query_one(DataTable)
        if table.row_count == 0 or not 0 <= table.cursor_row < len(self._rows):
            return None
        return self._rows[table.cursor_row]

    def add_account(self) -> None:
        raise NotImplementedError

    def edit_account(self, row: AccountRow) -> None:
        raise NotImplementedError

    def refused_in_demo_mode(self, what: str) -> bool:
        """Editing forms show real labels and credentials: not in demo mode."""
        if demo_redaction(self.app) is None:
            return False
        self.app.notify(
            f"{what} is disabled in demo mode — the form would show the real "
            "account names. Press ctrl+shift+d to turn demo mode off.",
            severity="warning",
            markup=False,
        )
        return True

    def _edit_selected(self) -> None:
        row = self.selected_row()
        if row is None:
            self.app.notify(f"Select an {self.NOUN} to edit", severity="warning", markup=False)
            return
        if self.refused_in_demo_mode("Editing accounts"):
            return
        self.edit_account(row)

    def _remove_selected(self) -> None:
        from servonaut.screens.memory import SimpleConfirmModal

        row = self.selected_row()
        if row is None:
            self.app.notify(f"Select an {self.NOUN} to remove", severity="warning", markup=False)
            return
        title = PROVIDER_TITLES[self.PROVIDER]
        if row.primary:
            self.app.notify(self.primary_removal_hint(), severity="warning", markup=False)
            return
        shown = shown_label(self.app, row.label)
        message = (
            f"Remove the {escape(title)} {self.NOUN} [b]{escape(shown)}[/b]?\n\n"
            f"Its servers leave the server list. Nothing changes at {escape(title)}."
        )

        def _confirmed(confirmed: Optional[bool]) -> None:
            if confirmed:
                self._remove_extra(row)

        self.app.push_screen(SimpleConfirmModal(message), _confirmed)

    def primary_removal_hint(self) -> str:
        return (
            f"The primary {self.NOUN} is the {PROVIDER_TITLES[self.PROVIDER]} "
            "settings themselves and cannot be removed."
        )

    def _remove_extra(self, row: AccountRow) -> None:
        config = self.app.config_manager.get()
        accounts = list(provider_block(config, self.PROVIDER).accounts)
        index = row.index
        # The list may have changed while the question was open: find the
        # account again by its label rather than trusting the position.
        if index is None or index >= len(accounts) or (
            (accounts[index].label or "").strip() != row.label
        ):
            index = next(
                (i for i, a in enumerate(accounts) if (a.label or "").strip() == row.label),
                None,
            )
        if index is None:
            self.app.notify(f"That {self.NOUN} no longer exists", severity="error", markup=False)
            self.refresh_accounts()
            return
        del accounts[index]
        save_extra_accounts(self.app, self.PROVIDER, accounts)
        shown = shown_label(self.app, row.label)
        self.accounts_changed(f"Removed {PROVIDER_TITLES[self.PROVIDER]} {self.NOUN} '{shown}'")

    def accounts_changed(self, message: str) -> None:
        """After a save: reload the accounts, the fleet and this table."""
        if rebuild_accounts(self.app):
            refresh_provider_fleet(self.app, self.PROVIDER)
        self.refresh_accounts()
        self.app.notify(message, severity="information", markup=False)


# ---------------------------------------------------------------------------
# Hetzner and OVH: credentials live in the setup wizards
# ---------------------------------------------------------------------------


def _credential_kind(value: str) -> str:
    """Whether a secret is set and where from — never the secret itself."""
    value = (value or "").strip()
    if not value:
        return ""
    if value.startswith("$"):
        return "set (variable)"
    if value.startswith("file:"):
        return "set (file)"
    return "set"


class HetznerAccountsSection(AccountsSection):
    """Hetzner Cloud projects; each has its own token, set in the wizard."""

    PROVIDER = "hetzner"
    NOUN = "project"
    HEADING = "Projects"
    HELP = "One API token per project, entered in the setup wizard."
    COLUMNS = ("Label", "API token")

    def redacted_cells(self, config: Any, row: AccountRow) -> Tuple[str, ...]:
        block = config.hetzner
        token = block.api_token if row.primary else block.accounts[row.index].api_token
        state = _credential_kind(token) or (
            "from environment" if row.primary else "missing"
        )
        return (shown_label(self.app, row.label), state)

    def add_account(self) -> None:
        from servonaut.screens.hetzner_setup import HetznerSetupScreen

        if not self.app.config_manager.get().hetzner.enabled:
            self.app.notify(
                "Set up Hetzner first (Setup Hetzner), then add more projects.",
                severity="warning",
                markup=False,
            )
            return
        self.app.push_screen(HetznerSetupScreen(add_extra=True))

    def edit_account(self, row: AccountRow) -> None:
        from servonaut.screens.hetzner_setup import HetznerSetupScreen

        if row.primary:
            self.app.push_screen(HetznerSetupScreen(show_label=True))
        else:
            self.app.push_screen(HetznerSetupScreen(extra=row.index))

    def primary_removal_hint(self) -> str:
        return (
            "The primary project cannot be removed. To stop listing Hetzner, "
            "use Setup Hetzner → Disable Hetzner."
        )


def ovh_auth_kind(account: Any) -> str:
    """Which OVH credential set an account has, never the values."""
    def filled(*values: str) -> bool:
        return all((v or "").strip() for v in values)

    if filled(account.client_id, account.client_secret):
        return "OAuth2"
    if filled(account.application_key, account.application_secret, account.consumer_key):
        return "application key"
    if (account.application_key or "").strip() or (account.client_id or "").strip():
        return "incomplete"
    return "missing"


class OvhAccountsSection(AccountsSection):
    """OVHcloud accounts; each has its own credentials, set in the wizard."""

    PROVIDER = "ovh"
    HELP = "Each account has its own API credentials, entered in the setup wizard."
    COLUMNS = ("Label", "Endpoint", "Auth", "Projects")

    def redacted_cells(self, config: Any, row: AccountRow) -> Tuple[str, ...]:
        account = config.ovh if row.primary else config.ovh.accounts[row.index]
        projects = len(account.cloud_project_ids)
        return (
            shown_label(self.app, row.label),
            account.endpoint or "ovh-eu",
            ovh_auth_kind(account),
            str(projects) if projects else "none",
        )

    def add_account(self) -> None:
        from servonaut.screens.ovh_setup import OVHSetupScreen

        if not self.app.config_manager.get().ovh.enabled:
            self.app.notify(
                "Set up OVHcloud first (Setup OVHcloud), then add more accounts.",
                severity="warning",
                markup=False,
            )
            return
        self.app.push_screen(OVHSetupScreen(add_extra=True))

    def edit_account(self, row: AccountRow) -> None:
        from servonaut.screens.ovh_setup import OVHSetupScreen

        if row.primary:
            self.app.push_screen(OVHSetupScreen(show_label=True))
        else:
            self.app.push_screen(OVHSetupScreen(extra=row.index))

    def primary_removal_hint(self) -> str:
        return (
            "The primary account cannot be removed. To stop listing OVHcloud, "
            "use Setup OVHcloud → Disable OVH."
        )
