"""AWS accounts in the AWS settings panel.

The primary account is the AWS settings themselves: an optional named
profile (empty keeps the default credential chain) and an optional region
list. Every extra account is a named profile from the AWS shared config
files. Nothing here is secret, so accounts are edited in an inline form,
and profiles found in ``~/.aws/config`` can be added in two steps.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any, List, Optional, Tuple

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.css.query import NoMatches
from textual.widgets import Button, Input, Select, Static

from servonaut.config.schema import AWSAccount
from servonaut.screens._provider_accounts import shown_label
from servonaut.screens.settings.accounts import (
    AccountRow,
    AccountsSection,
    demo_redaction,
    label_error,
    parse_regions,
    shown_profile,
    shown_text,
    suggest_label,
)

logger = logging.getLogger(__name__)


def detected_aws_profiles() -> Optional[List[str]]:
    """Profile names in the AWS shared config and credentials files.

    None when the files cannot be read, so callers can tell "no profiles"
    from "could not look".
    """
    import boto3
    from botocore.exceptions import BotoCoreError

    try:
        return sorted(boto3.session.Session().available_profiles)
    except BotoCoreError as exc:
        # $AWS_PROFILE naming a missing profile makes the session refuse to
        # start; the profile list itself does not depend on it.
        logger.debug("AWS session unavailable (%s); reading profiles directly", exc)
    try:
        import botocore.session

        return sorted(botocore.session.get_session().available_profiles)
    except BotoCoreError as exc:
        logger.warning("Could not read the AWS profiles: %s", exc)
        return None


def unconfigured_profiles(config: Any, profiles: List[str]) -> List[str]:
    """*profiles* not yet used by any configured AWS account.

    While the primary account uses the default credential chain, the
    ``default`` profile (and ``$AWS_PROFILE``) already are that account.
    """
    import os

    used = {(config.aws.profile or "").strip()}
    used.update((extra.profile or "").strip() for extra in config.aws.accounts)
    if not (config.aws.profile or "").strip():
        used.update({"default", os.environ.get("AWS_PROFILE", "").strip()})
    return [profile for profile in profiles if profile not in used]


class AwsAccountsSection(AccountsSection):
    """AWS accounts: the primary one and extra named profiles."""

    PROVIDER = "aws"
    HELP = "Each extra account is a named profile from ~/.aws/config."
    COLUMNS = ("Label", "Profile", "Regions")

    DEFAULT_CSS = """
    AwsAccountsSection #aws_account_form {
        height: auto;
        border: round $primary;
        background: $boost;
        padding: 0 1;
        margin: 1 0 0 0;
    }
    AwsAccountsSection #aws_account_form_title {
        height: auto;
        text-style: bold;
        padding: 1 0 0 0;
    }
    AwsAccountsSection #aws_account_form_hint,
    AwsAccountsSection #aws_account_form_error {
        height: auto;
        padding: 0 1 0 0;
    }
    AwsAccountsSection #aws_account_form_hint {
        color: $text-muted;
    }
    AwsAccountsSection #aws_account_form_error {
        color: $error;
    }
    AwsAccountsSection #aws_account_detected_row,
    AwsAccountsSection #aws_account_form_actions {
        height: auto;
    }
    AwsAccountsSection #aws_account_form_actions {
        margin: 1 0;
    }
    AwsAccountsSection #aws_account_form_actions Button {
        width: auto;
        margin: 0 1 0 0;
    }
    AwsAccountsSection #aws_account_label,
    AwsAccountsSection #aws_account_profile,
    AwsAccountsSection #aws_account_regions,
    AwsAccountsSection #aws_account_detected {
        width: 1fr;
    }
    AwsAccountsSection #btn_aws_account_save,
    AwsAccountsSection #btn_aws_account_cancel {
        min-width: 10;
    }
    AwsAccountsSection #btn_aws_account_add_profile {
        width: auto;
    }
    """

    def __init__(self, *, heading_classes: str = "") -> None:
        super().__init__(heading_classes=heading_classes)
        # The row being edited; None while adding an account.
        self._editing: Optional[AccountRow] = None
        # The label the detected-profile picker last filled in, so picking
        # another profile replaces it but never a label the user typed.
        self._auto_label = ""

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def action_buttons(self) -> List[Button]:
        add, edit, remove = super().action_buttons()
        return [add, Button("Add from profiles", id="btn_aws_account_add_profile"), edit, remove]

    def form_rows(self) -> ComposeResult:
        yield Container(
            Static("", id="aws_account_form_title"),
            Horizontal(
                Static("Detected profile", classes="label"),
                Select(
                    [],
                    prompt="Choose a profile",
                    allow_blank=True,
                    id="aws_account_detected",
                ),
                id="aws_account_detected_row",
                classes="setting_row",
            ),
            Horizontal(
                Static("Label", classes="label"),
                Input(placeholder="e.g. prod", id="aws_account_label"),
                classes="setting_row",
            ),
            Horizontal(
                Static("Profile", classes="label"),
                Input(placeholder="named profile in ~/.aws/config", id="aws_account_profile"),
                classes="setting_row",
            ),
            Horizontal(
                Static("Regions", classes="label"),
                Input(
                    placeholder="all enabled regions, or e.g. eu-west-1, us-east-1",
                    id="aws_account_regions",
                ),
                classes="setting_row",
            ),
            Static("", id="aws_account_form_hint"),
            Static("", id="aws_account_form_error"),
            Horizontal(
                Button("Save account", id="btn_aws_account_save", variant="primary"),
                Button("Cancel", id="btn_aws_account_cancel"),
                id="aws_account_form_actions",
            ),
            id="aws_account_form",
        )

    def on_mount(self) -> None:
        super().on_mount()
        self.query_one("#aws_account_form").display = False

    # ------------------------------------------------------------------
    # Drawing
    # ------------------------------------------------------------------

    def redacted_cells(self, config: Any, row: AccountRow) -> Tuple[str, ...]:
        account = config.aws if row.primary else config.aws.accounts[row.index]
        profile = (account.profile or "").strip()
        if profile:
            profile = shown_profile(self.app, profile)
        elif row.primary:
            profile = "default credentials"
        else:
            profile = "missing"
        regions = ", ".join(account.regions) if account.regions else "all enabled"
        return (shown_label(self.app, row.label), profile, regions)

    def refresh_after_demo_toggle(self) -> None:
        """Redraw; an open form holds real names, so demo mode closes it."""
        if demo_redaction(self.app) is not None:
            self._close_form()
        super().refresh_after_demo_toggle()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def button_handler(self, button_id: Optional[str]) -> Any:
        return {
            "btn_aws_account_add_profile": self._add_from_profiles,
            "btn_aws_account_save": self._save_form,
            "btn_aws_account_cancel": self._close_form,
        }.get(button_id or "")

    def add_account(self) -> None:
        self._open_form(None, detected=[])

    def edit_account(self, row: AccountRow) -> None:
        self._open_form(row, detected=[])

    def _add_from_profiles(self) -> None:
        if self.refused_in_demo_mode("Listing the AWS profiles"):
            return
        profiles = detected_aws_profiles()
        if profiles is None:
            self.app.notify(
                "Could not read the AWS profiles; see the log for details.",
                severity="error",
                markup=False,
            )
            return
        free = unconfigured_profiles(self.app.config_manager.get(), profiles)
        if not free:
            self.app.notify(
                "No AWS profiles to add: every profile in ~/.aws/config and "
                "~/.aws/credentials is already an account.",
                severity="warning",
                markup=False,
            )
            return
        self._open_form(None, detected=free)

    def on_select_changed(self, event: Select.Changed) -> None:
        """Fill the form from the picked profile."""
        if event.select.id != "aws_account_detected" or event.value is Select.BLANK:
            return
        profile = str(event.value)
        self.query_one("#aws_account_profile", Input).value = profile
        label_input = self.query_one("#aws_account_label", Input)
        if not label_input.value.strip() or label_input.value == self._auto_label:
            self._auto_label = suggest_label(profile, self.app.config_manager.get())
            label_input.value = self._auto_label

    # ------------------------------------------------------------------
    # Form
    # ------------------------------------------------------------------

    def _open_form(self, row: Optional[AccountRow], *, detected: List[str]) -> None:
        config = self.app.config_manager.get()
        self._editing = row
        self._auto_label = ""
        label_input = self.query_one("#aws_account_label", Input)
        profile_input = self.query_one("#aws_account_profile", Input)
        regions_input = self.query_one("#aws_account_regions", Input)
        picker = self.query_one("#aws_account_detected", Select)
        picker.set_options([(profile, profile) for profile in detected])
        self.query_one("#aws_account_detected_row").display = bool(detected)

        if row is None:
            title = "Add an AWS account"
            hint = "The profile must exist in ~/.aws/config or ~/.aws/credentials."
            label_input.value = profile_input.value = regions_input.value = ""
            label_input.placeholder = "e.g. prod"
            profile_input.placeholder = "named profile in ~/.aws/config"
        else:
            account = config.aws if row.primary else config.aws.accounts[row.index]
            title = f"Edit the AWS account '{row.label}'"
            label_input.value = (account.label or "").strip()
            profile_input.value = (account.profile or "").strip()
            regions_input.value = ", ".join(account.regions)
            if row.primary:
                hint = (
                    "The primary account. Leave the label empty to show it as "
                    "'aws' and the profile empty to use the default credentials "
                    "(environment, ~/.aws, instance role)."
                )
                label_input.placeholder = "aws"
                profile_input.placeholder = "default credentials"
            else:
                hint = "The profile must exist in ~/.aws/config or ~/.aws/credentials."
                label_input.placeholder = "e.g. prod"
                profile_input.placeholder = "named profile in ~/.aws/config"
        self.query_one("#aws_account_form_title", Static).update(escape(title))
        self.query_one("#aws_account_form_hint", Static).update(hint)
        self._set_error(config, "")
        self.query_one("#aws_account_form").display = True
        (picker if detected else label_input).focus()

    def _close_form(self) -> None:
        """Hide the form and empty it, so no real name lingers off screen."""
        self._editing = None
        self._auto_label = ""
        try:
            self.query_one("#aws_account_form").display = False
        except NoMatches:  # not mounted yet (demo toggle during start-up)
            return
        for field_id in ("aws_account_label", "aws_account_profile", "aws_account_regions"):
            self.query_one(f"#{field_id}", Input).value = ""
        self.query_one("#aws_account_detected", Select).set_options([])
        self.query_one("#aws_account_form_title", Static).update("")
        self.query_one("#aws_account_form_error", Static).update("")

    def _set_error(self, config: Any, message: str, field_id: Optional[str] = None) -> None:
        """Show why the form cannot be saved (names hidden in demo mode)."""
        for widget in self.query(".field-error"):
            widget.remove_class("field-error")
        error = self.query_one("#aws_account_form_error", Static)
        error.update(escape(shown_text(self.app, config, message)))
        error.display = bool(message)
        if field_id:
            field = self.query_one(f"#{field_id}", Input)
            field.add_class("field-error")
            field.focus()

    def _save_form(self) -> None:
        config = self.app.config_manager.get()
        row = self._editing
        index = None if row is None else row.index
        primary = row is not None and row.primary
        label = self.query_one("#aws_account_label", Input).value.strip()
        profile = self.query_one("#aws_account_profile", Input).value.strip()
        try:
            regions = parse_regions(self.query_one("#aws_account_regions", Input).value)
        except ValueError as exc:
            self._set_error(config, str(exc), "aws_account_regions")
            return

        if primary:
            slot = None
        else:
            # A new account takes the next free position, so it keeps no
            # other account's label.
            slot = len(config.aws.accounts) if index is None else index
        problem = label_error(config, "aws", label, index=slot)
        if problem is not None:
            self._set_error(config, problem, "aws_account_label")
            return
        problem = self._profile_problem(config, profile, primary=primary, index=index)
        if problem is not None:
            self._set_error(config, problem, "aws_account_profile")
            return

        if primary:
            new_aws = replace(config.aws, label=label, profile=profile, regions=regions)
        else:
            accounts = list(config.aws.accounts)
            entry = AWSAccount(label=label, profile=profile, regions=regions)
            if index is None:
                accounts.append(entry)
            else:
                accounts[index] = entry
            new_aws = replace(config.aws, accounts=accounts)
        self.app.config_manager.update(aws=new_aws)

        redaction = demo_redaction(self.app)
        if redaction is not None:
            # Typed during this demo session: show it as typed.
            redaction.keep_as_authored(label, profile)
        self._close_form()
        shown = shown_label(self.app, label or "aws")
        self.accounts_changed(f"Saved AWS account '{shown}'")

    def _profile_problem(
        self, config: Any, profile: str, *, primary: bool, index: Optional[int]
    ) -> Optional[str]:
        if not profile:
            if primary:
                return None
            return (
                "An extra account needs a named profile; without one it would "
                "list the primary account again."
            )
        for other_index, extra in enumerate(config.aws.accounts):
            if (extra.profile or "").strip() == profile and (primary or other_index != index):
                return f"The profile {profile!r} is already the account {extra.label!r}."
        if not primary and (config.aws.profile or "").strip() == profile:
            return f"The profile {profile!r} is already the primary account."
        known = detected_aws_profiles()
        if known is not None and profile not in known:
            return (
                f"No profile named {profile!r} in ~/.aws/config or "
                "~/.aws/credentials."
            )
        return None
