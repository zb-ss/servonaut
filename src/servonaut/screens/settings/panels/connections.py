"""Connections settings panel — connection profiles and connection rules editors.

Full CRUD editors for:
- :class:`~servonaut.config.schema.ConnectionProfile` (name, bastion_host,
  bastion_user, bastion_key, username, proxy_command, ssh_port 1-65535,
  extra_ssh_options List[str]).
- :class:`~servonaut.config.schema.ConnectionRule` (name, match_conditions
  Dict[str,str], profile_name — validated against existing profiles).

Both collections were read-only in the legacy screen; this panel upgrades them
to full add/edit/remove CRUD, matching the spec upgrade directive.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Dict, List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Select, Static

from servonaut.config.schema import ConnectionProfile, ConnectionRule
from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.screens.settings.widgets import KeyValueEditor, StringListEditor

logger = logging.getLogger(__name__)

# Sentinel used by Textual's Select widget to indicate "no selection".
_NULL = Select.BLANK


class ConnectionsPanel(SettingsPanel):
    """Full CRUD editors for connection profiles and connection rules.

    The two editors are independent: profiles are saved and reloaded before
    rule validation so that ``profile_name`` references are always resolved
    against the current profile list.

    Dirty-state overrides :meth:`is_dirty` because the editors are backed by
    DataTable + in-memory lists, not simple Input widgets.
    """

    PANEL_ID = "connections"
    TITLE = "Connections"

    DEFAULT_CSS = """
    ConnectionsPanel .conn-section-header {
        color: $primary;
        text-style: bold;
        margin: 1 0 0 0;
        height: auto;
    }
    ConnectionsPanel .conn-note {
        color: $text-muted;
        height: auto;
        margin: 0 0 1 0;
    }
    ConnectionsPanel .conn-action-row {
        height: auto;
        margin: 0 0 1 0;
    }
    ConnectionsPanel .conn-action-row Button { margin-right: 1; }
    ConnectionsPanel .conn-form {
        height: auto;
        border: round $primary;
        padding: 1;
        margin: 0 0 1 0;
    }
    ConnectionsPanel .conn-form-title {
        text-style: bold;
        height: auto;
        margin: 0 0 1 0;
    }
    ConnectionsPanel .conn-subsection {
        color: $accent;
        text-style: bold;
        height: auto;
        margin: 1 0 0 0;
    }
    ConnectionsPanel .conn-form-buttons {
        height: auto;
        margin: 1 0 0 0;
    }
    ConnectionsPanel .conn-form-buttons Button { margin-right: 1; }
    ConnectionsPanel DataTable { height: 8; }
    """

    # ------------------------------------------------------------------
    # Internal state
    # ------------------------------------------------------------------

    def __init__(self) -> None:
        super().__init__()
        # In-memory lists — the DataTables are view only; edits go here.
        self._profiles: List[ConnectionProfile] = []
        self._rules: List[ConnectionRule] = []
        # Which profile/rule row is being edited (-1 = adding new).
        self._editing_profile_idx: Optional[int] = None
        self._editing_rule_idx: Optional[int] = None

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield the connection profiles section and connection rules section."""

        # ---- Connection Profiles ----------------------------------------
        yield Static("Connection Profiles", classes="conn-section-header")
        yield Static(
            "Define SSH bastion/proxy configurations that can be applied to instances.",
            classes="conn-note",
        )
        yield DataTable(id="conn_profiles_table")
        yield Horizontal(
            Button("Add", id="btn_profile_add", variant="primary"),
            Button("Edit", id="btn_profile_edit"),
            Button("Remove", id="btn_profile_remove", variant="error"),
            classes="conn-action-row",
        )
        # Profile form (hidden until add/edit)
        with Vertical(id="profile_form", classes="conn-form"):
            yield Static("", id="profile_form_title", classes="conn-form-title")
            yield Horizontal(
                Static("Profile name", classes="label"),
                Input(placeholder="e.g. prod-bastion", id="pf_name"),
                classes="setting_row",
            )
            yield Horizontal(
                Static("Bastion host", classes="label"),
                Input(placeholder="bastion.example.com", id="pf_bastion_host"),
                classes="setting_row",
            )
            yield Horizontal(
                Static("Bastion user", classes="label"),
                Input(placeholder="ec2-user", id="pf_bastion_user"),
                classes="setting_row",
            )
            yield Horizontal(
                Static("Bastion key", classes="label"),
                Input(placeholder="~/.ssh/bastion_key.pem", id="pf_bastion_key"),
                classes="setting_row",
            )
            yield Horizontal(
                Static("Username (target)", classes="label"),
                Input(placeholder="ec2-user", id="pf_username"),
                classes="setting_row",
            )
            yield Horizontal(
                Static("Proxy command", classes="label"),
                Input(placeholder="ssh -W %h:%p bastion", id="pf_proxy_command"),
                classes="setting_row",
            )
            yield Horizontal(
                Static("SSH port (1-65535)", classes="label"),
                Input(placeholder="22", id="pf_ssh_port"),
                classes="setting_row",
            )
            yield Static("Extra SSH options (-o KEY=VALUE)", classes="conn-subsection")
            yield Static(
                "One entry per line, e.g. ServerAliveInterval=60",
                classes="conn-note",
            )
            yield StringListEditor(
                placeholder="KEY=VALUE",
                id="pf_extra_ssh_options",
            )
            yield Horizontal(
                Button("Save profile", id="btn_profile_save", variant="primary"),
                Button("Cancel", id="btn_profile_cancel"),
                classes="conn-form-buttons",
            )

        # ---- Connection Rules --------------------------------------------
        yield Static("Connection Rules", classes="conn-section-header")
        yield Static(
            "Rules map instance match conditions to a connection profile. "
            "The first matching rule wins.",
            classes="conn-note",
        )
        yield DataTable(id="conn_rules_table")
        yield Horizontal(
            Button("Add", id="btn_rule_add", variant="primary"),
            Button("Edit", id="btn_rule_edit"),
            Button("Remove", id="btn_rule_remove", variant="error"),
            classes="conn-action-row",
        )
        # Rule form (hidden until add/edit)
        with Vertical(id="rule_form", classes="conn-form"):
            yield Static("", id="rule_form_title", classes="conn-form-title")
            yield Horizontal(
                Static("Rule name", classes="label"),
                Input(placeholder="e.g. private-subnets", id="rl_name"),
                classes="setting_row",
            )
            yield Static("Match conditions", classes="conn-subsection")
            yield Static(
                "key=value pairs, e.g. name_contains=web  region=us-east-1",
                classes="conn-note",
            )
            yield KeyValueEditor(
                key_placeholder="condition key",
                value_placeholder="value",
                id="rl_match_conditions",
            )
            yield Horizontal(
                Static("Profile name", classes="label"),
                Input(placeholder="profile name", id="rl_profile_name"),
                classes="setting_row",
            )
            yield Horizontal(
                Button("Save rule", id="btn_rule_save", variant="primary"),
                Button("Cancel", id="btn_rule_cancel"),
                classes="conn-form-buttons",
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        """Configure tables then delegate to load()."""
        self._setup_tables()
        super().on_mount()

    def _setup_tables(self) -> None:
        """Add columns to the DataTables (idempotent)."""
        profiles_table = self.query_one("#conn_profiles_table", DataTable)
        profiles_table.clear(columns=True)
        profiles_table.cursor_type = "row"
        profiles_table.add_columns(
            "Profile Name", "Bastion Host", "Bastion User", "SSH Port"
        )

        rules_table = self.query_one("#conn_rules_table", DataTable)
        rules_table.clear(columns=True)
        rules_table.cursor_type = "row"
        rules_table.add_columns("Rule Name", "Match Conditions", "Profile")

    def load(self) -> None:
        """Populate the DataTables from config and hide the edit forms."""
        config = self.app.config_manager.get()
        self._profiles = list(config.connection_profiles)
        self._rules = list(config.connection_rules)
        self._refresh_profiles_table()
        self._refresh_rules_table()
        self._hide_profile_form()
        self._hide_rule_form()
        self._snapshot_now()

    # ------------------------------------------------------------------
    # Dirty tracking — override because state lives in lists, not widgets
    # ------------------------------------------------------------------

    def current_values(self) -> Dict[str, Any]:
        """Return a snapshot-comparable representation of the current lists."""
        return {
            "profiles": [dataclasses.asdict(p) for p in self._profiles],
            "rules": [dataclasses.asdict(r) for r in self._rules],
        }

    # The default is_dirty() (current_values() != snapshot) is correct here —
    # current_values() already serialises the in-memory lists.

    # ------------------------------------------------------------------
    # Collect + Persist
    # ------------------------------------------------------------------

    def collect(self) -> Dict[str, Any]:
        """Return the current lists as config-ready dicts.

        No widget validation is required here — each profile/rule was
        individually validated at save time via the form. The rule
        ``profile_name`` references are re-validated now.
        """
        known_names = {p.name for p in self._profiles}
        for rule in self._rules:
            if rule.profile_name not in known_names:
                raise ValidationError(
                    "rl_profile_name",
                    f"Rule '{escape(rule.name)}' references unknown profile "
                    f"'{escape(rule.profile_name)}'. Add the profile first.",
                )
        return {
            "connection_profiles": self._profiles,
            "connection_rules": self._rules,
        }

    def persist(self) -> None:
        """Validate then write connection_profiles + connection_rules."""
        fields = self.collect()
        self.app.config_manager.update(
            connection_profiles=fields["connection_profiles"],
            connection_rules=fields["connection_rules"],
        )
        self._finish_save("Connection settings saved")

    # ------------------------------------------------------------------
    # DataTable refresh helpers
    # ------------------------------------------------------------------

    def _refresh_profiles_table(self) -> None:
        table = self.query_one("#conn_profiles_table", DataTable)
        table.clear(columns=True)
        table.add_columns("Profile Name", "Bastion Host", "Bastion User", "SSH Port")
        for profile in self._profiles:
            table.add_row(
                escape(profile.name),
                escape(profile.bastion_host or "—"),
                escape(profile.bastion_user or "—"),
                str(profile.ssh_port),
            )

    def _refresh_rules_table(self) -> None:
        table = self.query_one("#conn_rules_table", DataTable)
        table.clear(columns=True)
        table.add_columns("Rule Name", "Match Conditions", "Profile")
        for rule in self._rules:
            conditions = ", ".join(
                f"{escape(k)}={escape(v)}"
                for k, v in rule.match_conditions.items()
            )
            table.add_row(
                escape(rule.name),
                conditions or "—",
                escape(rule.profile_name),
            )

    # ------------------------------------------------------------------
    # Profile form helpers
    # ------------------------------------------------------------------

    def _show_profile_form(self, title: str) -> None:
        self.query_one("#profile_form").display = True
        self.query_one("#profile_form_title", Static).update(escape(title))

    def _hide_profile_form(self) -> None:
        self.query_one("#profile_form").display = False
        self._editing_profile_idx = None
        self._clear_profile_form()

    def _clear_profile_form(self) -> None:
        self.query_one("#pf_name", Input).value = ""
        self.query_one("#pf_bastion_host", Input).value = ""
        self.query_one("#pf_bastion_user", Input).value = ""
        self.query_one("#pf_bastion_key", Input).value = ""
        self.query_one("#pf_username", Input).value = ""
        self.query_one("#pf_proxy_command", Input).value = ""
        self.query_one("#pf_ssh_port", Input).value = "22"
        self.query_one("#pf_extra_ssh_options", StringListEditor).set_values([])

    def _populate_profile_form(self, profile: ConnectionProfile) -> None:
        self.query_one("#pf_name", Input).value = profile.name
        self.query_one("#pf_bastion_host", Input).value = profile.bastion_host or ""
        self.query_one("#pf_bastion_user", Input).value = profile.bastion_user or ""
        self.query_one("#pf_bastion_key", Input).value = profile.bastion_key or ""
        self.query_one("#pf_username", Input).value = profile.username or ""
        self.query_one("#pf_proxy_command", Input).value = profile.proxy_command or ""
        self.query_one("#pf_ssh_port", Input).value = str(profile.ssh_port)
        self.query_one("#pf_extra_ssh_options", StringListEditor).set_values(
            list(profile.extra_ssh_options)
        )

    def _collect_profile_form(self) -> ConnectionProfile:
        """Read and validate the profile form.

        Raises:
            ValidationError: On empty name, duplicate name, or bad port.
        """
        name = self.query_one("#pf_name", Input).value.strip()
        if not name:
            raise ValidationError("pf_name", "Profile name cannot be empty")

        # Duplicate name check — allow the original name when editing
        for i, existing in enumerate(self._profiles):
            if existing.name == name and i != self._editing_profile_idx:
                raise ValidationError(
                    "pf_name",
                    f"A profile named '{escape(name)}' already exists",
                )

        port_raw = self.query_one("#pf_ssh_port", Input).value.strip() or "22"
        try:
            port = int(port_raw)
        except ValueError as exc:
            raise ValidationError(
                "pf_ssh_port", "SSH port must be a whole number"
            ) from exc
        if not 1 <= port <= 65535:
            raise ValidationError(
                "pf_ssh_port", "SSH port must be between 1 and 65535"
            )

        return ConnectionProfile(
            name=name,
            bastion_host=self.query_one("#pf_bastion_host", Input).value.strip() or None,
            bastion_user=self.query_one("#pf_bastion_user", Input).value.strip() or None,
            bastion_key=self.query_one("#pf_bastion_key", Input).value.strip() or None,
            username=self.query_one("#pf_username", Input).value.strip() or None,
            proxy_command=self.query_one("#pf_proxy_command", Input).value.strip() or None,
            ssh_port=port,
            extra_ssh_options=self.query_one(
                "#pf_extra_ssh_options", StringListEditor
            ).get_values(),
        )

    # ------------------------------------------------------------------
    # Rule form helpers
    # ------------------------------------------------------------------

    def _show_rule_form(self, title: str) -> None:
        self.query_one("#rule_form").display = True
        self.query_one("#rule_form_title", Static).update(escape(title))

    def _hide_rule_form(self) -> None:
        self.query_one("#rule_form").display = False
        self._editing_rule_idx = None
        self._clear_rule_form()

    def _clear_rule_form(self) -> None:
        self.query_one("#rl_name", Input).value = ""
        self.query_one("#rl_match_conditions", KeyValueEditor).set_map({})
        self.query_one("#rl_profile_name", Input).value = ""

    def _populate_rule_form(self, rule: ConnectionRule) -> None:
        self.query_one("#rl_name", Input).value = rule.name
        self.query_one("#rl_match_conditions", KeyValueEditor).set_map(
            dict(rule.match_conditions)
        )
        self.query_one("#rl_profile_name", Input).value = rule.profile_name

    def _collect_rule_form(self) -> ConnectionRule:
        """Read and validate the rule form.

        Raises:
            ValidationError: On empty name, duplicate name, missing/unknown
                profile_name, or invalid match conditions.
        """
        name = self.query_one("#rl_name", Input).value.strip()
        if not name:
            raise ValidationError("rl_name", "Rule name cannot be empty")

        for i, existing in enumerate(self._rules):
            if existing.name == name and i != self._editing_rule_idx:
                raise ValidationError(
                    "rl_name",
                    f"A rule named '{escape(name)}' already exists",
                )

        try:
            match_conditions: Dict[str, str] = {
                str(k): str(v)
                for k, v in self.query_one(
                    "#rl_match_conditions", KeyValueEditor
                ).get_map().items()
            }
        except ValueError as exc:
            raise ValidationError(
                "rl_match_conditions", f"Invalid match conditions: {exc}"
            ) from exc

        profile_name = self.query_one("#rl_profile_name", Input).value.strip()
        if not profile_name:
            raise ValidationError("rl_profile_name", "Profile name cannot be empty")

        known = {p.name for p in self._profiles}
        if profile_name not in known:
            raise ValidationError(
                "rl_profile_name",
                f"Profile '{escape(profile_name)}' does not exist. "
                "Add the profile first.",
            )

        return ConnectionRule(
            name=name,
            match_conditions=match_conditions,
            profile_name=profile_name,
        )

    # ------------------------------------------------------------------
    # Button event routing
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:  # type: ignore[override]
        """Route all button presses within this panel."""
        btn_id = event.button.id or ""

        if btn_id == f"save_{self.PANEL_ID}":
            # The base class save button — delegate to parent handler.
            super().on_button_pressed(event)
            return

        event.stop()
        self.clear_field_errors()

        # ---- Profile buttons ----------------------------------------
        if btn_id == "btn_profile_add":
            self._editing_profile_idx = None
            self._clear_profile_form()
            self._show_profile_form("Add Connection Profile")

        elif btn_id == "btn_profile_edit":
            idx = self._selected_profiles_row()
            if idx is None:
                self.app.notify("Select a profile to edit", severity="warning", markup=False)
                return
            self._editing_profile_idx = idx
            self._populate_profile_form(self._profiles[idx])
            self._show_profile_form(f"Edit Profile: {escape(self._profiles[idx].name)}")

        elif btn_id == "btn_profile_remove":
            idx = self._selected_profiles_row()
            if idx is None:
                self.app.notify("Select a profile to remove", severity="warning", markup=False)
                return
            removed_name = self._profiles[idx].name
            # Warn if any rule references this profile
            referencing = [r.name for r in self._rules if r.profile_name == removed_name]
            if referencing:
                rule_list = ", ".join(escape(r) for r in referencing)
                self.app.notify(
                    f"Profile '{escape(removed_name)}' is used by rule(s): {rule_list}. "
                    "Remove or update those rules first.",
                    severity="error",
                    markup=False,
                )
                return
            del self._profiles[idx]
            self._refresh_profiles_table()
            self._dirty_watch()

        elif btn_id == "btn_profile_save":
            self._handle_profile_save()

        elif btn_id == "btn_profile_cancel":
            self._hide_profile_form()

        # ---- Rule buttons -------------------------------------------
        elif btn_id == "btn_rule_add":
            self._editing_rule_idx = None
            self._clear_rule_form()
            self._show_rule_form("Add Connection Rule")

        elif btn_id == "btn_rule_edit":
            idx = self._selected_rules_row()
            if idx is None:
                self.app.notify("Select a rule to edit", severity="warning", markup=False)
                return
            self._editing_rule_idx = idx
            self._populate_rule_form(self._rules[idx])
            self._show_rule_form(f"Edit Rule: {escape(self._rules[idx].name)}")

        elif btn_id == "btn_rule_remove":
            idx = self._selected_rules_row()
            if idx is None:
                self.app.notify("Select a rule to remove", severity="warning", markup=False)
                return
            del self._rules[idx]
            self._refresh_rules_table()
            self._dirty_watch()

        elif btn_id == "btn_rule_save":
            self._handle_rule_save()

        elif btn_id == "btn_rule_cancel":
            self._hide_rule_form()

    # ------------------------------------------------------------------
    # Profile / rule save handlers
    # ------------------------------------------------------------------

    def _handle_profile_save(self) -> None:
        """Validate and commit the profile form into self._profiles."""
        try:
            profile = self._collect_profile_form()
        except ValidationError as exc:
            self.mark_field_error(exc.field_id, exc.message)
            return

        if self._editing_profile_idx is not None:
            self._profiles[self._editing_profile_idx] = profile
        else:
            self._profiles.append(profile)

        self._refresh_profiles_table()
        self._hide_profile_form()
        self._dirty_watch()
        self.app.notify(
            f"Profile '{profile.name}' saved (not yet written — click Save below)",
            severity="information",
            markup=False,
        )

    def _handle_rule_save(self) -> None:
        """Validate and commit the rule form into self._rules."""
        try:
            rule = self._collect_rule_form()
        except ValidationError as exc:
            self.mark_field_error(exc.field_id, exc.message)
            return

        if self._editing_rule_idx is not None:
            self._rules[self._editing_rule_idx] = rule
        else:
            self._rules.append(rule)

        self._refresh_rules_table()
        self._hide_rule_form()
        self._dirty_watch()
        self.app.notify(
            f"Rule '{rule.name}' saved (not yet written — click Save below)",
            severity="information",
            markup=False,
        )

    # ------------------------------------------------------------------
    # Table row selection helpers
    # ------------------------------------------------------------------

    def _selected_profiles_row(self) -> Optional[int]:
        """Return the cursor row index in the profiles table, or None."""
        table = self.query_one("#conn_profiles_table", DataTable)
        if table.cursor_row is None or table.row_count == 0:
            return None
        idx = table.cursor_row
        if 0 <= idx < len(self._profiles):
            return idx
        return None

    def _selected_rules_row(self) -> Optional[int]:
        """Return the cursor row index in the rules table, or None."""
        table = self.query_one("#conn_rules_table", DataTable)
        if table.cursor_row is None or table.row_count == 0:
            return None
        idx = table.cursor_row
        if 0 <= idx < len(self._rules):
            return idx
        return None

    # ------------------------------------------------------------------
    # Dirty marker refresh on any widget change
    # ------------------------------------------------------------------

    def on_input_changed(self, _event: Input.Changed) -> None:
        """Refresh dirty marker when any input changes."""
        self._dirty_watch()
