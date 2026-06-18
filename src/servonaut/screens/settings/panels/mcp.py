"""MCP server settings panel.

Exposes the :class:`~servonaut.config.schema.MCPConfig` fields:

- ``guard_level`` — Select (readonly / standard / dangerous)
- ``command_blocklist`` — StringListEditor of regex patterns
- ``command_allowlist`` — StringListEditor of allowed command stems
- ``audit_path`` — path to the JSONL audit trail
- ``max_output_lines`` — integer cap on tool output length
- ``allow_destructive_aws_call`` — opt-in switch for destructive AWS verbs

Security warnings are shown inline next to the dangerous guard_level option
and the allow_destructive_aws_call switch, and the panel warns when the
blocklist is emptied before saving.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Dict, List

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Input, Select, Static, Switch

from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.screens.settings.widgets import StringListEditor

logger = logging.getLogger(__name__)

_GUARD_LEVEL_OPTIONS: List[tuple] = [
    ("Read-only", "readonly"),
    ("Standard", "standard"),
    ("Dangerous", "dangerous"),
]

# Inline warning text shown when certain risky options are in use.
_WARN_DANGEROUS_GUARD = (
    "Warning: 'Dangerous' tier grants the MCP client elevated tool access. "
    "Use only when you trust the AI agent fully."
)
_WARN_ALLOW_DESTRUCTIVE = (
    "Warning: Enabling this allows destructive AWS operations (delete/terminate/purge) "
    "through the generic aws_call tool. The dangerous guard tier is also required."
)
_WARN_EMPTY_BLOCKLIST = (
    "Warning: The command blocklist is empty. The MCP server will not block any "
    "commands by pattern. Re-add entries to restore protection."
)


class McpPanel(SettingsPanel):
    """Settings panel for the MCP server configuration.

    Fields map directly to :class:`~servonaut.config.schema.MCPConfig`.
    The panel uses ``dataclasses.replace`` to preserve un-exposed fields
    (none at present, but guards against future additions).
    """

    PANEL_ID = "mcp"
    TITLE = "MCP Server"

    DEFAULT_CSS = """
    McpPanel .mcp-warn {
        color: $warning;
        padding: 0 0 0 1;
        height: auto;
    }
    McpPanel .mcp-section-label {
        padding: 1 0 0 0;
        text-style: bold;
    }
    McpPanel .list-editor-label {
        padding: 1 0 0 0;
    }
    """

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:  # noqa: D102
        """Yield the MCP form rows."""
        # Guard level
        yield Horizontal(
            Static("Guard level", classes="label"),
            Select(
                _GUARD_LEVEL_OPTIONS,
                value="standard",
                allow_blank=False,
                id="mcp_guard_level",
            ),
            classes="setting_row",
        )
        yield Static(
            "",
            id="mcp_guard_warn",
            classes="mcp-warn",
        )

        # Audit path
        yield Horizontal(
            Static("Audit log path", classes="label"),
            Input(
                placeholder="~/.servonaut/mcp_audit.jsonl",
                id="mcp_audit_path",
            ),
            classes="setting_row",
        )

        # Max output lines
        yield Horizontal(
            Static("Max output lines", classes="label"),
            Input(placeholder="500", id="mcp_max_output_lines"),
            classes="setting_row",
        )

        # allow_destructive_aws_call switch
        yield Horizontal(
            Static("Allow destructive AWS calls", classes="label"),
            Switch(id="mcp_allow_destructive"),
            classes="setting_row",
        )
        yield Static(
            "",
            id="mcp_destructive_warn",
            classes="mcp-warn",
        )

        # Command blocklist
        yield Static("Command blocklist (regex patterns)", classes="mcp-section-label")
        yield Static(
            "Patterns that are ALWAYS refused, regardless of guard level. "
            "Leave empty at your own risk.",
            classes="list-editor-label",
        )
        yield Static(
            "",
            id="mcp_blocklist_warn",
            classes="mcp-warn",
        )
        yield StringListEditor(
            placeholder="regex pattern, e.g. rm\\s+-rf",
            id="mcp_blocklist",
        )

        # Command allowlist
        yield Static("Command allowlist (standard tier stems)", classes="mcp-section-label")
        yield Static(
            "Commands permitted under the 'standard' guard level.",
            classes="list-editor-label",
        )
        yield StringListEditor(
            placeholder="command stem, e.g. ls",
            id="mcp_allowlist",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate all widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()
        mcp = config.mcp

        guard = mcp.guard_level if mcp.guard_level in ("readonly", "standard", "dangerous") else "standard"
        self.query_one("#mcp_guard_level", Select).value = guard
        self._update_guard_warn(guard)

        self.query_one("#mcp_audit_path", Input).value = mcp.audit_path
        self.query_one("#mcp_max_output_lines", Input).value = str(mcp.max_output_lines)

        allow_destructive = bool(mcp.allow_destructive_aws_call)
        self.query_one("#mcp_allow_destructive", Switch).value = allow_destructive
        self._update_destructive_warn(allow_destructive)

        self.query_one("#mcp_blocklist", StringListEditor).set_values(list(mcp.command_blocklist))
        self.query_one("#mcp_allowlist", StringListEditor).set_values(list(mcp.command_allowlist))
        self._update_blocklist_warn(mcp.command_blocklist)

        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "guard_level": str(self.query_one("#mcp_guard_level", Select).value),
            "audit_path": self.query_one("#mcp_audit_path", Input).value.strip(),
            "max_output_lines": self.query_one("#mcp_max_output_lines", Input).value.strip(),
            "allow_destructive": self.query_one("#mcp_allow_destructive", Switch).value,
            "blocklist": self.query_one("#mcp_blocklist", StringListEditor).get_values(),
            "allowlist": self.query_one("#mcp_allowlist", StringListEditor).get_values(),
        }

    def collect(self) -> Dict[str, Any]:
        """Validate and return the MCP fields to persist.

        Raises:
            ValidationError: On invalid max_output_lines.
        """
        guard = str(self.query_one("#mcp_guard_level", Select).value)
        audit_path = self.query_one("#mcp_audit_path", Input).value.strip()
        max_lines_raw = self.query_one("#mcp_max_output_lines", Input).value.strip()

        try:
            max_lines = int(max_lines_raw)
        except ValueError as exc:
            raise ValidationError(
                "mcp_max_output_lines", "Max output lines must be a whole number"
            ) from exc
        if max_lines < 1:
            raise ValidationError(
                "mcp_max_output_lines", "Max output lines must be at least 1"
            )

        allow_destructive = bool(self.query_one("#mcp_allow_destructive", Switch).value)
        blocklist = self.query_one("#mcp_blocklist", StringListEditor).get_values()
        allowlist = self.query_one("#mcp_allowlist", StringListEditor).get_values()

        return {
            "guard": guard,
            "audit_path": audit_path or "~/.servonaut/mcp_audit.jsonl",
            "max_output_lines": max_lines,
            "allow_destructive": allow_destructive,
            "blocklist": blocklist,
            "allowlist": allowlist,
        }

    def persist(self) -> None:
        """Validate, warn on dangerous options, and write through config_manager."""
        fields = self.collect()

        blocklist: List[str] = fields["blocklist"]
        if not blocklist:
            self.app.notify(
                _WARN_EMPTY_BLOCKLIST,
                severity="warning",
                markup=False,
            )

        # Use dataclasses.replace so any future MCPConfig fields are preserved.
        config = self.app.config_manager.get()
        updated_mcp = dataclasses.replace(
            config.mcp,
            guard_level=fields["guard"],
            audit_path=fields["audit_path"],
            max_output_lines=fields["max_output_lines"],
            allow_destructive_aws_call=fields["allow_destructive"],
            command_blocklist=blocklist,
            command_allowlist=fields["allowlist"],
        )
        self.app.config_manager.update(mcp=updated_mcp)
        self._finish_save()

    # ------------------------------------------------------------------
    # Dirty marker refresh
    # ------------------------------------------------------------------

    def on_input_changed(self, _event: Input.Changed) -> None:
        """Refresh the dirty marker on any text input edit."""
        self._dirty_watch()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Refresh the dirty marker and update the guard warning on guard change."""
        self._dirty_watch()
        if event.select.id == "mcp_guard_level":
            self._update_guard_warn(str(event.value))

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Refresh the dirty marker and update the destructive warning."""
        self._dirty_watch()
        if event.switch.id == "mcp_allow_destructive":
            self._update_destructive_warn(bool(event.value))

    def on_button_pressed(self, event) -> None:
        """Delegate list-editor buttons then refresh dirty marker."""
        # Let the StringListEditor buttons propagate first; the base class
        # save button is handled by SettingsPanel.on_button_pressed, so we
        # call super() for that case only and update dirty on everything else.
        super().on_button_pressed(event)
        self._dirty_watch()
        # Update blocklist warning when a row is added/removed.
        try:
            blocklist = self.query_one("#mcp_blocklist", StringListEditor).get_values()
            self._update_blocklist_warn(blocklist)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Inline security warnings
    # ------------------------------------------------------------------

    def _update_guard_warn(self, guard: str) -> None:
        """Show or hide the dangerous guard level warning."""
        try:
            warn = self.query_one("#mcp_guard_warn", Static)
        except Exception:
            return
        if guard == "dangerous":
            warn.update(escape(_WARN_DANGEROUS_GUARD))
        else:
            warn.update("")

    def _update_destructive_warn(self, enabled: bool) -> None:
        """Show or hide the allow-destructive-aws-call warning."""
        try:
            warn = self.query_one("#mcp_destructive_warn", Static)
        except Exception:
            return
        if enabled:
            warn.update(escape(_WARN_ALLOW_DESTRUCTIVE))
        else:
            warn.update("")

    def _update_blocklist_warn(self, blocklist: list) -> None:
        """Show a warning when the command blocklist has been emptied."""
        try:
            warn = self.query_one("#mcp_blocklist_warn", Static)
        except Exception:
            return
        if not blocklist:
            warn.update(escape(_WARN_EMPTY_BLOCKLIST))
        else:
            warn.update("")
