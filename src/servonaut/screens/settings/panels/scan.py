"""Scan settings panel — default scan paths and scan rules editor.

Covers:
- ``default_scan_paths`` (List[str]) — edited with :class:`StringListEditor`.
- ``scan_rules`` (List[ScanRule]) — full add/edit/remove editor for name,
  match_conditions (Dict[str, str]), scan_paths (List[str]), and
  scan_commands (List[str]).

The legacy monolith exposed scan paths as an add/remove list and scan rules as
a read-only DataTable.  This panel upgrades scan rules to a fully editable
CRUD form, while porting the scan-path list editor faithfully.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, Static

from servonaut.config.schema import ScanRule
from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.screens.settings.widgets import KeyValueEditor, StringListEditor

logger = logging.getLogger(__name__)


class ScanPanel(SettingsPanel):
    """Scan configuration: default scan paths and scan rules (full CRUD)."""

    PANEL_ID = "scan"
    TITLE = "Scan"

    DEFAULT_CSS = """
    ScanPanel .scan-section-title {
        color: $accent;
        text-style: bold;
        margin: 1 0 0 0;
        padding: 0 1;
    }
    ScanPanel .scan-rule-card {
        border: round $primary;
        padding: 1;
        margin: 0 0 1 0;
        height: auto;
    }
    ScanPanel .scan-rule-header {
        height: auto;
        margin: 0 0 1 0;
    }
    ScanPanel .scan-rule-name-label {
        color: $accent;
        text-style: bold;
        width: 1fr;
    }
    ScanPanel .scan-rule-sublabel {
        color: $text-muted;
        height: auto;
        padding: 0 1;
        margin: 0 0 0 0;
    }
    ScanPanel .scan-add-rule-row {
        height: auto;
        margin: 1 0 0 0;
    }
    ScanPanel .scan-new-rule-name {
        width: 1fr;
    }
    ScanPanel .scan-rule-remove {
        width: 10;
        min-width: 10;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        # Runtime state for the scan-rules editor: list of dicts mirroring each
        # ScanRule, plus their widget containers so we can read values back.
        self._rule_cards: List[Dict[str, Any]] = []
        # Monotonic id counter: only ever increments, never reset on remove, so
        # card/child widget ids are never reused within the panel's lifetime
        # (reusing a survivor's index would raise Textual DuplicateIds on add).
        self._next_rule_idx: int = 0
        # Container node for rule cards — populated in compose and reused.
        self._rules_container: Optional[Vertical] = None
        # Snapshot for dirty detection (rules component tracked separately).
        self._scan_paths_editor: Optional[StringListEditor] = None

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield the scan-paths list editor and the scan-rules CRUD panel."""
        yield Static("Default Scan Paths", classes="scan-section-title")
        yield Static(
            "Paths scanned on every instance during a global scan.",
            classes="scan-rule-sublabel",
        )
        scan_paths_editor = StringListEditor(
            placeholder="/path/to/scan",
            id="scan_default_paths_editor",
        )
        self._scan_paths_editor = scan_paths_editor
        yield scan_paths_editor

        yield Static("Scan Rules", classes="scan-section-title")
        yield Static(
            "Rules apply conditional scanning based on instance attributes. "
            "First-match wins when multiple rules target the same instance.",
            classes="scan-rule-sublabel",
        )
        # Rule cards flow directly in the panel body (which scrolls as a whole)
        # — no nested scroll region, so there is only ever one scrollbar.
        rules_container = Vertical(id="scan_rules_container")
        self._rules_container = rules_container
        yield rules_container
        yield Static(
            "Type a name and press “+ Add Rule” to append a new rule above.",
            classes="scan-rule-sublabel",
        )
        yield Horizontal(
            Input(
                placeholder="New rule name…",
                id="scan_new_rule_name",
                classes="scan-new-rule-name",
            ),
            Button("+ Add Rule", id="scan_btn_add_rule", variant="primary"),
            classes="scan-add-rule-row",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()

        # -- Default scan paths --
        editor = self.query_one("#scan_default_paths_editor", StringListEditor)
        editor.set_values(list(config.default_scan_paths))

        # -- Scan rules --
        self._rebuild_rule_cards(config.scan_rules)

        self._snapshot_now()

    def _rebuild_rule_cards(self, rules: List[ScanRule]) -> None:
        """Replace all rule cards with *rules*.

        Clears the existing card state before mounting fresh widgets so this is
        safe to call from both :meth:`load` (initial) and :meth:`discard`.
        """
        container = self.query_one("#scan_rules_container", Vertical)
        container.remove_children()
        self._rule_cards = []
        # Full rebuild removes every existing card, so it is safe to restart the
        # monotonic id counter from zero here.
        self._next_rule_idx = 0
        for rule in rules:
            self._mount_rule_card(container, rule)

    def _mount_rule_card(self, container: Vertical, rule: ScanRule) -> None:
        """Mount a single rule card into *container* and register it."""
        idx = self._next_rule_idx
        self._next_rule_idx += 1
        card_id = f"scan_rule_card_{idx}"

        name_input = Input(value=rule.name, placeholder="Rule name", id=f"scan_rule_name_{idx}")
        conditions_editor = KeyValueEditor(
            key_placeholder="condition (e.g. name_contains)",
            value_placeholder="value",
            id=f"scan_rule_conditions_{idx}",
        )
        conditions_editor.set_map(dict(rule.match_conditions))

        paths_editor = StringListEditor(
            placeholder="/path/to/scan",
            id=f"scan_rule_paths_{idx}",
        )
        paths_editor.set_values(list(rule.scan_paths))

        commands_editor = StringListEditor(
            placeholder="command to run",
            id=f"scan_rule_commands_{idx}",
        )
        commands_editor.set_values(list(rule.scan_commands))

        remove_btn = Button("Remove", id=f"scan_rule_remove_{idx}", classes="scan-rule-remove", variant="error")

        card = Vertical(
            Horizontal(
                Label(escape(rule.name) if rule.name else "(unnamed rule)", id=f"scan_rule_label_{idx}", classes="scan-rule-name-label"),
                remove_btn,
                classes="scan-rule-header",
            ),
            Static("Name:", classes="scan-rule-sublabel"),
            name_input,
            Static("Match Conditions (key → value):", classes="scan-rule-sublabel"),
            conditions_editor,
            Static("Scan Paths:", classes="scan-rule-sublabel"),
            paths_editor,
            Static("Scan Commands:", classes="scan-rule-sublabel"),
            commands_editor,
            id=card_id,
            classes="scan-rule-card",
        )
        container.mount(card)

        self._rule_cards.append({
            "card_id": card_id,
            "idx": idx,
            "name_id": f"scan_rule_name_{idx}",
            "conditions_id": f"scan_rule_conditions_{idx}",
            "paths_id": f"scan_rule_paths_{idx}",
            "commands_id": f"scan_rule_commands_{idx}",
            "remove_id": f"scan_rule_remove_{idx}",
            "label_id": f"scan_rule_label_{idx}",
        })

    # ------------------------------------------------------------------
    # Dirty tracking
    # ------------------------------------------------------------------

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison.

        For scan paths this is a plain list comparison. For scan rules we
        return a serialised-list representation so the base snapshot diff works.
        """
        try:
            paths = self.query_one("#scan_default_paths_editor", StringListEditor).get_values()
        except Exception:
            paths = []
        return {
            "default_scan_paths": paths,
            "scan_rules": self._collect_rule_dicts(),
        }

    def _collect_rule_dicts(self) -> List[Dict[str, Any]]:
        """Read all rule cards into a list of plain dicts for comparison / persistence."""
        out: List[Dict[str, Any]] = []
        for info in self._rule_cards:
            try:
                card = self.query_one(f"#{info['card_id']}")
            except Exception:
                continue
            try:
                name = card.query_one(f"#{info['name_id']}", Input).value.strip()
            except Exception:
                name = ""
            try:
                conditions = dict(card.query_one(f"#{info['conditions_id']}", KeyValueEditor).get_map())
            except Exception:
                conditions = {}
            try:
                paths = card.query_one(f"#{info['paths_id']}", StringListEditor).get_values()
            except Exception:
                paths = []
            try:
                commands = card.query_one(f"#{info['commands_id']}", StringListEditor).get_values()
            except Exception:
                commands = []
            out.append({
                "name": name,
                "conditions": conditions,
                "paths": paths,
                "commands": commands,
                # Real widget id so validation can focus the right field even
                # after a mid-list remove leaves indices non-contiguous.
                "name_id": info["name_id"],
            })
        return out

    # ------------------------------------------------------------------
    # Validation & persistence
    # ------------------------------------------------------------------

    def collect(self) -> Dict[str, Any]:
        """Read and validate widgets; raise :class:`ValidationError` on bad input.

        Returns:
            A dict with ``default_scan_paths`` and ``scan_rules`` keys.

        Raises:
            ValidationError: When a rule name is empty or conditions editor
                holds a non-integer value where an int is expected.
        """
        default_paths = self.query_one("#scan_default_paths_editor", StringListEditor).get_values()

        rule_dicts = self._collect_rule_dicts()
        rules: List[ScanRule] = []
        for i, rd in enumerate(rule_dicts):
            if not rd["name"]:
                raise ValidationError(
                    rd["name_id"],
                    f"Scan rule #{i + 1} must have a name",
                )
            rules.append(
                ScanRule(
                    name=rd["name"],
                    match_conditions={str(k): str(v) for k, v in rd["conditions"].items()},
                    scan_paths=rd["paths"],
                    scan_commands=rd["commands"],
                )
            )

        return {
            "default_scan_paths": default_paths,
            "scan_rules": rules,
        }

    def persist(self) -> None:
        """Validate via :meth:`collect` then write through ``config_manager``."""
        fields = self.collect()
        self.app.config_manager.update(
            default_scan_paths=fields["default_scan_paths"],
            scan_rules=fields["scan_rules"],
        )
        self._finish_save()

    # ------------------------------------------------------------------
    # Button handlers (add rule / remove rule)
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle add/remove rule buttons and delegate Save to the base class."""
        btn_id = event.button.id or ""

        if btn_id == "scan_btn_add_rule":
            event.stop()
            self._handle_add_rule()
            return

        if btn_id.startswith("scan_rule_remove_"):
            event.stop()
            self._handle_remove_rule(btn_id)
            return

        # Delegate Save button to base class.
        super().on_button_pressed(event)

    def _handle_add_rule(self) -> None:
        """Add a new empty rule card from the name input."""
        name_input = self.query_one("#scan_new_rule_name", Input)
        name = name_input.value.strip()
        container = self.query_one("#scan_rules_container", Vertical)
        new_rule = ScanRule(name=name, match_conditions={})
        self._mount_rule_card(container, new_rule)
        name_input.value = ""
        self._dirty_watch()

    def _handle_remove_rule(self, btn_id: str) -> None:
        """Remove the rule card matching *btn_id*."""
        try:
            idx = int(btn_id.split("_")[-1])
        except (ValueError, IndexError):
            return
        card_id = f"scan_rule_card_{idx}"
        try:
            self.query_one(f"#{card_id}").remove()
        except Exception:
            pass
        self._rule_cards = [c for c in self._rule_cards if c["idx"] != idx]
        self._dirty_watch()

    # ------------------------------------------------------------------
    # Dirty marker refresh hooks
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Refresh dirty marker on any input edit, including rule fields."""
        self._dirty_watch()
