"""The action rail every provider manager shares.

AWS, OVH and Hetzner list a provider's servers and act on the selected one.
Their rails differ only in which actions exist, so each screen describes its
actions as :class:`ActionSpec` rows and this module builds the groups
(inventory, power, danger zone) and keeps their enabled state in step with
the selected row.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.screen import Screen
from textual.widgets import Static

from servonaut.widgets.action_button import ActionButton, ActionRole, ActionRow


@dataclass(frozen=True)
class ActionSpec:
    """One action in a provider manager's rail."""

    button_id: str
    text: str
    key: str | None = None
    role: ActionRole = "default"
    short: str | None = None
    # Row actions start disabled until a row is selected.
    disabled: bool = True


def _button(spec: ActionSpec) -> ActionButton:
    return ActionButton(
        spec.text, spec.key, role=spec.role, short=spec.short,
        id=spec.button_id, disabled=spec.disabled,
    )


def _group(label: str, specs: Sequence[ActionSpec], *, classes: str = "") -> Horizontal:
    return Horizontal(
        Static(label, classes="provider-manager-action-label", markup=False),
        ActionRow(*(_button(spec) for spec in specs), classes="provider-manager-buttons"),
        classes=f"provider-manager-action-group {classes}".strip(),
    )


def action_rail(
    rail_id: str,
    *,
    inventory: Sequence[ActionSpec],
    selection: Vertical,
    power: Sequence[ActionSpec],
    danger: Sequence[ActionSpec],
    power_label: str = "Selected server",
) -> Vertical:
    """The rail: inventory actions, the selection, power actions, then the danger zone.

    The danger zone is its own group, set apart from the everyday actions, and
    holds the actions that destroy something (their confirmation dialogs stay
    with the screens).
    """
    return Vertical(
        _group("Inventory", inventory),
        selection,
        _group(power_label, power),
        _group("Danger zone", danger, classes="provider-manager-danger"),
        id=rail_id,
        classes="provider-manager-actions",
    )


class ProviderActionsMixin:
    """Switch a manager's action buttons to their compact form when its layout is narrow."""

    def sync_workspace_controls(self) -> None:
        super().sync_workspace_controls()  # type: ignore[misc]
        self.sync_compact_actions()

    def sync_compact_actions(self) -> None:
        compact = self.has_class("-content-narrow")  # type: ignore[attr-defined]
        for button in self.query(ActionButton):  # type: ignore[attr-defined]
            button.compact = compact
        for row in self.query(ActionRow):  # type: ignore[attr-defined]
            row.fit()


def sync_actions(
    screen: Screen,
    unavailable: Mapping[str, str | None],
) -> None:
    """Enable each action that has no reason against it and explain the others.

    *unavailable* maps a button id to why it cannot be used now (``None`` when
    it can). A disabled button keeps its reason as its tooltip.
    """
    for button_id, reason in unavailable.items():
        try:
            button = screen.query_one(f"#{button_id}", ActionButton)
        except NoMatches:  # pragma: no cover - defensive
            continue
        button.disabled = reason is not None
        button.tooltip = reason


def unless(has_row: bool, available: bool, reason: str) -> str | None:
    """Why an action cannot be used now, or ``None`` when it can.

    Without a selected row every action asks for one first; otherwise
    *reason* explains what the row's state lacks.
    """
    if not has_row:
        return "Select a server first."
    return None if available else reason
