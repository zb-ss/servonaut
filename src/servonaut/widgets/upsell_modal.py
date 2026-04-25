"""Upsell, beta-waitlist, and backend-maintenance modal widgets.

These modals are pushed when a tier-gated feature is accessed without the
required entitlement, when the user is on the beta waitlist, or when the
backend is undergoing maintenance.
"""

from __future__ import annotations

import webbrowser
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Static


# Entitlement-key → human-readable copy.
_UPSELL_COPY: dict[str, tuple[str, str]] = {
    "memory_sync": (
        "Memory Sync",
        "Sync your server memory to the cloud for cross-device access, "
        "history, and team sharing. Upgrade your plan to enable this feature.",
    ),
    "memory_drift": (
        "Memory Drift Detection",
        "Track configuration drift and anomalies across your fleet over time. "
        "Upgrade to a paid plan to unlock drift detection.",
    ),
    "memory_team_share": (
        "Team Memory Sharing",
        "Share server memory and grants with your team members. "
        "Upgrade to a Teams plan to enable sharing.",
    ),
    "memory_ai_summary": (
        "AI Memory Summaries",
        "Generate AI-powered summaries of your server memory using your choice "
        "of provider. Upgrade to enable AI summaries.",
    ),
    "memory_compliance_export": (
        "Compliance Export",
        "Export a signed, verifiable archive of your server memory for "
        "compliance and auditing. Upgrade to enable exports.",
    ),
    "team_workspaces": (
        "Team Workspaces",
        "Manage team members, roles, and shared server access. "
        "Upgrade to a Teams plan to unlock this feature.",
    ),
}

_DEFAULT_UPSELL = (
    "Premium Feature",
    "This feature requires an upgraded plan. Visit servonaut.dev/pricing to learn more.",
)

_BILLING_URL = "https://servonaut.dev/pricing"


class UpsellModal(ModalScreen[None]):
    """Modal shown when the user accesses a feature without the required entitlement.

    Args:
        entitlement_key: The feature slug that is required (e.g. ``"memory_sync"``).
    """

    DEFAULT_CSS = """
    UpsellModal {
        align: center middle;
    }

    #upsell-container {
        width: 64;
        height: auto;
        border: round $warning;
        background: $surface;
        padding: 1 2;
    }

    #upsell-title {
        text-style: bold;
        color: $warning;
        margin-bottom: 1;
    }

    #upsell-body {
        margin-bottom: 1;
    }

    #upsell-btn-row {
        height: auto;
        align: right middle;
        margin-top: 1;
    }

    #upsell-btn-close {
        margin-right: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "close", "Close", show=True),
    ]

    def __init__(self, entitlement_key: str) -> None:
        super().__init__()
        self._key = entitlement_key

    def compose(self) -> ComposeResult:
        feature_name, description = _UPSELL_COPY.get(self._key, _DEFAULT_UPSELL)
        yield Container(
            Static(
                f"[bold yellow]Upgrade Required: {feature_name}[/bold yellow]",
                id="upsell-title",
            ),
            Static(description, id="upsell-body"),
            Horizontal(
                Button("Close", variant="default", id="upsell-btn-close"),
                Button("View Plans", variant="warning", id="upsell-btn-upgrade"),
                id="upsell-btn-row",
            ),
            id="upsell-container",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "upsell-btn-upgrade":
            webbrowser.open(_BILLING_URL)
        self.dismiss()

    def action_close(self) -> None:
        self.dismiss()


class BetaWaitlistModal(ModalScreen[None]):
    """Modal shown when the user's account is on the beta waitlist for memory sync."""

    DEFAULT_CSS = """
    BetaWaitlistModal {
        align: center middle;
    }

    #waitlist-container {
        width: 60;
        height: auto;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }

    #waitlist-title {
        text-style: bold;
        margin-bottom: 1;
    }

    #waitlist-body {
        margin-bottom: 1;
    }

    #waitlist-btn-row {
        height: auto;
        align: center middle;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "close", "Close", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                "[bold cyan]You're on the Waitlist[/bold cyan]",
                id="waitlist-title",
            ),
            Static(
                "Memory sync is in private beta. You're on the waitlist and will "
                "be notified by email when access is granted.",
                id="waitlist-body",
            ),
            Horizontal(
                Button("OK", variant="primary", id="waitlist-btn-ok"),
                id="waitlist-btn-row",
            ),
            id="waitlist-container",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()

    def action_close(self) -> None:
        self.dismiss()


class BackendMaintenanceModal(ModalScreen[None]):
    """Modal shown when the memory sync backend is undergoing maintenance."""

    DEFAULT_CSS = """
    BackendMaintenanceModal {
        align: center middle;
    }

    #maintenance-container {
        width: 60;
        height: auto;
        border: round $error;
        background: $surface;
        padding: 1 2;
    }

    #maintenance-title {
        text-style: bold;
        color: $error;
        margin-bottom: 1;
    }

    #maintenance-body {
        margin-bottom: 1;
    }

    #maintenance-btn-row {
        height: auto;
        align: center middle;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "close", "Close", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                "[bold red]Memory Sync Unavailable[/bold red]",
                id="maintenance-title",
            ),
            Static(
                "The memory sync backend is currently undergoing maintenance. "
                "Local memory features continue to work. "
                "Cloud sync will resume automatically once maintenance is complete.",
                id="maintenance-body",
            ),
            Horizontal(
                Button("OK", variant="default", id="maintenance-btn-ok"),
                id="maintenance-btn-row",
            ),
            id="maintenance-container",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()

    def action_close(self) -> None:
        self.dismiss()
