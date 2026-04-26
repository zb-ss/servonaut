"""ShareInstanceScreen — share a server memory instance with team members.

Tier-gated on ``memory_team_share``.  Allows selecting a team, role, and
module subset, then calls ``TeamMemoryService.share_instance``.

Converted from a ModalScreen to a full Screen so the persistent sidebar
is visible during the workflow — the multi-step nature (team / role /
modules / member key fetch / share) felt out of place as a popup.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Select, SelectionList, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)

_ROLE_OPTIONS: List[tuple[str, str]] = [
    ("Viewer", "viewer"),
    ("Member", "member"),
    ("Admin", "admin"),
]

_DEFAULT_MODULES = ["os", "runtimes", "services", "git", "logs", "ports"]


class ShareInstanceScreen(Screen):
    """Screen for sharing a server memory instance with a team.

    Args:
        instance: Instance dict with ``id``, ``name``, ``provider`` keys.

    On success surfaces a notify and pops back to the previous screen
    (typically Fleet Memory). The grant dataclass is no longer returned
    via dismiss — the only existing caller didn't read it anyway.
    """

    DEFAULT_CSS = """
    ShareInstanceScreen #share_outer {
        width: 1fr;
        height: 100%;
        padding: 1 2;
        align: center middle;
        background: $surface;
    }
    ShareInstanceScreen #share-container {
        width: 80%;
        max-width: 90;
        height: auto;
        border: round $primary;
        background: $surface;
        padding: 2 4;
    }
    ShareInstanceScreen #share-title {
        text-style: bold;
        margin-bottom: 1;
    }
    ShareInstanceScreen #share-status {
        height: 1;
        margin-bottom: 1;
    }
    ShareInstanceScreen .share-field-row {
        height: auto;
        margin-bottom: 1;
    }
    ShareInstanceScreen #share-btn-row {
        height: auto;
        align: center middle;
        margin-top: 1;
    }
    ShareInstanceScreen #share-btn-row Button {
        margin: 0 1;
        min-width: 16;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def __init__(self, instance: Dict[str, Any]) -> None:
        super().__init__()
        self._instance = instance
        self._teams: List[Dict[str, Any]] = []
        self._member_pubkeys: List[Any] = []

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        from rich.markup import escape as rich_escape
        name = rich_escape(str(self._instance.get("name") or self._instance.get("id", "?")))
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Container(
                    Static(
                        f"[bold cyan]Share Memory: {name}[/bold cyan]",
                        id="share-title",
                    ),
                    Static("", id="share-status"),
                    VerticalScroll(
                        Container(
                            Label("Team"),
                            Select(
                                options=[("Loading...", "__loading__")],
                                value="__loading__",
                                id="share-team-select",
                            ),
                            classes="share-field-row",
                        ),
                        Container(
                            Label("Required Role"),
                            Select(
                                options=_ROLE_OPTIONS,
                                value="viewer",
                                id="share-role-select",
                            ),
                            classes="share-field-row",
                        ),
                        Container(
                            Label("Modules (all if empty)"),
                            SelectionList(
                                *[(m, m, True) for m in _DEFAULT_MODULES],
                                id="share-modules-list",
                            ),
                            classes="share-field-row",
                        ),
                        id="share-form-scroll",
                    ),
                    Horizontal(
                        Button("Cancel", variant="default", id="share-btn-cancel"),
                        Button(
                            "Share", variant="primary", id="share-btn-confirm", disabled=True,
                        ),
                        id="share-btn-row",
                    ),
                    id="share-container",
                ),
                id="share_outer",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Mount
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        auth = getattr(self.app, "auth_service", None)
        if auth and not auth.has_feature("memory_team_share"):
            from servonaut.widgets.upsell_modal import UpsellModal
            self.app.pop_screen()
            self.app.push_screen(UpsellModal("memory_team_share"))
            return
        self.run_worker(self._load_teams(), group="memory_fleet", name="share_load_teams")

    async def _load_teams(self) -> None:
        auth = getattr(self.app, "auth_service", None)
        if auth is None:
            return
        try:
            teams = await auth.list_teams()
            self._teams = teams or []
        except Exception as exc:
            logger.error("Failed to load teams: %s", exc)
            self._teams = []
        team_options = [
            (t.get("name", t.get("slug", "?")), t.get("slug", "?"))
            for t in self._teams
        ] or [("No teams available", "__none__")]
        try:
            sel = self.query_one("#share-team-select", Select)
            sel.set_options(team_options)
            if team_options:
                sel.value = team_options[0][1]
        except Exception:
            pass
        if self._teams:
            self.query_one("#share-btn-confirm", Button).disabled = False

    # ------------------------------------------------------------------
    # Share action
    # ------------------------------------------------------------------

    def action_cancel(self) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "share-btn-confirm":
            self.run_worker(self._do_share(), group="memory_fleet", name="share_execute", exclusive=True)
        elif event.button.id == "share-btn-cancel":
            self.action_cancel()

    async def _do_share(self) -> None:
        team_memory_service = getattr(self.app, "team_memory_service", None)
        status = self.query_one("#share-status", Static)
        if team_memory_service is None:
            status.update("[red]Team memory service not available.[/red]")
            return
        try:
            team_slug = str(self.query_one("#share-team-select", Select).value or "")
            role = str(self.query_one("#share-role-select", Select).value or "viewer")
            module_sel = self.query_one("#share-modules-list", SelectionList)
            modules = list(module_sel.selected) or None
            instance_id = self._instance.get("id") or self._instance.get("name", "")
            status.update("[yellow]Fetching member keys…[/yellow]")
            member_keys = await team_memory_service.list_team_member_keys(team_slug)
            status.update("[yellow]Sharing…[/yellow]")
            await team_memory_service.share_instance(
                team_slug=team_slug,
                instance_id=instance_id,
                required_role=role,
                modules=modules,
                member_pubkeys=member_keys,
            )
            status.update("[green]Shared successfully.[/green]")
            self.app.notify(
                f"Shared {instance_id} with team {team_slug}.",
                severity="information",
            )
            self.app.pop_screen()
        except Exception as exc:
            logger.error("Share failed: %s", exc)
            from rich.markup import escape as _esc
            status.update(f"[red]Share failed: {_esc(str(exc))}[/red]")


# Back-compat alias — the previous class name lives on so any cached
# import in a long-running session keeps working until the next reboot.
ShareInstanceModal = ShareInstanceScreen
