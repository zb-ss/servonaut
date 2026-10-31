"""ShareInstanceScreen — share a server memory instance with team members.

Tier-gated on ``memory_team_share``.  Allows selecting a team, role, and
module subset, then calls ``TeamMemoryService.share_instance``.

Before sharing, the form lists the members who will be able to read the
server. When the server is already shared with the chosen team it shows that
share instead, with Revoke, Share again and, behind a confirmation, a purge
of the members' copies.

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
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, Label, Select, SelectionList, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)

_ROLE_OPTIONS: List[tuple[str, str]] = [
    ("Viewer", "viewer"),
    ("Member", "member"),
    ("Admin", "admin"),
]

# Probed modules ticked by default: exactly what earlier releases offered
# (minus a name the server never accepted). Every other module is offered
# UNTICKED, so a default share never exposes more than it used to; widening
# the default is a product decision, not a picker change.
_DEFAULT_SHARED_MODULES = frozenset({"os", "runtimes", "services", "git", "logs"})

# User- and agent-authored modules. Offered, but unticked by default: they
# can hold free-form notes, so sharing them is an explicit opt-in.
_AUTHORED_MODULES = ["annotations", "findings"]


# Placeholder values of the team picker; neither names a team.
_NO_TEAM_VALUES = frozenset({"__loading__", "__none__"})


def _names(app: Any, names: List[str]) -> str:
    """Markup-safe, comma-separated names; stand-ins in demo mode."""
    from rich.markup import escape

    redaction = getattr(app, "redaction_service", None)
    demo = bool(getattr(app, "demo_mode", False)) and redaction is not None
    shown = [redaction.redact_name(n) if demo else n for n in names]
    return escape(", ".join(shown))


def _module_options() -> List[tuple[str, str, bool]]:
    """``(label, value, selected)`` rows for the module picker.

    Probed modules come from the prober registry so the picker can never
    drift from the module names the server accepts.
    """
    from servonaut.services.memory.modules import default_module_names

    probed = [
        (m, m, m in _DEFAULT_SHARED_MODULES) for m in default_module_names()
    ]
    authored = [(m, m, False) for m in _AUTHORED_MODULES]
    return probed + authored


class PurgeCopiesModal(ModalScreen[bool]):
    """Asks before the members' copies of a shared server are deleted."""

    DEFAULT_CSS = """
    PurgeCopiesModal { align: center middle; }
    PurgeCopiesModal #purge-box {
        width: 64;
        height: auto;
        border: round $error;
        background: $surface;
        padding: 1 2;
    }
    PurgeCopiesModal #purge-btn-row { height: auto; align: center middle; margin-top: 1; }
    PurgeCopiesModal #purge-btn-row Button { margin: 0 1; }
    """

    BINDINGS = [Binding("escape", "dismiss(False)", "Cancel", show=True)]

    def compose(self) -> ComposeResult:
        with Container(id="purge-box"):
            yield Static("[bold]Delete the members' copies?[/bold]", id="purge-title")
            yield Static(
                "This stops the sharing and deletes the copies the team's "
                "members hold. Your own memory is not touched. They cannot "
                "read the server again until you share it again.",
                id="purge-text",
            )
            with Horizontal(id="purge-btn-row"):
                yield Button("Cancel", id="purge-btn-cancel")
                yield Button("Delete copies", variant="error", id="purge-btn-confirm")

    def on_mount(self) -> None:
        self.query_one("#purge-btn-cancel", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "purge-btn-confirm")


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
    ShareInstanceScreen #share-readers,
    ShareInstanceScreen #share-existing-text {
        height: auto;
        margin-bottom: 1;
    }
    ShareInstanceScreen #share-existing {
        height: auto;
        display: none;
    }
    ShareInstanceScreen #share-existing.-shown { display: block; }
    ShareInstanceScreen #share-existing-row {
        height: auto;
        layout: vertical;
    }
    ShareInstanceScreen #share-existing-row Button {
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
        self._keys_by_team: Dict[str, List[Any]] = {}
        self._grant: Any = None

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        from rich.markup import escape as rich_escape
        name = rich_escape(str(self._instance.get("name") or self._instance.get("id", "?")))
        yield SafeHeader()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Container(
                    Static(
                        f"[bold $text-accent]Share Memory: {name}[/bold $text-accent]",
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
                        Static("", id="share-readers"),
                        Container(
                            Static("", id="share-existing-text"),
                            Container(
                                Button("Revoke", id="share-btn-revoke"),
                                Button("Share again", id="share-btn-reshare"),
                                Button(
                                    "Revoke and delete members' copies",
                                    variant="error",
                                    id="share-btn-purge",
                                ),
                                id="share-existing-row",
                            ),
                            id="share-existing",
                        ),
                        Container(
                            Label("Modules to share"),
                            SelectionList(
                                *_module_options(),
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
            (self._team_label(t), t.get("slug", "?"))
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

    def _team_label(self, team: Dict[str, Any]) -> str:
        """The team as the picker shows it (a stand-in in demo mode)."""
        name = str(team.get("name", team.get("slug", "?")))
        redaction = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redaction is not None:
            return redaction.redact_name(name)
        return name

    def _say(self, widget: Static, markup: str) -> None:
        """Write one status text. Callers pass fixed text, text run through
        ``rich.markup.escape``, or names from :func:`_names` (stand-ins in
        demo mode), so nothing real reaches a demo recording."""
        widget.update(markup)

    def _say_to(self, selector: str, markup: str) -> None:
        self._say(self.query_one(selector, Static), markup)

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the team names and the readers for the new demo mode."""
        if not self._teams:
            return
        select = self.query_one("#share-team-select", Select)
        chosen = select.value
        select.set_options([(self._team_label(t), t.get("slug", "?")) for t in self._teams])
        if isinstance(chosen, str):
            select.value = chosen
        self._render_form(self._selected_team(), None)

    # ------------------------------------------------------------------
    # Who can read it, and the share that exists
    # ------------------------------------------------------------------

    def _selected_team(self) -> str:
        value = self.query_one("#share-team-select", Select).value
        if not isinstance(value, str) or value in _NO_TEAM_VALUES:
            return ""
        return value

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "share-team-select":
            self._start_refresh(reload=True)
        elif event.select.id == "share-role-select":
            self._start_refresh(reload=False)

    def _start_refresh(self, *, reload: bool) -> None:
        self.run_worker(
            self._refresh_form(reload),
            group="memory_share_form",
            name="share_refresh",
            exclusive=True,
        )

    async def _refresh_form(self, reload: bool) -> None:
        """Show who can read the share, and the share already in place."""
        team_memory_service = getattr(self.app, "team_memory_service", None)
        slug = self._selected_team()
        if team_memory_service is None or not slug:
            self._grant = None
            self._render_form(slug)
            return
        status = self.query_one("#share-status", Static)
        if reload or slug not in self._keys_by_team:
            self._say(status, "[$text-warning]Checking who can read it…[/$text-warning]")
            try:
                self._keys_by_team[slug] = await team_memory_service.list_team_member_keys(slug)
                self._grant = await team_memory_service.find_live_grant(slug, self._instance_id())
            except Exception as exc:  # noqa: BLE001 — a worker reports, never crashes the screen
                logger.error("Could not load the share state: %s", exc)
                self._grant = None
                self._keys_by_team.pop(slug, None)
                self._show_error(f"Could not check the share: {exc}")
                self._render_form(slug)
                return
            self._say(status, "")
        self._render_form(slug)

    def _instance_id(self) -> str:
        return str(self._instance.get("id") or self._instance.get("name", ""))

    def _render_form(self, slug: str, pending: Optional[List[Dict[str, Any]]] = None) -> None:
        """Draw the readers line and the existing-share panel."""
        role = str(self.query_one("#share-role-select", Select).value or "viewer")
        keys = self._keys_by_team.get(slug)
        readers = self.query_one("#share-readers", Static)
        if keys is None:
            self._say(readers, "")
        else:
            service = getattr(self.app, "team_memory_service", None)
            eligible = service.eligible_members(keys, role) if service else keys
            who = _names(self.app, [m.name or f"member {m.user_id}" for m in eligible])
            line = (
                f"Will be able to read it ({len(eligible)}): {who}"
                if eligible
                else "No member with a memory key has this role yet."
            )
            line += (
                "\nMembers who set up Memory Sync later are added "
                "automatically on the next sync."
            )
            if pending:
                waiting = _names(self.app, [str(p.get("name") or f"member {p.get('user_id')}") for p in pending])
                line += (
                    f"\nNo memory key yet: {waiting}. Ask them to set up Memory Sync."
                )
            self._say(readers, line)
        self._render_existing()

    def _render_existing(self) -> None:
        panel = self.query_one("#share-existing")
        grant = self._grant
        panel.set_class(grant is not None, "-shown")
        self.query_one("#share-btn-confirm", Button).disabled = bool(grant) or not self._teams
        if grant is None:
            return
        modules = ", ".join(grant.modules) if grant.modules else "all modules"
        from rich.markup import escape

        self._say_to("#share-existing-text",
            f"Already shared with this team: role {escape(grant.required_role)}, "
            f"modules {escape(modules)}."
        )

    def _show_error(self, message: str) -> None:
        from rich.markup import escape

        self._say_to("#share-status",
            f"[$text-error]{escape(message)}[/$text-error]"
        )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_cancel(self) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "share-btn-confirm":
            self.run_worker(self._do_share(), group="memory_share", name="share_execute", exclusive=True)
        elif button_id == "share-btn-cancel":
            self.action_cancel()
        elif button_id == "share-btn-revoke":
            self.run_worker(self._do_revoke(), group="memory_share", name="share_revoke", exclusive=True)
        elif button_id == "share-btn-reshare":
            self.run_worker(self._do_reshare(), group="memory_share", name="share_again", exclusive=True)
        elif button_id == "share-btn-purge":
            self.app.push_screen(PurgeCopiesModal(), self._on_purge_answer)

    def _on_purge_answer(self, confirmed: Optional[bool]) -> None:
        if confirmed:
            self.run_worker(self._do_purge(), group="memory_share", name="share_purge", exclusive=True)

    def _form_choices(self) -> Optional[tuple]:
        """``(team, role, modules)`` from the form, or None after saying why."""
        team_slug = self._selected_team()
        role = str(self.query_one("#share-role-select", Select).value or "viewer")
        # Always an explicit whitelist: an empty selection must never
        # widen into "share everything".
        modules = list(self.query_one("#share-modules-list", SelectionList).selected)
        if not modules:
            self._say_to("#share-status",
                "[$text-error]Select at least one module to share.[/$text-error]"
            )
            return None
        return team_slug, role, modules

    async def _do_share(self) -> None:
        from servonaut.services.memory.team_service import GrantAlreadyExistsError

        team_memory_service = getattr(self.app, "team_memory_service", None)
        status = self.query_one("#share-status", Static)
        if team_memory_service is None:
            self._say(status, "[$text-error]Team memory service not available.[/$text-error]")
            return
        try:
            choices = self._form_choices()
            if choices is None:
                return
            team_slug, role, modules = choices
            self._say(status, "[$text-warning]Fetching member keys…[/$text-warning]")
            member_keys = await team_memory_service.list_team_member_keys(team_slug)
            self._say(status, "[$text-warning]Sharing…[/$text-warning]")
            grant = await team_memory_service.share_instance(
                team_slug=team_slug,
                instance_id=self._instance_id(),
                required_role=role,
                modules=modules,
                member_pubkeys=member_keys,
            )
        except GrantAlreadyExistsError:
            # Someone shared it meanwhile: show that share instead of failing.
            self._keys_by_team.pop(self._selected_team(), None)
            self._start_refresh(reload=True)
            self._show_error("This server is already shared with that team.")
            return
        except Exception as exc:  # noqa: BLE001 — shown to the user, not raised from a worker
            logger.error("Share failed: %s", exc)
            self._show_error(f"Share failed: {exc}")
            return
        self._finish_share(team_slug, grant)

    def _finish_share(self, team_slug: str, grant: Any) -> None:
        """Tell the user it worked; stay open when someone cannot read it yet."""
        pending = list(getattr(grant, "pending_recipients", None) or [])
        self.app.notify(
            f"Shared {self._instance_id()} with team {team_slug}.",
            severity="information",
            markup=False,
        )
        if not pending:
            self.app.pop_screen()
            return
        self._grant = grant
        self._say_to("#share-status",
            "[$text-success]Shared successfully.[/$text-success]"
        )
        self._render_form(team_slug, pending)

    async def _do_revoke(self) -> None:
        grant, team_slug = self._grant, self._selected_team()
        service = getattr(self.app, "team_memory_service", None)
        if grant is None or service is None:
            return
        try:
            await service.revoke_grant(team_slug, grant.id)
        except Exception as exc:  # noqa: BLE001
            logger.error("Revoke failed: %s", exc)
            self._show_error(f"Revoke failed: {exc}")
            return
        self.app.notify("Sharing stopped. Members can no longer read it.", markup=False)
        self._grant = None
        self._say_to("#share-status", "")
        self._render_form(team_slug)

    async def _do_reshare(self) -> None:
        grant, team_slug = self._grant, self._selected_team()
        service = getattr(self.app, "team_memory_service", None)
        if grant is None or service is None:
            return
        choices = self._form_choices()
        if choices is None:
            return
        _, role, modules = choices
        status = self.query_one("#share-status", Static)
        try:
            self._say(status, "[$text-warning]Sharing again…[/$text-warning]")
            member_keys = await service.list_team_member_keys(team_slug)
            new_grant = await service.reshare_instance(
                team_slug, grant.id, self._instance_id(), role, modules, member_keys,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Share again failed: %s", exc)
            # The revoke may have gone through: show what is true now.
            self._keys_by_team.pop(team_slug, None)
            self._start_refresh(reload=True)
            self._show_error(f"Share again failed: {exc}")
            return
        self._keys_by_team[team_slug] = member_keys
        self._finish_share(team_slug, new_grant)

    async def _do_purge(self) -> None:
        grant, team_slug = self._grant, self._selected_team()
        service = getattr(self.app, "team_memory_service", None)
        if grant is None or service is None:
            return
        try:
            deleted = await service.purge_grant(team_slug, grant.id)
        except Exception as exc:  # noqa: BLE001
            logger.error("Purge failed: %s", exc)
            self._show_error(f"Could not delete the copies: {exc}")
            return
        self.app.notify(
            f"Sharing stopped and {deleted} member copies deleted.", markup=False,
        )
        self._grant = None
        self._say_to("#share-status", "")
        self._render_form(team_slug)


# Back-compat alias — the previous class name lives on so any cached
# import in a long-running session keeps working until the next reboot.
ShareInstanceModal = ShareInstanceScreen
