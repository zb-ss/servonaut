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

import asyncio
import functools
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.content import Content
from textual.containers import Container, Horizontal, ScrollableContainer, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, Label, Select, SelectionList, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens._demo_resolve import connection_instance
from servonaut.screens.memory_key_change import MemberKeyChangeScreen
from servonaut.services.memory.interfaces import MemoryBackendError
from servonaut.utils.markup import literal, scrub
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


def _shown_names(app: Any, names: List[str]) -> str:
    """Comma-separated names as plain text; stand-ins in demo mode."""
    redaction = getattr(app, "redaction_service", None)
    demo = bool(getattr(app, "demo_mode", False)) and redaction is not None
    return ", ".join(redaction.redact_name(n) if demo else n for n in names)


# What the form says about a member the service did not add, by skip reason.
_SKIPPED_WORDING = {
    "key_changed": (
        "Could not add {who}: their key changed meanwhile. "
        "Review the share to confirm the new key."
    ),
    "no_memory_key": (
        "Could not add {who}: no memory key at the moment. "
        "They need to set up Memory Sync again."
    ),
    "not_eligible": "Could not add {who}: can no longer read this share.",
    "unconfirmed": "Could not add {who}: the service did not confirm it; try again.",
}


@dataclass(frozen=True)
class _ShareAction:
    """What one Share, Share again or Review click is about.

    Fixed when the button is pressed: a slow request, a key dialog and the
    retry after it all keep to this, whatever the form shows by then.
    ``modules`` is None for a share of every module.
    """

    team_slug: str
    instance_id: str
    role: str
    modules: Optional[Tuple[str, ...]]
    grant_id: Optional[str] = None


def _failure(exc: Exception) -> str:
    """The error's type (and HTTP status) for a log line; the service's text can name people."""
    status = getattr(exc, "status", None)
    name = type(exc).__name__
    return f"{name} (HTTP {status})" if isinstance(status, int) else name


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
        height: auto;
        min-height: 1;
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
        # Members of the live share whose changed key waits for confirmation.
        self._waiting: List[Any] = []
        # True while an error line is on show: a refresh must not wipe it.
        self._status_locked = False

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        name = str(self._instance.get("name") or self._instance.get("id", "?"))
        yield SafeHeader()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Container(
                    Static(
                        Content.from_markup(
                            "[bold $text-accent]Share Memory: $name[/bold $text-accent]", name=name
                        ),
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
                                Button("Review changed keys", id="share-btn-keys"),
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
        self.run_worker(self._load_teams, group="memory_fleet", name="share_load_teams")

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
            (Text(self._team_label(t)), t.get("slug", "?"))
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

    def _say(self, widget: Static, markup: Union[str, Content]) -> None:
        """Write one status text (markup, or literal content).

        Service text never gets here in demo mode (see :meth:`_explain`);
        the scrub is the second line of defence for anything else.
        """
        redaction = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redaction is not None:
            markup = scrub(markup, redaction.scrub_stream)
        widget.update(markup)

    def _explain(self, what: str, exc: Exception) -> str:
        """A one-line, plain-text reason for a failure.

        In demo mode the service's own wording is dropped: it may name a
        team, member or server, and nothing there can be redacted reliably.
        """
        from servonaut.services.memory.team_service import UnusableMemberKeyError

        if isinstance(exc, UnusableMemberKeyError):
            who = _shown_names(self.app, exc.names)
            return (
                f"{what}: the service sent a memory key for {who} that does not "
                "match its fingerprint. Nothing was changed."
            )
        if getattr(self.app, "demo_mode", False):
            return f"{what}. Turn demo mode off to see why."
        return f"{what}: {exc}"

    def _say_to(self, selector: str, markup: Union[str, Content]) -> None:
        self._say(self.query_one(selector, Static), markup)

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the team names and the readers for the new demo mode."""
        if not self._teams:
            return
        select = self.query_one("#share-team-select", Select)
        chosen = select.value
        select.set_options([(Text(self._team_label(t)), t.get("slug", "?")) for t in self._teams])
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
            # The other team's share is not this one's: drop it at once.
            self._grant = None
            self._status_locked = False
            self._render_existing()
            self._start_refresh(reload=True)
        elif event.select.id == "share-role-select":
            self._start_refresh(reload=False)

    def _start_refresh(self, *, reload: bool) -> None:
        # A callable, not a coroutine: a newer exclusive worker cancels this one
        # before it starts, and a coroutine nobody awaits raises a RuntimeWarning.
        self.run_worker(
            functools.partial(self._refresh_form, reload),
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
            if not self._status_locked:
                self._say(status, "[$text-warning]Checking who can read it…[/$text-warning]")
            try:
                self._keys_by_team[slug] = await team_memory_service.list_team_member_keys(slug)
                self._grant = await team_memory_service.find_live_grant(slug, self._instance_id())
            except Exception as exc:  # noqa: BLE001 — a worker reports, never crashes the screen
                logger.error("Could not load the share state: %s", _failure(exc))
                self._grant = None
                self._waiting = []
                self._keys_by_team.pop(slug, None)
                self._show_error(self._explain("Could not check the share", exc))
                self._render_form(slug)
                return
            await self._load_waiting(team_memory_service, slug)
            if not self._status_locked:
                self._say(status, "")
            self._adopt_grant_settings()
        self._render_form(slug)

    async def _load_waiting(self, service: Any, slug: str) -> None:
        """Find the members of the live share whose changed key waits for the user.

        A failure only costs the line: the rest of the panel works without it.
        A share the service no longer knows is dropped from the form.
        """
        from servonaut.services.memory.team_service import ShareGoneError

        self._waiting = []
        if self._grant is None:
            return
        try:
            coverage = await service.grant_coverage(slug, self._grant.id)
            self._waiting = service.waiting_key_changes(slug, coverage)
        except ShareGoneError:
            self._grant = None
            self._show_error("That share no longer exists. The form shows what is shared now.")
        except Exception as exc:  # noqa: BLE001 — the line is optional
            logger.warning("Could not read who can open the share: %s", type(exc).__name__)

    def _adopt_grant_settings(self) -> None:
        """Start the role and module controls from the share that exists.

        Share again then re-sends what is shared now unless the user changes
        it. Done once per load, so later edits are never overwritten.
        """
        grant = self._grant
        if grant is None:
            return
        role_select = self.query_one("#share-role-select", Select)
        modules = self.query_one("#share-modules-list", SelectionList)
        with self.prevent(Select.Changed):
            if grant.required_role in {value for _, value in _ROLE_OPTIONS}:
                role_select.value = grant.required_role
        if grant.modules is None:
            modules.select_all()
            return
        modules.deselect_all()
        known = {modules.get_option_at_index(i).value for i in range(modules.option_count)}
        for name in grant.modules:
            if name in known:
                modules.select(name)

    def _instance_id(self) -> str:
        """The server's real id: in demo mode the row shows a stand-in."""
        real = connection_instance(self.app, self._instance) or self._instance
        return str(real.get("id") or real.get("name", ""))

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
            who = _shown_names(self.app, [m.name or f"member {m.user_id}" for m in eligible])
            line = (
                Content.assemble(f"Will be able to read it ({len(eligible)}): ", literal(who))
                if eligible
                else Content("No member with a memory key has this role yet.")
            )
            line = Content.assemble(
                line,
                "\nMembers who set up Memory Sync later are added "
                "automatically on the next sync.",
            )
            if pending:
                waiting = _shown_names(
                    self.app, [str(p.get("name") or f"member {p.get('user_id')}") for p in pending]
                )
                line = Content.assemble(
                    line, "\nNo memory key yet: ", literal(waiting),
                    ". Ask them to set up Memory Sync.",
                )
            self._say(readers, line)
        self._render_existing()

    def _render_existing(self) -> None:
        panel = self.query_one("#share-existing")
        grant = self._grant
        panel.set_class(grant is not None, "-shown")
        self.query_one("#share-btn-confirm", Button).disabled = bool(grant) or not self._teams
        waiting = bool(grant is not None and self._waiting)
        self.query_one("#share-btn-keys", Button).display = waiting
        if grant is None:
            return
        modules = ", ".join(grant.modules) if grant.modules else "all modules"
        text = Content(
            f"Already shared with this team: role {grant.required_role}, modules {modules}."
        )
        if waiting:
            who = _shown_names(self.app, [self._member_label(c) for c in self._waiting])
            text = Content.assemble(
                text, "\nKey changed, waiting for your confirmation: ", literal(who)
            )
        self._say_to("#share-existing-text", text)

    @staticmethod
    def _member_label(change: Any) -> str:
        return change.name or f"member {change.user_id}"

    def _gone(self, exc: Exception, team_slug: Optional[str] = None) -> bool:
        """True (after saying so) when the service no longer knows the share.

        A revoke or purge answered 404: the share was removed meanwhile, so
        the form is refreshed to what is shared now instead of showing a
        raw status. An action for a team the form no longer shows only says
        so and leaves the form alone.
        """
        from servonaut.services.api_client import APIError
        from servonaut.services.memory.team_service import ShareGoneError

        if not (isinstance(exc, ShareGoneError) or (isinstance(exc, APIError) and exc.status == 404)):
            return False
        if team_slug is not None and team_slug != self._selected_team():
            self.app.notify("That share no longer exists.", markup=False)
            return True
        self._grant = None
        self._waiting = []
        self._keys_by_team.pop(self._selected_team(), None)
        self._show_error("That share no longer exists. The form shows what is shared now.")
        self._start_refresh(reload=True)
        return True

    def _show_error(self, message: str) -> None:
        self._status_locked = True
        self._say_to("#share-status", literal(message, "$text-error"))

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_cancel(self) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        self._status_locked = False
        if button_id == "share-btn-confirm":
            self._start_action(self._do_share, name="share_execute")
        elif button_id == "share-btn-cancel":
            self.action_cancel()
        elif button_id == "share-btn-revoke":
            self.run_worker(self._do_revoke, group="memory_share", name="share_revoke", exclusive=True)
        elif button_id == "share-btn-reshare":
            self._start_action(self._do_reshare, name="share_again")
        elif button_id == "share-btn-keys":
            action = self._review_action()
            if action is not None:
                self._ask_keys(list(self._waiting), action, mode="catch_up")
        elif button_id == "share-btn-purge":
            self.app.push_screen(PurgeCopiesModal(), self._on_purge_answer)

    def _on_purge_answer(self, confirmed: Optional[bool]) -> None:
        if confirmed:
            self.run_worker(self._do_purge, group="memory_share", name="share_purge", exclusive=True)

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

    def _start_action(self, work: Any, *, name: str) -> None:
        """Run Share or Share again for the choices on the form right now."""
        choices = self._form_choices()
        if choices is None:
            return
        team_slug, role, modules = choices
        grant = self._grant
        action = _ShareAction(
            team_slug=team_slug, instance_id=self._instance_id(), role=role,
            modules=tuple(modules), grant_id=grant.id if grant is not None else None,
        )
        self.run_worker(
            functools.partial(work, action), group="memory_share", name=name, exclusive=True,
        )

    def _review_action(self) -> Optional[_ShareAction]:
        """The action behind the review button: the live share, as it is now."""
        grant = self._grant
        if grant is None:
            return None
        return _ShareAction(
            team_slug=self._selected_team(), instance_id=self._instance_id(),
            role=grant.required_role,
            modules=tuple(grant.modules) if grant.modules is not None else None,
            grant_id=grant.id,
        )

    def _key_race(self, team_slug: str) -> None:
        """Say that a member's key changed during the share, and read the keys again."""
        self._keys_by_team.pop(team_slug, None)
        self._start_refresh(reload=True)
        self._show_error("A member's key changed while sharing. Nothing was shared; try again.")

    async def _do_share(self, action: _ShareAction) -> None:
        from servonaut.services.memory.team_service import (
            GrantAlreadyExistsError,
            InsufficientWrapsRequired,
            KeyChangedError,
        )

        team_memory_service = getattr(self.app, "team_memory_service", None)
        status = self.query_one("#share-status", Static)
        if team_memory_service is None:
            self._say(status, "[$text-error]Team memory service not available.[/$text-error]")
            return
        try:
            self._say(status, "[$text-warning]Fetching member keys…[/$text-warning]")
            member_keys = await team_memory_service.list_team_member_keys(action.team_slug)
            self._say(status, "[$text-warning]Sharing…[/$text-warning]")
            grant = await team_memory_service.share_instance(
                team_slug=action.team_slug,
                instance_id=action.instance_id,
                required_role=action.role,
                modules=list(action.modules or ()),
                member_pubkeys=member_keys,
            )
        except KeyChangedError as exc:
            self._say(status, "")
            self._ask_keys(exc.changes, action, mode="share", again=False)
            return
        except GrantAlreadyExistsError:
            # Someone shared it meanwhile: show that share instead of failing.
            self._keys_by_team.pop(action.team_slug, None)
            self._start_refresh(reload=True)
            self._show_error("This server is already shared with that team.")
            return
        except InsufficientWrapsRequired:
            self._key_race(action.team_slug)
            return
        except Exception as exc:  # noqa: BLE001 — shown to the user, not raised from a worker
            logger.error("Share failed: %s", _failure(exc))
            self._show_error(self._explain("Share failed", exc))
            return
        self._finish_share(action.team_slug, grant)

    def _finish_share(self, team_slug: str, grant: Any) -> None:
        """Tell the user it worked; stay open when someone cannot read it yet."""
        pending = list(getattr(grant, "pending_recipients", None) or [])
        # Built from the labels the screen shows (stand-ins in demo mode),
        # never from the real id or slug.
        server = str(self._instance.get("name") or self._instance.get("id") or "the server")
        team = next(
            (self._team_label(t) for t in self._teams if t.get("slug") == team_slug),
            "the team",
        )
        self.app.notify(
            f"Shared {server} with team {team}.", severity="information", markup=False,
        )
        if not pending:
            self.app.pop_screen()
            return
        if self._selected_team() != team_slug:
            return  # the form shows another team now; leave it alone
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
            if self._gone(exc):
                return
            logger.error("Revoke failed: %s", _failure(exc))
            self._show_error(self._explain("Revoke failed", exc))
            return
        self.app.notify("Sharing stopped. Members can no longer read it.", markup=False)
        self._grant = None
        self._say_to("#share-status", "")
        self._render_form(team_slug)

    async def _do_reshare(self, action: _ShareAction) -> None:
        service = getattr(self.app, "team_memory_service", None)
        if action.grant_id is None or service is None:
            return
        from servonaut.services.memory.team_service import InsufficientWrapsRequired, KeyChangedError

        team_slug = action.team_slug
        status = self.query_one("#share-status", Static)
        try:
            self._say(status, "[$text-warning]Sharing again…[/$text-warning]")
            member_keys = await service.list_team_member_keys(team_slug)
            new_grant = await service.reshare_instance(
                team_slug, action.grant_id, action.instance_id, action.role,
                list(action.modules or ()), member_keys,
            )
        except KeyChangedError as exc:
            # Raised before the revoke: nothing changed, the share is intact.
            self._say(status, "")
            self._ask_keys(exc.changes, action, mode="share", again=True)
            return
        except InsufficientWrapsRequired:
            # The revoke went through: the form shows what is shared now.
            self._key_race(team_slug)
            return
        except Exception as exc:  # noqa: BLE001
            if self._gone(exc, team_slug):
                return
            logger.error("Share again failed: %s", _failure(exc))
            # The revoke may have gone through: show what is true now.
            self._keys_by_team.pop(team_slug, None)
            self._start_refresh(reload=True)
            self._show_error(self._explain("Share again failed", exc))
            return
        self._keys_by_team[team_slug] = member_keys
        self._finish_share(team_slug, new_grant)

    def _ask_keys(
        self, changes: List[Any], action: _ShareAction, *, mode: str, again: bool = False
    ) -> None:
        """Open the confirmation for *changes*; act on the answer for *action*."""
        if self._selected_team() != action.team_slug:
            self._show_error("The team changed while sharing; nothing was shared.")
            return

        def answered(confirmed: Optional[List[Any]]) -> None:
            if not confirmed:
                self._show_error(self._cancelled_keys(changes))
                return
            self.run_worker(
                functools.partial(self._after_confirmation, action, confirmed, mode, again),
                group="memory_share", name="share_confirm_keys", exclusive=True,
            )

        self.app.push_screen(MemberKeyChangeScreen(changes, mode=mode, again=again), answered)  # type: ignore[arg-type]

    def _cancelled_keys(self, changes: List[Any]) -> str:
        who = _shown_names(self.app, [self._member_label(c) for c in changes])
        return f"Nothing was changed. {who} cannot read it until you confirm the new key."

    async def _after_confirmation(
        self, action: _ShareAction, confirmed: List[Any], mode: str, again: bool
    ) -> None:
        """Record the confirmed keys, then do what they were needed for."""
        service = getattr(self.app, "team_memory_service", None)
        if service is None:
            return
        try:
            await asyncio.to_thread(service.confirm_member_keys, action.team_slug, confirmed)
        except (OSError, ValueError, MemoryBackendError) as exc:
            logger.error("Could not save the confirmed keys: %s", type(exc).__name__)
            self._show_error("Could not save the confirmed keys. Nothing was changed.")
            return
        if mode == "catch_up":
            await self._top_up(action)
        elif again:
            await self._do_reshare(action)
        else:
            await self._do_share(action)

    async def _top_up(self, action: _ShareAction) -> None:
        """Seal the latest snapshots for the members whose key was just confirmed."""
        service = getattr(self.app, "team_memory_service", None)
        if action.grant_id is None or service is None:
            return
        team_slug = action.team_slug
        self._say_to("#share-status", "[$text-warning]Sharing the latest snapshots…[/$text-warning]")
        try:
            result = await service.top_up_grant(
                team_slug, action.grant_id, action.instance_id,
                list(action.modules) if action.modules is not None else None,
            )
        except Exception as exc:  # noqa: BLE001
            if self._gone(exc, team_slug):
                return
            logger.error("Top-up failed: %s", _failure(exc))
            self._show_error(self._explain("Could not share the latest snapshots", exc))
            return
        self._say_to("#share-status", "")
        if result.sealed_names:
            who = _shown_names(self.app, list(result.sealed_names))
            self.app.notify(f"The latest snapshots are shared with {who} now.", markup=False)
        if result.skipped_names:
            self._show_error(self._skipped_text(result))
        elif not result.sealed_names:
            self.app.notify("Keys confirmed. There was nothing to share right now.", markup=False)
        self._keys_by_team.pop(team_slug, None)
        self._start_refresh(reload=True)

    def _skipped_text(self, result: Any) -> str:
        """One sentence per skip reason; only a changed key points to the review."""
        by_reason: Dict[str, List[str]] = {}
        for name, reason in zip(result.skipped_names, result.skipped_reasons):
            by_reason.setdefault(reason, []).append(name)
        sentences = []
        for reason, names in by_reason.items():
            who = _shown_names(self.app, names)
            sentences.append(_SKIPPED_WORDING.get(reason, _SKIPPED_WORDING["unconfirmed"]).format(who=who))
        return " ".join(sentences)

    async def _do_purge(self) -> None:
        grant, team_slug = self._grant, self._selected_team()
        service = getattr(self.app, "team_memory_service", None)
        if grant is None or service is None:
            return
        try:
            deleted = await service.purge_grant(team_slug, grant.id)
        except Exception as exc:  # noqa: BLE001
            if self._gone(exc):
                return
            logger.error("Purge failed: %s", _failure(exc))
            self._show_error(self._explain("Could not delete the copies", exc))
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
