"""BulkShareScreen — share the memory of several servers with one team.

Opened from Fleet Memory when servers are marked. The form is the single
Share form's (team, lowest role, modules, with the same defaults) plus an
"update existing shares" option; the readers are listed once for the batch.
The batch itself runs in :class:`BulkMemoryShareService`; this screen shows
its progress and then one line per server.

A full Screen with the sidebar, like the single form: it is a multi-step,
content-heavy workflow, not a brief prompt.
"""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.content import Content
from textual.css.query import NoMatches
from textual.widgets import Button, Checkbox, Footer, Label, Select, SelectionList, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens.memory_key_change import MemberKeyChangeScreen
from servonaut.screens.memory_share import (
    _NO_TEAM_VALUES,
    _ROLE_OPTIONS,
    _module_options,
    _shown_names,
)
from servonaut.services.memory import bulk_share as bulk
from servonaut.services.memory.interfaces import MemoryBackendError
from servonaut.services.retry_after import wait_text
from servonaut.utils.markup import literal, scrub
from servonaut.widgets.safe_header import SafeHeader
from servonaut.styles import CSS_FILES
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

logger = logging.getLogger(__name__)

# Why a server was skipped or left alone, as the summary says it.
_REASON_TEXT: Dict[str, str] = {
    bulk.ID_NOT_ACCEPTED: "Memory Sync does not accept this server's id",
    bulk.NO_SNAPSHOT: "no snapshot on the service yet; let Memory Sync upload one first",
    bulk.NEVER_PROBED: "never probed; scan it first",
    bulk.MEMORY_OFF: "memory is turned off for this server",
    bulk.UNRESOLVED: "the real server is not known in demo mode",
    bulk.SAME_SETTINGS: "it already has these settings",
    bulk.KEY_RACE: "a member's key changed while sharing; nothing was shared for it",
    bulk.REVOKED_ONLY: "the old share was stopped but the new one was not created; share it again",
    bulk.UNLISTED: (
        "already shared, but the service does not list that share to you, "
        "so it cannot be changed from here"
    ),
}

# What the screen says while a batch runs and the user tries to leave.
_HOLD_TEXT = "Sharing is in progress. Press s (Stop) to end it after the current server."

# The headline counts, in the order the summary lists the groups.
_GROUPS: Tuple[Tuple[str, str], ...] = (
    (bulk.SHARED, "shared"),
    (bulk.UPDATED, "updated"),
    (bulk.ALREADY_SHARED, "already shared"),
    (bulk.SKIPPED, "skipped"),
    (bulk.FAILED, "failed"),
    (bulk.NOT_SENT, "not sent"),
)


def _failure(exc: BaseException) -> str:
    """The error's type (and HTTP status) for a log line; the service's text can name people."""
    status = getattr(exc, "status", None)
    name = type(exc).__name__
    return f"{name} (HTTP {status})" if isinstance(status, int) else name


def headline(report: bulk.BulkShareReport) -> str:
    """``12 shared, 2 skipped, 1 failed`` — the non-zero counts of *report*."""
    parts = [
        f"{len(report.with_status(status))} {words}"
        for status, words in _GROUPS
        if report.with_status(status)
    ]
    return ", ".join(parts) or "nothing to share"


class BulkShareScreen(WorkspaceScreen):
    """Share the memory of several marked servers with one team.

    Args:
        targets: The servers, in the order Fleet Memory lists them. Their
            labels are real names; the screen shows stand-ins in demo mode.

    Dismisses with True once a batch ran (whatever its outcome), False when
    the form is closed without sending anything.
    """

    CSS_PATH = CSS_FILES

    CHAT_REFLOW = True
    CHAT_MIN_CONTENT_WIDTH = 76
    CONTENT_NARROW_WIDTH = 96

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("s", "stop_batch", "Stop after this server", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action == "stop_batch":
            return self._sending
        return check_action_passthrough(self, action)

    def __init__(self, targets: Sequence[bulk.ShareTarget]) -> None:
        super().__init__()
        self._targets: Tuple[bulk.ShareTarget, ...] = tuple(targets)
        self._teams: List[Dict[str, Any]] = []
        self._keys_by_team: Dict[str, List[Any]] = {}
        self._sending = False
        self._ran = False
        self._report: Optional[bulk.BulkShareReport] = None
        self._report_team = ""
        # Set by Stop: the batch ends after the server being sent.
        self._stop_requested = False
        # Servers whose share the running batch changed (shared, replaced, or stopped).
        self._changed = 0

    @property
    def targets(self) -> Tuple[bulk.ShareTarget, ...]:
        """The servers this form shares."""
        return self._targets

    # ------------------------------------------------------------------
    # Compose / mount
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        count = len(self._targets)
        yield SafeHeader()
        yield WorkspaceControls("Share Memory")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            with Container(id="bulk_outer", classes="workspace-content"):
                with Container(id="bulk-container"):
                    yield Static(
                        Content.from_markup(
                            "[bold $text-accent]Share Memory: $count servers[/bold $text-accent]",
                            count=str(count),
                        ),
                        id="bulk-title",
                    )
                    with VerticalScroll(id="bulk-state"):
                        yield Static("", id="bulk-status")
                        yield Static("", id="bulk-progress")
                    with VerticalScroll(id="bulk-form-scroll"):
                        with Container(id="bulk-form"):
                            with Container(id="bulk-selection-panel"):
                                yield Static("", id="bulk-servers")
                            with Horizontal(id="bulk-settings"):
                                with Container(id="bulk-access-panel"):
                                    yield Static("Team access", classes="bulk-section-heading")
                                    with Container(classes="bulk-field-row"):
                                        yield Label("Team")
                                        yield Select(
                                            options=[("Loading...", "__loading__")],
                                            value="__loading__",
                                            id="bulk-team-select",
                                        )
                                    with Container(classes="bulk-field-row"):
                                        yield Label("Lowest role that may read")
                                        yield Select(options=_ROLE_OPTIONS, value="viewer",
                                                     id="bulk-role-select")
                                    yield Static("", id="bulk-readers")
                                with Container(id="bulk-modules-panel"):
                                    yield Label("Modules to share", classes="bulk-section-heading")
                                    yield SelectionList(*_module_options(), id="bulk-modules-list")
                            yield Checkbox(
                                "Update existing shares to these settings",
                                value=False,
                                id="bulk-update-existing",
                            )
                        yield Static("", id="bulk-summary")
                    with Horizontal(id="bulk-btn-row"):
                        yield Button("Cancel", variant="default", id="bulk-btn-cancel")
                        yield Button("Stop after this server", variant="warning", id="bulk-btn-stop")
                        yield Button(
                            f"Share {count} servers", variant="primary",
                            id="bulk-btn-confirm", disabled=True,
                        )
        yield Footer()

    def on_mount(self) -> None:
        auth = getattr(self.app, "auth_service", None)
        if auth and not auth.has_feature("memory_team_share"):
            from servonaut.widgets.upsell_modal import UpsellModal
            self.dismiss(False)
            self.app.push_screen(UpsellModal("memory_team_share"))
            return
        self._render_servers()
        self.run_worker(self._load_teams, group="memory_bulk_share_form", name="bulk_load_teams")

    async def _load_teams(self) -> None:
        auth = getattr(self.app, "auth_service", None)
        if auth is None:
            return
        try:
            self._teams = list(await auth.list_teams() or [])
        except Exception as exc:  # noqa: BLE001 — the picker says there is no team
            logger.error("Failed to load teams: %s", _failure(exc))
            self._teams = []
        options = [(Text(self._team_label(t)), t.get("slug", "?")) for t in self._teams] \
            or [("No teams available", "__none__")]
        select = self.query_one("#bulk-team-select", Select)
        select.set_options(options)
        select.value = options[0][1]
        self.query_one("#bulk-btn-confirm", Button).disabled = not self._teams

    # ------------------------------------------------------------------
    # Showing names (stand-ins in demo mode)
    # ------------------------------------------------------------------

    def _demo(self) -> bool:
        return bool(getattr(self.app, "demo_mode", False)) and \
            getattr(self.app, "redaction_service", None) is not None

    def _team_label(self, team: Dict[str, Any]) -> str:
        name = str(team.get("name", team.get("slug", "?")))
        return self.app.redaction_service.redact_name(name) if self._demo() else name

    def _team_name(self, slug: str) -> str:
        return next((self._team_label(t) for t in self._teams if t.get("slug") == slug), "the team")

    def _label(self, target: bulk.ShareTarget) -> str:
        return _shown_names(self.app, [target.label or target.instance_id])

    def _say(self, widget: Static, value: Any) -> None:
        """Write one text; in demo mode free text is scrubbed as a second line of defence."""
        if self._demo():
            value = scrub(value, self.app.redaction_service.scrub_stream)
        widget.update(value)

    def _say_to(self, selector: str, value: Any) -> None:
        self._say(self.query_one(selector, Static), value)

    def _show_error(self, message: str) -> None:
        self._say_to("#bulk-status", literal(message, "$text-error"))

    def _explain(self, what: str, exc: BaseException) -> str:
        """A one-line, plain-text reason; the service's wording is dropped in demo mode."""
        from servonaut.services.memory.team_service import UnusableMemberKeyError

        if isinstance(exc, UnusableMemberKeyError):
            who = _shown_names(self.app, exc.names)
            return (
                f"{what}: the service sent a memory key for {who} that does not "
                "match its fingerprint."
            )
        if self._demo():
            return f"{what}. Turn demo mode off to see why."
        return f"{what}: {exc}"

    def refresh_after_demo_toggle(self) -> None:
        """Redraw every name for the new demo mode."""
        self._render_servers()
        if self._teams:
            select = self.query_one("#bulk-team-select", Select)
            chosen = select.value
            select.set_options([(Text(self._team_label(t)), t.get("slug", "?")) for t in self._teams])
            if isinstance(chosen, str):
                select.value = chosen
        self._render_readers()
        if self._report is not None:
            self._render_report()

    def _render_servers(self) -> None:
        names = ", ".join(self._label(t) for t in self._targets)
        self._say_to("#bulk-servers", Content.assemble(
            Content.styled(f"Servers ({len(self._targets)}): ", "bold"), literal(names)))

    # ------------------------------------------------------------------
    # The readers, for the chosen team and role
    # ------------------------------------------------------------------

    def _selected_team(self) -> str:
        value = self.query_one("#bulk-team-select", Select).value
        if not isinstance(value, str) or value in _NO_TEAM_VALUES:
            return ""
        return value

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "bulk-team-select":
            self.run_worker(
                functools.partial(self._load_readers, self._selected_team()),
                group="memory_bulk_share_form", name="bulk_readers", exclusive=True,
            )
        elif event.select.id == "bulk-role-select":
            self._render_readers()

    async def _load_readers(self, slug: str) -> None:
        """Fetch the team's member keys to show who will be able to read."""
        service = getattr(self.app, "team_memory_service", None)
        if service is None or not slug:
            self._render_readers()
            return
        if slug not in self._keys_by_team:
            self._say_to("#bulk-readers", "[$text-warning]Checking who can read them…[/$text-warning]")
            try:
                self._keys_by_team[slug] = await service.list_team_member_keys(slug)
            except Exception as exc:  # noqa: BLE001 — a worker reports, never crashes the screen
                logger.error("Could not load the team's member keys: %s", _failure(exc))
                self._say_to("#bulk-readers", "")
                self._show_error(self._explain("Could not check who can read them", exc))
                return
        self._render_readers()

    def _render_readers(self) -> None:
        """Who will be able to read, listed once for the whole batch."""
        keys = self._keys_by_team.get(self._selected_team())
        readers = self.query_one("#bulk-readers", Static)
        if keys is None:
            self._say(readers, "")
            return
        role = str(self.query_one("#bulk-role-select", Select).value or "viewer")
        service = getattr(self.app, "team_memory_service", None)
        eligible = service.eligible_members(keys, role) if service else keys
        who = _shown_names(self.app, [m.name or f"member {m.user_id}" for m in eligible])
        line = (
            Content.assemble(f"Will be able to read them ({len(eligible)}): ", literal(who))
            if eligible
            else Content("No member with a memory key has this role yet.")
        )
        self._say(readers, Content.assemble(
            line,
            "\nMembers who set up Memory Sync later are added automatically on the next sync.",
        ))

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def navigation_hold_reason(self) -> Optional[str]:
        """Why the app must not leave this screen now (it would cancel the batch)."""
        return _HOLD_TEXT if self._sending else None

    def action_cancel(self) -> None:
        if self._sending:
            self.app.notify(_HOLD_TEXT, severity="warning", markup=False)
            return
        self.dismiss(self._ran)

    def action_stop_batch(self) -> None:
        """End the batch after the server being sent; the rest are not sent."""
        if not self._sending or self._stop_requested:
            return
        self._stop_requested = True
        stop = self.query_one("#bulk-btn-stop", Button)
        stop.label = "Stopping after this server…"
        stop.disabled = True

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "bulk-btn-cancel":
            self.action_cancel()
        elif event.button.id == "bulk-btn-stop":
            self.action_stop_batch()
        elif event.button.id == "bulk-btn-confirm" and not self._sending and not self._ran:
            choices = self._form_choices()
            if choices is not None:
                self._start_batch(choices)

    def _form_choices(self) -> Optional[Tuple[str, str, Tuple[str, ...], bool]]:
        """``(team, role, modules, update_existing)`` from the form, or None after saying why."""
        team = self._selected_team()
        if not team:
            self._show_error("Choose a team first.")
            return None
        # Always an explicit list: an empty selection never widens to "everything".
        modules = tuple(self.query_one("#bulk-modules-list", SelectionList).selected)
        if not modules:
            self._show_error("Select at least one module to share.")
            return None
        role = str(self.query_one("#bulk-role-select", Select).value or "viewer")
        update = bool(self.query_one("#bulk-update-existing", Checkbox).value)
        return team, role, modules, update

    def _start_batch(self, choices: Tuple[str, str, Tuple[str, ...], bool]) -> None:
        self.run_worker(
            functools.partial(self._run_batch, choices),
            group="memory_bulk_share", name="bulk_share", exclusive=True,
        )

    def _service(self) -> Optional[bulk.BulkMemoryShareService]:
        team_memory_service = getattr(self.app, "team_memory_service", None)
        if team_memory_service is None:
            return None

        def waits() -> Tuple[float, float]:
            from servonaut.config.schema import MemoryConfig

            config_manager = getattr(self.app, "config_manager", None)
            memory = getattr(config_manager.get(), "memory", None) if config_manager else None
            return (memory if isinstance(memory, MemoryConfig) else MemoryConfig()).team_wrap_wait()

        return bulk.BulkMemoryShareService(team_memory_service, waits)

    async def _run_batch(self, choices: Tuple[str, str, Tuple[str, ...], bool]) -> None:
        service = self._service()
        if service is None:
            self._show_error("Team memory service not available.")
            return
        self._say_to("#bulk-status", "")  # an older batch's error no longer applies
        self._stop_requested, self._changed = False, 0
        self._set_sending(True)
        try:
            report = await self._share(service, choices)
        finally:
            self._set_sending(False)
        if report is not None:
            self._finish(choices[0], report)

    async def _share(
        self, service: bulk.BulkMemoryShareService, choices: Tuple[str, str, Tuple[str, ...], bool],
    ) -> Optional[bulk.BulkShareReport]:
        """Run the batch; None after saying why it was refused (nothing was sent then)."""
        from servonaut.services.memory.team_service import KeyChangedError

        team, role, modules, update = choices
        self._progress(Content.styled("Checking member keys…", "$text-warning"))
        try:
            return await service.share(
                team, role, list(modules), self._targets,
                update_existing=update, on_progress=self._on_progress,
                should_stop=lambda: self._stop_requested,
            )
        except KeyChangedError as exc:
            self._progress(None)
            self._ask_keys(exc.changes, choices)
        except bulk.BatchRateLimitedError as exc:
            self._progress(None)
            self._show_error(
                f"The service is limiting requests. Nothing was shared; {wait_text(exc.retry_after)}."
            )
        except bulk.MemorySyncLockedError:
            self._progress(None)
            self._show_error("Unlock Memory Sync first. Nothing was shared.")
        except Exception as exc:  # noqa: BLE001 — shown to the user, not raised from a worker
            logger.error("Bulk share failed: %s", _failure(exc))
            self._progress(None)
            self._show_error(self._explain(self._interrupted_text(), exc))
        return None

    def _interrupted_text(self) -> str:
        """How a batch that ended in an error is described: did it change anything?"""
        if not self._changed:
            return "Nothing was shared"
        return (
            f"Sharing ended early after {self._changed} of {len(self._targets)} servers "
            "were changed (open Fleet Memory to see what is shared)"
        )

    def _set_sending(self, sending: bool) -> None:
        """Hold Share and offer Stop while a batch runs; the screen may be closing."""
        self._sending = sending
        if not self.is_mounted:
            return
        try:
            stop = self.query_one("#bulk-btn-stop", Button)
            stop.set_class(sending, "-shown")
            stop.label, stop.disabled = "Stop after this server", False
            if not self._ran:
                self.query_one("#bulk-btn-confirm", Button).disabled = sending or not self._teams
        except NoMatches:
            return
        self.refresh_bindings()

    def _progress(self, value: Optional[Content]) -> None:
        widget = self.query_one("#bulk-progress", Static)
        widget.set_class(value is not None, "-shown")
        self._say(widget, value if value is not None else "")

    def _on_progress(self, index: int, total: int, outcome: bulk.ShareOutcome) -> None:
        if outcome.status in (bulk.SHARED, bulk.UPDATED) or outcome.reason == bulk.REVOKED_ONLY:
            self._changed += 1
        good = outcome.status in (bulk.SHARED, bulk.UPDATED)
        bad = outcome.status in (bulk.FAILED, bulk.NOT_SENT)
        mark, style = ("✓", "$text-success") if good else ("✗", "$text-error") if bad else ("–", "")
        self._progress(Content.assemble(
            Content.styled(f"Sharing {index} / {total}", "$text-accent"),
            "  ·  last: ", literal(self._label(outcome.target)), " ",
            Content.styled(mark, style) if style else mark,
        ))

    # ------------------------------------------------------------------
    # A member's changed key: confirm, then run the same batch again
    # ------------------------------------------------------------------

    def _ask_keys(self, changes: List[Any], choices: Tuple[str, str, Tuple[str, ...], bool]) -> None:
        def answered(confirmed: Optional[List[Any]]) -> None:
            if not confirmed:
                who = _shown_names(self.app, [c.name or f"member {c.user_id}" for c in changes])
                self._show_error(
                    f"Nothing was shared. {who} cannot read them until you confirm the new key."
                )
                return
            self.run_worker(
                functools.partial(self._after_confirmation, choices, confirmed),
                group="memory_bulk_share", name="bulk_confirm_keys", exclusive=True,
            )

        self._show_error("A member's memory key changed. Nothing was shared.")
        self.app.push_screen(MemberKeyChangeScreen(changes, mode="share"), answered)  # type: ignore[arg-type]

    async def _after_confirmation(
        self, choices: Tuple[str, str, Tuple[str, ...], bool], confirmed: List[Any]
    ) -> None:
        service = getattr(self.app, "team_memory_service", None)
        if service is None:
            return
        try:
            await asyncio.to_thread(service.confirm_member_keys, choices[0], confirmed)
        except (OSError, ValueError, MemoryBackendError) as exc:
            logger.error("Could not save the confirmed keys: %s", type(exc).__name__)
            self._show_error("Could not save the confirmed keys. Nothing was shared.")
            return
        self._keys_by_team.pop(choices[0], None)
        await self._run_batch(choices)

    # ------------------------------------------------------------------
    # The summary
    # ------------------------------------------------------------------

    def _finish(self, team: str, report: bulk.BulkShareReport) -> None:
        self._ran = True
        self._report, self._report_team = report, team
        self._progress(None)
        self.query_one("#bulk-form").add_class("-done")
        self.query_one("#bulk-btn-confirm", Button).display = False
        self.query_one("#bulk-btn-cancel", Button).label = "Close"
        self._render_report()
        self.app.notify(
            f"Shared with team {self._team_name(team)}: {headline(report)}.", markup=False,
        )
        self.query_one("#bulk-btn-cancel", Button).focus()

    def _render_report(self) -> None:
        report = self._report
        if report is None:
            return
        style = "$text-success" if not (report.with_status(bulk.FAILED) or report.not_sent) \
            else "$text-warning"
        self._say_to("#bulk-status", Content.assemble(
            Content.styled("Done: ", f"bold {style}"),
            Content.styled(f"{headline(report)}.", style),
        ))
        self._say_to("#bulk-summary", self._summary(report))

    def _summary(self, report: bulk.BulkShareReport) -> Content:
        parts: List[Content] = [Content.assemble(
            "Team: ", literal(self._team_name(self._report_team)), "\n")]
        self._group(parts, report.with_status(bulk.SHARED), "Shared")
        self._group(parts, report.with_status(bulk.UPDATED), "Already shared, updated to these settings")
        left = report.with_status(bulk.ALREADY_SHARED)
        # Only for the shares left because the option was off.
        hint = "Tick \"Update existing shares to these settings\" to change them." \
            if not report.update_existing and any(not o.reason for o in left) else ""
        self._group(parts, left, "Already shared, left as it was", hint)
        self._group(parts, report.with_status(bulk.SKIPPED), "Skipped")
        self._group(parts, report.with_status(bulk.FAILED), "Failed")
        self._group(parts, report.with_status(bulk.NOT_SENT), "Not sent", self._stop_text(report))
        if report.pending:
            waiting = _shown_names(
                self.app, [str(p.get("name") or f"member {p.get('user_id')}") for p in report.pending])
            parts.append(Content.assemble(
                "\nNo memory key yet: ", literal(waiting), ". Ask them to set up Memory Sync.\n"))
        return Content.assemble(*parts)

    def _group(self, parts: List[Content], outcomes: List[bulk.ShareOutcome], title: str,
               hint: str = "") -> None:
        if not outcomes:
            return
        parts.append(Content.styled(f"\n{title} ({len(outcomes)})\n", "bold"))
        if hint:
            parts.append(literal(f"{hint}\n", "dim"))
        for outcome in outcomes:
            reason = self._reason(outcome)
            parts.append(Content.assemble(
                "  • ", literal(self._label(outcome.target)),
                literal(f" — {reason}", "dim") if reason else "", "\n",
            ))

    def _reason(self, outcome: bulk.ShareOutcome) -> str:
        """Why, in words; a failure's service text only outside demo mode."""
        if outcome.status == bulk.NOT_SENT:
            return ""  # the group's heading says why
        detail = outcome.detail
        if detail and self._demo():
            detail = "turn demo mode off to see why"
        text = _REASON_TEXT.get(outcome.reason, "")
        if text and detail:
            return f"{text} ({detail})"
        return text or detail

    def _stop_text(self, report: bulk.BulkShareReport) -> str:
        reason = report.stop_reason
        if reason == bulk.RATE_LIMITED:
            return f"The service kept limiting requests, so the rest was not sent; {wait_text(report.retry_after)}."
        if reason == bulk.KEY_RACE:
            return "A member's key changed while sharing, so the rest was not sent. Try again."
        if reason == bulk.STOPPED:
            return "You stopped the batch, so the rest was not sent."
        return "The service could not take more shares, so the rest was not sent."
