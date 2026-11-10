"""Instance list screen for Servonaut v2.0."""

from __future__ import annotations
import dataclasses
import time
from datetime import timedelta
from typing import Dict, Optional, List

from rich.cells import cell_len
from textual.app import ComposeResult
from textual.binding import Binding
from textual.content import Content
from textual.css.query import NoMatches
from textual.containers import Container, Grid, Vertical, VerticalScroll, Horizontal
from textual.timer import Timer
from textual.widgets import Button, Footer, Input, Label, Static, TextArea
from textual.worker import Worker, WorkerState

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens._fleet_filter import (
    provider_label,
    ALL, PROVIDERS, PROVIDER_LABELS, STATES, STATE_LABELS, STATE_OTHER,
    FleetFacets, FleetFilter, facets, next_choice, row_provider, row_state, summary,
)
from servonaut.screens._fleet_load import FleetLoad, format_ago, render_load
from servonaut.screens._footer_fit import fit_footer
from servonaut.widgets.action_button import ActionButton, ActionRole, action_label
from servonaut.widgets.fleet_skeleton import FleetSkeleton
from servonaut.widgets.fleet_values import FleetValueLine, FleetValues, ValueRow, instance_values
from servonaut.widgets.link_button import LinkButton
from servonaut.widgets.instance_table import MARK_NEW, MARK_WAS, InstanceTable
from servonaut.widgets.status_bar import StatusBar
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

from typing import TYPE_CHECKING
from servonaut.screens._demo_resolve import (
    connection_instance,
    display_text,
    fleet_rows,
    real_instance_id,
    reconcile_team_memory,
    refuse_unresolved,
    replace_instances,
    row_source,
    team_rows,
)
from servonaut.services.memory.provider import instance_provider
from servonaut.utils.instance_resolver import display_name, is_aws_row, row_identity
from servonaut.utils.markup import literal
if TYPE_CHECKING:
    from servonaut.app import ServonautApp

def _is_aws_row(instance: dict) -> bool:
    """Whether a fleet-table row came from the AWS fetch."""
    return is_aws_row(instance)


class FleetSearchInput(Input):
    """The fleet search box, which keeps the fleet shortcuts in the footer.

    Textual drops every binding for a printable key from the footer while an
    Input has focus, because the Input takes those keys as text. Here the
    fleet shortcuts stay listed: the screen's ``check_action`` reports them
    as disabled while the box has focus, so the footer shows them greyed
    out. Typing is unaffected: the box still receives every printable key,
    and a disabled action never runs.
    """

    def __init__(self, shortcut_characters: frozenset[str], **kwargs) -> None:
        super().__init__(**kwargs)
        self._shortcut_characters = shortcut_characters

    def check_consume_key(self, key: str, character: str | None) -> bool:
        if character is not None and character in self._shortcut_characters:
            return False
        return super().check_consume_key(key, character)


class FleetSummaryLine(Static):
    """The summary under the table: the key reminder goes first when the line is too narrow."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._texts = ("", "")

    def set_texts(self, full: str, short: str) -> None:
        """Set the full wording and the shorter one used when the line is too narrow."""
        self._texts = (full, short)
        self._draw()

    def on_resize(self) -> None:
        """Choose the wording again for the new width."""
        self._draw()

    def _draw(self) -> None:
        """Show the full wording when it fits, the short one otherwise."""
        full, short = self._texts
        width = self.size.width
        self.update(full if width == 0 or cell_len(full) <= width else short)


class FleetChip(Button):
    """A quick-filter chip: one state or provider choice, with its live count."""

    def __init__(self, group: str, value: str, label: str) -> None:
        key = "f" if group == "state" else "p"
        super().__init__(
            label, id=f"chip_{group}_{value}", classes="fleet-chip", compact=True,
            tooltip=f"Filter the list; press {key} to cycle these choices",
        )
        self.group = group
        self.value = value
        self.base_label = label


class InstanceListScreen(WorkspaceScreen):
    """Screen displaying list of EC2 instances with search/filter."""

    @property
    def app(self) -> "ServonautApp":
        return super().app # type: ignore

    BINDINGS = [
        # A tooltip shows on hovering the footer entry and is the key's
        # description on the help screen.
        Binding("r", "refresh", "Refresh", show=True,
                tooltip="Fetch the fleet again from every provider"),
        Binding("/", "focus_search", "Search", show=True,
                tooltip="Search instances and keyword scan results"),
        Binding("f", "filter_state", "State", show=True,
                tooltip="Cycle the state filter: all, running, stopped, other"),
        Binding("p", "filter_provider", "Provider", show=True,
                tooltip="Cycle the provider filter: all, then each provider in the list"),
        Binding("enter", "select_instance", "Actions", show=True,
                tooltip="Open the selected server's actions"),
        # Explicit footer-visible alternative — DataTable consumes Enter for
        # row-selected, which hides the Enter binding from the footer. ``o``
        # (for "Open") shows up in the footer so users can discover the
        # actions menu without needing to guess that Enter works.
        Binding("o", "select_instance", "Actions", show=True,
                tooltip="Open the selected server's actions"),
        Binding("s", "ssh_connect", "SSH", show=True,
                tooltip="SSH into the selected server in a new terminal window"),
        Binding("b", "browse_files", "Browse", show=True,
                tooltip="Browse the selected server's files"),
        Binding("c", "run_command", "Command", show=True,
                tooltip="Run commands on the selected server"),
        Binding("t", "scp_transfer", "Transfer", show=True,
                tooltip="Copy files to or from the selected server"),
        Binding("l", "view_logs", "Logs", show=True,
                tooltip="Stream the selected server's logs"),
        Binding("a", "ai_analysis", "AI", show=True,
                tooltip="Analyse the selected server's logs with AI"),
        Binding("m", "open_memory", "Memory", show=True,
                tooltip="Open the selected server's memory (cached facts)"),
        Binding("D", "fleet_db_scan", "DB vault", show=True,
                tooltip="Scan the fleet for database credentials"),
        Binding("k", "manage_ssh_ref", "SSH ref", show=True,
                tooltip="Set the Bitwarden SSH key reference of the selected server"),
        Binding("v", "verify_ssh", "Verify", show=True,
                tooltip="Check that the selected server's SSH key works"),
        Binding("y", "copy_row", "Copy row", show=True,
                tooltip="Copy the selected server's details"),
        Binding("Y", "copy_value", "Copy value", show=True,
                tooltip="Pick one value of the selected server to copy"),
        # Only while providers are answering (see check_action); otherwise the
        # key goes on to the focused widget as before.
        Binding("escape", "cancel_slow_providers", "Cancel slow", show=False,
                tooltip="Stop waiting for the providers that have not answered"),
    ]

    # The screen opens on the fleet table, so the arrow keys and every
    # shortcut above work straight away; "/" moves to the search box.
    AUTO_FOCUS = "InstanceTable"
    CHAT_REFLOW = True
    CHAT_MIN_CONTENT_WIDTH = 64
    CONTENT_NARROW_WIDTH = 105
    HORIZONTAL_BREAKPOINTS = [(0, "-narrow"), (130, "-wide")]
    # Tall enough that outlined chips (three rows) do not starve the table.
    VERTICAL_BREAKPOINTS = [(0, "-short"), (44, "-tall")]

    # The footer lists as many shortcuts as fit on one line, in this order
    # of usefulness; the rest stay bound, and the help screen lists them all.
    FOOTER_PRIORITY = (
        "refresh",
        "focus_search",
        "filter_state",
        "filter_provider",
        "ssh_connect",
        "select_instance",
        "run_command",
        "browse_files",
        "view_logs",
        "open_memory",
        "scp_transfer",
        "ai_analysis",
        "copy_row",
        "verify_ssh",
        "manage_ssh_ref",
        "fleet_db_scan",
        "copy_value",
    )

    # Debounce delay for search input (seconds)
    _SEARCH_DEBOUNCE = 0.15

    # How long a refresh marks the servers it added or changed (seconds).
    _MARK_SECONDS = 6.0

    # How often the spinner turns and the providers' progress is read (seconds).
    _SPINNER_SECONDS = 0.15

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action == "cancel_slow_providers":
            # While typing, Esc keeps its usual meaning.
            return self._load.active and not isinstance(self.focused, (Input, TextArea))
        if self.navigation_focused:
            return super().check_action(action, parameters)
        return check_action_passthrough(self, action)

    @property
    def active_bindings(self):
        """Active bindings, with the footer kept to the shortcuts that fit."""
        return fit_footer(
            self._without_inspector_keys(super().active_bindings), self, self.FOOTER_PRIORITY,
        )

    # Actions the inspector's buttons already show with their keys.
    _INSPECTOR_ACTIONS = frozenset({
        "browse_files", "scp_transfer", "run_command", "view_logs", "open_memory", "ai_analysis",
    })

    def _without_inspector_keys(self, bindings: dict) -> dict:
        """*bindings* without the footer entries the visible inspector repeats."""
        try:
            if not self.query_one("#fleet_inspector").display:
                return bindings
        except NoMatches:
            return bindings
        return {
            key: (
                active._replace(binding=dataclasses.replace(active.binding, show=False))
                if active.node is self and active.binding.action in self._INSPECTOR_ACTIONS
                else active
            )
            for key, active in bindings.items()
        }

    def on_resize(self) -> None:
        """Re-fit the footer to the new width."""
        self.refresh_bindings()
        self.call_after_refresh(self._sync_roomy)

    def on_mouse_up(self) -> None:
        """A drag that began in a value may end anywhere: the value hands the focus back."""
        self.app.call_later(self._values_give_focus_back)

    def _values_give_focus_back(self) -> None:
        for row in self.query(ValueRow):
            row.give_focus_back()

    def _set_layout_class(self, name: str, enabled: bool) -> None:
        super()._set_layout_class(name, enabled)
        self._sync_roomy()

    def _sync_roomy(self) -> None:
        """Mark a terminal with room for outlined chips: wide, tall, nothing beside the table."""
        roomy = (
            self.has_class("-wide") and self.has_class("-tall")
            and not self.has_class("-content-narrow") and not self.has_class("-chat-open")
        )
        if self.has_class("-roomy") != roomy:
            self.set_class(roomy, "-roomy")
        # A compact chip keeps its border off in every theme, hovered or not;
        # the outlined pill is the non-compact one.
        for chip in self.query(FleetChip):
            chip.compact = not roomy
        self._sync_table_room()
        self.call_after_refresh(self._sync_fresh_layout)
        self.call_after_refresh(self._sync_memory_note)

    def _sync_table_room(self) -> None:
        """Tell the table whether the inspector sits beside it (its Details then cover Region and Type)."""
        beside = not (
            self.has_class("-narrow") or self.has_class("-content-narrow")
            or self.has_class("-chat-open")
        )
        try:
            table = self.query_one(InstanceTable)
        except NoMatches:
            return
        if table.inspector_beside != beside:
            table.inspector_beside = beside
            table.replan()

    def _sync_fresh_layout(self) -> None:
        """Put the freshness on the chip row only when it fits there, whole.

        Measured, not guessed from the width class: the chips take what they
        take, and the age and the Refresh link need their own cells. When they
        do not fit, they sit right-aligned on a row of their own.
        """
        try:
            filters = self.query_one("#fleet_filters")
            # The last chip's one-cell margin sits outside the row's own width.
            chips = self.query_one("#fleet_chip_row").outer_size.width + 1
            refresh = self.query_one("#fleet_refresh").outer_size.width
        except NoMatches:
            return
        stacked = (
            self.has_class("-narrow") or self.has_class("-content-narrow")
            or self.has_class("-chat-open")
        )
        inline_age = self._inline_age(self._updated_text())
        age = cell_len(f"{inline_age} ·") if inline_age else 0
        inline = not stacked and 0 < chips and chips + age + refresh <= filters.size.width
        if filters.has_class("-fresh-inline") != inline:
            filters.set_class(inline, "-fresh-inline")
        if inline != self._fresh_inline:
            self._fresh_inline = inline
            self._updated_shown = None
        self._sync_updated()

    def __init__(self, initial_search: str = "") -> None:
        """Initialize instance list screen.

        Args:
            initial_search: Optional pre-filled search query. Set by
                provider-section sidebar buttons (e.g. "Hetzner Servers"
                pre-fills ``"hetzner"`` so the table opens already
                filtered to that provider). Empty string disables.
        """
        super().__init__()
        self._instances: List[dict] = []
        self._search_debounce_timer: Optional[Timer] = None
        self._initial_search = initial_search
        # (provider, account) pairs already reported as configured twice.
        self._reported_duplicate_accounts: set = set()
        self._filter = FleetFilter()
        self._load = FleetLoad()
        # What the last refreshes did to each server, shown for a few seconds.
        self._marks: Dict[str, str] = {}
        self._marks_timer: Optional[Timer] = None
        self._load_timer: Optional[Timer] = None
        # The worker each provider's current load runs in: a worker replaced by
        # a newer refresh reports "cancelled" for a load that is still going.
        self._load_workers: Dict[str, Worker] = {}
        self._last_updated: Optional[float] = None
        self._refresh_failed = False
        self._cache_written_at: Optional[float] = None
        self._updated_shown: Optional[str] = None
        self._fresh_inline = False
        self._updated_timer: Optional[Timer] = None

    def compose(self) -> ComposeResult:
        """Compose the instance list UI."""
        yield SafeHeader()
        yield WorkspaceControls("Servers")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            with Vertical(id="instance_list_container", classes="workspace-content"):
                yield Static("Search", id="fleet_search_label", markup=False)
                yield FleetSearchInput(
                    self._shortcut_characters(),
                    placeholder="Search servers, IPs and keywords…",
                    id="search_input",
                )
                # Memory discoverability banner — only visible when no
                # instance has memory yet, so it stops nagging once the user
                # has engaged with the feature. One line, action first: on a
                # short terminal every row it takes is a row of servers less.
                banner = Static(
                    "[bold]🧠 New:[/bold] press [b]m[/b] on a row, or open "
                    "[b]Fleet memory[/b] in the sidebar, to cache each server's "
                    "facts for the chat panel and MCP clients.",
                    id="memory_discover_banner",
                    classes="hidden",
                )
                banner.tooltip = (
                    "Build a fact cache for every server so the chat panel and "
                    "MCP clients can answer OS / runtime / service questions "
                    "without an SSH round-trip."
                )
                yield banner
                yield Static("", id="fleet_load_status", markup=False)
                yield from self._compose_filters()
                with Horizontal(id="fleet_workspace_row", classes="fleet-workspace-row"):
                    with Vertical(id="fleet_table_column"):
                        yield InstanceTable()
                        yield FleetSkeleton(id="fleet_skeleton")
                        yield FleetSummaryLine("", id="fleet_summary", markup=False)
                    with Vertical(id="fleet_inspector", classes="fleet-inspector"):
                        yield Static(
                            "[bold]Selected server[/bold]\n[dim]No server selected[/dim]",
                            id="fleet_inspector_header",
                            classes="fleet-inspector-header",
                        )
                        yield self._inspector_button(
                            "SSH connect", "s", "fleet_btn_ssh", role="primary",
                        )
                        with Container(id="fleet_inspector_grid", classes="fleet-inspector-grid"):
                            yield self._inspector_button("Browse", "b", "fleet_btn_browse")
                            yield self._inspector_button("Transfer", "t", "fleet_btn_scp")
                            yield self._inspector_button("Command", "c", "fleet_btn_command")
                            yield self._inspector_button("Logs", "l", "fleet_btn_logs")
                            yield self._inspector_button("Memory", "m", "fleet_btn_memory")
                            yield self._inspector_button("AI", "a", "fleet_btn_ai")
                        yield self._inspector_button("All actions", "enter", "fleet_btn_actions")
                        with Horizontal(id="fleet_values_heading"):
                            yield Static("Details", id="fleet_values_title", markup=False)
                            yield self._copy_row_button("fleet_copy_row")
                        yield FleetValues(id="fleet_values", classes="fleet-values")
                        yield Static(
                            "Click a value to copy it", id="fleet_values_hint", markup=False,
                        )
                yield Label("[bold]Keyword matches:[/bold]", id="keyword_matches_label")
                yield VerticalScroll(id="keyword_matches_container")
        with Vertical(id="fleet-bottom"):
            with Horizontal(id="fleet_value_bar"):
                yield self._copy_row_button("fleet_copy_row_line")
                yield FleetValueLine(id="fleet_value_line", classes="fleet-values")
            yield StatusBar()
            yield Footer()

    def _compose_filters(self) -> ComposeResult:
        """The chip rows and the summary line under the search box."""
        with Grid(id="fleet_filters"):
            with Horizontal(id="fleet_chip_row"):
                with Horizontal(id="fleet_state_chips"):
                    yield FleetChip("state", ALL, "All")
                    for state in STATES:
                        yield FleetChip("state", state, STATE_LABELS[state])
                with Horizontal(id="fleet_provider_chips"):
                    yield Static("│", classes="fleet-chip-divider", markup=False)
                    for provider in PROVIDERS:
                        yield FleetChip("provider", provider, PROVIDER_LABELS[provider])
            with Horizontal(id="fleet_fresh"):
                yield Static("", id="fleet_updated", markup=False)
                refresh = LinkButton(
                    "Refresh", key="r", id="fleet_refresh",
                    tooltip="Fetch the fleet again from every provider",
                )
                refresh.can_focus = False
                yield refresh

    @staticmethod
    def _copy_row_button(button_id: str) -> Button:
        """The "Copy row" link beside the values (it keeps the Tab order)."""
        button = LinkButton(
            "Copy row", key="y", id=button_id, classes="fleet-copy-row",
            disabled=True, tooltip="Copy the selected server's details",
        )
        button.can_focus = False
        return button

    @staticmethod
    def _inspector_button(
        text: str, key: str, button_id: str, role: ActionRole = "default",
    ) -> ActionButton:
        """A quick-action button with its key as a quiet hint; it keeps the Tab order."""
        button = ActionButton(text, key, role=role, id=button_id)
        button.can_focus = False
        return button

    @classmethod
    def _shortcut_characters(cls) -> frozenset[str]:
        """The single printable keys bound on this screen."""
        return frozenset(
            binding.key
            for binding in cls.BINDINGS
            if len(binding.key) == 1 and binding.key.isprintable()
        )

    def on_mount(self) -> None:
        """Start the loads; share-keyed memory uploads wait for all of them.

        The start-up itself counts as a load, so nothing is released before
        every load this run needs has registered itself.
        """
        self._expect_team_memory_load("startup")
        try:
            self._load_on_mount()
        finally:
            settle = getattr(self.app, "settle_team_memory_load", None)
            if callable(settle):
                settle("startup")
            self._release_team_memory_hold()

    def on_screen_resume(self) -> None:
        """Keep "Updated 12 s ago" current without waiting for a refresh."""
        if self._updated_timer is None:
            self._updated_timer = self.set_interval(1.0, self._sync_updated)

    def _load_on_mount(self) -> None:
        """Load instances using stale-while-revalidate strategy.

        1. If app already has cached data (loaded at startup), show it immediately
        2. If cache is still fresh, done — no AWS call needed
        3. If cache is stale or empty, fetch from AWS in the background
        """
        import logging
        logger = logging.getLogger(__name__)

        # Hide keyword panel until a search is performed
        self.query_one("#keyword_matches_label").display = False
        self.query_one("#keyword_matches_container").display = False
        self._restore_session_state()

        # Pre-fill search if requested by the caller (e.g. sidebar
        # "Hetzner Servers" button passes initial_search="hetzner").
        # Setting Input.value triggers on_input_changed → debounced
        # filter via the existing pipeline; no extra wiring needed.
        if self._initial_search:
            try:
                self.query_one("#search_input", Input).value = self._initial_search
            except Exception:
                pass

        # Use instances already loaded by app.on_mount(), or try cache directly
        if self.app.instances:
            self._instances = self.app.instances
            self._update_table()
            self._update_status_bar()
            logger.info("Loaded %d instances from app cache (age: %s)",
                        len(self._instances), self.app.cache_service.get_age())
        else:
            aws = self.app.provider_inventory("aws")
            stale_data = aws.get_cached_instances() if aws is not None else []
            if stale_data:
                self._instances = replace_instances(self.app, None, stale_data)
                self._update_table()
                self._update_status_bar()
                logger.info("Loaded %d instances from cache file (age: %s)",
                            len(stale_data), self.app.cache_service.get_age())

        # The teams' shared servers are never cached: listed on every start.
        self._fetch_shared_servers()

        # A fresh AWS cache skips the AWS fetch only: OVH and Hetzner keep
        # their own caches and are refreshed when theirs have expired. With
        # several accounts, a provider counts as fresh only when every one of
        # its accounts is.
        aws = self.app.provider_inventory("aws")
        if aws is None or aws.is_cache_fresh():
            logger.info("Cache is fresh, skipping AWS fetch")
            ovh = self.app.provider_inventory("ovh")
            if ovh is not None and not ovh.is_cache_fresh():
                self._fetch_ovh_instances()
            hetzner = self.app.provider_inventory("hetzner")
            if hetzner is not None and not hetzner.is_cache_fresh():
                self._fetch_hetzner_instances()
            return

        # Cache is stale or empty — fetch in background or foreground
        if self._instances:
            self._background_refresh()
        else:
            self._fetch_instances()
            self._fetch_ovh_instances()
            self._fetch_hetzner_instances()

    def _fetch_instances(self, force_refresh: bool = False) -> None:
        """Fetch instances from AWS via worker (blocking with progress indicator).

        Args:
            force_refresh: If True, bypass cache.
        """
        inventory = self.app.provider_inventory("aws")
        if inventory is None:
            return
        self._begin_load("aws")
        self._expect_team_memory_load("aws")
        self._run_load("aws",
            inventory.fetch_instances_cached(force_refresh=force_refresh),
            name="fetch_instances",
            exclusive=True,
            # Errors are reported by on_worker_state_changed; a failed fetch
            # must never close the app.
            exit_on_error=False,
        )

    def _background_refresh(self) -> None:
        """Refresh instances from AWS (and OVH if enabled) in the background.

        Shows a subtle notification instead of a blocking progress bar.
        """
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Starting background refresh of instances")
        self.app.notify("Refreshing instances in background...", severity="information")

        inventory = self.app.provider_inventory("aws")
        if inventory is not None:
            self._begin_load("aws")
            self._expect_team_memory_load("aws")
            self._run_load("aws",
                inventory.fetch_instances_cached(force_refresh=True),
                name="background_refresh",
                exclusive=True,
                exit_on_error=False,
            )
        # Also refresh OVH + Hetzner instances if those providers are enabled
        self._fetch_ovh_instances()
        self._fetch_hetzner_instances()

    def _fetch_ovh_instances(self) -> None:
        """Refresh every OVH account's instances in background via worker."""
        inventory = self.app.provider_inventory("ovh")
        if inventory is None:
            return
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Starting OVH instance refresh")
        self._begin_load("ovh")
        self._expect_team_memory_load("ovh")
        self._run_load("ovh",
            inventory.fetch_instances_cached(force_refresh=True),
            name="ovh_refresh",
            exclusive=False,
            exit_on_error=False,
        )

    def _fetch_hetzner_instances(self) -> None:
        """Refresh Hetzner Cloud instances in background via worker.

        Symmetric with :meth:`_fetch_ovh_instances`. Wired off the same
        ``_background_refresh`` trigger and the foreground fetch path so
        Hetzner servers appear at app startup and survive AWS refreshes.
        """
        inventory = self.app.provider_inventory("hetzner")
        if inventory is None:
            return
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Starting Hetzner instance refresh")
        self._begin_load("hetzner")
        self._expect_team_memory_load("hetzner")
        self._run_load("hetzner",
            inventory.fetch_instances_cached(force_refresh=True),
            name="hetzner_refresh",
            exclusive=False,
            # A refused token with no cache raises; the handler reports it.
            exit_on_error=False,
        )

    def _fetch_shared_servers(self) -> None:
        """List the servers the user's teams share, in the background.

        Signed out, nothing is asked and any shared rows still listed leave
        the list. They are never cached on disk: a member removed from a
        team stops seeing its servers at the next start. Once listed, the
        same teams' agent rules are fetched too.
        """
        from servonaut.services.shared_servers import load_shared_servers

        team_service = getattr(self.app, "team_service", None)
        auth = getattr(self.app, "auth_service", None)
        if team_service is None or auth is None or not auth.is_authenticated:
            self._release_team_memory_hold()
            if any(row.get("is_shared") is True for row in self.app.instances or []):
                self._replace_fleet("shared", [])
                self._update_table()
                self._update_status_bar()
            return
        self._begin_load("shared")
        self._expect_team_memory_load("shared")
        self._run_load("shared",
            load_shared_servers(team_service),
            name="shared_refresh",
            group="shared_servers",
            exclusive=True,
            exit_on_error=False,
        )

    def _reconcile_team_memory(self) -> bool:
        """Fold the memory of team copies into the user's own servers (see the app).

        Returns whether the merge was started.
        """
        return reconcile_team_memory(self.app)

    def _expect_team_memory_load(self, name: str) -> None:
        """Tell the app an inventory load started: share-keyed uploads wait for it."""
        expect = getattr(self.app, "expect_team_memory_load", None)
        if callable(expect):
            expect(name)

    def _reconcile_or_release(self) -> None:
        """After a load: start the merge, or lift the upload hold when none runs."""
        if not self._reconcile_team_memory():
            self._release_team_memory_hold()

    _LOAD_NAMES = {
        "shared_refresh": "shared",
        "ovh_refresh": "ovh",
        "hetzner_refresh": "hetzner",
        "fetch_instances": "aws",
        "background_refresh": "aws",
    }

    def _settle_team_memory_load(self, event: Worker.StateChanged) -> None:
        """An inventory load ended (rows, error or cancel): it no longer holds uploads back."""
        name = self._LOAD_NAMES.get(event.worker.name)
        finished = (WorkerState.SUCCESS, WorkerState.ERROR, WorkerState.CANCELLED)
        settle = getattr(self.app, "settle_team_memory_load", None)
        if name is not None and event.state in finished and callable(settle):
            settle(name)

    def _release_team_memory_hold(self) -> None:
        """No shared servers will fold: lift the hold on share-keyed uploads (see the app)."""
        release = getattr(self.app, "release_team_memory_hold", None)
        if callable(release):
            release()

    def _shared_servers_loaded(self, worker: Worker) -> None:
        """List what :meth:`_fetch_shared_servers` found."""
        import logging

        if worker.error:
            # No team plan, no network: the user's own servers are the list,
            # as before; nothing to warn about at every start.
            logging.getLogger(__name__).info(
                "Team shared servers not listed: %s", worker.error,
            )
            self._release_team_memory_hold()
            return
        found = worker.result
        # The team key tier of SSH connect reads the user's teams from here.
        self.app.teams = found.teams
        # What agents may do on these servers: the same teams' signed rules.
        refresh_rules = getattr(self.app, "refresh_team_policies", None)
        if callable(refresh_rules):
            refresh_rules(found.teams)
        self._replace_fleet("shared", found.rows)
        self._update_table()
        self._update_status_bar()
        if not self._reconcile_team_memory():
            self._release_team_memory_hold()
        if found.problems:
            self.app.notify(
                "Some team servers could not be listed: " + "; ".join(found.problems),
                severity="warning",
                markup=False,
            )

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        """Handle worker state changes: list the rows, then report the provider's outcome.

        Args:
            event: Worker state changed event.
        """
        self._settle_team_memory_load(event)
        self._handle_worker_state(event)
        self._record_load_outcome(event)
        self._forget_finished_load_worker(event)

    def _handle_worker_state(self, event: Worker.StateChanged) -> None:
        """List what a finished inventory worker found (or report why it failed)."""
        if event.state == WorkerState.CANCELLED:
            # A cancelled worker counts as finished but has no result.
            # Pressing R cancels the refreshes still running and starts new
            # ones; reading the cancelled ones as empty would clear rows or
            # report "no instances" before the new results arrive.
            self._release_team_memory_hold()
            return

        if event.worker.name == "shared_refresh" and event.worker.is_finished:
            self._shared_servers_loaded(event.worker)
            return

        if event.worker.name == "ovh_refresh" and event.worker.is_finished:
            if event.worker.error:
                self._release_team_memory_hold()
                self.app.notify(
                    f"OVH refresh error: {event.worker.error}",
                    severity="error",
                    markup=False,
                )
            else:
                new_ovh = event.worker.result or []
                # Keeps the real rows aside; lists them redacted in demo mode.
                self._replace_fleet("ovh", new_ovh)
                self._update_table()
                self._update_status_bar()
                self._report_duplicate_accounts("ovh")
                self._reconcile_or_release()
                fetch_error = getattr(
                    self.app.provider_inventory("ovh"), "last_fetch_error", None
                )
                if isinstance(fetch_error, str) and fetch_error:
                    self.app.notify(
                        self._ovh_refresh_warning(fetch_error),
                        severity="warning",
                        markup=False,
                    )
                elif new_ovh:
                    self.app.notify(
                        f"OVH refreshed: {len(new_ovh)} instances",
                        severity="information",
                    )
            return

        if event.worker.name == "hetzner_refresh" and event.worker.is_finished:
            if event.worker.error:
                self._release_team_memory_hold()
                # markup=False because the worker error message can
                # include server-controlled text (Hetzner names, label
                # values, error strings). The project mandates the flag
                # for any notify with server-controlled interpolation.
                self.app.notify(
                    f"Hetzner refresh error: {event.worker.error}",
                    severity="error",
                    markup=False,
                )
            else:
                new_hetzner = event.worker.result or []
                # Keeps the real rows aside; lists them redacted in demo mode.
                self._replace_fleet("hetzner", new_hetzner)
                self._update_table()
                self._update_status_bar()
                self._report_duplicate_accounts("hetzner")
                self._reconcile_or_release()
                inventory = self.app.provider_inventory("hetzner")
                fetch_error = getattr(inventory, "last_fetch_error", None)
                if isinstance(fetch_error, str) and fetch_error:
                    # The failed account(s) returned their cache in place of
                    # the fetch. markup=False: the text carries an API error.
                    if getattr(inventory, "last_fetch_partial", False) is True:
                        message = f"Hetzner refresh incomplete. {fetch_error}"
                    else:
                        message = (
                            f"Hetzner refresh failed: {fetch_error}. "
                            "Showing cached instances."
                        )
                    self.app.notify(message, severity="warning", markup=False)
                elif new_hetzner:
                    self.app.notify(
                        f"Hetzner refreshed: {len(new_hetzner)} instances",
                        severity="information",
                        markup=False,
                    )
            return

        if event.worker.name in ("fetch_instances", "background_refresh"):
            if event.worker.is_finished:
                is_background = event.worker.name == "background_refresh"

                if event.worker.error:
                    self._release_team_memory_hold()
                    self._handle_fetch_error(event.worker.error, is_background)
                else:
                    new_instances = event.worker.result or []
                    # The toast compares AWS with AWS: the table also holds
                    # custom, OVH and Hetzner rows that this fetch never sees.
                    old_count = sum(1 for i in self._instances if _is_aws_row(i))
                    # Re-merge custom servers, OVH and Hetzner instances
                    # with the fresh AWS instances.
                    custom = self.app.custom_server_service.list_as_instances()
                    ovh = self.app.provider_inventory("ovh")
                    ovh_instances = ovh.get_cached_instances() if ovh is not None else []
                    hetzner = self.app.provider_inventory("hetzner")
                    hetzner_instances = (
                        hetzner.get_cached_instances() if hetzner is not None else []
                    )
                    # Keeps the real rows aside; lists them redacted in demo mode.
                    self._replace_fleet(
                        None, new_instances + custom + ovh_instances + hetzner_instances,
                    )
                    self._update_table()
                    self._update_status_bar()
                    self._report_duplicate_accounts("aws")
                    self._reconcile_or_release()

                    aws = self.app.provider_inventory("aws")
                    fetch_error = getattr(aws, "last_fetch_error", None)
                    if isinstance(fetch_error, str) and fetch_error:
                        # The failed account(s) kept their previous cache; the
                        # rows on screen are stale, not the truth.
                        # markup=False: the text carries an SDK error string.
                        if getattr(aws, "last_fetch_partial", False) is True:
                            message = f"AWS refresh incomplete. {fetch_error}"
                        else:
                            message = f"AWS refresh failed: {fetch_error}."
                            if new_instances:
                                message += " Showing cached instances."
                        self.app.notify(message, severity="warning", markup=False)
                    elif not new_instances and not getattr(aws, "credentials_missing", False):
                        self.app.notify(
                            "No EC2 instances found in any region.",
                            severity="information"
                        )
                    elif is_background and new_instances:
                        diff = len(new_instances) - old_count
                        if diff != 0:
                            word = "more" if diff > 0 else "fewer"
                            self.app.notify(
                                f"Refreshed: {len(new_instances)} instances ({abs(diff)} {word})",
                                severity="information"
                            )
                        else:
                            self.app.notify(
                                f"Refreshed: {len(new_instances)} instances (up to date)",
                                severity="information"
                            )

    def _report_duplicate_accounts(self, provider: str) -> None:
        """Say once per session when two accounts list the same servers.

        The fleet already lists each server once; the notice tells the user
        why an account shows no servers of its own (it is the same account
        configured twice, e.g. two AWS profiles for one account).
        """
        from servonaut.config.accounts import PROVIDER_TITLES

        inventory = self.app.provider_inventory(provider)
        duplicates = getattr(inventory, "duplicate_accounts", None) or {}
        for later, earlier in duplicates.items():
            if (provider, later) in self._reported_duplicate_accounts:
                continue
            self._reported_duplicate_accounts.add((provider, later))
            self.app.notify(
                f"{PROVIDER_TITLES.get(provider, provider)} accounts '{later}' and "
                f"'{earlier}' list the same servers; they look like the same "
                "account configured twice.",
                severity="warning",
                markup=False,
            )

    def _ovh_refresh_warning(self, fetch_error: str) -> str:
        """Wording for an OVH refresh that failed in full or in part."""
        if getattr(self.app.provider_inventory("ovh"), "last_fetch_partial", False) is not True:
            return f"OVH refresh failed: {fetch_error}. Showing cached instances."
        if self.app.demo_mode:
            # The details name Public Cloud project ids.
            return (
                "OVH refresh incomplete: some sources could not be listed "
                "(details hidden in demo mode)."
            )
        # Names the failed sources and how many of their rows are cached;
        # every other OVH row is fresh.
        return f"OVH refresh incomplete. {fetch_error}"

    def _handle_fetch_error(self, error: BaseException, is_background: bool) -> None:
        """Handle AWS fetch errors with user-friendly messages.

        Args:
            error: The exception from the worker.
            is_background: Whether this was a background refresh.
        """
        import logging
        logger = logging.getLogger(__name__)
        logger.error("Failed to fetch instances: %s", error)

        error_msg = str(error)
        if "NoCredentialsError" in error_msg or "credentials" in error_msg.lower():
            self.app.notify(
                "AWS credentials not found. Please configure AWS credentials.",
                severity="error"
            )
        elif "EndpointConnectionError" in error_msg or "timed out" in error_msg.lower():
            self.app.notify(
                "Network error: Unable to connect to AWS. Check your connection.",
                severity="error"
            )
        elif "AccessDenied" in error_msg or "UnauthorizedOperation" in error_msg:
            self.app.notify(
                "Access denied: Check your AWS IAM permissions for EC2.",
                severity="error"
            )
        else:
            self.app.notify(
                f"Error loading instances: {error_msg}",
                severity="error",
                markup=False,
            )

        # Only clear data if foreground fetch with no existing data
        if not is_background and not self._instances:
            self._update_table()
            self._update_status_bar()

    def refresh_memory_status(self) -> None:
        """Redraw the memory line of the inspector after a fleet auto-scan.

        Called duck-typed by ``app._refresh_fleet_panels_after_scan`` when a
        background auto-scan cycle completes while this screen is mounted, so
        the status reflects freshly-probed servers in real time.
        """
        try:
            self._update_detail_panel()
        except NoMatches:
            return

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the fleet, status bar and detail pane after a demo toggle."""
        self._instances = list(self.app.instances)
        self._update_table()
        self._update_status_bar()
        self._update_detail_panel()
        self._render_load()

    def _update_table(self) -> None:
        """Update instance table with current data, preserving active filter."""
        table = self.query_one(InstanceTable)
        # The search text and the chips stay applied through a refresh, and
        # the table keeps the cursor on its server.
        table.configure_filters(
            self.query_one("#search_input", Input).value, self._filter.matches,
        )
        table.set_marks(self._marks, redraw=False)
        table.populate(self._instances)
        self._sync_memory_banner()
        self._update_detail_panel()

    def _sync_memory_banner(self) -> None:
        """Show the memory-discoverability banner only when no server has memory.

        Once the operator has captured memory for at least one instance the
        feature has been discovered; keeping the banner up from then on
        would be clutter.
        """
        memory_service = getattr(self.app, "memory_service", None)
        try:
            banner = self.query_one("#memory_discover_banner")
        except Exception:
            return
        if memory_service is None or not self._instances:
            banner.display = False
            return
        try:
            has_any = bool(memory_service.list_all())
        except Exception:
            has_any = True  # Fail closed — hide the banner on lookup errors.
        banner.display = not has_any

    def _update_status_bar(self) -> None:
        """Refresh the cache age and the filter-driven parts of the screen."""
        # The cache age is shown once, next to the summary (see _updated_text);
        # reading it here also keeps the file off the once-a-second path.
        self._note_cache_age(self.app.cache_service.get_age())
        self._sync_filter_ui()

    def _note_cache_age(self, age: object) -> None:
        """Remember when the cache was written, to count its age without reading it again."""
        self._cache_written_at = (
            time.time() - age.total_seconds() if isinstance(age, timedelta) else None
        )

    def _restore_session_state(self) -> None:
        """Bring back the filters and the refresh time this session left behind."""
        state = getattr(self.app, "workspace_state", None)
        state_filter = getattr(state, "fleet_state_filter", None)
        provider_filter = getattr(state, "fleet_provider_filter", None)
        if isinstance(state_filter, str) and isinstance(provider_filter, str):
            self._filter = FleetFilter().with_state(state_filter).with_provider(provider_filter)
        updated = getattr(state, "fleet_updated_at", None)
        if isinstance(updated, float):
            self._last_updated = updated
        self._sync_filter_ui()

    def _remember_filter(self) -> None:
        state = getattr(self.app, "workspace_state", None)
        if state is not None:
            state.fleet_state_filter = self._filter.state
            state.fleet_provider_filter = self._filter.provider

    def _sync_filter_ui(self) -> None:
        """Show the chips, their counts and the summary line for what the table lists."""
        try:
            table = self.query_one(InstanceTable)
            counts = facets(table.searched_rows(), self._filter)
            self._sync_chips(counts, table._all_instances)
            self._sync_summary(len(table._filtered_instances), len(table._all_instances))
        except NoMatches:
            return
        self._sync_updated()

    def _sync_chips(self, counts: FleetFacets, fleet: List[dict]) -> None:
        """Label each chip with its count; show only the choices the fleet offers."""
        present = {row_provider(row) for row in fleet} | {row_state(row) for row in fleet}
        for chip in self.query(FleetChip):
            if chip.value == ALL:
                number, shown = counts.total, True
                active = not self._filter.is_active
            elif chip.group == "state":
                number = counts.states[chip.value]
                active = self._filter.state == chip.value
                shown = chip.value != STATE_OTHER or chip.value in present or active
            else:
                number = counts.providers[chip.value]
                active = self._filter.provider == chip.value
                shown = chip.value in present or active
            label = self._chip_label(chip, number)
            if label != chip.label:
                chip.label = label
                # The chip is as wide as its words: measure them again.
                chip.refresh(layout=True)
                self.call_after_refresh(self._sync_fresh_layout)
            chip.set_class(active, "--chosen")
            chip.display = shown

    @staticmethod
    def _chip_label(chip: FleetChip, number: int) -> Content:
        glyphs = {"running": ("●", "$text-success"), "stopped": ("●", "$text-error"),
                  STATE_OTHER: ("○", "$text-muted")}
        glyph = glyphs.get(chip.value) if chip.group == "state" else None
        text = f"{chip.base_label} {number}"
        if glyph is None:
            return Content(text)
        return Content.assemble(literal(glyph[0], glyph[1]), " ", text)

    def _sync_summary(self, shown: int, total: int) -> None:
        query = self.query_one("#search_input", Input).value.strip()
        self.query_one("#fleet_summary", FleetSummaryLine).set_texts(
            summary(shown, total, self._filter, query),
            summary(shown, total, self._filter, query, hint=False),
        )

    def _sync_updated(self) -> None:
        """Say how fresh the list is, redrawing only when the words change.

        On the chip row only the age fits; on its own row the full words show.
        """
        full = self._updated_text()
        text = self._inline_age(full) if self._fresh_inline else full
        if text == self._updated_shown:
            return
        try:
            label = self.query_one("#fleet_updated", Static)
            label.update(f"{text} ·" if text else "")
            label.tooltip = full or None
        except NoMatches:
            return
        self._updated_shown = text
        self.call_after_refresh(self._sync_fresh_layout)

    @staticmethod
    def _inline_age(full: str) -> str:
        """*full* cut down to the age alone: "5 min ago", or "Refresh failed"."""
        if full.startswith("Refresh failed"):
            return "Refresh failed"
        for prefix in ("Updated ", "Cached ", "cached "):
            if full.startswith(prefix):
                return full[len(prefix):]
        return full

    def _cache_ago(self) -> str:
        if self._cache_written_at is None or not self._instances:
            return ""
        return format_ago(time.time() - self._cache_written_at)

    def _updated_text(self) -> str:
        """The freshness label; empty while the refresh line already says it."""
        if self._load.active and not self._load.first_run:
            return ""
        cached = f"cached {self._cache_ago()}" if self._cache_ago() else ""
        if self._refresh_failed:
            return f"Refresh failed · {cached}" if cached else "Refresh failed"
        if self._last_updated is not None:
            return f"Updated {format_ago(time.time() - self._last_updated)}"
        return cached.capitalize()

    def _set_filter(self, new_filter: FleetFilter) -> None:
        """Apply a new chip selection to the table, the inspector and the chips."""
        if new_filter == self._filter:
            return
        self._filter = new_filter
        self._remember_filter()
        table = self.query_one(InstanceTable)
        table.filter(self.query_one("#search_input", Input).value, self._filter.matches)
        self._update_status_bar()
        self._update_detail_panel()

    def _present_in_fleet(self, value: str) -> bool:
        rows = self.query_one(InstanceTable)._all_instances
        if value in STATES:
            return value != STATE_OTHER or any(row_state(r) == value for r in rows)
        return any(row_provider(r) == value for r in rows)

    def action_filter_state(self) -> None:
        """Cycle the state filter: all, running, stopped, other."""
        choice = next_choice(self._filter.state, STATES, self._present_in_fleet)
        self._set_filter(self._filter.with_state(choice))

    def action_filter_provider(self) -> None:
        """Cycle the provider filter through the providers in the list."""
        choice = next_choice(self._filter.provider, PROVIDERS, self._present_in_fleet)
        self._set_filter(self._filter.with_provider(choice))

    def _press_chip(self, chip: FleetChip) -> None:
        if chip.value == ALL:
            self._set_filter(FleetFilter())
        elif chip.group == "state":
            self._set_filter(self._filter.with_state(chip.value))
        else:
            self._set_filter(self._filter.with_provider(chip.value))

    # ------------------------------------------------------------------
    # Loading and refresh reporting
    # ------------------------------------------------------------------

    def _replace_fleet(self, source: Optional[str], rows: List[dict]) -> None:
        """List *rows* as *source*'s servers and remember what changed on screen."""
        before = {
            identity: (row_source(row), str(row.get("state") or ""))
            for row in self._instances
            if (identity := row_identity(row))
        }
        self._instances = replace_instances(self.app, source, rows)
        self._mark_changes(before)

    def _mark_changes(self, before: Dict[str, tuple]) -> None:
        """Mark servers that are new, or changed state, since *before*.

        A provider that listed nothing before is loading for the first time:
        everything it brings would be new, which says nothing, so none of it
        is marked.
        """
        had_rows = {source for source, _state in before.values()}
        marks: Dict[str, str] = {}
        for row in self._instances:
            identity = row_identity(row)
            if identity is None:
                continue
            known = before.get(identity)
            if known is None:
                if row_source(row) in had_rows:
                    marks[identity] = MARK_NEW
            elif known[1] and known[1] != str(row.get("state") or ""):
                marks[identity] = MARK_WAS.format(state=known[1])
        if not marks:
            return
        self._marks.update(marks)
        if self._marks_timer is not None:
            self._marks_timer.stop()
        self._marks_timer = self.set_timer(self._MARK_SECONDS, self._clear_marks)

    def _clear_marks(self) -> None:
        self._marks = {}
        self._marks_timer = None
        try:
            self.query_one(InstanceTable).set_marks({})
        except NoMatches:
            return

    def _begin_load(self, key: str) -> None:
        """A provider started answering: say so (see ``_fleet_load``)."""
        inventory = self.app.provider_inventory(key) if key != "shared" else None
        accounts = len(getattr(inventory, "bindings", None) or ())
        self._load.start(
            key, accounts=accounts, has_rows=bool(self._instances),
            cached_age=self._cached_age_text(),
        )
        self._render_load()

    def _cached_age_text(self) -> str:
        return self._cache_ago()

    def _run_load(self, key: str, work, **kwargs) -> None:
        """Start *key*'s load in a worker and remember it as the one that owns the load."""
        self._load_workers[key] = self.run_worker(work, **kwargs)

    def _forget_finished_load_worker(self, event: Worker.StateChanged) -> None:
        """A load's worker ended: it no longer owns the provider's load."""
        key = self._LOAD_NAMES.get(event.worker.name)
        if key is not None and event.worker.is_finished and self._load_workers.get(key) is event.worker:
            del self._load_workers[key]

    def _record_load_outcome(self, event: Worker.StateChanged) -> None:
        """A provider's worker ended: record its count, or why its rows are stale."""
        key = self._LOAD_NAMES.get(event.worker.name)
        if key is None:
            return
        if event.state == WorkerState.CANCELLED:
            if self._load_workers.get(key) is event.worker:
                self._record_cancelled(key)
            return
        if event.state not in (WorkerState.SUCCESS, WorkerState.ERROR):
            return
        if key == "shared":
            self._load.drop("shared")
        else:
            error = self._load_error(key, event.worker)
            count = sum(1 for row in self._instances if row_source(row) == key)
            self._load.finish(key, count=count, error=error)
        if not self._load.active:
            self._cycle_ended()
        self._render_load()

    def _record_cancelled(self, key: str) -> None:
        """A provider's worker was cancelled: its cached rows stay, marked stale."""
        if key == "shared":
            self._load.drop("shared")
        else:
            count = sum(1 for row in self._instances if row_source(row) == key)
            self._load.cancel(key, count=count)
        if not self._load.active:
            self._cycle_ended()
        self._render_load()

    def action_cancel_slow_providers(self) -> None:
        """Stop waiting for the providers that have not answered; the others keep their rows."""
        pending = {load.key for load in self._load.pending}
        for worker in list(self.workers):
            if self._LOAD_NAMES.get(worker.name) in pending and not worker.is_finished:
                worker.cancel()

    def _cycle_ended(self) -> None:
        """Claim "Updated" only if some provider really answered with fresh rows."""
        if self._load.delivered:
            self._last_updated = time.time()
            self._refresh_failed = False
            state = getattr(self.app, "workspace_state", None)
            if state is not None:
                state.fleet_updated_at = self._last_updated
        elif self._load.problems:
            self._refresh_failed = True
        self._sync_updated()

    def _load_error(self, key: str, worker: Worker) -> str:
        """Why a provider's rows are not fresh, or "" when they are."""
        if worker.error:
            reason = str(worker.error) or type(worker.error).__name__
        else:
            reported = getattr(self.app.provider_inventory(key), "last_fetch_error", None)
            reason = reported if isinstance(reported, str) else ""
        if reason and key == "ovh" and self.app.demo_mode:
            # Like the refresh toast: OVH details name Public Cloud project ids.
            return "could not refresh"
        return reason

    def _render_load(self) -> None:
        """Show the load report above the list, or hide it when there is none."""
        try:
            status = self.query_one("#fleet_load_status", Static)
        except NoMatches:
            return
        content = render_load(self._load, lambda text: display_text(self.app, text))
        status.display = content is not None
        if content is not None:
            status.update(content)
        self._sync_load_timer()
        self._sync_skeleton()
        self._sync_updated()

    def _sync_load_timer(self) -> None:
        """Turn the spinner while a provider is answering, and only then."""
        if self._load.active and self._load_timer is None:
            self._load_timer = self.set_interval(self._SPINNER_SECONDS, self._tick_load)
        elif not self._load.active and self._load_timer is not None:
            self._load_timer.stop()
            self._load_timer = None

    def _tick_load(self) -> None:
        """Turn the spinner one step and read where each provider's listing is."""
        moved = self.app.animation_level != "none"
        if moved:
            self._load.frame += 1
        for load in self._load.pending:
            inventory = self.app.provider_inventory(load.key) if load.key != "shared" else None
            progress = getattr(inventory, "load_progress", None)
            moved = self._load.note_progress(load.key, progress) or moved
        if moved:
            self._render_load()

    def _sync_skeleton(self) -> None:
        """Show placeholder rows below the servers while the first listing fills."""
        waiting = self._load.active and self._load.first_run
        try:
            self.query_one(FleetSkeleton).display = waiting
            self.query_one(InstanceTable).set_class(waiting, "--loading")
        except NoMatches:
            return

    def on_data_table_row_highlighted(self, event) -> None:
        """Update detail panel when table cursor moves."""
        self._update_detail_panel()

    def on_data_table_row_selected(self, event) -> None:
        """Open the actions menu when the user presses Enter or clicks a row.

        ``cursor_type="row"`` on InstanceTable makes DataTable post
        ``RowSelected`` for Enter key + double-click. Without this handler
        the events fall through to nothing — the screen-level ``enter``
        binding never fires because DataTable consumes the key first.
        """
        # Both clicks of a double-click on the highlighted row can reach the
        # table before the first one has opened the server: open it once.
        if self.app.screen is not self:
            return
        self.action_select_instance()

    def _update_detail_panel(self) -> None:
        """Show selected instance metadata in the detail panel and inspector."""
        table = self.query_one(InstanceTable)
        instance = table.get_selected_instance()
        for copy_row in self.query(".fleet-copy-row"):
            copy_row.disabled = not instance
        for values in self.query(".fleet-values"):
            values.set_instance(instance)
        self._update_inspector_panel(instance)
        self._sync_memory_note()

    def _update_inspector_panel(self, instance: Optional[dict]) -> None:
        """Update the right-hand Selected server quick-action inspector."""
        try:
            header = self.query_one("#fleet_inspector_header", Static)
        except NoMatches:
            return
        for btn in self.query("#fleet_inspector Button"):
            btn.disabled = not instance
        if not instance:
            header.update("[bold]Selected server[/bold]\n[dim]No server selected[/dim]")
            return
        name = display_name(instance) or str(instance.get("id") or "Unnamed")
        provider = provider_label(instance)
        address = str(instance.get("public_ip") or instance.get("private_ip") or instance.get("host") or "—")
        # Server-sourced text is content, never markup: a name written like a
        # markup link must neither crash the screen nor run an action.
        header.update(Content.assemble(
            literal(name, "bold $text-accent"),
            "  ",
            self._inspector_state_badge(instance),
            "\n",
            literal(f"{provider} · {address}", "dim"),
            "\n",
            self._memory_line(instance),
        ))

    def _sync_memory_note(self) -> None:
        """Say the selected server's memory status in the status bar while the inspector is hidden."""
        try:
            hidden = not self.query_one("#fleet_inspector").display
            instance = self.query_one(InstanceTable).get_selected_instance()
            bar = self.query_one(StatusBar)
        except NoMatches:
            return
        bar.set_note(self._memory_line(instance).plain if hidden and instance else "")

    def _memory_line(self, instance: dict) -> Content:
        """Whether the server's memory (cached facts) is fresh, stale, off or missing."""
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            return literal("Memory unavailable", "dim")
        from servonaut.screens.fleet_memory import (
            STATUS_FRESH, STATUS_OPT_OUT, STATUS_STALE, compute_memory_status,
        )
        try:
            status = compute_memory_status(instance, memory_service)
        except Exception:  # noqa: BLE001 - a broken memory store must not hide the server
            return literal("Memory unavailable", "dim")
        words = {
            STATUS_FRESH: ("● Memory fresh", "$text-success"),
            STATUS_STALE: ("● Memory stale", "$text-warning"),
            STATUS_OPT_OUT: ("⛔ Memory off", "$text-error"),
        }
        text, style = words.get(status, ("○ No memory yet", "dim"))
        return literal(text, style)

    @staticmethod
    def _inspector_state_badge(instance: dict) -> Content:
        """The state marker; a server without a state reads as unknown, not running."""
        state = str(instance.get("state") or "").strip() or "unknown"
        if state == "running":
            return literal(f"● {state}", "$text-success")
        return literal(f"○ {state}", "dim")

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle search input changes with debounce."""
        if event.input.id == "search_input":
            if self._search_debounce_timer is not None:
                self._search_debounce_timer.stop()
            value = event.value
            self._search_debounce_timer = self.set_timer(
                self._SEARCH_DEBOUNCE,
                lambda: self._apply_search_filter(value),
            )

    def _apply_search_filter(self, value: str) -> None:
        """Apply search filter and keyword search (called after debounce)."""
        table = self.query_one(InstanceTable)
        table.filter(value, self._filter.matches)
        self._update_status_bar()
        self._update_detail_panel()

        query = value.strip()
        if len(query) >= 2:
            self._search_keywords(query)
        else:
            self._clear_keyword_results()

    def _search_keywords(self, query: str) -> None:
        """Search keyword store and display matches."""
        try:
            matches = self.app.keyword_store.search(query)
        except Exception as e:
            self.app.notify(f"Error searching keywords: {e}", severity="error", markup=False)
            matches = []

        self._display_keyword_matches(matches)

    def _display_keyword_matches(self, matches: List[dict]) -> None:
        """Display keyword search results in the panel."""
        label = self.query_one("#keyword_matches_label")
        container = self.query_one("#keyword_matches_container", VerticalScroll)
        container.remove_children()

        if not matches:
            label.display = False
            container.display = False
            return

        label.display = True
        container.display = True

        # Demo mode: keyword rows are raw scan output captured from real
        # servers (file listings, grep hits). Arbitrary strings in them
        # (project/brand names in filenames) defeat pattern scrubbing, so
        # hide the content entirely rather than half-redact it.
        if getattr(self.app, "demo_mode", False):
            container.mount(
                Static(f"[dim]{len(matches)} match(es) hidden in demo mode[/dim]")
            )
            return

        for match in matches[:20]:
            server_id = match.get('server_id', '')
            source = match.get('source', '')
            content = match.get('content', '')

            if len(content) > 200:
                content = content[:200] + "..."

            # Scan output is raw text from the server: content, not markup.
            container.mount(Static(Content.assemble(
                literal(f"Server: {server_id}", "bold"),
                "\n  ",
                literal(f"Source: {source}"),
                "\n  ",
                literal(content, "dim"),
                "\n",
            )))

    def _clear_keyword_results(self) -> None:
        """Hide and clear keyword results panel."""
        self.query_one("#keyword_matches_label").display = False
        container = self.query_one("#keyword_matches_container", VerticalScroll)
        container.display = False
        container.remove_children()


    def action_refresh(self) -> None:
        """Force-refresh the instance list from AWS, OVH, Hetzner and the teams."""
        self._fetch_instances(force_refresh=True)
        self._fetch_ovh_instances()
        self._fetch_hetzner_instances()
        self._fetch_shared_servers()

    def action_focus_search(self) -> None:
        """Focus the search input."""
        search_input = self.query_one("#search_input", Input)
        search_input.focus()

    def action_select_instance(self) -> None:
        """Handle instance selection."""
        from servonaut.screens.server_actions import ServerActionsScreen

        table = self.query_one(InstanceTable)
        instance = table.get_selected_instance()

        if instance:
            self.app.push_screen(ServerActionsScreen(instance))
        else:
            self.app.notify("No instance selected", severity="warning")

    def action_manage_ssh_ref(self) -> None:
        """Open the BW SSH ref editor for the selected instance.

        Top-level shortcut so users can manage SSH refs without drilling
        into ServerActionsScreen. Loads the existing ref (if any) so the
        modal opens in edit mode when appropriate.
        """
        table = self.query_one(InstanceTable)
        instance = table.get_selected_instance()
        if not instance:
            self.app.notify("No instance selected", severity="warning")
            return
        if not getattr(self.app, "bw_ssh_config_service", None):
            self.app.notify(
                "BW SSH service unavailable — sign in to manage SSH refs",
                severity="warning",
            )
            return
        self.run_worker(
            self._open_ssh_ref_editor(instance),
            group="ssh_ref_edit",
            exclusive=True,
        )

    async def _open_ssh_ref_editor(self, instance: dict) -> None:
        from servonaut.screens.ssh_ref_editor import SshRefEditorModal
        provider = (instance.get("provider") or "aws").lower()
        instance_id = real_instance_id(self.app, instance.get("id"))
        existing = None
        try:
            existing = await self.app.bw_ssh_config_service.get_personal_instance_ref(
                provider, instance_id,
            )
        except Exception as exc:
            # 404 → no ref yet (add mode). Any other error: log + assume add mode.
            import logging
            logging.getLogger(__name__).debug(
                "Failed to preload SSH ref for %s/%s: %s",
                provider, instance_id, exc,
            )
        saved = await self.app.push_screen_wait(
            SshRefEditorModal(instance, existing_ref=existing),
        )
        if saved and hasattr(self.app, "_refresh_ssh_verify_status"):
            self.run_worker(
                self.app._refresh_ssh_verify_status(),
                group="memory_io",
            )

    def action_verify_ssh(self) -> None:
        """Run the SSH verify probe for the selected instance.

        Top-level shortcut mirroring ServerActionsScreen's V binding so the
        user can probe a key without diving into the action menu.
        """
        from servonaut.screens.server_actions import ServerActionsScreen
        table = self.query_one(InstanceTable)
        instance = table.get_selected_instance()
        if not instance:
            self.app.notify("No instance selected", severity="warning")
            return
        # Delegate to ServerActionsScreen's existing verify flow so behaviour
        # stays in lockstep — push the screen, then trigger its action.
        screen = ServerActionsScreen(instance)
        self.app.push_screen(screen)
        # ServerActionsScreen.action_verify_ssh runs in a worker; calling it
        # right after push is safe (the screen mounts then the action fires).
        self.app.call_later(screen.action_verify_ssh)

    def _get_selected_running_instance(self) -> Optional[dict]:
        """Get the selected instance, validate it's connectable.

        Only EC2 instances are checked for state: the other providers' rows,
        custom servers and team shared servers have no AWS state.

        Returns:
            Instance dict if valid, None otherwise.
        """
        table = self.query_one(InstanceTable)
        instance = table.get_selected_instance()

        if not instance:
            self.app.notify("No instance selected", severity="warning")
            return None

        if _is_aws_row(instance) and instance.get('state') != 'running':
            self.app.notify(
                f"Instance is {instance.get('state')}. Only running instances can connect.",
                severity="warning"
            )
            return None

        if refuse_unresolved(self.app, instance):
            return None
        return instance

    def action_ssh_connect(self) -> None:
        """Quick SSH connect to selected instance."""
        instance = self._get_selected_running_instance()
        if not instance:
            return
        display = instance
        # Demo mode redacts rows in place; connect to the real record.
        instance = connection_instance(self.app, display)

        try:
            profile = self.app.connection_service.resolve_profile(instance)
            host = self.app.connection_service.get_target_host(instance, profile)

            if not host:
                self.app.notify("No IP address available for this instance.", severity="error")
                return

            proxy_args = []
            if profile:
                proxy_args = self.app.connection_service.get_proxy_args(profile)

            # Custom servers use their own username/port/key; OVH uses provider defaults; AWS uses config defaults
            if instance.get('is_shared') is True:
                # The team's login and port. The team's key (vault or SSH
                # certificate), when it has one, replaces the user's own
                # configured key when the session starts.
                username = (
                    (profile.username if profile else None)
                    or instance.get('username')
                    or self.app.config_manager.get().default_username
                )
                port = instance.get('port') or None
                key_path = self.app.ssh_service.get_key_path(instance['id'])
            elif instance.get('is_custom'):
                username = instance.get('username') or 'root'
                port = instance.get('port') or 22
                key_path = instance.get('ssh_key') or instance.get('key_name') or None
            elif instance.get('is_ovh'):
                # The OVH account's own default key and username, the same
                # ones the server actions and background reads use.
                ovh_options = self.app.connection_service.resolve_ovh_connection(instance)
                username = (profile.username if profile else None) or ovh_options["username"]
                port = None
                key_path = ovh_options["key_path"] or None
            elif instance.get('is_hetzner'):
                username = (
                    (profile.username if profile else None)
                    or instance.get('username')
                    or 'root'
                )
                port = None
                key_path = (
                    instance.get('ssh_key')
                    or self.app.config_manager.get().default_key
                    or None
                )
            else:
                username = (
                    (profile.username if profile else None)
                    or self.app.config_manager.get().default_username
                )
                port = None
                key_path = self.app.ssh_service.get_key_path(instance['id'])
                if not key_path and instance.get('key_name'):
                    key_path = self.app.ssh_service.discover_key(instance['key_name'])

            extra_options = self.app.connection_service.get_extra_options(instance, profile)
            conn = {
                "host": host, "username": username, "key_path": key_path,
                "proxy_args": proxy_args, "port": port, "extra_options": extra_options,
                "profile": profile,
            }
        except Exception as e:
            self.app.notify(f"SSH error: {e}", severity="error", markup=False)
            return
        # The server's vault credential needs the event loop: launch from a worker.
        self.run_worker(
            self._launch_ssh(display, instance, conn),
            group="ssh_connect", exclusive=True, exit_on_error=False,
        )

    async def _launch_ssh(self, display: dict, instance: dict, conn: dict) -> None:
        """Open the SSH terminal for *instance*, with its vault credential when it has one."""
        from servonaut.services.ssh_credentials import (
            VaultCredentialError, resolve_with_vault, ssh_identity_kwargs,
        )

        profile = conn.get("profile")
        try:
            conn = await resolve_with_vault(
                conn, instance,
                vault_runtime=getattr(self.app, "vault_command_service", None),
                connection_service=self.app.connection_service,
                cache=getattr(self.app, "vault_lease_cache", None),
                team_rows=team_rows(self.app),
                rows=fleet_rows(self.app),
            )
        except VaultCredentialError as exc:
            self.app.notify(str(exc), severity="error", markup=False)
            return
        try:
            ssh_cmd = self.app.ssh_service.build_ssh_command(
                host=conn["host"],
                username=conn["username"],
                key_path=conn.get("key_path"),
                proxy_args=conn.get("proxy_args") or [],
                port=conn.get("port"),
                extra_options=conn.get("extra_options") or [],
                **{key: value for key, value in ssh_identity_kwargs(conn).items() if value},
            )

            if self.app.terminal_service.launch_ssh_in_terminal(ssh_cmd):
                name = display.get('name') or display.get('id', 'instance')
                via = f" via {profile.bastion_host}" if profile and profile.bastion_host else ""
                if conn.get("key_team"):
                    # No key of the user's own here: a team's key for the same server.
                    via = f" with team {conn['key_team']}'s key"
                self.app.notify(f"SSH session launched for {name}{via}", markup=False)
                self._maybe_show_memory_prompt(display)
                try:
                    self._maybe_pull_annotations(instance)
                except Exception:
                    pass
            else:
                self.app.notify("No terminal emulator detected. Set 'terminal_emulator' in settings.", severity="error")
        except Exception as e:
            self.app.notify(f"SSH error: {e}", severity="error", markup=False)

    def _maybe_show_memory_prompt(self, instance: dict) -> None:
        """Mount the first-connect memory-build banner for *instance*.

        Gated on:
            * App has a memory_service wired.
            * Instance not seen yet in this session.
            * ``memory_first_connect_dismissed_count < MAX_DISMISSALS``.
            * Memory is not opted-out for this specific server.
            * The server has no memory yet, or its snapshot is older than
              ``MemoryConfig.first_connect_reprompt_seconds`` — a recently
              probed server is never re-prompted.
        """
        try:
            from servonaut.config.schema import (
                DEFAULT_FIRST_CONNECT_REPROMPT_SECONDS,
            )
            from servonaut.screens.fleet_memory import snapshot_age_seconds
            from servonaut.widgets.memory_prompt import (
                MemoryPrompt, memory_needs_reprompt,
                should_show_first_connect_prompt,
            )

            app = self.app
            memory_service = getattr(app, "memory_service", None)
            if memory_service is None:
                return

            iid = instance.get("id") or instance.get("name", "")
            iname = instance.get("name", "")
            if not iid:
                return

            seen = getattr(app, "memory_first_connect_seen", None)
            if seen is None:
                seen = set()
                app.memory_first_connect_seen = seen
            if iid in seen:
                return

            config = app.config_manager.get() if app.config_manager else None
            if not should_show_first_connect_prompt(config):
                return
            if memory_service.is_memory_disabled(iid, iname):
                return

            # Suppress the banner for servers whose memory was probed
            # recently — only re-prompt when memory is missing entirely or
            # the snapshot has aged past the re-prompt threshold.
            provider = instance_provider(instance)
            try:
                modules = memory_service.get_all_modules(iid, provider)
            except Exception:  # noqa: BLE001 — never break SSH launch
                modules = {}
            reprompt_after = getattr(
                memory_service, "first_connect_reprompt_seconds", None
            )
            if not isinstance(reprompt_after, int) or isinstance(reprompt_after, bool):
                reprompt_after = DEFAULT_FIRST_CONNECT_REPROMPT_SECONDS
            age = snapshot_age_seconds(modules) if modules else None
            if not memory_needs_reprompt(age, reprompt_after):
                return

            seen.add(iid)

            # Mount the banner at the top of the instance list container —
            # after the search input but before the instance table.
            container = self.query_one("#instance_list_container")
            prompt = MemoryPrompt(instance)
            container.mount(prompt, after=self.query_one("#search_input"))
        except Exception as exc:  # noqa: BLE001 — UI helper must never break SSH launch
            import logging
            logging.getLogger(__name__).debug(
                "Could not show first-connect memory prompt: %s", exc
            )

    def _maybe_pull_annotations(self, instance: dict) -> None:
        """Kick off a best-effort annotation pull for *instance* on first connect.

        Runs once per instance per session (deduped via
        ``app.memory_annotations_pulled_seen``).  Requires Memory Sync to be
        configured; silently no-ops when it is not.  The actual pull runs in a
        Textual worker so it never blocks the UI.
        """
        app = self.app
        sync = getattr(app, "memory_sync_service", None)
        if sync is None or not getattr(sync, "is_configured", False):
            return

        iid = instance.get("id") or instance.get("name", "")
        if not iid:
            return

        pulled = getattr(app, "memory_annotations_pulled_seen", None)
        if pulled is None:
            pulled = set()
            app.memory_annotations_pulled_seen = pulled
        if iid in pulled:
            return
        pulled.add(iid)

        app.run_worker(
            self._pull_annotations_worker(instance),
            group="memory_annotations_pull",
            exclusive=False,
        )

    async def _pull_annotations_worker(self, instance: dict) -> None:
        """Worker coroutine that pulls memory (annotations + findings) for
        *instance* from the server on first connect. Best-effort; per-pull
        errors are swallowed so one unreachable instance can't break the flow."""
        app = self.app
        sync = getattr(app, "memory_sync_service", None)
        if sync is None:
            return
        iid = instance.get("id") or instance.get("name", "")
        name = instance.get("name", "")
        provider = instance_provider(instance)
        try:
            if await sync.pull_annotations(iid, name, provider) == "updated":
                app.notify(f"Annotations updated for {name}", markup=False)
        except Exception:
            pass
        try:
            if await sync.pull_findings(iid, name, provider) == "updated":
                app.notify(f"Findings updated for {name}", markup=False)
        except Exception:
            pass

    def action_browse_files(self) -> None:
        """Open file browser for selected instance."""
        instance = self._get_selected_running_instance()
        if not instance:
            return
        from servonaut.screens.file_browser import FileBrowserScreen
        self.app.push_screen(FileBrowserScreen(instance))

    def action_run_command(self) -> None:
        """Open command overlay for selected instance."""
        instance = self._get_selected_running_instance()
        if not instance:
            return
        from servonaut.screens.command_overlay import CommandOverlay
        self.app.push_screen(CommandOverlay(instance))

    def action_scp_transfer(self) -> None:
        """Open SCP transfer for selected instance."""
        instance = self._get_selected_running_instance()
        if not instance:
            return
        from servonaut.screens.scp_transfer import SCPTransferScreen
        self.app.push_screen(SCPTransferScreen(instance))

    def action_view_logs(self) -> None:
        """Open log viewer for selected instance."""
        instance = self._get_selected_running_instance()
        if not instance:
            return
        from servonaut.screens.log_viewer import LogViewerScreen
        self.app.push_screen(LogViewerScreen(instance))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if isinstance(event.button, FleetChip):
            event.stop()
            self._press_chip(event.button)
        elif btn_id == "fleet_refresh":
            event.stop()
            self.action_refresh()
        elif btn_id in ("fleet_copy_row", "fleet_copy_row_line"):
            event.stop()
            self.action_copy_row()
        elif btn_id == "fleet_btn_ssh":
            event.stop()
            self.action_ssh_connect()
        elif btn_id == "fleet_btn_browse":
            event.stop()
            self.action_browse_files()
        elif btn_id == "fleet_btn_scp":
            event.stop()
            self.action_scp_transfer()
        elif btn_id == "fleet_btn_command":
            event.stop()
            self.action_run_command()
        elif btn_id == "fleet_btn_logs":
            event.stop()
            self.action_view_logs()
        elif btn_id == "fleet_btn_memory":
            event.stop()
            self.action_open_memory()
        elif btn_id == "fleet_btn_ai":
            event.stop()
            self.action_ai_analysis()
        elif btn_id == "fleet_btn_actions":
            event.stop()
            self.action_select_instance()

    def action_copy_value(self) -> None:
        """Move onto the selected server's values to copy one of them."""
        if not self.query_one(InstanceTable).get_selected_instance():
            self.app.notify("No instance selected", severity="warning")
            return
        values = self.query_one(
            "#fleet_values" if self.query_one("#fleet_inspector").display
            else "#fleet_value_line",
        )
        values.begin_walk()

    def action_copy_row(self) -> None:
        """Copy full selected instance row data to clipboard."""
        from servonaut.utils.platform_utils import CopyOutcome, copy_text

        table = self.query_one(InstanceTable)
        instance = table.get_selected_instance()

        if not instance:
            self.app.notify("No instance selected", severity="warning")
            return

        # The same values, in the same order, as the inspector lists them.
        text = "  ".join(instance_values(instance).values())

        name = instance.get('name') or instance.get('id', '')
        outcome = copy_text(self.app, text)
        if outcome is CopyOutcome.COPIED:
            self.app.notify(f"Copied: {name}", markup=False)
        elif outcome is CopyOutcome.SENT_TO_TERMINAL:
            self.app.notify(f"Sent to the terminal clipboard: {name}", markup=False)
        else:
            self.app.notify("Clipboard not available", severity="warning")

    def action_ai_analysis(self) -> None:
        """Open AI analysis for selected instance."""
        instance = self._get_selected_running_instance()
        if not instance:
            return
        from servonaut.screens.ai_analysis import AIAnalysisScreen
        self.app.push_screen(AIAnalysisScreen(instance=instance))

    def action_open_memory(self) -> None:
        """Open the per-instance Memory screen for the selected row.

        Memory opens without the running-state gate the SSH-driven actions
        use: operators should still be able to view a server's cached facts
        when the instance is stopped, and the memory screen itself handles
        refresh-while-offline with a clear warning.
        """
        table = self.query_one(InstanceTable)
        instance = table.get_selected_instance()
        if not instance:
            self.app.notify("Select an instance first.", severity="warning")
            return
        from servonaut.screens.memory import MemoryScreen
        self.app.push_screen(MemoryScreen(instance))

    def action_fleet_db_scan(self) -> None:
        """Open the fleet DB-credential scan over all known instances (B3)."""
        instances = list(self.app.instances or [])
        if not instances:
            self.app.notify("No instances to scan.", severity="warning")
            return
        from servonaut.screens.db_fleet_scan import DbFleetScanScreen
        self.app.push_screen(DbFleetScanScreen(instances))
