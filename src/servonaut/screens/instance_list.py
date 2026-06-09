"""Instance list screen for Servonaut v2.0."""

from __future__ import annotations
from typing import Optional, List

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, VerticalScroll, Horizontal
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import Header, Footer, Input, Label, Static, TextArea
from textual.worker import Worker

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.instance_table import InstanceTable
from servonaut.widgets.status_bar import StatusBar
from servonaut.widgets.progress_indicator import ProgressIndicator
from servonaut.widgets.sidebar import Sidebar

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from servonaut.app import ServonautApp

class InstanceListScreen(Screen):
    """Screen displaying list of EC2 instances with search/filter."""

    @property
    def app(self) -> "ServonautApp":
        return super().app # type: ignore

    BINDINGS = [
        Binding("r", "refresh", "Refresh", show=True),
        Binding("/", "focus_search", "Search", show=True),
        Binding("enter", "select_instance", "Actions", show=True),
        # Explicit footer-visible alternative — DataTable consumes Enter for
        # row-selected, which hides the Enter binding from the footer. ``o``
        # (for "Open") shows up in the footer so users can discover the
        # actions menu without needing to guess that Enter works.
        Binding("o", "select_instance", "Actions", show=True),
        Binding("s", "ssh_connect", "SSH", show=True),
        Binding("b", "browse_files", "Browse", show=True),
        Binding("c", "run_command", "Command", show=True),
        Binding("t", "scp_transfer", "Transfer", show=True),
        Binding("l", "view_logs", "Logs", show=True),
        Binding("a", "ai_analysis", "AI", show=True),
        Binding("m", "open_memory", "Memory", show=True),
        Binding("k", "manage_ssh_ref", "SSH Ref", show=True),
        Binding("v", "verify_ssh", "Verify", show=True),
        Binding("y", "copy_row", "Copy", show=True),
    ]

    # Debounce delay for search input (seconds)
    _SEARCH_DEBOUNCE = 0.15

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

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

    def compose(self) -> ComposeResult:
        """Compose the instance list UI."""
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with Vertical(id="instance_list_container"):
                yield Input(placeholder="Search instances and keywords...", id="search_input")
                # Memory discoverability banner — only visible when no
                # instance has memory yet, so it stops nagging once the user
                # has engaged with the feature.
                yield Static(
                    "[bold]🧠 New:[/bold] Build a fact cache for every server "
                    "so the [b]chat panel[/b] and [b]MCP clients[/b] can "
                    "answer OS / runtime / service questions without an SSH "
                    "round-trip. [dim]Open [b]Fleet Memory[/b] in the "
                    "sidebar or press [b]m[/b] on a row to start.[/dim]",
                    id="memory_discover_banner",
                    classes="hidden",
                )
                yield ProgressIndicator()
                yield InstanceTable()
                yield TextArea("", id="instance_detail", read_only=True, soft_wrap=True)
                yield Label("[bold]Keyword Matches:[/bold]", id="keyword_matches_label")
                yield VerticalScroll(id="keyword_matches_container")
            yield StatusBar()
        yield Footer()

    def on_mount(self) -> None:
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
            stale_data = self.app.cache_service.load_any()
            if stale_data:
                self._instances = stale_data
                self.app.instances = stale_data
                self._update_table()
                self._update_status_bar()
                logger.info("Loaded %d instances from cache file (age: %s)",
                            len(stale_data), self.app.cache_service.get_age())

        # If cache is fresh, we're done (but still fetch OVH if no OVH cache)
        if self.app.cache_service.is_fresh():
            logger.info("Cache is fresh, skipping AWS fetch")
            if self.app.ovh_service is not None and not self.app.ovh_service.is_cache_fresh():
                self._fetch_ovh_instances()
            return

        # Cache is stale or empty — fetch in background or foreground
        if self._instances:
            self._background_refresh()
        else:
            self._fetch_instances()
            self._fetch_ovh_instances()
            self._fetch_hetzner_instances()

        # Default focus = search Input. The "find a server fast" journey
        # is the primary entry point: type a name fragment, then Tab/↓
        # into the filtered results and press a shortcut. The footer still
        # advertises every binding (check_action_passthrough returns None,
        # not False, when an Input is focused — bindings render greyed-out
        # rather than disappearing) so discoverability stays intact.

    def _fetch_instances(self, force_refresh: bool = False) -> None:
        """Fetch instances from AWS via worker (blocking with progress indicator).

        Args:
            force_refresh: If True, bypass cache.
        """
        progress = self.query_one(ProgressIndicator)
        progress.start("Loading instances...")

        self.run_worker(
            self.app.aws_service.fetch_instances_cached(force_refresh=force_refresh),
            name="fetch_instances",
            exclusive=True
        )

    def _background_refresh(self) -> None:
        """Refresh instances from AWS (and OVH if enabled) in the background.

        Shows a subtle notification instead of a blocking progress bar.
        """
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Starting background refresh of instances")
        self.app.notify("Refreshing instances in background...", severity="information")

        self.run_worker(
            self.app.aws_service.fetch_instances_cached(force_refresh=True),
            name="background_refresh",
            exclusive=True
        )
        # Also refresh OVH + Hetzner instances if those providers are enabled
        self._fetch_ovh_instances()
        self._fetch_hetzner_instances()

    def _fetch_ovh_instances(self) -> None:
        """Refresh OVH instances in background via worker."""
        if self.app.ovh_service is None:
            return
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Starting OVH instance refresh")
        self.run_worker(
            self.app.ovh_service.fetch_instances_cached(force_refresh=True),
            name="ovh_refresh",
            exclusive=False,
        )

    def _fetch_hetzner_instances(self) -> None:
        """Refresh Hetzner Cloud instances in background via worker.

        Symmetric with :meth:`_fetch_ovh_instances`. Wired off the same
        ``_background_refresh`` trigger and the foreground fetch path so
        Hetzner servers appear at app startup and survive AWS refreshes.
        """
        if self.app.hetzner_service is None:
            return
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Starting Hetzner instance refresh")
        self.run_worker(
            self.app.hetzner_service.fetch_instances_cached(force_refresh=True),
            name="hetzner_refresh",
            exclusive=False,
        )

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        """Handle worker state changes.

        Args:
            event: Worker state changed event.
        """
        if event.worker.name == "ovh_refresh" and event.worker.is_finished:
            if event.worker.error:
                self.app.notify(
                    f"OVH refresh error: {event.worker.error}",
                    severity="error",
                )
            else:
                new_ovh = event.worker.result or []
                # Redact the fresh OVH data before merging — only new_ovh is
                # raw here; non_ovh was already redacted on its own refresh.
                if self.app.demo_mode and self.app.redaction_service:
                    self.app.redaction_service.redact_instances(new_ovh)
                # Rebuild instance list: AWS+custom + fresh OVH data
                non_ovh = [i for i in self._instances if not i.get('is_ovh')]
                self._instances = non_ovh + new_ovh
                self.app.instances = self._instances
                self._update_table()
                self._update_status_bar()
                if new_ovh:
                    self.app.notify(
                        f"OVH refreshed: {len(new_ovh)} instances",
                        severity="information",
                    )
            return

        if event.worker.name == "hetzner_refresh" and event.worker.is_finished:
            if event.worker.error:
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
                # Redact the fresh Hetzner data before merging — only
                # new_hetzner is raw; non_hetzner was already redacted.
                if self.app.demo_mode and self.app.redaction_service:
                    self.app.redaction_service.redact_instances(new_hetzner)
                non_hetzner = [
                    i for i in self._instances if not i.get('is_hetzner')
                ]
                self._instances = non_hetzner + new_hetzner
                self.app.instances = self._instances
                self._update_table()
                self._update_status_bar()
                if new_hetzner:
                    self.app.notify(
                        f"Hetzner refreshed: {len(new_hetzner)} instances",
                        severity="information",
                        markup=False,
                    )
            return

        if event.worker.name in ("fetch_instances", "background_refresh"):
            if event.worker.is_finished:
                is_background = event.worker.name == "background_refresh"

                # Stop progress indicator for foreground fetches
                if not is_background:
                    progress = self.query_one(ProgressIndicator)
                    progress.stop()

                if event.worker.error:
                    self._handle_fetch_error(event.worker.error, is_background)
                else:
                    new_instances = event.worker.result or []
                    old_count = len(self._instances)
                    # Re-merge custom servers, OVH and Hetzner instances
                    # with the fresh AWS instances.
                    custom = self.app.custom_server_service.list_as_instances()
                    ovh_instances = (
                        self.app.ovh_service.get_cached_instances()
                        if self.app.ovh_service is not None
                        else []
                    )
                    hetzner_instances = (
                        self.app.hetzner_service.get_cached_instances()
                        if self.app.hetzner_service is not None
                        else []
                    )
                    self._instances = (
                        new_instances + custom + ovh_instances + hetzner_instances
                    )
                    # Re-snapshot pristine list BEFORE redaction to keep the
                    # toggle path stale-free on each refresh.
                    import copy
                    self.app._instances_pristine = copy.deepcopy(self._instances)
                    # Apply demo-mode redaction to fresh data
                    if self.app.demo_mode and self.app.redaction_service:
                        self.app.redaction_service.redact_instances(self._instances)
                    self.app.instances = self._instances
                    self._update_table()
                    self._update_status_bar()

                    if not new_instances:
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
                severity="error"
            )

        # Only clear data if foreground fetch with no existing data
        if not is_background and not self._instances:
            self._update_table()
            self._update_status_bar()

    def _update_table(self) -> None:
        """Update instance table with current data, preserving active filter."""
        table = self.query_one(InstanceTable)
        table.populate(self._instances)
        # Re-apply the current search filter so a background refresh
        # doesn't wipe the user's active query.
        current_query = self.query_one("#search_input", Input).value
        if current_query:
            table.filter(current_query)
        self._sync_memory_banner()

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
        """Update status bar with current counts and cache age."""
        status_bar = self.query_one(StatusBar)
        table = self.query_one(InstanceTable)

        # Update counts
        total = len(self._instances)
        filtered = len(table._filtered_instances)
        status_bar.update_instance_count(total, filtered)

        # Update cache age
        cache_age = self.app.cache_service.get_age()
        status_bar.update_cache_age(cache_age)

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
        self.action_select_instance()

    def _update_detail_panel(self) -> None:
        """Show selected instance metadata in the detail panel."""
        table = self.query_one(InstanceTable)
        instance = table.get_selected_instance()
        detail = self.query_one("#instance_detail", TextArea)

        if not instance:
            detail.load_text("")
            return

        parts = []
        for key, label in [
            ("name", "Name"),
            ("id", "ID"),
            ("type", "Type"),
            ("state", "State"),
            ("public_ip", "Public IP"),
            ("private_ip", "Private IP"),
            ("region", "Region"),
            ("provider", "Provider"),
            ("group", "Group"),
            ("key_name", "Key"),
            ("username", "Username"),
            ("port", "Port"),
        ]:
            val = instance.get(key)
            if val:
                parts.append(f"{label}: {val}")

        detail.load_text("  |  ".join(parts))

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
        table.filter(value)
        self._update_status_bar()

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
            self.app.notify(f"Error searching keywords: {e}", severity="error")
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

        for match in matches[:20]:
            server_id = match.get('server_id', '')
            source = match.get('source', '')
            content = match.get('content', '')

            if len(content) > 200:
                content = content[:200] + "..."

            result_text = (
                f"[bold]Server: {server_id}[/bold]\n"
                f"  Source: {source}\n"
                f"  [dim]{content}[/dim]\n"
            )
            container.mount(Static(result_text))

    def _clear_keyword_results(self) -> None:
        """Hide and clear keyword results panel."""
        self.query_one("#keyword_matches_label").display = False
        container = self.query_one("#keyword_matches_container", VerticalScroll)
        container.display = False
        container.remove_children()


    def action_refresh(self) -> None:
        """Force-refresh instance list from AWS and OVH."""
        self._fetch_instances(force_refresh=True)
        if self.app.ovh_service is not None:
            self._fetch_ovh_instances()

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
        instance_id = instance.get("id")
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

        Custom servers skip the state check since they don't have AWS state.

        Returns:
            Instance dict if valid, None otherwise.
        """
        table = self.query_one(InstanceTable)
        instance = table.get_selected_instance()

        if not instance:
            self.app.notify("No instance selected", severity="warning")
            return None

        if (not instance.get('is_custom') and not instance.get('is_ovh')
                and not instance.get('is_hetzner')
                and instance.get('state') != 'running'):
            self.app.notify(
                f"Instance is {instance.get('state')}. Only running instances can connect.",
                severity="warning"
            )
            return None

        return instance

    def action_ssh_connect(self) -> None:
        """Quick SSH connect to selected instance."""
        instance = self._get_selected_running_instance()
        if not instance:
            return

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
            if instance.get('is_custom'):
                username = instance.get('username') or 'root'
                port = instance.get('port') or 22
                key_path = instance.get('ssh_key') or instance.get('key_name') or None
            elif instance.get('is_ovh'):
                from servonaut.services.ovh_service import OVHService
                provider_type = instance.get('provider_type', '')
                username = (
                    (profile.username if profile else None)
                    or OVHService.default_username(provider_type)
                )
                port = None
                key_path = self.app.config_manager.get().default_key or None
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

            ssh_cmd = self.app.ssh_service.build_ssh_command(
                host=host,
                username=username,
                key_path=key_path,
                proxy_args=proxy_args,
                port=port,
                extra_options=extra_options,
            )

            if self.app.terminal_service.launch_ssh_in_terminal(ssh_cmd):
                name = instance.get('name') or instance.get('id', 'instance')
                via = f" via {profile.bastion_host}" if profile and profile.bastion_host else ""
                self.app.notify(f"SSH session launched for {name}{via}")
                self._maybe_show_memory_prompt(instance)
                try:
                    self._maybe_pull_annotations(instance)
                except Exception:
                    pass
            else:
                self.app.notify("No terminal emulator detected. Set 'terminal_emulator' in settings.", severity="error")
        except Exception as e:
            self.app.notify(f"SSH error: {e}", severity="error")

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
            provider = instance.get("provider", "custom")
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
        """Worker coroutine that pulls annotations for *instance* from the server."""
        app = self.app
        sync = getattr(app, "memory_sync_service", None)
        if sync is None:
            return
        iid = instance.get("id") or instance.get("name", "")
        name = instance.get("name", "")
        provider = instance.get("provider", "custom")
        try:
            result = await sync.pull_annotations(iid, name, provider)
        except Exception:
            return
        if result == "updated":
            app.notify(f"Annotations updated for {name}", markup=False)

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

    def action_copy_row(self) -> None:
        """Copy full selected instance row data to clipboard."""
        from servonaut.utils.platform_utils import copy_to_clipboard

        table = self.query_one(InstanceTable)
        instance = table.get_selected_instance()

        if not instance:
            self.app.notify("No instance selected", severity="warning")
            return

        fields = [
            ("Name", instance.get('name', '')),
            ("ID", instance.get('id', '')),
            ("Type", instance.get('type', '')),
            ("State", instance.get('state', '')),
            ("Public IP", instance.get('public_ip', '')),
            ("Private IP", instance.get('private_ip', '')),
            ("Region", instance.get('region', '')),
            ("Provider", instance.get('provider', '')),
            ("Key", instance.get('key_name', '')),
        ]
        text = "  ".join(f"{v}" for _, v in fields if v)

        if copy_to_clipboard(text):
            name = instance.get('name') or instance.get('id', '')
            self.app.notify(f"Copied: {name}")
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
