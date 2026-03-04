"""Instance list screen for Servonaut v2.0."""

from __future__ import annotations
from typing import Optional, List

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Header, Footer, Input, Label, Static
from textual.worker import Worker

from servonaut.widgets.instance_table import InstanceTable
from servonaut.widgets.status_bar import StatusBar
from servonaut.widgets.progress_indicator import ProgressIndicator


class InstanceListScreen(Screen):
    """Screen displaying list of EC2 instances with search/filter."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("/", "focus_search", "Search", show=True),
        Binding("enter", "select_instance", "Select", show=True),
        Binding("s", "ssh_connect", "SSH", show=True),
        Binding("b", "browse_files", "Browse", show=True),
        Binding("c", "run_command", "Command", show=True),
        Binding("t", "scp_transfer", "Transfer", show=True),
        Binding("l", "view_logs", "Logs", show=True),
        Binding("a", "ai_analysis", "AI", show=True),
        Binding("y", "copy_ip", "Copy IP", show=True),
    ]

    def __init__(self) -> None:
        """Initialize instance list screen."""
        super().__init__()
        self._instances: List[dict] = []

    def compose(self) -> ComposeResult:
        """Compose the instance list UI."""
        yield Header()
        yield Container(
            Input(placeholder="Search instances and keywords...", id="search_input"),
            ProgressIndicator(),
            InstanceTable(),
            Label("[bold]Keyword Matches:[/bold]", id="keyword_matches_label"),
            VerticalScroll(id="keyword_matches_container"),
            StatusBar(),
            id="instance_list_container"
        )
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

        # If cache is fresh, we're done
        if self.app.cache_service.is_fresh():
            logger.info("Cache is fresh, skipping AWS fetch")
            return

        # Cache is stale or empty — fetch in background or foreground
        if self._instances:
            self._background_refresh()
        else:
            self._fetch_instances()

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
        """Refresh instances from AWS in the background.

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

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        """Handle worker state changes.

        Args:
            event: Worker state changed event.
        """
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
                    # Re-merge custom servers with fresh AWS instances
                    custom = self.app.custom_server_service.list_as_instances()
                    self._instances = new_instances + custom
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
        """Update instance table with current data."""
        table = self.query_one(InstanceTable)
        table.populate(self._instances)

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

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle search input changes.

        Args:
            event: Input changed event.
        """
        if event.input.id == "search_input":
            table = self.query_one(InstanceTable)
            table.filter(event.value)
            self._update_status_bar()

            query = event.value.strip()
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

    def action_back(self) -> None:
        """Navigate back to main menu."""
        self.app.pop_screen()

    def action_refresh(self) -> None:
        """Force-refresh instance list from AWS."""
        self._fetch_instances(force_refresh=True)

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

        if not instance.get('is_custom') and instance.get('state') != 'running':
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
            username = self.app.config_manager.get().default_username
            key_path = self.app.ssh_service.get_key_path(instance['id'])

            if not key_path and instance.get('key_name'):
                key_path = self.app.ssh_service.discover_key(instance['key_name'])

            ssh_cmd = self.app.ssh_service.build_ssh_command(
                host=host,
                username=username,
                key_path=key_path,
                proxy_args=proxy_args,
            )

            if self.app.terminal_service.launch_ssh_in_terminal(ssh_cmd):
                name = instance.get('name') or instance.get('id', 'instance')
                via = f" via {profile.bastion_host}" if profile and profile.bastion_host else ""
                self.app.notify(f"SSH session launched for {name}{via}")
            else:
                self.app.notify("No terminal emulator detected. Set 'terminal_emulator' in settings.", severity="error")
        except Exception as e:
            self.app.notify(f"SSH error: {e}", severity="error")

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

    def action_copy_ip(self) -> None:
        """Copy selected instance's IP address to clipboard.

        Copies public IP if available, otherwise falls back to private IP.
        """
        from servonaut.utils.platform_utils import copy_to_clipboard

        table = self.query_one(InstanceTable)
        instance = table.get_selected_instance()

        if not instance:
            self.app.notify("No instance selected", severity="warning")
            return

        ip = table.get_selected_field('public_ip') or table.get_selected_field('private_ip')
        if not ip:
            self.app.notify("No IP address available", severity="warning")
            return

        if copy_to_clipboard(ip):
            self.app.notify(f"Copied: {ip}")
        else:
            self.app.notify(
                f"Clipboard not available. IP: {ip}",
                severity="warning"
            )

    def action_ai_analysis(self) -> None:
        """Open AI analysis for selected instance."""
        instance = self._get_selected_running_instance()
        if not instance:
            return
        from servonaut.screens.ai_analysis import AIAnalysisScreen
        self.app.push_screen(AIAnalysisScreen(instance=instance))
