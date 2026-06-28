"""Main Textual application for Servonaut v2.0."""

from __future__ import annotations
import logging
from typing import TYPE_CHECKING, Optional, List

from textual.app import App
from textual.reactive import reactive

from servonaut.styles import CSS_FILES

logger = logging.getLogger(__name__)
from textual.binding import Binding

from servonaut.utils.instance_resolver import resolve_instance_from_lists

# Maps sidebar nav ids for provider S3 screens to their provider strings.
# Used by on_sidebar_navigation_requested to resolve the ObjectStorageScreen
# provider and the corresponding service attribute in one lookup.
_S3_NAV_TO_PROVIDER: dict[str, str] = {
    "nav_aws_s3": "aws",
    "nav_ovh_s3": "ovh",
    "nav_hetzner_s3": "hetzner",
}

if TYPE_CHECKING:
    from servonaut.widgets.sidebar import Sidebar
    from servonaut.services.relay_manager import RelayManager, RelayState


class ServonautApp(App):
    """Servonaut TUI application."""

    CSS_PATH = CSS_FILES
    TITLE = "Servonaut"
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("question_mark", "show_help", "Help", show=True),
        Binding("f2", "toggle_chat", "Chat", show=True),
        # Fallback for terminals/multiplexers that swallow F-keys.
        Binding("ctrl+g", "toggle_chat", "Chat", show=False),
        Binding("ctrl+shift+d", "toggle_demo", "Demo mode", show=False),
        # Fallback: many terminals (xterm.js/ttyd, some multiplexers) cannot
        # deliver ctrl+shift chords, and browsers reserve Ctrl+Shift+D.
        Binding("ctrl+e", "toggle_demo", "Demo mode", show=False),
    ]

    # Service instances - created in on_mount
    config_manager = None
    aws_service = None
    cache_service = None
    ssh_service = None
    connection_service = None
    scan_service = None
    keyword_store = None
    terminal_service = None
    scp_service = None
    command_history = None
    custom_server_service = None
    log_viewer_service = None
    cloudtrail_service = None
    cloudwatch_service = None
    ip_ban_service = None
    memory_service = None
    ai_analysis_service = None
    chat_service = None
    update_service = None
    bug_report_service = None
    redaction_service = None
    ovh_service = None
    hetzner_service = None
    ovh_billing_service = None
    ovh_vps_service = None
    ovh_dedicated_service = None
    ovh_cloud_service = None
    ovh_monitoring_service = None
    ovh_ip_service = None
    ovh_snapshot_service = None
    ovh_storage_service = None
    ovh_dns_service = None
    ovh_audit = None
    auth_service = None
    api_client = None
    ai_conversations_client = None  # Wave 1 CRUD client, wired in init_paid_services
    entitlement_guard = None
    config_sync_service = None
    team_service = None
    remote_audit_service = None
    gcp_service = None
    azure_service = None
    servonaut_tools = None  # shared MCP-layer implementation (chat + MCP server)
    bw_ssh_config_service = None
    aws_object_storage_service = None
    hetzner_object_storage_service = None
    ovh_object_storage_service = None
    aws_audit = None

    # Memory cloud-sync layer (Stream 2 + 3 services)
    memory_rate_limiter = None
    memory_sync_service = None
    memory_retrieval_service = None
    memory_settings_service = None
    fleet_service = None
    fleet_scan_service = None
    drift_service = None
    anomaly_service = None
    ai_summary_service = None
    export_service = None
    team_memory_service = None
    memory_crypto = None
    _memory_key_material = None

    # Shared state
    instances: List[dict] = []  # all fetched instances
    demo_mode: bool = False
    _instances_pristine: Optional[List[dict]] = None  # deepcopy before redaction

    # T11: instance IDs that have already triggered the first-connect memory
    # prompt in this session.  Reset every time the app restarts.
    memory_first_connect_seen: set = set()

    # Instance IDs for which an annotation pull has already been kicked off
    # this session.  Kept separate from memory_first_connect_seen so that
    # banner-dismissal gating is untouched.
    memory_annotations_pulled_seen: set = set()

    # Latest version found by the background update check (None = not checked yet)
    _latest_version: Optional[str] = None

    # Timestamp of the last successful auto-scan cycle (epoch seconds).
    # Zero means no cycle has completed yet this session.
    _fleet_auto_scan_last_run: float = 0.0

    # True while the app-owned manual fleet scan worker is running.
    # Set before run_worker returns, cleared in the finally block of
    # _do_fleet_manual_scan.  Guards against double-spawning.
    _fleet_manual_scan_in_progress: bool = False

    # Relay connection status, reactive so widgets can bind and re-render on change.
    # Carries the RelayState enum value (starts as None until the manager inits).
    relay_state = reactive(None)
    relay_manager: Optional["RelayManager"] = None

    def __init__(self, initial_screen=None, **kwargs) -> None:
        """Initialize the application.

        Args:
            initial_screen: Optional extra Screen instance to push on top of the
                instance list after startup (e.g., OVHSetupScreen).
            **kwargs: Passed through to Textual App.__init__.
        """
        super().__init__(**kwargs)
        self._initial_screen = initial_screen

    def notify(
        self,
        message: str,
        *,
        title: str = "",
        severity: str = "information",
        timeout: Optional[float] = None,
        markup: bool = True,
    ) -> None:
        """Override to scrub PII from notification messages in demo mode.

        This is a single defensive choke point that closes all 50+ call sites
        (exception messages, SSH errors, tool results, auth failures, etc.)
        without having to guard each one individually.

        Scrubbing order: message first, then title (if non-empty). Both are
        scrubbed before being passed to the Textual App.notify() base method.
        """
        if self.demo_mode and self.redaction_service is not None:
            message = self.redaction_service.scrub_stream(message)
            if title:
                title = self.redaction_service.scrub_stream(title)
        # Textual's App.notify signature uses Optional[float] for timeout;
        # pass only when non-None to avoid overriding the default.
        if timeout is not None:
            super().notify(message, title=title, severity=severity, timeout=timeout, markup=markup)
        else:
            super().notify(message, title=title, severity=severity, markup=markup)

    def pop_screen(self):
        """Pop screen, but navigate to instances if at the root."""
        if len(self.screen_stack) <= 2:
            from servonaut.screens.instance_list import InstanceListScreen
            if not isinstance(self.screen, InstanceListScreen):
                return self.switch_screen(InstanceListScreen())
            return
        return super().pop_screen()

    def on_mount(self) -> None:
        """Initialize services and push main menu."""
        from servonaut.screens.instance_list import InstanceListScreen

        self._init_services()
        # Eagerly load cached instances so all screens have data
        cached = self.cache_service.load_any()
        if cached:
            self.instances = cached
        # Merge custom servers into instance list
        self.instances.extend(self.custom_server_service.list_as_instances())
        # Merge OVH cached instances (stale-while-revalidate — loaded from disk)
        if self.ovh_service is not None:
            self.instances.extend(self.ovh_service.get_cached_instances())
        # Merge Hetzner Cloud cached instances (same stale-while-revalidate
        # contract as OVH — provider-agnostic instant render at startup).
        if self.hetzner_service is not None:
            self.instances.extend(self.hetzner_service.get_cached_instances())
        # Snapshot pristine instance list BEFORE any redaction — always, so
        # the toggle path can restore real data even when --demo was set at
        # launch.  deepcopy prevents in-place mutations from affecting the
        # snapshot later.
        import copy
        self._instances_pristine = copy.deepcopy(self.instances)
        # Apply demo-mode redaction
        if self.demo_mode:
            from servonaut.services.redaction_service import RedactionService
            self.redaction_service = RedactionService()
            self.redaction_service.redact_instances(self.instances)
        self.push_screen(InstanceListScreen())
        # Push optional initial screen (e.g., OVH setup wizard launched via --setup-ovh)
        if self._initial_screen is not None:
            self.push_screen(self._initial_screen)
        # Check for updates in background. Own group is REQUIRED: other
        # on_mount workers (relay_autostart) run exclusive=True in the
        # default group and would otherwise cancel this in-flight network
        # call before it resolves, so the update button never appears.
        self.run_worker(
            self._check_for_update(),
            name="version_check",
            group="version_check",
            exclusive=True,
        )
        # Decorate instances with SSH verify sidecar data (no-op if not logged in)
        self.run_worker(
            self._refresh_ssh_verify_status(),
            name="ssh_verify_sidecar",
            group="memory_io",
            exclusive=False,
        )
        # Auto-start the in-process relay listener if the user is already
        # authenticated and their plan allows it. For users who log in later
        # via LoginScreen, that screen triggers the same hook.
        self._init_relay_manager()
        if (self.auth_service is not None
                and self.auth_service.is_authenticated
                and self.relay_manager is not None):
            self.run_worker(
                self._start_relay_with_toast(),
                name="relay_autostart",
                exclusive=True,
            )
        # Reactivate Memory Sync if the user enrolled on a previous session.
        # Gated entirely on local state (no eager network calls) so it is
        # safe and fast for users who have never set up Memory Sync.
        sync = getattr(self, "memory_sync_service", None)
        _auth = getattr(self, "auth_service", None)
        if (
            sync is not None
            and _auth is not None
            and _auth.is_authenticated
            and _auth.has_feature("memory_sync")
            and sync.is_enrolled_locally()
        ):
            self.run_worker(
                self._reactivate_memory_sync(),
                name="memory_sync_autostart",
                group="memory_reactivate",
                exclusive=True,
            )
        # Start background fleet auto-scan loop (sleeps first, so safe to
        # call here even before the instance list is fully populated).
        self._start_fleet_auto_scan_loop()

    def _init_services(self) -> None:
        """Create all service instances."""
        from servonaut.config.manager import ConfigManager
        from servonaut.services.cache_service import CacheService
        from servonaut.services.aws_service import AWSService
        from servonaut.services.ssh_service import SSHService
        from servonaut.services.connection_service import ConnectionService
        from servonaut.services.scan_service import ScanService
        from servonaut.services.keyword_store import KeywordStore
        from servonaut.services.terminal_service import TerminalService
        from servonaut.services.scp_service import SCPService
        from servonaut.services.command_history import CommandHistoryService
        from servonaut.services.custom_server_service import CustomServerService
        from servonaut.services.log_viewer_service import LogViewerService
        from servonaut.services.cloudtrail_service import CloudTrailService
        from servonaut.services.cloudwatch_service import CloudWatchService
        from servonaut.services.ip_ban_service import IPBanService
        from servonaut.services.ai_analysis_service import AIAnalysisService
        from servonaut.services.chat_service import ChatService
        from servonaut.services.chat_tools import ChatToolExecutor

        from servonaut.services.update_service import UpdateService
        self.update_service = UpdateService()
        self.config_manager = ConfigManager()
        config = self.config_manager.get()
        if self.config_manager.load_error:
            self.notify(self.config_manager.load_error, severity="error", timeout=15)
        self.cache_service = CacheService(ttl_seconds=config.cache_ttl_seconds)
        self.aws_service = AWSService(self.cache_service)
        # AWS audit logger and S3 object storage — always constructed;
        # boto3 default credential chain is used when keys are empty.
        from servonaut.services.aws_audit import AWSAuditLogger
        from servonaut.services.object_storage_factory import build_object_storage_services
        self.aws_audit = AWSAuditLogger(config.aws.audit_path)
        # Shared boto3 client factory — control-plane STS role / region pinning.
        # Backs aws_call + CloudWatch reads; defaults to the ambient credential
        # chain when no control-plane role is configured (no behaviour change).
        from servonaut.services.aws_client_factory import build_aws_client_factory
        self.aws_client_factory = build_aws_client_factory(config)
        # Delegate object-storage construction to the shared factory so that
        # the headless MCP server (mcp/server.py) reuses the same logic.
        (
            self.aws_object_storage_service,
            self.hetzner_object_storage_service,
            self.ovh_object_storage_service,
        ) = build_object_storage_services(config)
        self.ssh_service = SSHService(self.config_manager)
        self.connection_service = ConnectionService(self.config_manager)
        self.scan_service = ScanService(self.config_manager)
        self.keyword_store = KeywordStore(config.keyword_store_path)
        self.terminal_service = TerminalService(preferred=config.terminal_emulator)
        self.scp_service = SCPService(
            ssh_config=config.ssh,
            transfer_timeout_seconds=config.mcp.transfer_timeout_seconds,
        )
        self.command_history = CommandHistoryService(config.command_history_path)
        self.custom_server_service = CustomServerService(self.config_manager)
        self.log_viewer_service = LogViewerService(self.config_manager)
        self.cloudtrail_service = CloudTrailService(self.config_manager)
        self.cloudwatch_service = CloudWatchService(
            client_factory=self.aws_client_factory
        )
        self.ip_ban_service = IPBanService(self.config_manager)
        from servonaut.services.memory import MemoryService
        from servonaut.services.memory.store import MemoryStore
        from servonaut.services.memory.redaction import default_redactor, noop_redactor
        from servonaut.services.memory.modules import build_default_probers
        _memory_redactor = (
            default_redactor if config.memory.redaction_enabled else noop_redactor
        )
        self.memory_service = MemoryService(
            store=MemoryStore(redactor=_memory_redactor),
            config=config.memory,
            probers=build_default_probers(
                log_viewer_service=self.log_viewer_service,
                ssh_service=self.ssh_service,
                connection_service=self.connection_service,
            ),
            ssh_service=self.ssh_service,
            connection_service=self.connection_service,
        )
        # Memory and log-viewer services are mutually dependent: LogsProber
        # uses LogViewerService, and LogViewerService consults memory.logs
        # for cached readable paths. Wire the back-reference here.
        self.log_viewer_service.set_memory_service(self.memory_service)
        self.ai_analysis_service = AIAnalysisService(self.config_manager)
        # OVH — optional, requires python-ovh and enabled config
        try:
            ovh_config = config.ovh
            if ovh_config.enabled and (ovh_config.application_key or ovh_config.client_id):
                from servonaut.services.ovh_service import OVHService
                from servonaut.services.ovh_billing_service import OVHBillingService
                self.ovh_service = OVHService(ovh_config)
                self.ovh_billing_service = OVHBillingService(self.ovh_service)
                logger.info("OVH service initialized")
        except ImportError:
            logger.warning("python-ovh not installed; OVH provider unavailable. Install with: pip install 'servonaut[ovh]'")
        except Exception as e:
            logger.error("Failed to initialize OVH service: %s", e)

        # Initialize OVH sub-services if OVH is enabled
        if self.ovh_service is not None:
            from servonaut.services.ovh_vps_service import OVHVPSService
            from servonaut.services.ovh_dedicated_service import OVHDedicatedService
            from servonaut.services.ovh_cloud_service import OVHCloudService
            from servonaut.services.ovh_monitoring_service import OVHMonitoringService
            from servonaut.services.ovh_ip_service import OVHIPService
            from servonaut.services.ovh_snapshot_service import OVHSnapshotService
            from servonaut.services.ovh_storage_service import OVHStorageService
            from servonaut.services.ovh_dns_service import OVHDNSService
            from servonaut.services.ovh_audit import OVHAuditLogger

            self.ovh_vps_service = OVHVPSService(self.ovh_service)
            self.ovh_dedicated_service = OVHDedicatedService(self.ovh_service)
            self.ovh_cloud_service = OVHCloudService(self.ovh_service)
            self.ovh_monitoring_service = OVHMonitoringService(self.ovh_service)
            self.ovh_ip_service = OVHIPService(self.ovh_service)
            self.ovh_snapshot_service = OVHSnapshotService(self.ovh_service)
            self.ovh_storage_service = OVHStorageService(self.ovh_service)
            self.ovh_dns_service = OVHDNSService(self.ovh_service)
            self.ovh_audit = OVHAuditLogger(config.ovh.ovh_audit_path)

        # Hetzner Cloud — optional, requires hcloud SDK and a resolvable
        # API token. Always-attempt init when ``enabled=True`` AND a
        # token can be located via the resolution chain (config →
        # $HCLOUD_TOKEN → ~/.config/hcloud/token); otherwise leave the
        # service None so the rest of the app stays Hetzner-blind.
        try:
            hetzner_config = config.hetzner if hasattr(config, 'hetzner') else None
            if hetzner_config and hetzner_config.enabled:
                from servonaut.services.hetzner_service import (
                    HetznerService, HetznerNotConfiguredError, HetznerSDKMissingError,
                )
                provisional = HetznerService(hetzner_config)
                # Force token resolution up front so we don't initialise a
                # provider that will only fail on first user action.
                try:
                    provisional.resolve_token()
                except HetznerNotConfiguredError as exc:
                    logger.info(
                        "Hetzner enabled but no token resolved: %s", exc,
                    )
                    raise
                self.hetzner_service = provisional
                logger.info("Hetzner service initialized")
        except ImportError:
            logger.warning(
                "hcloud SDK not installed; Hetzner provider unavailable. "
                "Install with: pip install 'servonaut[hetzner]'"
            )
        except HetznerNotConfiguredError:
            # Already logged above; swallow so the TUI launches normally.
            pass
        except HetznerSDKMissingError as exc:
            logger.warning("Hetzner SDK missing: %s", exc)
        except Exception as exc:
            logger.error("Failed to initialise Hetzner service: %s", exc)

        # Initialize GCP/Azure if configured
        try:
            gcp_config = config.gcp if hasattr(config, 'gcp') else None
            if gcp_config and gcp_config.enabled:
                from servonaut.services.gcp_service import GCPService
                self.gcp_service = GCPService(self.cache_service, gcp_config)
        except Exception as e:
            logger.debug("GCP service init skipped: %s", e)

        try:
            azure_config = config.azure if hasattr(config, 'azure') else None
            if azure_config and azure_config.enabled:
                from servonaut.services.azure_service import AzureService
                self.azure_service = AzureService(self.cache_service, azure_config)
        except Exception as e:
            logger.debug("Azure service init skipped: %s", e)

        # Build a single ServonautTools instance that both the local MCP
        # server (if running) and the built-in chat adapter dispatch through.
        # This guarantees the chat sees OVH + custom servers the same way
        # MCP does — and prevents future tool-behaviour drift between the
        # two surfaces.
        from servonaut.mcp.audit import AuditTrail
        from servonaut.mcp.guards import CommandGuard
        from servonaut.mcp.tools import ServonautTools
        self.servonaut_tools = ServonautTools(
            config_manager=self.config_manager,
            aws_service=self.aws_service,
            custom_server_service=self.custom_server_service,
            cache_service=self.cache_service,
            ssh_service=self.ssh_service,
            connection_service=self.connection_service,
            scp_service=self.scp_service,
            guard=CommandGuard(config.mcp, self.config_manager),
            audit=AuditTrail(config.mcp.audit_path),
            ovh_service=self.ovh_service,
            hetzner_service=self.hetzner_service,
            cloudtrail_service=self.cloudtrail_service,
            cloudwatch_service=self.cloudwatch_service,
            ip_ban_service=self.ip_ban_service,
            aws_client_factory=self.aws_client_factory,
            auth_service=self.auth_service,
            memory_service=self.memory_service,
            aws_object_storage_service=self.aws_object_storage_service,
            hetzner_object_storage_service=self.hetzner_object_storage_service,
            ovh_object_storage_service=self.ovh_object_storage_service,
        )
        tool_executor = ChatToolExecutor(
            tools=self.servonaut_tools,
            guard_level=config.chat_tool_guard_level,
        )
        self.chat_service = ChatService(
            self.config_manager, self.ai_analysis_service, tool_executor,
            memory_service=self.memory_service,
        )

        # Initialize paid-tier services (optional, require httpx)
        try:
            from servonaut.services.auth_service import AuthService
            self.auth_service = AuthService()
            if self.auth_service.is_authenticated:
                self.init_paid_services()
        except ImportError:
            logger.debug("httpx not installed; paid-tier services unavailable")
        except Exception as e:
            logger.debug("Paid-tier services init skipped: %s", e)

        # Bug-report service — works for anonymous users too. Backend channel
        # needs httpx; GitHub channel works regardless. Reuse the existing
        # api_client when init_paid_services already ran (signed-in user);
        # otherwise build a standalone unauthenticated APIClient.
        try:
            from servonaut.services.bug_report_service import BugReportService
            from servonaut.services.api_client import APIClient
            br_client = self.api_client if self.api_client is not None else APIClient(self.auth_service)
            self.bug_report_service = BugReportService(
                config_manager=self.config_manager,
                api_client=br_client,
                auth_service=self.auth_service,
                update_service=self.update_service,
            )
        except ImportError:
            logger.debug("httpx not installed; bug report service unavailable")
        except Exception as e:
            logger.debug("Bug report service init skipped: %s", e)

        # BwSshConfigService — gated on api_client availability (paid tier /
        # authenticated). Constructed here so it's ready immediately after
        # init_paid_services; the ssh_verify refresh worker is kicked off in
        # on_mount after the instance list is populated.
        if self.api_client is not None:
            try:
                from servonaut.services.bw_ssh_config_service import BwSshConfigService
                self.bw_ssh_config_service = BwSshConfigService(self.api_client)
            except Exception as e:
                logger.debug("BwSshConfigService init skipped: %s", e)

    def _init_relay_manager(self) -> None:
        """Create the RelayManager the first time; subsequent calls are no-ops."""
        if self.relay_manager is not None:
            return
        try:
            from servonaut.services.relay_manager import RelayManager
        except ImportError:
            logger.debug("Relay manager unavailable (httpx-sse not installed).")
            return
        self.relay_manager = RelayManager(
            config_manager=self.config_manager,
            auth_service=self.auth_service,
            on_state_change=self._on_relay_state_change,
            app=self,
        )
        # Auto-populate relay URLs on first run so newly-logged-in users
        # don't trip the NOT_CONFIGURED state. Best-effort: log-only on
        # failure, RelayManager.check_applicability() will surface a
        # readable error to the UI if the URLs are still empty.
        try:
            self.relay_manager.ensure_configured()
        except Exception:
            logger.exception("ensure_configured failed; relay may be unconfigured.")
        self._register_relay_signal_handler()

    def _register_relay_signal_handler(self) -> None:
        """SIGUSR1 hands relay control over to a ``servonaut connect --force-bg``.

        The bg CLI sends SIGUSR1, expects us to drop the listener and release
        the lock so it can acquire it. Best-effort: on platforms without
        SIGUSR1 or without a running event loop, we silently skip registration.
        """
        import signal
        if not hasattr(signal, "SIGUSR1"):
            return
        try:
            import asyncio
            loop = asyncio.get_event_loop()
        except RuntimeError:
            return

        def _on_sigusr1() -> None:
            if self.relay_manager is not None:
                self.notify(
                    "Releasing relay to background listener (SIGUSR1).",
                    severity="information",
                )
                loop.create_task(self.relay_manager.stop())

        try:
            loop.add_signal_handler(signal.SIGUSR1, _on_sigusr1)
        except (NotImplementedError, RuntimeError):
            # Windows + some embedded loops don't support signal handlers.
            pass

    def _on_relay_state_change(self, new_state) -> None:
        """Propagate RelayManager state to the reactive attribute + indicator widgets."""
        from servonaut.services.relay_manager import RelayState

        prior_state = self.relay_state
        self.relay_state = new_state
        # Push into any mounted RelayIndicator widgets so they re-render.
        try:
            from servonaut.widgets.relay_indicator import RelayIndicator
            for indicator in self.query(RelayIndicator):
                indicator.state = new_state
        except Exception:
            pass

        # First-time entry into SESSION_EXPIRED — surface a clear toast
        # telling the user how to recover. Without this the only signal
        # is the (small) sidebar indicator label change, which is easy
        # to miss in the middle of a chat.
        if (
            new_state is RelayState.SESSION_EXPIRED
            and prior_state is not RelayState.SESSION_EXPIRED
        ):
            try:
                self.notify(
                    "Servonaut session expired. Click the relay "
                    "indicator (sidebar) to sign in again.",
                    severity="warning",
                    timeout=12,
                    markup=False,
                )
            except Exception:
                logger.debug("Failed to surface session-expired toast", exc_info=True)

    def on_user_login_success(self) -> None:
        """Called by LoginScreen after a successful device-flow completion.

        Kicks off the in-process relay listener in a background worker so
        the login UI doesn't block. RelayManager.start() is idempotent while
        the listener is already running, so calling this more than once is
        safe.
        """
        self._init_relay_manager()
        if self.relay_manager is None:
            return
        self.run_worker(self._start_relay_with_toast(),
                        name="relay_login_start", exclusive=True)

    async def _start_relay_with_toast(self) -> None:
        """Background worker that starts the relay and surfaces the outcome."""
        from servonaut.services.relay_manager import RelayState
        result = await self.relay_manager.start()
        if result.state is RelayState.CONNECTING:
            self.notify("Connecting to Servonaut relay…",
                        severity="information", timeout=3)
        elif result.state is RelayState.EXTERNAL:
            self.notify(
                f"MCP relay: using external listener (PID {result.external_owner.pid}).",
                severity="information", timeout=4,
            )
        elif result.state is RelayState.NO_ENTITLEMENT:
            self.notify(
                "MCP relay disabled by your plan. Upgrade at "
                "https://servonaut.dev/pricing",
                severity="warning", timeout=6,
            )
        elif result.state is RelayState.NOT_CONFIGURED:
            self.notify(
                "MCP relay URLs not configured. See ~/.servonaut/config.json.",
                severity="warning", timeout=6,
            )
        elif result.state is RelayState.ERROR:
            self.notify(
                f"MCP relay failed to start: {result.message}",
                severity="error", timeout=6,
            )

    def on_user_logout(self) -> None:
        """Called by LoginScreen after logout — tear down all session state.

        Single source of truth for logout cleanup: relay listener, config-sync
        session, and Memory Sync key material. (Previously split across two
        same-named methods, the second of which silently shadowed the first.)
        """
        # Relay listener
        relay = getattr(self, "relay_manager", None)
        if relay is not None and hasattr(self, "run_worker"):
            self.run_worker(relay.stop(),
                            name="relay_logout_stop", exclusive=True)
        # Config-sync session
        if getattr(self, "config_sync_service", None) is not None:
            self.config_sync_service.clear_session()
        # Memory Sync logout cleanup (MAJOR-2): clear the local keypair cache,
        # OS keychain passphrase, and remember flag so a different account on
        # the same OS user cannot silently reuse the prior keypair next launch.
        sync = getattr(self, "memory_sync_service", None)
        if sync is not None:
            try:
                if hasattr(sync, "lock"):
                    sync.lock()
            except Exception:
                pass
            try:
                sync.clear_local_keypair_cache()
            except Exception:
                pass
        try:
            from servonaut.services.memory import passphrase_store as _ps
            _ps.clear_passphrase()
        except Exception:
            pass
        try:
            import dataclasses as _dc
            cfg = self.config_manager.get()
            updated_mem = _dc.replace(cfg.memory, sync_remember_device=False)
            self.config_manager.update(memory=updated_mem)
        except Exception:
            pass

    async def on_unmount(self) -> None:
        """Cancel the relay listener cleanly as the app exits."""
        if self.relay_manager is not None:
            try:
                await self.relay_manager.stop(grace_seconds=1.0)
            except Exception:  # pragma: no cover - defensive
                logger.exception("Error stopping relay manager on exit")

    def init_paid_services(self) -> None:
        """Initialize paid-tier services (API client, sync, teams, etc.).

        Safe to call multiple times — overwrites existing instances.
        Called at startup if already authenticated, or after login.
        """
        try:
            from servonaut.services.api_client import APIClient
            from servonaut.services.entitlement_guard import EntitlementGuard
            from servonaut.services.config_sync_service import ConfigSyncService
            from servonaut.services.team_service import TeamService
            from servonaut.services.remote_audit_service import RemoteAuditService
            self.api_client = APIClient(self.auth_service)
            from servonaut.services.ai_conversations import AIConversationsClient
            self.ai_conversations_client = AIConversationsClient(self.api_client)
            self.entitlement_guard = EntitlementGuard(self.auth_service)
            self.config_sync_service = ConfigSyncService(self.api_client, self.config_manager)
            self.team_service = TeamService(self.api_client)
            self.remote_audit_service = RemoteAuditService(self.api_client)
            # Step 6 — wire the active :class:`SecretProvider` into the
            # SSH service. Resolver consults auth + entitlement + cached
            # team SecretsConfig and returns None for Free / unauthed
            # sessions (SSHService falls back to legacy ~/.ssh discovery
            # in that case — zero behaviour change). Re-runs on each
            # ``init_paid_services`` call so post-login / plan-upgrade
            # transitions land the right provider without a restart.
            try:
                from servonaut.services.secret_provider_resolver import (
                    resolve_secret_provider,
                )
                provider = resolve_secret_provider(
                    self.auth_service, self.entitlement_guard,
                )
                self.ssh_service.set_secret_provider(provider)
                # Same provider feeds the DB introspection tools (db_processlist
                # / db_top_queries) so they resolve passwords from the user's
                # selected secret store.
                if getattr(self, "servonaut_tools", None) is not None:
                    self.servonaut_tools.set_secret_provider(provider)
                logger.info(
                    "SSHService secret_provider bound: %s",
                    provider.provider_name if provider is not None else "None (legacy ~/.ssh)",
                )
            except Exception as e:  # pragma: no cover - defensive
                # Refusing to break boot if the resolver hits an
                # unexpected state — the legacy ~/.ssh path is the
                # safe default. Log loudly so we hear about it.
                logger.exception(
                    "SecretProvider wiring failed; falling back to "
                    "legacy ~/.ssh discovery: %s", e,
                )
                self.ssh_service.set_secret_provider(None)
                if getattr(self, "servonaut_tools", None) is not None:
                    self.servonaut_tools.set_secret_provider(None)
            # Wire the hosted Servonaut AI provider now that api_client +
            # auth_service exist. The provider is keyless (OAuth bearer) and
            # gated on the ``premium_ai`` entitlement.
            if self.ai_analysis_service is not None:
                try:
                    self.ai_analysis_service.register_servonaut_provider(
                        self.api_client, self.auth_service,
                    )
                except Exception as e:  # pragma: no cover - defensive
                    logger.debug("Servonaut AI provider registration skipped: %s", e)
            # Expose the ServonautProvider directly for chat-panel streaming.
            try:
                from servonaut.services.ai_providers import ServonautProvider
                self.servonaut_provider = ServonautProvider(
                    api_client=self.api_client,
                    auth_service=self.auth_service,
                )
            except Exception as e:  # pragma: no cover
                logger.debug("ServonautProvider direct init skipped: %s", e)
                self.servonaut_provider = None
            # T4.5 — provider preference resolver. Pure (no I/O) — safe
            # to construct even when other paid-tier wiring fails.
            try:
                from servonaut.services.ai_provider_preference import (
                    ProviderPreferenceResolver,
                )
                self.provider_preference_resolver = ProviderPreferenceResolver(
                    self.auth_service, self.config_manager,
                )
            except Exception as e:  # pragma: no cover
                logger.debug("ProviderPreferenceResolver init skipped: %s", e)
                self.provider_preference_resolver = None
            # T6 — AI tool bridge. Confirms tool calls (single y/n /
            # typed-RUN), executes via the relay, posts results back.
            try:
                from servonaut.services.relay_executors import RelayExecutors
                from servonaut.mcp.audit import AuditTrail
                from servonaut.services.ai_tool_bridge import AIToolBridge
                relay = RelayExecutors(
                    self.config_manager,
                    self.aws_service,
                    self.custom_server_service,
                    self.ssh_service,
                    self.connection_service,
                    self.scp_service,
                )
                self.ai_relay_executors = relay
                cfg = self.config_manager.get()
                ai_audit = AuditTrail(cfg.mcp.audit_path)

                async def _ai_confirm_callback(call) -> bool:
                    """Push the right confirm modal for *call* and await the user's choice."""
                    from servonaut.screens.tool_confirm_modal import (
                        DangerousToolConfirmModal,
                        ToolConfirmModal,
                    )
                    if call.guard_level == "dangerous":
                        modal = DangerousToolConfirmModal(call.tool, dict(call.args))
                    else:
                        modal = ToolConfirmModal(call.tool, dict(call.args))
                    try:
                        result = await self.push_screen_wait(modal)
                    except Exception:  # pragma: no cover — defensive
                        logger.exception("push_screen_wait failed for tool confirm")
                        return False
                    return bool(result)

                self.ai_tool_bridge = AIToolBridge(
                    api_client=self.api_client,
                    relay_executors=relay,
                    mcp_audit=ai_audit,
                    confirm_callback=_ai_confirm_callback,
                    auth_service=self.auth_service,
                    # Inject the same ServonautTools the MCP server uses
                    # so AI-driven readonly tools (list_instances,
                    # describe_instance) execute via the local CLI
                    # surface instead of the SSH/Mercure relay.
                    servonaut_tools=getattr(self, "servonaut_tools", None),
                    ip_ban_service=getattr(self, "ip_ban_service", None),
                )
            except Exception as e:  # pragma: no cover
                logger.debug("AIToolBridge init skipped: %s", e)
                self.ai_tool_bridge = None
            logger.info("Paid-tier services initialized")
        except ImportError:
            logger.debug("httpx not installed; paid-tier services unavailable")
        except Exception as e:
            logger.debug("Paid-tier services init failed: %s", e)
        self._init_memory_cloud_services()

    def _init_memory_cloud_services(self) -> None:
        """Wire memory cloud-sync services (Stream 2 + 3).

        Imports are deferred so missing Stream 2/3 modules don't crash the app
        when those services are not yet delivered.
        """
        import os
        if self.api_client is None or self.auth_service is None:
            return
        try:
            import servonaut.services.memory.crypto as _memory_crypto_module
            self.memory_crypto = _memory_crypto_module
        except ImportError:
            logger.debug("memory crypto module unavailable")
            return

        try:
            from servonaut.services.memory.rate_limiter import RateLimiter
            self.memory_rate_limiter = RateLimiter()
        except ImportError:
            logger.debug("RateLimiter unavailable")
            return

        try:
            from servonaut.services.memory.sync_service import MemorySyncService
            self.memory_sync_service = MemorySyncService(
                api_client=self.api_client,
                crypto=self.memory_crypto,
                memory_service=self.memory_service,
                config_manager=self.config_manager,
                auth_service=self.auth_service,
                rate_limiter=self.memory_rate_limiter,
            )
            if self.memory_service is not None and hasattr(self.memory_service, "set_sync_service"):
                self.memory_service.set_sync_service(self.memory_sync_service)
            if hasattr(self.memory_sync_service, "set_key_material_listener"):
                self.memory_sync_service.set_key_material_listener(
                    self._propagate_memory_key_material
                )
            # SEC-3: gate enqueue_module on the memory_sync entitlement so an
            # enrolled-but-lapsed user's background auto-scan doesn't accumulate
            # plaintext JSONL envelopes that can never be drained to the server.
            # auth_service is guaranteed non-None here (checked at method entry).
            if hasattr(self.memory_sync_service, "set_entitlement_check"):
                self.memory_sync_service.set_entitlement_check(
                    lambda: (
                        self.auth_service is not None
                        and self.auth_service.has_feature("memory_sync")
                    )
                )
            # S-1: cross-device rotation notify — show a user-visible toast
            # when the background drain loop detects that our local keypair
            # is no longer registered on the server (another device rotated).
            if hasattr(self.memory_sync_service, "set_key_mismatch_listener"):
                def _on_key_mismatch_notify() -> None:
                    try:
                        self.notify(
                            "Memory Sync key changed on another device — "
                            "re-unlock from the Memory Sync screen to resume sync.",
                            severity="warning",
                            timeout=10,
                            markup=False,
                        )
                    except Exception:
                        pass
                self.memory_sync_service.set_key_mismatch_listener(
                    _on_key_mismatch_notify
                )
        except Exception as exc:
            logger.debug("MemorySyncService init failed: %s", exc)

        try:
            from servonaut.services.memory.ai_summary_service import AISummaryService
            self.ai_summary_service = AISummaryService(
                api_client=self.api_client,
                rate_limiter=self.memory_rate_limiter,
                auth_service=self.auth_service,
                config_manager=self.config_manager,
            )
        except Exception as exc:
            logger.debug("AISummaryService init failed: %s", exc)

        try:
            from servonaut.services.memory.retrieval_service import MemoryRetrievalService
            self.memory_retrieval_service = MemoryRetrievalService(
                api_client=self.api_client,
                crypto=self.memory_crypto,
                passphrase_provider=self._prompt_memory_passphrase,
                rate_limiter=self.memory_rate_limiter,
            )
        except Exception as exc:
            logger.debug("MemoryRetrievalService init failed: %s", exc)

        if self.memory_sync_service and self.memory_retrieval_service:
            self.memory_sync_service.set_retrieval_service(self.memory_retrieval_service)

        try:
            from servonaut.services.memory.drift_service import DriftService, AnomalyService
            self.drift_service = DriftService(
                api_client=self.api_client,
                rate_limiter=self.memory_rate_limiter,
            )
            self.anomaly_service = AnomalyService(
                api_client=self.api_client,
                rate_limiter=self.memory_rate_limiter,
            )
        except Exception as exc:
            logger.debug("DriftService/AnomalyService init failed: %s", exc)

        try:
            from servonaut.services.memory.fleet_service import FleetService
            self.fleet_service = FleetService(
                api_client=self.api_client,
                memory_service=self.memory_service,
                sync_service=self.memory_sync_service,
                rate_limiter=self.memory_rate_limiter,
            )
        except Exception as exc:
            logger.debug("FleetService init failed: %s", exc)

        try:
            from servonaut.services.memory.fleet_scan_service import FleetScanService
            if self.memory_service is not None:
                self.fleet_scan_service = FleetScanService(
                    self.memory_service, max_parallel=4
                )
        except Exception as exc:
            logger.debug("FleetScanService init failed: %s", exc)

        try:
            from servonaut.services.memory.settings_service import MemorySettingsService
            self.memory_settings_service = MemorySettingsService(
                api_client=self.api_client,
                rate_limiter=self.memory_rate_limiter,
            )
        except Exception as exc:
            logger.debug("MemorySettingsService init failed: %s", exc)

        try:
            from servonaut.services.memory.export_service import MemoryExportService
            self.export_service = MemoryExportService(
                api_client=self.api_client,
                rate_limiter=self.memory_rate_limiter,
                auth_service=self.auth_service,
            )
        except Exception as exc:
            logger.debug("MemoryExportService init failed: %s", exc)

        try:
            from servonaut.services.memory.team_service import TeamMemoryService
            self.team_memory_service = TeamMemoryService(
                api_client=self.api_client,
                auth_service=self.auth_service,
                crypto=self.memory_crypto,
                key_store_provider=lambda: self._memory_key_material,
                retrieval_service=self.memory_retrieval_service,
            )
        except Exception as exc:
            logger.debug("TeamMemoryService init failed: %s", exc)

        # NOTE: Memory cloud is NOT bootstrapped at app start.  The user opts
        # in via ``MemorySyncSetupScreen`` (sidebar → Memory Sync), which calls
        # :meth:`bootstrap_memory_cloud` once they explicitly hit "Set up".
        # No auto-modals, no auto network calls.

    async def bootstrap_memory_cloud(
        self, passphrase_provider=None
    ) -> None:
        """Bootstrap the memory cloud sync layer (user-initiated or auto-restart).

        Called from ``MemorySyncSetupScreen`` when the user clicks "Set up",
        or from ``_reactivate_memory_sync`` on startup when a local keypair
        cache is present.

        Args:
            passphrase_provider: Async callable ``(mode: str) -> str`` that
                returns the passphrase.  Defaults to
                ``self._prompt_memory_passphrase`` (shows the TUI modal).
                Pass a custom coroutine factory to supply the passphrase
                silently (e.g. from the OS keychain) without opening a modal.

        Idempotent — safe to call multiple times; the underlying service
        skips the network round-trip if a key is already loaded.

        Exceptions are NOT swallowed — the caller catches them and shows
        the user a notify with the actual reason (wrong passphrase, backend
        down, beta-waitlisted, etc.).

        The background sync loop is spawned as a *separate* worker so this
        coroutine returns once enrolment completes — otherwise the caller
        would be stuck awaiting a forever-loop and never see the success
        notify or the screen state update.
        """
        if self.memory_sync_service is None:
            return
        provider = (
            passphrase_provider
            if passphrase_provider is not None
            else self._prompt_memory_passphrase
        )
        await self.auth_service.fetch_user_id()
        await self.memory_sync_service.bootstrap(
            passphrase_provider=provider,
        )
        self._propagate_memory_key_material()
        # Fetch the server-side auto_sync_enabled flag before spawning the loop.
        auto_sync = False
        try:
            if self.memory_settings_service and self.auth_service and self.auth_service.has_feature("memory_sync"):
                settings = await self.memory_settings_service.get_settings()
                auto_sync = bool(getattr(settings, "auto_sync_enabled", False))
        except Exception:
            auto_sync = False
        self._start_memory_sync_loop(auto_sync)

    def _start_memory_sync_loop(self, auto_sync_enabled: bool) -> None:
        """Spawn the long-running sync drain loop as a background worker.

        Idempotent + decoupled from setup so the setup coroutine can return
        promptly. Uses a distinct worker group from setup so cancelling a
        retry doesn't accidentally tear down the active sync loop.

        Args:
            auto_sync_enabled: Value of the server-side auto_sync_enabled flag,
                fetched from MemorySettingsService before this call.
        """
        sync = self.memory_sync_service
        if sync is None or not getattr(sync, "is_configured", False):
            return
        entitled = (
            self.auth_service is not None
            and self.auth_service.has_feature("memory_sync")
        )
        if not (auto_sync_enabled and entitled):
            return
        self.run_worker(
            sync.start_background_loop(interval_s=60),
            name="memory_sync_loop",
            group="memory_sync_background",
            exclusive=True,
        )

    async def _refresh_memory_sync_loop(self) -> None:
        """Re-evaluate the drain loop after the server-side auto_sync flag changes.

        Called by MemorySyncPanel after a successful patch_settings save.
        Re-fetches the server flag and either spawns the drain worker (if
        auto_sync_enabled AND entitled AND is_configured) or stops it.

        Stop mechanism: we use Textual's ``workers.cancel_group`` on the
        ``"memory_sync_background"`` group.  The loop was started via
        ``run_worker(..., group="memory_sync_background", exclusive=True)``
        which means it lives as a Textual worker, NOT as a bare asyncio Task
        (``_loop_task`` is only set when the coroutine is scheduled directly
        via ``asyncio.create_task``).  Calling ``sync.stop()`` sets
        ``_stopped=True`` but would NOT cancel the worker coroutine because
        the ``_loop_task`` handle is None in this path.  ``cancel_group``
        cancels the actual Textual worker and propagates CancelledError into
        ``start_background_loop``, which catches it and exits cleanly.
        """
        sync = getattr(self, "memory_sync_service", None)
        if sync is None:
            return

        entitled = (
            self.auth_service is not None
            and self.auth_service.has_feature("memory_sync")
        )
        is_configured = bool(getattr(sync, "is_configured", False))

        auto_sync = False
        try:
            if self.memory_settings_service and entitled:
                settings = await self.memory_settings_service.get_settings(force_refresh=True)
                auto_sync = bool(getattr(settings, "auto_sync_enabled", False))
        except Exception:
            auto_sync = False

        if auto_sync and entitled and is_configured:
            self._start_memory_sync_loop(auto_sync)
        else:
            # Cancel the worker group so the running loop coroutine receives
            # CancelledError on its next asyncio.sleep and exits cleanly.
            try:
                self.workers.cancel_group(self, "memory_sync_background")
            except Exception:
                pass

    def _remember_passphrase_expired(self, cfg) -> bool:
        """Return ``True`` when the remembered passphrase has passed its TTL.

        Reads ``config.memory.sync_remember_expires_at`` (ISO-8601 UTC).  An
        empty value means "no expiry recorded" (legacy enrolment from before
        the TTL feature) and is treated as NOT expired so existing users are
        not surprised by a sudden re-prompt; the timestamp is stamped the next
        time they re-enter the passphrase.  Unparseable values fail open
        (not expired) — a malformed timestamp should not lock a user out.
        """
        raw = getattr(cfg.memory, "sync_remember_expires_at", "") or ""
        if not raw:
            return False
        try:
            from datetime import datetime, timezone
            exp = datetime.fromisoformat(raw)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) >= exp
        except Exception:
            return False

    def _clear_remember_device(self, *, drop_cache: bool = False) -> None:
        """Forget the device-remembered passphrase (keychain + config flags).

        Always clears the OS keychain entry and resets
        ``sync_remember_device`` / ``sync_remember_expires_at`` in config.
        When *drop_cache* is ``True`` the local passphrase-encrypted keypair
        cache (``keys.json``) is also removed — used when the stored passphrase
        no longer unwraps the cache (rotated elsewhere).  Never raises.
        """
        import logging as _log
        _logger = _log.getLogger(__name__)
        try:
            from servonaut.services.memory import passphrase_store as _ps
            _ps.clear_passphrase()
        except Exception:
            pass
        if drop_cache:
            sync = getattr(self, "memory_sync_service", None)
            if sync is not None:
                try:
                    sync.clear_local_keypair_cache()
                except Exception:
                    pass
        try:
            import dataclasses as _dc
            cfg = self.config_manager.get()
            updated_mem = _dc.replace(
                cfg.memory,
                sync_remember_device=False,
                sync_remember_expires_at="",
            )
            self.config_manager.update(memory=updated_mem)
        except Exception as exc:
            _logger.warning(
                "_clear_remember_device: could not clear remember flags: %s", exc
            )

    async def _try_silent_memory_unlock(self) -> bool:
        """Attempt a no-modal keychain-based Memory Sync unlock.

        Returns ``True`` iff the sync service ends up configured.  Never shows
        a modal and never raises.  Honours the remember TTL and self-corrects
        stale state:

        - keychain unavailable / nothing stored / TTL expired → clear the
          remember flags and return ``False`` (no credential to use);
        - stored passphrase no longer unwraps the local cache (rotated on
          another device) → clear keychain + cache + flags, return ``False``;
        - transient network/backend failure with a VALID passphrase → keep the
          credential untouched and return ``False`` (retry next launch);
        - valid passphrase + successful bootstrap → return ``True``.
        """
        import logging as _log
        _logger = _log.getLogger(__name__)

        sync = getattr(self, "memory_sync_service", None)
        if sync is None:
            return False
        if sync.is_configured:
            return True

        cfg = self.config_manager.get()
        if not getattr(cfg.memory, "sync_remember_device", False):
            return False

        try:
            from servonaut.services.memory import passphrase_store as _ps
            if not _ps.keyring_available():
                _logger.debug(
                    "_try_silent_memory_unlock: keychain unavailable; "
                    "clearing stale remember flag"
                )
                self._clear_remember_device()
                return False
            stored_pw = _ps.get_passphrase()
            if stored_pw is None:
                _logger.debug(
                    "_try_silent_memory_unlock: no passphrase in keychain; "
                    "clearing stale remember flag"
                )
                self._clear_remember_device()
                return False
            if self._remember_passphrase_expired(cfg):
                _logger.info(
                    "_try_silent_memory_unlock: remembered passphrase expired; "
                    "clearing keychain (user will be re-prompted)"
                )
                self._clear_remember_device()
                return False
            # MAJOR-1: validate the passphrase LOCALLY before any network call
            # so a transient backend error is never mistaken for a wrong one.
            if not sync.can_unwrap_local(stored_pw):
                _logger.info(
                    "_try_silent_memory_unlock: stored passphrase no longer "
                    "unwraps local cache; clearing keychain + cache"
                )
                self._clear_remember_device(drop_cache=True)
                return False

            async def _kc_provider(mode: str) -> str:
                return stored_pw

            try:
                await self.bootstrap_memory_cloud(passphrase_provider=_kc_provider)
                _logger.info("_try_silent_memory_unlock: silent reactivation succeeded")
                return True
            except Exception as exc:
                if sync.is_configured:
                    return True
                # Network/backend error — passphrase WAS valid; keep the
                # credential and retry on the next launch / section open.
                _logger.warning(
                    "_try_silent_memory_unlock: transient bootstrap failure "
                    "(passphrase valid): %s; will retry later", exc
                )
                return False
        except Exception as exc:
            _logger.warning(
                "_try_silent_memory_unlock: keychain check failed: %s", exc
            )
            return False

    async def _reactivate_memory_sync(self) -> None:
        """Startup SILENT reactivation of Memory Sync (no modal).

        Runs as a background worker from ``on_mount``.  Only attempts the
        non-intrusive keychain-based unlock — it NEVER opens a passphrase
        modal on boot.  When the user has not opted into "Remember on this
        device" (or the credential is stale/expired), Memory Sync simply stays
        dormant until the user opens a memory section, at which point
        :meth:`prompt_memory_sync_unlock` offers the unlock modal in context.

        Early-returns quickly when reactivation is not applicable so there is
        no startup cost for users who never set up Memory Sync.  Free users
        (no ``memory_sync`` entitlement) never reach the unlock path at all.
        """
        sync = getattr(self, "memory_sync_service", None)
        if sync is None or sync.is_configured or not sync.is_enrolled_locally():
            return
        # Auth guard — all cheap (reads from persisted token, no network).
        auth = getattr(self, "auth_service", None)
        if auth is None or not auth.is_authenticated or not auth.has_feature("memory_sync"):
            return
        await self._try_silent_memory_unlock()

    async def prompt_memory_sync_unlock(self) -> None:
        """Unlock Memory Sync when the user opens a memory section.

        Called from the memory screens' ``on_mount`` (e.g. the fleet memory
        view) — NOT on app boot — so the passphrase modal only appears in the
        context the user navigated to.  Tries a silent keychain unlock first
        (covers the transient-failure-on-boot case), then falls back to the
        ``PassphraseEnrolModal`` in unlock mode.

        No-op when sync is already active, the user is not enrolled on this
        device, lacks the ``memory_sync`` entitlement, or already declined the
        prompt earlier this session.  A cancel is NOT an error — it just leaves
        sync dormant until the user explicitly unlocks from the Memory Sync
        screen.
        """
        import logging as _log
        _logger = _log.getLogger(__name__)

        sync = getattr(self, "memory_sync_service", None)
        if sync is None or sync.is_configured or not sync.is_enrolled_locally():
            return
        auth = getattr(self, "auth_service", None)
        if auth is None or not auth.is_authenticated or not auth.has_feature("memory_sync"):
            return
        # Don't nag: if the user dismissed the prompt this session, stay quiet.
        if getattr(self, "_memory_sync_prompt_skipped", False):
            return

        # Silent path first (also re-tries a transient boot failure).
        if await self._try_silent_memory_unlock():
            return
        if sync.is_configured:
            return

        try:
            await self.bootstrap_memory_cloud()
            self.notify(
                "Memory Sync unlocked.",
                severity="information",
                timeout=4,
            )
        except RuntimeError:
            # User cancelled the modal — leave sync dormant, no error toast.
            self._memory_sync_prompt_skipped = True
            _logger.info(
                "prompt_memory_sync_unlock: user cancelled passphrase prompt; "
                "sync stays dormant"
            )
            self.notify(
                "Memory Sync locked — open Memory Sync to unlock.",
                severity="information",
                timeout=5,
            )
        except Exception as exc:
            _logger.warning(
                "prompt_memory_sync_unlock: prompt path failed: %s", exc
            )

    def _refresh_fleet_auto_scan_loop(self) -> None:
        """Re-evaluate the fleet auto-scan loop after the config flag changes.

        Analogous to ``_refresh_memory_sync_loop``.  Reads the current config
        and either spawns the loop (when both ``enabled`` and
        ``auto_scan_enabled`` are True) or cancels the running worker group
        promptly so the loop stops within one asyncio tick rather than waiting
        up to ``auto_scan_interval_seconds``.

        Called by ``FleetMemoryScreen.action_toggle_auto_scan`` after persisting
        the new flag, and by ``MemoryPanel.persist`` so toggling auto-scan in
        Settings starts/stops the loop immediately.
        """
        cfg = self.config_manager.get().memory
        if cfg.enabled and cfg.auto_scan_enabled:
            self._start_fleet_auto_scan_loop()
        else:
            try:
                self.workers.cancel_group(self, "memory_auto_scan")
            except Exception:  # noqa: BLE001
                pass

    def _start_fleet_auto_scan_loop(self) -> None:
        """Spawn the background fleet auto-scan loop as a worker.

        No-op when ``config.memory.auto_scan_enabled`` is ``False`` or when
        either ``memory_service`` or ``fleet_scan_service`` is unavailable.
        The worker sleeps for the configured interval before the FIRST scan,
        so calling this in ``on_mount`` is safe regardless of instance-list
        readiness.

        The worker group ``memory_auto_scan`` is exclusive and distinct from
        ``memory_refresh`` and ``memory_sync_background`` so cancelling one
        loop does not tear down the others.
        """
        cfg = self.config_manager.get().memory
        if not (cfg.enabled and cfg.auto_scan_enabled):
            return
        if self.fleet_scan_service is None or self.memory_service is None:
            return
        self.run_worker(
            self._fleet_auto_scan_loop(),
            name="fleet_auto_scan_loop",
            group="memory_auto_scan",
            exclusive=True,
        )

    async def _fleet_auto_scan_loop(self) -> None:
        """Long-running background fleet auto-scan coroutine.

        Sleeps for ``auto_scan_interval_seconds`` (minimum 60 s), then
        probes eligible instances via ``FleetScanService``.  Re-reads config
        before each cycle so operators can disable the loop without a restart.
        Exceptions inside a scan cycle are logged and swallowed so the loop
        survives transient SSH failures — ``asyncio.CancelledError`` is
        always re-raised.
        """
        import asyncio
        import time

        while True:
            cfg = self.config_manager.get().memory
            if not (cfg.enabled and cfg.auto_scan_enabled):
                return
            interval = max(60, cfg.auto_scan_interval_seconds)
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                return
            # Re-read config after the sleep in case it changed.
            cfg = self.config_manager.get().memory
            if not (cfg.enabled and cfg.auto_scan_enabled):
                return
            try:
                await self.fleet_scan_service.scan(
                    self.instances or [],
                    stale_only=cfg.auto_scan_stale_only,
                )
                self._fleet_auto_scan_last_run = time.time()
            except asyncio.CancelledError:
                return
            except Exception:
                logger.exception("fleet auto-scan cycle failed")
                # Loop MUST survive individual cycle failures.

    # ------------------------------------------------------------------
    # App-owned manual fleet scan (survives screen navigation)
    # ------------------------------------------------------------------

    def start_fleet_manual_scan(
        self,
        instances: list,
        *,
        stale_only: bool,
    ) -> bool:
        """Spawn the app-owned manual fleet scan worker.

        Returns ``True`` when the worker was successfully spawned, ``False``
        when a scan is already in progress (caller should notify the user).

        The worker runs in group ``memory_manual_scan`` — a dedicated group
        distinct from ``memory_auto_scan``, ``memory_refresh``,
        ``memory_fleet``, and ``memory_sync_background`` — so it is never
        cancelled by navigation or by any other worker group.
        """
        if self._fleet_manual_scan_in_progress:
            return False
        self._fleet_manual_scan_in_progress = True
        self.run_worker(
            self._do_fleet_manual_scan(list(instances), stale_only),
            name="fleet_manual_scan",
            group="memory_manual_scan",
            exclusive=True,
        )
        return True

    async def _do_fleet_manual_scan(
        self,
        instances: list,
        stale_only: bool,
    ) -> None:
        """App-owned coroutine that drives the manual fleet scan.

        Survives screen navigation because it is a worker on the *app*, not
        on any screen.  Progress callbacks and completion hooks are routed to
        whichever ``FleetMemoryScreen`` is currently mounted via duck-typing
        — they are silent no-ops when the user has navigated elsewhere.

        On completion the current screen's ``on_fleet_manual_scan_done``
        method is called (if present) so the screen can repopulate the table,
        push the summary modal, and clear its in-progress indicator.
        """
        import asyncio as _asyncio

        try:
            fleet_scan_service = getattr(self, "fleet_scan_service", None)
            if fleet_scan_service is None:
                self.notify("Fleet scan service not available.", severity="error")
                return

            result = await fleet_scan_service.scan(
                instances,
                stale_only=stale_only,
                on_progress=self._fleet_manual_scan_progress,
            )
        except _asyncio.CancelledError:
            # Worker cancelled (app quit, etc.) — exit quietly.
            logger.info("Fleet manual scan cancelled")
            return
        except Exception:
            logger.exception("Fleet manual scan crashed")
            self.notify(
                "Fleet scan crashed — check logs for details.",
                severity="error",
                markup=False,
            )
            return
        finally:
            self._fleet_manual_scan_in_progress = False
            # Tell the current screen (if it's a Fleet Memory screen) to
            # refresh its in-progress indicator regardless of outcome.
            screen = getattr(self, "screen", None)
            set_progress = getattr(screen, "_set_progress", None)
            if callable(set_progress):
                try:
                    set_progress("")
                except Exception:
                    pass

        # Success path: notify and hand off to the screen.
        self.notify(
            f"Fleet scan done: {len(result.succeeded)} ok, "
            f"{len(result.failed)} failed.",
            markup=False,
        )
        screen = getattr(self, "screen", None)
        done_hook = getattr(screen, "on_fleet_manual_scan_done", None)
        if callable(done_hook):
            try:
                done_hook(result)
            except Exception:
                logger.exception("on_fleet_manual_scan_done raised")

    def _fleet_manual_scan_progress(self, progress: object) -> None:
        """Route a scan progress event to the currently mounted Fleet Memory screen.

        Uses duck-typing to avoid importing the screen class (which would
        create a circular import).  The call is a safe no-op when the user
        has navigated to a different screen.
        """
        screen = getattr(self, "screen", None)
        cb = getattr(screen, "_on_scan_progress", None)
        if callable(cb):
            try:
                cb(progress)
            except Exception:
                logger.debug("_fleet_manual_scan_progress: _on_scan_progress raised", exc_info=True)

    def _propagate_memory_key_material(self) -> None:
        """Mirror keypair material from MemorySyncService onto the app.

        TeamMemoryService and MemoryRetrievalService both need access to
        the unwrapped keypair after enrolment, but only MemorySyncService
        knows when the user has provided their passphrase. This runs once
        after bootstrap and again whenever the sync service fires its
        key-material listener (after a rotate).
        """
        sync = self.memory_sync_service
        if sync is None:
            return
        material = sync.get_key_material()
        if material is None:
            return
        self._memory_key_material = material
        if self.memory_retrieval_service is not None:
            self.memory_retrieval_service.set_key_material(material)
            self.memory_retrieval_service.clear_cache()

    async def _prompt_memory_passphrase(self, mode: str = "enrol") -> str:
        """Return the memory encryption passphrase.

        Checks ``SERVONAUT_MEMORY_PASSPHRASE`` env var first (headless/MCP
        mode).  Falls back to ``PassphraseEnrolModal`` in TUI mode with
        the appropriate ``mode`` (``"enrol"`` for first-time setup,
        ``"unlock"`` when the keypair already exists server-side).

        When the user checks "Remember on this device" in the modal AND the
        OS keychain is available, the passphrase is stored in the keychain
        and ``config.memory.sync_remember_device`` is set to ``True`` so
        the startup reactivation path can silently unlock on the next launch.

        Args:
            mode: ``"enrol"`` (default — confirm field shown) or
                ``"unlock"`` (single passphrase input). The sync service
                passes ``"unlock"`` whenever ``GET /keys/me`` returns an
                existing wrapped key.

        Returns:
            Passphrase string.

        Raises:
            RuntimeError: If the user cancels the modal.
        """
        import os as _os
        env = _os.environ.get("SERVONAUT_MEMORY_PASSPHRASE")
        if env:
            return env
        from servonaut.screens.memory_keys import PassphraseEnrolModal
        result = await self.push_screen_wait(PassphraseEnrolModal(mode=mode))
        if result is None:
            raise RuntimeError(
                f"Memory keypair {mode} cancelled by user"
            )
        # Honor the "Remember on this device" opt-in: store the passphrase
        # in the OS keychain and flag it in config for startup reactivation.
        if result.remember:
            try:
                from servonaut.services.memory import passphrase_store
                if passphrase_store.keyring_available():
                    if passphrase_store.store_passphrase(result.passphrase):
                        import dataclasses as _dc
                        from datetime import datetime, timedelta, timezone
                        from servonaut.config.schema import DEFAULT_REMEMBER_TTL_DAYS
                        expires_at = (
                            datetime.now(timezone.utc)
                            + timedelta(days=DEFAULT_REMEMBER_TTL_DAYS)
                        ).isoformat()
                        cfg = self.config_manager.get()
                        updated_mem = _dc.replace(
                            cfg.memory,
                            sync_remember_device=True,
                            sync_remember_expires_at=expires_at,
                        )
                        self.config_manager.update(memory=updated_mem)
                        logger.info(
                            "_prompt_memory_passphrase: passphrase stored in "
                            "keychain (expires %s)", expires_at
                        )
                else:
                    # The user asked to remember but there is no secure OS
                    # keychain backend on this machine — be honest rather than
                    # silently re-prompting on every launch.
                    self.notify(
                        "No OS keychain available on this device — couldn't "
                        "save the passphrase. You'll be asked again next time.",
                        severity="warning",
                        timeout=7,
                    )
            except Exception as exc:
                logger.warning(
                    "_prompt_memory_passphrase: keychain store failed: %s", exc
                )
        return result.passphrase

    def on_text_selected(self) -> None:
        """Auto-copy selected text to clipboard when user highlights with mouse.

        Checks both Screen-level selection (for Static widgets) and
        TextArea.selected_text (for TextArea widgets, which have their
        own selection mechanism).
        """
        import re
        from textual.widgets import TextArea

        # 1. Try Screen-level selection (works on Static, Label, etc.)
        text = self.screen.get_selected_text()

        # 2. If nothing, check TextArea selections on the current screen
        if not text or not text.strip():
            try:
                for ta in self.screen.query(TextArea):
                    sel = ta.selected_text
                    if sel and sel.strip():
                        text = sel
                        break
            except Exception:
                pass

        if not text or not text.strip():
            return

        # Strip ANSI escape codes
        clean = re.sub(r'\x1b\[[0-9;]*m', '', text).strip()
        if not clean:
            return

        from servonaut.utils.platform_utils import copy_to_clipboard
        if copy_to_clipboard(clean):
            lines = len(clean.splitlines())
            label = f"{lines} lines" if lines > 1 else f"{len(clean)} chars"
            self.notify(f"Copied {label}", severity="information")
        else:
            self.copy_to_clipboard(clean)
            self.notify("Copied (via terminal)", severity="information")

    def action_show_help(self) -> None:
        """Show help screen from any context."""
        from servonaut.screens.help import HelpScreen
        self.push_screen(HelpScreen())

    def action_toggle_chat(self) -> None:
        """Toggle the chat panel on the current screen."""
        from textual.css.query import NoMatches
        from servonaut.widgets.chat_panel import ChatPanel
        try:
            panel = self.screen.query_one("#chat-panel", ChatPanel)
            panel.remove()
        except NoMatches:
            panel = ChatPanel()
            self.screen.mount(panel)
            panel.focus_input()

    def action_toggle_demo(self) -> None:
        """Toggle demo mode at runtime (ctrl+shift+d).

        ON  → instantiate RedactionService, redact instances in place, refresh
              status bar + active screen, notify (information).
        OFF → restore self.instances from self._instances_pristine (deepcopy),
              clear redaction_service so guards short-circuit, refresh, notify
              (warning — "real data restored").

        Race-safety: snapshot captured once at on_mount + re-captured on
        instance-list refresh; never mutated otherwise. Mid-stream renders
        may land mid-burst — next flush tick re-syncs. Documented.
        """
        import copy
        from servonaut.services.redaction_service import RedactionService

        if self.demo_mode:
            if self._instances_pristine is not None:
                self.instances = copy.deepcopy(self._instances_pristine)
            self.demo_mode = False
            self.redaction_service = None
            self.notify("Demo mode OFF — real data restored.", severity="warning", timeout=4)
        else:
            if self.redaction_service is None:
                self.redaction_service = RedactionService()
            self.redaction_service.redact_instances(self.instances)
            self.demo_mode = True
            self.notify("Demo mode ON — all surfaces redacted.", severity="information", timeout=4)

        # Re-render active screen + StatusBar.
        try:
            self.screen.refresh(recompose=False)
        except Exception:
            pass

        from servonaut.screens.instance_list import InstanceListScreen
        from servonaut.screens.fleet_memory import FleetMemoryScreen
        from servonaut.screens.log_viewer import LogViewerScreen
        if isinstance(self.screen, InstanceListScreen):
            self.screen._instances = list(self.instances)
            self.screen._update_table()
        elif isinstance(self.screen, FleetMemoryScreen):
            self.screen._launch_populate()
        elif isinstance(self.screen, LogViewerScreen):
            # Pre-toggle scrollback + copy/AI buffer hold raw lines; the
            # screen re-scrubs and repaints them (and its header) itself.
            self.screen.refresh_after_demo_toggle()

        try:
            from servonaut.widgets.status_bar import StatusBar
            for sb in self.query(StatusBar):
                sb._update_display()
        except Exception:
            pass

    def resolve_instance(self, id_or_name: str) -> Optional[dict]:
        """Case-insensitive instance lookup across all providers.

        AWS instances are checked before custom/OVH instances so AWS wins on
        name collisions (matches the rule in ServonautTools._find_instance).

        Args:
            id_or_name: Instance ID or display name to search for.

        Returns:
            Matching instance dict, or None if not found.
        """
        aws_instances = [i for i in self.instances if not i.get("is_custom")]
        other_instances = [i for i in self.instances if i.get("is_custom")]
        return resolve_instance_from_lists(id_or_name, aws_instances, other_instances)

    def on_sidebar_navigation_requested(self, message: "Sidebar.NavigationRequested") -> None:
        """Handle navigation events from the sidebar."""
        target_id = message.target_id
        if not target_id:
            return
            
        if target_id == "nav_list":
            from servonaut.screens.instance_list import InstanceListScreen
            self.switch_screen(InstanceListScreen())
        elif target_id == "nav_keys":
            from servonaut.screens.key_management import KeyManagementScreen
            self.switch_screen(KeyManagementScreen())
        elif target_id == "nav_scan":
            self._run_global_scan()
        elif target_id == "nav_memory":
            from servonaut.screens.fleet_memory import FleetMemoryScreen
            self.switch_screen(FleetMemoryScreen())
        elif target_id == "nav_settings":
            from servonaut.screens.settings import SettingsScreen
            self.switch_screen(SettingsScreen())
        elif target_id == "nav_custom_servers":
            from servonaut.screens.custom_servers import CustomServersScreen
            self.switch_screen(CustomServersScreen())
        elif target_id == "nav_cloudtrail":
            from servonaut.screens.cloudtrail_browser import CloudTrailBrowserScreen
            self.switch_screen(CloudTrailBrowserScreen())
        elif target_id == "nav_ip_ban":
            from servonaut.screens.ip_ban import IPBanScreen
            self.switch_screen(IPBanScreen())
        elif target_id == "nav_cloudwatch":
            from servonaut.screens.cloudwatch_browser import CloudWatchBrowserScreen
            self.switch_screen(CloudWatchBrowserScreen())
        elif target_id == "nav_update":
            self._run_update()
        elif target_id == "nav_ovh_dns":
            from servonaut.screens.ovh_dns import OVHDNSScreen
            self.switch_screen(OVHDNSScreen())
        elif target_id == "nav_ovh_ips":
            from servonaut.screens.ovh_ip_management import OVHIPManagementScreen
            self.switch_screen(OVHIPManagementScreen())
        elif target_id == "nav_ovh_storage":
            from servonaut.screens.ovh_storage import OVHStorageScreen
            self.switch_screen(OVHStorageScreen())
        elif target_id == "nav_ovh_billing":
            from servonaut.screens.ovh_billing import OVHBillingScreen
            self.switch_screen(OVHBillingScreen())
        elif target_id == "nav_ovh_ssh_keys":
            from servonaut.screens.ovh_ssh_keys import OVHSSHKeysScreen
            self.switch_screen(OVHSSHKeysScreen())
        elif target_id == "nav_login":
            from servonaut.screens.login import LoginScreen
            self.switch_screen(LoginScreen())
        elif target_id == "nav_teams":
            auth = getattr(self, 'auth_service', None)
            if not auth or not auth.has_feature("team_workspaces"):
                self.notify(
                    "Team management requires a Teams subscription.",
                    severity="warning",
                )
                return
            from servonaut.screens.team_management import TeamManagementScreen
            self.switch_screen(TeamManagementScreen())
        elif target_id == "nav_sync_config":
            auth = getattr(self, "auth_service", None)
            if not auth or not auth.is_authenticated:
                from servonaut.screens.login import LoginScreen
                self.notify(
                    "Sign in to manage config snapshots.",
                    severity="information",
                )
                self.switch_screen(LoginScreen(return_to="sync_config"))
                return
            if not auth.has_feature("config_sync"):
                self.notify(
                    "Config sync requires a Solo or Teams subscription.",
                    severity="warning",
                )
                return
            from servonaut.screens.snapshot_manager import SnapshotManagerScreen
            self.switch_screen(SnapshotManagerScreen())
        elif target_id == "nav_memory_sync":
            from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen
            self.switch_screen(MemorySyncSetupScreen())
        elif target_id == "nav_secrets":
            from servonaut.screens.secrets import SecretsScreen
            self.switch_screen(SecretsScreen())
        elif target_id == "nav_drift":
            from servonaut.screens.memory_drift import MemoryDriftScreen
            self.switch_screen(MemoryDriftScreen())
        elif target_id == "nav_memory_export":
            from servonaut.screens.memory_export import MemoryExportScreen
            self.switch_screen(MemoryExportScreen())
        elif target_id == "nav_bug_report":
            if self.bug_report_service is None:
                self.notify(
                    "Bug reporting requires httpx. Install with: pip install 'servonaut[pro]'",
                    severity="warning",
                )
                return
            from servonaut.screens.bug_report import BugReportScreen
            self.push_screen(BugReportScreen())
        elif target_id == "nav_hetzner_manage":
            if getattr(self, "hetzner_service", None) is None:
                self.notify(
                    "Hetzner is not configured. Visit Settings → Hetzner Cloud "
                    "to set up a token.",
                    severity="warning", markup=False,
                )
                return
            from servonaut.screens.hetzner_manager import HetznerManagerScreen
            self.switch_screen(HetznerManagerScreen())
        elif target_id == "nav_hetzner_ssh_keys":
            if getattr(self, "hetzner_service", None) is None:
                self.notify(
                    "Hetzner is not configured. Visit Settings → Hetzner Cloud "
                    "to set up a token.",
                    severity="warning", markup=False,
                )
                return
            from servonaut.screens.hetzner_ssh_keys import HetznerSSHKeysScreen
            self.switch_screen(HetznerSSHKeysScreen())
        elif target_id == "nav_ovh_manage":
            if getattr(self, "ovh_service", None) is None:
                self.notify(
                    "OVHcloud is not configured. Visit Settings → OVHcloud to "
                    "set up credentials.",
                    severity="warning", markup=False,
                )
                return
            from servonaut.screens.ovh_manager import OVHManagerScreen
            self.switch_screen(OVHManagerScreen())
        elif target_id == "nav_aws_manage":
            from servonaut.screens.aws_manager import AWSManagerScreen
            self.switch_screen(AWSManagerScreen())
        elif target_id in _S3_NAV_TO_PROVIDER:
            provider = _S3_NAV_TO_PROVIDER[target_id]
            svc = getattr(self, f"{provider}_object_storage_service", None)
            if svc is None:
                self.notify(
                    f"{provider.upper()} Object Storage is not configured. "
                    "Visit Settings to add credentials.",
                    severity="warning", markup=False,
                )
                return
            from servonaut.screens.object_storage import ObjectStorageScreen
            self.switch_screen(ObjectStorageScreen(provider=provider))
        elif target_id == "nav_quit":
            self.exit()

    def _run_global_scan(self) -> None:
        """Run keyword scan across all running instances."""
        self.notify("Starting scan of all running servers...", severity="information")
        self.run_worker(self._do_global_scan(), name="global_scan", exclusive=True)

    async def _do_global_scan(self) -> None:
        """Worker: scan all running instances for keywords."""
        instances = self.instances
        if not instances:
            self.notify("No instances loaded. Load instances first.", severity="warning")
            return

        running = [i for i in instances if i.get('state') == 'running']
        if not running:
            self.notify("No running instances to scan.", severity="warning")
            return

        total = len(running)
        scanned = 0
        for idx, instance in enumerate(running, 1):
            name = instance.get('name') or instance.get('id', 'unknown')
            self.notify(f"Scanning {idx}/{total}: {name}...", severity="information")
            try:
                results = await self.scan_service.scan_server(
                    instance, self.ssh_service, self.connection_service
                )
                if results:
                    self.keyword_store.save_results(instance['id'], results)
                    scanned += 1
            except Exception as e:
                self.notify(f"Scan failed for {name}: {e}", severity="error")

        self.notify(f"Scan complete. {scanned}/{total} servers scanned.")

    async def _check_for_update(self) -> None:
        """Check PyPI for a newer version in the background."""
        import asyncio
        latest = await asyncio.to_thread(self.update_service.check_for_update)
        if latest:
            self._latest_version = latest
            self._show_update_button(latest)
            self.notify(
                f"Update available: v{latest} (you have v{self.update_service.current_version})",
                severity="information",
                timeout=8,
            )

    def _show_update_button(self, version: str) -> None:
        """Reveal the update button on the current screen's sidebar."""
        from textual.widgets import Button
        try:
            btn = self.screen.query_one("#nav_update", Button)
            btn.label = f"📥 Update to v{version}"
            btn.remove_class("hidden")
        except Exception:
            pass

    def _run_update(self) -> None:
        """Run the upgrade via pipx/pip."""
        if not self._latest_version:
            self.notify("Already up to date!", severity="information")
            return
        self.notify("Updating Servonaut...", severity="information")
        self.run_worker(self._do_update(), name="update", exclusive=True)

    async def _do_update(self) -> None:
        """Worker: run the upgrade."""
        success, message = await self.update_service.run_upgrade()
        severity = "information" if success else "error"
        self.notify(message, severity=severity, timeout=10)

    async def _refresh_ssh_verify_status(self) -> None:
        """Fetch ssh_verify_status sidecar data and decorate self.instances.

        Defensive — if the call fails (not logged in, 402 Free tier, network),
        silently leaves instances un-decorated. The TUI column gracefully
        renders "—" for missing data.
        """
        if self.bw_ssh_config_service is None:
            return
        try:
            rows = await self.bw_ssh_config_service.list_personal_instances()
        except Exception as exc:
            logger.debug("Failed to load SSH verify status sidecar: %s", exc)
            return
        by_key = {
            (r.get("provider"), r.get("instance_id")): r
            for r in rows
        }
        for inst in self.instances:
            sidecar = by_key.get(
                (inst.get("provider", "aws").lower(), inst.get("id"))
            )
            if sidecar:
                inst["ssh_verify_status"] = sidecar.get("ssh_verify_status")
                inst["ssh_verified_at"] = sidecar.get("ssh_verified_at")
        # Trigger instance table refresh if the list screen is mounted
        try:
            from servonaut.screens.instance_list import InstanceListScreen
            if isinstance(self.screen, InstanceListScreen):
                self.screen._update_table()
        except Exception:
            pass
