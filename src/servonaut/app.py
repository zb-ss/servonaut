"""Main Textual application for Servonaut v2.0."""

from __future__ import annotations
import logging
from typing import TYPE_CHECKING, Optional, List

from textual.app import App
from textual.reactive import reactive

logger = logging.getLogger(__name__)
from textual.binding import Binding

from servonaut.utils.instance_resolver import resolve_instance_from_lists

if TYPE_CHECKING:
    from servonaut.widgets.sidebar import Sidebar
    from servonaut.services.relay_manager import RelayManager, RelayState


class ServonautApp(App):
    """Servonaut TUI application."""

    CSS_PATH = "app.css"
    TITLE = "Servonaut"
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("question_mark", "show_help", "Help", show=True),
        Binding("f2", "toggle_chat", "Chat", show=True),
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

    # Memory cloud-sync layer (Stream 2 + 3 services)
    memory_rate_limiter = None
    memory_sync_service = None
    memory_retrieval_service = None
    memory_settings_service = None
    fleet_service = None
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

    # T11: instance IDs that have already triggered the first-connect memory
    # prompt in this session.  Reset every time the app restarts.
    memory_first_connect_seen: set = set()

    # Latest version found by the background update check (None = not checked yet)
    _latest_version: Optional[str] = None

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
        # Apply demo-mode redaction
        if self.demo_mode:
            from servonaut.services.redaction_service import RedactionService
            self.redaction_service = RedactionService()
            self.redaction_service.redact_instances(self.instances)
        self.push_screen(InstanceListScreen())
        # Push optional initial screen (e.g., OVH setup wizard launched via --setup-ovh)
        if self._initial_screen is not None:
            self.push_screen(self._initial_screen)
        # Check for updates in background
        self.run_worker(self._check_for_update(), name="version_check", exclusive=True)
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
        self.ssh_service = SSHService(self.config_manager)
        self.connection_service = ConnectionService(self.config_manager)
        self.scan_service = ScanService(self.config_manager)
        self.keyword_store = KeywordStore(config.keyword_store_path)
        self.terminal_service = TerminalService(preferred=config.terminal_emulator)
        self.scp_service = SCPService()
        self.command_history = CommandHistoryService(config.command_history_path)
        self.custom_server_service = CustomServerService(self.config_manager)
        self.log_viewer_service = LogViewerService(self.config_manager)
        self.cloudtrail_service = CloudTrailService(self.config_manager)
        self.cloudwatch_service = CloudWatchService()
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
            auth_service=self.auth_service,
            memory_service=self.memory_service,
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
        """Called by LoginScreen after logout — tear the relay down."""
        if self.relay_manager is not None:
            self.run_worker(self.relay_manager.stop(),
                            name="relay_logout_stop", exclusive=True)

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

    async def bootstrap_memory_cloud(self) -> None:
        """Bootstrap the memory cloud sync layer (user-initiated).

        Called from ``MemorySyncSetupScreen`` when the user clicks "Set up".
        Idempotent — safe to call multiple times; the underlying service
        skips the network round-trip if a key is already loaded.

        Exceptions are NOT swallowed — the caller (the setup screen worker)
        catches them and shows the user a notify with the actual reason
        (wrong passphrase, backend down, beta-waitlisted, etc.). Swallowing
        here would leave the user staring at an unchanged screen wondering
        what went wrong.

        The background sync loop is spawned as a *separate* worker so this
        coroutine returns once enrolment completes — otherwise the caller
        would be stuck awaiting a forever-loop and never see the success
        notify or the screen state update.
        """
        if self.memory_sync_service is None:
            return
        await self.auth_service.fetch_user_id()
        await self.memory_sync_service.bootstrap(
            passphrase_provider=self._prompt_memory_passphrase,
        )
        self._propagate_memory_key_material()
        self._start_memory_sync_loop()

    def _start_memory_sync_loop(self) -> None:
        """Spawn the long-running sync drain loop as a background worker.

        Idempotent + decoupled from setup so the setup coroutine can return
        promptly. Uses a distinct worker group from setup so cancelling a
        retry doesn't accidentally tear down the active sync loop.
        """
        sync = self.memory_sync_service
        if sync is None or not getattr(sync, "is_configured", False):
            return
        self.run_worker(
            sync.start_background_loop(interval_s=60),
            name="memory_sync_loop",
            group="memory_sync_background",
            exclusive=True,
        )

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
        if not result:
            raise RuntimeError(
                f"Memory keypair {mode} cancelled by user"
            )
        return result

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
            btn.label = f"⬇️ Update to v{version}"
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

    def on_user_logout(self) -> None:
        """Called after a successful logout to clean up session state."""
        if hasattr(self, "config_sync_service") and self.config_sync_service is not None:
            self.config_sync_service.clear_session()
