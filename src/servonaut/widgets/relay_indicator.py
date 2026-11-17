"""Compact status indicator for the TUI's relay connection.

One tiny widget whose label reflects the enum from ``RelayManager.state``.
Lives in the sidebar. Clicking opens :class:`RelayStatusScreen` — a full
screen with the persistent sidebar, showing the backend's view alongside
the local view and exposing Restart / Stop actions.
"""
from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.content import Content
from textual.containers import Container, Horizontal, ScrollableContainer, VerticalScroll
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Button, Footer, Static

from servonaut.services.relay_manager import RelayState
from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens._demo_resolve import display_text
from servonaut.utils.formatting import format_time_ago
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen


# Enum → (dot, color, label) mapping, kept here so the indicator stays tiny.
_STATE_DISPLAY = {
    RelayState.CONNECTED: ("●", "$text-success", "connected"),
    RelayState.CONNECTING: ("○", "$text-warning", "connecting…"),
    RelayState.EXTERNAL: ("●", "$text-accent", "external listener"),
    RelayState.NO_ENTITLEMENT: ("○", "$text-primary", "upgrade to connect"),
    RelayState.NOT_CONFIGURED: ("○", "$text-error", "not configured"),
    RelayState.ERROR: ("○", "$text-error", "error"),
    RelayState.STOPPED: ("○", "$text-muted", "disconnected"),
    RelayState.DISABLED: ("○", "$text-muted", "not logged in"),
    RelayState.SESSION_EXPIRED: ("○", "$text-error", "session expired"),
}


def _format(state: Optional[RelayState]) -> str:
    if state is None:
        return "[$text-muted]○ relay[/$text-muted]"
    dot, color, label = _STATE_DISPLAY.get(
        state, ("○", "$text-muted", state.value),
    )
    return f"[{color}]{dot}[/{color}] [dim]{label}[/dim]"


class RelayIndicator(Widget):
    """Static line in the sidebar showing the current relay state."""

    DEFAULT_CSS = """
    RelayIndicator {
        height: 1;
        width: 100%;
        padding: 0 2;
        margin: 1 0 0 0;
    }
    RelayIndicator:hover { background: $boost; }
    """

    # Copy of the app's state so the widget can react without a callback chain.
    state = reactive(None)

    def render(self) -> str:  # type: ignore[override]
        return _format(self.state)

    def watch_state(self, _old, _new) -> None:
        self.refresh()

    def on_mount(self) -> None:
        """Subscribe to the app's ``relay_state`` reactive directly.

        Without this, the indicator only got the initial value from
        ``Sidebar.on_mount`` and missed every later state transition that
        happened on the *current* screen — they were pushed via
        ``App._on_relay_state_change`` which queries the active screen,
        but if the state change fired before the indicator had finished
        mounting (race during boot), the update was silently dropped.
        Watching the reactive directly closes that race.
        """
        # Pull the current value first so we don't render with `None` for a
        # frame after every screen switch.
        self.state = getattr(self.app, "relay_state", None)
        try:
            self.watch(self.app, "relay_state", self._sync_from_app)
        except Exception:
            # Older Textual or app variants without a relay_state reactive.
            pass

    def _sync_from_app(self, new_state) -> None:
        self.state = new_state

    def on_click(self) -> None:
        open_relay_status(self.app, self.state)


def open_relay_status(app, state=None) -> None:
    """What clicking the relay indicator does; the command palette offers it too.

    Session-expired is the one state where the user can't fix anything from
    the relay status screen: sign-in is the required next step, so it opens
    the sign-in screen instead. *state* defaults to the app's relay state.
    """
    if state is None:
        state = getattr(app, "relay_state", None)
    if state is RelayState.SESSION_EXPIRED:
        try:
            from servonaut.screens.login import LoginScreen
            app.push_screen(LoginScreen())
            return
        except Exception:
            # Fall through to the relay status screen as a last
            # resort if login screen isn't available for some reason.
            pass
    app.push_screen(RelayStatusScreen())


class RelayStatusScreen(WorkspaceScreen):
    """Inspect the relay connection and offer Restart / Stop actions.

    Full screen with sidebar (was previously a ModalScreen but the panel
    has too much info — and several actions — to feel like a transient
    confirmation). Pop with Escape or the Close button to return to the
    previous screen.
    """

    CHAT_REFLOW = True
    # Keep status and action labels readable alongside an open chat column.
    CHAT_MIN_CONTENT_WIDTH = 84
    # Local and backend status stack below this available content width.
    CONTENT_NARROW_WIDTH = 84

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "restart", "Restart", show=True),
        Binding("s", "stop", "Stop", show=True),
    ]

    DEFAULT_CSS = """
    RelayStatusScreen #relay_container {
        width: 1fr;
        height: 100%;
        padding: 0 2 1 2;
        overflow: hidden hidden;
        background: transparent;
    }
    RelayStatusScreen #relay_heading { height: auto; margin-bottom: 1; }
    RelayStatusScreen #relay_title { height: auto; text-style: bold; color: $text; }
    RelayStatusScreen #relay_description { height: auto; color: $text-muted; }
    RelayStatusScreen #relay_card { width: 100%; height: 1fr; min-height: 4; padding: 0; }
    RelayStatusScreen #relay_status_regions { height: auto; }
    RelayStatusScreen .relay_status_area {
        height: auto;
        padding: 1;
        margin: 0 0 1 0;
        border: round $border-blurred;
        background: $surface;
    }
    RelayStatusScreen #relay_backend_area { width: 2fr; border: round $primary; }
    RelayStatusScreen #relay_local_area { width: 1fr; max-width: 42; margin-left: 1; background: $panel; }
    RelayStatusScreen .relay_status_heading { height: auto; text-style: bold; margin-bottom: 1; color: $text; }
    RelayStatusScreen #local_status,
    RelayStatusScreen #backend_status { height: auto; }
    RelayStatusScreen #relay_actions {
        dock: bottom;
        layout: grid;
        grid-size: 3;
        grid-columns: 1fr;
        grid-rows: auto;
        grid-gutter: 0 1;
        width: 100%;
        height: auto;
        border-top: solid $border-blurred;
        background: $surface;
    }
    RelayStatusScreen #relay_actions Button { width: 1fr; min-width: 0; height: auto; min-height: 3; margin: 0; }
    RelayStatusScreen.-content-narrow #relay_container { padding: 0 1 1 1; }
    RelayStatusScreen.-content-narrow #relay_status_regions { layout: vertical; }
    RelayStatusScreen.-content-narrow #relay_backend_area,
    RelayStatusScreen.-content-narrow #relay_local_area { width: 100%; max-width: 100%; margin: 0 0 1 0; }
    """

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if self.navigation_focused:
            return super().check_action(action, parameters)
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield WorkspaceControls("Relay status")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            yield ScrollableContainer(
                Container(
                    Static("Relay connection", id="relay_title"),
                    Static(
                        "Local listener and backend session are reported separately.",
                        id="relay_description",
                    ),
                    id="relay_heading",
                ),
                VerticalScroll(
                    Horizontal(
                        Container(
                            Static("Backend session", classes="relay_status_heading"),
                            BusyIndicator(id="relay_backend_busy"),
                            Static("Backend: loading…", id="backend_status"),
                            id="relay_backend_area", classes="relay_status_area",
                        ),
                        Container(
                            Static("This device", classes="relay_status_heading"),
                            Static("Local: loading…", id="local_status"),
                            id="relay_local_area", classes="relay_status_area",
                        ),
                        id="relay_status_regions",
                    ),
                    id="relay_card",
                ),
                Horizontal(
                    Button("Restart", id="btn_relay_restart", variant="primary"),
                    Button("Stop", id="btn_relay_stop"),
                    Button("Close", id="btn_relay_close"),
                    id="relay_actions",
                ),
                id="relay_container", classes="workspace-content",
            )
        yield Footer()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_restart(self) -> None:
        self._do_restart()

    def action_stop(self) -> None:
        self._do_stop()

    def on_mount(self) -> None:
        self._refresh_local()
        self.run_worker(
            self._refresh_backend_with_loading(), group="relay_status_read",
            exclusive=True, name="relay_modal_backend",
        )

    def _refresh_local(self) -> None:
        state = getattr(self.app, "relay_state", None)
        label = state.value if state is not None else "unknown"
        text = f"Local: [bold]{label}[/bold]"
        from servonaut.services.relay_lock import read_owner
        owner = read_owner(self.app.relay_lock_path)
        if owner.pid is not None:
            text += f" — lock owner: {owner.mode} (PID {owner.pid})"
        manager = getattr(self.app, "relay_manager", None)
        reason = getattr(manager, "last_error", None)
        if isinstance(reason, str) and reason:
            # Why it failed (for example a refused relay URL), not just "error".
            text = Content.assemble(
                Content.from_markup(text), "\n", (display_text(self.app, reason), "$text-error"),
            )
        self.query_one("#local_status", Static).update(text)

    async def _refresh_backend_with_loading(self) -> None:
        """Keep backend status visibly loading until its existing read completes."""
        # Screen-owned workers are cancelled by Textual on unmount. The
        # screen may already have closed before this coroutine first runs.
        if not self.is_attached or self not in self.app.screen_stack:
            return
        indicator = next(iter(self.query("#relay_backend_busy")), None)
        target = next(iter(self.query("#backend_status")), None)
        if indicator is None or target is None:
            return
        indicator.start("Checking backend connection…")
        try:
            await self._refresh_backend(target=target)
        finally:
            indicator.stop()

    async def _refresh_backend(self, target: Optional[Static] = None) -> None:
        """Call /api/cli/status via the existing MCP api_request plumbing."""
        def update(value: str | Content) -> None:
            if target is None:
                self.query_one("#backend_status", Static).update(value)
            elif target.is_attached and self in self.app.screen_stack:
                # Children are pruned before Textual cancels this screen's
                # workers. Do not publish into a view that has already closed.
                target.update(value)

        tools = _build_mcp_tools_for_this_app(self.app)
        if tools is None:
            update(
                "Backend: unavailable (httpx not installed)."
            )
            return
        import json
        try:
            raw = await tools.relay_status()
            payload = json.loads(raw)
        except Exception as e:  # pragma: no cover - UI safety net
            update(
                Content.assemble("Backend: error — ", display_text(self.app, str(e)))
            )
            return
        if isinstance(payload, dict) and payload.get("error"):
            update(
                Content.assemble(
                    "Backend: error — ",
                    display_text(self.app, str(payload['error'].get('message', 'unknown'))),
                )
            )
            return
        connected = payload.get("connected") if isinstance(payload, dict) else None
        last_hb = payload.get("last_heartbeat_at") if isinstance(payload, dict) else None
        clients = payload.get("client_ids") if isinstance(payload, dict) else None
        flag = "[$text-success]connected[/$text-success]" if connected else "[$text-warning]disconnected[/$text-warning]"
        parts = [Content.assemble("Backend: ", Content.from_markup(flag))]
        if last_hb:
            parts.append(Content.assemble(
                "last heartbeat ", display_text(self.app, format_time_ago(str(last_hb))),
            ))
        if clients:
            if getattr(self.app, "demo_mode", False) and getattr(self.app, "redaction_service", None):
                # A client id embeds the OS user and the machine model.
                clients = [self.app.redaction_service.redact_name(str(c)) for c in clients]
            parts.append(Content.assemble("listening: ", ", ".join(str(c) for c in clients)))
        update(Content(" · ").join(parts))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_relay_restart":
            self._do_restart()
        elif event.button.id == "btn_relay_stop":
            self._do_stop()
        elif event.button.id == "btn_relay_close":
            self.app.pop_screen()

    def _do_restart(self) -> None:
        mgr = getattr(self.app, "relay_manager", None)
        if mgr is not None:
            self.app.run_worker(
                _restart_relay(self.app, mgr),
                exclusive=True,
                name="relay_restart",
                exit_on_error=False,
            )
            self.app.notify("Relay restart requested.", severity="information")
        self.app.pop_screen()

    def _do_stop(self) -> None:
        mgr = getattr(self.app, "relay_manager", None)
        if mgr is not None:
            self.app.run_worker(mgr.stop(), exclusive=True, name="relay_stop")
            self.app.notify(
                "Relay stopped. Use `servonaut connect --bg` for a detached listener.",
                severity="information", timeout=5,
            )
        self.app.pop_screen()


async def _restart_relay(app, manager) -> None:
    """Restart the relay and report a failed start instead of dropping it."""
    result = await manager.restart()
    if result.state is RelayState.ERROR:
        app.notify(
            f"MCP relay failed to restart: {result.message}",
            severity="error",
            timeout=6,
            markup=False,
        )


def _build_mcp_tools_for_this_app(app):
    """Instantiate a ServonautTools configured from the live app services."""
    try:
        from servonaut.mcp.tools import ServonautTools
        from servonaut.mcp.guards import CommandGuard
        from servonaut.mcp.audit import AuditTrail
    except ImportError:
        return None
    cfg = app.config_manager.get()
    return ServonautTools(
        config_manager=app.config_manager,
        aws_service=app.aws_service,
        custom_server_service=app.custom_server_service,
        cache_service=app.cache_service,
        ssh_service=app.ssh_service,
        connection_service=app.connection_service,
        scp_service=app.scp_service,
        guard=CommandGuard(cfg.mcp, app.config_manager),
        audit=AuditTrail(cfg.mcp.audit_path),
        auth_service=app.auth_service,
        memory_service=getattr(app, "memory_service", None),
        shared_memory_reader=getattr(app, "shared_memory_reader", None),
    )
