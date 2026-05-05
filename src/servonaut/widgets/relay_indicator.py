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
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.reactive import reactive
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import Button, Footer, Header, Static

from servonaut.services.relay_manager import RelayState
from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar


# Enum → (dot, color, label) mapping, kept here so the indicator stays tiny.
_STATE_DISPLAY = {
    RelayState.CONNECTED: ("●", "green", "connected"),
    RelayState.CONNECTING: ("○", "yellow", "connecting…"),
    RelayState.EXTERNAL: ("●", "cyan", "external listener"),
    RelayState.NO_ENTITLEMENT: ("○", "magenta", "upgrade to connect"),
    RelayState.NOT_CONFIGURED: ("○", "red", "not configured"),
    RelayState.ERROR: ("○", "red", "error"),
    RelayState.STOPPED: ("○", "grey50", "disconnected"),
    RelayState.DISABLED: ("○", "grey50", "not logged in"),
    RelayState.SESSION_EXPIRED: ("○", "red", "session expired"),
}


def _format(state: Optional[RelayState]) -> str:
    if state is None:
        return "[grey50]○ relay[/grey50]"
    dot, color, label = _STATE_DISPLAY.get(
        state, ("○", "grey50", state.value),
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
        self.app.push_screen(RelayStatusScreen())


class RelayStatusScreen(Screen):
    """Inspect the relay connection and offer Restart / Stop actions.

    Full screen with sidebar (was previously a ModalScreen but the panel
    has too much info — and several actions — to feel like a transient
    confirmation). Pop with Escape or the Close button to return to the
    previous screen.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "restart", "Restart", show=True),
        Binding("s", "stop", "Stop", show=True),
    ]

    DEFAULT_CSS = """
    RelayStatusScreen #relay_container {
        width: 1fr;
        height: 100%;
        padding: 1 2;
        align: center middle;
        background: $surface;
    }
    RelayStatusScreen #relay_card {
        width: 80%;
        max-width: 90;
        height: auto;
        padding: 2 4;
        background: $panel;
        border: round $primary;
    }
    RelayStatusScreen #relay_title { text-style: bold; padding: 0 0 1 0; }
    RelayStatusScreen #local_status,
    RelayStatusScreen #backend_status { margin: 1 0; }
    RelayStatusScreen #relay_actions {
        height: auto;
        margin-top: 1;
        align: center middle;
    }
    RelayStatusScreen #relay_actions Button {
        margin: 0 1;
        min-width: 16;
    }
    """

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Container(
                    Static(
                        "[bold cyan]MCP relay connection[/bold cyan]",
                        id="relay_title",
                    ),
                    Static("Local:  loading…", id="local_status"),
                    Static("Backend: loading…", id="backend_status"),
                    Horizontal(
                        Button(
                            "Restart", id="btn_relay_restart", variant="primary"
                        ),
                        Button("Stop", id="btn_relay_stop"),
                        Button("Close", id="btn_relay_close"),
                        id="relay_actions",
                    ),
                    id="relay_card",
                ),
                id="relay_container",
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
        self.app.run_worker(self._refresh_backend(), exclusive=True,
                             name="relay_modal_backend")

    def _refresh_local(self) -> None:
        mgr = getattr(self.app, "relay_manager", None)
        state = getattr(self.app, "relay_state", None)
        label = state.value if state is not None else "unknown"
        text = f"Local: [bold]{label}[/bold]"
        from servonaut.services.relay_lock import read_owner, DEFAULT_LOCK_PATH
        owner = read_owner(DEFAULT_LOCK_PATH)
        if owner.pid is not None:
            text += f" — lock owner: {owner.mode} (PID {owner.pid})"
        self.query_one("#local_status", Static).update(text)

    async def _refresh_backend(self) -> None:
        """Call /api/cli/status via the existing MCP api_request plumbing."""
        tools = _build_mcp_tools_for_this_app(self.app)
        if tools is None:
            self.query_one("#backend_status", Static).update(
                "Backend: unavailable (httpx not installed)."
            )
            return
        import json
        try:
            raw = await tools.relay_status()
            payload = json.loads(raw)
        except Exception as e:  # pragma: no cover - UI safety net
            self.query_one("#backend_status", Static).update(
                f"Backend: error — {e}"
            )
            return
        if isinstance(payload, dict) and payload.get("error"):
            self.query_one("#backend_status", Static).update(
                f"Backend: error — {payload['error'].get('message', 'unknown')}"
            )
            return
        connected = payload.get("connected") if isinstance(payload, dict) else None
        last_hb = payload.get("last_heartbeat_at") if isinstance(payload, dict) else None
        clients = payload.get("client_ids") if isinstance(payload, dict) else None
        flag = "[green]connected[/green]" if connected else "[yellow]disconnected[/yellow]"
        parts = [f"Backend: {flag}"]
        if last_hb:
            parts.append(f"last heartbeat {last_hb}")
        if clients:
            parts.append(f"client_ids={clients}")
        self.query_one("#backend_status", Static).update(" · ".join(parts))

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
            self.app.run_worker(mgr.restart(), exclusive=True, name="relay_restart")
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
    )
