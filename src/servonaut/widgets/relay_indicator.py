"""Compact status indicator for the TUI's relay connection.

One tiny widget whose label reflects the enum from ``RelayManager.state``.
Lives in the sidebar. Clicking opens a :class:`RelayStatusModal` that shows
the backend's view alongside the local view and exposes Restart / Stop
actions.
"""
from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.widgets import Button, Static

from servonaut.services.relay_manager import RelayState


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

    def on_click(self) -> None:
        self.app.push_screen(RelayStatusModal())


class RelayStatusModal(ModalScreen[None]):
    """Inspect the relay connection and offer Restart / Stop actions."""

    DEFAULT_CSS = """
    RelayStatusModal {
        align: center middle;
    }
    RelayStatusModal > Vertical {
        width: 70;
        height: auto;
        padding: 1 2;
        background: $panel;
        border: round $primary;
    }
    RelayStatusModal #backend_status,
    RelayStatusModal #local_status { margin: 1 0; }
    RelayStatusModal .modal_title { text-style: bold; }
    RelayStatusModal Button { margin: 0 1 0 0; }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("[bold cyan]MCP relay connection[/bold cyan]",
                         classes="modal_title")
            yield Static("Local:  loading…", id="local_status")
            yield Static("Backend: loading…", id="backend_status")
            yield Static("", id="modal_footer")
            yield Button("Restart", id="btn_relay_restart", variant="primary")
            yield Button("Stop", id="btn_relay_stop")
            yield Button("Close", id="btn_relay_close")

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
            mgr = getattr(self.app, "relay_manager", None)
            if mgr is not None:
                self.app.run_worker(mgr.restart(), exclusive=True, name="relay_restart")
                self.app.notify("Relay restart requested.", severity="information")
            self.dismiss()
        elif event.button.id == "btn_relay_stop":
            mgr = getattr(self.app, "relay_manager", None)
            if mgr is not None:
                self.app.run_worker(mgr.stop(), exclusive=True, name="relay_stop")
                self.app.notify(
                    "Relay stopped. Use `servonaut connect --bg` for a detached listener.",
                    severity="information", timeout=5,
                )
            self.dismiss()
        elif event.button.id == "btn_relay_close":
            self.dismiss()


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
