"""Compact view switcher shared by Fleet memory, Memory Sync, Drift, and Export."""
from __future__ import annotations

from textual.widgets import Button

from servonaut.widgets.action_button import ActionButton, ActionRow


_MEMORY_VIEWS: tuple[tuple[str, str, str], ...] = (
    ("fleet", "Fleet", "Switch to Fleet memory overview"),
    ("sync", "Sync", "Manage encrypted Memory Sync setup and status"),
    ("drift", "Drift", "Inspect configuration drift events across the fleet"),
    ("export", "Export", "Export a signed compliance archive of server memory"),
)


class MemoryViewsBar(ActionRow):
    """Single-row view bar linking the four memory screens without extra sidebar slots."""

    DEFAULT_CSS = """
    MemoryViewsBar {
        height: auto;
        width: auto;
        margin: 0 0 1 0;
        padding: 0;
        background: transparent;
    }

    MemoryViewsBar > ActionButton.-textual-compact {
        margin: 0 1 0 0;
        padding: 0 1;
    }

    MemoryViewsBar > ActionButton.-current-view,
    MemoryViewsBar > ActionButton.-current-view:hover,
    MemoryViewsBar > ActionButton.-current-view:focus {
        background: $primary;
        color: $background;
        text-style: bold;
    }

    MemoryViewsBar > ActionButton.-current-view:ansi,
    MemoryViewsBar > ActionButton.-current-view:ansi:hover,
    MemoryViewsBar > ActionButton.-current-view:ansi:focus {
        background: $surface;
        color: $foreground;
        text-style: bold reverse;
    }
    """

    def __init__(self, active: str = "fleet", **kwargs) -> None:
        self._active = active
        kwargs.setdefault("id", "memory_views")
        buttons = [
            ActionButton(
                label,
                compact=True,
                id=f"memory_view_{key}",
                classes="-current-view" if key == active else None,
                tooltip=tip,
            )
            for key, label, tip in _MEMORY_VIEWS
        ]
        super().__init__(*buttons, prefer_one_line=True, **kwargs)

    def on_mount(self) -> None:
        super().on_mount()
        self.refresh_gates()

    def refresh_gates(self) -> None:
        """Show Drift and Export tabs when entitled and sync-configured (or active)."""
        app = getattr(self, "app", None)
        auth = getattr(app, "auth_service", None)
        sync_svc = getattr(app, "memory_sync_service", None)
        is_configured = bool(sync_svc and getattr(sync_svc, "is_configured", False))
        gates = {
            "drift": bool(auth and auth.has_feature("memory_drift") and is_configured),
            "export": bool(
                auth and auth.has_feature("memory_compliance_export") and is_configured
            ),
        }
        for key, allowed in gates.items():
            try:
                btn = self.query_one(f"#memory_view_{key}", Button)
                btn.display = allowed or (self._active == key)
            except Exception:
                pass
        self.request_fit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if not btn_id.startswith("memory_view_"):
            return
        event.stop()
        target = btn_id.removeprefix("memory_view_")
        if target == self._active:
            return
        if target == "fleet":
            from servonaut.screens.fleet_memory import FleetMemoryScreen

            self.app.switch_screen(FleetMemoryScreen())
        elif target == "sync":
            from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen

            self.app.switch_screen(MemorySyncSetupScreen())
        elif target == "drift":
            from servonaut.screens.memory_drift import MemoryDriftScreen

            self.app.switch_screen(MemoryDriftScreen())
        elif target == "export":
            from servonaut.screens.memory_export import MemoryExportScreen

            self.app.switch_screen(MemoryExportScreen())
