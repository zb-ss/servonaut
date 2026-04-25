"""Memory Export screen — compliance-grade export and verification of server memory.

Tier-gated on ``memory_compliance_export``.  Allows specifying a date range,
kicking off an export, and verifying the resulting tarball signature.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


class MemoryExportScreen(Screen):
    """Screen for exporting memory archives with Ed25519 signature verification.

    Tier-gated on ``memory_compliance_export``.  Provides from/to date inputs,
    an export button, and in-place status updates after verification.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("ctrl+s", "start_export", "Export", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield VerticalScroll(
                Container(
                    Static(
                        "[bold cyan]Compliance Memory Export[/bold cyan]",
                        id="export-title",
                    ),
                    Static(
                        "[dim]Export a signed archive of all memory envelopes for audit "
                        "or compliance purposes.  The archive is verified with an "
                        "Ed25519 signature from the server.[/dim]",
                        id="export-description",
                    ),
                    Container(
                        Label("From date (ISO-8601, optional)"),
                        Input(
                            placeholder="e.g. 2024-01-01T00:00:00Z",
                            id="export-from-input",
                        ),
                        classes="export-field-row",
                    ),
                    Container(
                        Label("To date (ISO-8601, optional)"),
                        Input(
                            placeholder="e.g. 2024-12-31T23:59:59Z",
                            id="export-to-input",
                        ),
                        classes="export-field-row",
                    ),
                    Static("", id="export-status"),
                    Horizontal(
                        Button("ctrl+s. Start Export", variant="primary", id="btn-export-start"),
                        Button("Back", variant="default", id="btn-export-back"),
                        id="export-btn-row",
                    ),
                    id="export-container",
                ),
                id="export-scroll",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Mount
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        auth = getattr(self.app, "auth_service", None)
        if auth and not auth.has_feature("memory_compliance_export"):
            from servonaut.widgets.upsell_modal import UpsellModal
            self.app.push_screen(UpsellModal("memory_compliance_export"))

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_start_export(self) -> None:
        export_service = getattr(self.app, "export_service", None)
        status = self.query_one("#export-status", Static)
        if export_service is None:
            status.update("[red]Export service not available.[/red]")
            return
        self.run_worker(
            self._do_export(),
            group="memory_export",
            name="export_run",
        )

    async def _do_export(self) -> None:
        export_service = getattr(self.app, "export_service", None)
        status = self.query_one("#export-status", Static)
        if export_service is None:
            return
        from_val = self.query_one("#export-from-input", Input).value.strip() or None
        to_val = self.query_one("#export-to-input", Input).value.strip() or None
        try:
            status.update("[yellow]Starting export…[/yellow]")
            tarball_path = await export_service.export(from_=from_val, to_=to_val)
            status.update(f"[yellow]Verifying signature: {tarball_path}…[/yellow]")
            valid = await export_service.verify_export(tarball_path)
            if valid:
                status.update(
                    f"[green]Export verified: {tarball_path}[/green]"
                )
                self.app.notify(f"Export saved and verified: {tarball_path}")
            else:
                status.update(
                    f"[red]Signature INVALID: {tarball_path}[/red]"
                )
                self.app.notify(
                    "Export signature verification FAILED — archive may be corrupt.",
                    severity="error",
                )
        except Exception as exc:
            logger.error("Export failed: %s", exc)
            from rich.markup import escape as _esc
            status.update(f"[red]Export failed: {_esc(str(exc))}[/red]")
            self.app.notify(f"Export failed: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Button handler
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-export-start":
            self.action_start_export()
        elif event.button.id == "btn-export-back":
            self.action_back()
