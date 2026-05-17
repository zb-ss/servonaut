"""SecretsListScreen — read-only list of names in the active provider.

Step 9 sub-screen reached via ``[l]`` from :class:`SecretsScreen`.

**Hard invariant** (kickoff doc §MCP boundary, audit-fix 7):
    NAMES are listed; VALUES are never read or rendered. The screen
    only calls :meth:`SecretProviderInterface.list_secrets`, never
    :meth:`get_secret`. Pinned by a test that mocks a provider whose
    ``get_secret`` raises if called.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


class SecretsListScreen(Screen):
    """Read-only listing of the active provider's secret names."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static(
                    "[bold cyan]🔐 Stored secrets[/bold cyan]",
                    id="secrets_list_title",
                ),
                Static(
                    "[dim]Names of secrets in the active provider. Values "
                    "are NEVER displayed in the TUI — fetch via the provider "
                    "directly when you need them.[/dim]",
                    id="secrets_list_subtitle",
                ),
                Static("", id="secrets_list_summary"),
                VerticalScroll(id="secrets_list_body"),
                id="secrets_list_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        self._render_loading()
        self.run_worker(
            self._load_names_worker(),
            group="secrets_list", exclusive=True,
        )

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._render_loading()
        self.run_worker(
            self._load_names_worker(),
            group="secrets_list", exclusive=True,
        )

    # ------------------------------------------------------------------
    # Render helpers
    # ------------------------------------------------------------------

    def _render_loading(self) -> None:
        body = self.query_one("#secrets_list_body", VerticalScroll)
        body.remove_children()
        body.mount(Static("[dim]Loading names…[/dim]"))
        self.query_one("#secrets_list_summary", Static).update("")

    def _render_names(self, names: List[str], provider_label: str) -> None:
        body = self.query_one("#secrets_list_body", VerticalScroll)
        body.remove_children()
        summary = self.query_one("#secrets_list_summary", Static)
        summary.update(
            f"[bold]{escape(provider_label)}[/bold] — "
            f"{len(names)} secret{'s' if len(names) != 1 else ''}",
        )
        if not names:
            body.mount(Static(
                "[dim]No secrets stored. Push one with "
                "`bws secret create` (Bitwarden) or use the provider's "
                "CLI for the active backend.[/dim]",
            ))
            return
        for name in names:
            body.mount(Static(f"  {escape(name)}"))

    def _render_error(self, message: str) -> None:
        body = self.query_one("#secrets_list_body", VerticalScroll)
        body.remove_children()
        body.mount(Static(
            f"[red]Could not list secrets:[/red] {escape(message)}\n\n"
            "Common causes:\n"
            "  - bws CLI not installed (Bitwarden).\n"
            "  - BWS_ACCESS_TOKEN env var unset.\n"
            "  - Network failure reaching the Bitwarden API."
        ))

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------

    async def _load_names_worker(self) -> None:
        """Resolve the active provider and call :meth:`list_secrets`.

        NO call to ``get_secret`` here — pinning the "names only"
        invariant. Test ``test_secrets_list_screen.py`` mocks a
        provider whose ``get_secret`` raises, so if a future refactor
        ever calls it the test trips.
        """
        auth = getattr(self.app, "auth_service", None)
        guard = getattr(self.app, "entitlement_guard", None)
        if auth is None or guard is None:
            self._render_error("Auth service not ready.")
            return
        try:
            from servonaut.services.secret_provider_resolver import (
                resolve_secret_provider,
            )
            provider = resolve_secret_provider(auth, guard)
            if provider is None:
                self._render_error(
                    "No active provider. Sign in and configure a team or "
                    "use the local store."
                )
                return
            names = await provider.list_secrets()
            self._render_names(names, provider.provider_name)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list secrets: %s", exc)
            self._render_error(str(exc))
