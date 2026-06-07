"""SecretsScreen — in-TUI control for the secrets-management feature.

Part of the secrets-management feature.
Five state variants share one screen layout; the body card swaps based
on :class:`SecretsStatusSummary`.

Read-only on first render. Background workers handle the only mutating
actions: refresh-from-server, clear-cache, install-bws. Listing
stored secrets is a sub-screen so it doesn't crowd the status card.

Pinned design invariants:

- Secret VALUES never appear on this screen or any of its sub-screens.
  Only NAMES — see :class:`SecretsListScreen`. Pinned by a test that
  asserts no rendered string ever contains the values returned by a
  mocked provider.
- All user-controlled strings (cached project IDs, team slugs from the
  server) are passed through ``rich.markup.escape`` before being
  interpolated into Rich markup.
- Workers carry ``group="secrets_*"`` so the relay/AI worker queue
  doesn't share group lifecycle with this screen's reactive UI.
"""
from __future__ import annotations

import logging
import webbrowser
from typing import Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.services.secrets_status import (
    SecretsStatusSummary,
    compute_secrets_status,
    format_relative_age,
)
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


# URLs we deep-link to from the UI. Kept here (not hardcoded across
# the file) so a future move of the pricing page is a one-line patch.
# Aligns with the "no hardcoded user-facing values" principle — these
# are app-level pointers, not per-render strings.
_UPGRADE_URL = "https://servonaut.dev/pricing"
_DOCS_URL = "https://servonaut.dev/docs/secrets-management"
_TEAM_SETTINGS_URL_TEMPLATE = "https://servonaut.dev/account/teams/{slug}/secrets"


class SecretsScreen(Screen):
    """Secrets-management status + control panel.

    Same shape as :class:`MemorySyncSetupScreen`: persistent Sidebar +
    a body container whose contents adapt to the current state. No
    modal usage at the top level — sub-screens (list / confirm
    modal) get pushed on top when invoked.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("l", "list_secrets", "List", show=True),
        Binding("c", "clear_cache", "Clear", show=False),
        Binding("o", "open_team_settings", "Open settings", show=False),
        Binding("u", "open_upgrade", "Upgrade", show=False),
        Binding("i", "install_bws", "Install bws", show=False),
        Binding("s", "open_login", "Sign in", show=False),
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
            yield Container(
                Static(
                    "🔐 Secrets management",
                    id="secrets_title",
                ),
                Static(
                    "Centralise SSH keys and named secrets behind a "
                    "pluggable provider — Bitwarden / local store. The "
                    "CLI checks the active provider first, falls back to "
                    "~/.ssh.",
                    id="secrets_subtitle",
                ),
                # Pill-style status indicator at the top of the body.
                Static("", id="secrets_status_pill"),
                # The body swaps content based on state.
                VerticalScroll(id="secrets_body"),
                id="secrets_container",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Card-building helpers
    # ------------------------------------------------------------------

    def _card(
        self,
        title: str,
        *children,
        primary: bool = False,
        warning: bool = False,
    ) -> Container:
        """Build a rounded-border card with a title and stacked children."""
        classes = "secrets_card"
        if primary:
            classes += " secrets_card_primary"
        elif warning:
            classes += " secrets_card_warning"
        body = Vertical(
            *children,
            classes="secrets_card_body",
        )
        return Container(
            Static(title, classes="secrets_card_title"),
            body,
            classes=classes,
        )

    def _kv_grid(self, *rows: tuple[str, str]) -> Vertical:
        """Build a label/value grid. ``value`` may contain rich markup."""
        return Vertical(
            *[
                Horizontal(
                    Static(label, classes="secrets_kv_label"),
                    Static(value, classes="secrets_kv_value"),
                    classes="secrets_kv_row",
                )
                for label, value in rows
            ],
            classes="secrets_kv_grid",
        )

    def _actions(self, *items: tuple[str, str]) -> Vertical:
        """Build a stack of ``key  label`` action rows."""
        return Vertical(
            *[
                Horizontal(
                    Static(key, classes="secrets_action_key"),
                    Static(label, classes="secrets_action_label"),
                    classes="secrets_action_row",
                )
                for key, label in items
            ],
            classes="secrets_actions",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._render_state()

    # ------------------------------------------------------------------
    # State render
    # ------------------------------------------------------------------

    def _summary(self) -> Optional[SecretsStatusSummary]:
        """Compute the snapshot the screen renders from.

        Returns ``None`` when the necessary services aren't wired
        yet (very early app boot or a screen instantiated in
        isolation in tests).
        """
        auth = getattr(self.app, "auth_service", None)
        guard = getattr(self.app, "entitlement_guard", None)
        if auth is None or guard is None:
            return None
        try:
            return compute_secrets_status(auth, guard)
        except Exception as exc:  # noqa: BLE001 — defensive
            logger.exception(
                "Failed to compute secrets status; "
                "rendering an error-state body: %s", exc,
            )
            return None

    def _render_state(self) -> None:
        """Repaint the status pill + body for the current snapshot."""
        body = self.query_one("#secrets_body", VerticalScroll)
        pill = self.query_one("#secrets_status_pill", Static)
        body.remove_children()

        summary = self._summary()
        if summary is None:
            pill.update("[bold red]✕ Unavailable[/bold red]")
            body.mount(self._card(
                "Unavailable",
                Static(
                    "Could not read the secrets-management state. "
                    "Check [dim]~/.servonaut/logs/servonaut.log[/dim] "
                    "for details.",
                ),
                warning=True,
            ))
            return

        if not summary.authenticated:
            self._render_unauthenticated(pill, body)
            return
        if not summary.entitled_secrets_management:
            self._render_free_tier(pill, body, summary)
            return
        if summary.active_provider_name == "bitwarden":
            self._render_bitwarden(pill, body, summary)
            return
        if summary.active_provider_name == "local":
            self._render_local(pill, body, summary)
            return
        # Fallback — resolver returned None but the user IS entitled
        # (e.g. transient resolver hiccup). Surface what we can.
        pill.update("[bold yellow]⚠ No active provider[/bold yellow]")
        body.mount(self._card(
            "No active provider",
            Static(
                "SSH falls back to [dim]~/.ssh[/dim] discovery. "
                "Run [bold]Refresh[/bold] to re-read your team's "
                "configuration.",
            ),
            warning=True,
        ))
        body.mount(self._card(
            "Actions",
            self._actions(
                ("r", "Refresh from server"),
            ),
        ))

    # --- variants -----------------------------------------------------

    def _render_unauthenticated(self, pill: Static, body: VerticalScroll) -> None:
        pill.update("[bold yellow]⚪ Not signed in[/bold yellow]")
        body.mount(self._card(
            "Sign in required",
            Static(
                "Sign in to your Servonaut account to manage SSH keys and "
                "named secrets across your fleet.",
            ),
            primary=True,
        ))
        body.mount(self._card(
            "Actions",
            self._actions(
                ("s", "Open Login"),
                ("o", "Open docs"),
            ),
        ))

    def _render_free_tier(
        self, pill: Static, body: VerticalScroll, s: SecretsStatusSummary,
    ) -> None:
        pill.update("[bold yellow]⚠ Upgrade required[/bold yellow]")
        body.mount(self._card(
            "Upgrade required",
            Static(
                "Secrets management is available on the Solo and Teams plans.",
            ),
            Static(
                "  • [bold]Solo[/bold] — local-only secret storage with "
                "optional Bitwarden integration.",
            ),
            Static(
                "  • [bold]Teams[/bold] — shared team-wide secret pools "
                "managed by your admin.",
            ),
            Static(
                f"[dim]{escape(s.entitlement_reason)}[/dim]",
                classes="secrets_card_note",
            ),
            primary=True,
        ))
        body.mount(self._card(
            "Actions",
            self._actions(
                ("u", "Open Pricing"),
                ("o", "Open docs"),
            ),
        ))

    def _render_bitwarden(
        self, pill: Static, body: VerticalScroll, s: SecretsStatusSummary,
    ) -> None:
        if s.has_health_warning:
            pill.update("[bold yellow]⚠ Bitwarden — needs attention[/bold yellow]")
        else:
            pill.update("[bold green]● Bitwarden — active[/bold green]")
        # All server-supplied strings escaped before interpolation.
        proj = escape(s.bitwarden_project_id or "(none)")
        env_var = escape(s.bitwarden_token_env_var or "(none)")
        token_state = "[green]set[/green]" if s.bws_token_set else "[red]NOT SET[/red]"
        bws_state = (
            escape(s.bws_path) if s.bws_path else "[red]not installed[/red]"
        )
        fetched_age = format_relative_age(s.cache_fetched_at)

        body.mount(self._card(
            "Provider",
            self._kv_grid(
                ("Active provider", "Bitwarden"),
                ("Project", f"[dim]{proj}[/dim]"),
                ("Token env var", f"{env_var} ({token_state})"),
                ("bws CLI", bws_state),
                ("Last fetched", fetched_age),
            ),
            primary=not s.has_health_warning,
            warning=s.has_health_warning,
        ))
        if s.has_health_warning:
            body.mount(self._card(
                "Needs attention",
                Static(
                    "[yellow]The CLI is falling back to ~/.ssh discovery "
                    "until bws is installed and the token env var is set."
                    "[/yellow]",
                ),
                warning=True,
            ))
        body.mount(self._card(
            "Actions",
            self._actions(
                ("r", "Refresh from server"),
                ("l", "List stored secrets (names only)"),
                ("o", "Open team settings (web)"),
                ("i", "Install / re-install bws"),
                ("c", "Clear cached config"),
            ),
        ))

    def _render_local(
        self, pill: Static, body: VerticalScroll, s: SecretsStatusSummary,
    ) -> None:
        pill.update("[bold green]● Local — active[/bold green]")
        path = escape(s.local_secrets_path or "~/.servonaut/secrets.json")
        children = [
            self._kv_grid(
                ("Active provider", "Local"),
                ("Store", f"[dim]{path}[/dim] (mode 0600)"),
            ),
        ]
        if not s.entitled_secrets_team_shared:
            children.append(Static(
                "[dim]Team-shared secrets (Bitwarden / future Vault) "
                "require a Teams plan.[/dim]",
                classes="secrets_card_note",
            ))
        body.mount(self._card("Provider", *children, primary=True))
        body.mount(self._card(
            "Actions",
            self._actions(
                ("l", "List stored secrets (names only)"),
                ("u", "Upgrade for team-shared secrets"),
                ("o", "Open docs"),
            ),
        ))

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self.run_worker(
            self._refresh_worker(),
            group="secrets_refresh", exclusive=True,
            name="secrets_refresh",
        )

    async def _refresh_worker(self) -> None:
        """Re-fetch the team's SecretsConfig from the API, then repaint."""
        auth = getattr(self.app, "auth_service", None)
        api_client = getattr(self.app, "api_client", None)
        if auth is None or api_client is None:
            self.notify(
                "Refresh unavailable — log in first.",
                severity="warning",
            )
            return
        slug = await auth.active_team_slug()
        if not slug:
            self.notify(
                "No active team — Solo users get the local store. "
                "Refresh skipped.",
                severity="information",
            )
            self._render_state()
            return
        try:
            from servonaut.services.secret_provider_resolver import (
                fetch_and_apply_secrets_config,
            )
            ok = await fetch_and_apply_secrets_config(auth, api_client, slug)
            if ok:
                self.notify("Secrets config refreshed.", severity="information")
            else:
                self.notify(
                    "Refresh failed (transient). Existing cache retained.",
                    severity="warning",
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Secrets refresh failed: %s", exc)
            self.notify(
                f"Refresh failed: {exc}",
                severity="error", markup=False,
            )
        finally:
            # Re-render the provider summary regardless — clears any
            # stale UI if the cache transitioned to LocalProvider.
            self._refresh_secret_provider_binding()
            self._render_state()

    def _refresh_secret_provider_binding(self) -> None:
        """Re-run :func:`resolve_secret_provider` and re-bind ssh_service.

        After ``fetch_and_apply`` mutates the cached config, the
        currently-bound provider on :class:`SSHService` may be stale
        (e.g. cached Bitwarden → cache cleared → fall back to
        LocalProvider on next SSH connect). Refreshing the binding
        keeps the in-process state consistent without restarting.
        """
        try:
            from servonaut.services.secret_provider_resolver import (
                resolve_secret_provider,
            )
            auth = self.app.auth_service
            guard = self.app.entitlement_guard
            ssh_service = self.app.ssh_service
            if not all([auth, guard, ssh_service]):
                return
            new_provider = resolve_secret_provider(auth, guard)
            ssh_service.set_secret_provider(new_provider)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to rebind ssh_service provider: %s", exc)

    def action_list_secrets(self) -> None:
        from servonaut.screens.secrets_list import SecretsListScreen
        self.app.push_screen(SecretsListScreen())

    def action_clear_cache(self) -> None:
        from servonaut.screens.secrets_clear_modal import ConfirmClearCacheModal
        self.app.push_screen(
            ConfirmClearCacheModal(),
            self._handle_clear_cache_result,
        )

    def _handle_clear_cache_result(self, confirmed: Optional[bool]) -> None:
        if not confirmed:
            return
        auth = getattr(self.app, "auth_service", None)
        if auth is None:
            return
        auth.clear_secrets_cache()
        self.notify("Secrets cache cleared.", severity="information")
        self._refresh_secret_provider_binding()
        self._render_state()

    def action_open_team_settings(self) -> None:
        self.run_worker(
            self._open_team_settings_worker(),
            group="secrets_open_url", exclusive=True,
        )

    async def _open_team_settings_worker(self) -> None:
        auth = getattr(self.app, "auth_service", None)
        if auth is None:
            return
        slug = await auth.active_team_slug()
        if not slug:
            self.notify(
                "No active team — nothing to open.",
                severity="warning",
            )
            return
        url = _TEAM_SETTINGS_URL_TEMPLATE.format(slug=slug)
        webbrowser.open(url)
        self.notify(
            f"Opened {url} in your browser.",
            severity="information", markup=False,
        )

    def action_open_upgrade(self) -> None:
        webbrowser.open(_UPGRADE_URL)
        self.notify(f"Opened {_UPGRADE_URL}", markup=False)

    def action_install_bws(self) -> None:
        self.run_worker(
            self._install_bws_worker(),
            group="secrets_install", exclusive=True,
        )

    async def _install_bws_worker(self) -> None:
        """Spawn `servonaut secrets install bws --yes` as a subprocess.

        Reuses the CLI command rather than re-implementing the install
        flow inside the TUI. Output streams to the user's notification
        area so they see progress. The TUI doesn't try to capture
        full installer output — that's the CLI's job and the user can
        re-run from a shell for verbose output if needed.
        """
        import asyncio
        try:
            proc = await asyncio.create_subprocess_exec(
                "servonaut", "secrets", "install", "bws", "--yes",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                self.notify(
                    "bws installed. Refresh ([r]) to re-evaluate state.",
                    severity="information",
                )
            else:
                tail = stdout.decode("utf-8", errors="replace")[-300:]
                self.notify(
                    f"bws install failed (exit {proc.returncode}). "
                    f"Tail: {tail}",
                    severity="error", markup=False,
                )
        except FileNotFoundError:
            self.notify(
                "`servonaut` not on PATH for subprocess invocation. "
                "Install via pipx and retry.",
                severity="error",
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("bws install worker failed: %s", exc)
            self.notify(
                f"Install error: {exc}",
                severity="error", markup=False,
            )
        finally:
            self._render_state()

    def action_open_login(self) -> None:
        from servonaut.screens.login import LoginScreen
        self.app.switch_screen(LoginScreen())
