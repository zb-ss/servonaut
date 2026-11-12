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
from textual.widgets import Button, Footer, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.services.secrets_status import (
    SecretsStatusSummary,
    compute_secrets_status,
    format_relative_age,
)
from servonaut.widgets.action_button import ActionButton, ActionRole, ActionRow
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

logger = logging.getLogger(__name__)


# URLs we deep-link to from the UI. Kept here (not hardcoded across
# the file) so a future move of the pricing page is a one-line patch.
# Aligns with the "no hardcoded user-facing values" principle — these
# are app-level pointers, not per-render strings.
_UPGRADE_URL = "https://servonaut.dev/pricing"
_DOCS_URL = "https://servonaut.dev/docs/secrets-management"
_TEAM_SETTINGS_URL_TEMPLATE = "https://servonaut.dev/account/teams/{slug}/secrets"


class SecretsScreen(WorkspaceScreen):
    """Secrets-management status + control panel.

    Same shape as :class:`MemorySyncSetupScreen`: persistent Sidebar +
    a body container whose contents adapt to the current state. No
    modal usage at the top level — sub-screens (list / confirm
    modal) get pushed on top when invoked.
    """

    CHAT_REFLOW = True
    # Body and card padding, border and scrollbar (14) plus the 22-column
    # key/value label and a readable value beside the chat column.
    CHAT_MIN_CONTENT_WIDTH = 60
    # Below this width the key/value rows stack and the action row wraps.
    CONTENT_NARROW_WIDTH = 96
    # Short terminals get tighter cards, so the hub fits without scrolling.
    VERTICAL_BREAKPOINTS = [(0, "-short"), (40, "-tall")]

    # Compact words for a row that is too narrow for the full ones, by label.
    _ACTION_SHORT = {
        "Guided Bitwarden setup": "Set up Bitwarden",
        "Set up Bitwarden": "Set up Bitwarden",
        "DB-vault coverage": "DB coverage",
        "Refresh from server": "Refresh",
        "List stored secrets": "List secrets",
        "Open team settings": "Open settings",
        "Install bws": "Install bws",
        "Clear cached config": "Clear cache",
        "Upgrade for team secrets": "Upgrade",
    }
    _ACTION_TIPS = {
        "Guided Bitwarden setup": "Pick a project and test the connection",
        "Set up Bitwarden": "Pick a project and test the connection",
        "DB-vault coverage": "See which servers are stored",
        "List stored secrets": "Names only; values stay hidden",
        "Open team settings": "Opens the team settings on the web",
        "Open docs": "Opens the documentation in your browser",
        "Open pricing": "Opens the pricing page in your browser",
        "Install bws": "Install or re-install the Bitwarden Secrets CLI",
        "Upgrade for team secrets": "Opens the pricing page in your browser",
    }
    _ACTION_NAMES = {
        "r": "refresh", "l": "list_secrets", "c": "clear_cache",
        "o": "open_team_settings", "u": "open_upgrade", "i": "install_bws",
        "g": "guided_setup", "v": "db_coverage", "s": "open_login",
    }

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("l", "list_secrets", "List", show=True),
        Binding("c", "clear_cache", "Clear", show=False),
        Binding("o", "open_team_settings", "Open settings", show=False),
        Binding("u", "open_upgrade", "Upgrade", show=False),
        Binding("i", "install_bws", "Install bws", show=False),
        Binding("g", "guided_setup", "Setup", show=True),
        Binding("v", "db_coverage", "Coverage", show=True),
        Binding("s", "open_login", "Sign in", show=False),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if self.navigation_focused:
            return super().check_action(action, parameters)
        return check_action_passthrough(self, action)

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield WorkspaceControls("Secrets")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            yield Container(
                Vertical(
                    Horizontal(
                        Static("Secrets management", id="secrets_title", classes="screen-title"),
                        Static("", id="secrets_status_pill"),
                        id="secrets_heading_row",
                    ),
                    Static(
                        "Check your active provider, manage its cache, or browse secret names. "
                        "Secret values stay hidden.",
                        id="secrets_subtitle",
                        classes="screen-description",
                    ),
                    classes="secrets_overview",
                ),
                # The body swaps content based on state.
                VerticalScroll(id="secrets_body"),
                id="secrets_container",
                classes="workspace-content",
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
        if any(child.has_class("secrets_actions") for child in children):
            classes += " secrets_card_actions"
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

    def _actions(self, *items: tuple[str, str]) -> ActionRow:
        """One standard button per action, each showing its own hotkey."""
        return ActionRow(
            *[
                ActionButton(
                    label, key, role=self._action_role(index, key),
                    short=self._ACTION_SHORT.get(label),
                    tooltip=self._ACTION_TIPS.get(label, label), id=f"secrets_action_{key}",
                    classes="secrets_action",
                )
                for index, (key, label) in enumerate(items)
            ],
            keep_hints=True,
            classes="secrets_actions",
        )

    @staticmethod
    def _action_role(index: int, key: str) -> ActionRole:
        """The first action leads; clearing the cache is the one risky step."""
        if key == "c":
            return "warning"
        return "primary" if index == 0 else "default"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button = event.button
        if not button.has_class("secrets_action") or button.id is None:
            return
        name = self._ACTION_NAMES.get(button.id.removeprefix("secrets_action_"))
        if name is not None:
            getattr(self, f"action_{name}")()

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
        """Repaint the status pill + body, then fit the rebuilt action rows."""
        self._mounting = []
        self._render_cards()
        self.call_later(self._fit_when_mounted, list(self._mounting))

    def _mount_card(self, body: VerticalScroll, card: Container) -> None:
        self._mounting.append(body.mount(card))

    async def _fit_when_mounted(self, mounting: list) -> None:
        """Fit each rebuilt action row once its buttons exist.

        A new row can be sized before its buttons are mounted, so it would
        otherwise keep the unwrapped layout and run past the right edge.
        """
        for pending in mounting:
            await pending
        for row in self.query(ActionRow):
            row.fit()

    def _render_cards(self) -> None:
        """Repaint the status pill + body for the current snapshot."""
        body = self.query_one("#secrets_body", VerticalScroll)
        pill = self.query_one("#secrets_status_pill", Static)
        body.remove_children()

        summary = self._summary()
        if summary is None:
            pill.update("[bold $text-error]✕ Unavailable[/bold $text-error]")
            self._mount_card(body, self._card(
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
        pill.update("[bold $text-warning]⚠ No active provider[/bold $text-warning]")
        self._mount_card(body, self._card(
            "No active provider",
            Static(
                "SSH falls back to [dim]~/.ssh[/dim] discovery. "
                "Run [bold]Refresh[/bold] to re-read your team's "
                "configuration.",
            ),
            warning=True,
        ))
        self._mount_card(body, self._card(
            "Actions",
            self._actions(
                ("r", "Refresh from server"),
            ),
        ))

    # --- variants -----------------------------------------------------

    def _render_unauthenticated(self, pill: Static, body: VerticalScroll) -> None:
        pill.update("[bold $text-warning]⚪ Not signed in[/bold $text-warning]")
        self._mount_card(body, self._card(
            "Sign in required",
            Static(
                "Sign in to your Servonaut account to manage SSH keys and "
                "named secrets across your fleet.",
            ),
            primary=True,
        ))
        self._mount_card(body, self._card(
            "Actions",
            self._actions(
                ("s", "Open login"),
                ("o", "Open docs"),
            ),
        ))

    def _render_free_tier(
        self, pill: Static, body: VerticalScroll, s: SecretsStatusSummary,
    ) -> None:
        pill.update("[bold $text-warning]⚠ Upgrade required[/bold $text-warning]")
        self._mount_card(body, self._card(
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
        self._mount_card(body, self._card(
            "Actions",
            self._actions(
                ("u", "Open pricing"),
                ("o", "Open docs"),
            ),
        ))

    @staticmethod
    def _scope_suffix(s: SecretsStatusSummary) -> str:
        """"(team)" / "(personal)" / "" from the config source.

        Tells the operator whether the active config came from a team
        (admin-managed) or their personal ``/me`` config — the precedence
        winner. Empty when no server config is in play (LocalProvider
        default).
        """
        if s.config_source == "team":
            return " (team)"
        if s.config_source == "user":
            return " (personal)"
        return ""

    def _render_bitwarden(
        self, pill: Static, body: VerticalScroll, s: SecretsStatusSummary,
    ) -> None:
        scope = self._scope_suffix(s)
        if s.has_health_warning:
            pill.update(
                f"[bold $text-warning]⚠ Bitwarden{scope} — needs attention[/bold $text-warning]"
            )
        else:
            pill.update(f"[bold $text-success]● Bitwarden{scope} — active[/bold $text-success]")
        # All server-supplied strings escaped before interpolation.
        proj = escape(s.bitwarden_project_id or "(none)")
        env_var = escape(s.bitwarden_token_env_var or "(none)")
        token_state = "[$text-success]set[/$text-success]" if s.bws_token_set else "[$text-error]NOT SET[/$text-error]"
        bws_state = (
            escape(s.bws_path) if s.bws_path else "[$text-error]not installed[/$text-error]"
        )
        fetched_age = format_relative_age(s.cache_fetched_at)

        project_cell = f"[dim]{proj}[/dim]"
        if s.project_id_invalid:
            project_cell = f"[$text-error]{proj} — not a valid project UUID[/$text-error]"

        rows = [
            ("Active provider", f"Bitwarden{self._scope_suffix(s)}"),
            ("Project", project_cell),
            ("Token env var", f"{env_var} ({token_state})"),
            ("bws CLI", bws_state),
            ("Last fetched", fetched_age),
        ]
        if s.shadowed_user_project_id:
            rows.insert(2, (
                "Personal (shadowed)",
                f"[dim]{escape(s.shadowed_user_project_id)}[/dim] "
                "[$text-warning]— hidden by team config[/$text-warning]",
            ))
        if s.team_config_broken and s.broken_team_project_id:
            # A broken team config was skipped in favour of this (personal)
            # config — show the team id that's being ignored.
            rows.insert(2, (
                "Team (ignored)",
                f"[$text-error]{escape(s.broken_team_project_id)}[/$text-error] "
                "[$text-warning]— invalid, using your personal config[/$text-warning]",
            ))

        self._mount_card(body, self._card(
            "Provider",
            self._kv_grid(*rows),
            primary=not s.has_health_warning,
            warning=s.has_health_warning,
        ))
        if s.has_health_warning:
            problems = []
            if s.project_id_invalid:
                problems.append(
                    "the configured project id is not a valid UUID (looks "
                    "like a placeholder) — fix it in the team settings (o) "
                    "or clear the cached config (c) to fall back to your "
                    "personal setup"
                )
            if s.team_config_broken:
                problems.append(
                    "the team config's project id is invalid and is being "
                    "ignored — fix it in the team settings (o), or it will "
                    "keep re-appearing on refresh"
                )
            if s.bws_path is None:
                problems.append("bws is not installed (i)")
            if not s.bws_token_set:
                problems.append("the token env var is not set")
            # If the active bitwarden config is itself usable (only the team
            # config is broken and it was skipped), we are NOT falling back to
            # ~/.ssh — the personal config still resolves secrets.
            usable = (
                s.active_provider_name == "bitwarden"
                and not s.project_id_invalid
                and s.bws_path is not None
                and s.bws_token_set
            )
            lead = (
                "Using your personal config — attention: " if usable
                else "The CLI is falling back to ~/.ssh discovery: "
            )
            self._mount_card(body, self._card(
                "Needs attention",
                Static("[$text-warning]" + lead + "; ".join(problems) + ".[/$text-warning]"),
                warning=True,
            ))
        self._mount_card(body, self._card(
            "Actions",
            self._actions(
                ("g", "Guided Bitwarden setup"),
                ("v", "DB-vault coverage"),
                ("r", "Refresh from server"),
                ("l", "List stored secrets"),
                ("o", "Open team settings"),
                ("i", "Install bws"),
                ("c", "Clear cached config"),
            ),
        ))

    def _render_local(
        self, pill: Static, body: VerticalScroll, s: SecretsStatusSummary,
    ) -> None:
        if s.project_id_invalid:
            # A broken Bitwarden config forced this fallback — signal it in the
            # pill rather than reading as a clean, healthy Local setup.
            pill.update(
                "[bold $text-warning]⚠ Local (fallback) — Bitwarden config needs "
                "attention[/bold $text-warning]"
            )
        else:
            pill.update(
                f"[bold $text-success]● Local{self._scope_suffix(s)} — active[/bold $text-success]"
            )
        from servonaut.services.ssh_host_keys import home_relative

        path = escape(home_relative(s.local_secrets_path or "~/.servonaut/secrets.json"))
        children = [
            self._kv_grid(
                ("Active provider", f"Local{self._scope_suffix(s)}"),
                ("Store", f"[dim]{path}[/dim] (mode 0600)"),
            ),
        ]
        if not s.entitled_secrets_team_shared:
            children.append(Static(
                "[dim]Team-shared secrets (Bitwarden / future Vault) "
                "require a Teams plan.[/dim]",
                classes="secrets_card_note",
            ))
        self._mount_card(body, self._card("Provider", *children, primary=True))
        if s.project_id_invalid:
            # The cached config wanted Bitwarden but its project id is
            # unusable (placeholder / malformed) — the resolver fell back
            # to the local store. Say so instead of a clean bill of health.
            invalid_id = escape(s.bitwarden_project_id or "(empty)")
            self._mount_card(body, self._card(
                "Needs attention",
                Static(
                    f"[$text-warning]A Bitwarden config exists but its project id "
                    f"([$text-error]{invalid_id}[/$text-error]) is not a valid project UUID — "
                    "using the local store until it's fixed. Repair it via the "
                    "guided setup (g) or the team settings, or clear the "
                    "cached config (c).[/$text-warning]",
                ),
                warning=True,
            ))
        actions = [
            ("g", "Set up Bitwarden"),
            ("v", "DB-vault coverage"),
            ("l", "List stored secrets"),
            ("u", "Upgrade for team secrets"),
            ("o", "Open docs"),
        ]
        # If a server-supplied config is cached (e.g. a broken team config that
        # forced this local fallback), offer Clear here too — otherwise the
        # only way to drop the poisoned cache is an undiscoverable key press.
        if s.project_id_invalid or s.config_source is not None:
            actions.append(("c", "Clear cached config"))
        self._mount_card(body, self._card("Actions", self._actions(*actions)))

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
        """Re-fetch the personal + team SecretsConfig from the API, then repaint.

        The personal (``/me``) fetch always runs when authenticated; the
        team fetch runs only when an active team slug resolves. Both fan
        out in parallel via :func:`refresh_all_secrets_configs`, and the
        precedence layer (team-in-team-context → personal → Local) picks
        the winner on the subsequent ``_render_state``.
        """
        auth = getattr(self.app, "auth_service", None)
        api_client = getattr(self.app, "api_client", None)
        if auth is None or api_client is None:
            self.notify(
                "Refresh unavailable — log in first.",
                severity="warning",
            )
            return
        try:
            from servonaut.services.secret_provider_resolver import (
                refresh_all_secrets_configs,
            )
            slug = await auth.active_team_slug()
            await refresh_all_secrets_configs(auth, api_client, slug=slug)
            self.notify("Secrets config refreshed.", severity="information")
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
            # The tools layer holds its own provider reference (db_setup_save
            # etc.) — rebinding only ssh_service leaves it pointing at the
            # pre-clear provider for the rest of the session.
            tools = getattr(self.app, "servonaut_tools", None)
            if tools is not None:
                tools.set_secret_provider(new_provider)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to rebind ssh_service provider: %s", exc)

    def action_list_secrets(self) -> None:
        from servonaut.screens.secrets_list import SecretsListScreen
        self.app.push_screen(SecretsListScreen())

    def action_guided_setup(self) -> None:
        """Open the guided Bitwarden onboarding wizard (B1)."""
        from servonaut.screens.secrets_setup import SecretsSetupScreen
        self.app.push_screen(SecretsSetupScreen())

    def action_db_coverage(self) -> None:
        """Open the DB-vault coverage + search view (B4)."""
        from servonaut.screens.db_coverage_view import DbCoverageScreen
        self.app.push_screen(DbCoverageScreen())

    def action_clear_cache(self) -> None:
        from servonaut.screens.secrets_clear_modal import ConfirmClearCacheModal
        auth = getattr(self.app, "auth_service", None)
        # Clearing drops only the team cache; say what takes over instead.
        personal_cached = bool(auth and auth.is_user_secrets_cache_present())
        self.app.push_screen(
            ConfirmClearCacheModal(personal_config_cached=personal_cached),
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
        from servonaut.runtime import RuntimeCapabilityError, validate_launch_argv

        runtime = self.app.runtime_layout
        try:
            command = validate_launch_argv(
                runtime.current_app_argv("secrets", "install", "bws", "--yes"),
                runtime=runtime,
            )
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                self.notify(
                    "bws installed. Refresh (r) to re-evaluate state.",
                    severity="information",
                )
            else:
                tail = stdout.decode("utf-8", errors="replace")[-300:]
                self.notify(
                    f"bws install failed (exit {proc.returncode}). "
                    f"Tail: {tail}",
                    severity="error", markup=False,
                )
        except (FileNotFoundError, RuntimeCapabilityError):
            self.notify(
                "Servonaut's command helper could not be launched. "
                "Repair or update the installation and retry.",
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
