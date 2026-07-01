"""SecretsSetupScreen — guided Bitwarden onboarding in the TUI (Layer B1).

The graphical twin of ``servonaut secrets setup``. Both surfaces drive the
SAME stateless helpers in :mod:`servonaut.services.bws_onboarding` and the
SAME ``PUT /api/v1/me/secrets-config`` client method, so the flow is
identical: install bws → set the token → PICK a project by name (no UUID
paste) → TEST the connection → save the personal SecretsConfig.

Security invariants (carried from the CLI + provider):
- The bws access token is read from an env var and never rendered,
  logged, or persisted — only its env-var NAME + the project_id are saved.
- Any bws-side error text is already token-scrubbed by the helper layer.
- Every user-controlled string is escaped before interpolation into Rich
  markup.
"""
from __future__ import annotations

import logging

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    OptionList,
    Static,
)
from textual.widgets.option_list import Option

from servonaut.services import bws_onboarding as bws
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


class SecretsSetupScreen(Screen):
    """Guided bws onboarding wizard.

    Stateful only in the sense that it remembers the token env-var name
    and the currently-selected project between button presses; all real
    work happens in background workers over the shared service layer.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._selected_project_id: str = ""

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static("🔐 Guided Bitwarden setup", id="secrets_setup_title"),
                Static(
                    "Pick a project by name, test the connection, then save "
                    "it as your personal secret store. Your access token stays "
                    "in your environment — only its name and the project id are "
                    "stored.",
                    id="secrets_setup_subtitle",
                ),
                VerticalScroll(
                    Static("", id="setup_preflight"),
                    Static("Token env var:", classes="setup_label"),
                    Input(
                        value=bws.DEFAULT_TOKEN_ENV_VAR,
                        id="token_env",
                        placeholder=bws.DEFAULT_TOKEN_ENV_VAR,
                    ),
                    Horizontal(
                        Button("List projects", id="list_projects", variant="primary"),
                        Button("Test connection", id="test_conn"),
                        Button("Save", id="save", variant="success"),
                        id="setup_buttons",
                    ),
                    OptionList(id="project_list"),
                    Static("", id="setup_status"),
                    id="secrets_setup_body",
                ),
                id="secrets_setup_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        self._render_preflight()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _token_env(self) -> str:
        try:
            raw = self.query_one("#token_env", Input).value.strip()
        except Exception:  # noqa: BLE001 - widget not mounted yet
            raw = ""
        return raw or bws.DEFAULT_TOKEN_ENV_VAR

    def _set_status(self, message: str, *, error: bool = False) -> None:
        # Demo mode: scrub IP/host/path identifiers from the status line
        # (bws error text can echo a project host / path).
        if self.app.demo_mode and self.app.redaction_service:
            message = self.app.redaction_service.scrub_stream(message)
        colour = "red" if error else "green"
        try:
            self.query_one("#setup_status", Static).update(
                f"[{colour}]{escape(message)}[/{colour}]"
            )
        except Exception:  # noqa: BLE001
            pass

    def _render_preflight(self) -> None:
        """Show the install/token/entitlement readiness up front."""
        lines = []
        entitled = self._entitled()
        installed = bws.bws_installed()
        token_env = self._token_env()
        token_ok = bws.token_is_set(token_env)
        lines.append(
            f"{'✓' if entitled else '✗'} Entitled to secrets management"
            if entitled
            else "✗ Secrets management requires a Solo or Teams plan"
        )
        lines.append(
            f"{'✓' if installed else '✗'} bws CLI installed"
            + ("" if installed else " — run `servonaut secrets install bws`")
        )
        lines.append(
            f"{'✓' if token_ok else '✗'} {escape(token_env)} set in environment"
            + ("" if token_ok else " — export it, then List projects")
        )
        text = "\n".join(lines)
        # Demo mode: scrub in case a custom token env-var name embeds a path.
        if self.app.demo_mode and self.app.redaction_service:
            text = self.app.redaction_service.scrub_stream(text)
        try:
            self.query_one("#setup_preflight", Static).update(text)
        except Exception:  # noqa: BLE001
            pass

    def _entitled(self) -> bool:
        guard = getattr(self.app, "entitlement_guard", None)
        if guard is None:
            return False
        try:
            allowed, _ = guard.check("secrets_management")
            return bool(allowed)
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "token_env":
            self._render_preflight()

    def on_option_list_option_selected(
        self, event: OptionList.OptionSelected,
    ) -> None:
        if event.option_list.id == "project_list":
            self._selected_project_id = str(event.option.id or "")
            self._set_status(f"Selected project {self._selected_project_id}.")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "list_projects":
            self.run_worker(
                self._list_projects_worker(),
                group="secrets_setup", exclusive=True, name="secrets_setup_list",
            )
        elif event.button.id == "test_conn":
            self.run_worker(
                self._test_connection_worker(),
                group="secrets_setup", exclusive=True, name="secrets_setup_test",
            )
        elif event.button.id == "save":
            self.run_worker(
                self._save_worker(),
                group="secrets_setup", exclusive=True, name="secrets_setup_save",
            )

    def action_back(self) -> None:
        self.app.pop_screen()

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    async def _list_projects_worker(self) -> None:
        if not self._entitled():
            self._set_status(
                "Secrets management requires a Solo or Teams plan.", error=True,
            )
            return
        token_env = self._token_env()
        option_list = self.query_one("#project_list", OptionList)
        option_list.clear_options()
        self._selected_project_id = ""
        try:
            projects = await bws.list_bws_projects(token_env)
        except bws.BwsOnboardingError as exc:
            self._set_status(str(exc), error=True)
            return
        if not projects:
            self._set_status(
                "No projects visible to this token — create one and grant "
                "the machine account access.",
                error=True,
            )
            return
        for p in projects:
            label = f"{p.name or '(unnamed)'}  [{p.id}]"
            option_list.add_option(Option(escape(label), id=p.id))
        self._set_status(
            f"Found {len(projects)} project(s). Select one, then Test connection."
        )

    async def _test_connection_worker(self) -> None:
        if not self._selected_project_id:
            self._set_status("Select a project first.", error=True)
            return
        token_env = self._token_env()
        try:
            count = await bws.bws_test_connection(
                self._selected_project_id, token_env,
            )
        except bws.BwsOnboardingError as exc:
            self._set_status(str(exc), error=True)
            return
        self._set_status(
            f"Connection OK — resolved {count} secret(s). Ready to Save."
        )

    async def _save_worker(self) -> None:
        if not self._selected_project_id:
            self._set_status("Select a project first.", error=True)
            return
        auth = getattr(self.app, "auth_service", None)
        api = getattr(self.app, "api_client", None)
        if auth is None or api is None:
            self._set_status("Sign in first.", error=True)
            return
        token_env = self._token_env()
        # Re-validate before persisting — never save an unverified config.
        try:
            await bws.bws_test_connection(self._selected_project_id, token_env)
        except bws.BwsOnboardingError as exc:
            self._set_status(f"Not saved — {exc}", error=True)
            return
        config = {
            "project_id": self._selected_project_id,
            "token_env_var": token_env,
        }
        try:
            body = await api.put_user_secrets_config("bitwarden", config)
        except Exception as exc:  # noqa: BLE001 - APIError et al.
            self._set_status(f"Failed to save: {exc}", error=True)
            return
        if isinstance(body, dict) and body.get("provider"):
            auth.apply_user_secrets_config(body)
        else:
            auth.apply_user_secrets_config(
                {"provider": "bitwarden", "config": config, "updated_at": ""}
            )
        self._rebind_provider()
        self._set_status(
            "Saved. Bitwarden is now your personal secret store. "
            "The token stays in your environment."
        )
        self.notify("Personal secret store configured.", severity="information")

    def _rebind_provider(self) -> None:
        """Re-resolve + bind the provider so it's active without a restart."""
        try:
            from servonaut.services.secret_provider_resolver import (
                resolve_secret_provider,
            )
            auth = self.app.auth_service
            guard = self.app.entitlement_guard
            ssh = getattr(self.app, "ssh_service", None)
            provider = resolve_secret_provider(auth, guard)
            if ssh is not None:
                ssh.set_secret_provider(provider)
            tools = getattr(self.app, "servonaut_tools", None)
            if tools is not None:
                tools.set_secret_provider(provider)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to rebind provider after setup: %s", exc)
