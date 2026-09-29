"""OVH credential setup wizard screen.

Sets up the primary OVHcloud account (the ``ovh`` block itself) and adds or
edits EXTRA accounts (``ovh.accounts``), each with its own endpoint and
credentials — an application key set or an OAuth2 service account — and
its own projects, filters, SSH defaults and Object Storage keys. An extra
account's credentials are tested before it is saved.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import replace
from typing import TYPE_CHECKING, List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import Button, Footer, Input, Select, Static

from servonaut.screens.settings.accounts import (
    label_error,
    rebuild_accounts,
    reload_provider_fleet,
)
from servonaut.services.object_storage_regions import (
    OVH_S3_DEFAULT_REGION,
    OVH_S3_REGIONS,
)
from servonaut.runtime import RuntimeCapabilityError, detect_runtime
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)


class OVHSetupScreen(Screen):
    """Guided setup wizard for OVHcloud API credentials.

    Supports both classic 3-key auth (Application Key + Secret + Consumer Key)
    and OAuth2 service account auth (Client ID + Client Secret) for extra
    accounts. Opened with no arguments it sets up the primary account;
    ``add_extra`` adds another account and ``extra`` edits extra account
    number *extra*; ``show_label`` also offers the primary account's label.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    DEFAULT_CSS = """
    OVHSetupScreen #ovh_label_row,
    OVHSetupScreen #ovh_auth_row {
        height: auto;
    }
    OVHSetupScreen #ovh_input_label,
    OVHSetupScreen #ovh_input_client_id,
    OVHSetupScreen #ovh_input_client_secret {
        width: 1fr;
    }
    OVHSetupScreen #ovh_select_auth {
        width: 1fr;
    }
    OVHSetupScreen #btn_ovh_add_account {
        margin: 0 1 0 0;
    }
    """

    # Authentication choices for an extra account.
    _AUTH_CLASSIC = "classic"
    _AUTH_OAUTH = "oauth"

    def __init__(
        self,
        *,
        extra: Optional[int] = None,
        add_extra: bool = False,
        show_label: bool = False,
    ) -> None:
        super().__init__()
        self._extra_index = extra
        self._add_extra = add_extra
        self._show_label = show_label
        # Whether the label row is on screen; decided in compose.
        self._label_shown = False

    @property
    def app(self) -> "ServonautApp":
        return super().app  # type: ignore

    @property
    def _account_mode(self) -> bool:
        """True when the wizard adds or edits an EXTRA account."""
        return self._add_extra or self._extra_index is not None

    def compose(self) -> ComposeResult:
        ovh = self.app.config_manager.get().ovh
        # The primary account's label only matters once there are several
        # accounts; a single-account user never sees the row unasked.
        self._label_shown = (
            self._account_mode or self._show_label or bool(ovh.accounts) or bool(ovh.label)
        )
        yield SafeHeader()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                *self._intro_rows(),
                *self._credential_rows(),
                *self._option_rows(),
                # Test + Save
                Static("", id="ovh_test_result"),
                Horizontal(*self._action_buttons(), classes="ovh_action_row"),
                id="ovh_setup_container",
            )
        yield Footer()

    def _intro_rows(self) -> List[Widget]:
        if self._account_mode:
            title = "Add an OVHcloud Account" if self._add_extra else "OVHcloud Account"
            rows: List[Widget] = [
                Static(f"[bold cyan]{title}[/bold cyan]", id="ovh_setup_header"),
                Static(
                    "[dim]Each OVHcloud account has its own API credentials. Its "
                    "servers join the instance list next to your other accounts.[/dim]",
                    classes="note",
                ),
            ]
            placeholder = "e.g. client-a (servers are shown as client-a/<name>)"
        else:
            rows = [
                Static("[bold cyan]OVHcloud Setup[/bold cyan]", id="ovh_setup_header"),
                Static(
                    "[dim]Configure OVHcloud API credentials to manage dedicated servers, "
                    "VPS, and Public Cloud instances.[/dim]",
                    classes="note",
                ),
            ]
            placeholder = "ovh (the name shown for this account)"
        if self._label_shown:
            rows.append(
                Horizontal(
                    Static("Account Label:", classes="label"),
                    Input(placeholder=placeholder, id="ovh_input_label"),
                    classes="setting_row",
                    id="ovh_label_row",
                )
            )
        return rows

    def _credential_rows(self) -> List[Widget]:
        rows: List[Widget] = [
            # Step 1: Endpoint
            Static("[bold]Step 1: API Endpoint[/bold]", classes="section_header"),
            Static(
                "[dim]Choose your OVH region. Most users should use ovh-eu.[/dim]",
                classes="note",
            ),
            Horizontal(
                Static("Endpoint:", classes="label"),
                Input(
                    placeholder="ovh-eu",
                    id="ovh_input_endpoint",
                    value="ovh-eu",
                ),
                classes="setting_row",
            ),

            # Step 2: Credentials
            Static("[bold]Step 2: API Credentials[/bold]", classes="section_header"),
            Static(
                "[dim]Visit https://www.ovh.com/auth/api/createApp to create an application "
                "and obtain your Application Key and Secret.\n"
                "For other regions: ovh-ca → ca.api.ovh.com/createApp/ | "
                "ovh-us → api.us.ovhcloud.com/createApp/[/dim]",
                classes="note",
            ),
        ]
        if self._account_mode:
            rows.extend([
                Horizontal(
                    Static("Authentication:", classes="label"),
                    Select(
                        [
                            ("Application key (3 keys)", self._AUTH_CLASSIC),
                            ("OAuth2 service account", self._AUTH_OAUTH),
                        ],
                        value=self._AUTH_CLASSIC,
                        allow_blank=False,
                        id="ovh_select_auth",
                    ),
                    classes="setting_row",
                    id="ovh_auth_row",
                ),
                Horizontal(
                    Static("Client ID:", classes="label"),
                    Input(
                        placeholder="OAuth2 service account client ID",
                        id="ovh_input_client_id",
                    ),
                    classes="setting_row ovh-oauth-auth",
                ),
                Horizontal(
                    Static("Client Secret:", classes="label"),
                    Input(
                        placeholder="Client secret, $ENV_VAR or file:/path",
                        id="ovh_input_client_secret",
                        password=True,
                    ),
                    classes="setting_row ovh-oauth-auth",
                ),
            ])
        rows.extend([
            Horizontal(
                Static("Application Key:", classes="label"),
                Input(
                    placeholder="Your OVH Application Key",
                    id="ovh_input_app_key",
                ),
                classes="setting_row ovh-classic-auth",
            ),
            Horizontal(
                Static("Application Secret:", classes="label"),
                Input(
                    placeholder="Your OVH Application Secret or $ENV_VAR",
                    id="ovh_input_app_secret",
                    password=True,
                ),
                classes="setting_row ovh-classic-auth",
            ),

            # Step 3: Consumer Key
            Static(
                "[bold]Step 3: Consumer Key[/bold]",
                classes="section_header ovh-classic-auth",
            ),
            Static(
                "[dim]If you already have a Consumer Key, enter it below. "
                "Otherwise, click 'Request Consumer Key' to generate one.[/dim]",
                classes="note ovh-classic-auth",
            ),
            Horizontal(
                Static("Consumer Key:", classes="label"),
                Input(
                    placeholder="Your OVH Consumer Key or $ENV_VAR",
                    id="ovh_input_consumer_key",
                    password=True,
                ),
                classes="setting_row ovh-classic-auth",
            ),
            Button(
                "Request Consumer Key",
                id="btn_ovh_request_ck",
                variant="default",
                classes="ovh-classic-auth",
            ),
            Static(
                "[dim]After adding new features, click 'Request Consumer Key' again "
                "to grant permissions for all OVH operations.[/dim]",
                classes="note ovh-classic-auth",
            ),
            Static("", id="ovh_validation_url", classes="ovh-classic-auth"),
        ])
        return rows

    def _option_rows(self) -> List[Widget]:
        return [
            # Step 4: SSH Defaults
            Static("[bold]Step 4: SSH Defaults[/bold]", classes="section_header"),
            Static(
                "[dim]OVH doesn't provide SSH keys via the API. Set the local private "
                "key to use for connecting to OVH instances. You can also map "
                "per-instance keys in Settings > SSH Keys.[/dim]",
                classes="note",
            ),
            Horizontal(
                Static("Default SSH Key:", classes="label"),
                Input(
                    placeholder="~/.ssh/id_rsa or ~/.ssh/ovh_key",
                    id="ovh_input_default_ssh_key",
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Default Username:", classes="label"),
                Input(
                    placeholder="auto (ubuntu for VPS, debian for dedicated)",
                    id="ovh_input_default_username",
                ),
                classes="setting_row",
            ),

            # Step 5: Cloud Project IDs
            Static("[bold]Step 5: Public Cloud Projects (optional)[/bold]", classes="section_header"),
            Static(
                "[dim]Enter comma-separated OVH Public Cloud project IDs to include. "
                "Leave blank to skip cloud instances.[/dim]",
                classes="note",
            ),
            Horizontal(
                Static("Project IDs:", classes="label"),
                Input(
                    placeholder="abc123, def456",
                    id="ovh_input_project_ids",
                ),
                classes="setting_row",
            ),

            # Step 6: Filters
            Static("[bold]Step 6: Instance Filters[/bold]", classes="section_header"),
            Static(
                "[dim]Choose which OVH resource types to include.[/dim]",
                classes="note",
            ),
            Horizontal(
                Static("Include Dedicated Servers:", classes="label"),
                Input(
                    placeholder="true",
                    id="ovh_input_include_dedicated",
                    value="true",
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Include VPS:", classes="label"),
                Input(
                    placeholder="true",
                    id="ovh_input_include_vps",
                    value="true",
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Include Cloud:", classes="label"),
                Input(
                    placeholder="true",
                    id="ovh_input_include_cloud",
                    value="true",
                ),
                classes="setting_row",
            ),

            # Step 7: Object Storage (S3-compatible)
            Static(
                "[bold]Step 7: Object Storage (S3-compatible)[/bold]",
                classes="section_header",
            ),
            Static(
                "[dim]OVH Object Storage uses S3-compatible credentials "
                "(separate from the OVH API keys above). Generate them at "
                "OVH Manager → Public Cloud → Object Storage → Users. "
                "Leave blank to skip — the S3 file manager will show a "
                "configuration prompt instead. Both fields support "
                "[b]$ENV_VAR[/b] and [b]file:[/b] prefixes.[/dim]",
                classes="note",
            ),
            Horizontal(
                Static("Access Key:", classes="label"),
                Input(
                    placeholder="your-key or $OVH_S3_ACCESS_KEY or file:/path",
                    id="ovh_input_s3_access_key",
                    password=True,
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Secret Key:", classes="label"),
                Input(
                    placeholder="your-secret or $OVH_S3_SECRET_KEY or file:/path",
                    id="ovh_input_s3_secret_key",
                    password=True,
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Region:", classes="label"),
                Select(
                    options=[
                        (label, code) for label, code in OVH_S3_REGIONS
                    ],
                    id="ovh_input_s3_region",
                    value=OVH_S3_DEFAULT_REGION,
                    allow_blank=False,
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Endpoint URL:", classes="label"),
                Input(
                    placeholder="https://s3.<region>.io.cloud.ovh.net (auto-derived from region — leave blank unless you have a custom endpoint)",
                    id="ovh_input_s3_endpoint_url",
                ),
                classes="setting_row",
            ),
        ]

    def _action_buttons(self) -> List[Widget]:
        test = Button("Test Connection", id="btn_ovh_test", variant="default")
        back = Button("Back", id="btn_ovh_back")
        if self._account_mode:
            return [test, Button("Test & Save", id="btn_ovh_save", variant="primary"), back]
        return [
            test,
            Button("Save & Enable", id="btn_ovh_save", variant="primary"),
            Button("Disable OVH", id="btn_ovh_disable", variant="error"),
            Button("Add Another Account", id="btn_ovh_add_account"),
            back,
        ]

    def on_mount(self) -> None:
        """Load the account being set up into the form fields."""
        config = self.app.config_manager.get()
        ovh = config.ovh
        if self._account_mode:
            source = self._extra_account(ovh)
            if source is None:
                return
        else:
            source = ovh
            # Another account can only join a provider that is set up.
            self.query_one("#btn_ovh_add_account", Button).display = ovh.enabled
        if self._label_shown:
            self.query_one("#ovh_input_label", Input).value = source.label

        self.query_one("#ovh_input_endpoint", Input).value = source.endpoint or "ovh-eu"
        self.query_one("#ovh_input_app_key", Input).value = source.application_key or ""
        self.query_one("#ovh_input_app_secret", Input).value = source.application_secret or ""
        self.query_one("#ovh_input_consumer_key", Input).value = source.consumer_key or ""
        self.query_one("#ovh_input_default_ssh_key", Input).value = source.default_ssh_key or ""
        self.query_one("#ovh_input_default_username", Input).value = source.default_username or ""
        self.query_one("#ovh_input_project_ids", Input).value = ", ".join(
            source.cloud_project_ids
        )
        self.query_one("#ovh_input_include_dedicated", Input).value = (
            "true" if source.include_dedicated else "false"
        )
        self.query_one("#ovh_input_include_vps", Input).value = (
            "true" if source.include_vps else "false"
        )
        self.query_one("#ovh_input_include_cloud", Input).value = (
            "true" if source.include_cloud else "false"
        )
        if self._account_mode:
            self._load_extra_auth(source, ovh)

        # S3 / Object Storage credentials — independent of OVH API keys.
        s3 = source.object_storage
        self.query_one("#ovh_input_s3_access_key", Input).value = s3.access_key
        self.query_one("#ovh_input_s3_secret_key", Input).value = s3.secret_key
        s3_region_sel = self.query_one("#ovh_input_s3_region", Select)
        known_regions = {code for _, code in OVH_S3_REGIONS}
        s3_region_sel.value = (
            s3.region if s3.region in known_regions else OVH_S3_DEFAULT_REGION
        )
        self.query_one("#ovh_input_s3_endpoint_url", Input).value = s3.endpoint_url

    def _extra_account(self, ovh):
        """The extra account being edited, a blank one to add, or None."""
        from servonaut.config.schema import OVHAccount

        index = self._extra_index
        if index is None:
            return OVHAccount()
        if index >= len(ovh.accounts):
            self.app.notify("That OVHcloud account no longer exists.", severity="error")
            self.call_after_refresh(self.action_back)
            return None
        return ovh.accounts[index]

    def _load_extra_auth(self, account, ovh) -> None:
        """Fill the OAuth2 fields and show the account's credential set."""
        self.query_one("#ovh_input_client_id", Input).value = account.client_id
        self.query_one("#ovh_input_client_secret", Input).value = account.client_secret
        oauth = bool(account.client_id or account.client_secret) and not account.application_key
        auth = self._AUTH_OAUTH if oauth else self._AUTH_CLASSIC
        self.query_one("#ovh_select_auth", Select).value = auth
        self._show_auth(auth)
        # Empty SSH defaults fall back to the primary account's.
        if ovh.default_ssh_key:
            self.query_one("#ovh_input_default_ssh_key", Input).placeholder = (
                f"{ovh.default_ssh_key} (as the primary account)"
            )
        if ovh.default_username:
            self.query_one("#ovh_input_default_username", Input).placeholder = (
                f"{ovh.default_username} (as the primary account)"
            )

    def _show_auth(self, auth: str) -> None:
        """Show the fields of one credential set and hide the other's."""
        for widget in self.query(".ovh-classic-auth"):
            widget.display = auth == self._AUTH_CLASSIC
        for widget in self.query(".ovh-oauth-auth"):
            widget.display = auth == self._AUTH_OAUTH

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "ovh_select_auth" and event.value is not Select.BLANK:
            self._show_auth(str(event.value))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn_ovh_request_ck":
            self._request_consumer_key()
        elif button_id == "btn_ovh_test":
            self._test_connection()
        elif button_id == "btn_ovh_save":
            if self._account_mode:
                # An extra account is saved only once its credentials work.
                self._test_connection(save=True)
            else:
                self._save_config(enable=True)
        elif button_id == "btn_ovh_add_account":
            self.app.switch_screen(OVHSetupScreen(add_extra=True))
        elif button_id == "btn_ovh_disable":
            self._save_config(enable=False)
        elif button_id == "btn_ovh_back":
            self.action_back()

    def _collect_form_values(self) -> dict:
        """Collect and return all form field values."""
        endpoint = self.query_one("#ovh_input_endpoint", Input).value.strip() or "ovh-eu"
        app_key = self.query_one("#ovh_input_app_key", Input).value.strip()
        app_secret = self.query_one("#ovh_input_app_secret", Input).value.strip()
        consumer_key = self.query_one("#ovh_input_consumer_key", Input).value.strip()
        default_ssh_key = self.query_one("#ovh_input_default_ssh_key", Input).value.strip()
        default_username = self.query_one("#ovh_input_default_username", Input).value.strip()
        project_ids_raw = self.query_one("#ovh_input_project_ids", Input).value.strip()
        project_ids = [p.strip() for p in project_ids_raw.split(",") if p.strip()]
        include_dedicated = (
            self.query_one("#ovh_input_include_dedicated", Input).value.strip().lower()
            != "false"
        )
        include_vps = (
            self.query_one("#ovh_input_include_vps", Input).value.strip().lower()
            != "false"
        )
        include_cloud = (
            self.query_one("#ovh_input_include_cloud", Input).value.strip().lower()
            != "false"
        )
        s3_access_key = self.query_one("#ovh_input_s3_access_key", Input).value.strip()
        s3_secret_key = self.query_one("#ovh_input_s3_secret_key", Input).value.strip()
        s3_region_sel = self.query_one("#ovh_input_s3_region", Select)
        s3_region = (
            "" if s3_region_sel.value is Select.BLANK else str(s3_region_sel.value)
        )
        s3_endpoint_url = self.query_one("#ovh_input_s3_endpoint_url", Input).value.strip()
        values = {
            'endpoint': endpoint,
            'application_key': app_key,
            'application_secret': app_secret,
            'consumer_key': consumer_key,
            'default_ssh_key': default_ssh_key,
            'default_username': default_username,
            'cloud_project_ids': project_ids,
            'include_dedicated': include_dedicated,
            'include_vps': include_vps,
            'include_cloud': include_cloud,
            's3_access_key': s3_access_key,
            's3_secret_key': s3_secret_key,
            's3_region': s3_region,
            's3_endpoint_url': s3_endpoint_url,
        }
        if self._label_shown:
            values['label'] = self.query_one("#ovh_input_label", Input).value.strip()
        if self._account_mode:
            auth = self.query_one("#ovh_select_auth", Select).value
            oauth = auth == self._AUTH_OAUTH
            client_id = self.query_one("#ovh_input_client_id", Input).value.strip()
            client_secret = self.query_one("#ovh_input_client_secret", Input).value.strip()
            # Only the chosen credential set is kept: a hidden, stale set
            # would decide which one the account really uses.
            values['auth'] = self._AUTH_OAUTH if oauth else self._AUTH_CLASSIC
            values['client_id'] = client_id if oauth else ""
            values['client_secret'] = client_secret if oauth else ""
            if oauth:
                for key in ('application_key', 'application_secret', 'consumer_key'):
                    values[key] = ""
        return values

    def _label_problem(self, values: dict) -> Optional[str]:
        """Why the typed label cannot name this account, or None."""
        if not self._label_shown:
            return None
        config = self.app.config_manager.get()
        if not self._account_mode:
            index = None
        elif self._extra_index is None:
            index = len(config.ovh.accounts)
        else:
            index = self._extra_index
        return label_error(config, "ovh", values.get('label', ''), index=index)

    def _request_consumer_key(self) -> None:
        """Initiate the OVH consumer key request flow."""
        values = self._collect_form_values()
        if not values['application_key'] or not values['application_secret']:
            self.app.notify(
                "Application Key and Secret are required to request a Consumer Key.",
                severity="error",
            )
            return

        self.app.notify("Requesting Consumer Key from OVH...", severity="information")
        self.run_worker(
            self._do_request_consumer_key(values),
            name="ovh_request_ck",
            exclusive=True,
        )

    async def _install_ovh_if_needed(self) -> bool:
        """Ensure python-ovh is installed when the runtime permits it."""
        try:
            import ovh  # noqa: F401
            return True
        except ImportError:
            pass

        runtime = getattr(self.app, "runtime_layout", None) or detect_runtime()
        capability = runtime.package_management
        if runtime.is_frozen:
            self.app.notify(
                "This packaged build is missing python-ovh. "
                "Repair or reinstall the complete bundle.",
                severity="error",
                timeout=10,
                markup=False,
            )
            return False

        try:
            argv = capability.dependency_install_argv(["ovh"])
        except RuntimeCapabilityError:
            self.app.notify(
                "The current Servonaut runtime cannot install python-ovh.",
                severity="error",
                timeout=10,
                markup=False,
            )
            return False

        self.app.notify(
            "Installing python-ovh package...", severity="information", markup=False
        )

        try:
            import asyncio

            await asyncio.to_thread(subprocess.check_call, argv)
            logger.info("python-ovh installed via runtime package capability")
            return True
        except (subprocess.CalledProcessError, OSError) as exc:
            logger.error("Failed to install python-ovh: %s", exc)
            self.app.notify(
                "Failed to install python-ovh. Retry from a terminal.",
                severity="error",
                timeout=10,
                markup=False,
            )
            return False

    async def _do_request_consumer_key(self, values: dict) -> None:
        """Worker: request consumer key from OVH API."""
        if not await self._install_ovh_if_needed():
            return

        from servonaut.config.schema import OVHConfig
        from servonaut.services.ovh_service import OVHService

        temp_config = OVHConfig(
            enabled=False,
            endpoint=values['endpoint'],
            application_key=values['application_key'],
            application_secret=values['application_secret'],
        )
        svc = OVHService(temp_config)
        try:
            result = await svc.request_consumer_key()
            ck = result.get('consumerKey') or ''
            url = result.get('validationUrl') or ''
            if ck:
                self.query_one("#ovh_input_consumer_key", Input).value = ck
                self.query_one("#ovh_validation_url", Static).update(
                    f"[bold green]Consumer Key received![/bold green]\n"
                    f"[dim]Validation URL (open in browser to activate):[/dim]\n"
                    f"[cyan]{url}[/cyan]\n"
                    f"[dim]After granting access, click 'Test Connection'.[/dim]"
                )
                self.app.notify(
                    "Consumer Key received! Open the validation URL to activate it.",
                    severity="information",
                    timeout=10,
                )
            else:
                self.query_one("#ovh_validation_url", Static).update(
                    "[red]Failed to obtain Consumer Key[/red]"
                )
        except Exception as e:
            logger.error("Consumer key request failed: %s", e)
            self.query_one("#ovh_validation_url", Static).update(
                "[red]Failed to request Consumer Key. Check credentials and try again.[/red]"
            )
            self.app.notify("Consumer Key request failed. Check credentials.", severity="error")

    def _test_connection(self, save: bool = False) -> None:
        """Test OVH connection with current form values.

        With *save* (an extra account), the account is stored once the
        test succeeds, and never when it fails.
        """
        values = self._collect_form_values()
        if save:
            problem = self._label_problem(values)
            if problem is not None:
                self.app.notify(problem, severity="error", markup=False)
                self.query_one("#ovh_input_label", Input).focus()
                return
        if values.get('auth') == self._AUTH_OAUTH:
            if not (values['client_id'] and values['client_secret']):
                self.app.notify(
                    "Enter the Client ID and Client Secret to test.",
                    severity="warning",
                )
                return
        elif save and not all(
            values[key] for key in ('application_key', 'application_secret', 'consumer_key')
        ):
            # An extra account never borrows the primary's keys, so all
            # three must be its own.
            self.app.notify(
                "Enter the Application Key, Application Secret and Consumer Key "
                "(or request one) to save this account.",
                severity="warning",
            )
            return
        elif not values['application_key']:
            self.app.notify(
                "Enter at least Application Key and Consumer Key to test.",
                severity="warning",
            )
            return

        self.query_one("#ovh_test_result", Static).update("[dim]Testing connection...[/dim]")
        self.run_worker(
            self._do_test_connection(values, save=save),
            name="ovh_test",
            exclusive=True,
        )

    async def _do_test_connection(self, values: dict, save: bool = False) -> bool:
        """Worker: test OVH API credentials."""
        if not await self._install_ovh_if_needed():
            return False

        from servonaut.config.schema import OVHConfig
        from servonaut.services.ovh_service import OVHService

        temp_config = OVHConfig(
            enabled=False,
            endpoint=values['endpoint'],
            application_key=values['application_key'],
            application_secret=values['application_secret'],
            consumer_key=values['consumer_key'],
            client_id=values.get('client_id', ''),
            client_secret=values.get('client_secret', ''),
        )
        svc = OVHService(temp_config)
        try:
            result = await svc.test_connection()
            if result['success']:
                self.query_one("#ovh_test_result", Static).update(
                    f"[green]Connection successful! Account: {escape(result['account'])}[/green]"
                )
                self.app.notify(
                    f"OVH connected as: {result['account']}",
                    severity="information",
                    markup=False,
                )
            else:
                self.query_one("#ovh_test_result", Static).update(
                    f"[red]Connection failed: {escape(result['message'])}[/red]"
                )
                self.app.notify(
                    f"OVH connection failed: {result['message']}",
                    severity="error",
                    markup=False,
                )
        except Exception as e:
            logger.error("OVH connection test failed: %s", e)
            self.query_one("#ovh_test_result", Static).update(
                "[red]Connection test failed. Check credentials and try again.[/red]"
            )
            self.app.notify("OVH connection test failed. Check credentials.", severity="error")
            result = {'success': False}
        if save:
            if result['success']:
                await self._store_extra_account(values)
            else:
                self.app.notify(
                    "The account was not saved: its credentials do not work.",
                    severity="error",
                    markup=False,
                )
        return bool(result['success'])

    def _save_config(self, enable: bool) -> None:
        """Save the primary account (``enable`` False disables OVH).

        When enabling, auto-installs python-ovh if missing and reloads the
        provider accounts, so a restart is not required.

        Args:
            enable: Whether to enable the OVH provider.
        """
        values = self._collect_form_values()
        problem = self._label_problem(values)
        if problem is not None:
            self.app.notify(problem, severity="error", markup=False)
            self.query_one("#ovh_input_label", Input).focus()
            return
        config = self.app.config_manager.get()

        s3_config = replace(
            config.ovh.object_storage,
            access_key=values['s3_access_key'],
            secret_key=values['s3_secret_key'],
            region=values['s3_region'],
            endpoint_url=values['s3_endpoint_url'],
        )
        # ``replace`` keeps what the form does not show — the OAuth2
        # client, audit path, cost alerts, the label and the extra
        # accounts — exactly as saved.
        ovh_config = replace(
            config.ovh,
            enabled=enable,
            endpoint=values['endpoint'],
            application_key=values['application_key'],
            application_secret=values['application_secret'],
            consumer_key=values['consumer_key'],
            default_ssh_key=values['default_ssh_key'],
            default_username=values['default_username'],
            cloud_project_ids=values['cloud_project_ids'],
            include_dedicated=values['include_dedicated'],
            include_vps=values['include_vps'],
            include_cloud=values['include_cloud'],
            object_storage=s3_config,
        )
        if self._label_shown:
            ovh_config = replace(ovh_config, label=values['label'])
        config.ovh = ovh_config

        try:
            self.app.config_manager.save(config)
        except Exception as e:
            logger.error("Failed to save OVH config: %s", e)
            self.app.notify("Failed to save OVH configuration. Check logs for details.", severity="error")
            return
        # Every surface moves to the saved accounts together, Object Storage
        # included (so the sidebar's S3 entry appears at once); disabling
        # makes the OVH services go away.
        rebuild_accounts(self.app)
        if enable:
            self.app.notify("OVH configuration saved.", severity="information")
            logger.info("OVH configuration saved: enabled=True, endpoint=%s", values['endpoint'])
            self.run_worker(
                self._ensure_ovh_ready(),
                name="ovh_setup",
                exclusive=True,
            )
        else:
            self.app.notify("OVH disabled and settings saved.", severity="information")
            logger.info("OVH configuration saved: enabled=False")
            self.action_back()

    def _ovh_inventory(self):
        """Every OVH account as one inventory; None when none is usable."""
        lookup = getattr(self.app, "provider_inventory", None)
        return lookup("ovh") if callable(lookup) else None

    async def _ensure_ovh_ready(self) -> None:
        """Install python-ovh if needed, then fetch every account's instances."""
        if not await self._install_ovh_if_needed():
            self.action_back()
            return

        if self._ovh_inventory() is None:
            from servonaut.config.accounts import primary_label

            config = self.app.config_manager.get()
            key = primary_label("ovh", config.ovh).lower()
            unavailable = getattr(getattr(self.app, "accounts", None), "unavailable", None) or {}
            reason = unavailable.get(f"ovh:{key}") or "no usable OVH account"
            self.app.notify(
                f"OVH service init failed: {reason}",
                severity="error",
                markup=False,
            )
            self.action_back()
            return

        # Fetch instances immediately
        self.app.notify("Fetching OVH instances...", severity="information")
        try:
            instances, error = await reload_provider_fleet(self.app, "ovh")
        except Exception as e:
            logger.error("OVH instance fetch failed: %s", e)
            self.app.notify(
                f"OVH enabled but fetch failed: {e}",
                severity="warning",
                timeout=8,
                markup=False,
            )
            self.action_back()
            return
        if error:
            self.app.notify(
                f"OVH refresh incomplete. {error}", severity="warning", markup=False
            )
        if instances:
            self.app.notify(
                f"OVH enabled — {len(instances)} instances loaded.",
                severity="information",
                timeout=8,
            )
        else:
            self.app.notify(
                "OVH enabled — no instances found. Check your filters and project IDs.",
                severity="warning",
                timeout=8,
            )

        self.action_back()

    async def _store_extra_account(self, values: dict) -> None:
        """Save the tested extra account, reload the accounts, list its servers."""
        from servonaut.config.schema import OVHAccount

        config = self.app.config_manager.get()
        accounts = list(config.ovh.accounts)
        index = self._extra_index
        editing = index is not None and index < len(accounts)
        previous = accounts[index] if editing else OVHAccount()
        account = replace(
            previous,
            label=values['label'],
            endpoint=values['endpoint'],
            application_key=values['application_key'],
            application_secret=values['application_secret'],
            consumer_key=values['consumer_key'],
            client_id=values['client_id'],
            client_secret=values['client_secret'],
            default_ssh_key=values['default_ssh_key'],
            default_username=values['default_username'],
            cloud_project_ids=values['cloud_project_ids'],
            include_dedicated=values['include_dedicated'],
            include_vps=values['include_vps'],
            include_cloud=values['include_cloud'],
            object_storage=replace(
                previous.object_storage,
                access_key=values['s3_access_key'],
                secret_key=values['s3_secret_key'],
                region=values['s3_region'],
                endpoint_url=values['s3_endpoint_url'],
            ),
        )
        if editing:
            accounts[index] = account
        else:
            accounts.append(account)
        config.ovh = replace(config.ovh, accounts=accounts)
        try:
            self.app.config_manager.save(config)
        except Exception as exc:
            logger.error("Failed to save the OVH account: %s", exc)
            self.app.notify(
                "Failed to save the OVH account. Check logs for details.", severity="error"
            )
            return
        rebuild_accounts(self.app)
        label = values['label']
        self.app.notify(f"OVH account '{label}' saved.", markup=False)

        if self._ovh_inventory() is not None:
            try:
                instances, error = await reload_provider_fleet(self.app, "ovh")
            except Exception as exc:
                logger.error("OVH fetch after adding an account failed: %s", exc)
                self.app.notify(
                    f"Listing the OVH instances failed: {exc}",
                    severity="warning",
                    markup=False,
                )
            else:
                if error:
                    self.app.notify(
                        f"OVH refresh incomplete. {error}", severity="warning", markup=False
                    )
                count = sum(
                    1 for row in instances
                    if str(row.get("account") or "").lower() == label.lower()
                )
                self.app.notify(
                    f"OVH account '{label}': {count} instance(s) loaded.",
                    severity="information",
                    markup=False,
                )
        self.action_back()

    def action_back(self) -> None:
        """Return to previous screen."""
        self.app.pop_screen()
