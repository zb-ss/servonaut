"""OVH credential setup wizard screen."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Static

from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)


class OVHSetupScreen(Screen):
    """Guided setup wizard for OVHcloud API credentials.

    Supports both classic 3-key auth (Application Key + Secret + Consumer Key)
    and OAuth2 service account auth (Client ID + Client Secret).
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    @property
    def app(self) -> "ServonautApp":
        return super().app  # type: ignore

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static("[bold cyan]OVHcloud Setup[/bold cyan]", id="ovh_setup_header"),
                Static(
                    "[dim]Configure OVHcloud API credentials to manage dedicated servers, "
                    "VPS, and Public Cloud instances.[/dim]",
                    classes="note",
                ),

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
                    "[dim]Visit https://eu.api.ovh.com/createApp to create an application "
                    "and obtain your Application Key and Secret.[/dim]",
                    classes="note",
                ),
                Horizontal(
                    Static("Application Key:", classes="label"),
                    Input(
                        placeholder="Your OVH Application Key",
                        id="ovh_input_app_key",
                    ),
                    classes="setting_row",
                ),
                Horizontal(
                    Static("Application Secret:", classes="label"),
                    Input(
                        placeholder="Your OVH Application Secret or $ENV_VAR",
                        id="ovh_input_app_secret",
                        password=True,
                    ),
                    classes="setting_row",
                ),

                # Step 3: Consumer Key
                Static("[bold]Step 3: Consumer Key[/bold]", classes="section_header"),
                Static(
                    "[dim]If you already have a Consumer Key, enter it below. "
                    "Otherwise, click 'Request Consumer Key' to generate one.[/dim]",
                    classes="note",
                ),
                Horizontal(
                    Static("Consumer Key:", classes="label"),
                    Input(
                        placeholder="Your OVH Consumer Key or $ENV_VAR",
                        id="ovh_input_consumer_key",
                        password=True,
                    ),
                    classes="setting_row",
                ),
                Button(
                    "Request Consumer Key",
                    id="btn_ovh_request_ck",
                    variant="default",
                ),
                Static("", id="ovh_validation_url"),

                # Step 4: Cloud Project IDs
                Static("[bold]Step 4: Public Cloud Projects (optional)[/bold]", classes="section_header"),
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

                # Step 5: Filters
                Static("[bold]Step 5: Instance Filters[/bold]", classes="section_header"),
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

                # Test + Save
                Static("", id="ovh_test_result"),
                Horizontal(
                    Button("Test Connection", id="btn_ovh_test", variant="default"),
                    Button("Save & Enable", id="btn_ovh_save", variant="primary"),
                    Button("Disable OVH", id="btn_ovh_disable", variant="error"),
                    Button("Back", id="btn_ovh_back"),
                    classes="ovh_action_row",
                ),

                id="ovh_setup_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        """Load existing OVH config into form fields."""
        config = self.app.config_manager.get()
        ovh = config.ovh

        self.query_one("#ovh_input_endpoint", Input).value = ovh.endpoint or "ovh-eu"
        self.query_one("#ovh_input_app_key", Input).value = ovh.application_key or ""
        self.query_one("#ovh_input_app_secret", Input).value = ovh.application_secret or ""
        self.query_one("#ovh_input_consumer_key", Input).value = ovh.consumer_key or ""
        self.query_one("#ovh_input_project_ids", Input).value = ", ".join(
            ovh.cloud_project_ids
        )
        self.query_one("#ovh_input_include_dedicated", Input).value = (
            "true" if ovh.include_dedicated else "false"
        )
        self.query_one("#ovh_input_include_vps", Input).value = (
            "true" if ovh.include_vps else "false"
        )
        self.query_one("#ovh_input_include_cloud", Input).value = (
            "true" if ovh.include_cloud else "false"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn_ovh_request_ck":
            self._request_consumer_key()
        elif button_id == "btn_ovh_test":
            self._test_connection()
        elif button_id == "btn_ovh_save":
            self._save_config(enable=True)
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
        return {
            'endpoint': endpoint,
            'application_key': app_key,
            'application_secret': app_secret,
            'consumer_key': consumer_key,
            'cloud_project_ids': project_ids,
            'include_dedicated': include_dedicated,
            'include_vps': include_vps,
            'include_cloud': include_cloud,
        }

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

    async def _do_request_consumer_key(self, values: dict) -> None:
        """Worker: request consumer key from OVH API."""
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

    def _test_connection(self) -> None:
        """Test OVH connection with current form values."""
        values = self._collect_form_values()
        if not values['application_key']:
            self.app.notify(
                "Enter at least Application Key and Consumer Key to test.",
                severity="warning",
            )
            return

        self.query_one("#ovh_test_result", Static).update("[dim]Testing connection...[/dim]")
        self.run_worker(
            self._do_test_connection(values),
            name="ovh_test",
            exclusive=True,
        )

    async def _do_test_connection(self, values: dict) -> None:
        """Worker: test OVH API credentials."""
        from servonaut.config.schema import OVHConfig
        from servonaut.services.ovh_service import OVHService

        temp_config = OVHConfig(
            enabled=False,
            endpoint=values['endpoint'],
            application_key=values['application_key'],
            application_secret=values['application_secret'],
            consumer_key=values['consumer_key'],
        )
        svc = OVHService(temp_config)
        try:
            result = await svc.test_connection()
            if result['success']:
                self.query_one("#ovh_test_result", Static).update(
                    f"[green]Connection successful! Account: {result['account']}[/green]"
                )
                self.app.notify(
                    f"OVH connected as: {result['account']}",
                    severity="information",
                )
            else:
                self.query_one("#ovh_test_result", Static).update(
                    f"[red]Connection failed: {result['message']}[/red]"
                )
                self.app.notify(
                    f"OVH connection failed: {result['message']}",
                    severity="error",
                )
        except Exception as e:
            logger.error("OVH connection test failed: %s", e)
            self.query_one("#ovh_test_result", Static).update(
                "[red]Connection test failed. Check credentials and try again.[/red]"
            )
            self.app.notify("OVH connection test failed. Check credentials.", severity="error")

    def _save_config(self, enable: bool) -> None:
        """Save OVH configuration to app config.

        Args:
            enable: Whether to enable the OVH provider.
        """
        from servonaut.config.schema import OVHConfig

        values = self._collect_form_values()
        config = self.app.config_manager.get()

        config.ovh = OVHConfig(
            enabled=enable,
            endpoint=values['endpoint'],
            application_key=values['application_key'],
            application_secret=values['application_secret'],
            consumer_key=values['consumer_key'],
            cloud_project_ids=values['cloud_project_ids'],
            include_dedicated=values['include_dedicated'],
            include_vps=values['include_vps'],
            include_cloud=values['include_cloud'],
        )

        try:
            self.app.config_manager.save(config)
            if enable:
                self.app.notify(
                    "OVH configuration saved and enabled. Restart or refresh to load instances.",
                    severity="information",
                    timeout=8,
                )
                logger.info("OVH configuration saved: enabled=True, endpoint=%s", values['endpoint'])
            else:
                self.app.notify("OVH disabled and settings saved.", severity="information")
                logger.info("OVH configuration saved: enabled=False")
            self.action_back()
        except Exception as e:
            logger.error("Failed to save OVH config: %s", e)
            self.app.notify("Failed to save OVH configuration. Check logs for details.", severity="error")

    def action_back(self) -> None:
        """Return to previous screen."""
        self.app.pop_screen()
