"""Hetzner Cloud credential + defaults setup wizard screen.

Single-token provider — no OAuth2 / consumer-key dance like OVH. The
form covers the full :class:`servonaut.config.schema.HetznerConfig`
surface a first-time user needs:

* ``api_token`` (Read+Write scope, supports ``$ENV_VAR`` and ``file:`` prefixes)
* SSH defaults (Hetzner-side key name + local key path + username)
* ``hetzner create`` defaults (image, server type, location)

Save flow auto-installs the ``hcloud`` SDK if missing (pipx-aware,
mirroring :mod:`servonaut.screens.ovh_setup`'s pattern), reloads the
provider accounts, and triggers an immediate instance fetch so the table
populates without a relaunch.

Besides the primary project (the ``hetzner`` block itself) the wizard adds
and edits EXTRA projects (``hetzner.accounts``): a label, the project's own
token and SSH defaults, and its own Object Storage keys. An extra project's
token is tested before it is saved.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from dataclasses import replace
from typing import List, Optional, TYPE_CHECKING, Tuple

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
    HETZNER_S3_DEFAULT_REGION,
    HETZNER_S3_REGIONS,
)
from servonaut.runtime import RuntimeCapabilityError, detect_runtime
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)


class HetznerSetupScreen(Screen):
    """Guided setup wizard for Hetzner Cloud — token + defaults.

    Opened with no arguments it sets up the primary project. ``add_extra``
    adds another project and ``extra`` edits extra project number *extra*;
    ``show_label`` also offers the primary project's label for editing.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    DEFAULT_CSS = """
    HetznerSetupScreen #hetzner_label_row {
        height: auto;
    }
    HetznerSetupScreen #hetzner_input_label {
        width: 1fr;
    }
    HetznerSetupScreen #btn_hetzner_add_project {
        margin: 0 1 0 0;
    }
    """

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
    def app(self) -> "ServonautApp":  # type: ignore[override]
        return super().app  # type: ignore[return-value]

    @property
    def _account_mode(self) -> bool:
        """True when the wizard adds or edits an EXTRA project."""
        return self._add_extra or self._extra_index is not None

    def compose(self) -> ComposeResult:
        h = self.app.config_manager.get().hetzner
        # The primary project's label only matters once there are several
        # projects; a single-project user never sees the row unasked.
        self._label_shown = (
            self._account_mode or self._show_label or bool(h.accounts) or bool(h.label)
        )
        yield SafeHeader()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                *self._intro_rows(),
                *self._token_rows(),
                *self._ssh_rows(),
                *([] if self._account_mode else self._create_default_rows()),
                *self._object_storage_rows(),
                # Test + Save row
                Static("", id="hetzner_test_result"),
                Horizontal(*self._action_buttons(), classes="hetzner_action_row"),
                id="hetzner_setup_container",
            )
        yield Footer()

    def _intro_rows(self) -> List[Widget]:
        if self._account_mode:
            title = (
                "Add a Hetzner Cloud Project" if self._add_extra else "Hetzner Cloud Project"
            )
            rows: List[Widget] = [
                Static(f"[bold cyan]{title}[/bold cyan]", id="hetzner_setup_header"),
                Static(
                    "[dim]Each Hetzner Cloud project has its own API token. Its "
                    "servers join the instance list next to your other projects; "
                    "the server-creation defaults of the primary project are "
                    "shared.[/dim]",
                    classes="note",
                ),
            ]
            placeholder = "e.g. staging (servers are shown as staging/<name>)"
        else:
            rows = [
                Static(
                    "[bold cyan]Hetzner Cloud Setup[/bold cyan]",
                    id="hetzner_setup_header",
                ),
                Static(
                    "[dim]Configure your Hetzner Cloud API token and defaults. "
                    "Servers will appear inline in the instance list once enabled.[/dim]",
                    classes="note",
                ),
            ]
            placeholder = "hetzner (the name shown for this project)"
        if self._label_shown:
            rows.append(
                Horizontal(
                    Static("Project Label:", classes="label"),
                    Input(placeholder=placeholder, id="hetzner_input_label"),
                    classes="setting_row",
                    id="hetzner_label_row",
                )
            )
        return rows

    def _token_rows(self) -> List[Widget]:
        if self._account_mode:
            where = (
                "a variable of its own (prefix with [b]$[/b], e.g. "
                "[b]$HCLOUD_TOKEN_STAGING[/b]) or a file (prefix with [b]file:[/b])"
            )
        else:
            where = (
                "environment (prefix with [b]$[/b], e.g. [b]$HCLOUD_TOKEN[/b]) or a file "
                "(prefix with [b]file:[/b], e.g. [b]file:~/.config/hcloud/token[/b])"
            )
        return [
            # Step 1 — API token
            Static("[bold]Step 1: API Token[/bold]", classes="section_header"),
            Static(
                "[dim]Create a token at https://console.hetzner.cloud → "
                "Project → Security → API Tokens. Use a [b]Read & Write[/b] "
                f"scope. The token can also be supplied via {where}.[/dim]",
                classes="note",
            ),
            Horizontal(
                Static("API Token:", classes="label"),
                Input(
                    placeholder="Hetzner API token, $ENV_VAR, or file:/path",
                    id="hetzner_input_token",
                    password=True,
                ),
                classes="setting_row",
            ),
        ]

    def _ssh_rows(self) -> List[Widget]:
        return [
            # Step 2 — SSH defaults
            Static("[bold]Step 2: SSH Defaults[/bold]", classes="section_header"),
            Static(
                "[dim][b]Hetzner-side SSH Key[/b] is the [i]name[/i] (or numeric ID) "
                "of an SSH key already registered on your Hetzner Cloud project — "
                "used at server-creation time so newly-created servers accept your "
                "key. [b]Local SSH Key[/b] is the on-disk private-key path used by "
                "[b]ssh -i[/b] when connecting to those servers.[/dim]",
                classes="note",
            ),
            Horizontal(
                Static("Hetzner SSH Key:", classes="label"),
                Select(
                    options=[],
                    id="hetzner_select_remote_ssh_key",
                    prompt="Test Connection to load options",
                    allow_blank=True,
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Local SSH Key:", classes="label"),
                Input(
                    placeholder="~/.ssh/id_rsa or ~/.ssh/hetzner_key",
                    id="hetzner_input_local_ssh_key",
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Default Username:", classes="label"),
                Input(
                    placeholder="root",
                    id="hetzner_input_username",
                    value="root",
                ),
                classes="setting_row",
            ),
        ]

    def _create_default_rows(self) -> List[Widget]:
        return [
            # Step 3 — Create-time defaults
            Static(
                "[bold]Step 3: hetzner create Defaults[/bold]",
                classes="section_header",
            ),
            Static(
                "[dim]Used when [b]servonaut hetzner create <name>[/b] (or the "
                "TUI's [b]+ New[/b] action) is called without explicit flags. "
                "Until you click [b]Test Connection[/b] each dropdown shows only "
                "your currently-saved value; a successful connection refreshes "
                "the list from the Hetzner API.[/dim]",
                classes="note",
            ),
            Horizontal(
                Static("Default Image:", classes="label"),
                Select(
                    options=[],
                    id="hetzner_select_image",
                    prompt="Test Connection to load options",
                    allow_blank=True,
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Default Server Type:", classes="label"),
                Select(
                    options=[],
                    id="hetzner_select_server_type",
                    prompt="Test Connection to load options",
                    allow_blank=True,
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Default Location:", classes="label"),
                Select(
                    options=[],
                    id="hetzner_select_location",
                    prompt="Test Connection to load options",
                    allow_blank=True,
                ),
                classes="setting_row",
            ),
        ]

    def _object_storage_rows(self) -> List[Widget]:
        step = 3 if self._account_mode else 4
        return [
            # Object Storage (S3-compatible) credentials
            Static(
                f"[bold]Step {step}: Object Storage (S3-compatible)[/bold]",
                classes="section_header",
            ),
            Static(
                "[dim]Hetzner Object Storage uses S3-compatible credentials "
                "(separate from the API token above). Generate keys at "
                "Hetzner Console → Object Storage → Manage Credentials. "
                "Leave blank to skip — the S3 file manager will show a "
                "configuration prompt instead. Both fields support "
                "[b]$ENV_VAR[/b] and [b]file:[/b] prefixes.[/dim]",
                classes="note",
            ),
            Horizontal(
                Static("Access Key:", classes="label"),
                Input(
                    placeholder="your-key or $HETZNER_S3_ACCESS_KEY or file:/path",
                    id="hetzner_input_s3_access_key",
                    password=True,
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Secret Key:", classes="label"),
                Input(
                    placeholder="your-secret or $HETZNER_S3_SECRET_KEY or file:/path",
                    id="hetzner_input_s3_secret_key",
                    password=True,
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Region:", classes="label"),
                Select(
                    options=[
                        (label, code)
                        for label, code in HETZNER_S3_REGIONS
                    ],
                    id="hetzner_input_s3_region",
                    value=HETZNER_S3_DEFAULT_REGION,
                    allow_blank=False,
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Endpoint URL:", classes="label"),
                Input(
                    placeholder="https://<region>.your-objectstorage.com (auto-derived from region — leave blank unless you have a custom endpoint)",
                    id="hetzner_input_s3_endpoint_url",
                ),
                classes="setting_row",
            ),
        ]

    def _action_buttons(self) -> List[Widget]:
        test = Button("Test Connection", id="btn_hetzner_test", variant="default")
        back = Button("Back", id="btn_hetzner_back")
        if self._account_mode:
            return [test, Button("Test & Save", id="btn_hetzner_save", variant="primary"), back]
        save = Button("Save & Enable", id="btn_hetzner_save", variant="primary")
        keep_off = Button("Save", id="btn_hetzner_disable")
        self._label_save_buttons(
            save, keep_off, self.app.config_manager.get().hetzner.enabled
        )
        return [
            test,
            save,
            keep_off,
            Button("Add Another Project", id="btn_hetzner_add_project"),
            back,
        ]

    @staticmethod
    def _label_save_buttons(save: Button, keep_off: Button, enabled: bool) -> None:
        """Name the primary project's save buttons after whether Hetzner is on.

        Save turns Hetzner on; the second button saves and leaves it off:
        "Disable Hetzner" while it is on, a plain "Save" while it is off (an
        Object-Storage-only setup saves its keys without listing servers).
        """
        save.label = "Save" if enabled else "Save & Enable"
        keep_off.label = "Disable Hetzner" if enabled else "Save"
        keep_off.variant = "error" if enabled else "default"

    def on_mount(self) -> None:
        """Load existing Hetzner config into form fields."""
        config = self.app.config_manager.get()
        h = config.hetzner
        if self._account_mode:
            self._load_extra_project(h)
            return

        if self._label_shown:
            self.query_one("#hetzner_input_label", Input).value = h.label
        # Another project can only join a provider that is set up.
        self.query_one("#btn_hetzner_add_project", Button).display = h.enabled
        self.query_one("#hetzner_input_token", Input).value = h.api_token or ""
        self.query_one("#hetzner_input_local_ssh_key", Input).value = (
            h.default_local_ssh_key or ""
        )
        self.query_one("#hetzner_input_username", Input).value = (
            h.default_username or "root"
        )

        # S3 / Object Storage credentials — independent of API token.
        s3 = h.object_storage
        self.query_one("#hetzner_input_s3_access_key", Input).value = s3.access_key
        self.query_one("#hetzner_input_s3_secret_key", Input).value = s3.secret_key
        # Region is a Select; fall back to the default when the saved
        # value isn't one of the known regions (stale config, new
        # provider entry pending, etc.).
        s3_region_sel = self.query_one("#hetzner_input_s3_region", Select)
        known_regions = {code for _, code in HETZNER_S3_REGIONS}
        s3_region_sel.value = (
            s3.region if s3.region in known_regions else HETZNER_S3_DEFAULT_REGION
        )
        self.query_one("#hetzner_input_s3_endpoint_url", Input).value = s3.endpoint_url

        # Seed each dropdown with just the user's current saved value so
        # they can save without first clicking Test Connection (e.g.
        # tweaking only the username). Test Connection later swaps in
        # the full API list and preserves whichever value is selected.
        self._seed_select(
            "#hetzner_select_remote_ssh_key", h.default_hetzner_ssh_key or "",
        )
        self._seed_select(
            "#hetzner_select_image", h.default_image or "ubuntu-22.04",
        )
        self._seed_select(
            "#hetzner_select_server_type", h.default_server_type or "cx23",
        )
        self._seed_select(
            "#hetzner_select_location", h.default_location or "fsn1",
        )

    def _load_extra_project(self, h) -> None:
        """Fill the form from extra project number ``extra`` (or blank)."""
        from servonaut.config.schema import HetznerAccount

        index = self._extra_index
        if index is not None and index >= len(h.accounts):
            self.app.notify("That Hetzner project no longer exists.", severity="error")
            self.call_after_refresh(self.action_back)
            return
        extra = h.accounts[index] if index is not None else HetznerAccount()

        self.query_one("#hetzner_input_label", Input).value = extra.label
        self.query_one("#hetzner_input_token", Input).value = extra.api_token
        local_key = self.query_one("#hetzner_input_local_ssh_key", Input)
        local_key.value = extra.default_local_ssh_key
        if h.default_local_ssh_key:
            local_key.placeholder = f"{h.default_local_ssh_key} (as the primary project)"
        username = self.query_one("#hetzner_input_username", Input)
        username.value = extra.default_username
        username.placeholder = f"{h.default_username or 'root'} (as the primary project)"

        s3 = extra.object_storage
        self.query_one("#hetzner_input_s3_access_key", Input).value = s3.access_key
        self.query_one("#hetzner_input_s3_secret_key", Input).value = s3.secret_key
        known_regions = {code for _, code in HETZNER_S3_REGIONS}
        self.query_one("#hetzner_input_s3_region", Select).value = (
            s3.region if s3.region in known_regions else HETZNER_S3_DEFAULT_REGION
        )
        self.query_one("#hetzner_input_s3_endpoint_url", Input).value = s3.endpoint_url
        self._seed_select("#hetzner_select_remote_ssh_key", extra.default_hetzner_ssh_key)

    def _seed_select(self, selector: str, value: str) -> None:
        """Pre-populate a Select with one option (the saved config value).

        Empty strings collapse to BLANK so the placeholder prompt
        ("Test Connection to load options") is shown — better signal
        than a row that just says "''".
        """
        sel = self.query_one(selector, Select)
        if value:
            sel.set_options([(value, value)])
            sel.value = value
        else:
            sel.set_options([])
            sel.value = Select.NULL

    def _select_value(self, selector: str) -> str:
        """Return the Select's selected value as a string ("" for BLANK)."""
        sel = self.query_one(selector, Select)
        return "" if sel.value is Select.NULL else str(sel.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn_hetzner_test":
            self._test_connection()
        elif button_id == "btn_hetzner_save":
            if self._account_mode:
                # An extra project is saved only once its token works.
                self._test_connection(save=True)
            else:
                self._save_config(enable=True)
        elif button_id == "btn_hetzner_add_project":
            self.app.switch_screen(HetznerSetupScreen(add_extra=True))
        elif button_id == "btn_hetzner_disable":
            self._save_config(enable=False)
        elif button_id == "btn_hetzner_back":
            self.action_back()

    # ------------------------------------------------------------------
    # Form helpers
    # ------------------------------------------------------------------

    def _collect_form_values(self) -> dict:
        username = self.query_one("#hetzner_input_username", Input).value.strip()
        values = {
            "api_token": self.query_one("#hetzner_input_token", Input).value.strip(),
            "default_hetzner_ssh_key": self._select_value(
                "#hetzner_select_remote_ssh_key"
            ),
            "default_local_ssh_key": self.query_one(
                "#hetzner_input_local_ssh_key", Input
            ).value.strip(),
            # An extra project's empty username inherits the primary's.
            "default_username": username if self._account_mode else (username or "root"),
            "s3_access_key": self.query_one(
                "#hetzner_input_s3_access_key", Input
            ).value.strip(),
            "s3_secret_key": self.query_one(
                "#hetzner_input_s3_secret_key", Input
            ).value.strip(),
            "s3_region": self._select_value("#hetzner_input_s3_region"),
            "s3_endpoint_url": self.query_one(
                "#hetzner_input_s3_endpoint_url", Input
            ).value.strip(),
        }
        if self._label_shown:
            values["label"] = self.query_one("#hetzner_input_label", Input).value.strip()
        if not self._account_mode:
            values["default_image"] = (
                self._select_value("#hetzner_select_image") or "ubuntu-22.04"
            )
            values["default_server_type"] = (
                self._select_value("#hetzner_select_server_type") or "cx23"
            )
            values["default_location"] = (
                self._select_value("#hetzner_select_location") or "fsn1"
            )
        return values

    def _label_problem(self, values: dict) -> Optional[str]:
        """Why the typed label cannot name this project, or None."""
        if not self._label_shown:
            return None
        config = self.app.config_manager.get()
        if not self._account_mode:
            index = None
        elif self._extra_index is None:
            index = len(config.hetzner.accounts)
        else:
            index = self._extra_index
        return label_error(config, "hetzner", values.get("label", ""), index=index)

    # ------------------------------------------------------------------
    # hcloud SDK installation
    # ------------------------------------------------------------------

    async def _install_hcloud_if_needed(self) -> bool:
        """Ensure the ``hcloud`` SDK is importable.

        The runtime's package capability owns the command choice. Packaged
        builds never guess an embedded pip command; a missing SDK there means
        the bundle must be repaired or reinstalled.
        """
        try:
            import hcloud  # noqa: F401

            return True
        except ImportError:
            pass

        runtime = getattr(self.app, "runtime_layout", None) or detect_runtime()
        capability = runtime.package_management
        if runtime.is_frozen:
            self.app.notify(
                "This packaged build is missing the hcloud SDK. "
                "Repair or reinstall the complete bundle.",
                severity="error",
                timeout=10,
                markup=False,
            )
            return False

        try:
            argv = capability.dependency_install_argv(["hcloud"])
        except RuntimeCapabilityError:
            self.app.notify(
                "The current Servonaut runtime cannot install the hcloud SDK.",
                severity="error",
                timeout=10,
                markup=False,
            )
            return False

        self.app.notify("Installing hcloud SDK...", severity="information", markup=False)

        try:
            import asyncio

            await asyncio.to_thread(subprocess.check_call, argv)
            logger.info("hcloud SDK installed via runtime package capability")
            return True
        except (subprocess.CalledProcessError, OSError) as exc:
            logger.error("Failed to install hcloud: %s", exc)
            self.app.notify(
                "Failed to install the hcloud SDK. Retry from a terminal.",
                severity="error",
                timeout=10,
                markup=False,
            )
            return False

    # ------------------------------------------------------------------
    # Test
    # ------------------------------------------------------------------

    def _test_connection(self, save: bool = False) -> None:
        """Test the token; with *save*, store the extra project if it works."""
        values = self._collect_form_values()
        if save:
            problem = self._label_problem(values)
            if problem is not None:
                self.app.notify(problem, severity="error", markup=False)
                self.query_one("#hetzner_input_label", Input).focus()
                return
        if not values["api_token"]:
            self.app.notify(
                "Enter an API token (or $ENV_VAR / file: ref) to test.",
                severity="warning",
            )
            return
        self.query_one("#hetzner_test_result", Static).update(
            "[dim]Testing connection...[/dim]"
        )
        self.run_worker(
            self._do_test_connection(values, save=save),
            name="hetzner_test",
            exclusive=True,
        )

    async def _do_test_connection(self, values: dict, save: bool = False) -> bool:
        if not await self._install_hcloud_if_needed():
            self.query_one("#hetzner_test_result", Static).update(
                "[red]hcloud SDK not installed. See notification.[/red]"
            )
            return False

        from servonaut.config.schema import HetznerConfig
        from servonaut.services.hetzner_service import HetznerService

        temp_config = HetznerConfig(
            enabled=True,
            api_token=values["api_token"],
        )
        try:
            # An extra project never falls back to $HCLOUD_TOKEN or the
            # hcloud CLI token: those belong to the primary project, and a
            # "working" test would then prove the wrong project.
            svc = HetznerService(temp_config, allow_ambient_token=not self._account_mode)
            result = await svc.test_connection()
        except Exception as exc:
            logger.error("Hetzner connection test failed: %s", exc)
            self.query_one("#hetzner_test_result", Static).update(
                "[red]Connection test failed. Check credentials and try again.[/red]"
            )
            # markup=False because exc message can carry server-controlled text.
            self.app.notify(
                f"Hetzner connection test failed: {exc}",
                severity="error",
                markup=False,
            )
            return False

        # ``test_connection`` returns a dict on the real service; success
        # signals vary across SDK versions, so accept the common shapes.
        if isinstance(result, dict):
            ok = (
                result.get("ok")
                or result.get("success")
                or result.get("status") == "ok"
            )
            detail = (
                result.get("project")
                or result.get("location")
                or result.get("message")
                or ""
            )
        else:
            ok = bool(result)
            detail = str(result) if result else ""

        if ok:
            label = "Connection successful!" + (
                f" {detail}" if detail else ""
            )
            self.query_one("#hetzner_test_result", Static).update(
                f"[green]{escape(label)}[/green]"
            )
            self.app.notify("Hetzner connection OK.", severity="information")
            await self._populate_dropdowns_from_api(svc)
            if save:
                await self._store_extra_project(self._collect_form_values())
            return True
        self.query_one("#hetzner_test_result", Static).update(
            f"[red]Connection failed: {escape(detail or 'no detail')}[/red]"
        )
        self.app.notify(
            f"Hetzner connection failed: {detail or 'no detail'}",
            severity="error",
            markup=False,
        )
        if save:
            self.app.notify(
                "The project was not saved: its token does not work.",
                severity="error",
                markup=False,
            )
        return False

    # ------------------------------------------------------------------
    # API-driven dropdown population
    # ------------------------------------------------------------------

    async def _populate_dropdowns_from_api(self, svc) -> None:
        """Refresh the four Selects with options pulled from Hetzner.

        Runs all four list calls in parallel via :func:`asyncio.gather`
        so the user doesn't wait serially for ~four round-trips. Any
        single call that fails leaves its dropdown untouched (still
        shows the seeded current-value option) — partial population
        is preferable to dropping back to free-text on a transient
        glitch.
        """
        if self._account_mode:
            # An extra project shows only its own SSH keys; the creation
            # defaults belong to the primary project.
            (keys_res,) = await asyncio.gather(svc.list_ssh_keys(), return_exceptions=True)
        else:
            types_res, images_res, locations_res, keys_res = await asyncio.gather(
                svc.list_server_types(),
                svc.list_images(),
                svc.list_locations(),
                svc.list_ssh_keys(),
                return_exceptions=True,
            )
            self._fill_create_defaults(types_res, images_res, locations_res)

        if isinstance(keys_res, Exception):
            logger.warning("list_ssh_keys failed: %s", keys_res)
        else:
            self._refresh_select(
                "#hetzner_select_remote_ssh_key",
                [
                    (
                        f"{k.get('name', '')}"
                        + (f" — {k.get('fingerprint', '')[:23]}" if k.get('fingerprint') else ""),
                        k.get("name", ""),
                    )
                    for k in keys_res
                    if k.get("name")
                ],
            )

    def _fill_create_defaults(self, types_res, images_res, locations_res) -> None:
        """Offer the listed server types, images and locations."""
        if isinstance(types_res, Exception):
            logger.warning("list_server_types failed: %s", types_res)
        else:
            self._refresh_select(
                "#hetzner_select_server_type",
                [
                    (
                        f"{t.get('name', '')} — "
                        f"{t.get('cores', 0)}vCPU / {t.get('memory_gb', 0)}GB / "
                        f"{t.get('architecture', '')} / "
                        f"€{t.get('monthly_price_gross') or '?'}/mo",
                        t.get("name", ""),
                    )
                    for t in types_res
                    if t.get("name")
                ],
            )

        if isinstance(images_res, Exception):
            logger.warning("list_images failed: %s", images_res)
        else:
            self._refresh_select(
                "#hetzner_select_image",
                [
                    (
                        f"{i.get('name', '')} — {i.get('description', '') or i.get('os_flavor', '')}"
                        f" ({i.get('architecture', '')})",
                        i.get("name", ""),
                    )
                    for i in images_res
                    if i.get("name")
                ],
            )

        if isinstance(locations_res, Exception):
            logger.warning("list_locations failed: %s", locations_res)
        else:
            self._refresh_select(
                "#hetzner_select_location",
                [
                    (
                        f"{loc.get('name', '')} — "
                        f"{loc.get('city', '') or loc.get('description', '')}"
                        f" ({loc.get('country', '')})",
                        loc.get("name", ""),
                    )
                    for loc in locations_res
                    if loc.get("name")
                ],
            )

    def _refresh_select(
        self, selector: str, options: List[Tuple[str, str]],
    ) -> None:
        """Replace a Select's options while preserving the current value.

        If the current value isn't present in the new option list (the
        user has a stale or deprecated default saved), it's prepended
        with a ``(saved)`` suffix so the user can keep it selected and
        explicitly re-pick if they want.
        """
        sel = self.query_one(selector, Select)
        current = "" if sel.value is Select.NULL else str(sel.value)

        merged: List[Tuple[str, str]] = []
        seen = set()
        if current and not any(opt_value == current for _, opt_value in options):
            merged.append((f"{current} (saved)", current))
            seen.add(current)
        for label, value in options:
            if value in seen:
                continue
            merged.append((label, value))
            seen.add(value)

        sel.set_options(merged)
        if current and current in seen:
            sel.value = current
        elif merged:
            sel.value = merged[0][1]
        else:
            sel.value = Select.NULL

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def _save_config(self, enable: bool) -> None:
        """Save the primary project (``enable`` False disables Hetzner)."""
        values = self._collect_form_values()
        problem = self._label_problem(values)
        if problem is not None:
            self.app.notify(problem, severity="error", markup=False)
            self.query_one("#hetzner_input_label", Input).focus()
            return
        config = self.app.config_manager.get()
        was_enabled = config.hetzner.enabled

        s3_config = replace(
            config.hetzner.object_storage,
            access_key=values["s3_access_key"],
            secret_key=values["s3_secret_key"],
            region=values["s3_region"],
            endpoint_url=values["s3_endpoint_url"],
        )
        # ``replace`` keeps what the form does not show — paths, tunables,
        # the label and the extra projects — exactly as saved.
        new_config = replace(
            config.hetzner,
            enabled=enable,
            api_token=values["api_token"],
            default_hetzner_ssh_key=values["default_hetzner_ssh_key"],
            default_local_ssh_key=values["default_local_ssh_key"],
            default_username=values["default_username"],
            default_image=values["default_image"],
            default_server_type=values["default_server_type"],
            default_location=values["default_location"],
            object_storage=s3_config,
        )
        if self._label_shown:
            new_config = replace(new_config, label=values["label"])
        config.hetzner = new_config

        try:
            self.app.config_manager.save(config)
        except Exception as exc:
            logger.error("Failed to save Hetzner config: %s", exc)
            self.app.notify(
                "Failed to save Hetzner configuration. Check logs.",
                severity="error",
            )
            return

        # Every surface moves to the saved projects together, Object Storage
        # included (so the sidebar's S3 entry appears at once); disabling
        # makes the Hetzner services go away.
        rebuild_accounts(self.app)

        if enable:
            # The form stays open: its buttons now act on an enabled Hetzner.
            self._label_save_buttons(
                self.query_one("#btn_hetzner_save", Button),
                self.query_one("#btn_hetzner_disable", Button),
                True,
            )
            self.app.notify(
                "Hetzner configuration saved.", severity="information"
            )
            logger.info(
                "Hetzner configuration saved: enabled=True, "
                "default_image=%s, default_server_type=%s, default_location=%s",
                values["default_image"],
                values["default_server_type"],
                values["default_location"],
            )
            self.run_worker(
                self._ensure_hetzner_ready(),
                name="hetzner_setup",
                exclusive=True,
            )
        else:
            self.app.notify(
                "Hetzner disabled and settings saved." if was_enabled
                else "Hetzner settings saved; Hetzner stays disabled.",
                severity="information",
            )
            logger.info("Hetzner configuration saved: enabled=False")
            self.action_back()

    def _hetzner_inventory(self):
        """Every Hetzner project as one inventory; None when none is usable."""
        lookup = getattr(self.app, "provider_inventory", None)
        return lookup("hetzner") if callable(lookup) else None

    async def _ensure_hetzner_ready(self) -> None:
        """Install hcloud if needed, check the token, fetch every project."""
        if not await self._install_hcloud_if_needed():
            self.action_back()
            return

        from servonaut.config.accounts import primary_label

        config = self.app.config_manager.get()
        key = primary_label("hetzner", config).lower()
        unavailable = getattr(getattr(self.app, "accounts", None), "unavailable", None) or {}
        reason = unavailable.get(f"hetzner:{key}")
        if reason:
            # Surface a bad token before the table starts firing fetches.
            logger.warning("Hetzner enabled but no token resolved: %s", reason)
            self.app.notify(
                f"Hetzner saved but token did not resolve: {reason}",
                severity="error",
                markup=False,
            )
        if self._hetzner_inventory() is None:
            self.action_back()
            return

        # Fetch immediately so the table populates without a relaunch.
        self.app.notify(
            "Fetching Hetzner servers...", severity="information"
        )
        try:
            instances, error = await reload_provider_fleet(self.app, "hetzner")
        except Exception as exc:
            logger.error("Hetzner initial fetch failed: %s", exc)
            self.app.notify(
                f"Hetzner enabled but initial fetch failed: {exc}",
                severity="error",
                markup=False,
            )
            self.action_back()
            return

        if error:
            # markup=False: the text carries an API error.
            self.app.notify(
                f"Hetzner refresh incomplete. {error}", severity="warning", markup=False
            )
        if instances:
            self.app.notify(
                f"Hetzner enabled — {len(instances)} server(s) loaded.",
                severity="information",
                timeout=8,
            )
        else:
            self.app.notify(
                "Hetzner enabled — no servers in this project yet.",
                severity="information",
            )

        self.action_back()

    async def _store_extra_project(self, values: dict) -> None:
        """Save the tested extra project, reload the accounts, list its servers."""
        from servonaut.config.schema import HetznerAccount

        config = self.app.config_manager.get()
        accounts = list(config.hetzner.accounts)
        index = self._extra_index
        editing = index is not None and index < len(accounts)
        previous = accounts[index] if editing else HetznerAccount()
        project = replace(
            previous,
            label=values["label"],
            api_token=values["api_token"],
            default_hetzner_ssh_key=values["default_hetzner_ssh_key"],
            default_local_ssh_key=values["default_local_ssh_key"],
            default_username=values["default_username"],
            object_storage=replace(
                previous.object_storage,
                access_key=values["s3_access_key"],
                secret_key=values["s3_secret_key"],
                region=values["s3_region"],
                endpoint_url=values["s3_endpoint_url"],
            ),
        )
        if editing:
            accounts[index] = project
        else:
            accounts.append(project)
        config.hetzner = replace(config.hetzner, accounts=accounts)
        try:
            self.app.config_manager.save(config)
        except Exception as exc:
            logger.error("Failed to save the Hetzner project: %s", exc)
            self.app.notify(
                "Failed to save the Hetzner project. Check logs.", severity="error"
            )
            return
        rebuild_accounts(self.app)
        label = values["label"]
        self.app.notify(f"Hetzner project '{label}' saved.", markup=False)

        if self._hetzner_inventory() is not None:
            try:
                instances, error = await reload_provider_fleet(self.app, "hetzner")
            except Exception as exc:
                logger.error("Hetzner fetch after adding a project failed: %s", exc)
                self.app.notify(
                    f"Listing the Hetzner servers failed: {exc}",
                    severity="warning",
                    markup=False,
                )
            else:
                if error:
                    self.app.notify(
                        f"Hetzner refresh incomplete. {error}",
                        severity="warning",
                        markup=False,
                    )
                count = sum(
                    1 for row in instances
                    if str(row.get("account") or "").lower() == label.lower()
                )
                self.app.notify(
                    f"Hetzner project '{label}': {count} server(s) loaded.",
                    severity="information",
                    markup=False,
                )
        self.action_back()

    def action_back(self) -> None:
        """Return to the Settings screen (or whatever pushed us)."""
        self.app.pop_screen()
