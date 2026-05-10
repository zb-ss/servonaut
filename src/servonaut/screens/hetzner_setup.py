"""Hetzner Cloud credential + defaults setup wizard screen.

Single-token provider — no OAuth2 / consumer-key dance like OVH. The
form covers the full :class:`servonaut.config.schema.HetznerConfig`
surface a first-time user needs:

* ``api_token`` (Read+Write scope, supports ``$ENV_VAR`` and ``file:`` prefixes)
* SSH defaults (Hetzner-side key name + local key path + username)
* ``hetzner create`` defaults (image, server type, location)

Save flow auto-installs the ``hcloud`` SDK if missing (pipx-aware,
mirroring :mod:`servonaut.screens.ovh_setup`'s pattern), initialises
:attr:`ServonautApp.hetzner_service`, and triggers an immediate
instance fetch so the table populates without a relaunch.
"""

from __future__ import annotations

import asyncio
import logging
from typing import List, TYPE_CHECKING, Tuple

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Select, Static

from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)


class HetznerSetupScreen(Screen):
    """Guided setup wizard for Hetzner Cloud — token + defaults."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    @property
    def app(self) -> "ServonautApp":  # type: ignore[override]
        return super().app  # type: ignore[return-value]

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static(
                    "[bold cyan]Hetzner Cloud Setup[/bold cyan]",
                    id="hetzner_setup_header",
                ),
                Static(
                    "[dim]Configure your Hetzner Cloud API token and defaults. "
                    "Servers will appear inline in the instance list once enabled.[/dim]",
                    classes="note",
                ),

                # Step 1 — API token
                Static("[bold]Step 1: API Token[/bold]", classes="section_header"),
                Static(
                    "[dim]Create a token at https://console.hetzner.cloud → "
                    "Project → Security → API Tokens. Use a [b]Read & Write[/b] "
                    "scope. The token can also be supplied via environment "
                    "(prefix with [b]$[/b], e.g. [b]$HCLOUD_TOKEN[/b]) or a file "
                    "(prefix with [b]file:[/b], e.g. [b]file:~/.config/hcloud/token[/b]).[/dim]",
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

                # Test + Save row
                Static("", id="hetzner_test_result"),
                Horizontal(
                    Button(
                        "Test Connection",
                        id="btn_hetzner_test",
                        variant="default",
                    ),
                    Button(
                        "Save & Enable",
                        id="btn_hetzner_save",
                        variant="primary",
                    ),
                    Button(
                        "Disable Hetzner",
                        id="btn_hetzner_disable",
                        variant="error",
                    ),
                    Button("Back", id="btn_hetzner_back"),
                    classes="hetzner_action_row",
                ),
                id="hetzner_setup_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        """Load existing Hetzner config into form fields."""
        config = self.app.config_manager.get()
        h = config.hetzner

        self.query_one("#hetzner_input_token", Input).value = h.api_token or ""
        self.query_one("#hetzner_input_local_ssh_key", Input).value = (
            h.default_local_ssh_key or ""
        )
        self.query_one("#hetzner_input_username", Input).value = (
            h.default_username or "root"
        )

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
            self._save_config(enable=True)
        elif button_id == "btn_hetzner_disable":
            self._save_config(enable=False)
        elif button_id == "btn_hetzner_back":
            self.action_back()

    # ------------------------------------------------------------------
    # Form helpers
    # ------------------------------------------------------------------

    def _collect_form_values(self) -> dict:
        return {
            "api_token": self.query_one("#hetzner_input_token", Input).value.strip(),
            "default_hetzner_ssh_key": self._select_value(
                "#hetzner_select_remote_ssh_key"
            ),
            "default_local_ssh_key": self.query_one(
                "#hetzner_input_local_ssh_key", Input
            ).value.strip(),
            "default_username": (
                self.query_one("#hetzner_input_username", Input).value.strip() or "root"
            ),
            "default_image": (
                self._select_value("#hetzner_select_image") or "ubuntu-22.04"
            ),
            "default_server_type": (
                self._select_value("#hetzner_select_server_type") or "cx23"
            ),
            "default_location": (
                self._select_value("#hetzner_select_location") or "fsn1"
            ),
        }

    # ------------------------------------------------------------------
    # hcloud SDK install (pipx-aware)
    # ------------------------------------------------------------------

    async def _install_hcloud_if_needed(self) -> bool:
        """Ensure the ``hcloud`` SDK is importable.

        Mirrors :meth:`OVHSetupScreen._install_ovh_if_needed`: detects
        whether servonaut is installed via pipx and, if so, uses
        ``pipx inject`` so the SDK lands in the same venv. Falls back
        to ``pip install`` otherwise. Returns False on install failure
        and surfaces a notification — caller should abort.
        """
        try:
            import hcloud  # noqa: F401

            return True
        except ImportError:
            pass

        import asyncio
        import shutil
        import subprocess
        import sys

        self.app.notify("Installing hcloud SDK...", severity="information")

        pipx_bin = shutil.which("pipx")
        use_pipx = False
        if pipx_bin:
            try:
                pipx_list = await asyncio.to_thread(
                    subprocess.check_output,
                    [pipx_bin, "list", "--short"],
                    text=True,
                )
                use_pipx = any(
                    line.strip().startswith("servonaut ")
                    for line in pipx_list.splitlines()
                )
            except subprocess.CalledProcessError:
                pass

        try:
            if use_pipx:
                await asyncio.to_thread(
                    subprocess.check_call,
                    [pipx_bin, "inject", "servonaut", "hcloud"],
                )
            else:
                await asyncio.to_thread(
                    subprocess.check_call,
                    [sys.executable, "-m", "pip", "install", "hcloud", "-q"],
                )
            logger.info(
                "hcloud SDK installed via %s", "pipx" if use_pipx else "pip"
            )
            return True
        except subprocess.CalledProcessError as exc:
            logger.error("Failed to install hcloud: %s", exc)
            hint = (
                "pipx inject servonaut hcloud"
                if use_pipx
                else "pip install 'servonaut[hetzner]'"
            )
            self.app.notify(
                f"Failed to install hcloud SDK. Run: {hint}",
                severity="error",
                timeout=10,
                markup=False,
            )
            return False

    # ------------------------------------------------------------------
    # Test
    # ------------------------------------------------------------------

    def _test_connection(self) -> None:
        values = self._collect_form_values()
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
            self._do_test_connection(values),
            name="hetzner_test",
            exclusive=True,
        )

    async def _do_test_connection(self, values: dict) -> None:
        if not await self._install_hcloud_if_needed():
            self.query_one("#hetzner_test_result", Static).update(
                "[red]hcloud SDK not installed. See notification.[/red]"
            )
            return

        from servonaut.config.schema import HetznerConfig
        from servonaut.services.hetzner_service import HetznerService

        temp_config = HetznerConfig(
            enabled=True,
            api_token=values["api_token"],
        )
        try:
            svc = HetznerService(temp_config)
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
            return

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
                f"[green]{label}[/green]"
            )
            self.app.notify("Hetzner connection OK.", severity="information")
            await self._populate_dropdowns_from_api(svc)
        else:
            self.query_one("#hetzner_test_result", Static).update(
                f"[red]Connection failed: {detail or 'no detail'}[/red]"
            )
            self.app.notify(
                f"Hetzner connection failed: {detail or 'no detail'}",
                severity="error",
                markup=False,
            )

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
        results = await asyncio.gather(
            svc.list_server_types(),
            svc.list_images(),
            svc.list_locations(),
            svc.list_ssh_keys(),
            return_exceptions=True,
        )
        types_res, images_res, locations_res, keys_res = results

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
        from servonaut.config.schema import HetznerConfig

        values = self._collect_form_values()
        config = self.app.config_manager.get()

        new_config = HetznerConfig(
            enabled=enable,
            api_token=values["api_token"],
            default_hetzner_ssh_key=values["default_hetzner_ssh_key"],
            default_local_ssh_key=values["default_local_ssh_key"],
            default_username=values["default_username"],
            default_image=values["default_image"],
            default_server_type=values["default_server_type"],
            default_location=values["default_location"],
            # Keep paths and tunables at their previous values so the
            # form doesn't accidentally reset cache_path / audit_path /
            # cost_alert_threshold etc. that the user may have edited
            # outside the wizard.
            cache_ttl_seconds=config.hetzner.cache_ttl_seconds,
            cache_path=config.hetzner.cache_path,
            audit_path=config.hetzner.audit_path,
            cost_alert_threshold=config.hetzner.cost_alert_threshold,
            require_ssh_keys_on_create=config.hetzner.require_ssh_keys_on_create,
        )
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

        if enable:
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
                self._ensure_hetzner_ready(new_config),
                name="hetzner_setup",
                exclusive=True,
            )
        else:
            self.app.hetzner_service = None
            self.app.notify(
                "Hetzner disabled and settings saved.", severity="information"
            )
            logger.info("Hetzner configuration saved: enabled=False")
            self.action_back()

    async def _ensure_hetzner_ready(self, hetzner_config) -> None:
        """Install hcloud if needed, init the service, fetch instances."""
        if not await self._install_hcloud_if_needed():
            self.action_back()
            return

        try:
            from servonaut.services.hetzner_service import (
                HetznerNotConfiguredError,
                HetznerSDKMissingError,
                HetznerService,
            )
        except ImportError as exc:
            logger.error("Hetzner service import failed: %s", exc)
            self.app.notify(
                "Hetzner service module unavailable. Check logs.",
                severity="error",
                markup=False,
            )
            self.action_back()
            return

        try:
            service = HetznerService(hetzner_config)
            # Force token resolution up front so we surface bad tokens
            # before the table starts firing background fetches.
            service.resolve_token()
            self.app.hetzner_service = service
        except HetznerNotConfiguredError as exc:
            logger.warning("Hetzner enabled but no token resolved: %s", exc)
            self.app.notify(
                f"Hetzner saved but token did not resolve: {exc}",
                severity="error",
                markup=False,
            )
            self.action_back()
            return
        except HetznerSDKMissingError as exc:
            logger.warning("Hetzner SDK still missing post-install: %s", exc)
            self.app.notify(
                f"hcloud SDK missing after install: {exc}",
                severity="error",
                markup=False,
            )
            self.action_back()
            return
        except Exception as exc:
            logger.error("Hetzner service init failed: %s", exc)
            self.app.notify(
                f"Hetzner service init failed: {exc}",
                severity="error",
                markup=False,
            )
            self.action_back()
            return

        # Fetch immediately so the table populates without a relaunch.
        self.app.notify(
            "Fetching Hetzner servers...", severity="information"
        )
        try:
            instances = await self.app.hetzner_service.fetch_instances_cached(
                force_refresh=True
            )
        except Exception as exc:
            logger.error("Hetzner initial fetch failed: %s", exc)
            self.app.notify(
                f"Hetzner enabled but initial fetch failed: {exc}",
                severity="error",
                markup=False,
            )
            self.action_back()
            return

        if instances:
            non_hetzner = [
                i for i in self.app.instances if not i.get("is_hetzner")
            ]
            self.app.instances = non_hetzner + instances
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

    def action_back(self) -> None:
        """Return to the Settings screen (or whatever pushed us)."""
        self.app.pop_screen()
