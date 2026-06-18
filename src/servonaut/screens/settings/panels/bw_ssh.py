"""Bitwarden SSH vault settings panel.

Configures personal Bitwarden vault wiring: which vault URL the CLI queries
when resolving per-instance SSH credential refs, and an optional default
collection ID. The config lives server-side at ``/api/v1/me/ssh-config`` —
not in ``config.json`` — so persistence goes through
``bw_ssh_config_service.put_personal_config`` rather than
``config_manager.update``.

402 from the API means the feature requires a paid plan; the panel surfaces
an upgrade notice and leaves the form open so the user can note their input.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import Button, Input, Static

from servonaut.screens.settings.base import SettingsPanel, ValidationError

logger = logging.getLogger(__name__)


class BwSshPanel(SettingsPanel):
    """Bitwarden SSH vault wiring — vault_url + default_collection_id.

    Unlike other panels this one persists via the cloud API (PUT
    ``/api/v1/me/ssh-config``) rather than ``config_manager``.  The panel
    follows the same SettingsPanel contract: status section for current state,
    an inline edit form that can be shown/hidden, a Save button that triggers
    an async worker, and Cancel to hide the form without saving.
    """

    PANEL_ID = "bw_ssh"
    TITLE = "Bitwarden SSH Vault"

    DEFAULT_CSS = """
    BwSshPanel .bw-status-row {
        height: auto;
        margin: 0 0 1 0;
    }
    BwSshPanel .bw-form {
        height: auto;
        border: round $primary;
        padding: 1 2;
        margin: 1 0;
    }
    BwSshPanel .bw-form-actions {
        height: auto;
        margin: 1 0 0 0;
    }
    BwSshPanel .bw-actions-row {
        height: auto;
        margin: 0 0 1 0;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        # Cached server response from get_personal_config; None = not yet loaded.
        self._bw_ssh_config: Optional[Dict[str, Any]] = None

    def form_rows(self) -> ComposeResult:
        """Yield the vault-wiring status, action button, and inline edit form."""
        yield Static(
            "[dim]Set up vault wiring to resolve per-instance SSH keys "
            "from your Bitwarden vault.[/dim]",
            classes="note",
        )
        # Current status line — updated by _refresh_bw_ssh_status after load/save.
        yield Static(
            "[dim]Not configured.[/dim]",
            id="bw_ssh_status",
            classes="bw-status-row",
        )
        yield Horizontal(
            Button("Edit", id="btn_bw_ssh_edit", variant="default"),
            classes="bw-actions-row",
        )
        # Inline edit form — hidden until the user clicks Edit.
        yield Container(
            Static("[bold]Edit Vault Wiring[/bold]", classes="section_header"),
            Horizontal(
                Static("Vault URL", classes="label"),
                Input(
                    id="bw_ssh_vault_url",
                    placeholder="https://vault.bitwarden.com",
                ),
                classes="setting_row",
            ),
            Horizontal(
                Static("Default Collection ID (optional)", classes="label"),
                Input(
                    id="bw_ssh_default_collection_id",
                    placeholder="",
                ),
                classes="setting_row",
            ),
            Horizontal(
                Button("Save", id="btn_bw_ssh_save", variant="primary"),
                Button("Cancel", id="btn_bw_ssh_cancel", variant="default"),
                classes="bw-form-actions",
            ),
            id="bw_ssh_vault_form",
            classes="bw-form",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        """Hide the form immediately, then kick off the async config fetch."""
        try:
            self._hide_form()
        except Exception:
            pass
        self._load_bw_ssh_config()

    def load(self) -> None:
        """Snapshot current widget state (no config.json fields to load here).

        The real population happens via the async worker initiated in
        :meth:`on_mount`.  ``_snapshot_now`` is called here so the base
        class dirty-tracker has a baseline; it will always reflect "empty
        form" until the worker populates the inputs and we snapshot again.
        """
        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current form values for dirty comparison."""
        try:
            vault_url = self.query_one("#bw_ssh_vault_url", Input).value.strip()
            collection_id = self.query_one(
                "#bw_ssh_default_collection_id", Input
            ).value.strip()
        except Exception:
            return {}
        return {"vault_url": vault_url, "default_collection_id": collection_id}

    def collect(self) -> Dict[str, Any]:
        """Validate form fields and return values to persist.

        Raises:
            ValidationError: When vault URL is empty or not http/https.
        """
        vault_url = self.query_one("#bw_ssh_vault_url", Input).value.strip()
        if not vault_url:
            raise ValidationError("bw_ssh_vault_url", "Vault URL is required.")
        if not (vault_url.startswith("http://") or vault_url.startswith("https://")):
            raise ValidationError(
                "bw_ssh_vault_url",
                "Vault URL must start with http:// or https://",
            )
        collection_id = (
            self.query_one("#bw_ssh_default_collection_id", Input).value.strip() or None
        )
        return {"vault_url": vault_url, "default_collection_id": collection_id}

    def persist(self) -> None:
        """Validate via :meth:`collect` then launch the async save worker.

        Unlike other panels, the actual write is async (API call).  Collect
        validates inputs eagerly; the worker handles the network path.
        """
        fields = self.collect()
        self.run_worker(
            self._do_save_bw_ssh_config(
                vault_url=fields["vault_url"],
                collection_id=fields.get("default_collection_id"),
            ),
            group="settings_bw_ssh",
            exclusive=True,
        )

    # ------------------------------------------------------------------
    # Button overrides (panel-specific buttons beyond the base Save)
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle Edit / Cancel in addition to the base Save logic."""
        button_id = event.button.id or ""
        if button_id == "btn_bw_ssh_edit":
            event.stop()
            self._show_form()
            return
        if button_id == "btn_bw_ssh_cancel":
            event.stop()
            self._hide_form()
            return
        # Delegate the panel Save button + any other buttons to the base class.
        super().on_button_pressed(event)

    # ------------------------------------------------------------------
    # Async load
    # ------------------------------------------------------------------

    def _load_bw_ssh_config(self) -> None:
        """Kick off a background fetch of the personal BW SSH config."""
        svc = getattr(self.app, "bw_ssh_config_service", None)
        if svc is None:
            return
        self.run_worker(
            self._do_load_bw_ssh_config(),
            group="settings_bw_ssh",
            name="bw_ssh_load",
            exclusive=True,
        )

    async def _do_load_bw_ssh_config(self) -> None:
        """Fetch the current config from the API and refresh the status line."""
        from servonaut.services.api_client import APIError  # avoid import cycle

        svc = getattr(self.app, "bw_ssh_config_service", None)
        if svc is None:
            return
        try:
            config = await svc.get_personal_config()
        except APIError as exc:
            logger.warning("BW SSH config load failed: %s", exc)
            return
        except Exception as exc:
            logger.warning("BW SSH config load failed: %s", exc)
            return
        self._bw_ssh_config = config
        self._refresh_bw_ssh_status()

    # ------------------------------------------------------------------
    # Async save
    # ------------------------------------------------------------------

    async def _do_save_bw_ssh_config(
        self,
        vault_url: str,
        collection_id: Optional[str],
    ) -> None:
        """PUT the vault wiring to the API, handle 402 → upgrade notice."""
        from servonaut.services.api_client import APIError  # avoid import cycle
        from servonaut.services.bw_ssh_config_service import BITWARDEN_PM_PROVIDER

        svc = getattr(self.app, "bw_ssh_config_service", None)
        if svc is None:
            self.app.notify(
                "Bitwarden SSH config service unavailable.",
                severity="error",
                markup=False,
            )
            return
        try:
            result = await svc.put_personal_config(
                vault_url=vault_url,
                default_collection_id=collection_id,
                provider=BITWARDEN_PM_PROVIDER,
            )
        except APIError as exc:
            if exc.status == 402:
                self.app.notify(
                    "Personal SSH vault config requires a paid plan. "
                    "Upgrade at https://servonaut.dev/pricing",
                    severity="warning",
                    markup=False,
                )
                # Keep form open so the user can review their input.
                return
            logger.error("BW SSH config save failed: %s", exc)
            self.app.notify(str(exc), severity="error", markup=False)
            return
        except Exception as exc:
            logger.error("BW SSH config save failed: %s", exc)
            self.app.notify(str(exc), severity="error", markup=False)
            return

        self._bw_ssh_config = result
        self._hide_form()
        self._refresh_bw_ssh_status()
        self._finish_save("Bitwarden SSH vault config saved.")

    # ------------------------------------------------------------------
    # Form show / hide
    # ------------------------------------------------------------------

    def _show_form(self) -> None:
        """Reveal the inline form and pre-populate from the cached config."""
        cfg = self._bw_ssh_config
        inner: Dict[str, Any] = cfg.get("config") or {} if cfg else {}

        try:
            vault_url_input = self.query_one("#bw_ssh_vault_url", Input)
            collection_input = self.query_one("#bw_ssh_default_collection_id", Input)
        except Exception:
            return

        vault_url_input.value = inner.get("vault_url", "") if inner else ""
        collection_input.value = inner.get("default_collection_id", "") if inner else ""

        try:
            self.query_one("#bw_ssh_vault_form").display = True
        except Exception:
            pass
        vault_url_input.focus()
        self._snapshot_now()

    def _hide_form(self) -> None:
        """Collapse the inline form without making an API call."""
        try:
            self.query_one("#bw_ssh_vault_form").display = False
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Status line refresh
    # ------------------------------------------------------------------

    def _refresh_bw_ssh_status(self) -> None:
        """Update the status Static from the cached ``_bw_ssh_config``."""
        try:
            status = self.query_one("#bw_ssh_status", Static)
        except Exception:
            return

        cfg = self._bw_ssh_config
        if cfg is None:
            status.update(
                "[dim]Not configured. Set up vault wiring to resolve "
                "per-instance SSH keys.[/dim]"
            )
            return

        inner: Dict[str, Any] = cfg.get("config") or {}
        vault_url: str = inner.get("vault_url", "")
        updated_at: str = cfg.get("updated_at", "")

        # Demo-mode: redact vault_url (may reveal self-hosted infra endpoint).
        if getattr(self.app, "demo_mode", False) and getattr(
            self.app, "redaction_service", None
        ):
            vault_url = "[redacted]"

        url_display = escape(vault_url) if vault_url else "[dim]unknown[/dim]"
        if updated_at:
            ts_display = escape(str(updated_at))
            status.update(
                f"[green]Configured.[/green] Vault: {url_display} · Updated {ts_display}"
            )
        else:
            status.update(f"[green]Configured.[/green] Vault: {url_display}")

    # ------------------------------------------------------------------
    # Dirty tracking (override: snapshot after form toggles)
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Refresh the dirty marker when the user edits either form field."""
        self._dirty_watch()
