"""Server Memory screen for Servonaut.

Displays stored memory modules for a server instance and provides
keyboard actions to refresh, pin, clear, annotate, and export memory.
"""

from __future__ import annotations

import getpass
import hashlib
import logging
import os
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from rich.markup import escape
from typing import Any, Dict, Optional

from servonaut.styles import CSS_FILES as _APP_CSS_FILES

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.services.memory.status import (
    STATUS_FRESH,
    STATUS_NONE,
    STATUS_OPT_OUT,
    STATUS_STALE,
    compute_memory_status,
)
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


def _sync_status_label(sync_service: Any) -> str:
    """Return a compact Rich markup string describing the sync status."""
    if sync_service is None:
        return "[dim]Cloud sync: unavailable[/dim]"
    try:
        status = sync_service.status
        state = status.state
        pending = status.pending_envelopes
        last = (status.last_sync_at or "never")[:19].replace("T", " ")
        if state == "running":
            return f"[cyan]Cloud sync: running[/cyan] · {pending} pending"
        if state == "halted":
            reason = status.halted_reason or "unknown"
            return f"[red]Cloud sync: halted ({reason})[/red] · {pending} pending"
        if state == "error":
            return f"[red]Cloud sync: error[/red] · last: {last}"
        return f"[green]Cloud sync: {state}[/green] · last: {last} · {pending} pending"
    except Exception:
        return "[dim]Cloud sync: unknown[/dim]"


def _enhancement_error_detail(exc: Exception) -> str:
    """Return a safe, actionable detail from a typed API error."""
    details = getattr(exc, "details", None)
    if isinstance(details, dict):
        detail = details.get("detail")
        if isinstance(detail, str) and detail.strip():
            return detail.strip()
    return str(exc)


# ---------------------------------------------------------------------------
# Helper: human-readable age string
# ---------------------------------------------------------------------------


def _human_age(probed_at_str: str) -> str:
    """Return a human-readable age string for a probed_at ISO timestamp.

    Args:
        probed_at_str: ISO-8601 UTC timestamp from stored module JSON.

    Returns:
        Age string, e.g. "5m ago", "2h ago", "3d ago", or "?" on error.
    """
    if not probed_at_str:
        return "?"
    try:
        probed_at = datetime.fromisoformat(probed_at_str.rstrip("Z"))
        if not probed_at.tzinfo:
            probed_at = probed_at.replace(tzinfo=timezone.utc)
        age_seconds = (datetime.now(tz=timezone.utc) - probed_at).total_seconds()
        if age_seconds < 60:
            return f"{int(age_seconds)}s ago"
        if age_seconds < 3600:
            return f"{int(age_seconds // 60)}m ago"
        if age_seconds < 86400:
            return f"{int(age_seconds // 3600)}h ago"
        return f"{int(age_seconds // 86400)}d ago"
    except (ValueError, TypeError):
        return "?"


_MEMORY_STATUS_LABELS = {
    STATUS_FRESH: "[green]● Fresh[/green]",
    STATUS_STALE: "[yellow]● Stale[/yellow]",
    STATUS_NONE: "[dim]○ Not probed[/dim]",
    STATUS_OPT_OUT: "[red]⛔ Opted-out[/red]",
}


def _memory_scan_status_label(instance: Dict[str, Any], memory_service: Any) -> str:
    """Return the current local scan status using the fleet-wide classifier."""
    if memory_service is None:
        return "[dim]Memory scan: unavailable[/dim]"

    status = compute_memory_status(instance, memory_service)
    status_label = _MEMORY_STATUS_LABELS.get(status, "[dim]unknown[/dim]")
    label = f"[bold]Memory scan:[/bold] {status_label}"
    if status not in (STATUS_FRESH, STATUS_STALE):
        return label

    instance_id = instance.get("id") or instance.get("name", "")
    provider = instance.get("provider", "custom")
    try:
        modules = memory_service.get_all_modules(instance_id, provider)
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "Could not load memory scan details for %s: %s",
            instance_id,
            exc,
        )
        return label

    module_count = len(modules)
    details = [f"{module_count} module{'s' if module_count != 1 else ''}"]
    latest_probed_at = max(
        (
            module.get("probed_at", "")
            for module in modules.values()
            if isinstance(module, dict)
        ),
        default="",
    )
    if latest_probed_at:
        details.append(f"last probe {_human_age(latest_probed_at)}")
    return f"{label} · {' · '.join(details)}"


# ---------------------------------------------------------------------------
# PinKeyModal
# ---------------------------------------------------------------------------


class PinKeyModal(ModalScreen[Optional[str]]):
    """Modal for pinning a declared value for a memory field.

    Args:
        module: Module name.
        key: Field key to pin.
        current_value: Current observed value (shown as placeholder).

    Returns via dismiss():
        The user-entered value string, or ``None`` on cancel.
    """

    DEFAULT_CSS = """
    PinKeyModal {
        align: center middle;
    }

    PinKeyModal #pin_modal_container {
        width: 60;
        height: auto;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }

    PinKeyModal #pin_modal_title {
        text-style: bold;
        margin-bottom: 1;
    }

    PinKeyModal #pin_modal_field {
        margin-bottom: 1;
    }

    PinKeyModal #pin_value_input {
        margin-bottom: 1;
    }

    PinKeyModal #pin_btn_row {
        height: auto;
        align: right middle;
    }

    PinKeyModal #pin_btn_cancel {
        margin-right: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    def __init__(self, module: str, key: str, current_value: str = "") -> None:
        super().__init__()
        self._module = module
        self._key = key
        self._current_value = current_value

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                f"[bold cyan]Pin value for [yellow]{self._module}[/yellow].[yellow]{self._key}[/yellow][/bold cyan]",
                id="pin_modal_title",
            ),
            Static(
                f"[dim]Current observed value:[/dim] {self._current_value or '[dim](none)[/dim]'}",
                id="pin_modal_field",
            ),
            Input(
                placeholder="Enter pinned value…",
                value="",
                id="pin_value_input",
            ),
            Horizontal(
                Button("Cancel", variant="default", id="pin_btn_cancel"),
                Button("Pin", variant="primary", id="pin_btn_confirm"),
                id="pin_btn_row",
            ),
            id="pin_modal_container",
        )

    def on_mount(self) -> None:
        self.query_one("#pin_value_input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "pin_btn_confirm":
            value = self.query_one("#pin_value_input", Input).value.strip()
            self.dismiss(value if value else None)
        elif event.button.id == "pin_btn_cancel":
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------------------
# SimpleConfirmModal
# ---------------------------------------------------------------------------


class SimpleConfirmModal(ModalScreen[bool]):
    """Lightweight confirm modal that asks a yes/no question.

    Args:
        message: The question to display.

    Returns via dismiss():
        ``True`` if confirmed, ``False`` on cancel.
    """

    DEFAULT_CSS = """
    SimpleConfirmModal {
        align: center middle;
    }

    SimpleConfirmModal #confirm_container {
        width: 55;
        height: auto;
        border: round $warning;
        background: $surface;
        padding: 1 2;
    }

    SimpleConfirmModal #confirm_message {
        margin-bottom: 1;
    }

    SimpleConfirmModal #confirm_btn_row {
        height: auto;
        align: right middle;
    }

    SimpleConfirmModal #confirm_no_btn {
        margin-right: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        yield Container(
            Static(self._message, id="confirm_message"),
            Horizontal(
                Button("No", variant="default", id="confirm_no_btn"),
                Button("Yes", variant="warning", id="confirm_yes_btn"),
                id="confirm_btn_row",
            ),
            id="confirm_container",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm_yes_btn":
            self.dismiss(True)
        else:
            self.dismiss(False)

    def action_cancel(self) -> None:
        self.dismiss(False)


# ---------------------------------------------------------------------------
# MemoryScreen
# ---------------------------------------------------------------------------


class MemoryScreen(Screen):
    """Screen for viewing and managing server memory modules.

    Displays observed + declared data per module, supports in-place probing
    refreshes, value pinning, module clearing, annotation editing (drop to
    ``$EDITOR``), and Markdown export.

    Args:
        instance: Instance dict with ``id``, ``name``, ``provider`` keys.
    """

    CSS_PATH = [*_APP_CSS_FILES, Path(__file__).parent.parent / "memory_screen.tcss"]

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh_all", "Refresh All", show=True),
        Binding("m", "refresh_module", "Refresh Module", show=True),
        Binding("p", "pin_key", "Pin", show=True),
        Binding("c", "clear_module", "Clear", show=True),
        Binding("a", "annotate", "Annotate", show=True),
        Binding("e", "export", "Export", show=True),
        Binding("v", "view_summary", "View Summary", show=True),
        Binding("S", "sync_now", "Sync Server", show=True),
        Binding("A", "enhance_with_ai", "Enhance Local", show=True),
        Binding("H", "build_ai_summary", "Generate Hosted", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def __init__(self, instance: dict) -> None:
        """Initialise MemoryScreen.

        Args:
            instance: Instance dict (same format as ``app.instances``).
        """
        super().__init__()
        self._instance = instance
        self._has_local_memory = False

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        """Compose the memory screen layout."""
        from rich.markup import escape

        instance_id = self._instance.get("id") or self._instance.get("name", "unknown")
        instance_name = self._instance.get("name") or instance_id
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static(
                    f"[bold cyan]Server Memory: {escape(str(instance_name))}[/bold cyan]",
                    id="memory-title",
                ),
                Static(
                    "[dim]Memory scan: checking…[/dim]",
                    id="memory-local-status",
                ),
                Static(
                    "[yellow]Memory disabled for this server.[/yellow]",
                    id="memory-opt-out-banner",
                    classes="hidden",
                ),
                # Inline informational banner — shown when Memory Sync is
                # not configured (Free tier or Solo not yet enrolled). Routes
                # to MemorySyncSetupScreen which adapts to the user's tier.
                Container(
                    Static("", id="memory-cloud-banner-text"),
                    Button(
                        "Set up →", variant="primary", id="btn_open_memory_sync_setup"
                    ),
                    id="memory-cloud-banner",
                    classes="hidden",
                ),
                # T11 empty-state CTA — shown when the DataTable has no rows
                # and the server is not opted out.  Resolves the UAT gap where
                # users couldn't tell they needed to press [r] to probe first.
                Container(
                    Static(
                        "[bold yellow]No memory captured yet.[/bold yellow]\n\n"
                        "[dim]Press [b]r[/b] or click below to probe this server.[/dim]",
                        id="memory-empty-state-label",
                    ),
                    Button(
                        "r. Probe server now", variant="primary", id="btn_empty_probe"
                    ),
                    id="memory-empty-state",
                    classes="hidden",
                ),
                DataTable(id="memory-table"),
                Horizontal(
                    Button("r. Refresh All", id="btn_refresh_all"),
                    Button("m. Refresh Module", id="btn_refresh_module"),
                    Button("p. Pin Key", id="btn_pin_key"),
                    Button("c. Clear Module", id="btn_clear_module"),
                    Button("a. Annotate", id="btn_annotate"),
                    id="memory-actions",
                ),
                Horizontal(
                    Static(
                        "[bold]Local summary[/bold]  [dim]Built on this device; "
                        "available without an AI plan.[/dim]",
                        id="memory-summary-status",
                    ),
                    Button("v. View Summary", variant="primary", id="btn_view_summary"),
                    Button("e. Export", id="btn_export"),
                    id="memory-summary-row",
                ),
                Horizontal(
                    Static(
                        "[dim]Cloud sync: unavailable[/dim]", id="memory-sync-status"
                    ),
                    Button("S. Sync This Server", id="btn_sync_now"),
                    id="memory-sync-row",
                ),
                Horizontal(
                    Static(
                        "[dim]AI enhancement: optional[/dim]", id="memory-ai-status"
                    ),
                    Button("A. Enhance Local Summary", id="btn_enhance_ai"),
                    Button("H. Generate from Memory Sync", id="btn_build_ai"),
                    id="memory-ai-row",
                ),
                Static(
                    "[dim]● Hosted summary · Idle[/dim]",
                    id="memory-hosted-status",
                ),
                id="memory-container",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Mount
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        """Set up DataTable columns and populate data on mount."""
        table = self.query_one("#memory-table", DataTable)
        table.cursor_type = "row"
        table.add_column("Module", key="module")
        table.add_column("Key", key="key")
        table.add_column("Observed", key="observed")
        table.add_column("Declared", key="declared")
        table.add_column("ProbedAt", key="probed_at")
        table.add_column("Age", key="age")
        self._render_table()
        self._refresh_sync_status()
        self._refresh_ai_status()
        self.set_interval(5, self._refresh_statuses)

    # ------------------------------------------------------------------
    # Table rendering
    # ------------------------------------------------------------------

    def _render_table(self) -> None:
        """Populate the DataTable with stored memory module data.

        Checks opt-out first; shows the banner and clears the table if
        memory is disabled for this instance.  Stale rows are coloured
        yellow via Rich markup.
        """
        self._refresh_local_memory_status()
        table = self.query_one("#memory-table", DataTable)
        banner = self.query_one("#memory-opt-out-banner", Static)

        instance_id = self._instance.get("id") or self._instance.get("name", "")
        provider = self._instance.get("provider", "custom")

        # Opt-out check
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is not None and self._is_opted_out(
            instance_id, memory_service
        ):
            banner.remove_class("hidden")
            table.clear()
            self._set_empty_state_visible(False)
            self._set_summary_actions_enabled(False)
            return

        banner.add_class("hidden")
        table.clear()

        if memory_service is None:
            self._set_empty_state_visible(False)
            self._set_summary_actions_enabled(False)
            return

        # Load all stored modules
        try:
            all_modules: Dict[str, Dict[str, Any]] = memory_service.get_all_modules(
                instance_id, provider
            )
        except Exception as exc:
            logger.warning("Could not load memory modules for %s: %s", instance_id, exc)
            self._set_empty_state_visible(False)
            self._set_summary_actions_enabled(False)
            return

        if not all_modules:
            # Empty: show the CTA so users know how to populate memory.
            self._set_empty_state_visible(True)
            self._set_summary_actions_enabled(False)
            return
        self._set_empty_state_visible(False)
        self._set_summary_actions_enabled(True)

        # Determine stale modules
        try:
            stale_names = set(memory_service.stale_modules(instance_id, provider))
        except Exception as exc:  # noqa: BLE001
            logger.debug("stale_modules failed for %s: %s", instance_id, exc)
            stale_names = set()

        for module_name in sorted(all_modules.keys()):
            data = all_modules[module_name]
            observed: Dict[str, Any] = data.get("observed", {})
            declared: Dict[str, Any] = data.get("declared", {})
            probed_at_str: str = data.get("probed_at", "")
            probed_at_display = (
                probed_at_str[:19].replace("T", " ") if probed_at_str else ""
            )
            age_display = _human_age(probed_at_str)
            is_stale = module_name in stale_names

            if is_stale:
                age_display = f"[yellow]{age_display}[/yellow]"

            if not observed:
                # Show a placeholder row for modules with no observed keys
                table.add_row(
                    module_name,
                    "",
                    "",
                    "",
                    probed_at_display,
                    age_display,
                    key=f"{module_name}::__empty__",
                )
                continue

            for key, obs_value in observed.items():
                decl_entry = declared.get(key)
                decl_value = (
                    decl_entry.get("value", "") if isinstance(decl_entry, dict) else ""
                )
                obs_str = str(obs_value) if obs_value is not None else ""
                decl_str = str(decl_value) if decl_value is not None else ""
                # Scrub observed and declared values (highest-value memory wire).
                # module_name and key are taxonomy — do NOT scrub.
                if (
                    getattr(self.app, "demo_mode", False)
                    and getattr(self.app, "redaction_service", None) is not None
                ):
                    obs_str = self.app.redaction_service.scrub_stream(obs_str)
                    decl_str = self.app.redaction_service.scrub_stream(decl_str)

                table.add_row(
                    module_name,
                    key,
                    obs_str,
                    decl_str,
                    probed_at_display,
                    age_display,
                    key=f"{module_name}::{key}",
                )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _set_empty_state_visible(self, visible: bool) -> None:
        """Show or hide the T11 empty-state CTA."""
        try:
            cta = self.query_one("#memory-empty-state")
        except Exception:  # noqa: BLE001 — container not mounted yet is fine
            return
        if visible:
            cta.remove_class("hidden")
        else:
            cta.add_class("hidden")

    def _set_summary_actions_enabled(self, enabled: bool) -> None:
        """Enable summary actions only when local memory exists."""
        self._has_local_memory = enabled
        for button_id in ("#btn_view_summary", "#btn_export"):
            try:
                self.query_one(button_id, Button).disabled = not enabled
            except Exception:  # noqa: BLE001 - compose may not have mounted yet
                pass
        self._refresh_ai_status()

    def _refresh_ai_status(self) -> None:
        """Describe configured enhancement providers without choosing one."""
        provider_names: list[str] = []
        ai_service = getattr(self.app, "ai_analysis_service", None)
        if ai_service is not None:
            try:
                provider_names = list(ai_service.available_memory_summary_providers())
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not resolve Memory-summary providers: %s", exc)

        try:
            status = self.query_one("#memory-ai-status", Static)
            enhance_button = self.query_one("#btn_enhance_ai", Button)
            enhance_button.disabled = not (self._has_local_memory and provider_names)
            if provider_names:
                status.update(
                    "[dim]AI summaries · Enhance the local view or generate "
                    "from synced memory[/dim]"
                )
            else:
                status.update(
                    "[dim]AI enhancement: optional · configure a provider in "
                    "Settings to enable[/dim]"
                )
        except Exception:  # noqa: BLE001 - screen may not have mounted yet
            pass

    def _scrub_summary_for_demo(self, summary: str) -> str:
        """Scrub summary text before rendering in demo mode."""
        if not getattr(self.app, "demo_mode", False):
            return summary
        redaction_service = getattr(self.app, "redaction_service", None)
        if redaction_service is None:
            return summary
        try:
            return redaction_service.scrub_stream(summary)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not scrub Memory summary for demo mode: %s", exc)
            return summary

    def _is_opted_out(self, instance_id: str, memory_service: Any) -> bool:
        """Return True if memory is disabled for this instance.

        Checks by both cloud id and human-readable name so that
        per_server_overrides keyed by name (not id) are honoured.

        Args:
            instance_id: Instance identifier to check.
            memory_service: The wired MemoryService (may be None).

        Returns:
            True when the global enabled flag is False or when this
            specific instance has been opted out via per_server_overrides.
        """
        instance_name = self._instance.get("name", "")
        try:
            return memory_service.is_memory_disabled(instance_id, instance_name)
        except Exception as exc:  # noqa: BLE001
            logger.debug("is_memory_disabled check failed: %s", exc)
            return False

    def _get_cursor_module_key(self) -> tuple[str, str]:
        """Return (module_name, key) for the currently focused DataTable row.

        Returns:
            Tuple of (module_name, key) strings; both empty strings when
            no valid row is selected.
        """
        table = self.query_one("#memory-table", DataTable)
        if table.row_count == 0:
            return "", ""
        try:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate)
            row_id = row_key.row_key.value or ""
            if "::" in row_id:
                module_name, key = row_id.split("::", 1)
                return module_name, key
        except Exception as exc:  # noqa: BLE001
            logger.debug("_get_cursor_module_key failed: %s", exc)
        return "", ""

    # ------------------------------------------------------------------
    # Button handler
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Map button presses to actions."""
        btn_map = {
            "btn_refresh_all": self.action_refresh_all,
            "btn_refresh_module": self.action_refresh_module,
            "btn_pin_key": self.action_pin_key,
            "btn_clear_module": self.action_clear_module,
            "btn_annotate": self.action_annotate,
            "btn_export": self.action_export,
            "btn_view_summary": self.action_view_summary,
            # T11: CTA in the empty-state dispatches the same refresh-all flow.
            "btn_empty_probe": self.action_refresh_all,
            "btn_sync_now": self.action_sync_now,
            "btn_enhance_ai": self.action_enhance_with_ai,
            "btn_build_ai": self.action_build_ai_summary,
            "btn_open_memory_sync_setup": self.action_open_memory_sync_setup,
        }
        handler = btn_map.get(event.button.id)
        if handler:
            handler()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_back(self) -> None:
        """Pop this screen and return to the previous one."""
        self.app.pop_screen()

    def action_refresh_all(self) -> None:
        """Refresh all memory modules for this instance."""
        instance_id = self._instance.get("id") or self._instance.get("name", "")
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            self.app.notify("Memory service not available.", severity="error")
            return
        if self._is_opted_out(instance_id, memory_service):
            self.app.notify("Memory disabled for this server.", severity="warning")
            return
        self.run_worker(
            self._do_refresh_all(),
            exclusive=True,
            group="memory_refresh",
            name="memory_refresh_all",
        )

    async def _do_refresh_all(self) -> None:
        """Worker: probe all modules and re-render the table."""
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            return
        self.app.notify("Probing all modules…")
        try:
            await memory_service.refresh(self._instance)
            self._render_table()
            self.app.notify("Memory refreshed.")
        except Exception as exc:
            logger.error("Memory refresh failed: %s", exc, exc_info=True)
            self.app.notify(f"Refresh failed: {exc}", severity="error")

    def action_refresh_module(self) -> None:
        """Refresh the module at the cursor row."""
        instance_id = self._instance.get("id") or self._instance.get("name", "")
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            self.app.notify("Memory service not available.", severity="error")
            return
        if self._is_opted_out(instance_id, memory_service):
            self.app.notify("Memory disabled for this server.", severity="warning")
            return
        module_name, _ = self._get_cursor_module_key()
        if not module_name:
            self.app.notify("Select a row first.", severity="warning")
            return
        self.run_worker(
            self._do_refresh_module(module_name),
            exclusive=True,
            group="memory_refresh",
            name=f"memory_refresh_{module_name}",
        )

    async def _do_refresh_module(self, module_name: str) -> None:
        """Worker: probe a single module and re-render."""
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            return
        self.app.notify(f"Probing {module_name}…")
        try:
            await memory_service.refresh(self._instance, modules=[module_name])
            self._render_table()
            self.app.notify(f"Module '{module_name}' refreshed.")
        except Exception as exc:
            logger.error("Module refresh failed: %s", exc, exc_info=True)
            self.app.notify(f"Refresh failed: {exc}", severity="error")

    def action_pin_key(self) -> None:
        """Push PinKeyModal to pin a declared value for the cursor key."""
        instance_id = self._instance.get("id") or self._instance.get("name", "")
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            self.app.notify("Memory service not available.", severity="error")
            return
        if self._is_opted_out(instance_id, memory_service):
            self.app.notify("Memory disabled for this server.", severity="warning")
            return
        module_name, key = self._get_cursor_module_key()
        if not module_name or not key or key == "__empty__":
            self.app.notify("Select a key row first.", severity="warning")
            return

        # Look up the current observed value for the placeholder text
        provider = self._instance.get("provider", "custom")
        try:
            data = memory_service.get(instance_id, module_name, provider)
            current_value = str(data.get("observed", {}).get(key, "")) if data else ""
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "Could not read current value for %s.%s: %s", module_name, key, exc
            )
            current_value = ""

        def _on_dismiss(value: Optional[str]) -> None:
            if value is None:
                return
            self.run_worker(
                self._do_pin(instance_id, module_name, key, value),
                exclusive=False,
                group="memory_mutation",
                name=f"memory_pin_{module_name}_{key}",
            )

        self.app.push_screen(PinKeyModal(module_name, key, current_value), _on_dismiss)

    async def _do_pin(
        self,
        instance_id: str,
        module_name: str,
        key: str,
        value: str,
    ) -> None:
        """Worker: call MemoryService.pin and re-render."""
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            return
        provider = self._instance.get("provider", "custom")
        try:
            await memory_service.pin(
                instance_id,
                module_name,
                key,
                value,
                pinned_by=getpass.getuser(),
                provider=provider,
            )
            self._render_table()
            self.app.notify(f"Pinned {module_name}.{key} = {value!r}")
        except Exception as exc:
            logger.error("Pin failed: %s", exc, exc_info=True)
            self.app.notify(f"Pin failed: {exc}", severity="error")

    def action_clear_module(self) -> None:
        """Clear the module at the cursor row after confirmation."""
        instance_id = self._instance.get("id") or self._instance.get("name", "")
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            self.app.notify("Memory service not available.", severity="error")
            return
        if self._is_opted_out(instance_id, memory_service):
            self.app.notify("Memory disabled for this server.", severity="warning")
            return
        module_name, _ = self._get_cursor_module_key()
        if not module_name:
            self.app.notify("Select a row first.", severity="warning")
            return

        def _on_confirmed(confirmed: bool) -> None:
            if not confirmed:
                return
            # Re-check opt-out at action time
            if self._is_opted_out(instance_id, memory_service):
                self.app.notify("Memory disabled for this server.", severity="warning")
                return
            provider = self._instance.get("provider", "custom")
            try:
                memory_service.clear(
                    instance_id, modules=[module_name], provider=provider
                )
                self._render_table()
                self.app.notify(f"Module '{module_name}' cleared.")
            except Exception as exc:
                logger.error("Clear failed: %s", exc, exc_info=True)
                self.app.notify(f"Clear failed: {exc}", severity="error")

        self.app.push_screen(
            SimpleConfirmModal(f"Clear module [bold]{module_name}[/bold]?"),
            _on_confirmed,
        )

    def _annotation_template(self, instance_id: str) -> str:
        """Return the seed content for a fresh ``annotations.md`` file.

        First-time users open this via the ``a`` key and expect to see
        the server's existing memory — but annotations are a separate
        free-form notes file.  Seeding a short template makes that
        distinction obvious without fighting the data-table surface.
        """
        name = self._instance.get("name") or instance_id
        provider = self._instance.get("provider", "custom")
        return (
            f"# Notes — {name} ({instance_id}) @ {provider}\n"
            "\n"
            "<!--\n"
            "Free-form notes about this server.  They appear in the memory\n"
            "summary alongside machine-probed data (OS, runtimes, services,\n"
            "logs), which is what the chat panel and MCP agents read.\n"
            "\n"
            "The read-only table you saw on the Memory screen is the probed\n"
            "data — edit observed values with 'p' (Pin) instead of writing\n"
            "them here.  Everything below this comment block is yours: use\n"
            "it for purpose / runbook notes / ownership / known quirks.\n"
            "\n"
            "Delete this comment block freely; it is only a one-shot primer.\n"
            "-->\n"
            "\n"
            "## Purpose\n"
            "\n"
            '<!-- What does this server do? e.g. "primary billing API, '
            'reads from RDS, serves api.example.com" -->\n'
            "\n"
            "## Runbook\n"
            "\n"
            "<!-- Deploy path, log locations, key commands, known quirks. -->\n"
            "\n"
            "## Ownership\n"
            "\n"
            "<!-- Team, owner, Slack channel, escalation path. -->\n"
            "\n"
        )

    def action_annotate(self) -> None:
        """Open the annotations file in the user's ``$EDITOR``.

        Drops out of the TUI via ``self.app.suspend()``, opens the editor,
        then re-renders the table on return.
        """
        instance_id = self._instance.get("id") or self._instance.get("name", "")
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            self.app.notify("Memory service not available.", severity="error")
            return
        if self._is_opted_out(instance_id, memory_service):
            self.app.notify("Memory disabled for this server.", severity="warning")
            return

        provider = self._instance.get("provider", "custom")
        try:
            path = memory_service.get_annotations_path(instance_id, provider)
        except Exception as exc:
            self.app.notify(
                f"Could not resolve annotations path: {exc}", severity="error"
            )
            return

        # Seed a short template on first open so operators understand what
        # goes here (free-form notes) vs. what is machine-probed (the table
        # on this screen).  Also treat zero-byte files as "first open" —
        # an earlier crash or an interrupted first annotate left some users
        # with an empty annotations.md that was never seeded.
        try:
            needs_seed = (not path.exists()) or path.stat().st_size == 0
        except OSError:
            needs_seed = True
        if needs_seed:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch(mode=0o600)
                path.write_text(
                    self._annotation_template(instance_id),
                    encoding="utf-8",
                )
            except OSError as exc:
                self.app.notify(
                    f"Could not create annotations file: {exc}", severity="error"
                )
                return

        editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
        # $EDITOR / $VISUAL may include flags (e.g. "emacsclient -c -a emacs")
        # so split with shlex rather than passing the raw string as argv[0];
        # otherwise subprocess tries to exec the whole thing as a binary name
        # and crashes with FileNotFoundError.
        try:
            argv = shlex.split(editor)
        except ValueError:
            argv = [editor]
        if not argv:
            argv = ["vi"]
        argv.append(str(path))

        logger.info("Opening annotations editor: argv=%r path=%s", argv, path)

        # Heuristic: catch the common "$EDITOR=emacs -c -a emacs" typo.  Those
        # flags are emacsclient-specific; plain emacs treats them as filenames
        # and opens buffers named -c / -a / emacs alongside the real file,
        # which users perceive as "emacs opened but not my file".
        editor_binary = os.path.basename(argv[0])
        looks_like_bad_emacs_config = editor_binary == "emacs" and any(
            flag in argv[1:-1] for flag in ("-c", "-a", "--alternate-editor")
        )
        try:
            with self.app.suspend():
                # capture_output so a non-zero exit (e.g. emacsclient can't
                # reach a daemon and fallback emacs fails) can be surfaced
                # instead of dropping the user back into the TUI with no
                # clue why nothing happened.
                proc = subprocess.run(  # noqa: S603
                    argv,
                    check=False,
                    capture_output=True,
                    text=True,
                )
        except FileNotFoundError:
            self.app.notify(
                f"Editor not found: {argv[0]}. Set $EDITOR or $VISUAL to an "
                "installed command (e.g. 'vi', 'nano').",
                severity="error",
            )
            return
        except OSError as exc:
            self.app.notify(f"Could not launch editor: {exc}", severity="error")
            return

        if looks_like_bad_emacs_config:
            self.app.notify(
                "Your $EDITOR is 'emacs' but uses emacsclient flags (-c / -a). "
                "Plain emacs treats those as filenames, so the wrong buffer "
                "is focused. Set $EDITOR='emacsclient -c -a emacs' or "
                "just 'emacs', not both.",
                severity="warning",
                timeout=10,
            )

        if proc is not None and proc.returncode != 0:
            stderr_snippet = (proc.stderr or "").strip().splitlines()
            last_err = stderr_snippet[-1] if stderr_snippet else ""
            logger.warning(
                "Editor exited non-zero: argv=%r rc=%d stderr=%r",
                argv,
                proc.returncode,
                proc.stderr,
            )
            # emacsclient is a common trip-wire: it only opens a frame when
            # an emacs daemon is running, and "emacsclient -c -a emacs"
            # falls back to GUI emacs which needs DISPLAY.  Hint at the fix
            # rather than just showing a bare exit code.
            hint = ""
            if "emacsclient" in argv[0]:
                hint = (
                    " — try 'emacsclient -t' (terminal frame) or start an "
                    "emacs daemon with 'emacs --daemon'."
                )
            msg = (
                f"Editor exited with code {proc.returncode}"
                f"{': ' + last_err if last_err else ''}{hint}"
            )
            self.app.notify(msg, severity="warning")

        # After the editor closes, compute a content hash and enqueue the
        # updated annotations for sync if the content has changed.
        try:
            content = memory_service.read_annotations(instance_id, provider)
            new_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            prior_hash = memory_service.get_annotations_meta(instance_id).get(
                "annotations_hash", ""
            )
            if new_hash != prior_hash:
                now_iso = datetime.now(timezone.utc).isoformat()
                memory_service.set_annotations_meta(
                    instance_id,
                    annotations_hash=new_hash,
                    annotations_modified_at=now_iso,
                )
                sync = getattr(self.app, "memory_sync_service", None)
                if sync is not None:
                    sync.enqueue_annotations(self._instance, content, probed_at=now_iso)
        except Exception as exc:
            logger.warning("Could not enqueue annotations after edit: %s", exc)

        self._render_table()

    def action_view_summary(self) -> None:
        """Render the deterministic local summary without an entitlement gate."""
        instance_id = self._instance.get("id") or self._instance.get("name", "")
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            self.app.notify("Memory service not available.", severity="error")
            return
        if self._is_opted_out(instance_id, memory_service):
            self.app.notify("Memory disabled for this server.", severity="warning")
            return
        if not self._has_local_memory:
            self.app.notify(
                "No local memory exists yet. Probe this server first.",
                severity="warning",
            )
            return
        self.run_worker(
            self._do_view_summary(),
            exclusive=False,
            group="memory_io",
            name="memory_view_summary",
        )

    async def _do_view_summary(self) -> None:
        """Build and open the local Markdown summary reader."""
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            return
        try:
            summary = await memory_service.get_summary(self._instance)
            summary = self._scrub_summary_for_demo(summary)
            from servonaut.screens.memory_summary import MemorySummaryScreen

            instance_name = (
                self._instance.get("name") or self._instance.get("id") or "Server"
            )
            self.app.push_screen(
                MemorySummaryScreen(
                    title=f"Memory Summary: {instance_name}",
                    summary=summary,
                    source_label=(
                        "Local · deterministic · built on this device · "
                        "no AI entitlement required"
                    ),
                )
            )
        except Exception as exc:
            logger.error("Local summary failed: %s", exc, exc_info=True)
            self.app.notify(
                f"Could not build local summary: {exc}",
                severity="error",
                markup=False,
            )

    def action_enhance_with_ai(self) -> None:
        """Ask the user to select and consent to one configured provider."""
        if not self._has_local_memory:
            self.app.notify(
                "No local memory exists yet. Probe this server first.",
                severity="warning",
            )
            return
        ai_service = getattr(self.app, "ai_analysis_service", None)
        if ai_service is None:
            self.app.notify("AI analysis service not available.", severity="warning")
            return
        try:
            providers = ai_service.available_memory_summary_providers()
        except Exception as exc:  # noqa: BLE001
            logger.error("Could not list AI providers: %s", exc)
            self.app.notify(
                f"Could not list configured AI providers: {exc}",
                severity="error",
                markup=False,
            )
            return
        if not providers:
            self.app.notify(
                "Configure an AI provider in Settings before enhancing a summary.",
                severity="warning",
            )
            return

        from servonaut.screens.memory_summary import AIEnhanceConsentModal

        def _after_consent(provider_name: Optional[str]) -> None:
            if not provider_name:
                return
            self.run_worker(
                self._do_enhance_with_ai(provider_name),
                exclusive=False,
                group="memory_ai_summary",
                name="memory_ai_enhance",
            )

        self.app.push_screen(
            AIEnhanceConsentModal(providers),
            _after_consent,
        )

    async def _do_enhance_with_ai(self, provider_name: str) -> None:
        """Send the local summary to exactly the consented provider."""
        memory_service = getattr(self.app, "memory_service", None)
        ai_service = getattr(self.app, "ai_analysis_service", None)
        config_manager = getattr(self.app, "config_manager", None)
        if memory_service is None or ai_service is None or config_manager is None:
            self.app.notify(
                "AI enhancement services are not available.",
                severity="error",
            )
            return
        try:
            local_summary = await memory_service.get_summary(self._instance)
            prompt = config_manager.get().memory.ai_enhancement_prompt
            from servonaut.screens.memory_summary import (
                MemorySummaryScreen,
                provider_label,
            )

            label = provider_label(provider_name)
            self.app.notify(
                f"Sending the local summary to {label} with tools disabled…",
                markup=False,
            )
            result = await ai_service.enhance_memory_summary(
                local_summary,
                provider_name,
                prompt,
            )
            enhanced_summary = self._scrub_summary_for_demo(result["content"])
            instance_name = (
                self._instance.get("name") or self._instance.get("id") or "Server"
            )
            self.app.push_screen(
                MemorySummaryScreen(
                    title=f"AI-enhanced Summary: {instance_name}",
                    summary=enhanced_summary,
                    source_label=(
                        f"AI-enhanced with {label} · summary-only request · "
                        "tools disabled · no fallback"
                    ),
                )
            )
        except Exception as exc:
            logger.error("AI summary enhancement failed: %s", exc, exc_info=True)
            self.app.notify(
                f"AI enhancement failed: {_enhancement_error_detail(exc)}",
                severity="error",
                markup=False,
            )

    def action_export(self) -> None:
        """Export memory summary to a Markdown file."""
        instance_id = self._instance.get("id") or self._instance.get("name", "")
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            self.app.notify("Memory service not available.", severity="error")
            return
        if self._is_opted_out(instance_id, memory_service):
            self.app.notify("Memory disabled for this server.", severity="warning")
            return
        self.run_worker(
            self._do_export(),
            exclusive=False,
            group="memory_io",
            name="memory_export",
        )

    async def _do_export(self) -> None:
        """Worker: write summary.md and notify with the path."""
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            return
        try:
            path = await memory_service.write_summary(self._instance)
            self.app.notify(f"Exported to {path}")
        except Exception as exc:
            logger.error("Export failed: %s", exc, exc_info=True)
            self.app.notify(f"Export failed: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Cloud sync actions (S binding)
    # ------------------------------------------------------------------

    def _refresh_statuses(self) -> None:
        """Refresh local scan freshness and cloud-sync state."""
        self._refresh_local_memory_status()
        self._refresh_sync_status()
        self._refresh_ai_status()

    def _refresh_local_memory_status(self) -> None:
        """Update the local scan label from the latest stored modules."""
        memory_service = getattr(self.app, "memory_service", None)
        label = _memory_scan_status_label(self._instance, memory_service)
        try:
            self.query_one("#memory-local-status", Static).update(label)
        except Exception:  # noqa: BLE001
            pass

    def refresh_memory_status(self) -> None:
        """Reload local memory after an app-owned fleet scan completes.

        ``ServonautApp._refresh_fleet_panels_after_scan`` calls this hook on
        whichever screen is active. This keeps the badge and module rows aligned
        with the Fleet Memory screen immediately.
        """
        try:
            self._render_table()
        except Exception:  # noqa: BLE001
            logger.debug(
                "Could not refresh per-instance memory status",
                exc_info=True,
            )

    def _refresh_sync_status(self) -> None:
        """Poll the sync service status and update the status label.

        Also drives the inline "Memory Sync is off — set up" banner: shown
        when the user hasn't enrolled their keypair yet (Free tier or Solo
        not yet configured), hidden once sync is active.
        """
        sync_service = getattr(self.app, "memory_sync_service", None)
        configured = bool(
            sync_service and getattr(sync_service, "is_configured", False)
        )
        label = _sync_status_label(sync_service)
        try:
            self.query_one("#memory-sync-status", Static).update(label)
        except Exception:
            pass
        # Cloud-banner copy is tier-aware so Free users get a "Solo unlocks"
        # message and Solo users get a "Finish setup" message — both route to
        # MemorySyncSetupScreen which adapts to whichever state applies.
        try:
            banner = self.query_one("#memory-cloud-banner")
            text = self.query_one("#memory-cloud-banner-text", Static)
            if configured:
                banner.add_class("hidden")
            else:
                banner.remove_class("hidden")
                auth = getattr(self.app, "auth_service", None)
                if auth and auth.has_feature("memory_sync"):
                    text.update(
                        "[bold]🔒 Memory Sync is off[/bold]  "
                        "[dim]— local data stays on this machine. "
                        "Set up to back up encrypted snapshots to your account.[/dim]"
                    )
                else:
                    text.update(
                        "[bold]🔒 Memory Sync is off[/bold]  "
                        "[dim]— available with the Solo plan. "
                        "Encrypted backup, drift detection, and AI-queryable history.[/dim]"
                    )
        except Exception:
            pass

    def action_open_memory_sync_setup(self) -> None:
        from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen

        self.app.switch_screen(MemorySyncSetupScreen())

    def action_sync_now(self) -> None:
        """Queue this server's local memory and sync it in the background."""
        sync_service = getattr(self.app, "memory_sync_service", None)
        if sync_service is None:
            self.app.notify("Memory sync service not available.", severity="warning")
            return
        if not getattr(sync_service, "is_configured", False):
            self.app.notify(
                "Memory Sync is locked — open Memory Sync to unlock it first.",
                severity="warning",
            )
            return
        if getattr(self.app, "_memory_manual_sync_in_progress", False):
            self.app.notify(
                "Memory Sync is already running in the background.",
                severity="information",
            )
            return
        self._publish_manual_sync_progress(
            f"Preparing {self._instance.get('name') or 'this server'}…"
        )
        self.app.run_worker(
            self._run_sync_now_background(sync_service),
            group="memory_sync_manual",
            name="memory_sync_manual",
            exclusive=False,
        )

    def refresh_memory_sync_progress(self, message: Optional[str]) -> None:
        """Reflect an app-owned manual sync while this screen is visible."""
        if not self.is_mounted:
            return
        if message is None:
            self._refresh_sync_status()
            return
        redaction = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redaction is not None:
            message = redaction.scrub_stream(message)
        try:
            self.query_one("#memory-sync-status", Static).update(
                f"[cyan]Cloud sync: {escape(message)}[/cyan]"
            )
        except Exception:
            pass

    def _publish_manual_sync_progress(self, message: str) -> None:
        setattr(self.app, "_memory_manual_sync_in_progress", True)
        setattr(self.app, "_memory_manual_sync_message", message)
        self._refresh_visible_sync_screen(message)

    def _finish_manual_sync(self) -> None:
        setattr(self.app, "_memory_manual_sync_in_progress", False)
        setattr(self.app, "_memory_manual_sync_message", "")
        self._refresh_visible_sync_screen(None)

    def _refresh_visible_sync_screen(self, message: Optional[str]) -> None:
        try:
            screen = self.app.screen
        except Exception:
            return
        callback = getattr(screen, "refresh_memory_sync_progress", None)
        if callable(callback):
            callback(message)

    async def _run_sync_now_background(self, sync_service: Any) -> None:
        try:
            await self._do_sync_now(sync_service)
        finally:
            self._finish_manual_sync()

    @staticmethod
    def _pending_for_instance(sync_service: Any, instance_id: str) -> int:
        try:
            return int(sync_service.pending_count(instance_id))
        except (AttributeError, TypeError, ValueError):
            return int(getattr(sync_service.status, "pending_envelopes", 0))

    _MAX_MANUAL_SYNC_BATCHES = 200

    async def _do_sync_now(self, sync_service: Any) -> None:
        iid = self._instance.get("id") or self._instance.get("name", "")
        name = self._instance.get("name", "")
        provider = self._instance.get("provider", "custom")
        display_name = name or iid or "this server"
        try:
            queued = sync_service.backfill_from_local_store(instance_id=iid)
            pending_before = self._pending_for_instance(sync_service, iid)
            if pending_before:
                self._publish_manual_sync_progress(
                    f"{display_name} · uploading {pending_before} envelope(s)…"
                )
            else:
                self._publish_manual_sync_progress(
                    f"{display_name} · checking remote changes…"
                )

            total_accepted = 0
            total_rejected = 0
            if pending_before:
                for _ in range(self._MAX_MANUAL_SYNC_BATCHES):
                    result = await sync_service.drain_now(instance_id=iid)
                    batch_accepted = len(getattr(result, "accepted", []) or [])
                    batch_rejected = len(getattr(result, "rejected", []) or [])
                    total_accepted += batch_accepted
                    total_rejected += batch_rejected
                    pending_now = self._pending_for_instance(sync_service, iid)
                    self._publish_manual_sync_progress(
                        f"{display_name} · {total_accepted} uploaded · "
                        f"{pending_now} pending"
                    )
                    if batch_accepted == 0 and batch_rejected == 0:
                        break
            else:
                await sync_service.drain_now(instance_id=iid)

            status_after = sync_service.status
            pending_after = self._pending_for_instance(sync_service, iid)
            last_error = getattr(status_after, "last_error", None)
            halted_reason = getattr(status_after, "halted_reason", None)
            self._publish_manual_sync_progress(
                f"{display_name} · checking remote annotations and findings…"
            )

            pulled = []
            try:
                result = await sync_service.pull_annotations(iid, name, provider)
                if result == "updated":
                    pulled.append("annotations")
            except Exception:
                pass
            try:
                result = await sync_service.pull_findings(iid, name, provider)
                if result == "updated":
                    pulled.append("findings")
            except Exception:
                pass

            pulled_suffix = f" · {' and '.join(pulled)} refreshed" if pulled else ""
            if total_accepted > 0 and total_rejected == 0:
                self.app.notify(
                    f"Synced {total_accepted} envelope(s) for "
                    f"{display_name}{pulled_suffix}.",
                    markup=False,
                )
            elif total_accepted > 0:
                self.app.notify(
                    f"Synced {total_accepted} envelope(s) for {display_name}; "
                    f"{total_rejected} rejected{pulled_suffix}.",
                    severity="warning",
                    markup=False,
                )
            elif pending_after > 0:
                reason = halted_reason or last_error or "see logs"
                self.app.notify(
                    f"{pending_after} envelope(s) for {display_name} remain "
                    f"queued — {reason}.",
                    severity="error",
                    markup=False,
                )
            elif total_rejected > 0:
                self.app.notify(
                    f"Memory Sync checked {display_name}; "
                    f"{total_rejected} envelope(s) were skipped.",
                    severity="warning",
                    markup=False,
                )
            elif pulled:
                self.app.notify(
                    f"{display_name} is up to date · {' and '.join(pulled)} refreshed.",
                    markup=False,
                )
            elif queued:
                self.app.notify(
                    f"Memory Sync checked {display_name}; no envelope was "
                    "accepted. See logs for details.",
                    severity="warning",
                    markup=False,
                )
            else:
                self.app.notify(
                    f"{display_name} is already up to date — "
                    "no local changes were queued.",
                    markup=False,
                )
        except Exception as exc:
            logger.error("Sync now failed: %s", exc)
            self.app.notify(f"Sync failed: {exc}", severity="error", markup=False)

    # ------------------------------------------------------------------
    # AI summary action (A binding)
    # ------------------------------------------------------------------

    def action_build_ai_summary(self) -> None:
        """Refresh entitlement, then start disclosure → consent → dispatch."""
        ai_service = getattr(self.app, "ai_summary_service", None)
        if ai_service is None:
            self.app.notify("AI summary service not available.", severity="warning")
            return
        self.run_worker(
            self._start_ai_summary_flow(),
            group="memory_ai_summary",
            name="memory_ai_summary",
        )

    async def _start_ai_summary_flow(self) -> None:
        """Recheck server overrides before deciding whether to show an upsell."""
        auth = getattr(self.app, "auth_service", None)
        if auth:
            if not getattr(auth, "is_authenticated", False):
                self.app.notify(
                    "Sign in to verify AI summary access.",
                    severity="warning",
                )
                return

            fetch_entitlements = getattr(auth, "fetch_entitlements", None)
            refreshed_entitlements = None
            if callable(fetch_entitlements):
                try:
                    refreshed_entitlements = await fetch_entitlements()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("AI-summary entitlement refresh failed: %s", exc)

            if refreshed_entitlements is None:
                self.app.notify(
                    "Could not verify AI summary access. "
                    "Check your connection and retry.",
                    severity="warning",
                )
                return

            if not auth.has_feature("memory_ai_summary"):
                from servonaut.widgets.upsell_modal import UpsellModal

                self.app.push_screen(UpsellModal("memory_ai_summary"))
                return

        instance_id = self._instance.get("id") or self._instance.get("name", "")
        await self._do_ai_summary_flow(instance_id)

    async def _do_ai_summary_flow(self, instance_id: str) -> None:
        """Worker: full AI summary flow per spec §3.6."""
        ai_service = getattr(self.app, "ai_summary_service", None)
        if ai_service is None:
            return
        try:
            # Step 1: fetch provider info (contains retention_text to show verbatim)
            provider_info = await ai_service.get_provider_info()
        except Exception as exc:
            from servonaut.services.memory.interfaces import UpsellRequired

            if isinstance(exc, UpsellRequired):
                logger.error("AI summary API denied the verified entitlement")
                self.app.notify(
                    "AI summary access was accepted locally, but the server denied it. "
                    "Your account entitlement has not reached the summary API yet.",
                    severity="error",
                    markup=False,
                )
                return
            logger.error("AI provider info failed: %s", exc)
            self.app.notify(
                f"Could not fetch AI provider info: {exc}",
                severity="error",
                markup=False,
            )
            return

        # Step 2: show provider disclosure verbatim and ask for confirmation.
        # We push a confirm modal on the main thread; run the rest from its callback.
        from servonaut.screens.memory import SimpleConfirmModal
        from rich.markup import escape as rich_escape

        disclosure_text = (
            f"[bold]AI Provider:[/bold] {rich_escape(provider_info.provider_name)}\n\n"
            f"{rich_escape(provider_info.retention_text)}\n\n"
            "Do you consent to submitting server memory data to this provider?"
        )

        async def _after_consent(confirmed: bool) -> None:
            if not confirmed:
                return
            ai_service.confirm_provider_disclosure_shown(instance_id)

            # Establish a stable baseline before dispatch so an older result can
            # never be shown as if it belonged to this request.
            try:
                previous = await ai_service.get_latest_summary(instance_id)
                previous_id = None
                if previous is not None:
                    previous_id = str(previous.get("id", "") or "")
                    if not previous_id:
                        raise RuntimeError(
                            "Latest summary response has no stable envelope id"
                        )
            except Exception as exc:
                logger.error("Hosted summary baseline failed: %s", exc)
                self.app.notify(
                    f"Could not establish the hosted-summary baseline: {exc}",
                    severity="error",
                    markup=False,
                )
                return

            try:
                consent_token = await ai_service.request_consent_token(
                    instance_id=instance_id,
                    mode="server_60s",
                    modules=None,
                    provider_ack=True,
                )
            except Exception as exc:
                logger.error("Consent token failed: %s", exc)
                self.app.notify(
                    f"Consent token failed: {exc}",
                    severity="error",
                    markup=False,
                )
                return

            try:
                passphrase = await self.app._prompt_memory_passphrase()
            except RuntimeError:
                self.app.notify("Hosted summary cancelled.", severity="information")
                return

            try:
                self.app.notify("Dispatching hosted AI summary…")
                try:
                    result = await ai_service.dispatch_summary(
                        instance_id=instance_id,
                        consent_token=consent_token,
                        mode=consent_token.mode,
                        passphrase=passphrase,
                    )
                finally:
                    passphrase = ""
                if getattr(result, "correlation_supported", False):
                    # The dispatch response atomically identifies the envelope
                    # that was current when this job was queued. Prefer it to
                    # the pre-dispatch compatibility baseline so concurrent
                    # requests cannot be mistaken for this result.
                    previous_id = result.previous_summary_id
                self.query_one("#memory-hosted-status", Static).update(
                    f"[cyan]● Hosted summary · {result.status.title()} — waiting[/cyan]"
                )
                self.app.notify(
                    "Hosted summary queued. Waiting for the encrypted result…"
                )
                envelope = await ai_service.wait_for_new_summary(
                    instance_id,
                    previous_envelope_id=previous_id,
                    initial_poll_after_seconds=getattr(
                        result,
                        "poll_after_seconds",
                        None,
                    ),
                )
                if envelope is None:
                    self.query_one("#memory-hosted-status", Static).update(
                        "[yellow]● Hosted summary · Still processing[/yellow]"
                    )
                    self.app.notify(
                        "The hosted summary is still processing. Retry after a "
                        "short wait; no older result was displayed.",
                        severity="warning",
                    )
                    return
                await self._open_hosted_summary(
                    envelope,
                    provider_name=provider_info.provider_name,
                )
            except Exception as exc:
                logger.error("Hosted AI summary failed: %s", exc, exc_info=True)
                self.query_one("#memory-hosted-status", Static).update(
                    "[red]● Hosted summary · Failed[/red]"
                )
                self.app.notify(
                    f"Hosted summary failed: {exc}",
                    severity="error",
                    markup=False,
                )

        self.app.push_screen(
            SimpleConfirmModal(disclosure_text),
            _after_consent,
        )

    async def _open_hosted_summary(
        self,
        envelope: Dict[str, Any],
        *,
        provider_name: str,
    ) -> None:
        """Decrypt and display a completed hosted summary envelope."""
        retrieval_service = getattr(self.app, "memory_retrieval_service", None)
        if retrieval_service is None:
            raise RuntimeError(
                "Memory retrieval is unavailable; unlock Memory Sync and retry"
            )
        instance_id = self._instance.get("id") or self._instance.get("name", "")
        decrypted = await retrieval_service.decrypt_envelope(
            envelope,
            expected_instance_id=instance_id,
            expected_module="ai_summary",
        )
        summary = self._summary_markdown_from_plaintext(decrypted.plaintext)
        summary = self._scrub_summary_for_demo(summary)

        from servonaut.screens.memory_summary import MemorySummaryScreen

        instance_name = (
            self._instance.get("name") or self._instance.get("id") or "Server"
        )
        self.query_one("#memory-hosted-status", Static).update(
            "[green]● Hosted summary · Ready[/green]"
        )
        self.app.push_screen(
            MemorySummaryScreen(
                title=f"Hosted AI Summary: {instance_name}",
                summary=summary,
                source_label=(
                    f"Hosted provider: {provider_name} · encrypted retrieval · "
                    "explicit consent"
                ),
            )
        )

    @staticmethod
    def _summary_markdown_from_plaintext(plaintext: Any) -> str:
        """Extract Markdown from supported hosted-summary plaintext shapes."""
        if isinstance(plaintext, str) and plaintext.strip():
            return plaintext
        if not isinstance(plaintext, dict):
            raise RuntimeError("Hosted summary plaintext is not a Markdown payload")

        for key in ("summary", "markdown", "content"):
            value = plaintext.get(key)
            if isinstance(value, str) and value.strip():
                return value

        observed = plaintext.get("observed")
        if isinstance(observed, str) and observed.strip():
            return observed
        if isinstance(observed, dict):
            for key in ("summary", "markdown", "content"):
                value = observed.get(key)
                if isinstance(value, str) and value.strip():
                    return value

        raise RuntimeError("Hosted summary plaintext contains no Markdown content")
