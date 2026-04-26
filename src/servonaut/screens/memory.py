"""Server Memory screen for Servonaut.

Displays stored memory modules for a server instance and provides
keyboard actions to refresh, pin, clear, annotate, and export memory.
"""

from __future__ import annotations

import getpass
import logging
import os
import shlex
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


def _sync_status_label(sync_service: Any) -> str:
    """Return a compact Rich markup string describing the sync status."""
    if sync_service is None:
        return "[dim]Sync: unavailable[/dim]"
    try:
        status = sync_service.status
        state = status.state
        pending = status.pending_envelopes
        last = (status.last_sync_at or "never")[:19].replace("T", " ")
        if state == "running":
            return f"[cyan]Sync: running[/cyan] · {pending} pending"
        if state == "halted":
            reason = status.halted_reason or "unknown"
            return f"[red]Sync: halted ({reason})[/red] · {pending} pending"
        if state == "error":
            return f"[red]Sync: error[/red] · last: {last}"
        return f"[green]Sync: {state}[/green] · last: {last} · {pending} pending"
    except Exception:
        return "[dim]Sync: unknown[/dim]"


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

    CSS_PATH = ["../app.css", "../memory_screen.tcss"]

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh_all", "Refresh All", show=True),
        Binding("m", "refresh_module", "Refresh Module", show=True),
        Binding("p", "pin_key", "Pin", show=True),
        Binding("c", "clear_module", "Clear", show=True),
        Binding("a", "annotate", "Annotate", show=True),
        Binding("e", "export", "Export", show=True),
        Binding("S", "sync_now", "Sync Now", show=True),
        Binding("A", "build_ai_summary", "AI Summary", show=True),
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
                    "[yellow]Memory disabled for this server.[/yellow]",
                    id="memory-opt-out-banner",
                    classes="hidden",
                ),
                # Inline informational banner — shown when Memory Sync is
                # not configured (Free tier or Solo not yet enrolled). Routes
                # to MemorySyncSetupScreen which adapts to the user's tier.
                Container(
                    Static("", id="memory-cloud-banner-text"),
                    Button("Set up →", variant="primary", id="btn_open_memory_sync_setup"),
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
                    Button("r. Probe server now", variant="primary", id="btn_empty_probe"),
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
                    Button("e. Export", id="btn_export"),
                    id="memory-actions",
                ),
                Horizontal(
                    Static("[dim]Sync: unavailable[/dim]", id="memory-sync-status"),
                    Button("S. Sync Now", id="btn_sync_now"),
                    id="memory-sync-row",
                ),
                Horizontal(
                    Static("[dim]AI summary: not built[/dim]", id="memory-ai-status"),
                    Button("A. Build AI Summary", id="btn_build_ai"),
                    id="memory-ai-row",
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
        self.set_interval(5, self._refresh_sync_status)

    # ------------------------------------------------------------------
    # Table rendering
    # ------------------------------------------------------------------

    def _render_table(self) -> None:
        """Populate the DataTable with stored memory module data.

        Checks opt-out first; shows the banner and clears the table if
        memory is disabled for this instance.  Stale rows are coloured
        yellow via Rich markup.
        """
        table = self.query_one("#memory-table", DataTable)
        banner = self.query_one("#memory-opt-out-banner", Static)

        instance_id = self._instance.get("id") or self._instance.get("name", "")
        provider = self._instance.get("provider", "custom")

        # Opt-out check
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is not None and self._is_opted_out(instance_id, memory_service):
            banner.remove_class("hidden")
            table.clear()
            self._set_empty_state_visible(False)
            return

        banner.add_class("hidden")
        table.clear()

        if memory_service is None:
            self._set_empty_state_visible(False)
            return

        # Load all stored modules
        try:
            all_modules: Dict[str, Dict[str, Any]] = (
                memory_service.get_all_modules(instance_id, provider)
            )
        except Exception as exc:
            logger.warning("Could not load memory modules for %s: %s", instance_id, exc)
            self._set_empty_state_visible(False)
            return

        if not all_modules:
            # Empty: show the CTA so users know how to populate memory.
            self._set_empty_state_visible(True)
            return
        self._set_empty_state_visible(False)

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
            probed_at_display = probed_at_str[:19].replace("T", " ") if probed_at_str else ""
            age_display = _human_age(probed_at_str)
            is_stale = module_name in stale_names

            if is_stale:
                age_display = f"[yellow]{age_display}[/yellow]"

            if not observed:
                # Show a placeholder row for modules with no observed keys
                table.add_row(
                    module_name, "", "", "", probed_at_display, age_display,
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
            # T11: CTA in the empty-state dispatches the same refresh-all flow.
            "btn_empty_probe": self.action_refresh_all,
            "btn_sync_now": self.action_sync_now,
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
            logger.debug("Could not read current value for %s.%s: %s", module_name, key, exc)
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
                memory_service.clear(instance_id, modules=[module_name], provider=provider)
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
            "<!-- What does this server do? e.g. \"primary billing API, "
            "reads from RDS, serves api.example.com\" -->\n"
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
            self.app.notify(f"Could not resolve annotations path: {exc}", severity="error")
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
                self.app.notify(f"Could not create annotations file: {exc}", severity="error")
                return

        editor = (
            os.environ.get("VISUAL")
            or os.environ.get("EDITOR")
            or "vi"
        )
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
        looks_like_bad_emacs_config = (
            editor_binary == "emacs"
            and any(flag in argv[1:-1] for flag in ("-c", "-a", "--alternate-editor"))
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
                argv, proc.returncode, proc.stderr,
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

        self._render_table()

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

    def _refresh_sync_status(self) -> None:
        """Poll the sync service status and update the status label.

        Also drives the inline "Memory Sync is off — set up" banner: shown
        when the user hasn't enrolled their keypair yet (Free tier or Solo
        not yet configured), hidden once sync is active.
        """
        sync_service = getattr(self.app, "memory_sync_service", None)
        configured = bool(sync_service and getattr(sync_service, "is_configured", False))
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
        """Trigger an immediate drain of the sync queue."""
        sync_service = getattr(self.app, "memory_sync_service", None)
        if sync_service is None:
            self.app.notify("Memory sync service not available.", severity="warning")
            return
        self.run_worker(
            self._do_sync_now(sync_service),
            group="memory_sync",
            name="memory_sync_now",
        )

    async def _do_sync_now(self, sync_service: Any) -> None:
        try:
            await sync_service.drain_now()
            self.app.notify("Sync complete.")
            self._refresh_sync_status()
        except Exception as exc:
            logger.error("Sync now failed: %s", exc)
            self.app.notify(f"Sync failed: {exc}", severity="error")
            self._refresh_sync_status()

    # ------------------------------------------------------------------
    # AI summary action (A binding)
    # ------------------------------------------------------------------

    def action_build_ai_summary(self) -> None:
        """Start the AI summary flow: provider disclosure → consent → dispatch."""
        ai_service = getattr(self.app, "ai_summary_service", None)
        if ai_service is None:
            self.app.notify("AI summary service not available.", severity="warning")
            return
        auth = getattr(self.app, "auth_service", None)
        if auth and not auth.has_feature("memory_ai_summary"):
            from servonaut.widgets.upsell_modal import UpsellModal
            self.app.push_screen(UpsellModal("memory_ai_summary"))
            return
        instance_id = self._instance.get("id") or self._instance.get("name", "")
        self.run_worker(
            self._do_ai_summary_flow(instance_id),
            group="memory_ai_summary",
            name="memory_ai_summary",
        )

    async def _do_ai_summary_flow(self, instance_id: str) -> None:
        """Worker: full AI summary flow per spec §3.6."""
        ai_service = getattr(self.app, "ai_summary_service", None)
        if ai_service is None:
            return
        try:
            # Step 1: fetch provider info (contains retention_text to show verbatim)
            provider_info = await ai_service.get_provider_info()
        except Exception as exc:
            logger.error("AI provider info failed: %s", exc)
            self.app.notify(f"Could not fetch AI provider info: {exc}", severity="error")
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
            # Step 3: mark disclosure as shown (hard gate in service)
            ai_service.confirm_provider_disclosure_shown(instance_id)
            # Step 4: request consent token
            try:
                consent_token = await ai_service.request_consent_token(
                    instance_id=instance_id,
                    mode="server_60s",
                    modules=None,
                    provider_ack=True,
                )
            except Exception as exc:
                logger.error("Consent token failed: %s", exc)
                self.app.notify(f"Consent token failed: {exc}", severity="error")
                return
            # Step 5: prompt for passphrase to enable server-side decryption
            try:
                passphrase = await self.app._prompt_memory_passphrase()
            except RuntimeError:
                self.app.notify("AI summary cancelled.", severity="information")
                return
            # Step 6: dispatch summary
            try:
                self.app.notify("Dispatching AI summary…")
                result = await ai_service.dispatch_summary(
                    instance_id=instance_id,
                    consent_token=consent_token,
                    mode=consent_token.mode,
                    passphrase=passphrase,
                )
                self.query_one("#memory-ai-status", Static).update(
                    f"[cyan]AI summary: {result.status}[/cyan]"
                )
                self.app.notify(f"AI summary dispatched: {result.message}")
            except Exception as exc:
                logger.error("AI summary dispatch failed: %s", exc)
                self.app.notify(f"AI summary failed: {exc}", severity="error")

        self.app.push_screen(
            SimpleConfirmModal(disclosure_text),
            _after_consent,
        )
