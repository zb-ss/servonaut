"""Server Memory screen for Servonaut.

Displays stored memory modules for a server instance and provides
keyboard actions to refresh, pin, clear, annotate, and export memory.
"""

from __future__ import annotations

import getpass
import logging
import os
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

        # Ensure file exists with restricted permissions before opening
        if not path.exists():
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch(mode=0o600)
            except OSError as exc:
                self.app.notify(f"Could not create annotations file: {exc}", severity="error")
                return

        editor = (
            os.environ.get("VISUAL")
            or os.environ.get("EDITOR")
            or "vi"
        )

        with self.app.suspend():
            subprocess.run([editor, str(path)], check=False)  # noqa: S603

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
