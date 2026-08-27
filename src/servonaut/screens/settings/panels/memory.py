"""Memory & Sync settings panel.

Covers the :class:`~servonaut.config.schema.MemoryConfig` nested dataclass plus
the top-level ``sync_encryption_enabled`` scalar on :class:`AppConfig`.

Fields exposed:
- memory.enabled (switch)
- memory.redaction_enabled (switch)
- memory.disabled_modules (StringListEditor)
- memory.default_ttl_overrides (KeyValueEditor, Dict[str, int])
- memory.snapshot_stale_seconds (int input)
- memory.first_connect_reprompt_seconds (int input)
- memory.findings_sync_enabled (switch)
- memory.findings_confidence_threshold (float 0-1)
- memory.findings_index_char_cap (int)
- sync_encryption_enabled (top-level switch)
- memory.per_server_overrides (read-only summary with "edit in config.json" note)

All un-exposed :class:`MemoryConfig` fields are preserved via
``dataclasses.replace`` — the panel never stomps on fields it does not render.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Dict

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, Input, Static, Switch

from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.screens.settings.widgets import KeyValueEditor, StringListEditor

logger = logging.getLogger(__name__)

# Reasonable upper bounds for int fields to catch accidental pasting.
_MAX_SECONDS = 365 * 24 * 3600  # 1 year
_MAX_CHAR_CAP = 10_000_000


class MemoryPanel(SettingsPanel):
    """Settings panel for the Memory & Sync subsystem.

    Exposes the top-level ``sync_encryption_enabled`` scalar alongside all
    user-facing fields of :class:`~servonaut.config.schema.MemoryConfig`.
    Fields that belong to the nested dataclass but are not shown here
    (currently none beyond ``per_server_overrides``) are preserved by reading
    the whole object and using ``dataclasses.replace`` before writing.
    """

    PANEL_ID = "memory"
    TITLE = "Memory & Sync"

    DEFAULT_CSS = """
    MemoryPanel .memory-section-label {
        color: $accent;
        text-style: bold;
        margin: 1 0 0 0;
        height: auto;
    }
    MemoryPanel .memory-per-server-note {
        color: $text-muted;
        height: auto;
        margin: 0 0 0 2;
    }
    MemoryPanel .memory-confidence-hint {
        color: $text-muted;
        height: auto;
        margin: 0 0 0 2;
    }
    MemoryPanel #memory_device_auto_unlock_status {
        width: 1fr;
    }
    MemoryPanel #memory_manage_device_auto_unlock {
        min-width: 12;
    }
    """

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield all Memory & Sync form rows."""
        # ---- Master switches ----------------------------------------
        yield Static("Master switches", classes="memory-section-label")
        yield Horizontal(
            Static("Memory enabled", classes="label"),
            Switch(id="memory_enabled"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Sync encryption enabled", classes="label"),
            Switch(id="memory_sync_encryption"),
            classes="setting_row",
        )
        yield Static("Device auto-unlock", classes="memory-section-label")
        yield Horizontal(
            Static("Remembered unlock", classes="label"),
            Static("", id="memory_device_auto_unlock_status"),
            Button("Manage…", id="memory_manage_device_auto_unlock"),
            classes="setting_row",
        )

        # ---- Redaction -----------------------------------------------
        yield Static("Privacy", classes="memory-section-label")
        yield Horizontal(
            Static("Redaction enabled", classes="label"),
            Switch(id="memory_redaction_enabled"),
            classes="setting_row",
        )

        # ---- Module control ------------------------------------------
        yield Static("Module control", classes="memory-section-label")
        yield Horizontal(
            Static("Disabled modules", classes="label"),
            classes="setting_row",
        )
        yield StringListEditor(
            placeholder="module name (e.g. containers)",
            id="memory_disabled_modules",
        )

        # ---- TTL overrides -------------------------------------------
        yield Static("TTL overrides (seconds)", classes="memory-section-label")
        yield Horizontal(
            Static("Default TTL overrides", classes="label"),
            classes="setting_row",
        )
        yield KeyValueEditor(
            key_placeholder="module name",
            value_placeholder="seconds",
            value_is_int=True,
            id="memory_ttl_overrides",
        )

        # ---- Staleness thresholds ------------------------------------
        yield Static("Staleness thresholds", classes="memory-section-label")
        yield Horizontal(
            Static("Snapshot stale (seconds)", classes="label"),
            Input(placeholder="604800", id="memory_snapshot_stale"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("First-connect reprompt (seconds)", classes="label"),
            Input(placeholder="1209600", id="memory_first_connect_reprompt"),
            classes="setting_row",
        )

        # ---- Background automation -----------------------------------
        yield Static("Background automation", classes="memory-section-label")
        yield Horizontal(
            Static("Background fleet auto-scan", classes="label"),
            Switch(id="memory_auto_scan_enabled"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Auto-scan interval (seconds)", classes="label"),
            Input(placeholder="86400", id="memory_auto_scan_interval"),
            classes="setting_row",
        )
        # ---- Agent findings ------------------------------------------
        yield Static("Agent findings", classes="memory-section-label")
        yield Horizontal(
            Static("Findings sync enabled", classes="label"),
            Switch(id="memory_findings_sync"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Confidence threshold (0–1)", classes="label"),
            Input(placeholder="0.6", id="memory_findings_confidence"),
            classes="setting_row",
        )
        yield Static(
            "Findings with a score below this are omitted from injected context.",
            classes="memory-confidence-hint",
        )
        yield Horizontal(
            Static("Findings index char cap", classes="label"),
            Input(placeholder="1200", id="memory_findings_index_char_cap"),
            classes="setting_row",
        )

        # ---- Per-server overrides (read-only summary) ----------------
        yield Static("Per-server overrides", classes="memory-section-label")
        yield Static(
            "", id="memory_per_server_summary", classes="memory-per-server-note"
        )
        yield Static(
            "Per-server overrides (memory_disabled, module exclusions) are "
            "managed via the instance context menu or by editing config.json "
            "directly.",
            classes="memory-per-server-note",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate all widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()
        mem = config.memory

        # Master switches
        self.query_one("#memory_enabled", Switch).value = mem.enabled
        self.query_one("#memory_sync_encryption", Switch).value = (
            config.sync_encryption_enabled
        )
        self.query_one("#memory_device_auto_unlock_status", Static).update(
            self._device_auto_unlock_status(mem)
        )

        # Privacy
        self.query_one("#memory_redaction_enabled", Switch).value = (
            mem.redaction_enabled
        )

        # Module control
        self.query_one("#memory_disabled_modules", StringListEditor).set_values(
            list(mem.disabled_modules)
        )

        # TTL overrides
        self.query_one("#memory_ttl_overrides", KeyValueEditor).set_map(
            dict(mem.default_ttl_overrides)
        )

        # Staleness thresholds
        self.query_one("#memory_snapshot_stale", Input).value = str(
            mem.snapshot_stale_seconds
        )
        self.query_one("#memory_first_connect_reprompt", Input).value = str(
            mem.first_connect_reprompt_seconds
        )

        # Background automation
        self.query_one("#memory_auto_scan_enabled", Switch).value = mem.auto_scan_enabled
        self.query_one("#memory_auto_scan_interval", Input).value = str(
            mem.auto_scan_interval_seconds
        )

        # Agent findings
        self.query_one("#memory_findings_sync", Switch).value = mem.findings_sync_enabled
        self.query_one("#memory_findings_confidence", Input).value = str(
            mem.findings_confidence_threshold
        )
        self.query_one("#memory_findings_index_char_cap", Input).value = str(
            mem.findings_index_char_cap
        )

        # Per-server overrides summary
        override_count = len(mem.per_server_overrides)
        summary = (
            f"{override_count} server override(s) configured."
            if override_count
            else "No per-server overrides configured."
        )
        self.query_one("#memory_per_server_summary", Static).update(escape(summary))

        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison.

        List/map editors are compared by value — overriding ``is_dirty``
        directly is not needed because the editors expose plain Python
        lists/dicts which compare by equality.
        """
        try:
            ttl_map = self.query_one("#memory_ttl_overrides", KeyValueEditor).get_map()
        except ValueError:
            ttl_map = {}
        return {
            "enabled": self.query_one("#memory_enabled", Switch).value,
            "sync_encryption_enabled": self.query_one(
                "#memory_sync_encryption", Switch
            ).value,
            "redaction_enabled": self.query_one(
                "#memory_redaction_enabled", Switch
            ).value,
            "disabled_modules": self.query_one(
                "#memory_disabled_modules", StringListEditor
            ).get_values(),
            "default_ttl_overrides": ttl_map,
            "snapshot_stale_seconds": self.query_one(
                "#memory_snapshot_stale", Input
            ).value.strip(),
            "first_connect_reprompt_seconds": self.query_one(
                "#memory_first_connect_reprompt", Input
            ).value.strip(),
            "findings_sync_enabled": self.query_one(
                "#memory_findings_sync", Switch
            ).value,
            "findings_confidence": self.query_one(
                "#memory_findings_confidence", Input
            ).value.strip(),
            "findings_index_char_cap": self.query_one(
                "#memory_findings_index_char_cap", Input
            ).value.strip(),
            "auto_scan_enabled": self.query_one(
                "#memory_auto_scan_enabled", Switch
            ).value,
            "auto_scan_interval_seconds": self.query_one(
                "#memory_auto_scan_interval", Input
            ).value.strip(),
        }

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def collect(self) -> Dict[str, Any]:
        """Validate all widgets and return a field dict ready for persistence.

        Raises:
            ValidationError: On the first field that fails validation.
        """
        # snapshot_stale_seconds
        stale_raw = self.query_one("#memory_snapshot_stale", Input).value.strip()
        stale_seconds = self._parse_non_negative_int(
            stale_raw, "memory_snapshot_stale", "Snapshot stale threshold"
        )
        if stale_seconds > _MAX_SECONDS:
            raise ValidationError(
                "memory_snapshot_stale",
                f"Snapshot stale threshold must be at most {_MAX_SECONDS} seconds.",
            )

        # first_connect_reprompt_seconds
        reprompt_raw = self.query_one(
            "#memory_first_connect_reprompt", Input
        ).value.strip()
        reprompt_seconds = self._parse_non_negative_int(
            reprompt_raw, "memory_first_connect_reprompt", "First-connect reprompt"
        )
        if reprompt_seconds > _MAX_SECONDS:
            raise ValidationError(
                "memory_first_connect_reprompt",
                f"First-connect reprompt must be at most {_MAX_SECONDS} seconds.",
            )

        # auto_scan_interval_seconds
        auto_scan_interval_raw = self.query_one(
            "#memory_auto_scan_interval", Input
        ).value.strip()
        auto_scan_interval = self._parse_non_negative_int(
            auto_scan_interval_raw,
            "memory_auto_scan_interval",
            "Auto-scan interval",
        )
        if auto_scan_interval < 60 or auto_scan_interval > _MAX_SECONDS:
            raise ValidationError(
                "memory_auto_scan_interval",
                f"Auto-scan interval must be between 60 and {_MAX_SECONDS} seconds.",
            )

        # findings_confidence_threshold
        confidence_raw = self.query_one(
            "#memory_findings_confidence", Input
        ).value.strip()
        try:
            confidence = float(confidence_raw)
        except ValueError as exc:
            raise ValidationError(
                "memory_findings_confidence",
                "Confidence threshold must be a number (e.g. 0.6).",
            ) from exc
        if not (0.0 <= confidence <= 1.0):
            raise ValidationError(
                "memory_findings_confidence",
                "Confidence threshold must be between 0 and 1.",
            )

        # findings_index_char_cap
        char_cap_raw = self.query_one(
            "#memory_findings_index_char_cap", Input
        ).value.strip()
        char_cap = self._parse_non_negative_int(
            char_cap_raw, "memory_findings_index_char_cap", "Findings index char cap"
        )
        if char_cap > _MAX_CHAR_CAP:
            raise ValidationError(
                "memory_findings_index_char_cap",
                f"Findings index char cap must be at most {_MAX_CHAR_CAP}.",
            )

        # TTL overrides (raises ValueError on non-int value)
        try:
            ttl_overrides = self.query_one(
                "#memory_ttl_overrides", KeyValueEditor
            ).get_map()
        except ValueError as exc:
            raise ValidationError(
                "memory_ttl_overrides",
                f"TTL overrides: {exc}",
            ) from exc

        return {
            "enabled": self.query_one("#memory_enabled", Switch).value,
            "sync_encryption_enabled": self.query_one(
                "#memory_sync_encryption", Switch
            ).value,
            "redaction_enabled": self.query_one(
                "#memory_redaction_enabled", Switch
            ).value,
            "disabled_modules": self.query_one(
                "#memory_disabled_modules", StringListEditor
            ).get_values(),
            "default_ttl_overrides": {k: int(v) for k, v in ttl_overrides.items()},
            "snapshot_stale_seconds": stale_seconds,
            "first_connect_reprompt_seconds": reprompt_seconds,
            "findings_sync_enabled": self.query_one(
                "#memory_findings_sync", Switch
            ).value,
            "findings_confidence_threshold": confidence,
            "findings_index_char_cap": char_cap,
            "auto_scan_enabled": self.query_one(
                "#memory_auto_scan_enabled", Switch
            ).value,
            "auto_scan_interval_seconds": auto_scan_interval,
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def persist(self) -> None:
        """Validate via :meth:`collect` then write to config.

        The :class:`~servonaut.config.schema.MemoryConfig` nested dataclass is
        read whole and replaced with only the exposed fields changed, so any
        un-exposed field (e.g. ``per_server_overrides``) is preserved verbatim.
        """
        fields = self.collect()

        config = self.app.config_manager.get()
        existing_mem = config.memory

        updated_mem = dataclasses.replace(
            existing_mem,
            enabled=fields["enabled"],
            redaction_enabled=fields["redaction_enabled"],
            disabled_modules=fields["disabled_modules"],
            default_ttl_overrides=fields["default_ttl_overrides"],
            snapshot_stale_seconds=fields["snapshot_stale_seconds"],
            first_connect_reprompt_seconds=fields["first_connect_reprompt_seconds"],
            findings_sync_enabled=fields["findings_sync_enabled"],
            findings_confidence_threshold=fields["findings_confidence_threshold"],
            findings_index_char_cap=fields["findings_index_char_cap"],
            auto_scan_enabled=fields["auto_scan_enabled"],
            auto_scan_interval_seconds=fields["auto_scan_interval_seconds"],
            # per_server_overrides is intentionally preserved from existing_mem
        )

        self.app.config_manager.update(
            memory=updated_mem,
            sync_encryption_enabled=fields["sync_encryption_enabled"],
        )
        # Start or cancel the fleet auto-scan loop based on the saved settings
        # so toggling auto-scan in Settings takes effect immediately.
        getattr(self.app, "_refresh_fleet_auto_scan_loop", lambda: None)()
        self._finish_save()

    # ------------------------------------------------------------------
    # Dirty tracking
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Refresh the dirty marker on any input change."""
        self._dirty_watch()

    def on_switch_changed(self, event: "Switch.Changed") -> None:
        """Refresh the dirty marker on any switch toggle."""
        self._dirty_watch()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Open remembered-unlock management or refresh dirty state."""
        if event.button.id == "memory_manage_device_auto_unlock":
            event.stop()
            self._open_device_auto_unlock_management()
            return
        super().on_button_pressed(event)
        # Propagated button events from StringListEditor / KeyValueEditor
        # that were NOT the panel Save button still warrant a dirty check.
        self._dirty_watch()

    def _open_device_auto_unlock_management(self) -> None:
        """Push the sole setup screen that can enable or forget auto-unlock."""
        from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen

        self.app.push_screen(MemorySyncSetupScreen())

    def refresh_external_state(self) -> None:
        """Refresh remembered-unlock status after the setup screen closes."""
        try:
            config = self.app.config_manager.get()
            status = self._device_auto_unlock_status(config.memory)
            self.query_one("#memory_device_auto_unlock_status", Static).update(status)
        except Exception as exc:  # pragma: no cover - defensive UI refresh
            logger.debug("Could not refresh device auto-unlock status: %s", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _device_auto_unlock_status(memory_config: Any) -> str:
        """Describe remembered unlock without reading any credential material."""
        try:
            from servonaut.services.memory import passphrase_store

            if not passphrase_store.keyring_available():
                return "Unavailable (no trusted OS keychain)"
        except Exception:
            return "Unavailable (no trusted OS keychain)"

        if not getattr(memory_config, "sync_remember_device", False):
            return "Off"

        from servonaut.config.schema import DEFAULT_REMEMBER_TTL_DAYS

        return f"On ({DEFAULT_REMEMBER_TTL_DAYS}-day re-prompt)"

    def _parse_non_negative_int(
        self, raw: str, field_id: str, label: str
    ) -> int:
        """Parse *raw* as a non-negative integer or raise :class:`ValidationError`.

        Args:
            raw: The raw string value from the widget.
            field_id: The widget id to highlight on error.
            label: Human-readable label for the error message.

        Returns:
            The parsed non-negative integer.

        Raises:
            ValidationError: When *raw* is not a valid non-negative integer.
        """
        try:
            value = int(raw)
        except ValueError as exc:
            raise ValidationError(
                field_id,
                f"{label} must be a whole number (seconds).",
            ) from exc
        if value < 0:
            raise ValidationError(
                field_id,
                f"{label} must be zero or greater.",
            )
        return value
