"""AI provider settings panel.

Exposes every user-configurable field on :class:`AIProviderConfig`:

- provider (the "Analysis provider" — used for AI log analysis)
- per-provider API keys via :class:`EnvVarInput` (password=True)
- model, base_url, max_tokens, temperature
- provider_preference as an editable "Chat provider" selector + [Reset]
  button (Reset delegates to :class:`ProviderPreferenceResolver.reset`,
  which also re-enables the first-run prompt and dismissed banners)

Fields NOT exposed here (but preserved via ``dataclasses.replace``):
- ``dismissed_banners`` — cleared only via [Reset]
- ``local_fallback_provider`` — controlled by the ai_chat panel
- ``api_key`` (legacy single-key) — kept for backward compatibility

Servonaut AI status row is included as a read-only informational widget
refreshed on mount.
"""

from __future__ import annotations

import logging
from dataclasses import replace as dataclass_replace
from typing import Any, Dict

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, Input, Select, Static

from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.screens.settings.widgets import EnvVarInput

logger = logging.getLogger(__name__)

_PROVIDER_OPTIONS = [
    ("servonaut", "servonaut"),
    ("openai", "openai"),
    ("anthropic", "anthropic"),
    ("gemini", "gemini"),
    ("ollama", "ollama"),
]

_KNOWN_PROVIDERS = {p for _, p in _PROVIDER_OPTIONS}

# Chat provider preference options. "" means "no preference — ask on first
# chat", which maps to ``provider_preference = None``.
_PREF_OPTIONS = [
    ("Ask on first chat (no preference)", ""),
    ("servonaut", "servonaut"),
    ("openai", "openai"),
    ("anthropic", "anthropic"),
    ("gemini", "gemini"),
    ("ollama", "ollama"),
]


class AiProviderPanel(SettingsPanel):
    """AI provider configuration: keys, model, limits, preference."""

    PANEL_ID = "ai_provider"
    TITLE = "AI Provider"

    DEFAULT_CSS = """
    AiProviderPanel .ai-status-row {
        height: auto;
        margin: 0 0 1 0;
    }
    AiProviderPanel .pref-row {
        height: auto;
        margin: 0 0 1 0;
    }
    AiProviderPanel .ai-note {
        color: $text-muted;
        height: auto;
        padding: 0 0 1 1;
    }
    AiProviderPanel #ai_provider_reset {
        min-width: 10;
    }
    """

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield the AI provider form rows."""
        yield Static(
            "[dim]Configure the AI provider used for log analysis and chat.[/dim]",
            classes="ai-note",
        )
        # Servonaut AI status row (read-only, refreshed on mount).
        yield Horizontal(
            Static(
                "Servonaut AI: [dim]loading…[/dim]",
                id="ai_provider_servonaut_status",
                classes="label",
            ),
            Button(
                "Upgrade",
                id="ai_provider_upgrade",
                variant="primary",
            ),
            classes="setting_row ai-status-row",
        )

        # Analysis provider selector (drives AI log analysis).
        yield Static(
            "[dim]Provider used for AI log analysis (the Analyze screen).[/dim]",
            classes="ai-note",
        )
        yield Horizontal(
            Static("Analysis provider", classes="label"),
            Select(
                _PROVIDER_OPTIONS,
                value="openai",
                allow_blank=False,
                id="ai_provider_provider",
            ),
            classes="setting_row",
        )

        # Per-provider API keys.
        yield Horizontal(
            Static("OpenAI key", classes="label"),
            EnvVarInput(
                placeholder="sk-... or $OPENAI_API_KEY",
                password=True,
                id="ai_provider_openai_key",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Anthropic key", classes="label"),
            EnvVarInput(
                placeholder="sk-ant-... or $ANTHROPIC_API_KEY",
                password=True,
                id="ai_provider_anthropic_key",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Gemini key", classes="label"),
            EnvVarInput(
                placeholder="AIza... or $GEMINI_API_KEY",
                password=True,
                id="ai_provider_gemini_key",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Ollama key", classes="label"),
            EnvVarInput(
                placeholder="ollama.com key (blank = local) or $OLLAMA_API_KEY",
                password=True,
                id="ai_provider_ollama_key",
            ),
            classes="setting_row",
        )

        # Model + base URL.
        yield Horizontal(
            Static("Model", classes="label"),
            Input(
                placeholder="leave blank for provider default",
                id="ai_provider_model",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Base URL", classes="label"),
            Input(
                placeholder="http://localhost:11434 (Ollama local) or https://ollama.com",
                id="ai_provider_base_url",
            ),
            classes="setting_row",
        )

        # Numeric limits.
        yield Horizontal(
            Static("Max tokens", classes="label"),
            Input(placeholder="4096", id="ai_provider_max_tokens"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Temperature", classes="label"),
            Input(placeholder="0.3", id="ai_provider_temperature"),
            classes="setting_row",
        )

        # Chat provider preference (editable) — drives the chat panel,
        # independent of the analysis provider above.
        yield Static(
            "[dim]Which provider the chat panel uses. Independent of the "
            "analysis provider above; only matters when more than one "
            "provider is set up. “Ask on first chat” lets the chat prompt "
            "you once.[/dim]",
            classes="ai-note",
        )
        yield Horizontal(
            Static("Chat provider", classes="label"),
            Select(
                _PREF_OPTIONS,
                value="",
                allow_blank=False,
                id="ai_provider_pref_select",
            ),
            classes="setting_row",
        )
        yield Static(
            "[dim]Reset re-enables the first-run prompt and any dismissed "
            "banners.[/dim]",
            classes="ai-note",
        )
        yield Horizontal(
            Button("Reset", id="ai_provider_reset", variant="default"),
            classes="setting_row pref-row",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        """Load config then refresh the Servonaut AI status row."""
        super().on_mount()
        self._refresh_servonaut_status()

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()
        ai = config.ai_provider

        provider = ai.provider if ai.provider in _KNOWN_PROVIDERS else "openai"
        self.query_one("#ai_provider_provider", Select).value = provider
        self.query_one("#ai_provider_openai_key", EnvVarInput).value = ai.openai_api_key
        self.query_one("#ai_provider_anthropic_key", EnvVarInput).value = ai.anthropic_api_key
        self.query_one("#ai_provider_gemini_key", EnvVarInput).value = ai.gemini_api_key
        self.query_one("#ai_provider_ollama_key", EnvVarInput).value = ai.ollama_api_key
        self.query_one("#ai_provider_model", Input).value = ai.model
        self.query_one("#ai_provider_base_url", Input).value = ai.base_url
        self.query_one("#ai_provider_max_tokens", Input).value = str(ai.max_tokens)
        self.query_one("#ai_provider_temperature", Input).value = str(ai.temperature)

        pref = (ai.provider_preference or "")
        pref = pref if pref in {v for _, v in _PREF_OPTIONS} else ""
        self.query_one("#ai_provider_pref_select", Select).value = pref

        self._snapshot_now()

    # ------------------------------------------------------------------
    # Dirty tracking
    # ------------------------------------------------------------------

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "provider": str(self.query_one("#ai_provider_provider", Select).value),
            "openai_api_key": self.query_one("#ai_provider_openai_key", EnvVarInput).value.strip(),
            "anthropic_api_key": self.query_one("#ai_provider_anthropic_key", EnvVarInput).value.strip(),
            "gemini_api_key": self.query_one("#ai_provider_gemini_key", EnvVarInput).value.strip(),
            "ollama_api_key": self.query_one("#ai_provider_ollama_key", EnvVarInput).value.strip(),
            "model": self.query_one("#ai_provider_model", Input).value.strip(),
            "base_url": self.query_one("#ai_provider_base_url", Input).value.strip(),
            "max_tokens": self.query_one("#ai_provider_max_tokens", Input).value.strip(),
            "temperature": self.query_one("#ai_provider_temperature", Input).value.strip(),
            "provider_preference": str(self.query_one("#ai_provider_pref_select", Select).value),
        }

    # ------------------------------------------------------------------
    # Validation + collection
    # ------------------------------------------------------------------

    def collect(self) -> Dict[str, Any]:
        """Validate and return fields to persist.

        Raises:
            ValidationError: On invalid max_tokens or temperature.
        """
        provider = str(self.query_one("#ai_provider_provider", Select).value)

        openai_key = self.query_one("#ai_provider_openai_key", EnvVarInput).value.strip()
        anthropic_key = self.query_one("#ai_provider_anthropic_key", EnvVarInput).value.strip()
        gemini_key = self.query_one("#ai_provider_gemini_key", EnvVarInput).value.strip()
        ollama_key = self.query_one("#ai_provider_ollama_key", EnvVarInput).value.strip()
        model = self.query_one("#ai_provider_model", Input).value.strip()
        base_url = self.query_one("#ai_provider_base_url", Input).value.strip()

        max_tokens_raw = self.query_one("#ai_provider_max_tokens", Input).value.strip() or "4096"
        try:
            max_tokens = int(max_tokens_raw)
        except ValueError as exc:
            raise ValidationError(
                "ai_provider_max_tokens", "Max tokens must be a whole number"
            ) from exc
        if max_tokens <= 0:
            raise ValidationError(
                "ai_provider_max_tokens", "Max tokens must be greater than zero"
            )

        temperature_raw = self.query_one("#ai_provider_temperature", Input).value.strip() or "0.3"
        try:
            temperature = float(temperature_raw)
        except ValueError as exc:
            raise ValidationError(
                "ai_provider_temperature", "Temperature must be a number (e.g. 0.3)"
            ) from exc
        if temperature < 0.0 or temperature > 2.0:
            raise ValidationError(
                "ai_provider_temperature", "Temperature must be between 0.0 and 2.0"
            )

        pref_raw = str(self.query_one("#ai_provider_pref_select", Select).value).strip()
        provider_preference = pref_raw or None

        return {
            "provider": provider,
            "openai_api_key": openai_key,
            "anthropic_api_key": anthropic_key,
            "gemini_api_key": gemini_key,
            "ollama_api_key": ollama_key,
            "model": model,
            "base_url": base_url,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "provider_preference": provider_preference,
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def persist(self) -> None:
        """Validate via :meth:`collect` then write via ``config_manager``.

        Preserves un-exposed fields (``provider_preference``,
        ``local_fallback_provider``, ``dismissed_banners``, legacy
        ``api_key``) via ``dataclasses.replace``.
        """
        fields = self.collect()
        config = self.app.config_manager.get()
        ai_config = dataclass_replace(
            config.ai_provider,
            provider=fields["provider"],
            openai_api_key=fields["openai_api_key"],
            anthropic_api_key=fields["anthropic_api_key"],
            gemini_api_key=fields["gemini_api_key"],
            ollama_api_key=fields["ollama_api_key"],
            model=fields["model"],
            base_url=fields["base_url"],
            max_tokens=fields["max_tokens"],
            temperature=fields["temperature"],
            provider_preference=fields["provider_preference"],
        )
        self.app.config_manager.update(ai_provider=ai_config)
        self._finish_save()

    # ------------------------------------------------------------------
    # Button handler
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle Save, Reset, and Upgrade buttons."""
        btn_id = event.button.id

        if btn_id == f"save_{self.PANEL_ID}":
            # Delegate to base-class save handler.
            super().on_button_pressed(event)
            return

        if btn_id == "ai_provider_reset":
            event.stop()
            self._handle_reset()
            return

        if btn_id == "ai_provider_upgrade":
            event.stop()
            self._handle_upgrade()
            return

    # ------------------------------------------------------------------
    # Dirty marker refresh
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Refresh the dirty marker on any input edit."""
        self._dirty_watch()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Refresh the dirty marker on provider change."""
        self._dirty_watch()

    # ------------------------------------------------------------------
    # Servonaut AI status helpers
    # ------------------------------------------------------------------

    def _refresh_servonaut_status(self) -> None:
        """Populate the Servonaut AI status row (read-only, no secrets shown)."""
        auth = getattr(self.app, "auth_service", None)
        try:
            status = self.query_one("#ai_provider_servonaut_status", Static)
            upgrade_btn = self.query_one("#ai_provider_upgrade", Button)
        except Exception:
            return

        if auth is None or not getattr(auth, "is_authenticated", False):
            status.update("Servonaut AI: [yellow]locked[/yellow] [dim]Login required[/dim]")
            upgrade_btn.display = True
            return

        try:
            has_premium = bool(auth.has_feature("premium_ai"))
        except Exception:
            has_premium = False

        if not has_premium:
            status.update("Servonaut AI: [yellow]locked[/yellow] [dim]Solo or Teams required[/dim]")
            upgrade_btn.display = True
            return

        upgrade_btn.display = False
        status.update("Servonaut AI: [green]ready[/green]")

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def _handle_reset(self) -> None:
        """Clear the provider preference and dismissed banners via resolver."""
        from servonaut.services.ai_provider_preference import (
            ProviderPreferenceResolver,
        )

        auth = getattr(self.app, "auth_service", None)
        if auth is None:
            self.app.notify(
                "Auth service unavailable; preference not reset.",
                severity="warning",
                markup=False,
            )
            return
        try:
            resolver = ProviderPreferenceResolver(auth, self.app.config_manager)
            resolver.reset()
        except Exception as exc:
            logger.error("Provider preference reset failed: %s", exc)
            self.app.notify(
                f"Reset failed: {escape(str(exc))}",
                severity="error",
                markup=False,
            )
            return

        # Reset clears provider_preference → reflect "no preference" in the
        # select, and re-baseline so the panel isn't left falsely dirty.
        try:
            self.query_one("#ai_provider_pref_select", Select).value = ""
        except Exception:
            pass
        self._snapshot_now()
        self._refresh_dirty_marker()
        self._refresh_servonaut_status()
        self.app.notify(
            "Cleared AI provider preference and dismissed banners.",
            severity="information",
            markup=False,
        )

    def _handle_upgrade(self) -> None:
        """Trigger the upgrade / login flow if available."""
        try:
            from servonaut.screens.login import LoginScreen  # type: ignore[import]
            self.app.push_screen(LoginScreen())
        except Exception:
            self.app.notify(
                "Open https://servonaut.dev to upgrade.",
                severity="information",
                markup=False,
            )
