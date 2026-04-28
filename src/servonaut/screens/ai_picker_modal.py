"""T4.5 first-run + empty-state provider picker modals.

Both are :class:`ModalScreen` (per CLAUDE.md "ModalScreen vs Screen rule
of thumb"): brief blocking choices with two or three buttons. The
caller awaits the dismiss return value to decide what to do next.

* :class:`AIProviderFirstRunModal` — shown when ``premium_ai`` is true AND
  any non-Servonaut provider is configured AND no preference is set yet.
  Returns the chosen provider name (``"servonaut"`` or the existing
  provider's name) or ``None`` if the user dismissed without choosing.

* :class:`AIEmptyStateModal` — shown when neither subscription nor any
  provider is configured. Returns one of ``"subscribe"`` /
  ``"add_api_key"`` / ``"ollama"`` / ``None``.
"""
from __future__ import annotations

from typing import Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Static


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _format_existing_provider_label(
    provider_name: str,
    base_url: str = "",
) -> str:
    """Return the "Currently configured: [...]" string for the modal title.

    Per the agent brief:
      - Ollama with default base_url ``http://localhost:11434`` →
        ``"Ollama @ localhost:11434"``
      - Ollama with non-default base_url → ``"Ollama @ <stripped url>"``
      - Anything else → capitalised provider name (``"OpenAI"``, ``"Anthropic"``,
        ``"Gemini"``).

    All user-influenced strings are passed through :func:`rich.markup.escape`
    before interpolation.
    """
    name = (provider_name or "").lower()
    if name == "ollama":
        url = (base_url or "http://localhost:11434").strip()
        # Strip leading scheme for compactness.
        for scheme in ("http://", "https://"):
            if url.lower().startswith(scheme):
                url = url[len(scheme):]
                break
        return f"Ollama @ {escape(url)}"
    pretty = {
        "openai": "OpenAI",
        "anthropic": "Anthropic",
        "gemini": "Gemini",
    }.get(name, name.title() if name else "your existing provider")
    return escape(pretty)


def _short_provider_name(provider_name: str) -> str:
    """One-word provider label for the "Keep [Ollama]" button."""
    name = (provider_name or "").lower()
    return {
        "openai": "OpenAI",
        "anthropic": "Anthropic",
        "ollama": "Ollama",
        "gemini": "Gemini",
    }.get(name, name.title() if name else "Existing")


# ---------------------------------------------------------------------------
# AIProviderFirstRunModal
# ---------------------------------------------------------------------------


class AIProviderFirstRunModal(ModalScreen[Optional[str]]):
    """First-run choice between hosted Servonaut AI and the user's existing local provider.

    Args:
        existing_provider: Name of the configured non-Servonaut provider (e.g.
            ``"ollama"``).
        base_url: Optional base URL for Ollama, used in the title.

    Returns via ``dismiss``:
        - ``"servonaut"`` if the user picks "Switch to Servonaut AI"
        - the ``existing_provider`` name if they pick "Keep ..."
        - ``None`` if they hit Escape / press the close button
    """

    BINDINGS = [
        Binding("escape", "dismiss_none", "Cancel", show=True),
    ]

    DEFAULT_CSS = """
    AIProviderFirstRunModal {
        align: center middle;
    }

    AIProviderFirstRunModal #ai_picker_container {
        width: 78;
        height: auto;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }

    AIProviderFirstRunModal #ai_picker_title {
        text-style: bold;
        margin-bottom: 1;
    }

    AIProviderFirstRunModal #ai_picker_body {
        margin-bottom: 1;
    }

    AIProviderFirstRunModal #ai_picker_existing {
        margin-bottom: 1;
        text-style: italic;
    }

    AIProviderFirstRunModal #ai_picker_buttons {
        height: auto;
        align: center middle;
    }

    AIProviderFirstRunModal #ai_picker_buttons Button {
        margin: 0 1;
    }
    """

    def __init__(
        self,
        existing_provider: str,
        base_url: str = "",
    ) -> None:
        super().__init__()
        # Normalise to a known provider name (or leave blank).
        self._existing_provider = (existing_provider or "").lower()
        self._existing_label = _format_existing_provider_label(
            self._existing_provider, base_url,
        )
        self._existing_short = _short_provider_name(self._existing_provider)

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Static(
                "[bold cyan]You're now subscribed to Servonaut AI.[/bold cyan]",
                id="ai_picker_title",
            ),
            Static(
                "Servonaut AI unlocks model-driven tool execution "
                "(tail logs, run commands, deploy) on your servers through "
                "the existing relay — your local provider cannot do that.\n\n"
                "Switch to Servonaut AI for this CLI?",
                id="ai_picker_body",
            ),
            Static(
                f"Currently configured: [cyan]{self._existing_label}[/cyan]",
                id="ai_picker_existing",
            ),
            Horizontal(
                Button(
                    "Switch to Servonaut AI",
                    id="btn_pick_servonaut",
                    variant="primary",
                ),
                Button(
                    f"Keep {escape(self._existing_short)}",
                    id="btn_pick_existing",
                    variant="default",
                ),
                id="ai_picker_buttons",
            ),
            id="ai_picker_container",
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_pick_servonaut":
            self.dismiss("servonaut")
        elif event.button.id == "btn_pick_existing":
            # Return the canonical lowercase provider name so the caller
            # can persist it directly as ``ai.provider_preference``.
            self.dismiss(self._existing_provider or None)

    def action_dismiss_none(self) -> None:
        """Escape key dismisses the modal without persisting a choice."""
        self.dismiss(None)


# ---------------------------------------------------------------------------
# AIEmptyStateModal
# ---------------------------------------------------------------------------


class AIEmptyStateModal(ModalScreen[Optional[str]]):
    """Empty-state onboarding when neither subscription nor any provider is set.

    Returns via ``dismiss``:
        - ``"subscribe"`` → caller opens billing / subscription flow
        - ``"add_api_key"`` → caller opens Settings to add an OpenAI/Anthropic key
        - ``"ollama"`` → caller opens an Ollama setup helper
        - ``None`` → user dismissed without choosing
    """

    BINDINGS = [
        Binding("escape", "dismiss_none", "Cancel", show=True),
    ]

    DEFAULT_CSS = """
    AIEmptyStateModal {
        align: center middle;
    }

    AIEmptyStateModal #ai_empty_container {
        width: 76;
        height: auto;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }

    AIEmptyStateModal #ai_empty_title {
        text-style: bold;
        margin-bottom: 1;
    }

    AIEmptyStateModal #ai_empty_body {
        margin-bottom: 1;
    }

    AIEmptyStateModal #ai_empty_buttons {
        height: auto;
        align: center middle;
    }

    AIEmptyStateModal #ai_empty_buttons Button {
        margin: 0 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Static(
                "[bold cyan]Servonaut needs an AI provider.[/bold cyan]",
                id="ai_empty_title",
            ),
            Static(
                "  1. Subscribe to Servonaut AI (zero config, "
                "includes tool execution)\n"
                "  2. Add an OpenAI / Anthropic key\n"
                "  3. Run a local model with Ollama (free, no key)",
                id="ai_empty_body",
            ),
            Horizontal(
                Button(
                    "Subscribe",
                    id="btn_empty_subscribe",
                    variant="primary",
                ),
                Button(
                    "Add API key",
                    id="btn_empty_add_key",
                    variant="default",
                ),
                Button(
                    "Set up Ollama",
                    id="btn_empty_ollama",
                    variant="default",
                ),
                id="ai_empty_buttons",
            ),
            id="ai_empty_container",
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_empty_subscribe":
            self.dismiss("subscribe")
        elif event.button.id == "btn_empty_add_key":
            self.dismiss("add_api_key")
        elif event.button.id == "btn_empty_ollama":
            self.dismiss("ollama")

    def action_dismiss_none(self) -> None:
        self.dismiss(None)


__all__ = [
    "AIProviderFirstRunModal",
    "AIEmptyStateModal",
]
