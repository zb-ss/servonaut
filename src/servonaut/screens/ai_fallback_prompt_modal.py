"""T10 fallback prompt modal — second-upstream-unavailable-in-60s.

Shown by :class:`ChatPanel` when the server emits
``upstream_unavailable`` for the second time within a 60-second
window AND ``ai.local_fallback_provider`` is null AND a non-Servonaut
provider is configured. Lets the user opt in to a session-only
fallback without mutating ``ai.provider_preference`` (per plan §T10
"Once accepted, fallback is session-scoped").

Per CLAUDE.md ModalScreen rule: brief blocking choice ("which provider
do you want to use for THIS session"), so a Modal is the right fit.
"""
from __future__ import annotations

from typing import List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Static


# Display labels for known providers. Anything else falls through to a
# title-cased version of the raw provider id.
_PROVIDER_LABELS = {
    "ollama":    "Ollama (local, private)",
    "openai":    "OpenAI",
    "anthropic": "Anthropic",
    "gemini":    "Gemini",
}


class AIFallbackPromptModal(ModalScreen[Optional[str]]):
    """Offer a session-scoped fallback after two ``upstream_unavailable`` errors.

    Args:
        available_providers: Subset of ``{"ollama", "openai", "anthropic",
            "gemini"}`` that the user has actually configured. Only
            entries in this list get a button.
        reason: Optional explanation rendered above the buttons. Caller
            typically passes the raw error code or count, e.g.
            ``"Second upstream timeout in 60s"``.

    Returns via ``dismiss``:
        - One of the provider names from ``available_providers`` if the
          user picked one (caller switches the active provider for the
          rest of this chat session).
        - ``None`` if the user pressed Escape / "Keep retrying"
          (caller resumes Servonaut AI with backoff).
    """

    BINDINGS = [
        Binding("escape", "dismiss_none", "Cancel", show=True),
    ]

    DEFAULT_CSS = """
    AIFallbackPromptModal {
        align: center middle;
    }

    AIFallbackPromptModal #ai_fallback_container {
        width: 76;
        height: auto;
        border: round $warning;
        background: $surface;
        padding: 1 2;
    }

    AIFallbackPromptModal #ai_fallback_title {
        text-style: bold;
        color: $warning;
        margin-bottom: 1;
    }

    AIFallbackPromptModal #ai_fallback_reason {
        margin-bottom: 1;
    }

    AIFallbackPromptModal #ai_fallback_body {
        margin-bottom: 1;
    }

    AIFallbackPromptModal #ai_fallback_buttons {
        height: auto;
        align: center middle;
    }

    AIFallbackPromptModal #ai_fallback_buttons Button {
        margin: 0 1;
    }

    AIFallbackPromptModal #ai_fallback_keep {
        margin-top: 1;
        align: center middle;
    }
    """

    def __init__(
        self,
        available_providers: List[str],
        reason: str = "",
    ) -> None:
        super().__init__()
        # Defensive normalisation — accept duplicates / unknown entries
        # without crashing; we just don't render buttons for them.
        seen: set = set()
        clean: List[str] = []
        for name in available_providers:
            normalised = (name or "").lower().strip()
            if normalised and normalised not in seen:
                seen.add(normalised)
                clean.append(normalised)
        self._available = clean
        self._reason = (reason or "").strip()

    def compose(self) -> ComposeResult:
        yield Header()
        children = [
            Static(
                "[bold yellow]Servonaut AI is unavailable.[/bold yellow]",
                id="ai_fallback_title",
            ),
        ]
        if self._reason:
            children.append(
                Static(
                    f"[dim]{escape(self._reason)}[/dim]",
                    id="ai_fallback_reason",
                )
            )
        children.append(
            Static(
                "Use one of your local providers for this session? "
                "This won't change your default — only the current chat.",
                id="ai_fallback_body",
            )
        )

        if self._available:
            buttons = []
            for provider in self._available:
                label = _PROVIDER_LABELS.get(provider, provider.title())
                buttons.append(
                    Button(
                        escape(label),
                        id=f"btn_fallback_{provider}",
                        variant="primary",
                    )
                )
            children.append(
                Horizontal(*buttons, id="ai_fallback_buttons")
            )
        else:
            # No fallback configured — show a hint instead of buttons.
            children.append(
                Static(
                    "[dim]No alternate provider configured. "
                    "Add an OpenAI / Anthropic key or set up Ollama in Settings.[/dim]",
                    id="ai_fallback_body",
                )
            )

        children.append(
            Vertical(
                Button("Keep retrying", id="btn_fallback_keep", variant="default"),
                id="ai_fallback_keep",
            )
        )

        yield Container(*children, id="ai_fallback_container")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "btn_fallback_keep":
            self.dismiss(None)
            return
        if button_id.startswith("btn_fallback_"):
            provider = button_id.removeprefix("btn_fallback_")
            # Only accept providers we offered — defensive against id
            # collision with other button schemes.
            if provider in self._available:
                self.dismiss(provider)
                return
        # Fallthrough: unrecognised button id → no change.

    def action_dismiss_none(self) -> None:
        self.dismiss(None)


__all__ = ["AIFallbackPromptModal"]
