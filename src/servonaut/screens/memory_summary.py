"""Memory-summary views and explicit AI-provider consent UI."""

from __future__ import annotations

from typing import Optional, Sequence

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, Header, Markdown, Select, Static

from servonaut.styles import CSS_FILES as _APP_CSS_FILES
from servonaut.widgets.sidebar import Sidebar


_PROVIDER_LABELS = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "gemini": "Google Gemini",
    "ollama": "Ollama",
    "servonaut": "Servonaut AI",
}


def provider_label(provider_name: str) -> str:
    """Return a human-readable label for a configured AI provider."""
    normalised = (provider_name or "").strip().lower()
    return _PROVIDER_LABELS.get(normalised, normalised.replace("_", " ").title())


class MemorySummaryScreen(Screen):
    """Full-screen Markdown reader for local and AI-enhanced summaries."""

    CSS_PATH = [*_APP_CSS_FILES]

    DEFAULT_CSS = """
    MemorySummaryScreen #memory-summary-container {
        width: 1fr;
        padding: 0 1;
    }

    MemorySummaryScreen #memory-summary-title {
        height: auto;
        text-style: bold;
        margin-bottom: 1;
    }

    MemorySummaryScreen #memory-summary-source {
        height: auto;
        color: $text-muted;
        margin-bottom: 1;
        padding: 0 1;
        border-left: thick $primary;
    }

    MemorySummaryScreen #memory-summary-scroll {
        height: 1fr;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }

    MemorySummaryScreen #memory-summary-actions {
        height: auto;
        align: right middle;
        padding-top: 1;
    }

    MemorySummaryScreen #memory-summary-markdown {
        width: 1fr;
        height: auto;
    }

    MemorySummaryScreen #memory-summary-back {
        min-width: 12;
    }
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    def __init__(
        self,
        *,
        title: str,
        summary: str,
        source_label: str,
    ) -> None:
        super().__init__()
        self._title = title
        self._summary = summary
        self._source_label = source_label

    def compose(self) -> ComposeResult:
        """Compose a focused, scrollable Markdown reading surface."""
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static(
                    f"[bold cyan]{escape(self._title)}[/bold cyan]",
                    id="memory-summary-title",
                ),
                Static(
                    escape(self._source_label),
                    id="memory-summary-source",
                ),
                ScrollableContainer(
                    Markdown(self._summary, id="memory-summary-markdown"),
                    id="memory-summary-scroll",
                ),
                Horizontal(
                    Button("Back", variant="primary", id="memory-summary-back"),
                    id="memory-summary-actions",
                ),
                id="memory-summary-container",
            )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Return to the originating Memory screen."""
        if event.button.id == "memory-summary-back":
            self.action_back()

    def action_back(self) -> None:
        """Close the summary reader."""
        self.app.pop_screen()


class AIEnhanceConsentModal(ModalScreen[Optional[str]]):
    """Select one configured provider and grant one-time summary consent."""

    DEFAULT_CSS = """
    AIEnhanceConsentModal {
        align: center middle;
    }

    AIEnhanceConsentModal #ai-enhance-consent-container {
        width: 78;
        height: auto;
        max-height: 28;
        border: round $warning;
        background: $surface;
        padding: 1 2;
    }

    AIEnhanceConsentModal #ai-enhance-consent-title {
        height: auto;
        text-style: bold;
        color: $warning;
        margin-bottom: 1;
    }

    AIEnhanceConsentModal #ai-enhance-provider {
        margin: 1 0;
    }

    AIEnhanceConsentModal #ai-enhance-disclosure,
    AIEnhanceConsentModal #ai-enhance-guardrails {
        height: auto;
        margin-bottom: 1;
    }

    AIEnhanceConsentModal #ai-enhance-actions {
        height: auto;
        align: right middle;
    }

    AIEnhanceConsentModal #ai-enhance-cancel {
        margin-right: 1;
    }

    AIEnhanceConsentModal #ai-enhance-confirm {
        min-width: 22;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    def __init__(self, provider_names: Sequence[str]) -> None:
        super().__init__()
        clean_names = list(
            dict.fromkeys(
                name.strip().lower() for name in provider_names if name.strip()
            )
        )
        if not clean_names:
            raise ValueError("At least one configured AI provider is required")
        self._provider_names = clean_names

    def compose(self) -> ComposeResult:
        """Compose the provider picker and one-time disclosure."""
        options = [
            (provider_label(provider_name), provider_name)
            for provider_name in self._provider_names
        ]
        selected = self._provider_names[0]
        yield Container(
            Static("Enhance local summary with AI", id="ai-enhance-consent-title"),
            Static(
                "Choose the exact provider for this one request. Your configured "
                "default is not changed.",
            ),
            Select(
                options,
                value=selected,
                allow_blank=False,
                id="ai-enhance-provider",
            ),
            Static(
                self._disclosure_text(selected),
                id="ai-enhance-disclosure",
            ),
            Static(
                "[bold]Guardrails:[/bold] AI tools are disabled and no fallback "
                "provider will be used. Only the local Markdown summary is sent; "
                "review View Summary first if it contains sensitive annotations.",
                id="ai-enhance-guardrails",
            ),
            Horizontal(
                Button("Cancel", id="ai-enhance-cancel"),
                Button(
                    "Consent and enhance",
                    variant="warning",
                    id="ai-enhance-confirm",
                ),
                id="ai-enhance-actions",
            ),
            id="ai-enhance-consent-container",
        )

    def on_select_changed(self, event: Select.Changed) -> None:
        """Keep the disclosure aligned with the currently selected provider."""
        if event.select.id != "ai-enhance-provider" or event.value is Select.BLANK:
            return
        self.query_one("#ai-enhance-disclosure", Static).update(
            self._disclosure_text(str(event.value))
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Dismiss with the exact provider only after affirmative consent."""
        if event.button.id == "ai-enhance-cancel":
            self.dismiss(None)
            return
        if event.button.id != "ai-enhance-confirm":
            return
        selected = self.query_one("#ai-enhance-provider", Select).value
        if selected is Select.BLANK:
            return
        provider_name = str(selected)
        if provider_name not in self._provider_names:
            return
        self.dismiss(provider_name)

    def action_cancel(self) -> None:
        """Cancel without sending any summary text."""
        self.dismiss(None)

    @staticmethod
    def _disclosure_text(provider_name: str) -> str:
        label = escape(provider_label(provider_name))
        return (
            f"[bold]Destination:[/bold] {label}\n"
            "Continuing grants one-time consent to send this server's "
            "deterministic local summary to that provider for enhancement."
        )
