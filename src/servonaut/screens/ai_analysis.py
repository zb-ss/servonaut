"""AI log analysis screen for Servonaut."""

from __future__ import annotations

from typing import Optional, Dict

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Button, RichLog

from servonaut.widgets.progress_indicator import ProgressIndicator


class AIAnalysisScreen(Screen):
    """Screen for AI-powered log analysis using OpenAI, Anthropic, or Ollama.

    Accepts text to analyze and displays AI-generated insights including
    summaries, errors, security concerns, and recommended actions.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    def __init__(self, text: str = "", instance: Optional[Dict] = None) -> None:
        """Initialize the AI analysis screen.

        Args:
            text: Log text to analyze.
            instance: Optional instance dictionary for context.
        """
        super().__init__()
        self._text = text
        self._instance = instance

    def compose(self) -> ComposeResult:
        """Compose the AI analysis UI."""
        yield Header()
        yield Container(
            Static("[bold cyan]AI Log Analysis[/bold cyan]", id="ai_header"),
            Static("", id="ai_provider_info"),
            Static("", id="ai_token_estimate"),
            Button("Analyze", id="btn_analyze", variant="primary"),
            ProgressIndicator(),
            RichLog(id="ai_output", highlight=True),
            Static("", id="ai_cost_info"),
            Button("Back", id="btn_back", variant="error"),
            id="ai_container",
        )
        yield Footer()

    def on_mount(self) -> None:
        """Populate provider info and token estimate on mount."""
        self._update_provider_info()
        self._update_token_estimate()

    def _update_provider_info(self) -> None:
        config = self.app.config_manager.get()
        ai_config = config.ai_provider
        model = ai_config.model or self._default_model_for(ai_config.provider)
        info = f"Provider: [cyan]{ai_config.provider}[/cyan]  Model: [cyan]{model}[/cyan]"
        self.query_one("#ai_provider_info", Static).update(info)

    def _update_token_estimate(self) -> None:
        service = self.app.ai_analysis_service
        tokens = service.estimate_tokens(self._text)
        chunks = len(service.chunk_text(self._text))
        chunk_note = f"  ({chunks} chunk{'s' if chunks != 1 else ''})" if chunks > 1 else ""
        self.query_one("#ai_token_estimate", Static).update(
            f"Input: ~[yellow]{tokens}[/yellow] tokens{chunk_note}"
        )

    def _default_model_for(self, provider: str) -> str:
        defaults = {
            'openai': 'gpt-4o-mini',
            'anthropic': 'claude-sonnet-4-20250514',
            'ollama': 'llama3',
        }
        return defaults.get(provider, 'unknown')

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_analyze":
            self._run_analysis()
        elif event.button.id == "btn_back":
            self.action_back()

    def _run_analysis(self) -> None:
        """Start async analysis worker."""
        if not self._text.strip():
            self.app.notify("No text to analyze.", severity="warning")
            return

        output = self.query_one("#ai_output", RichLog)
        output.clear()
        output.write("[dim]Analyzing...[/dim]")

        progress = self.query_one(ProgressIndicator)
        progress.start()

        self.run_worker(self._do_analysis, exclusive=True)

    async def _do_analysis(self) -> None:
        """Perform the AI analysis asynchronously."""
        progress = self.query_one(ProgressIndicator)
        output = self.query_one("#ai_output", RichLog)
        cost_info = self.query_one("#ai_cost_info", Static)

        try:
            result = await self.app.ai_analysis_service.analyze_text(self._text)
            output.clear()
            output.write(result['content'])

            tokens = result.get('tokens_used', 0)
            model = result.get('model', '')
            cost = result.get('estimated_cost', 0)

            cost_str = f"${cost:.4f}" if cost > 0 else "free/unknown"
            cost_info.update(
                f"Tokens used: [yellow]{tokens}[/yellow]  "
                f"Model: [cyan]{model}[/cyan]  "
                f"Est. cost: [yellow]{cost_str}[/yellow]"
            )
        except Exception as exc:
            output.clear()
            output.write(f"[red]Error: {exc}[/red]")
        finally:
            progress.stop()

    def action_back(self) -> None:
        """Return to previous screen."""
        self.app.pop_screen()
