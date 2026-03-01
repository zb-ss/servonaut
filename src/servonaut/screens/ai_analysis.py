"""AI log analysis screen for Servonaut."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional, Dict

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Button, RichLog, TextArea

from servonaut.widgets.progress_indicator import ProgressIndicator

logger = logging.getLogger(__name__)


class AIAnalysisScreen(Screen):
    """Screen for AI-powered log analysis using OpenAI, Anthropic, or Ollama.

    Accepts text to analyze and displays AI-generated insights including
    summaries, errors, security concerns, and recommended actions.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("f5", "run_analyze", "Analyze", show=True),
    ]

    def __init__(self, text: str = "", instance: Optional[Dict] = None) -> None:
        """Initialize the AI analysis screen.

        Args:
            text: Log text to analyze (pre-filled if provided).
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
            TextArea("", id="ai_text_input", tab_behavior="focus"),
            Static("", id="ai_token_estimate"),
            Button("Fetch Recent Logs", id="btn_fetch_logs", variant="default"),
            Button("Analyze (F5)", id="btn_analyze", variant="primary"),
            ProgressIndicator(),
            RichLog(id="ai_output", highlight=True, markup=True),
            Static("", id="ai_cost_info"),
            Button("Back", id="btn_back", variant="error"),
            id="ai_container",
        )
        yield Footer()

    def on_mount(self) -> None:
        """Populate provider info, load text deferred, and show token estimate."""
        self._update_provider_info()

        # Hide fetch button if no instance context
        if not self._instance:
            self.query_one("#btn_fetch_logs").display = False

        # Deferred text load — avoids blocking compose() with large input
        if self._text:
            text_area = self.query_one("#ai_text_input", TextArea)
            text_area.load_text(self._text)

            output = self.query_one("#ai_output", RichLog)
            output.write("[dim]Text loaded. Press Analyze or F5 to start.[/dim]")

            # Warn on large input
            tokens = self.app.ai_analysis_service.estimate_tokens(self._text)
            if tokens > 8000:
                output.write(
                    f"[yellow]Warning: ~{tokens} tokens is a large input. "
                    f"Analysis may be slow or costly.[/yellow]"
                )

        self._update_token_estimate()

    def _update_provider_info(self) -> None:
        config = self.app.config_manager.get()
        ai_config = config.ai_provider
        model = ai_config.model or self._default_model_for(ai_config.provider)
        api_key = ai_config.api_key
        key_status = "[green]set[/green]" if api_key else "[red]not set[/red]"
        if ai_config.provider == 'ollama':
            key_status = "[dim]n/a[/dim]"
        info = (
            f"Provider: [cyan]{ai_config.provider}[/cyan]  "
            f"Model: [cyan]{model}[/cyan]  "
            f"API Key: {key_status}"
        )
        self.query_one("#ai_provider_info", Static).update(info)

    def _update_token_estimate(self) -> None:
        text = self._get_input_text()
        service = self.app.ai_analysis_service
        tokens = service.estimate_tokens(text)
        chunks = len(service.chunk_text(text))
        chunk_note = f"  ({chunks} chunk{'s' if chunks != 1 else ''})" if chunks > 1 else ""
        self.query_one("#ai_token_estimate", Static).update(
            f"Input: ~[yellow]{tokens}[/yellow] tokens{chunk_note}"
        )

    def _get_input_text(self) -> str:
        """Get text from the TextArea widget."""
        return self.query_one("#ai_text_input", TextArea).text

    def _default_model_for(self, provider: str) -> str:
        defaults = {
            'openai': 'gpt-4o-mini',
            'anthropic': 'claude-sonnet-4-20250514',
            'ollama': 'llama3',
        }
        return defaults.get(provider, 'unknown')

    def action_run_analyze(self) -> None:
        """Trigger analysis via keyboard shortcut (F5)."""
        self._run_analysis()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_analyze":
            self._run_analysis()
        elif event.button.id == "btn_fetch_logs":
            self._fetch_recent_logs()
        elif event.button.id == "btn_back":
            self.action_back()

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        """Update token estimate when text changes."""
        self._update_token_estimate()

    def _set_buttons_disabled(self, disabled: bool) -> None:
        """Enable or disable action buttons."""
        self.query_one("#btn_analyze", Button).disabled = disabled
        self.query_one("#btn_fetch_logs", Button).disabled = disabled

    def _fetch_recent_logs(self) -> None:
        """Fetch recent log output from the server via SSH."""
        if not self._instance:
            self.app.notify("No server context available.", severity="warning")
            return

        output = self.query_one("#ai_output", RichLog)
        output.clear()
        output.write("[dim]Fetching recent logs from server...[/dim]")

        progress = self.query_one(ProgressIndicator)
        progress.start("Fetching logs...")

        self._set_buttons_disabled(True)
        self.run_worker(self._do_fetch_logs(), name="fetch_logs", exclusive=True)

    async def _do_fetch_logs(self) -> None:
        """Worker to fetch logs via SSH and populate the text area.

        Uses log_viewer_service to probe available paths and resolve
        connection details, avoiding duplicated SSH logic.
        """
        progress = self.query_one(ProgressIndicator)
        output = self.query_one("#ai_output", RichLog)
        text_area = self.query_one("#ai_text_input", TextArea)

        try:
            instance = self._instance
            service = self.app.log_viewer_service

            # Resolve connection via service helper
            conn = service._resolve_connection(
                instance,
                self.app.ssh_service,
                self.app.connection_service,
            )

            if not conn["host"]:
                output.clear()
                output.write("[red]No IP address available for this instance.[/red]")
                return

            # Probe for readable log files
            available = await service.probe_log_paths(
                instance,
                self.app.ssh_service,
                self.app.connection_service,
            )

            if not available:
                output.clear()
                output.write("[yellow]No readable log files found on this server.[/yellow]")
                return

            # Fetch last 100 lines from the first available log (non-follow)
            log_path = available[0]
            tail_cmd = service.get_tail_command(log_path, num_lines=100, follow=False)

            ssh_cmd = self.app.ssh_service.build_ssh_command(
                host=conn["host"],
                username=conn["username"],
                key_path=conn["key_path"],
                proxy_args=conn["proxy_args"],
                remote_command=tail_cmd,
                port=conn["port"],
            )

            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=30
            )

            log_text = stdout.decode("utf-8", errors="replace").strip()
            if log_text:
                text_area.load_text(log_text)
                self._update_token_estimate()
                output.clear()
                output.write(
                    f"[green]Fetched {len(log_text.splitlines())} lines "
                    f"from {log_path}.[/green] "
                    f"Press [bold]Analyze[/bold] to send to AI."
                )
            else:
                err_text = stderr.decode("utf-8", errors="replace").strip()
                output.clear()
                if err_text:
                    output.write(f"[yellow]No logs fetched.[/yellow]\n[dim]{err_text}[/dim]")
                else:
                    output.write("[yellow]No readable log files found on this server.[/yellow]")

        except asyncio.TimeoutError:
            output.clear()
            output.write("[red]Timed out fetching logs from server.[/red]")
        except Exception as exc:
            logger.error("Error fetching logs: %s", exc)
            output.clear()
            output.write(Text.assemble(("Error: ", "bold red"), (str(exc), "red")))
        finally:
            progress.stop()
            self._set_buttons_disabled(False)

    def _run_analysis(self) -> None:
        """Start async analysis worker."""
        text = self._get_input_text()
        if not text.strip():
            self.app.notify(
                "No text to analyze. Paste text or press 'Fetch Recent Logs'.",
                severity="warning",
            )
            return

        output = self.query_one("#ai_output", RichLog)
        output.clear()
        output.write("[dim]Analyzing...[/dim]")

        progress = self.query_one(ProgressIndicator)
        progress.start("Analyzing with AI...")

        self._set_buttons_disabled(True)
        self.run_worker(self._do_analysis(text), name="analyze", exclusive=True)

    async def _do_analysis(self, text: str) -> None:
        """Perform the AI analysis asynchronously."""
        progress = self.query_one(ProgressIndicator)
        output = self.query_one("#ai_output", RichLog)
        cost_info = self.query_one("#ai_cost_info", Static)

        try:
            result = await self.app.ai_analysis_service.analyze_text(text)
            output.clear()
            # Write as plain Text to prevent Rich from eating [ERROR],
            # [INFO], timestamps, etc. in the AI response.
            output.write(Text(result['content']))

            input_tok = result.get('input_tokens', 0)
            output_tok = result.get('output_tokens', 0)
            total_tok = result.get('tokens_used', 0)
            model = result.get('model', '')
            cost = result.get('estimated_cost')

            if cost is None:
                cost_str = "[dim]pricing unavailable[/dim]"
            elif cost == 0:
                cost_str = "[green]free (local)[/green]"
            else:
                cost_str = f"[yellow]${cost:.4f}[/yellow]"
            cost_info.update(
                f"Tokens: [yellow]{input_tok}[/yellow] in / "
                f"[yellow]{output_tok}[/yellow] out "
                f"([yellow]{total_tok}[/yellow] total)  "
                f"Model: [cyan]{model}[/cyan]  "
                f"Est. cost: {cost_str}"
            )
        except Exception as exc:
            output.clear()
            output.write(Text.assemble(("Error: ", "bold red"), (str(exc), "red")))
        finally:
            progress.stop()
            self._set_buttons_disabled(False)

    def action_back(self) -> None:
        """Return to previous screen."""
        self.app.pop_screen()
