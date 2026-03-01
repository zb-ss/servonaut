"""AI log analysis screen for Servonaut."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional, Dict, List

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
            TextArea(self._text, id="ai_text_input"),
            Static("", id="ai_token_estimate"),
            Button("Fetch Recent Logs", id="btn_fetch_logs", variant="default"),
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

        # Hide fetch button if no instance context
        if not self._instance:
            self.query_one("#btn_fetch_logs").display = False

        # If text was pre-filled, show it in the output area as hint
        if self._text:
            output = self.query_one("#ai_output", RichLog)
            output.write("[dim]Text loaded. Press Analyze to start.[/dim]")

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

        self.run_worker(self._do_fetch_logs(), name="fetch_logs", exclusive=True)

    async def _do_fetch_logs(self) -> None:
        """Worker to fetch logs via SSH and populate the text area."""
        progress = self.query_one(ProgressIndicator)
        output = self.query_one("#ai_output", RichLog)
        text_area = self.query_one("#ai_text_input", TextArea)

        try:
            instance = self._instance
            config = self.app.config_manager.get()

            # Resolve connection details
            if instance.get('is_custom'):
                host = instance.get('public_ip') or instance.get('private_ip')
                username = instance.get('username') or 'root'
                key_path = instance.get('key_name') or None
                proxy_args = []  # type: List[str]
                port = instance.get('port', 22)
            else:
                profile = self.app.connection_service.resolve_profile(instance)
                host = self.app.connection_service.get_target_host(instance, profile)
                proxy_args = []
                if profile:
                    proxy_args = self.app.connection_service.get_proxy_args(profile)
                username = config.default_username
                key_path = self.app.ssh_service.get_key_path(instance.get('id', ''))
                if not key_path and instance.get('key_name'):
                    key_path = self.app.ssh_service.discover_key(instance['key_name'])
                port = None

            if not host:
                output.clear()
                output.write("[red]No IP address available for this instance.[/red]")
                return

            # Fetch last 100 lines from common log files
            remote_cmd = (
                "for f in /var/log/syslog /var/log/messages /var/log/auth.log "
                "/var/log/nginx/error.log /var/log/nginx/access.log "
                "/var/log/apache2/error.log /var/log/httpd/error_log; do "
                "if [ -r \"$f\" ]; then echo \"=== $f ===\"; tail -100 \"$f\"; break; fi; "
                "done"
            )

            ssh_cmd = self.app.ssh_service.build_ssh_command(
                host=host,
                username=username,
                key_path=key_path,
                proxy_args=proxy_args,
                remote_command=remote_cmd,
                port=port,
            )

            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=30
            )

            log_text = stdout.decode('utf-8', errors='replace').strip()
            if log_text:
                text_area.load_text(log_text)
                self._update_token_estimate()
                output.clear()
                output.write(
                    f"[green]Fetched {len(log_text.splitlines())} lines.[/green] "
                    f"Press [bold]Analyze[/bold] to send to AI."
                )
            else:
                err_text = stderr.decode('utf-8', errors='replace').strip()
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
            output.write(f"[red]Error: {exc}[/red]")
        finally:
            progress.stop()

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

        self.run_worker(self._do_analysis(text), name="analyze", exclusive=True)

    async def _do_analysis(self, text: str) -> None:
        """Perform the AI analysis asynchronously."""
        progress = self.query_one(ProgressIndicator)
        output = self.query_one("#ai_output", RichLog)
        cost_info = self.query_one("#ai_cost_info", Static)

        try:
            result = await self.app.ai_analysis_service.analyze_text(text)
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
