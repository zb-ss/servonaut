"""AI log analysis screen for Servonaut."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional, Dict, List

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Button, RichLog, TextArea, Input

from servonaut.config.secrets import resolve_secret, is_secret_ref
from servonaut.screens.log_picker import LogPickerModal, AddPathModal, ADD_PATH_SENTINEL
from servonaut.widgets.progress_indicator import ProgressIndicator

logger = logging.getLogger(__name__)


class AIAnalysisScreen(Screen):
    """Screen for AI-powered log analysis using OpenAI, Anthropic, Ollama, or Gemini.

    Accepts text to analyze and displays AI-generated insights including
    summaries, errors, security concerns, and recommended actions.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("f5", "run_analyze", "Analyze", show=True),
        Binding("y", "copy_output", "Copy", show=True),
    ]

    def __init__(self, text: str = "", instance: Optional[Dict] = None) -> None:
        super().__init__()
        self._text = text
        self._instance = instance
        # Filter state
        self._raw_text: str = text
        self._filter_pattern: str = ""
        # Log picker state
        self._available_logs: List[str] = []
        self._discovered_logs: List[str] = []
        self._scan_complete: bool = False
        # Track AI analysis output for clipboard
        self._output_text: str = ""

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Static("[bold cyan]AI Log Analysis[/bold cyan]", id="ai_header"),
            Static("", id="ai_provider_info"),
            TextArea("", id="ai_text_input", tab_behavior="focus"),
            Horizontal(
                Input(
                    placeholder="Filter lines (substring or /regex/)",
                    id="ai_filter_input",
                ),
                Button("Apply", id="btn_filter_apply", variant="default"),
                Button("Clear", id="btn_filter_clear", variant="default"),
                id="ai_filter_row",
            ),
            Static("", id="ai_token_estimate"),
            Input(
                placeholder="Custom prompt (leave empty for default analysis)",
                id="ai_user_prompt",
            ),
            Horizontal(
                Button("Fetch Logs", id="btn_fetch_logs", variant="default"),
                Button("Analyze (F5)", id="btn_analyze", variant="primary"),
                id="ai_action_row",
            ),
            ProgressIndicator(),
            RichLog(id="ai_output", highlight=True, markup=True),
            Static("", id="ai_cost_info"),
            Button("Back", id="btn_back", variant="error"),
            id="ai_container",
        )
        yield Footer()

    def on_mount(self) -> None:
        self._update_provider_info()

        if not self._instance:
            self.query_one("#btn_fetch_logs").display = False

        # Deferred text load
        if self._text:
            text_area = self.query_one("#ai_text_input", TextArea)
            text_area.load_text(self._text)
            self._raw_text = self._text

            output = self.query_one("#ai_output", RichLog)
            output.write("[dim]Text loaded. Press Analyze or F5 to start.[/dim]")

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
        if ai_config.provider == 'ollama':
            key_status = "[dim]n/a[/dim]"
        elif not api_key:
            key_status = "[red]not set[/red]"
        elif is_secret_ref(api_key) and not resolve_secret(api_key):
            key_status = "[yellow]ref unresolved[/yellow]"
        else:
            key_status = "[green]set[/green]"
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

        # Show filtered line count when filter is active
        if self._filter_pattern:
            filtered_count = len(text.splitlines()) if text else 0
            total_count = len(self._raw_text.splitlines()) if self._raw_text else 0
            line_info = f"  [dim]({filtered_count}/{total_count} lines)[/dim]"
        else:
            line_info = ""

        self.query_one("#ai_token_estimate", Static).update(
            f"Input: ~[yellow]{tokens}[/yellow] tokens{chunk_note}{line_info}"
        )

    def _get_input_text(self) -> str:
        return self.query_one("#ai_text_input", TextArea).text

    def _default_model_for(self, provider: str) -> str:
        defaults = {
            'openai': 'gpt-4o-mini',
            'anthropic': 'claude-sonnet-4-20250514',
            'ollama': 'llama3',
            'gemini': 'gemini-2.0-flash',
        }
        return defaults.get(provider, 'unknown')

    def action_run_analyze(self) -> None:
        self._run_analysis()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_analyze":
            self._run_analysis()
        elif event.button.id == "btn_fetch_logs":
            self._fetch_recent_logs()
        elif event.button.id == "btn_filter_apply":
            self._apply_filter()
        elif event.button.id == "btn_filter_clear":
            self._clear_filter()
        elif event.button.id == "btn_back":
            self.action_back()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "ai_filter_input":
            self._apply_filter()

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        # Only track raw text when not in filtered (read-only) mode
        if not self._filter_pattern:
            self._raw_text = event.text_area.text
        self._update_token_estimate()

    def _set_buttons_disabled(self, disabled: bool) -> None:
        self.query_one("#btn_analyze", Button).disabled = disabled
        self.query_one("#btn_fetch_logs", Button).disabled = disabled
        self.query_one("#btn_filter_apply", Button).disabled = disabled
        self.query_one("#btn_filter_clear", Button).disabled = disabled

    # --- Filter logic ---

    def _apply_filter(self) -> None:
        """Filter lines from _raw_text by pattern and display in TextArea."""
        filter_input = self.query_one("#ai_filter_input", Input)
        pattern = filter_input.value.strip()
        if not pattern:
            self.app.notify("Enter a filter pattern first.", severity="warning")
            return

        if not self._raw_text.strip():
            self.app.notify("No text to filter.", severity="warning")
            return

        # Parse regex syntax: /pattern/
        regex_match = re.match(r'^/(.+)/$', pattern)
        if regex_match:
            try:
                compiled = re.compile(regex_match.group(1), re.IGNORECASE)
            except re.error as e:
                self.app.notify(f"Invalid regex: {e}", severity="error")
                return
            filtered = [
                line for line in self._raw_text.splitlines()
                if compiled.search(line)
            ]
        else:
            # Case-insensitive substring match
            pattern_lower = pattern.lower()
            filtered = [
                line for line in self._raw_text.splitlines()
                if pattern_lower in line.lower()
            ]

        self._filter_pattern = pattern
        text_area = self.query_one("#ai_text_input", TextArea)
        text_area.load_text("\n".join(filtered))
        text_area.read_only = True
        self._update_token_estimate()

    def _clear_filter(self) -> None:
        """Restore original unfiltered text."""
        self._filter_pattern = ""
        text_area = self.query_one("#ai_text_input", TextArea)
        text_area.read_only = False
        text_area.load_text(self._raw_text)
        self.query_one("#ai_filter_input", Input).value = ""
        self._update_token_estimate()

    # --- Log fetching with picker ---

    def _fetch_recent_logs(self) -> None:
        if not self._instance:
            self.app.notify("No server context available.", severity="warning")
            return

        output = self.query_one("#ai_output", RichLog)
        output.clear()
        output.write("[dim]Probing available logs...[/dim]")

        progress = self.query_one(ProgressIndicator)
        progress.start("Probing logs...")

        self._set_buttons_disabled(True)
        self.run_worker(self._do_probe_and_pick(), name="fetch_logs", exclusive=True)

    async def _do_probe_and_pick(self) -> None:
        """Probe log paths, then open the log picker modal."""
        progress = self.query_one(ProgressIndicator)
        output = self.query_one("#ai_output", RichLog)

        try:
            service = self.app.log_viewer_service

            # Resolve connection first to check host
            conn = service._resolve_connection(
                self._instance,
                self.app.ssh_service,
                self.app.connection_service,
            )
            if not conn["host"]:
                output.clear()
                output.write("[red]No IP address available for this instance.[/red]")
                return

            # Probe for readable log files
            available = await service.probe_log_paths(
                self._instance,
                self.app.ssh_service,
                self.app.connection_service,
            )
            self._available_logs = available

            if not available:
                output.clear()
                output.write("[yellow]No readable log files found on this server.[/yellow]")
                return

            progress.stop()
            output.clear()

            # Open log picker modal
            self.app.push_screen(
                LogPickerModal(
                    available_logs=self._available_logs,
                    discovered_logs=self._discovered_logs,
                    classify_fn=service.classify_log_file,
                ),
                callback=self._on_log_picked,
            )

            # Kick off background directory scan if not done yet
            if not self._scan_complete:
                self.run_worker(
                    self._background_scan(), name="bg_scan", exclusive=False
                )

        except Exception as exc:
            logger.error("Error probing logs: %s", exc)
            output.clear()
            output.write(Text.assemble(("Error: ", "bold red"), (str(exc), "red")))
        finally:
            progress.stop()
            self._set_buttons_disabled(False)

    async def _background_scan(self) -> None:
        """Scan remote directories in the background to discover more log files."""
        try:
            discovered = await self.app.log_viewer_service.scan_log_directories(
                self._instance,
                self.app.ssh_service,
                self.app.connection_service,
            )
            self._discovered_logs = discovered
            self._scan_complete = True
        except Exception as e:
            logger.error("Background log scan failed: %s", e)

    def _on_log_picked(self, result: Optional[str]) -> None:
        """Handle the result from LogPickerModal."""
        if result is None:
            return

        if result == ADD_PATH_SENTINEL:
            self.app.push_screen(
                AddPathModal(),
                callback=self._on_custom_path_added,
            )
            return

        # Fetch the selected log
        self._fetch_log_file(result)

    def _on_custom_path_added(self, result: Optional[str]) -> None:
        """Handle the result from AddPathModal."""
        if not result:
            return
        if result not in self._available_logs:
            self._available_logs.append(result)
        self._fetch_log_file(result)

    def _fetch_log_file(self, log_path: str) -> None:
        """Fetch a specific log file from the server."""
        output = self.query_one("#ai_output", RichLog)
        output.clear()
        output.write(f"[dim]Fetching {log_path}...[/dim]")

        progress = self.query_one(ProgressIndicator)
        progress.start("Fetching log...")

        self._set_buttons_disabled(True)
        self.run_worker(
            self._do_fetch_log(log_path), name="fetch_log", exclusive=True
        )

    async def _do_fetch_log(self, log_path: str) -> None:
        """Worker to fetch a specific log file via SSH."""
        progress = self.query_one(ProgressIndicator)
        output = self.query_one("#ai_output", RichLog)
        text_area = self.query_one("#ai_text_input", TextArea)

        try:
            service = self.app.log_viewer_service
            conn = service._resolve_connection(
                self._instance,
                self.app.ssh_service,
                self.app.connection_service,
            )

            # Use get_read_command for compressed/rotated, tail for active
            classification = service.classify_log_file(log_path)
            if classification == "compressed":
                read_cmd = service.get_read_command(log_path) + " | tail -n 200"
            else:
                read_cmd = service.get_tail_command(
                    log_path, num_lines=200, follow=False
                )

            ssh_cmd = self.app.ssh_service.build_ssh_command(
                host=conn["host"],
                username=conn["username"],
                key_path=conn["key_path"],
                proxy_args=conn["proxy_args"],
                remote_command=read_cmd,
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
                # Clear any active filter before loading new text
                self._filter_pattern = ""
                text_area.read_only = False
                self.query_one("#ai_filter_input", Input).value = ""

                text_area.load_text(log_text)
                self._raw_text = log_text
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
                    output.write(
                        f"[yellow]No logs fetched.[/yellow]\n[dim]{err_text}[/dim]"
                    )
                else:
                    output.write(
                        "[yellow]Log file is empty or not readable.[/yellow]"
                    )

        except asyncio.TimeoutError:
            output.clear()
            output.write("[red]Timed out fetching logs from server.[/red]")
        except Exception as exc:
            logger.error("Error fetching log %s: %s", log_path, exc)
            output.clear()
            output.write(Text.assemble(("Error: ", "bold red"), (str(exc), "red")))
        finally:
            progress.stop()
            self._set_buttons_disabled(False)

    # --- Analysis ---

    def _run_analysis(self) -> None:
        text = self._get_input_text()
        if not text.strip():
            self.app.notify(
                "No text to analyze. Paste text or press 'Fetch Logs'.",
                severity="warning",
            )
            return

        # Read custom prompt if provided
        user_prompt = self.query_one("#ai_user_prompt", Input).value.strip()

        output = self.query_one("#ai_output", RichLog)
        output.clear()
        output.write("[dim]Analyzing...[/dim]")

        progress = self.query_one(ProgressIndicator)
        progress.start("Analyzing with AI...")

        self._set_buttons_disabled(True)
        self.run_worker(
            self._do_analysis(text, system_prompt=user_prompt),
            name="analyze",
            exclusive=True,
        )

    async def _do_analysis(self, text: str, system_prompt: str = "") -> None:
        progress = self.query_one(ProgressIndicator)
        output = self.query_one("#ai_output", RichLog)
        cost_info = self.query_one("#ai_cost_info", Static)

        try:
            result = await self.app.ai_analysis_service.analyze_text(
                text, system_prompt=system_prompt
            )
            output.clear()
            # Write as plain Text to prevent Rich from eating [ERROR],
            # [INFO], timestamps, etc. in the AI response.
            output.write(Text(result['content']))
            self._output_text = result['content']

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

    def action_copy_output(self) -> None:
        """Copy AI analysis output to the clipboard."""
        if self._output_text:
            self.app.copy_to_clipboard(self._output_text)
            self.notify("Copied to clipboard")
        else:
            self.notify("Nothing to copy", severity="warning")

    def action_back(self) -> None:
        self.app.pop_screen()
