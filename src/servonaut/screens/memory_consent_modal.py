"""First-run consent modal for chat memory injection.

Surfaces the privacy trade-off the moment it would actually fire: a chat
turn is about to send locally-probed server data (OS, services, configs,
log paths, runtimes, …) to ``api.servonaut.dev/api/ai/chat`` over TLS.
The server forwards plaintext to the active LLM provider for inference.

This is a step DOWN from Memory Sync (E2E encrypted, server can never
read) so the consent decision is captured separately and persisted to
``config.chat_inject_server_memory_decision``.

Per the project ModalScreen convention: a brief blocking choice ("allow this or
not") lives in a Modal.  The "show me what'll be sent" affordance opens
a non-blocking detail panel.
"""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class MemoryInjectionConsentModal(ModalScreen[Optional[str]]):
    """Capture explicit user consent for memory injection.

    Returns via ``dismiss``:
      - ``"allowed"`` — user pressed Allow; caller persists
        ``decision="allowed"`` and proceeds with injection.
      - ``"denied"``  — user pressed Deny; caller persists
        ``decision="denied"`` and skips injection (this turn AND all
        future turns until the user re-enables in Settings).
      - ``None``      — user pressed Escape / dismissed without
        choosing; caller does NOT persist a decision and skips
        injection for this turn only.  The modal will fire again next
        time an in-scope instance is detected.
    """

    BINDINGS = [
        Binding("escape", "dismiss_none", "Decide later", show=True),
    ]

    DEFAULT_CSS = """
    MemoryInjectionConsentModal {
        align: center middle;
    }

    MemoryInjectionConsentModal #consent_container {
        width: 86;
        height: auto;
        max-height: 40;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }

    MemoryInjectionConsentModal #consent_title {
        height: auto;
        text-style: bold;
        color: $accent;
        text-align: center;
        margin-bottom: 1;
    }

    MemoryInjectionConsentModal #consent_body {
        height: auto;
        max-height: 22;
        margin-bottom: 1;
    }

    MemoryInjectionConsentModal .consent_para {
        height: auto;
        margin-bottom: 1;
    }

    MemoryInjectionConsentModal #consent_buttons {
        height: auto;
        align-horizontal: center;
        margin-top: 1;
    }

    MemoryInjectionConsentModal Button {
        margin: 0 1;
        min-width: 14;
    }

    MemoryInjectionConsentModal #btn_allow {
        background: $primary;
        color: $text;
    }

    MemoryInjectionConsentModal #btn_deny {
        background: $surface-darken-2;
    }

    MemoryInjectionConsentModal #btn_details {
        background: $boost;
    }

    MemoryInjectionConsentModal #consent_details {
        display: none;
        height: auto;
        max-height: 16;
        border-top: solid $primary 30%;
        padding-top: 1;
        margin-top: 1;
        color: $text-muted;
    }

    MemoryInjectionConsentModal #consent_details.shown {
        display: block;
    }
    """

    def compose(self) -> ComposeResult:
        with Container(id="consent_container"):
            yield Static(
                "Send local server memory to Servonaut AI?",
                id="consent_title",
            )
            with VerticalScroll(id="consent_body"):
                yield Static(
                    "Servonaut can pre-fill every chat turn with a "
                    "snapshot of what your CLI has probed locally about "
                    "the server in scope (OS, runtimes, services, web "
                    "stack, log paths, etc.). The model uses this as "
                    "context so it can answer "
                    '"what services are running on srv-X?" instantly '
                    "instead of running SSH commands on every turn.",
                    classes="consent_para",
                )
                yield Static(
                    "[bold]What this means in practice:[/bold]\n"
                    "  • Memory is sent over TLS to api.servonaut.dev "
                    "as part of the chat request.\n"
                    "  • The server forwards plaintext to the active "
                    "LLM provider (Anthropic / OpenAI / Gemini / Ollama "
                    "Cloud) for inference.\n"
                    "  • Memory Sync (E2E encrypted) is a separate, "
                    "stricter pipe — declining this does NOT affect "
                    "Memory Sync.\n"
                    "  • You can change this later in Settings → AI "
                    "Provider, or run [bold]servonaut memory purge "
                    "--all[/bold] to wipe everything that was probed.",
                    classes="consent_para",
                )
                yield Static(
                    "[dim]Press Esc to decide later — we won't ask "
                    "again on THIS turn but the prompt will fire again "
                    "next time an in-scope server is detected.[/dim]",
                    classes="consent_para",
                )
                yield Static(
                    "",
                    id="consent_details",
                )
            with Horizontal(id="consent_buttons"):
                yield Button("Allow", id="btn_allow", variant="primary")
                yield Button("Deny",  id="btn_deny",  variant="default")
                yield Button("What's sent?", id="btn_details", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_allow":
            self.dismiss("allowed")
        elif event.button.id == "btn_deny":
            self.dismiss("denied")
        elif event.button.id == "btn_details":
            self._toggle_details()

    def action_dismiss_none(self) -> None:
        self.dismiss(None)

    def _toggle_details(self) -> None:
        details = self.query_one("#consent_details", Static)
        details.update(
            "Example payload (one block per in-scope server):\n"
            "<CONTEXT name=\"server_memory:srv-a\" "
            "snapshot_at=\"2026-05-07T...\">\n"
            "{\n"
            "  \"os\":       {\"observed\": {\"distro\": \"Ubuntu\", "
            "\"version\": \"24.04\"}},\n"
            "  \"services\": {\"observed\": {\"running\": [\"nginx\", "
            "\"sshd\", ...]}},\n"
            "  \"runtimes\": {\"observed\": {\"python3\": \"3.12\"}},\n"
            "  \"web_stack\":{\"observed\": {\"server\": \"nginx 1.26\"}},\n"
            "  \"network\": {\"observed\": {\"listen\": [\"0.0.0.0:443\"]}}\n"
            "}\n"
            "</CONTEXT>\n\n"
            "Secrets are scrubbed by the local redactor before send "
            "(SSH keys, AWS access keys, JWTs, DB connection strings, "
            "bearer tokens — see services/memory/redaction.py)."
        )
        details.add_class("shown")
