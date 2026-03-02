"""Chat panel widget mounted as a sidebar on the active screen."""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.widget import Widget
from textual.widgets import Button, Input, Label, Static


# Braille art — clean space helmet with two eyes
SERVONAUT_LOGO = "[bold cyan]" + "\n".join([
    "⠀⠀⠀⠀⠀⣀⣤⣴⣶⣶⣶⣶⣦⣤⣀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀",
    "⠀⠀⣰⣿⣿⠿⠛⠛⠛⠛⠛⠛⠛⠛⠿⣿⣿⣆⠀⠀",
    "⠀⢠⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⡄⠀",
    "⠀⣾⣿⠁⠀⠀⣠⣤⡄⠀⠀⢠⣤⣄⠀⠀⠈⣿⣷⠀",
    "⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⠀⢸⣿⣿⠀⠀⠀⣿⣿⠀",
    "⠀⢿⣿⡀⠀⠀⠈⠉⠀⠀⠀⠀⠉⠁⠀⠀⢀⣿⡿⠀",
    "⠀⠘⣿⣧⠀⠀⠀⠀⢀⣤⣤⡀⠀⠀⠀⠀⣼⣿⠃⠀",
    "⠀⠀⠹⣿⣦⡀⠀⠀⠈⠛⠛⠁⠀⠀⢀⣴⣿⠏⠀⠀",
    "⠀⠀⠀⠙⢿⣿⣶⣤⣀⣀⣀⣀⣤⣶⣿⡿⠋⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠉⠛⠿⣿⣿⣿⣿⠿⠛⠉⠀⠀⠀⠀⠀",
]) + (
    "\n[bold bright_cyan]   S E R V O N A U T\n"
    "[dim cyan]   DevOps AI Assistant[/]"
)

# Inline bot marker for assistant messages
BOT_MARKER = "[bold bright_cyan]\u25c9[/]"


class ChatPanel(Widget):
    """Right-docked sidebar for chatting with the Servonaut DevOps assistant."""

    def __init__(self, **kwargs) -> None:
        super().__init__(id="chat-panel", **kwargs)
        self._session = None  # type: Optional[object]
        self._thinking = False
        self._total_tokens = 0
        self._total_cost = 0.0
        self._model = ""

    def compose(self) -> ComposeResult:
        with Vertical(id="chat-inner"):
            # Header with logo and controls
            with Vertical(id="chat-header"):
                yield Static(SERVONAUT_LOGO, id="chat-logo")
                with Horizontal(id="chat-controls"):
                    yield Button("+ New Chat", id="btn-chat-new", variant="primary")
                    yield Button("Close", id="btn-chat-close", variant="default")
            # Message area
            yield VerticalScroll(id="chat-messages")
            # Stats bar
            yield Static("", id="chat-stats")
            # Input row
            with Horizontal(id="chat-input-row"):
                yield Input(placeholder="Ask anything DevOps...", id="chat-input")
                yield Button("\u25b6", id="btn-chat-send", variant="success")

    def on_mount(self) -> None:
        """Load or create a chat session when mounted."""
        self._start_or_resume_session()
        self._update_stats()

    def focus_input(self) -> None:
        """Focus the chat input field."""
        self.call_after_refresh(self._do_focus_input)

    def _do_focus_input(self) -> None:
        try:
            self.query_one("#chat-input", Input).focus()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Welcome & stats
    # ------------------------------------------------------------------

    def _show_welcome(self) -> None:
        """Show a welcome message if the session is empty."""
        if self._session is None or len(self._session.messages) > 0:  # type: ignore[union-attr]
            return
        container = self.query_one("#chat-messages", VerticalScroll)
        welcome = Static(
            f"{BOT_MARKER} [bold]Servonaut[/bold]\n\n"
            "Hello! I'm your DevOps assistant. I can help with:\n\n"
            "[dim]\u2022[/dim] Server management & SSH issues\n"
            "[dim]\u2022[/dim] AWS operations & troubleshooting\n"
            "[dim]\u2022[/dim] Log analysis & debugging\n"
            "[dim]\u2022[/dim] Networking & security questions\n"
            "[dim]\u2022[/dim] CI/CD pipelines & containerization\n\n"
            "I can also [bold]interact with your servers directly[/bold] \u2014\n"
            "list instances, check status, run commands, and view logs.\n\n"
            "[dim italic]Type a message below to get started.[/dim italic]",
            classes="chat-message-assistant chat-welcome",
        )
        container.mount(welcome)

    def _update_stats(self) -> None:
        """Update the token/cost stats bar."""
        try:
            stats_widget = self.query_one("#chat-stats", Static)
        except Exception:
            return

        if self._model:
            parts = [f"[dim]Model:[/dim] [bold]{self._model}[/bold]"]
        else:
            parts = [f"[dim]Model:[/dim] [dim italic]not configured[/dim italic]"]

        if self._total_tokens > 0:
            parts.append(f"[dim]Tokens:[/dim] {self._total_tokens:,}")
        if self._total_cost > 0:
            parts.append(f"[dim]Cost:[/dim] ${self._total_cost:.4f}")

        msg_count = 0
        if self._session is not None:
            msg_count = len(self._session.messages)  # type: ignore[union-attr]
        parts.append(f"[dim]Messages:[/dim] {msg_count}")

        stats_widget.update("  \u2502  ".join(parts))

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def _get_chat_service(self):
        """Get the chat service, returning None if unavailable."""
        try:
            svc = self.app.chat_service  # type: ignore[attr-defined]
        except AttributeError:
            return None
        return svc

    def _start_or_resume_session(self) -> None:
        """Load the most recent session or create a fresh one."""
        chat_service = self._get_chat_service()
        if chat_service is None:
            return

        sessions = chat_service.list_sessions()
        if sessions:
            self._session = chat_service.load_session(sessions[0]["id"])
        if self._session is None:
            self._session = chat_service.create_session()

        self._refresh_messages()

    def _refresh_messages(self) -> None:
        """Rebuild the message display from the current session."""
        container = self.query_one("#chat-messages", VerticalScroll)
        container.remove_children()

        if self._session is None:
            return

        messages = self._session.messages  # type: ignore[union-attr]
        if not messages:
            self._show_welcome()
            return

        for msg in messages:
            if msg.role == "user":
                widget = Static(
                    f"[bold yellow]\u25b6[/bold yellow] [bold]You[/bold]\n{msg.content}",
                    classes="chat-message-user",
                )
            else:
                widget = Static(
                    f"{BOT_MARKER} [bold]Servonaut[/bold]\n{msg.content}",
                    classes="chat-message-assistant",
                )
            container.mount(widget)

        self.call_after_refresh(self._scroll_to_bottom)
        self._update_stats()

    def _scroll_to_bottom(self) -> None:
        try:
            container = self.query_one("#chat-messages", VerticalScroll)
            container.scroll_end(animate=False)
        except Exception:
            pass

    def _show_thinking(self, text: str = "Servonaut is thinking...") -> None:
        """Add an animated thinking indicator with customisable text."""
        container = self.query_one("#chat-messages", VerticalScroll)
        widget = Static(
            f"{BOT_MARKER} [dim italic]{text}[/dim italic]",
            id="chat-thinking",
            classes="chat-message-assistant chat-thinking",
        )
        container.mount(widget)
        self.call_after_refresh(self._scroll_to_bottom)

    def _update_thinking_status(self, text: str) -> None:
        """Update the thinking indicator text (called from worker thread)."""
        try:
            widget = self.query_one("#chat-thinking", Static)
            widget.update(f"{BOT_MARKER} [dim italic]{text}[/dim italic]")
        except Exception:
            pass

    def _hide_thinking(self) -> None:
        """Remove the thinking indicator."""
        try:
            self.query_one("#chat-thinking", Static).remove()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn-chat-new":
            self._new_chat()
        elif button_id == "btn-chat-send":
            self._send()
        elif button_id == "btn-chat-close":
            self.remove()
        event.stop()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "chat-input":
            self._send()

    def _new_chat(self) -> None:
        """Create a new session and clear the display."""
        chat_service = self._get_chat_service()
        if chat_service is None:
            return
        self._session = chat_service.create_session()
        self._total_tokens = 0
        self._total_cost = 0.0
        self._refresh_messages()
        self._update_stats()
        self._do_focus_input()

    def _send(self) -> None:
        """Read the input field and dispatch the message as a worker."""
        if self._thinking:
            return
        try:
            inp = self.query_one("#chat-input", Input)
        except Exception:
            return

        text = inp.value.strip()
        if not text:
            return

        inp.value = ""
        self._thinking = True
        self._show_thinking()

        self.run_worker(self._do_send(text), exclusive=False)

    async def _do_send(self, text: str) -> None:
        """Worker: send message to AI and refresh display."""
        try:
            chat_service = self._get_chat_service()
            if chat_service is None:
                return
            if self._session is None:
                self._session = chat_service.create_session()

            result = await chat_service.send_message(
                self._session, text, status_callback=self._update_thinking_status
            )
            self._total_tokens += result.get("tokens_used", 0)
            cost = result.get("estimated_cost")
            if cost is not None:
                self._total_cost += cost
            self._model = result.get("model", "") or self._model
        except Exception as exc:
            from servonaut.services.chat_service import ChatMessage
            if self._session is not None:
                self._session.messages.append(  # type: ignore[union-attr]
                    ChatMessage(role="assistant", content=f"Error: {exc}")
                )
        finally:
            self._hide_thinking()
            self._thinking = False
            self._refresh_messages()
