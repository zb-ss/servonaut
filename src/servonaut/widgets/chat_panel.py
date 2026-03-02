"""Chat panel widget for AI conversations."""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Button, Input, Label, Select, Static


class ChatPanel(Widget):
    """Sliding side panel for chatting with the Servonaut DevOps assistant."""

    DEFAULT_CSS = ""
    _is_visible: reactive[bool] = reactive(False)

    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(id="chat-panel", **kwargs)
        self._session = None  # type: Optional[object]
        self._thinking = False

    def compose(self) -> ComposeResult:
        with Vertical(id="chat-inner"):
            with Horizontal(id="chat-header"):
                yield Label("[bold]Servonaut Chat[/bold]", id="chat-title")
                yield Button("New", id="btn-chat-new", variant="primary")
            yield VerticalScroll(id="chat-messages")
            with Horizontal(id="chat-input-row"):
                yield Input(placeholder="Ask anything DevOps...", id="chat-input")
                yield Button("Send", id="btn-chat-send", variant="success")

    def on_mount(self) -> None:
        """Start or resume a chat session on first mount."""
        self._start_or_resume_session()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def toggle(self) -> None:
        """Show or hide the panel by toggling the --visible CSS class."""
        if self.has_class("--visible"):
            self.remove_class("--visible")
            self._is_visible = False
        else:
            self.add_class("--visible")
            self._is_visible = True
            # Focus input when opening
            try:
                self.query_one("#chat-input", Input).focus()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def _start_or_resume_session(self) -> None:
        """Load the most recent session or create a fresh one."""
        try:
            chat_service = self.app.chat_service  # type: ignore[attr-defined]
        except AttributeError:
            return

        sessions = chat_service.list_sessions()
        if sessions:
            self._session = chat_service.load_session(sessions[0]["id"])
        if self._session is None:
            self._session = chat_service.create_session()

        self._refresh_messages()

    def _load_session(self, session_id: str) -> None:
        """Switch to a different chat session."""
        try:
            chat_service = self.app.chat_service  # type: ignore[attr-defined]
        except AttributeError:
            return

        session = chat_service.load_session(session_id)
        if session is not None:
            self._session = session
            self._refresh_messages()

    def _refresh_messages(self) -> None:
        """Rebuild the message display from the current session."""
        container = self.query_one("#chat-messages", VerticalScroll)
        container.remove_children()

        if self._session is None:
            return

        for msg in self._session.messages:  # type: ignore[union-attr]
            css_class = (
                "chat-message-user" if msg.role == "user" else "chat-message-assistant"
            )
            role_label = "You" if msg.role == "user" else "Servonaut"
            widget = Static(
                f"[bold]{role_label}[/bold]\n{msg.content}",
                classes=css_class,
            )
            container.mount(widget)

        # Scroll to bottom after rendering
        self.call_after_refresh(self._scroll_to_bottom)

    def _scroll_to_bottom(self) -> None:
        try:
            container = self.query_one("#chat-messages", VerticalScroll)
            container.scroll_end(animate=False)
        except Exception:
            pass

    def _show_thinking(self) -> None:
        """Add a temporary 'Thinking...' indicator."""
        container = self.query_one("#chat-messages", VerticalScroll)
        widget = Static(
            "[dim italic]Servonaut is thinking...[/dim italic]",
            id="chat-thinking",
            classes="chat-message-assistant",
        )
        container.mount(widget)
        self.call_after_refresh(self._scroll_to_bottom)

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
        event.stop()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "chat-input":
            self._send()

    def _new_chat(self) -> None:
        """Create a new session and clear the display."""
        try:
            chat_service = self.app.chat_service  # type: ignore[attr-defined]
        except AttributeError:
            return
        self._session = chat_service.create_session()
        self._refresh_messages()
        try:
            self.query_one("#chat-input", Input).focus()
        except Exception:
            pass

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
            chat_service = self.app.chat_service  # type: ignore[attr-defined]
            if self._session is None:
                self._session = chat_service.create_session()
            await chat_service.send_message(self._session, text)
        except Exception as exc:
            # Append an error message to the session display without saving
            from servonaut.services.chat_service import ChatMessage
            if self._session is not None:
                self._session.messages.append(  # type: ignore[union-attr]
                    ChatMessage(role="assistant", content=f"Error: {exc}")
                )
        finally:
            self._hide_thinking()
            self._thinking = False
            self._refresh_messages()
