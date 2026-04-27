"""Chat panel widget mounted as a sidebar on the active screen."""

from __future__ import annotations

import logging
import time
from typing import Dict, List, Optional, Tuple

from rich.markup import escape as _rich_escape

logger = logging.getLogger(__name__)
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.widget import Widget
from textual.widgets import Button, Input, Label, Static, TextArea


# Minimal AI Logo (Matches Website)
SERVONAUT_LOGO = (
    "[bold bright_cyan]🖧[/]  [bold]Servonaut AI Assistant[/]\n"
    "   [bold bright_green]●[/] [dim bright_green]MCP Server Online[/]"
)

# Inline bot marker for assistant messages
BOT_MARKER = "[bold bright_cyan]\u25c9[/]"


class ChatPanel(Widget):
    """Right-docked sidebar for chatting with the Servonaut DevOps assistant."""

    # Debounce: stale_modules results cached 2 seconds per (instance_id, provider) key.
    _STALE_CACHE_TTL = 2.0

    def __init__(self, **kwargs) -> None:
        super().__init__(id="chat-panel", **kwargs)
        self._session = None  # type: Optional[object]
        self._thinking = False
        self._total_tokens = 0
        self._total_cost = 0.0
        self._model = ""
        # Cache for stale module lookups: key → (timestamp, result)
        self._stale_cache: Dict[tuple, tuple] = {}

    def compose(self) -> ComposeResult:
        with Vertical(id="chat-inner"):
            # Header with logo and controls
            with Vertical(id="chat-header"):
                yield Static(SERVONAUT_LOGO, id="chat-logo")
                with Horizontal(id="chat-controls"):
                    yield Button("New Chat", id="btn-chat-new", classes="chat-btn")
                    yield Button("History", id="btn-chat-history", classes="chat-btn")
                    yield Button("Close", id="btn-chat-close", classes="chat-btn error")
            # Session history list (hidden by default)
            with VerticalScroll(id="chat-history-list", classes="hidden"):
                yield Static("[dim]No saved chats[/dim]", id="chat-history-empty")
            # Stale-memory banner (hidden until staleness detected)
            yield Static("", id="chat-memory-banner", classes="hidden")
            # Message area
            yield VerticalScroll(id="chat-messages")
            # Stats bar
            yield Static("", id="chat-stats")
            # Input row
            with Horizontal(id="chat-input-row"):
                yield TextArea("", id="chat-input", soft_wrap=True, tab_behavior="focus")
                yield Button("➤", id="btn-chat-send", variant="primary")

    def on_mount(self) -> None:
        """Load or create a chat session when mounted."""
        self._start_or_resume_session()
        self._update_stats()
        self._update_memory_banner()

    def focus_input(self) -> None:
        """Focus the chat input field."""
        self.call_after_refresh(self._do_focus_input)

    def _do_focus_input(self) -> None:
        try:
            self.query_one("#chat-input", TextArea).focus()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Focus failed on chat input", exc_info=True)
        self._update_memory_banner()

    # ------------------------------------------------------------------
    # Memory banner + instance resolution
    # ------------------------------------------------------------------

    def _parse_at_prefix(self, text: str) -> Tuple[Optional[dict], str]:
        """Extract an ``@<id-or-name>`` prefix from *text*.

        If the first whitespace-delimited token starts with ``@``, the token
        (without the ``@``) is looked up via ``self.app.resolve_instance``.
        The prefix is stripped from the returned text only when a match is
        found.

        Args:
            text: Raw input string from the chat input field.

        Returns:
            Tuple of (instance_dict_or_None, effective_text).
        """
        parts = text.split(None, 1)
        if not parts or not parts[0].startswith("@"):
            return None, text
        token = parts[0][1:]  # strip leading @
        rest = parts[1] if len(parts) > 1 else ""
        try:
            resolve = getattr(self.app, "resolve_instance", None)
            if resolve is not None:
                inst = resolve(token)
            else:
                # Fallback: linear scan of self.app.instances
                needle = token.lower()
                inst = next(
                    (
                        i for i in getattr(self.app, "instances", [])
                        if (
                            i.get("id", "").lower() == needle
                            or i.get("name", "").lower() == needle
                        )
                    ),
                    None,
                )
        except Exception:
            return None, text
        if inst is None:
            return None, text
        return inst, rest

    def _resolve_active_instance(self, text: str) -> Tuple[Optional[dict], str]:
        """Determine the active instance and strip any ``@`` prefix from text.

        Resolution order:
        1. ``@<token>`` prefix in *text* → ``_parse_at_prefix``.
        2. ``InstanceTable.get_selected_instance()`` on the current screen.

        Args:
            text: Raw input string.

        Returns:
            Tuple of (instance_dict_or_None, text_to_send).
        """
        inst, stripped = self._parse_at_prefix(text)
        if inst is not None:
            return inst, stripped

        # Fallback 1: selected row in the instance table
        try:
            from servonaut.widgets.instance_table import InstanceTable
            table = self.app.screen.query_one(InstanceTable)
            selected = table.get_selected_instance()
            if selected:
                return selected, text
        except Exception:
            pass

        # Fallback 2: screen's own _instance attribute (e.g. ServerActionsScreen)
        try:
            screen_instance = getattr(self.app.screen, "_instance", None)
            if screen_instance is not None:
                return screen_instance, text
        except Exception:
            pass

        return None, text

    def _update_memory_banner(self) -> None:
        """Show or hide the stale-memory banner based on the current instance."""
        try:
            banner = self.query_one("#chat-memory-banner", Static)
        except Exception:
            return

        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            banner.add_class("hidden")
            return

        # Resolve instance without consuming input text (use empty string for prefix check)
        inst, _ = self._resolve_active_instance("")
        if inst is None:
            banner.add_class("hidden")
            return

        instance_id = inst.get("id") or ""
        instance_name = inst.get("name") or ""
        provider = inst.get("provider") or "custom"

        try:
            config = self.app.config_manager.get()
            config_memory = getattr(config, "memory", None)
        except Exception:
            banner.add_class("hidden")
            return

        if config_memory is None or not config_memory.enabled:
            banner.add_class("hidden")
            return

        # Check by both id and name so name-based overrides fire correctly.
        if config_memory.is_instance_disabled(instance_id, instance_name):
            banner.add_class("hidden")
            return

        # Detect the "no memory yet" case first — this is the user's most
        # common trip-up: they ask a question about a server the agent has
        # never probed, and the chat answers blind.  Offer a one-click build.
        try:
            stored_modules = memory_service.get_all_modules(instance_id, provider)
        except Exception:
            stored_modules = {}
        if not stored_modules:
            banner.update(
                f"[cyan]🧠 No memory yet for[/cyan] "
                f"[bold]{_rich_escape(instance_id)}[/bold]. "
                f"Build one and I can answer instantly without SSH round-trips. "
                f"[@click=action_build_memory]Build now[/@click]"
            )
            banner.remove_class("hidden")
            return

        cache_key = (instance_id, provider)
        now = time.monotonic()
        cached = self._stale_cache.get(cache_key)
        if cached is not None and (now - cached[0]) < self._STALE_CACHE_TTL:
            stale = cached[1]
        else:
            try:
                stale = memory_service.stale_modules(instance_id, provider)
            except Exception:
                banner.add_class("hidden")
                return
            self._stale_cache[cache_key] = (now, stale)

        if not stale:
            banner.add_class("hidden")
            return

        module_list = ", ".join(_rich_escape(m) for m in stale)
        banner.update(
            f"[yellow]Memory is stale for[/yellow] [bold]{_rich_escape(instance_id)}[/bold] "
            f"(modules: {module_list}). "
            f"[@click=action_refresh_memory]Refresh[/@click]"
        )
        banner.remove_class("hidden")

    def action_refresh_memory(self) -> None:
        """Refresh stale memory for the currently active instance."""
        inst, _ = self._resolve_active_instance("")
        if inst is None:
            self.app.notify("No active instance selected.", severity="warning")
            return
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            return
        self.run_worker(
            memory_service.refresh(inst),
            name="chat_memory_refresh",
        )

    def action_build_memory(self) -> None:
        """Build memory from scratch for the current instance.

        Triggered from the "No memory yet" banner.  Shares the refresh
        worker group so only one memory probe per chat session runs at a
        time, and clears the stale cache on completion so the banner
        updates to green without waiting for the next render tick.
        """
        inst, _ = self._resolve_active_instance("")
        if inst is None:
            self.app.notify("No active instance selected.", severity="warning")
            return
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            return
        name = inst.get("name") or inst.get("id") or "server"
        self.app.notify(f"🧠 Building memory for {name}…")

        async def _build_then_refresh() -> None:
            try:
                if hasattr(memory_service, "build_report"):
                    report = await memory_service.build_report(inst)
                    if report.has_any_success:
                        self.app.notify(
                            f"Memory built for {name}: {report.count} modules."
                        )
                    else:
                        self.app.notify(
                            f"Memory build failed for {name} "
                            f"({report.overall_reason or 'unknown'}). "
                            "Check SSH connectivity.",
                            severity="warning",
                        )
                else:
                    await memory_service.refresh(inst)
                    self.app.notify(f"Memory built for {name}.")
            except Exception as exc:  # noqa: BLE001
                self.app.notify(
                    f"Memory build failed for {name}: {exc}",
                    severity="error",
                )
            finally:
                self._stale_cache.clear()
                self._update_memory_banner()

        self.run_worker(
            _build_then_refresh(),
            name="chat_memory_build",
            group="memory_refresh",
        )

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
                    f"[bold]You[/bold]\n{msg.content}",
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
        elif button_id == "btn-chat-history":
            self._toggle_history()
        elif button_id == "btn-chat-send":
            self._send()
        elif button_id == "btn-chat-close":
            self.remove()
        elif button_id and button_id.startswith("btn-session-"):
            session_id = button_id.removeprefix("btn-session-")
            self._load_session(session_id)
        elif button_id and button_id.startswith("btn-del-session-"):
            session_id = button_id.removeprefix("btn-del-session-")
            self._delete_session(session_id)
        event.stop()

    def on_key(self, event) -> None:
        """Enter sends message, Shift+Enter inserts newline."""
        if event.key == "enter":
            focused = self.app.focused
            if focused is not None and getattr(focused, "id", None) == "chat-input":
                event.prevent_default()
                self._send()

    def _toggle_history(self) -> None:
        """Show or hide the session history list."""
        history_panel = self.query_one("#chat-history-list", VerticalScroll)
        if history_panel.has_class("hidden"):
            self._populate_history()
            history_panel.remove_class("hidden")
        else:
            history_panel.add_class("hidden")

    def _populate_history(self) -> None:
        """Populate the history list with saved sessions."""
        chat_service = self._get_chat_service()
        if chat_service is None:
            return

        history_panel = self.query_one("#chat-history-list", VerticalScroll)
        history_panel.remove_children()

        sessions = chat_service.list_sessions()
        if not sessions:
            history_panel.mount(Static("[dim]No saved chats[/dim]", id="chat-history-empty"))
            return

        for s in sessions:
            title = s["title"]
            session_id = s["id"]
            is_current = self._session is not None and self._session.id == session_id
            marker = "[bold cyan]▸[/bold cyan] " if is_current else "  "

            # Parse date for display
            updated = s.get("updated_at", "")
            date_str = ""
            if updated:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(updated)
                    date_str = dt.strftime("%b %d %H:%M")
                except (ValueError, TypeError):
                    pass

            row = Horizontal(classes="chat-history-item")
            load_btn = Button(
                f"{marker}{title[:30]}{'…' if len(title) > 30 else ''} [dim]{date_str}[/dim]",
                id=f"btn-session-{session_id}",
                classes="chat-history-btn",
            )
            del_btn = Button(
                "✕",
                id=f"btn-del-session-{session_id}",
                variant="error",
                classes="chat-history-del",
            )
            history_panel.mount(row)
            row.mount(load_btn)
            row.mount(del_btn)

    def _load_session(self, session_id: str) -> None:
        """Load a session by ID and switch to it."""
        chat_service = self._get_chat_service()
        if chat_service is None:
            return
        session = chat_service.load_session(session_id)
        if session is None:
            self.app.notify("Session not found", severity="error")
            return
        self._session = session
        self._total_tokens = 0
        self._total_cost = 0.0
        self._refresh_messages()
        self._update_stats()
        # Hide history panel after selection
        self.query_one("#chat-history-list", VerticalScroll).add_class("hidden")
        self._do_focus_input()

    def _delete_session(self, session_id: str) -> None:
        """Delete a session and refresh the history list."""
        chat_service = self._get_chat_service()
        if chat_service is None:
            return

        # If deleting the current session, create a new one
        is_current = self._session is not None and self._session.id == session_id
        chat_service.delete_session(session_id)

        if is_current:
            self._session = chat_service.create_session()
            self._total_tokens = 0
            self._total_cost = 0.0
            self._refresh_messages()
            self._update_stats()

        # Refresh the history list
        self._populate_history()

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
        self.query_one("#chat-history-list", VerticalScroll).add_class("hidden")
        self._do_focus_input()

    def _send(self) -> None:
        """Read the input field and dispatch the message as a worker."""
        if self._thinking:
            return
        try:
            inp = self.query_one("#chat-input", TextArea)
        except Exception:
            return

        text = inp.text.strip()
        if not text:
            return

        inp.load_text("")
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

            # Resolve active instance and strip any @prefix from the text.
            inst, effective_text = self._resolve_active_instance(text)
            instance_id = inst.get("id") if inst else None
            instance_name = inst.get("name") if inst else None
            instance_provider = (inst.get("provider") or "custom") if inst else "custom"

            result = await chat_service.send_message(
                self._session,
                effective_text,
                status_callback=self._update_thinking_status,
                instance_id=instance_id,
                instance_name=instance_name,
                instance_provider=instance_provider,
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
