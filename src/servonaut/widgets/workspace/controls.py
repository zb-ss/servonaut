"""Permanent controls outside the panes they open and close."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.css.query import NoMatches
from textual.widgets import Button, Static

from servonaut.widgets.link_button import LinkButton
from servonaut.widgets.sidebar import Sidebar


class WorkspaceControls(Horizontal):
    """Mouse access to the same workspace actions exposed by keyboard."""

    def __init__(self, context: str) -> None:
        super().__init__()
        self._workspace_context = context

    def compose(self) -> ComposeResult:
        navigation = LinkButton("Hide navigation", id="workspace_navigation")
        navigation.can_focus = False
        yield navigation
        yield Static(self._workspace_context, id="workspace_context", markup=False)
        chat = LinkButton("Open chat", id="workspace_chat")
        chat.can_focus = False
        yield chat
        end = LinkButton("End chat", id="workspace_chat_end", tooltip="End chat and stop its reply · F3")
        end.can_focus = False
        end.disabled = True
        yield end

    def on_mount(self) -> None:
        self.sync_state()

    def set_context(self, context: str) -> None:
        """Refresh the literal screen context without replacing its controls."""
        self._workspace_context = context
        self.sync_state()

    def sync_state(self) -> None:
        """Read actual panes; collapse and explicit End have separate actions."""
        if not self.is_attached:
            return
        try:
            sidebar = self.screen.query_one(Sidebar)
            navigation = self.query_one("#workspace_navigation", Button)
            chat = self.query_one("#workspace_chat", Button)
            end = self.query_one("#workspace_chat_end", Button)
            context = self.query_one("#workspace_context", Static)
        except NoMatches:
            return  # A sibling may still be mounting, or children are leaving.
        navigation_action = "Hide navigation" if sidebar.display else "Show navigation"
        if navigation.label.plain != navigation_action:
            navigation.label = navigation_action
        navigation.set_class(sidebar.display, "--pane-open")
        navigation.tooltip = f"{navigation_action} · Shift+F6 to focus"
        panel = next(iter(self.screen.query("#chat-panel")), None)
        chat_open = panel is not None and not panel._collapsed
        chat_action = (
            ("Collapse chat" if chat_open else "Restore chat") if panel else "Open chat"
        )
        if chat.label.plain != chat_action:
            chat.label = chat_action
        chat.set_class(chat_open, "--pane-open")
        chat.tooltip = f"{chat_action} · F2 / Ctrl+G"
        end.disabled = panel is None
        end.styles.visibility = "visible" if panel is not None else "hidden"
        context.update(self._workspace_context + (
            " · Chat replying…" if panel is not None and panel._thinking else ""
        ))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "workspace_navigation":
            self.app.action_toggle_navigation()
        elif event.button.id == "workspace_chat":
            self.app.action_toggle_chat()
        elif event.button.id == "workspace_chat_end":
            self.app.action_end_chat()
