"""AI Chat settings panel.

Exposes chat-specific tunables: chunk size for log analysis, per-module
system prompts (multiline), conversation history depth, agentic loop
limits, guard level, and the server-memory injection toggle (which also
promotes the tri-state consent decision).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Input, Select, Static, Switch, TextArea

from servonaut.screens.settings.base import SettingsPanel, ValidationError

logger = logging.getLogger(__name__)

# Guard-level options — readonly < standard < dangerous.
_GUARD_OPTIONS = [
    ("Read-only", "readonly"),
    ("Standard", "standard"),
    ("Dangerous", "dangerous"),
]

# Human-readable summary shown near the dangerous guard warning.
_DANGEROUS_WARNING = (
    "Warning: 'dangerous' allows destructive tool calls from the chat panel."
)


class AiChatPanel(SettingsPanel):
    """Settings panel for AI chat behaviour and tunables.

    Fields covered
    --------------
    - ai_chunk_size              — int, log chunk size sent to AI analysis
    - ai_system_prompt           — str (multiline), system prompt for log analysis
    - chat_max_history_messages  — int, conversation history depth
    - chat_system_prompt         — str (multiline), system prompt for chat turns
    - chat_max_tool_iterations   — int, max agentic tool calls per turn (local)
    - chat_max_tool_rounds       — Optional[int], max tool rounds for hosted AI
    - chat_tool_guard_level      — select: readonly / standard / dangerous
    - chat_keep_tool_results     — bool switch
    - chat_inject_server_memory  — bool switch; also promotes
                                   chat_inject_server_memory_decision
    """

    PANEL_ID = "ai_chat"
    TITLE = "AI Chat"

    DEFAULT_CSS = """
    AiChatPanel .ai-chat-section-header {
        margin: 1 0 0 0;
        text-style: bold;
        color: $accent;
    }
    AiChatPanel .ai-chat-help {
        color: $text-muted;
        height: auto;
        padding: 0 0 0 1;
    }
    AiChatPanel .ai-chat-warning {
        color: $warning;
        height: auto;
        padding: 0 0 0 1;
    }
    AiChatPanel TextArea {
        height: 8;
        width: 1fr;
        border: round $primary;
        margin: 0 0 1 0;
    }
    """

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def form_rows(self) -> ComposeResult:
        """Yield all AI chat form rows."""
        # --- Log analysis section ---
        yield Static("Log Analysis", classes="ai-chat-section-header")
        yield Horizontal(
            Static("Log chunk size (chars)", classes="label"),
            Input(placeholder="100000", id="ai_chat_chunk_size"),
            classes="setting_row",
        )
        yield Static(
            "System prompt for log analysis mode:",
            classes="ai-chat-help",
        )
        yield TextArea(id="ai_chat_system_prompt", language=None)

        # --- Chat behaviour section ---
        yield Static("Chat Behaviour", classes="ai-chat-section-header")
        yield Horizontal(
            Static("Max history messages", classes="label"),
            Input(placeholder="20", id="ai_chat_max_history_messages"),
            classes="setting_row",
        )
        yield Static(
            "System prompt prepended to each chat turn (leave blank for default):",
            classes="ai-chat-help",
        )
        yield TextArea(id="ai_chat_chat_system_prompt", language=None)

        # --- Agentic loop limits ---
        yield Static("Agentic Loop Limits", classes="ai-chat-section-header")
        yield Horizontal(
            Static("Max tool iterations (local AI)", classes="label"),
            Input(placeholder="10", id="ai_chat_max_tool_iterations"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Max tool rounds (hosted AI, blank=server default)", classes="label"),
            Input(placeholder="", id="ai_chat_max_tool_rounds"),
            classes="setting_row",
        )

        # --- Guard level ---
        yield Static("Tool Guard Level", classes="ai-chat-section-header")
        yield Horizontal(
            Static("Chat tool guard level", classes="label"),
            Select(
                _GUARD_OPTIONS,
                value="standard",
                allow_blank=False,
                id="ai_chat_tool_guard_level",
            ),
            classes="setting_row",
        )
        yield Static("", id="ai_chat_guard_warning", classes="ai-chat-warning")

        # --- Memory and result switches ---
        yield Static("Context & History", classes="ai-chat-section-header")
        yield Horizontal(
            Static("Keep tool results in chat history", classes="label"),
            Switch(value=True, id="ai_chat_keep_tool_results"),
            classes="setting_row",
        )
        yield Static(
            "When off, tool results are dropped on save and won't appear on reload.",
            classes="ai-chat-help",
        )
        yield Horizontal(
            Static("Inject server memory into chats", classes="label"),
            Switch(value=False, id="ai_chat_inject_server_memory"),
            classes="setting_row",
        )
        yield Static(
            "Pre-flights a <CONTEXT> block of local server memory on each turn. "
            "Disable for compliance scenarios where memory must not leave the local store. "
            "Toggling this also sets the memory-inject consent decision.",
            classes="ai-chat-help",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()

        self.query_one("#ai_chat_chunk_size", Input).value = str(
            config.ai_chunk_size
        )
        self.query_one("#ai_chat_system_prompt", TextArea).load_text(
            config.ai_system_prompt
        )
        self.query_one("#ai_chat_max_history_messages", Input).value = str(
            config.chat_max_history_messages
        )
        self.query_one("#ai_chat_chat_system_prompt", TextArea).load_text(
            config.chat_system_prompt or ""
        )
        self.query_one("#ai_chat_max_tool_iterations", Input).value = str(
            config.chat_max_tool_iterations
        )
        rounds_val = config.chat_max_tool_rounds
        self.query_one("#ai_chat_max_tool_rounds", Input).value = (
            str(rounds_val) if rounds_val is not None else ""
        )

        guard = config.chat_tool_guard_level
        if guard not in ("readonly", "standard", "dangerous"):
            guard = "standard"
        self.query_one("#ai_chat_tool_guard_level", Select).value = guard

        self.query_one("#ai_chat_keep_tool_results", Switch).value = bool(
            config.chat_keep_tool_results
        )
        self.query_one("#ai_chat_inject_server_memory", Switch).value = bool(
            config.chat_inject_server_memory
        )

        self._refresh_guard_warning(guard)
        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        return {
            "ai_chunk_size": self.query_one("#ai_chat_chunk_size", Input).value.strip(),
            "ai_system_prompt": self.query_one("#ai_chat_system_prompt", TextArea).text,
            "chat_max_history_messages": self.query_one(
                "#ai_chat_max_history_messages", Input
            ).value.strip(),
            "chat_system_prompt": self.query_one(
                "#ai_chat_chat_system_prompt", TextArea
            ).text,
            "chat_max_tool_iterations": self.query_one(
                "#ai_chat_max_tool_iterations", Input
            ).value.strip(),
            "chat_max_tool_rounds": self.query_one(
                "#ai_chat_max_tool_rounds", Input
            ).value.strip(),
            "chat_tool_guard_level": str(
                self.query_one("#ai_chat_tool_guard_level", Select).value
            ),
            "chat_keep_tool_results": self.query_one(
                "#ai_chat_keep_tool_results", Switch
            ).value,
            "chat_inject_server_memory": self.query_one(
                "#ai_chat_inject_server_memory", Switch
            ).value,
        }

    def collect(self) -> Dict[str, Any]:
        """Validate widgets and return fields to persist.

        Raises:
            ValidationError: On any invalid field value.
        """
        # ai_chunk_size
        chunk_raw = self.query_one("#ai_chat_chunk_size", Input).value.strip()
        try:
            ai_chunk_size = int(chunk_raw)
        except ValueError as exc:
            raise ValidationError(
                "ai_chat_chunk_size", "Chunk size must be a whole number"
            ) from exc
        if ai_chunk_size <= 0:
            raise ValidationError(
                "ai_chat_chunk_size", "Chunk size must be greater than zero"
            )

        ai_system_prompt = self.query_one("#ai_chat_system_prompt", TextArea).text

        # chat_max_history_messages
        history_raw = self.query_one(
            "#ai_chat_max_history_messages", Input
        ).value.strip()
        try:
            chat_max_history_messages = int(history_raw)
        except ValueError as exc:
            raise ValidationError(
                "ai_chat_max_history_messages",
                "Max history messages must be a whole number",
            ) from exc
        if chat_max_history_messages < 0:
            raise ValidationError(
                "ai_chat_max_history_messages",
                "Max history messages must be zero or greater",
            )

        chat_system_prompt = self.query_one(
            "#ai_chat_chat_system_prompt", TextArea
        ).text

        # chat_max_tool_iterations
        iterations_raw = self.query_one(
            "#ai_chat_max_tool_iterations", Input
        ).value.strip()
        try:
            chat_max_tool_iterations = int(iterations_raw)
        except ValueError as exc:
            raise ValidationError(
                "ai_chat_max_tool_iterations",
                "Max tool iterations must be a whole number",
            ) from exc
        if chat_max_tool_iterations < 1:
            raise ValidationError(
                "ai_chat_max_tool_iterations",
                "Max tool iterations must be at least 1",
            )

        # chat_max_tool_rounds — Optional[int]; blank means None
        rounds_raw = self.query_one("#ai_chat_max_tool_rounds", Input).value.strip()
        chat_max_tool_rounds: Optional[int] = None
        if rounds_raw:
            try:
                chat_max_tool_rounds = int(rounds_raw)
            except ValueError as exc:
                raise ValidationError(
                    "ai_chat_max_tool_rounds",
                    "Max tool rounds must be a whole number or blank",
                ) from exc
            if chat_max_tool_rounds < 1:
                raise ValidationError(
                    "ai_chat_max_tool_rounds",
                    "Max tool rounds must be at least 1",
                )

        # chat_tool_guard_level
        guard_level = str(
            self.query_one("#ai_chat_tool_guard_level", Select).value
        )
        if guard_level not in ("readonly", "standard", "dangerous"):
            guard_level = "standard"

        chat_keep_tool_results = self.query_one(
            "#ai_chat_keep_tool_results", Switch
        ).value
        chat_inject_server_memory = self.query_one(
            "#ai_chat_inject_server_memory", Switch
        ).value

        return {
            "ai_chunk_size": ai_chunk_size,
            "ai_system_prompt": ai_system_prompt,
            "chat_max_history_messages": chat_max_history_messages,
            "chat_system_prompt": chat_system_prompt,
            "chat_max_tool_iterations": chat_max_tool_iterations,
            "chat_max_tool_rounds": chat_max_tool_rounds,
            "chat_tool_guard_level": guard_level,
            "chat_keep_tool_results": chat_keep_tool_results,
            "chat_inject_server_memory": chat_inject_server_memory,
        }

    def persist(self) -> None:
        """Validate via :meth:`collect` then write through config_manager.

        The ``chat_inject_server_memory`` toggle also promotes the tri-state
        ``chat_inject_server_memory_decision`` to ``"allowed"`` or ``"denied"``
        so the consent modal does not re-prompt after an explicit Settings toggle.
        """
        fields = self.collect()
        inject = bool(fields["chat_inject_server_memory"])
        # Promote consent decision — mirrors legacy settings.py save path.
        fields["chat_inject_server_memory_decision"] = (
            "allowed" if inject else "denied"
        )
        self.app.config_manager.update(**fields)
        self._finish_save()

    # ------------------------------------------------------------------
    # Dirty marker refresh
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Refresh the dirty marker on any Input change."""
        self._dirty_watch()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Refresh the dirty marker and guard warning on guard-level change."""
        self._dirty_watch()
        if event.select.id == "ai_chat_tool_guard_level":
            self._refresh_guard_warning(str(event.value))

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Refresh the dirty marker on any Switch change."""
        self._dirty_watch()

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        """Refresh the dirty marker when either TextArea changes."""
        self._dirty_watch()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _refresh_guard_warning(self, guard_level: str) -> None:
        """Show or hide the dangerous-guard warning text."""
        try:
            warning = self.query_one("#ai_chat_guard_warning", Static)
        except Exception:
            return
        if guard_level == "dangerous":
            warning.update(escape(_DANGEROUS_WARNING))
        else:
            warning.update("")
