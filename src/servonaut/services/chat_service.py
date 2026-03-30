"""Chat service for managing AI chat sessions with agentic tool-use loop."""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from servonaut.config.manager import ConfigManager

logger = logging.getLogger(__name__)

DEFAULT_MAX_TOOL_ITERATIONS = 10


@dataclass
class ChatMessage:
    role: str  # "user" or "assistant"
    content: str
    timestamp: str = ""  # ISO format

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class ChatSession:
    id: str = ""
    title: str = "New Chat"
    messages: List[ChatMessage] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


def _load_default_system_prompt() -> str:
    """Load the knowledge-base system prompt from the data directory."""
    prompt_path = Path(__file__).resolve().parent.parent / "data" / "chat_system_prompt.txt"
    try:
        return prompt_path.read_text(encoding="utf-8").strip()
    except OSError:
        return (
            "You are Servonaut, a senior DevOps engineer assistant. "
            "You help with server management, AWS operations, SSH troubleshooting, "
            "log analysis, networking, and general DevOps questions. "
            "Be concise and practical."
        )


class ChatService:
    """Service for managing AI chat sessions with persistence and agentic tool-use."""

    DEFAULT_SYSTEM_PROMPT = _load_default_system_prompt()

    def __init__(
        self,
        config_manager: ConfigManager,
        ai_analysis_service: Any = None,
        tool_executor: Any = None,
    ) -> None:
        self._config_manager = config_manager
        self._ai_service = ai_analysis_service
        self._tool_executor = tool_executor
        config = config_manager.get()
        self._chat_dir = Path(os.path.expanduser(
            getattr(config, 'chat_history_path', '~/.servonaut/chats')
        ))
        self._max_history = getattr(config, 'chat_max_history_messages', 20)
        self._system_prompt = (
            getattr(config, 'chat_system_prompt', '') or self.DEFAULT_SYSTEM_PROMPT
        )
        self._chat_dir.mkdir(parents=True, exist_ok=True)

    def create_session(self) -> ChatSession:
        """Create a new chat session and persist it."""
        session = ChatSession()
        self.save_session(session)
        return session

    def list_sessions(self) -> List[Dict[str, str]]:
        """List all sessions sorted by most recently updated."""
        sessions: List[Dict[str, str]] = []
        for f in self._chat_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                sessions.append({
                    "id": data.get("id", f.stem),
                    "title": data.get("title", "Untitled"),
                    "updated_at": data.get("updated_at", ""),
                })
            except (json.JSONDecodeError, OSError):
                continue
        sessions.sort(key=lambda s: s["updated_at"], reverse=True)
        return sessions

    def load_session(self, session_id: str) -> Optional[ChatSession]:
        """Load a session from disk by its ID."""
        path = self._chat_dir / f"{session_id}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return None
        messages = [ChatMessage(**m) for m in data.get("messages", [])]
        return ChatSession(
            id=data["id"],
            title=data.get("title", "Untitled"),
            messages=messages,
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )

    def save_session(self, session: ChatSession) -> None:
        """Persist a session to disk."""
        session.updated_at = datetime.now(timezone.utc).isoformat()
        path = self._chat_dir / f"{session.id}.json"
        data = {
            "id": session.id,
            "title": session.title,
            "messages": [asdict(m) for m in session.messages],
            "created_at": session.created_at,
            "updated_at": session.updated_at,
        }
        path.write_text(json.dumps(data, indent=2))

    async def send_message(
        self,
        session: ChatSession,
        user_message: str,
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """Append user message, run agentic loop, append final response.

        Returns dict with keys: content, tokens_used, input_tokens,
        output_tokens, model, estimated_cost, tools_used.
        """
        session.messages.append(ChatMessage(role="user", content=user_message))

        stats: Dict[str, Any] = {
            "content": "",
            "tokens_used": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "model": "",
            "estimated_cost": None,
            "tools_used": [],
        }

        try:
            if self._ai_service and self._tool_executor:
                response_text = await self._run_agentic_loop(session, stats, status_callback)
            elif self._ai_service:
                # Fallback: no tool executor, use plain text analysis
                recent = session.messages[-self._max_history:]
                conversation_text = self._format_conversation(recent)
                result = await self._ai_service.analyze_text(
                    text=conversation_text,
                    system_prompt=self._system_prompt,
                )
                stats.update({k: v for k, v in result.items() if k in stats})
                response_text = result.get("content", "No response received.")
                stats["content"] = response_text
            else:
                response_text = (
                    "AI provider not configured. Set up an AI provider in Settings."
                )
                stats["content"] = response_text
        except Exception as exc:
            logger.exception("Chat error")
            response_text = f"Error: {exc}"
            stats["content"] = response_text

        session.messages.append(ChatMessage(role="assistant", content=response_text))

        # Auto-title from first user message
        if session.title == "New Chat" and len(session.messages) >= 2:
            first_msg = session.messages[0].content
            session.title = first_msg[:50] + ("..." if len(first_msg) > 50 else "")

        self.save_session(session)
        return stats

    # ------------------------------------------------------------------
    # Agentic loop
    # ------------------------------------------------------------------

    async def _run_agentic_loop(
        self,
        session: ChatSession,
        stats: Dict[str, Any],
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Execute the agentic tool-use loop until text response or max iterations."""
        config = self._config_manager.get()
        provider_name = config.ai_provider.provider

        max_iterations = config.chat_max_tool_iterations or DEFAULT_MAX_TOOL_ITERATIONS

        # Get tool definitions formatted for the provider
        tool_defs = self._tool_executor.get_tool_definitions()
        provider_tools = self._format_tools_for_provider(tool_defs, provider_name)

        # Build initial API messages from session history
        api_messages = self._build_api_messages(session, provider_name)

        tools_used: List[str] = []
        tool_outputs: List[str] = []

        for iteration in range(max_iterations):
            if status_callback:
                if iteration == 0:
                    status_callback("Thinking...")
                else:
                    status_callback(f"Thinking (step {iteration + 1})...")

            # On last iteration, don't pass tools to force a text response
            current_tools = provider_tools if iteration < max_iterations - 1 else None

            result = await self._ai_service.chat(
                messages=api_messages,
                system_prompt=self._system_prompt,
                tools=current_tools,
            )

            # Accumulate stats
            stats["tokens_used"] += result.get("tokens_used", 0)
            stats["input_tokens"] += result.get("input_tokens", 0)
            stats["output_tokens"] += result.get("output_tokens", 0)
            stats["model"] = result.get("model", "") or stats["model"]
            cost = result.get("estimated_cost")
            if cost is not None:
                stats["estimated_cost"] = (stats["estimated_cost"] or 0) + cost

            # Check for tool calls
            tool_calls = self._parse_tool_calls(result, provider_name)

            if not tool_calls or result.get("stop_reason") != "tool_use":
                # Done — final text response
                content = result.get("content", "")
                stats["content"] = content
                stats["tools_used"] = tools_used
                return content

            # Append the assistant message (with tool calls) for re-sending
            self._append_assistant_tool_msg(api_messages, result, provider_name)

            # Execute each tool call and append results
            for tc in tool_calls:
                tools_used.append(tc.name)
                if status_callback:
                    status_callback(f"Running {tc.name}...")

                tool_result = await self._tool_executor.execute(
                    tc.name, tc.arguments, status_callback
                )
                tool_outputs.append(f"**{tc.name}**:\n{tool_result}")
                self._append_tool_result(api_messages, tc, tool_result, provider_name)

        # Exhausted iterations — build a response from collected tool outputs
        logger.warning("Chat agentic loop exhausted %d iterations. Tools used: %s", max_iterations, tools_used)
        content = result.get("content") or ""
        summary_parts = [
            f"I reached the maximum number of tool calls ({max_iterations}) "
            "before I could finish. Here's what I gathered:\n"
        ]
        if content:
            summary_parts.append(content)
        if tool_outputs:
            # Include the last few tool outputs (most relevant), trim to avoid huge messages
            recent = tool_outputs[-5:]
            for output in recent:
                trimmed = output[:2000] + "\n…(truncated)" if len(output) > 2000 else output
                summary_parts.append(trimmed)
            if len(tool_outputs) > 5:
                summary_parts.insert(1, f"*(showing last 5 of {len(tool_outputs)} tool results)*\n")
        else:
            summary_parts.append("No tool results were collected.")

        content = "\n\n".join(summary_parts)
        stats["content"] = content
        stats["tools_used"] = tools_used
        return content

    # ------------------------------------------------------------------
    # Provider-specific message building
    # ------------------------------------------------------------------

    def _format_tools_for_provider(
        self, tool_defs: List[Dict], provider_name: str
    ) -> Optional[List[Dict]]:
        """Convert generic tool definitions to provider-specific format."""
        if not tool_defs:
            return None

        from servonaut.services.chat_tool_converters import (
            tools_for_openai,
            tools_for_anthropic,
            tools_for_gemini,
        )

        converters = {
            "openai": tools_for_openai,
            "anthropic": tools_for_anthropic,
            "gemini": tools_for_gemini,
            "ollama": tools_for_openai,
        }
        converter = converters.get(provider_name)
        if not converter:
            return None
        return converter(tool_defs)

    def _build_api_messages(
        self, session: ChatSession, provider_name: str
    ) -> List[Dict[str, Any]]:
        """Convert ChatMessage list to provider-native message format."""
        recent = session.messages[-self._max_history:]

        if provider_name == "gemini":
            messages = []
            for msg in recent:
                role = "user" if msg.role == "user" else "model"
                messages.append({"role": role, "parts": [{"text": msg.content}]})
            return messages

        # OpenAI / Anthropic / Ollama all use {"role": "...", "content": "..."}
        messages = []
        for msg in recent:
            messages.append({"role": msg.role, "content": msg.content})
        return messages

    def _parse_tool_calls(self, result: Dict, provider_name: str) -> List[Any]:
        """Parse tool calls from provider response using converters."""
        from servonaut.services.chat_tool_converters import (
            parse_openai_tool_calls,
            parse_anthropic_tool_calls,
            parse_gemini_tool_calls,
        )

        if provider_name in ("openai", "ollama"):
            raw_message = result.get("raw_message") or {}
            return parse_openai_tool_calls(raw_message)
        elif provider_name == "anthropic":
            raw = result.get("raw_message") or []
            return parse_anthropic_tool_calls(raw)
        elif provider_name == "gemini":
            raw = result.get("raw_message") or []
            return parse_gemini_tool_calls(raw)
        return []

    def _append_assistant_tool_msg(
        self, messages: List[Dict], result: Dict, provider_name: str
    ) -> None:
        """Append the raw assistant message (containing tool calls) to messages."""
        if provider_name in ("openai", "ollama"):
            raw = result.get("raw_message")
            if raw:
                messages.append(raw)
        elif provider_name == "anthropic":
            raw_blocks = result.get("raw_message") or []
            messages.append({"role": "assistant", "content": raw_blocks})
        elif provider_name == "gemini":
            raw_parts = result.get("raw_message") or []
            messages.append({"role": "model", "parts": raw_parts})

    def _append_tool_result(
        self, messages: List[Dict], tc: Any, result_text: str, provider_name: str
    ) -> None:
        """Append a tool result message in provider-native format."""
        from servonaut.services.chat_tool_converters import (
            build_openai_tool_result,
            build_anthropic_tool_result,
            build_gemini_tool_result,
        )

        if provider_name in ("openai", "ollama"):
            messages.append(build_openai_tool_result(tc.id, result_text))
        elif provider_name == "anthropic":
            messages.append(build_anthropic_tool_result(tc.id, result_text))
        elif provider_name == "gemini":
            messages.append(build_gemini_tool_result(tc.name, result_text))

    # ------------------------------------------------------------------
    # Legacy helpers
    # ------------------------------------------------------------------

    def _format_conversation(self, messages: List[ChatMessage]) -> str:
        """Format messages as plain text for the AI provider."""
        lines = []
        for msg in messages:
            prefix = "User" if msg.role == "user" else "Assistant"
            lines.append(f"{prefix}: {msg.content}")
        return "\n\n".join(lines)

    def delete_session(self, session_id: str) -> bool:
        """Delete a session file. Returns True if deleted."""
        path = self._chat_dir / f"{session_id}.json"
        if path.exists():
            path.unlink()
            return True
        return False
