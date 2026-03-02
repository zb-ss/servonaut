"""Chat service for managing AI chat sessions."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from servonaut.config.manager import ConfigManager


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
    """Service for managing AI chat sessions with persistence."""

    DEFAULT_SYSTEM_PROMPT = _load_default_system_prompt()

    def __init__(self, config_manager: ConfigManager, ai_analysis_service: Any = None) -> None:
        self._config_manager = config_manager
        self._ai_service = ai_analysis_service
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

    async def send_message(self, session: ChatSession, user_message: str) -> Dict[str, Any]:
        """Append user message, call AI provider, append response.

        Returns dict with keys: content, tokens_used, input_tokens,
        output_tokens, model, estimated_cost.
        """
        session.messages.append(ChatMessage(role="user", content=user_message))

        # Use last N messages to stay within token limits
        recent = session.messages[-self._max_history:]
        conversation_text = self._format_conversation(recent)

        stats: Dict[str, Any] = {
            "content": "",
            "tokens_used": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "model": "",
            "estimated_cost": None,
        }

        try:
            if self._ai_service:
                result = await self._ai_service.analyze_text(
                    text=conversation_text,
                    system_prompt=self._system_prompt,
                )
                stats.update(result)
                response_text = result.get("content", "No response received.")
            else:
                response_text = (
                    "AI provider not configured. Set up an AI provider in Settings."
                )
                stats["content"] = response_text
        except Exception as exc:
            response_text = f"Error: {exc}"
            stats["content"] = response_text

        session.messages.append(ChatMessage(role="assistant", content=response_text))

        # Auto-title from first user message
        if session.title == "New Chat" and len(session.messages) >= 2:
            first_msg = session.messages[0].content
            session.title = first_msg[:50] + ("..." if len(first_msg) > 50 else "")

        self.save_session(session)
        return stats

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
