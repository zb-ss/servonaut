"""Chat service for managing AI chat sessions with agentic tool-use loop."""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field, fields, asdict
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
    # Which AI provider produced (or sent) this message: "servonaut",
    # "openai", "anthropic", "gemini", "ollama". None for legacy messages
    # saved before this field existed — those are treated as local-only
    # by the unified history view.
    provider: Optional[str] = None

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
    # Server-side conversation row this local session is paired with,
    # populated when the user chats with Servonaut AI. Persists across
    # session save/load so the history view can show "uploaded" status
    # and so paired delete (Local tab) can also drop the remote row.
    remote_conversation_id: Optional[str] = None

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
        memory_service: Any = None,
    ) -> None:
        self._config_manager = config_manager
        self._ai_service = ai_analysis_service
        self._tool_executor = tool_executor
        self._memory_service = memory_service
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

    # Manifest layout: a single JSON file at chats/manifest.json with one
    # entry per session — id, title, timestamps, message count, the
    # provider that produced the *last* message, and (when paired) the
    # server-side conversation_id. Listing reads only the manifest, so a
    # heavy user with thousands of sessions doesn't pay an open-and-parse
    # per file just to render the history.
    _MANIFEST_NAME = "manifest.json"

    def list_sessions(
        self,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List sessions sorted by most recently updated.

        Reads the manifest only — see :meth:`_load_manifest`. If the
        manifest is missing or stale (existing install pre-manifest), it
        is rebuilt from the per-session files on the fly.

        Pagination: pass ``limit`` to cap the returned slice and
        ``offset`` to skip earlier rows. Caller is responsible for
        rendering "Load more" UI when appropriate. Without ``limit`` the
        full sorted list is returned.

        Each entry has ``id``, ``title``, ``updated_at``,
        ``message_count``, ``last_provider`` (Optional[str]),
        ``remote_conversation_id`` (Optional[str]), ``created_at``.
        """
        manifest = self._load_manifest()
        manifest.sort(key=lambda s: s.get("updated_at", ""), reverse=True)
        if limit is None:
            return manifest[offset:]
        return manifest[offset:offset + limit]

    def _manifest_path(self) -> Path:
        return self._chat_dir / self._MANIFEST_NAME

    def _load_manifest(self) -> List[Dict[str, Any]]:
        """Read the manifest, lazily rebuilding it if missing or invalid."""
        path = self._manifest_path()
        try:
            raw = json.loads(path.read_text())
            if isinstance(raw, list):
                return [dict(entry) for entry in raw if isinstance(entry, dict)]
        except FileNotFoundError:
            pass
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "chat manifest unreadable, rebuilding: %s", exc,
            )
        return self._rebuild_manifest()

    def _rebuild_manifest(self) -> List[Dict[str, Any]]:
        """Scan per-session files and construct a fresh manifest.

        One-time cost on first list after upgrade; subsequent
        save/delete keep the manifest in sync without re-scanning. The
        rebuild also covers the recovery case where the manifest gets
        corrupted or hand-edited away.
        """
        entries: List[Dict[str, Any]] = []
        for f in self._chat_dir.glob("*.json"):
            if f.name == self._MANIFEST_NAME:
                continue
            try:
                data = json.loads(f.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            entries.append(self._manifest_entry_from_data(data, fallback_id=f.stem))
        self._write_manifest(entries)
        return entries

    @staticmethod
    def _manifest_entry_from_data(
        data: Dict[str, Any],
        fallback_id: str = "",
    ) -> Dict[str, Any]:
        """Build a manifest row from a loaded session dict."""
        messages = data.get("messages") or []
        last_provider: Optional[str] = None
        for msg in reversed(messages):
            if isinstance(msg, dict) and msg.get("provider"):
                last_provider = msg["provider"]
                break
        return {
            "id": data.get("id") or fallback_id,
            "title": data.get("title") or "Untitled",
            "created_at": data.get("created_at", ""),
            "updated_at": data.get("updated_at", ""),
            "message_count": len(messages),
            "last_provider": last_provider,
            "remote_conversation_id": data.get("remote_conversation_id"),
        }

    def _write_manifest(self, entries: List[Dict[str, Any]]) -> None:
        """Write the manifest atomically (write-temp + rename)."""
        path = self._manifest_path()
        tmp = path.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps(entries, indent=2))
            tmp.replace(path)
        except OSError as exc:
            logger.warning("Failed to write chat manifest: %s", exc)
            try:
                tmp.unlink()
            except OSError:
                pass

    def _upsert_manifest_entry(self, session: ChatSession) -> None:
        """Replace (or append) the manifest row for *session* and persist."""
        last_provider: Optional[str] = None
        for msg in reversed(session.messages):
            if msg.provider:
                last_provider = msg.provider
                break
        entry = {
            "id": session.id,
            "title": session.title,
            "created_at": session.created_at,
            "updated_at": session.updated_at,
            "message_count": len(session.messages),
            "last_provider": last_provider,
            "remote_conversation_id": session.remote_conversation_id,
        }
        manifest = self._load_manifest()
        replaced = False
        for i, row in enumerate(manifest):
            if row.get("id") == session.id:
                manifest[i] = entry
                replaced = True
                break
        if not replaced:
            manifest.append(entry)
        self._write_manifest(manifest)

    def _drop_manifest_entry(self, session_id: str) -> None:
        manifest = self._load_manifest()
        new = [row for row in manifest if row.get("id") != session_id]
        if len(new) != len(manifest):
            self._write_manifest(new)

    def load_session(self, session_id: str) -> Optional[ChatSession]:
        """Load a session from disk by its ID."""
        path = self._chat_dir / f"{session_id}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return None
        # Filter to known dataclass fields so unknown keys (e.g. a future
        # field that this CLI doesn't recognise yet) don't blow up the
        # ``ChatMessage(**m)`` call.
        msg_keys = {f.name for f in fields(ChatMessage)}
        messages = [
            ChatMessage(**{k: v for k, v in m.items() if k in msg_keys})
            for m in data.get("messages", [])
        ]
        return ChatSession(
            id=data["id"],
            title=data.get("title", "Untitled"),
            messages=messages,
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            remote_conversation_id=data.get("remote_conversation_id"),
        )

    def save_session(self, session: ChatSession) -> None:
        """Persist a session to disk and update the manifest entry."""
        session.updated_at = datetime.now(timezone.utc).isoformat()
        path = self._chat_dir / f"{session.id}.json"
        data = {
            "id": session.id,
            "title": session.title,
            "messages": [asdict(m) for m in session.messages],
            "created_at": session.created_at,
            "updated_at": session.updated_at,
            "remote_conversation_id": session.remote_conversation_id,
        }
        path.write_text(json.dumps(data, indent=2))
        self._upsert_manifest_entry(session)

    async def send_message(
        self,
        session: ChatSession,
        user_message: str,
        status_callback: Optional[Callable[[str], None]] = None,
        instance_id: Optional[str] = None,
        instance_name: Optional[str] = None,
        instance_provider: str = "custom",
        ai_provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Append user message, run agentic loop, append final response.

        Returns dict with keys: content, tokens_used, input_tokens,
        output_tokens, model, estimated_cost, tools_used.

        Args:
            session: Active chat session.
            user_message: Raw user text.
            status_callback: Optional callable invoked with status strings
                during the agentic loop.
            instance_id: Optional server ID for memory injection.
            instance_name: Optional server name for memory injection.
            instance_provider: Provider slug for memory lookup.
            ai_provider: Active AI provider name ("openai", "anthropic",
                "gemini", "ollama"). Stamped on both the user and the
                assistant message so the unified history view can route
                a session to the Local tab via the last-message
                provider tag.
        """
        session.messages.append(
            ChatMessage(role="user", content=user_message, provider=ai_provider)
        )

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
                response_text = await self._run_agentic_loop(
                    session, stats, status_callback,
                    instance_id=instance_id,
                    instance_name=instance_name,
                    instance_provider=instance_provider,
                )
            elif self._ai_service:
                # Fallback: no tool executor, use plain text analysis.
                # Memory block is injected into system prompt for consistency
                # with the agentic path.
                system_prompt = await self._build_system_prompt_with_memory(
                    instance_id=instance_id,
                    instance_name=instance_name,
                    instance_provider=instance_provider,
                    prompt=user_message,
                )
                recent = session.messages[-self._max_history:]
                conversation_text = self._format_conversation(recent)
                result = await self._ai_service.analyze_text(
                    text=conversation_text,
                    system_prompt=system_prompt,
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

        session.messages.append(
            ChatMessage(
                role="assistant", content=response_text, provider=ai_provider,
            )
        )

        # Auto-title from first user message
        if session.title == "New Chat" and len(session.messages) >= 2:
            first_msg = session.messages[0].content
            session.title = first_msg[:50] + ("..." if len(first_msg) > 50 else "")

        self.save_session(session)
        return stats

    # ------------------------------------------------------------------
    # Agentic loop
    # ------------------------------------------------------------------

    async def _build_system_prompt_with_memory(
        self,
        instance_id: Optional[str],
        instance_name: Optional[str],
        instance_provider: str,
        prompt: str = "",
    ) -> str:
        """Return self._system_prompt, prepended with server memory when available.

        Both the agentic and non-agentic code paths share this helper so memory
        injection is consistent regardless of whether tool use is enabled.
        The injected block uses the same ``<CONTEXT name="server_memory:...">``
        envelope as the hosted Servonaut chat path — only the placement
        differs (system prompt for BYO vs synthetic user message for hosted).

        Args:
            instance_id: Optional server ID.
            instance_name: Optional server name.
            instance_provider: Provider slug for memory lookup.
            prompt: User's latest message — drives conditional module
                inclusion (logs / disk / databases / git).

        Returns:
            Effective system prompt string, possibly prefixed with a
            ``<CONTEXT>`` block.
        """
        system_prompt = self._system_prompt
        if instance_id and self._memory_service is not None and self._ai_service is not None:
            config = self._config_manager.get()
            if not getattr(config, "chat_inject_server_memory", True):
                return system_prompt
            config_memory = getattr(config, "memory", None)
            block = await self._ai_service.build_server_memory_block(
                instance_id,
                instance_name or "",
                instance_provider,
                memory_service=self._memory_service,
                config_memory=config_memory,
                prompt=prompt,
            )
            if block:
                system_prompt = f"{block}\n\n{system_prompt}"
        return system_prompt

    async def _run_agentic_loop(
        self,
        session: ChatSession,
        stats: Dict[str, Any],
        status_callback: Optional[Callable[[str], None]] = None,
        instance_id: Optional[str] = None,
        instance_name: Optional[str] = None,
        instance_provider: str = "custom",
    ) -> str:
        """Execute the agentic tool-use loop until text response or max iterations."""
        config = self._config_manager.get()
        provider_name = config.ai_provider.provider

        max_iterations = config.chat_max_tool_iterations or DEFAULT_MAX_TOOL_ITERATIONS

        last_user_msg = ""
        for msg in reversed(session.messages):
            if msg.role == "user":
                last_user_msg = msg.content
                break
        # Build effective system prompt, prepending server memory block when available.
        system_prompt = await self._build_system_prompt_with_memory(
            instance_id=instance_id,
            instance_name=instance_name,
            instance_provider=instance_provider,
            prompt=last_user_msg,
        )

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
                system_prompt=system_prompt,
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
        """Delete a session file + manifest entry. Returns True if deleted."""
        path = self._chat_dir / f"{session_id}.json"
        existed = path.exists()
        if existed:
            path.unlink()
        # Drop the manifest row regardless — a stale manifest entry from
        # a previously hand-deleted file would otherwise linger.
        self._drop_manifest_entry(session_id)
        return existed
