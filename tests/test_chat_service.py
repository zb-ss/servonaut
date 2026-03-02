"""Tests for ChatService."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from servonaut.config.schema import AIProviderConfig, AppConfig
from servonaut.services.chat_service import ChatMessage, ChatService, ChatSession


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_service(tmp_path: Path, ai_service=None, tool_executor=None) -> ChatService:
    """Return a ChatService pointing at tmp_path for storage."""
    config = MagicMock()
    config.chat_history_path = str(tmp_path / "chats")
    config.chat_max_history_messages = 20
    config.chat_system_prompt = ""
    config.ai_provider = AIProviderConfig(provider="openai")

    config_manager = MagicMock()
    config_manager.get.return_value = config

    return ChatService(config_manager, ai_service, tool_executor)


def _run(coro):  # type: ignore[no-untyped-def]
    """Run a coroutine synchronously (no pytest-asyncio required)."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_create_session(tmp_path: Path) -> None:
    svc = _make_service(tmp_path)
    session = svc.create_session()

    assert session.id != ""
    assert session.title == "New Chat"
    # File persisted
    saved = tmp_path / "chats" / f"{session.id}.json"
    assert saved.exists()


def test_save_and_load_session(tmp_path: Path) -> None:
    svc = _make_service(tmp_path)
    session = svc.create_session()
    session.messages.append(ChatMessage(role="user", content="hello"))
    svc.save_session(session)

    loaded = svc.load_session(session.id)
    assert loaded is not None
    assert loaded.id == session.id
    assert len(loaded.messages) == 1
    assert loaded.messages[0].content == "hello"
    assert loaded.messages[0].role == "user"


def test_list_sessions(tmp_path: Path) -> None:
    svc = _make_service(tmp_path)
    s1 = svc.create_session()
    s2 = svc.create_session()

    sessions = svc.list_sessions()
    ids = [s["id"] for s in sessions]
    # Both sessions present
    assert s1.id in ids
    assert s2.id in ids
    # Most recently updated first
    assert sessions[0]["updated_at"] >= sessions[1]["updated_at"]


def test_send_message(tmp_path: Path) -> None:
    ai_service = MagicMock()
    ai_service.analyze_text = AsyncMock(return_value={"content": "pong"})

    svc = _make_service(tmp_path, ai_service)
    session = svc.create_session()

    result = _run(svc.send_message(session, "ping"))

    assert result["content"] == "pong"
    assert len(session.messages) == 2
    assert session.messages[0].role == "user"
    assert session.messages[0].content == "ping"
    assert session.messages[1].role == "assistant"
    assert session.messages[1].content == "pong"


def test_auto_title(tmp_path: Path) -> None:
    ai_service = MagicMock()
    ai_service.analyze_text = AsyncMock(return_value={"content": "ok"})

    svc = _make_service(tmp_path, ai_service)
    session = svc.create_session()
    assert session.title == "New Chat"

    _run(svc.send_message(session, "How do I restart nginx?"))
    assert session.title == "How do I restart nginx?"


def test_auto_title_truncates_long_message(tmp_path: Path) -> None:
    ai_service = MagicMock()
    ai_service.analyze_text = AsyncMock(return_value={"content": "ok"})

    svc = _make_service(tmp_path, ai_service)
    session = svc.create_session()
    long_msg = "x" * 80

    _run(svc.send_message(session, long_msg))
    assert len(session.title) == 53  # 50 chars + "..."
    assert session.title.endswith("...")


def test_history_truncation(tmp_path: Path) -> None:
    """Only the last N messages are forwarded to the AI."""
    captured_texts = []

    async def fake_analyze(text: str, system_prompt: str = "") -> dict:
        captured_texts.append(text)
        return {"content": "ok"}

    ai_service = MagicMock()
    ai_service.analyze_text = AsyncMock(side_effect=fake_analyze)

    # Low limit so truncation is easy to test
    config = MagicMock()
    config.chat_history_path = str(tmp_path / "chats")
    config.chat_max_history_messages = 4
    config.chat_system_prompt = ""
    config_manager = MagicMock()
    config_manager.get.return_value = config

    svc = ChatService(config_manager, ai_service)
    session = svc.create_session()

    # Seed 5 existing messages
    for i in range(5):
        session.messages.append(ChatMessage(role="user", content=f"msg{i}"))

    _run(svc.send_message(session, "final"))

    # The text sent to AI should only contain the last 4 messages
    # (truncated after the new "final" is appended — so messages[-4:])
    text_sent = captured_texts[-1]
    assert "msg0" not in text_sent
    assert "msg1" not in text_sent
    assert "final" in text_sent


def test_delete_session(tmp_path: Path) -> None:
    svc = _make_service(tmp_path)
    session = svc.create_session()
    saved = tmp_path / "chats" / f"{session.id}.json"
    assert saved.exists()

    result = svc.delete_session(session.id)
    assert result is True
    assert not saved.exists()

    # Deleting again returns False
    result2 = svc.delete_session(session.id)
    assert result2 is False


def test_format_conversation(tmp_path: Path) -> None:
    svc = _make_service(tmp_path)
    messages = [
        ChatMessage(role="user", content="Hello"),
        ChatMessage(role="assistant", content="Hi there"),
        ChatMessage(role="user", content="How are you?"),
    ]
    result = svc._format_conversation(messages)
    assert "User: Hello" in result
    assert "Assistant: Hi there" in result
    assert "User: How are you?" in result
    # Separated by double newline
    assert "\n\n" in result


def test_send_message_no_ai_provider(tmp_path: Path) -> None:
    """Without an AI provider, a helpful error message is returned."""
    svc = _make_service(tmp_path, ai_service=None)
    session = svc.create_session()
    result = _run(svc.send_message(session, "ping"))
    assert "not configured" in result["content"].lower() or "provider" in result["content"].lower()


def test_load_session_missing_returns_none(tmp_path: Path) -> None:
    svc = _make_service(tmp_path)
    result = svc.load_session("nonexistent-id")
    assert result is None


# ---------------------------------------------------------------------------
# Agentic loop tests
# ---------------------------------------------------------------------------

def _make_tool_executor():
    """Create a mock ChatToolExecutor."""
    executor = MagicMock()
    executor.get_tool_definitions.return_value = [
        {
            "name": "list_instances",
            "description": "List all servers.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    ]
    executor.execute = AsyncMock(return_value="3 instances found: web-1, web-2, db-1")
    return executor


def test_agentic_loop_tool_then_text(tmp_path: Path) -> None:
    """AI calls a tool, gets result, then responds with text."""
    call_count = [0]

    async def mock_chat(messages, system_prompt="", tools=None):
        call_count[0] += 1
        if call_count[0] == 1:
            # First call: AI wants to use a tool
            return {
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_1",
                        "function": {
                            "name": "list_instances",
                            "arguments": "{}",
                        },
                    }
                ],
                "tokens_used": 50,
                "input_tokens": 30,
                "output_tokens": 20,
                "model": "gpt-4o-mini",
                "raw_message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "function": {
                                "name": "list_instances",
                                "arguments": "{}",
                            },
                        }
                    ],
                },
                "stop_reason": "tool_use",
                "estimated_cost": 0.001,
            }
        else:
            # Second call: AI responds with text
            return {
                "content": "You have 3 servers: web-1, web-2, and db-1.",
                "tool_calls": [],
                "tokens_used": 40,
                "input_tokens": 25,
                "output_tokens": 15,
                "model": "gpt-4o-mini",
                "raw_message": {"role": "assistant", "content": "You have 3 servers."},
                "stop_reason": "end_turn",
                "estimated_cost": 0.0008,
            }

    ai_service = MagicMock()
    ai_service.chat = AsyncMock(side_effect=mock_chat)

    executor = _make_tool_executor()
    svc = _make_service(tmp_path, ai_service, executor)
    session = svc.create_session()

    result = _run(svc.send_message(session, "What servers do I have?"))

    assert "3 servers" in result["content"]
    assert result["tokens_used"] == 90  # 50 + 40
    assert result["tools_used"] == ["list_instances"]
    assert len(session.messages) == 2  # user + final assistant
    executor.execute.assert_called_once_with("list_instances", {}, executor.execute.call_args[0][2] if executor.execute.call_args else None)


def test_agentic_loop_no_tools_text_only(tmp_path: Path) -> None:
    """AI responds with text directly, no tool calls."""
    async def mock_chat(messages, system_prompt="", tools=None):
        return {
            "content": "Hello! How can I help?",
            "tool_calls": [],
            "tokens_used": 20,
            "input_tokens": 10,
            "output_tokens": 10,
            "model": "gpt-4o-mini",
            "raw_message": {"role": "assistant", "content": "Hello! How can I help?"},
            "stop_reason": "end_turn",
            "estimated_cost": 0.0005,
        }

    ai_service = MagicMock()
    ai_service.chat = AsyncMock(side_effect=mock_chat)

    executor = _make_tool_executor()
    svc = _make_service(tmp_path, ai_service, executor)
    session = svc.create_session()

    result = _run(svc.send_message(session, "Hello"))

    assert result["content"] == "Hello! How can I help?"
    assert result["tools_used"] == []
    executor.execute.assert_not_called()


def test_agentic_loop_max_iterations(tmp_path: Path) -> None:
    """After MAX_TOOL_ITERATIONS, AI is forced to produce text."""
    iteration = [0]

    async def mock_chat(messages, system_prompt="", tools=None):
        iteration[0] += 1
        if tools is not None:
            # Keep requesting tools
            return {
                "content": "",
                "tool_calls": [{"id": f"call_{iteration[0]}", "function": {"name": "list_instances", "arguments": "{}"}}],
                "tokens_used": 10,
                "input_tokens": 5,
                "output_tokens": 5,
                "model": "gpt-4o-mini",
                "raw_message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{"id": f"call_{iteration[0]}", "function": {"name": "list_instances", "arguments": "{}"}}],
                },
                "stop_reason": "tool_use",
                "estimated_cost": 0.0001,
            }
        else:
            # Final call without tools
            return {
                "content": "Summary after many tool calls.",
                "tool_calls": [],
                "tokens_used": 10,
                "input_tokens": 5,
                "output_tokens": 5,
                "model": "gpt-4o-mini",
                "raw_message": {"role": "assistant", "content": "Summary."},
                "stop_reason": "end_turn",
                "estimated_cost": 0.0001,
            }

    ai_service = MagicMock()
    ai_service.chat = AsyncMock(side_effect=mock_chat)

    executor = _make_tool_executor()
    svc = _make_service(tmp_path, ai_service, executor)
    session = svc.create_session()

    result = _run(svc.send_message(session, "Keep checking"))

    # Should have called chat() 10 (tool calls) + 1 (final) = 11 times
    # Actually the last iteration (10th) passes tools=None which forces text
    assert ai_service.chat.call_count <= 11
    assert len(result["tools_used"]) > 0


def test_agentic_loop_ollama_fallback(tmp_path: Path) -> None:
    """Ollama model that ignores tools returns text directly."""
    async def mock_chat(messages, system_prompt="", tools=None):
        # Ollama returns text even though tools were provided
        return {
            "content": "I can see your servers.",
            "tool_calls": [],
            "tokens_used": 20,
            "input_tokens": 10,
            "output_tokens": 10,
            "model": "llama3",
            "raw_message": {"role": "assistant", "content": "I can see your servers."},
            "stop_reason": "end_turn",
            "estimated_cost": 0.0,
        }

    ai_service = MagicMock()
    ai_service.chat = AsyncMock(side_effect=mock_chat)

    # Config with Ollama provider
    config = MagicMock()
    config.chat_history_path = str(tmp_path / "chats")
    config.chat_max_history_messages = 20
    config.chat_system_prompt = ""
    config.ai_provider = AIProviderConfig(provider="ollama")
    config_manager = MagicMock()
    config_manager.get.return_value = config

    executor = _make_tool_executor()
    svc = ChatService(config_manager, ai_service, executor)
    session = svc.create_session()

    result = _run(svc.send_message(session, "What servers?"))

    assert result["content"] == "I can see your servers."
    assert result["tools_used"] == []
    executor.execute.assert_not_called()


def test_agentic_loop_fallback_no_executor(tmp_path: Path) -> None:
    """Without a tool executor, falls back to plain text analysis."""
    ai_service = MagicMock()
    ai_service.analyze_text = AsyncMock(return_value={
        "content": "plain response",
        "tokens_used": 10,
        "input_tokens": 5,
        "output_tokens": 5,
        "model": "gpt-4o-mini",
        "estimated_cost": 0.001,
    })

    svc = _make_service(tmp_path, ai_service, tool_executor=None)
    session = svc.create_session()

    result = _run(svc.send_message(session, "hello"))

    assert result["content"] == "plain response"
    ai_service.analyze_text.assert_called_once()


def test_agentic_loop_status_callback(tmp_path: Path) -> None:
    """Status callback is invoked during tool execution."""
    call_count = [0]
    statuses = []

    async def mock_chat(messages, system_prompt="", tools=None):
        call_count[0] += 1
        if call_count[0] == 1:
            return {
                "content": "",
                "tool_calls": [{"id": "call_1", "function": {"name": "list_instances", "arguments": "{}"}}],
                "tokens_used": 10, "input_tokens": 5, "output_tokens": 5,
                "model": "gpt-4o-mini",
                "raw_message": {
                    "role": "assistant", "content": None,
                    "tool_calls": [{"id": "call_1", "function": {"name": "list_instances", "arguments": "{}"}}],
                },
                "stop_reason": "tool_use", "estimated_cost": 0.0001,
            }
        return {
            "content": "Done.", "tool_calls": [],
            "tokens_used": 10, "input_tokens": 5, "output_tokens": 5,
            "model": "gpt-4o-mini",
            "raw_message": {"role": "assistant", "content": "Done."},
            "stop_reason": "end_turn", "estimated_cost": 0.0001,
        }

    def on_status(text):
        statuses.append(text)

    ai_service = MagicMock()
    ai_service.chat = AsyncMock(side_effect=mock_chat)

    executor = _make_tool_executor()
    svc = _make_service(tmp_path, ai_service, executor)
    session = svc.create_session()

    _run(svc.send_message(session, "list servers", status_callback=on_status))

    assert any("Thinking" in s for s in statuses)
    assert any("list_instances" in s for s in statuses)
