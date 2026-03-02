"""Tests for ChatService."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from servonaut.services.chat_service import ChatMessage, ChatService, ChatSession


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_service(tmp_path: Path, ai_service=None) -> ChatService:
    """Return a ChatService pointing at tmp_path for storage."""
    config = MagicMock()
    config.chat_history_path = str(tmp_path / "chats")
    config.chat_max_history_messages = 20
    config.chat_system_prompt = ""

    config_manager = MagicMock()
    config_manager.get.return_value = config

    return ChatService(config_manager, ai_service)


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
