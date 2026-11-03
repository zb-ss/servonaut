"""The in-app chat tells the model to record what it learns about a server.

The guidance follows the system prompt (default or custom) whenever the chat
offers ``remember_server_finding``, and is absent otherwise.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from servonaut.config.schema import AIProviderConfig
from servonaut.mcp.agent_guidance import RECORD_FINDINGS_GUIDANCE
from servonaut.services.chat_service import ChatService

_HEADING = "Record what you learn"


_REMEMBER_DEF = {
    "name": "remember_server_finding",
    "description": "Save a finding.",
    "parameters": {"type": "object", "properties": {}, "required": []},
}
_LIST_DEF = {
    "name": "list_instances",
    "description": "List all servers.",
    "parameters": {"type": "object", "properties": {}, "required": []},
}


def _chat_service(tmp_path: Path, *, tool_defs, custom_prompt: str = ""):
    config = MagicMock()
    config.chat_history_path = str(tmp_path / "chats")
    config.chat_max_history_messages = 20
    config.chat_max_tool_iterations = 3
    config.chat_system_prompt = custom_prompt
    config.ai_provider = AIProviderConfig(provider="openai")
    config_manager = MagicMock()
    config_manager.get.return_value = config

    prompts = []

    async def chat(messages, system_prompt="", tools=None):
        prompts.append(system_prompt)
        return {
            "content": "done",
            "tool_calls": [],
            "raw_message": {"role": "assistant", "content": "done"},
            "stop_reason": "end_turn",
        }

    async def analyze_text(text, system_prompt=""):
        prompts.append(system_prompt)
        return {"content": "done"}

    ai_service = MagicMock()
    ai_service.chat = AsyncMock(side_effect=chat)
    ai_service.analyze_text = AsyncMock(side_effect=analyze_text)

    executor = None
    if tool_defs is not None:
        executor = MagicMock()
        executor.get_tool_definitions.return_value = tool_defs
        executor.execute = AsyncMock(return_value="")

    svc = ChatService(config_manager, ai_service, executor)
    return svc, prompts


def _send(svc: ChatService) -> None:
    session = svc.create_session()
    asyncio.run(svc.send_message(session, "Why is the disk full on web-1?"))


class TestChatPrompt:
    def test_guidance_follows_the_prompt_when_the_tool_is_offered(self, tmp_path):
        svc, prompts = _chat_service(tmp_path, tool_defs=[_LIST_DEF, _REMEMBER_DEF])
        _send(svc)
        assert prompts and prompts[0].endswith(RECORD_FINDINGS_GUIDANCE)
        assert prompts[0].startswith(ChatService.DEFAULT_SYSTEM_PROMPT)

    def test_no_guidance_when_the_guard_level_hides_the_tool(self, tmp_path):
        svc, prompts = _chat_service(tmp_path, tool_defs=[_LIST_DEF])
        _send(svc)
        assert prompts and _HEADING not in prompts[0]

    def test_custom_prompt_gets_the_guidance_only_with_the_tool(self, tmp_path):
        custom = "You are a terse assistant."
        svc, prompts = _chat_service(
            tmp_path, tool_defs=[_REMEMBER_DEF], custom_prompt=custom,
        )
        _send(svc)
        assert prompts[0] == f"{custom}\n\n{RECORD_FINDINGS_GUIDANCE}"

    def test_no_guidance_without_tools(self, tmp_path):
        svc, prompts = _chat_service(tmp_path, tool_defs=None)
        _send(svc)
        assert prompts and _HEADING not in prompts[0]

    def test_the_default_prompt_does_not_repeat_it(self):
        assert _HEADING not in ChatService.DEFAULT_SYSTEM_PROMPT
