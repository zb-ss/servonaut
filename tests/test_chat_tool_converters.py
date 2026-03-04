"""Tests for chat tool format converters — all 4 providers."""

from __future__ import annotations

from servonaut.services.chat_tool_converters import (
    ToolCall,
    build_anthropic_tool_result,
    build_gemini_tool_result,
    build_openai_tool_result,
    parse_anthropic_tool_calls,
    parse_gemini_tool_calls,
    parse_openai_tool_calls,
    tools_for_anthropic,
    tools_for_gemini,
    tools_for_ollama,
    tools_for_openai,
)

SAMPLE_TOOLS = [
    {
        "name": "list_instances",
        "description": "List all servers.",
        "parameters": {
            "type": "object",
            "properties": {
                "region": {"type": "string", "description": "AWS region."},
            },
            "required": [],
        },
    },
    {
        "name": "run_command",
        "description": "Run a command on a server.",
        "parameters": {
            "type": "object",
            "properties": {
                "instance_id": {"type": "string"},
                "command": {"type": "string"},
            },
            "required": ["instance_id", "command"],
        },
    },
]


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------

class TestOpenAIConverters:
    def test_tools_for_openai_format(self):
        result = tools_for_openai(SAMPLE_TOOLS)
        assert len(result) == 2
        assert result[0]["type"] == "function"
        assert result[0]["function"]["name"] == "list_instances"
        assert result[0]["function"]["description"] == "List all servers."
        assert "properties" in result[0]["function"]["parameters"]

    def test_parse_openai_tool_calls(self):
        message = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_abc123",
                    "type": "function",
                    "function": {
                        "name": "list_instances",
                        "arguments": '{"region": "us-east-1"}',
                    },
                },
                {
                    "id": "call_def456",
                    "type": "function",
                    "function": {
                        "name": "run_command",
                        "arguments": '{"instance_id": "i-123", "command": "uptime"}',
                    },
                },
            ],
        }
        calls = parse_openai_tool_calls(message)
        assert len(calls) == 2
        assert calls[0].id == "call_abc123"
        assert calls[0].name == "list_instances"
        assert calls[0].arguments == {"region": "us-east-1"}
        assert calls[1].name == "run_command"
        assert calls[1].arguments["command"] == "uptime"

    def test_parse_openai_no_tool_calls(self):
        message = {"role": "assistant", "content": "Hello!"}
        calls = parse_openai_tool_calls(message)
        assert calls == []

    def test_parse_openai_invalid_json_args(self):
        message = {
            "tool_calls": [
                {
                    "id": "call_bad",
                    "function": {"name": "test", "arguments": "not json"},
                }
            ]
        }
        calls = parse_openai_tool_calls(message)
        assert len(calls) == 1
        assert calls[0].arguments == {}

    def test_build_openai_tool_result(self):
        result = build_openai_tool_result("call_abc123", "3 instances found")
        assert result["role"] == "tool"
        assert result["tool_call_id"] == "call_abc123"
        assert result["content"] == "3 instances found"


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------

class TestAnthropicConverters:
    def test_tools_for_anthropic_format(self):
        result = tools_for_anthropic(SAMPLE_TOOLS)
        assert len(result) == 2
        assert result[0]["name"] == "list_instances"
        assert result[0]["description"] == "List all servers."
        assert "input_schema" in result[0]
        assert result[0]["input_schema"]["type"] == "object"

    def test_parse_anthropic_tool_calls(self):
        content_blocks = [
            {"type": "text", "text": "Let me check your servers."},
            {
                "type": "tool_use",
                "id": "toolu_abc",
                "name": "list_instances",
                "input": {"region": "us-east-1"},
            },
        ]
        calls = parse_anthropic_tool_calls(content_blocks)
        assert len(calls) == 1
        assert calls[0].id == "toolu_abc"
        assert calls[0].name == "list_instances"
        assert calls[0].arguments == {"region": "us-east-1"}

    def test_parse_anthropic_no_tool_use(self):
        content_blocks = [{"type": "text", "text": "Hello!"}]
        calls = parse_anthropic_tool_calls(content_blocks)
        assert calls == []

    def test_build_anthropic_tool_result(self):
        result = build_anthropic_tool_result("toolu_abc", "3 instances found")
        assert result["role"] == "user"
        assert len(result["content"]) == 1
        assert result["content"][0]["type"] == "tool_result"
        assert result["content"][0]["tool_use_id"] == "toolu_abc"
        assert result["content"][0]["content"] == "3 instances found"


# ---------------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------------

class TestGeminiConverters:
    def test_tools_for_gemini_format(self):
        result = tools_for_gemini(SAMPLE_TOOLS)
        assert len(result) == 1
        assert "function_declarations" in result[0]
        decls = result[0]["function_declarations"]
        assert len(decls) == 2
        assert decls[0]["name"] == "list_instances"

    def test_parse_gemini_tool_calls(self):
        parts = [
            {"text": "Let me list your servers."},
            {
                "functionCall": {
                    "name": "list_instances",
                    "args": {"region": "eu-west-1"},
                }
            },
        ]
        calls = parse_gemini_tool_calls(parts)
        assert len(calls) == 1
        assert calls[0].name == "list_instances"
        assert calls[0].arguments == {"region": "eu-west-1"}
        assert calls[0].id  # should have a generated UUID

    def test_parse_gemini_no_function_calls(self):
        parts = [{"text": "Hello!"}]
        calls = parse_gemini_tool_calls(parts)
        assert calls == []

    def test_build_gemini_tool_result(self):
        result = build_gemini_tool_result("list_instances", "3 instances found")
        assert result["role"] == "function"
        assert len(result["parts"]) == 1
        fr = result["parts"][0]["functionResponse"]
        assert fr["name"] == "list_instances"
        assert fr["response"]["result"] == "3 instances found"


# ---------------------------------------------------------------------------
# Ollama (aliases to OpenAI)
# ---------------------------------------------------------------------------

class TestOllamaConverters:
    def test_tools_for_ollama_is_openai(self):
        assert tools_for_ollama is tools_for_openai

    def test_ollama_format_matches_openai(self):
        result = tools_for_ollama(SAMPLE_TOOLS)
        assert result[0]["type"] == "function"
        assert result[0]["function"]["name"] == "list_instances"
