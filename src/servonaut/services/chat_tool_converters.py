"""Per-provider format conversion for chat tool calling.

Converts provider-agnostic ToolDefinition dicts to/from each provider's
native tool-calling format.  Pure stateless functions — no dependencies
except the stdlib.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolCall:
    """Normalized tool call parsed from any provider's response."""

    id: str
    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# OpenAI  (also used by Ollama)
# ---------------------------------------------------------------------------

def tools_for_openai(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert generic tool definitions to OpenAI function-calling format."""
    result = []
    for t in tools:
        result.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["parameters"],
            },
        })
    return result


def parse_openai_tool_calls(message: Dict[str, Any]) -> List[ToolCall]:
    """Parse tool calls from an OpenAI chat completion message dict."""
    raw_calls = message.get("tool_calls") or []
    calls = []
    for tc in raw_calls:
        fn = tc.get("function", {})
        args_str = fn.get("arguments", "{}")
        try:
            args = json.loads(args_str) if isinstance(args_str, str) else args_str
        except (json.JSONDecodeError, TypeError):
            args = {}
        calls.append(ToolCall(
            id=tc.get("id", str(uuid.uuid4())),
            name=fn.get("name", ""),
            arguments=args,
        ))
    return calls


def build_openai_tool_result(tool_call_id: str, content: str) -> Dict[str, Any]:
    """Build a tool-result message for OpenAI."""
    return {
        "role": "tool",
        "tool_call_id": tool_call_id,
        "content": content,
    }


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------

def tools_for_anthropic(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert generic tool definitions to Anthropic format."""
    result = []
    for t in tools:
        result.append({
            "name": t["name"],
            "description": t["description"],
            "input_schema": t["parameters"],
        })
    return result


def parse_anthropic_tool_calls(content_blocks: List[Dict[str, Any]]) -> List[ToolCall]:
    """Parse tool_use blocks from Anthropic response content."""
    calls = []
    for block in content_blocks:
        if block.get("type") == "tool_use":
            calls.append(ToolCall(
                id=block.get("id", str(uuid.uuid4())),
                name=block.get("name", ""),
                arguments=block.get("input", {}),
            ))
    return calls


def build_anthropic_tool_result(tool_use_id: str, content: str) -> Dict[str, Any]:
    """Build a tool_result message for Anthropic."""
    return {
        "role": "user",
        "content": [
            {
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": content,
            }
        ],
    }


# ---------------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------------

def tools_for_gemini(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert generic tool definitions to Gemini function_declarations."""
    declarations = []
    for t in tools:
        declarations.append({
            "name": t["name"],
            "description": t["description"],
            "parameters": t["parameters"],
        })
    return [{"function_declarations": declarations}]


def parse_gemini_tool_calls(parts: List[Dict[str, Any]]) -> List[ToolCall]:
    """Parse functionCall parts from a Gemini response."""
    calls = []
    for part in parts:
        fc = part.get("functionCall")
        if fc:
            calls.append(ToolCall(
                id=str(uuid.uuid4()),
                name=fc.get("name", ""),
                arguments=fc.get("args", {}),
            ))
    return calls


def build_gemini_tool_result(name: str, content: str) -> Dict[str, Any]:
    """Build a function-response message for Gemini."""
    return {
        "role": "function",
        "parts": [
            {
                "functionResponse": {
                    "name": name,
                    "response": {"result": content},
                }
            }
        ],
    }


# ---------------------------------------------------------------------------
# Ollama  (same wire format as OpenAI)
# ---------------------------------------------------------------------------

tools_for_ollama = tools_for_openai
parse_ollama_tool_calls = parse_openai_tool_calls
build_ollama_tool_result = build_openai_tool_result
