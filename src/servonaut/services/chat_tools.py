"""Chat tool adapter — bridges the built-in TUI LLM chat to ``ServonautTools``.

All tool implementations live on :class:`servonaut.mcp.tools.ServonautTools`.
This module is a thin dispatcher that:

* surfaces a filtered set of tool schemas to the LLM (``chat_exposed=True``
  in :mod:`servonaut.mcp.tool_schemas`);
* enforces the ``CommandGuard`` once per call before delegating;
* trims overly long tool output so the LLM doesn't waste tokens on multi-MB
  command dumps.

There is deliberately no per-tool handler method here anymore. If a tool
needs new behaviour specific to the chat (pre-formatting, summarisation),
add a thin wrapper here — but treat ``ServonautTools`` as the truth.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from servonaut.config.schema import MCPConfig
from servonaut.mcp.guards import CommandGuard
from servonaut.mcp.tool_schemas import chat_tool_list, chat_tool_names

logger = logging.getLogger(__name__)

# Chat-specific caps. MCP's own max_output_lines default is 500; the chat
# trims further because LLM tokens are expensive and a 500-line dump is
# almost always noise.
MAX_OUTPUT_LINES = 150
MAX_OUTPUT_CHARS = 20_000


# Exposed so tests and other callers can enumerate the chat tool surface
# without poking at tool_schemas directly.
CHAT_TOOLS: List[Dict[str, Any]] = chat_tool_list()


def _truncate_for_chat(output: str) -> str:
    """Trim tool output to fit LLM context without losing the important parts."""
    if not output:
        return output
    lines = output.splitlines()
    if len(lines) > MAX_OUTPUT_LINES:
        output = "\n".join(lines[:MAX_OUTPUT_LINES]) + (
            f"\n... (truncated, {len(lines)} total lines)"
        )
    if len(output) > MAX_OUTPUT_CHARS:
        output = output[:MAX_OUTPUT_CHARS] + "\n... (truncated at character limit)"
    return output


class ChatToolExecutor:
    """Dispatches chat-exposed tool calls to a shared :class:`ServonautTools`.

    The ``guard_level`` here governs the chat's own safety posture; it is
    independent of the MCP server's guard level. The chat can be set to
    ``readonly`` even while the MCP server is ``dangerous`` — callers pick
    the level appropriate to each trust boundary.
    """

    def __init__(
        self,
        tools=None,
        guard_level: str = "standard",
        # Legacy kwargs kept for backwards compatibility with call sites that
        # haven't been migrated to pass a ServonautTools directly. If ``tools``
        # isn't given, we build one from the individual services.
        config_manager: Any = None,
        aws_service: Any = None,
        cache_service: Any = None,
        ssh_service: Any = None,
        connection_service: Any = None,
        custom_server_service: Any = None,
        ovh_service: Any = None,
    ) -> None:
        if tools is None:
            tools = self._build_tools(
                config_manager=config_manager,
                aws_service=aws_service,
                cache_service=cache_service,
                ssh_service=ssh_service,
                connection_service=connection_service,
                custom_server_service=custom_server_service,
                ovh_service=ovh_service,
            )
        self._tools = tools

        mcp_config = tools.config_manager.get().mcp
        guard_config = MCPConfig(
            guard_level=guard_level,
            command_blocklist=mcp_config.command_blocklist,
            command_allowlist=mcp_config.command_allowlist,
        )
        self._guard = CommandGuard(guard_config)
        self._allowed_names = chat_tool_names()

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Tool definitions the LLM is allowed to see at the current guard level."""
        out = []
        for tool in CHAT_TOOLS:
            allowed, _ = self._guard.check_tool(tool["name"])
            if allowed:
                out.append(tool)
        return out

    async def execute(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Execute a tool call and return the (possibly truncated) text result."""
        if tool_name not in self._allowed_names:
            return f"Unknown tool: {tool_name}"

        allowed, reason = self._guard.check_tool(tool_name)
        if not allowed:
            return f"Blocked: {reason}"

        # run_command gets a second-level guard check on the command itself,
        # the one thing that isn't driven from tool name alone.
        if tool_name == "run_command":
            command = arguments.get("command", "")
            cmd_allowed, cmd_reason = self._guard.check_command(command)
            if not cmd_allowed:
                return f"Blocked: {cmd_reason}"

        if status_callback:
            status_callback(f"Running {tool_name}...")

        handler = getattr(self._tools, tool_name, None)
        if handler is None:
            return f"Tool handler not available: {tool_name}"

        try:
            result = await handler(**arguments)
        except Exception as exc:
            logger.exception("Chat tool execution error: %s", tool_name)
            return f"Error executing {tool_name}: {exc}"
        return _truncate_for_chat(result)

    # ------------------------------------------------------------------
    # Constructor-compat shim for call sites that haven't been migrated
    # to pass a ServonautTools instance directly.
    # ------------------------------------------------------------------

    @staticmethod
    def _build_tools(
        *, config_manager, aws_service, cache_service, ssh_service,
        connection_service, custom_server_service, ovh_service,
    ):
        """Construct a minimal ServonautTools from individual services.

        Used only when the legacy kwargs path is taken. Builds the guard and
        audit trail from the same MCP config, so behaviour stays consistent
        with the explicit-``tools`` path.
        """
        from servonaut.mcp.audit import AuditTrail
        from servonaut.mcp.guards import CommandGuard as _CommandGuard
        from servonaut.mcp.tools import ServonautTools
        from servonaut.services.scp_service import SCPService

        if config_manager is None:
            raise ValueError(
                "ChatToolExecutor needs either a ServonautTools or a config_manager."
            )
        mcp_config = config_manager.get().mcp
        return ServonautTools(
            config_manager=config_manager,
            aws_service=aws_service,
            custom_server_service=custom_server_service,
            cache_service=cache_service,
            ssh_service=ssh_service,
            connection_service=connection_service,
            scp_service=SCPService(),
            guard=_CommandGuard(mcp_config, config_manager),
            audit=AuditTrail(mcp_config.audit_path),
            ovh_service=ovh_service,
        )
