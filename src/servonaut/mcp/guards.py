"""Guard system for MCP server command safety."""
from __future__ import annotations

import re
import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)


class GuardLevel:
    READONLY = "readonly"
    STANDARD = "standard"
    DANGEROUS = "dangerous"


class CommandGuard:
    """Validates commands against guard level and blocklist/allowlist."""

    def __init__(self, config) -> None:
        """config is MCPConfig instance."""
        self._level = config.guard_level
        self._blocklist = [re.compile(p) for p in config.command_blocklist]
        self._allowlist = config.command_allowlist

    def check_command(self, command: str) -> Tuple[bool, str]:
        """Check if command is allowed. Returns (allowed: bool, reason: str)."""
        # Blocklist ALWAYS enforced, even in dangerous mode
        for pattern in self._blocklist:
            if pattern.search(command):
                return False, f"Command matches blocklist pattern: {pattern.pattern}"

        if self._level == GuardLevel.READONLY:
            return False, "Command execution not allowed in readonly mode"

        if self._level == GuardLevel.STANDARD:
            # Check if command starts with an allowed command
            cmd_base = command.strip().split()[0] if command.strip() else ""
            # Handle sudo prefix
            if cmd_base == "sudo" and len(command.strip().split()) > 1:
                cmd_base = command.strip().split()[1]
            if cmd_base not in self._allowlist:
                return False, f"Command '{cmd_base}' not in allowlist for standard mode"

        # Dangerous mode: allowed (passed blocklist check)
        return True, "OK"

    def check_tool(self, tool_name: str) -> Tuple[bool, str]:
        """Check if a tool is allowed at current guard level. Returns (allowed, reason)."""
        readonly_tools = {'list_instances', 'check_status', 'get_server_info'}
        standard_tools = readonly_tools | {'run_command', 'get_logs'}
        dangerous_tools = standard_tools | {'transfer_file'}

        if self._level == GuardLevel.READONLY:
            if tool_name not in readonly_tools:
                return False, f"Tool '{tool_name}' not available in readonly mode"
        elif self._level == GuardLevel.STANDARD:
            if tool_name not in standard_tools:
                return False, f"Tool '{tool_name}' not available in standard mode"
        # Dangerous: all tools allowed

        return True, "OK"
