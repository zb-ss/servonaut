"""Chat tool definitions and executor for the agentic chat loop.

Defines the tools the LLM can call and dispatches execution to the
appropriate Servonaut services.  Reuses the MCP ``CommandGuard`` for
safety enforcement.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from servonaut.config.schema import MCPConfig
from servonaut.mcp.guards import CommandGuard
from servonaut.utils.ssh_utils import run_ssh_subprocess

logger = logging.getLogger(__name__)

MAX_OUTPUT_LINES = 150
MAX_OUTPUT_CHARS = 20_000

# ---------------------------------------------------------------------------
# Tool definitions (provider-agnostic)
# ---------------------------------------------------------------------------

CHAT_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "list_instances",
        "description": (
            "List all servers (AWS EC2 instances and custom servers). "
            "Optionally filter by region or state."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "region": {
                    "type": "string",
                    "description": "AWS region filter (e.g. us-east-1). Empty for all.",
                },
                "state": {
                    "type": "string",
                    "description": "Instance state filter (running, stopped, etc). Empty for all.",
                },
            },
            "required": [],
        },
    },
    {
        "name": "check_status",
        "description": (
            "Get status details for a specific server: state, IPs, type, region. "
            "Accepts instance ID or server name."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID (e.g. i-abc123) or server name.",
                },
            },
            "required": ["instance_id"],
        },
    },
    {
        "name": "get_server_info",
        "description": (
            "Get detailed server information: hostname, uptime, disk usage, memory. "
            "Connects via SSH to retrieve live data."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID or server name.",
                },
            },
            "required": ["instance_id"],
        },
    },
    {
        "name": "run_command",
        "description": (
            "Run a shell command on a remote server via SSH. "
            "Only safe read-only commands are allowed in standard mode."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID or server name.",
                },
                "command": {
                    "type": "string",
                    "description": "Shell command to execute remotely.",
                },
            },
            "required": ["instance_id", "command"],
        },
    },
    {
        "name": "get_logs",
        "description": (
            "Get log file contents from a remote server. "
            "Reads the last N lines of a log file via SSH."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID or server name.",
                },
                "log_path": {
                    "type": "string",
                    "description": "Path to log file (default: /var/log/syslog).",
                },
                "lines": {
                    "type": "integer",
                    "description": "Number of lines to retrieve (default: 100).",
                },
            },
            "required": ["instance_id"],
        },
    },
]


class ChatToolExecutor:
    """Executes chat tool calls using Servonaut services.

    Uses the MCP ``CommandGuard`` to enforce safety levels.
    """

    def __init__(
        self,
        config_manager: Any,
        aws_service: Any,
        cache_service: Any,
        ssh_service: Any,
        connection_service: Any,
        guard_level: str = "standard",
    ) -> None:
        self._config_manager = config_manager
        self._aws_service = aws_service
        self._cache_service = cache_service
        self._ssh_service = ssh_service
        self._connection_service = connection_service

        mcp_config = config_manager.get().mcp
        guard_config = MCPConfig(
            guard_level=guard_level,
            command_blocklist=mcp_config.command_blocklist,
            command_allowlist=mcp_config.command_allowlist,
        )
        self._guard = CommandGuard(guard_config)

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Return tool definitions allowed at the current guard level."""
        tools = []
        for tool in CHAT_TOOLS:
            allowed, _ = self._guard.check_tool(tool["name"])
            if allowed:
                tools.append(tool)
        return tools

    async def execute(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Execute a tool call and return the text result."""
        allowed, reason = self._guard.check_tool(tool_name)
        if not allowed:
            return f"Blocked: {reason}"

        if status_callback:
            status_callback(f"Running {tool_name}...")

        handlers = {
            "list_instances": self._list_instances,
            "check_status": self._check_status,
            "get_server_info": self._get_server_info,
            "run_command": self._run_command,
            "get_logs": self._get_logs,
        }

        handler = handlers.get(tool_name)
        if not handler:
            return f"Unknown tool: {tool_name}"

        try:
            return await handler(**arguments)
        except Exception as exc:
            logger.exception("Tool execution error: %s", tool_name)
            return f"Error executing {tool_name}: {exc}"

    # ------------------------------------------------------------------
    # Tool handlers
    # ------------------------------------------------------------------

    async def _list_instances(self, region: str = "", state: str = "") -> str:
        instances = await self._aws_service.fetch_instances_cached()
        # Merge custom servers
        try:
            custom_svc = self._config_manager._custom_server_service
        except AttributeError:
            custom_svc = None

        if region:
            instances = [i for i in instances if i.get("region") == region]
        if state:
            instances = [i for i in instances if i.get("state") == state]

        return self._format_instances(instances)

    async def _check_status(self, instance_id: str = "") -> str:
        if not instance_id:
            return "Error: instance_id is required"
        instance = await self._find_instance(instance_id)
        if not instance:
            return f"Instance not found: {instance_id}"

        lines = [
            f"Instance:   {instance.get('id', '')}",
            f"Name:       {instance.get('name', '')}",
            f"State:      {instance.get('state', '')}",
            f"Type:       {instance.get('type', '')}",
            f"Region:     {instance.get('region', '')}",
            f"Public IP:  {instance.get('public_ip') or '-'}",
            f"Private IP: {instance.get('private_ip') or '-'}",
            f"Key Name:   {instance.get('key_name') or '-'}",
        ]
        if instance.get("is_custom"):
            lines.append(f"Provider:   {instance.get('provider', '')}")
            lines.append(f"Group:      {instance.get('group', '')}")
        return "\n".join(lines)

    async def _get_server_info(self, instance_id: str = "") -> str:
        if not instance_id:
            return "Error: instance_id is required"
        command = "hostname && uptime && df -h && free -m"
        return await self._ssh_exec(instance_id, command)

    async def _run_command(self, instance_id: str = "", command: str = "") -> str:
        if not instance_id:
            return "Error: instance_id is required"
        if not command:
            return "Error: command is required"

        cmd_allowed, cmd_reason = self._guard.check_command(command)
        if not cmd_allowed:
            return f"Blocked: {cmd_reason}"

        return await self._ssh_exec(instance_id, command)

    async def _get_logs(
        self, instance_id: str = "", log_path: str = "/var/log/syslog", lines: int = 100
    ) -> str:
        if not instance_id:
            return "Error: instance_id is required"
        command = f"tail -n {int(lines)} {log_path}"
        return await self._ssh_exec(instance_id, command)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _ssh_exec(self, instance_id: str, command: str) -> str:
        """Execute a command on a remote instance via SSH."""
        instance = await self._find_instance(instance_id)
        if not instance:
            return f"Instance not found: {instance_id}"

        profile = self._connection_service.resolve_profile(instance)
        host = self._connection_service.get_target_host(instance, profile)
        proxy_args = self._connection_service.get_proxy_args(profile) if profile else []

        # Resolve username: custom server username > profile > default
        username = (
            instance.get("username")
            or (getattr(profile, "username", None) if profile else None)
            or self._config_manager.get().default_username
        )
        port = instance.get("port") if instance.get("is_custom") else None

        key_path = self._ssh_service.get_key_path(instance.get("id", ""))
        if not key_path and instance.get("key_name"):
            key_path = self._ssh_service.discover_key(instance["key_name"])
        if not key_path and instance.get("ssh_key"):
            key_path = instance["ssh_key"]

        ssh_cmd = self._ssh_service.build_ssh_command(
            host=host,
            username=username,
            key_path=key_path,
            proxy_args=proxy_args,
            remote_command=command,
            port=port,
        )

        try:
            stdout, stderr = await run_ssh_subprocess(ssh_cmd, timeout=60)
        except asyncio.TimeoutError:
            return "Error: Command timed out after 60 seconds"
        except Exception as exc:
            return f"Error: {exc}"

        output = stdout.decode("utf-8", errors="replace")
        lines_list = output.split("\n")
        if len(lines_list) > MAX_OUTPUT_LINES:
            output = (
                "\n".join(lines_list[:MAX_OUTPUT_LINES])
                + f"\n... (truncated, {len(lines_list)} total lines)"
            )

        if len(output) > MAX_OUTPUT_CHARS:
            output = output[:MAX_OUTPUT_CHARS] + f"\n... (truncated at {MAX_OUTPUT_CHARS} chars)"

        if stderr:
            err_text = stderr.decode("utf-8", errors="replace").strip()
            if err_text:
                output += f"\nSTDERR:\n{err_text}"

        return output

    async def _find_instance(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Find instance by ID, name, or IP address from cache."""
        instances = await self._aws_service.fetch_instances_cached()
        # Also include custom servers from the app instance list
        try:
            from servonaut.services.custom_server_service import CustomServerService
            custom_svc = CustomServerService(self._config_manager)
            instances = list(instances) + custom_svc.list_as_instances()
        except Exception:
            pass

        needle = instance_id.strip()
        for inst in instances:
            if inst.get("id") == needle or inst.get("name") == needle:
                return inst
            if inst.get("public_ip") == needle or inst.get("private_ip") == needle:
                return inst
        return None

    def _format_instances(self, instances: List[Dict[str, Any]]) -> str:
        if not instances:
            return "No instances found."
        lines = [
            f"{'Name':<30} {'ID':<20} {'State':<10} {'Public IP':<16} {'Region':<14}"
        ]
        lines.append("-" * 90)
        for i in instances:
            lines.append(
                f"{(i.get('name') or ''):<30} "
                f"{i.get('id', ''):<20} "
                f"{i.get('state', ''):<10} "
                f"{(i.get('public_ip') or '-'):<16} "
                f"{i.get('region', ''):<14}"
            )
        return "\n".join(lines)
