"""MCP server for Servonaut using stdio transport."""
from __future__ import annotations

import logging
import sys

logger = logging.getLogger(__name__)


def create_mcp_server():
    """Create and configure the MCP server."""
    try:
        from mcp.server import Server
        from mcp.types import Tool, TextContent
    except ImportError:
        logger.error("MCP SDK not installed. Install with: pip install 'servonaut[mcp]'")
        sys.exit(1)

    from servonaut.config.manager import ConfigManager
    from servonaut.services.cache_service import CacheService
    from servonaut.services.aws_service import AWSService
    from servonaut.services.ssh_service import SSHService
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.scp_service import SCPService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.mcp.guards import CommandGuard
    from servonaut.mcp.audit import AuditTrail
    from servonaut.mcp.tools import ServonautTools

    # Initialize services (headless — no TUI)
    config_manager = ConfigManager()
    config = config_manager.get()
    cache_service = CacheService(ttl_seconds=config.cache_ttl_seconds)
    aws_service = AWSService(cache_service)
    custom_server_service = CustomServerService(config_manager)
    ssh_service = SSHService(config_manager)
    connection_service = ConnectionService(config_manager)
    scp_service = SCPService()

    guard = CommandGuard(config.mcp, config_manager)
    audit = AuditTrail(config.mcp.audit_path)

    # OVH service — optional, only if configured and enabled
    ovh_service = None
    try:
        ovh_config = config.ovh
        if ovh_config.enabled and (ovh_config.application_key or ovh_config.client_id):
            from servonaut.services.ovh_service import OVHService
            ovh_service = OVHService(ovh_config)
            logger.info("OVH service initialized for MCP")
    except ImportError:
        logger.warning("python-ovh not installed; OVH provider unavailable in MCP")
    except Exception as e:
        logger.error("Failed to initialize OVH service for MCP: %s", e)

    tools = ServonautTools(
        config_manager, aws_service, custom_server_service, cache_service,
        ssh_service, connection_service, scp_service,
        guard, audit,
        ovh_service=ovh_service,
    )

    server = Server("servonaut")

    @server.list_tools()
    async def list_tools():
        return [
            Tool(name="list_instances", description="List all managed server instances (AWS EC2, custom servers)", inputSchema={
                "type": "object",
                "properties": {
                    "region": {"type": "string", "description": "Filter by region or provider (e.g. 'us-east-1', 'custom')"},
                    "state": {"type": "string", "description": "Instance state filter"},
                },
            }),
            Tool(name="run_command", description="Run command on any managed instance via SSH", inputSchema={
                "type": "object",
                "properties": {
                    "instance_id": {"type": "string", "description": "Instance ID, name, or custom server name"},
                    "command": {"type": "string", "description": "Command to execute"},
                },
                "required": ["instance_id", "command"],
            }),
            Tool(name="get_logs", description="Get log file content from any managed instance", inputSchema={
                "type": "object",
                "properties": {
                    "instance_id": {"type": "string", "description": "Instance ID, name, or custom server name"},
                    "log_path": {"type": "string", "description": "Log file path", "default": "/var/log/syslog"},
                    "lines": {"type": "integer", "description": "Number of lines to retrieve", "default": 100},
                },
                "required": ["instance_id"],
            }),
            Tool(name="check_status", description="Check status of any managed instance", inputSchema={
                "type": "object",
                "properties": {"instance_id": {"type": "string", "description": "Instance ID, name, or custom server name"}},
                "required": ["instance_id"],
            }),
            Tool(name="get_server_info", description="Get detailed server info from any managed instance", inputSchema={
                "type": "object",
                "properties": {"instance_id": {"type": "string", "description": "Instance ID, name, or custom server name"}},
                "required": ["instance_id"],
            }),
            Tool(name="transfer_file", description="Transfer file via SCP to/from any managed instance", inputSchema={
                "type": "object",
                "properties": {
                    "instance_id": {"type": "string", "description": "Instance ID, name, or custom server name"},
                    "local_path": {"type": "string"},
                    "remote_path": {"type": "string"},
                    "direction": {"type": "string", "enum": ["upload", "download"]},
                },
                "required": ["instance_id", "local_path", "remote_path", "direction"],
            }),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        handler = {
            'list_instances': tools.list_instances,
            'run_command': tools.run_command,
            'get_logs': tools.get_logs,
            'check_status': tools.check_status,
            'get_server_info': tools.get_server_info,
            'transfer_file': tools.transfer_file,
        }.get(name)

        if not handler:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

        result = await handler(**arguments)
        return [TextContent(type="text", text=result)]

    return server


async def run_server() -> None:
    """Run the MCP server with stdio transport."""
    try:
        from mcp.server.stdio import stdio_server
    except ImportError:
        logger.error("MCP SDK not installed. Install with: pip install 'servonaut[mcp]'")
        sys.exit(1)

    server = create_mcp_server()

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
