"""MCP server for Servonaut using stdio transport.

Agents: when you plan to operate on a managed server, call
get_server_memory(instance_id) FIRST. The cached summary frequently answers
OS/runtime/service/web-stack questions without an SSH round-trip.
"""
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
    from servonaut.services.log_viewer_service import LogViewerService
    from servonaut.services.scp_service import SCPService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.auth_service import AuthService
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
    log_viewer_service = LogViewerService(config_manager)
    scp_service = SCPService()

    # MemoryService — headless init, same construction as app.py::_init_services
    memory_service = None
    try:
        from servonaut.services.memory import MemoryService
        from servonaut.services.memory.store import MemoryStore
        from servonaut.services.memory.redaction import default_redactor, noop_redactor
        from servonaut.services.memory.modules import build_default_probers
        _memory_redactor = (
            default_redactor if config.memory.redaction_enabled else noop_redactor
        )
        memory_service = MemoryService(
            store=MemoryStore(redactor=_memory_redactor),
            config=config.memory,
            probers=build_default_probers(
                log_viewer_service=log_viewer_service,
                ssh_service=ssh_service,
                connection_service=connection_service,
            ),
            ssh_service=ssh_service,
            connection_service=connection_service,
        )
        # Back-reference so LogViewerService.probe_log_paths can consult
        # cached memory.logs before spawning an SSH probe.
        log_viewer_service.set_memory_service(memory_service)
        logger.info("MemoryService initialized for MCP")
    except Exception as e:
        logger.warning("MemoryService unavailable in MCP: %s", e)

    guard = CommandGuard(config.mcp, config_manager)
    audit = AuditTrail(config.mcp.audit_path)
    auth_service = AuthService()

    # OVH service — optional, only if configured and enabled
    ovh_service = None
    ovh_monitoring_service = None
    ovh_ip_service = None
    ovh_snapshot_service = None
    ovh_dns_service = None
    ovh_billing_service = None
    try:
        ovh_config = config.ovh
        if ovh_config.enabled and (ovh_config.application_key or ovh_config.client_id):
            from servonaut.services.ovh_service import OVHService
            from servonaut.services.ovh_monitoring_service import OVHMonitoringService
            from servonaut.services.ovh_ip_service import OVHIPService
            from servonaut.services.ovh_snapshot_service import OVHSnapshotService
            from servonaut.services.ovh_dns_service import OVHDNSService
            from servonaut.services.ovh_billing_service import OVHBillingService
            ovh_service = OVHService(ovh_config)
            ovh_monitoring_service = OVHMonitoringService(ovh_service)
            ovh_ip_service = OVHIPService(ovh_service)
            ovh_snapshot_service = OVHSnapshotService(ovh_service)
            ovh_dns_service = OVHDNSService(ovh_service)
            ovh_billing_service = OVHBillingService(ovh_service)
            logger.info("OVH services initialized for MCP")
    except ImportError:
        logger.warning("python-ovh not installed; OVH provider unavailable in MCP")
    except Exception as e:
        logger.error("Failed to initialize OVH service for MCP: %s", e)

    tools = ServonautTools(
        config_manager, aws_service, custom_server_service, cache_service,
        ssh_service, connection_service, scp_service,
        guard, audit,
        ovh_service=ovh_service,
        ovh_monitoring_service=ovh_monitoring_service,
        ovh_ip_service=ovh_ip_service,
        ovh_snapshot_service=ovh_snapshot_service,
        ovh_dns_service=ovh_dns_service,
        ovh_billing_service=ovh_billing_service,
        auth_service=auth_service,
        memory_service=memory_service,
    )

    _instructions = (
        "Agents: when you plan to operate on a managed server, call "
        "get_server_memory(instance_id) FIRST. The cached summary frequently "
        "answers OS/runtime/service/web-stack questions without an SSH round-trip."
    )
    server = Server("servonaut", instructions=_instructions)

    from servonaut.mcp.tool_schemas import mcp_tool_list
    have_ovh = ovh_service is not None

    @server.list_tools()
    async def list_tools():
        return mcp_tool_list(have_ovh=have_ovh)

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        # Dispatch is just method lookup on the shared ServonautTools instance
        # — the tool name always matches the method name. tool_schemas.py is
        # the sole registry, so adding a new tool only needs an entry there
        # plus the implementation on ServonautTools.
        from servonaut.mcp.tool_schemas import TOOL_SCHEMAS
        if name not in TOOL_SCHEMAS:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
        handler = getattr(tools, name, None)
        if handler is None:
            return [TextContent(type="text", text=f"Tool handler not available: {name}")]
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
