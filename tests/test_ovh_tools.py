"""Tests for the 5 new OVH MCP tool implementations.

Covers ``ovh_create_instance``, ``ovh_delete_instance``, and the three
power-management tools (``ovh_start_instance`` / ``ovh_stop_instance``
/ ``ovh_reboot_instance``).

For each tool we assert: service-unavailable handling, guard rejection
at the wrong tier, dispatch to the right underlying service method,
and that error paths surface a useful message + write a failure audit
row. The state-aware UI logic on top (which provider_type can call
which tool) is enforced by ``OVHManagerScreen``; this layer just
proxies whatever the screen / agent passes through.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AppConfig, MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools


def _run(coro):
    return asyncio.run(coro)


def _make_tools(
    *,
    guard_level: str = GuardLevel.DANGEROUS,
    ovh_service=None,
    ovh_cloud_service=None,
):
    """Construct a ServonautTools wired with mocked services.

    ``ovh_service`` covers start/stop/reboot (those route through
    ``OVHService``). ``ovh_cloud_service`` covers create/delete
    (those route through ``OVHCloudService``). They're independent —
    each test wires only what it needs.
    """
    config = AppConfig(mcp=MCPConfig(guard_level=guard_level))
    config_manager = MagicMock()
    config_manager.get.return_value = config

    aws_service = MagicMock()
    aws_service.fetch_instances_cached = AsyncMock(return_value=[])
    custom_server_service = MagicMock()
    custom_server_service.list_as_instances.return_value = []
    cache_service = MagicMock()
    ssh_service = MagicMock()
    connection_service = MagicMock()
    scp_service = MagicMock()
    audit = MagicMock()
    audit.log = MagicMock()
    guard = CommandGuard(config.mcp, config_manager)

    return ServonautTools(
        config_manager, aws_service, custom_server_service, cache_service,
        ssh_service, connection_service, scp_service,
        guard, audit,
        ovh_service=ovh_service,
        ovh_cloud_service=ovh_cloud_service,
    )


# ---------------------------------------------------------------------------
# Tool: ovh_create_instance
# ---------------------------------------------------------------------------

class TestOVHCreateInstance:
    def test_unavailable_when_no_cloud_service(self):
        tools = _make_tools()  # ovh_cloud_service = None
        out = _run(tools.ovh_create_instance(
            project_id="P", name="n", flavor_id="f", image_id="i", region="r",
        ))
        assert "OVHcloud is not configured" in out
        tools._audit.log.assert_called_once()

    def test_blocked_in_standard_mode(self):
        # create_instance lives at the dangerous tier — standard must
        # refuse it (it costs money and provisions a new resource).
        cloud = MagicMock()
        cloud.create_instance = AsyncMock()
        tools = _make_tools(
            guard_level=GuardLevel.STANDARD, ovh_cloud_service=cloud,
        )
        out = _run(tools.ovh_create_instance(
            project_id="P", name="n", flavor_id="f", image_id="i", region="r",
        ))
        assert out.startswith("Blocked: ")
        cloud.create_instance.assert_not_called()

    def test_happy_path(self):
        cloud = MagicMock()
        cloud.create_instance = AsyncMock(return_value={
            "id": "i-123", "name": "demo-1", "status": "BUILD",
        })
        tools = _make_tools(ovh_cloud_service=cloud)
        out = _run(tools.ovh_create_instance(
            project_id="P", name="demo-1", flavor_id="s1-2",
            image_id="ub-22", region="GRA11", ssh_key_id="key-1",
        ))
        assert "demo-1" in out
        assert "i-123" in out
        cloud.create_instance.assert_awaited_once()
        kwargs = cloud.create_instance.await_args.kwargs
        assert kwargs["project_id"] == "P"
        assert kwargs["ssh_key_id"] == "key-1"

    def test_validation_error_wrapped(self):
        cloud = MagicMock()
        cloud.create_instance = AsyncMock(
            side_effect=ValueError("project_id must be alphanumeric"),
        )
        tools = _make_tools(ovh_cloud_service=cloud)
        out = _run(tools.ovh_create_instance(
            project_id="bad/", name="n", flavor_id="f", image_id="i", region="r",
        ))
        assert out.startswith("Error:")
        last_log = tools._audit.log.call_args_list[-1]
        assert last_log.args[3] is False
        assert "validation" in last_log.args[4]

    def test_api_error_wrapped(self):
        cloud = MagicMock()
        cloud.create_instance = AsyncMock(
            side_effect=RuntimeError("ovh 503"),
        )
        tools = _make_tools(ovh_cloud_service=cloud)
        out = _run(tools.ovh_create_instance(
            project_id="P", name="n", flavor_id="f", image_id="i", region="r",
        ))
        assert "ovh 503" in out
        last_log = tools._audit.log.call_args_list[-1]
        assert last_log.args[3] is False
        assert "api_error" in last_log.args[4]


# ---------------------------------------------------------------------------
# Tool: ovh_delete_instance
# ---------------------------------------------------------------------------

class TestOVHDeleteInstance:
    def test_unavailable_when_no_cloud_service(self):
        tools = _make_tools()
        out = _run(tools.ovh_delete_instance(project_id="P", instance_id="i-1"))
        assert "OVHcloud is not configured" in out

    def test_blocked_in_standard_mode(self):
        cloud = MagicMock()
        cloud.delete_instance = AsyncMock()
        tools = _make_tools(
            guard_level=GuardLevel.STANDARD, ovh_cloud_service=cloud,
        )
        out = _run(tools.ovh_delete_instance(project_id="P", instance_id="i-1"))
        assert out.startswith("Blocked: ")
        cloud.delete_instance.assert_not_called()

    def test_happy_path(self):
        cloud = MagicMock()
        cloud.delete_instance = AsyncMock(return_value=True)
        tools = _make_tools(ovh_cloud_service=cloud)
        out = _run(tools.ovh_delete_instance(project_id="P", instance_id="i-1"))
        assert "Deleted" in out
        cloud.delete_instance.assert_awaited_once_with("P", "i-1")


# ---------------------------------------------------------------------------
# Tool: ovh_start_instance / ovh_stop_instance / ovh_reboot_instance
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tool_name,service_method,verb", [
    ("ovh_start_instance",  "start_instance",  "started"),
    ("ovh_stop_instance",   "stop_instance",   "stop sent"),
    ("ovh_reboot_instance", "reboot_instance", "reboot sent"),
])
class TestOVHPowerTools:
    def test_unavailable_when_no_service(
        self, tool_name, service_method, verb,
    ):
        tools = _make_tools()  # ovh_service = None
        out = _run(getattr(tools, tool_name)("i-1", "cloud"))
        assert "OVHcloud is not configured" in out

    def test_dispatches_to_service_with_provider_type(
        self, tool_name, service_method, verb,
    ):
        svc = MagicMock()
        # Stub all three so a misrouted tool surfaces as "wrong method
        # called" rather than a silent pass.
        for m in ("start_instance", "stop_instance", "reboot_instance"):
            setattr(svc, m, AsyncMock(return_value=True))
        tools = _make_tools(ovh_service=svc)
        out = _run(getattr(tools, tool_name)("project-x/i-99", "cloud"))
        assert verb in out
        assert "project-x/i-99" in out
        getattr(svc, service_method).assert_awaited_once_with(
            "project-x/i-99", "cloud",
        )
        for other in ("start_instance", "stop_instance", "reboot_instance"):
            if other != service_method:
                getattr(svc, other).assert_not_called()

    def test_api_error_wrapped(
        self, tool_name, service_method, verb,
    ):
        svc = MagicMock()
        setattr(
            svc, service_method,
            AsyncMock(side_effect=RuntimeError("ovh 502")),
        )
        tools = _make_tools(ovh_service=svc)
        out = _run(getattr(tools, tool_name)("i-1", "vps"))
        assert "ovh 502" in out
        last_log = tools._audit.log.call_args_list[-1]
        assert last_log.args[3] is False
        assert "api_error" in last_log.args[4]

    def test_blocked_in_readonly_mode(
        self, tool_name, service_method, verb,
    ):
        # Power tools live at the standard tier — readonly must refuse.
        svc = MagicMock()
        setattr(svc, service_method, AsyncMock(return_value=True))
        tools = _make_tools(
            guard_level=GuardLevel.READONLY, ovh_service=svc,
        )
        out = _run(getattr(tools, tool_name)("i-1", "cloud"))
        assert out.startswith("Blocked: ")
        getattr(svc, service_method).assert_not_called()
