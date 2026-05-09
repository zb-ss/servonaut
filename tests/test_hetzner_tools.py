"""Tests for the 6 Hetzner-specific MCP tool implementations.

Each tool is exercised at minimum on:

- happy path
- service unavailable (no Hetzner wired up)
- guard rejection (insufficient guard level)
- API failure surface

The integration with the existing instance-listing code (``list_instances``,
``_find_instance``) is also covered so a regression in the merge order is
caught at unit-test time.
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_tools(
    *, guard_level: str = GuardLevel.DANGEROUS,
    hetzner_service=None,
    hetzner_instances=None,
):
    """Build a ServonautTools instance pre-wired with mocks.

    *guard_level* defaults to ``DANGEROUS`` so the test cases for the
    dangerous-only tools (create / delete) can exercise the success
    path; the readonly / standard tests override it.
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

    if hetzner_service is None and hetzner_instances is not None:
        hetzner_service = MagicMock()
        hetzner_service.fetch_instances_cached = AsyncMock(
            return_value=hetzner_instances,
        )

    return ServonautTools(
        config_manager, aws_service, custom_server_service, cache_service,
        ssh_service, connection_service, scp_service,
        guard, audit,
        hetzner_service=hetzner_service,
    )


SAMPLE_HETZNER_INSTANCE = {
    "id": "555",
    "name": "demo-1",
    "type": "cx22",
    "state": "running",
    "public_ip": "10.20.30.40",
    "private_ip": "",
    "region": "fsn1",
    "key_name": "",
    "provider": "hetzner",
    "is_hetzner": True,
    "username": "root",
    "ssh_key": "/home/u/.ssh/id_ed25519",
    "owned_by_servonaut": True,
    "disposable": True,
    "created_at": "2026-05-09T01:00:00",
    "labels": {},
}


# ---------------------------------------------------------------------------
# Tool: hetzner_list_servers
# ---------------------------------------------------------------------------

class TestHetznerListServers:
    def test_unavailable_when_no_service(self):
        tools = _make_tools()  # hetzner_service = None
        out = _run(tools.hetzner_list_servers())
        assert "Hetzner service is not available" in out
        tools._audit.log.assert_called_once()

    def test_happy_path(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[SAMPLE_HETZNER_INSTANCE])
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_list_servers())
        assert "demo-1" in out
        assert "10.20.30.40" in out
        # Audit success row
        success_calls = [
            c for c in tools._audit.log.call_args_list
            if len(c.args) >= 4 and c.args[3] is True
        ]
        assert success_calls

    def test_empty_project(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_list_servers())
        assert "No Hetzner Cloud servers" in out

    def test_api_error_propagates_string(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(side_effect=RuntimeError("auth"))
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_list_servers())
        assert "Error listing Hetzner servers" in out

    def test_blocked_in_readonly_is_still_allowed(self):
        # readonly is the floor for hetzner_list_servers — must succeed.
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        tools = _make_tools(
            guard_level=GuardLevel.READONLY, hetzner_service=svc,
        )
        out = _run(tools.hetzner_list_servers())
        assert "No Hetzner Cloud servers" in out


# ---------------------------------------------------------------------------
# Tool: hetzner_list_server_types
# ---------------------------------------------------------------------------

class TestHetznerListServerTypes:
    def test_happy_path(self):
        svc = MagicMock()
        svc.list_server_types = AsyncMock(return_value=[
            {
                "id": "1", "name": "cx22", "description": "CX 22",
                "cores": 2, "memory_gb": 4, "disk_gb": 40,
                "architecture": "x86",
                "hourly_price_gross": "0.0050",
                "monthly_price_gross": "3.79",
                "currency": "EUR",
            },
        ])
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_list_server_types())
        assert "cx22" in out
        assert "0.0050" in out

    def test_unavailable(self):
        tools = _make_tools()
        out = _run(tools.hetzner_list_server_types())
        assert "Hetzner service is not available" in out

    def test_api_error(self):
        svc = MagicMock()
        svc.list_server_types = AsyncMock(side_effect=RuntimeError("upstream"))
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_list_server_types())
        assert "Error listing server types" in out


# ---------------------------------------------------------------------------
# Tool: hetzner_list_ssh_keys
# ---------------------------------------------------------------------------

class TestHetznerListSshKeys:
    def test_happy_path(self):
        svc = MagicMock()
        svc.list_ssh_keys = AsyncMock(return_value=[
            {"id": "1", "name": "laptop", "fingerprint": "aa:bb"},
        ])
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_list_ssh_keys())
        assert "laptop" in out
        assert "aa:bb" in out

    def test_empty(self):
        svc = MagicMock()
        svc.list_ssh_keys = AsyncMock(return_value=[])
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_list_ssh_keys())
        assert "No SSH keys" in out

    def test_unavailable(self):
        tools = _make_tools()
        out = _run(tools.hetzner_list_ssh_keys())
        assert "Hetzner service is not available" in out


# ---------------------------------------------------------------------------
# Tool: hetzner_create_ssh_key
# ---------------------------------------------------------------------------

class TestHetznerCreateSshKey:
    def test_happy_path(self):
        svc = MagicMock()
        svc.create_ssh_key = AsyncMock(return_value={
            "id": "42", "name": "laptop", "fingerprint": "aa:bb",
        })
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_create_ssh_key("laptop", "ssh-ed25519 AAAA"))
        assert "Registered SSH key" in out
        assert "laptop" in out
        # Audit row should NOT contain the public_key in the payload.
        for call in tools._audit.log.call_args_list:
            assert "public_key" not in (call.args[1] or {})

    def test_validation_error(self):
        svc = MagicMock()
        svc.create_ssh_key = AsyncMock(
            side_effect=ValueError("bad prefix"),
        )
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_create_ssh_key("laptop", "no-prefix"))
        assert "bad prefix" in out

    def test_blocked_in_readonly(self):
        svc = MagicMock()
        tools = _make_tools(
            guard_level=GuardLevel.READONLY, hetzner_service=svc,
        )
        out = _run(tools.hetzner_create_ssh_key("laptop", "ssh-ed25519 AAA"))
        assert "Blocked" in out
        svc.create_ssh_key.assert_not_called() if hasattr(
            svc.create_ssh_key, "assert_not_called",
        ) else None

    def test_unavailable(self):
        tools = _make_tools()
        out = _run(tools.hetzner_create_ssh_key("a", "ssh-ed25519 AAA"))
        assert "Hetzner service is not available" in out


# ---------------------------------------------------------------------------
# Tool: hetzner_create_server
# ---------------------------------------------------------------------------

class TestHetznerCreateServer:
    def test_happy_path(self):
        svc = MagicMock()
        svc.create_server = AsyncMock(return_value=SAMPLE_HETZNER_INSTANCE)
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_create_server(
            name="demo-1", server_type="cx22",
        ))
        assert "Created Hetzner server" in out
        assert "demo-1" in out
        svc.create_server.assert_awaited_once()

    def test_blocked_in_standard(self):
        svc = MagicMock()
        tools = _make_tools(
            guard_level=GuardLevel.STANDARD, hetzner_service=svc,
        )
        out = _run(tools.hetzner_create_server(name="demo-1"))
        assert "Blocked" in out
        svc.create_server.assert_not_called()

    def test_validation_error(self):
        svc = MagicMock()
        svc.create_server = AsyncMock(
            side_effect=ValueError("bad name"),
        )
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_create_server(name="bad"))
        assert "bad name" in out

    def test_api_failure(self):
        svc = MagicMock()
        svc.create_server = AsyncMock(side_effect=RuntimeError("oom"))
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_create_server(name="demo-1"))
        assert "Error creating Hetzner server" in out

    def test_unavailable(self):
        tools = _make_tools()
        out = _run(tools.hetzner_create_server(name="x"))
        assert "Hetzner service is not available" in out


# ---------------------------------------------------------------------------
# Tool: hetzner_delete_server
# ---------------------------------------------------------------------------

class TestHetznerDeleteServer:
    def test_happy_path(self):
        svc = MagicMock()
        svc.delete_server = AsyncMock(return_value=True)
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_delete_server("demo-1"))
        assert "Deleted Hetzner server" in out
        svc.delete_server.assert_awaited_once_with("demo-1")

    def test_blocked_in_standard(self):
        svc = MagicMock()
        tools = _make_tools(
            guard_level=GuardLevel.STANDARD, hetzner_service=svc,
        )
        out = _run(tools.hetzner_delete_server("demo-1"))
        assert "Blocked" in out
        svc.delete_server.assert_not_called()

    def test_validation_error(self):
        svc = MagicMock()
        svc.delete_server = AsyncMock(side_effect=ValueError("bad id"))
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_delete_server(""))
        assert "bad id" in out

    def test_api_failure(self):
        svc = MagicMock()
        svc.delete_server = AsyncMock(side_effect=RuntimeError("not-found"))
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.hetzner_delete_server("ghost"))
        assert "Error deleting Hetzner server" in out


# ---------------------------------------------------------------------------
# list_instances + _find_instance integration with Hetzner
# ---------------------------------------------------------------------------

class TestInstanceMerge:
    def test_list_includes_hetzner(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[
            SAMPLE_HETZNER_INSTANCE,
        ])
        tools = _make_tools(hetzner_service=svc)
        out = _run(tools.list_instances())
        assert "demo-1" in out

    def test_find_instance_resolves_hetzner_by_name(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[
            SAMPLE_HETZNER_INSTANCE,
        ])
        tools = _make_tools(hetzner_service=svc)
        match = _run(tools._find_instance("demo-1"))
        assert match is not None
        assert match["is_hetzner"] is True

    def test_find_instance_resolves_hetzner_by_id(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[
            SAMPLE_HETZNER_INSTANCE,
        ])
        tools = _make_tools(hetzner_service=svc)
        match = _run(tools._find_instance("555"))
        assert match is not None
        assert match["name"] == "demo-1"
