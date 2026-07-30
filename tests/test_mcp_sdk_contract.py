"""Guard the MCP SDK surface that :pymod:`servonaut.mcp.server` builds on.

``create_mcp_server`` registers its handlers with the low-level SDK's
decorator API::

    server = Server("servonaut", instructions=...)

    @server.list_tools()
    async def list_tools(): ...

    @server.call_tool()
    async def call_tool(name, arguments): ...

Nothing else in the suite executes that registration — the other MCP tests
import ``_dispatch_tool`` and the tools module directly, so the decorators
are never touched. That left a gap: SDK 2.x replaced this API with
constructor-based ``on_list_tools=`` / ``on_call_tool=`` handlers, and the
only symptom was ``'Server' object has no attribute 'list_tools'`` when a
user actually started the server. The suite stayed green throughout.

These tests are deliberately about the *SDK contract*, not our logic. They
run the same construction and registration a real start-up performs, without
initialising any services, so an incompatible SDK fails here instead of in
someone's terminal. When the port to 2.x happens, this file changes with it.
"""
from __future__ import annotations

import pytest

pytest.importorskip("mcp")


class TestServerConstruction:
    def test_server_accepts_name_and_instructions(self):
        """``Server(name, instructions=...)`` is the constructor we call."""
        from mcp.server import Server

        server = Server("servonaut-test", instructions="test instructions")
        assert server is not None

    def test_decorator_registration_is_available(self):
        """The decorator API must exist and accept our handler signatures.

        Mirrors ``create_mcp_server`` exactly: a nullary ``list_tools`` and a
        ``call_tool`` taking ``(name, arguments)``. A signature change on
        either one breaks dispatch just as surely as a missing attribute.
        """
        from mcp.server import Server

        server = Server("servonaut-test")

        @server.list_tools()
        async def list_tools():
            return []

        @server.call_tool()
        async def call_tool(name: str, arguments: dict):
            return []

        assert callable(list_tools)
        assert callable(call_tool)

    def test_initialization_options_are_buildable(self):
        """``run_server`` passes this into ``server.run`` on every start-up."""
        from mcp.server import Server

        server = Server("servonaut-test")
        assert server.create_initialization_options() is not None


class TestStdioTransport:
    def test_stdio_server_is_importable(self):
        """``run_server`` imports this lazily, so a move would surface late."""
        from mcp.server.stdio import stdio_server

        assert stdio_server is not None


class TestToolTypes:
    def test_tool_and_text_content_are_importable(self):
        """``tool_schemas`` builds ``Tool``; dispatch wraps results in ``TextContent``."""
        from mcp.types import TextContent, Tool

        assert Tool is not None
        assert TextContent is not None

    def test_tool_list_builds_against_the_installed_sdk(self):
        """The real schema registry must instantiate under this SDK.

        ``mcp_tool_list`` constructs one ``Tool`` per entry, so a change to
        that model's required fields shows up here rather than at start-up.
        """
        from servonaut.mcp.tool_schemas import mcp_tool_list

        tools = mcp_tool_list(
            have_ovh=False,
            have_hetzner=False,
            have_ip_ban=False,
            have_memory=False,
        )
        assert len(tools) > 0
        for tool in tools:
            assert tool.name
            # Assert through the serialised wire form rather than attribute
            # access. 1.x names the field ``inputSchema``; 2.x renames it
            # ``input_schema`` behind that alias, so ``tool.inputSchema``
            # raises there — for a rename that does not actually break us,
            # since construction takes the alias and the wire output is
            # unchanged. A false failure here would drown out the real
            # incompatibility this file exists to catch. ``by_alias=True``
            # emits ``inputSchema`` identically on both lines.
            dumped = tool.model_dump(by_alias=True)
            assert dumped.get("inputSchema") is not None
