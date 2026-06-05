"""CI gate: CLI tool inventory must match the server's published catalog.

    set(catalog) == set(tool_schemas.TOOL_SCHEMAS)
                    - CATALOG_EXCLUDED_CLI_ONLY
                    - CATALOG_PENDING_SERVER

The fixture mirrors the server's tool catalog. When the server catalog
changes, the fixture updates in the same change. Drift fails CI loudly.
"""
from __future__ import annotations

import json
import pathlib

from servonaut.mcp import tool_schemas


CATALOG_EXCLUDED_CLI_ONLY: frozenset[str] = frozenset({
    "whoami",
    "relay_status",
    "relay_reconnect",
    "api_request",
    "mcp_tool_call",
    "check_status",
    "get_server_info",
})

# Tools that exist on the CLI (MCP + local chat dispatch) AHEAD of the server
# catalog — they run on the CLI's own SSH / boto3 / network surface, so they
# can ship CLI-first. This set is INTENTIONALLY TEMPORARY (unlike
# CATALOG_EXCLUDED_CLI_ONLY, which is permanently CLI-only): when a tool is
# added to the server catalog, move it out of here and into the fixture in the
# same change, keeping the gate honest both ways. Empty = fully converged.
CATALOG_PENDING_SERVER: frozenset[str] = frozenset()


_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "server_catalog_v1.json"


def _server_catalog_names() -> set[str]:
    data = json.loads(_FIXTURE.read_text())
    return set(data["tools"])


def test_catalog_matches_cli_minus_local_only():
    cli_tools = set(tool_schemas.TOOL_SCHEMAS.keys())
    expected = cli_tools - CATALOG_EXCLUDED_CLI_ONLY - CATALOG_PENDING_SERVER
    actual = _server_catalog_names()
    missing = expected - actual
    extra = actual - expected
    assert not missing and not extra, (
        f"Catalog drift detected.\n"
        f"  CLI has, catalog missing: {sorted(missing)}\n"
        f"  Catalog has, CLI missing: {sorted(extra)}"
    )


def test_pending_server_tools_not_yet_in_catalog():
    """Pending (CLI-ahead) tools must NOT already be in the server fixture.

    Guards the convergence protocol: once a tool is added to the catalog, this
    fails until it's also removed from CATALOG_PENDING_SERVER — forcing the two
    halves of the contract to move together.
    """
    catalog = _server_catalog_names()
    leaked = CATALOG_PENDING_SERVER & catalog
    assert not leaked, (
        f"Pending tools already in server catalog — move them out of "
        f"CATALOG_PENDING_SERVER and update the fixture: {sorted(leaked)}"
    )


def test_catalog_fixture_has_74_entries():
    """Sanity check: the fixture must contain exactly 74 names."""
    names = _server_catalog_names()
    assert len(names) == 74, (
        f"Expected 74 catalog entries, got {len(names)}: {sorted(names)}"
    )


def test_cli_local_only_tools_not_in_catalog():
    """The 7 CLI-local-only tools must NOT appear in the server catalog."""
    catalog = _server_catalog_names()
    in_catalog = CATALOG_EXCLUDED_CLI_ONLY & catalog
    assert not in_catalog, (
        f"CLI-local-only tools found in server catalog: {sorted(in_catalog)}"
    )
