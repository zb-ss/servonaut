"""CI gate: CLI tool inventory must match server's catalog.

Locked formula from agent-bus thread d59dd956-...:
    set(catalog) == set(tool_schemas.TOOL_SCHEMAS) - CATALOG_EXCLUDED_CLI_ONLY

The fixture mirrors PR1''s 60-entry seed verbatim. When the server
catalog changes, the fixture updates in the same PR. Drift fails CI
loudly.
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


_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "server_catalog_v1.json"


def _server_catalog_names() -> set[str]:
    data = json.loads(_FIXTURE.read_text())
    return set(data["tools"])


def test_catalog_matches_cli_minus_local_only():
    cli_tools = set(tool_schemas.TOOL_SCHEMAS.keys())
    expected = cli_tools - CATALOG_EXCLUDED_CLI_ONLY
    actual = _server_catalog_names()
    missing = expected - actual
    extra = actual - expected
    assert not missing and not extra, (
        f"Catalog drift detected.\n"
        f"  CLI has, catalog missing: {sorted(missing)}\n"
        f"  Catalog has, CLI missing: {sorted(extra)}"
    )


def test_catalog_fixture_has_60_entries():
    """Sanity check: the fixture must contain exactly 60 names."""
    names = _server_catalog_names()
    assert len(names) == 60, (
        f"Expected 60 catalog entries, got {len(names)}: {sorted(names)}"
    )


def test_cli_local_only_tools_not_in_catalog():
    """The 7 CLI-local-only tools must NOT appear in the server catalog."""
    catalog = _server_catalog_names()
    in_catalog = CATALOG_EXCLUDED_CLI_ONLY & catalog
    assert not in_catalog, (
        f"CLI-local-only tools found in server catalog: {sorted(in_catalog)}"
    )
