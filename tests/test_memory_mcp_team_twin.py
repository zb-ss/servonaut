"""MCP memory tools work on the user's own row of a server a team also shares."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from servonaut.services.shared_servers import shared_row
from tests.test_memory_mcp_tools import _make_memory_service, _make_tools, run

TEAM = {"slug": "team-a", "name": "Team A", "id": 7}
OWN = {
    "id": "i-0abc0abc0abc0abc0", "name": "web-1", "state": "running",
    "public_ip": "9.9.9.9", "provider": "aws",
}
TWIN = shared_row(
    {"id": "11111111-aaaa-bbbb-cccc-000000000001", "name": "web-1",
     "hostname": "9.9.9.9", "instance_id": OWN["id"], "username": "deploy"},
    TEAM,
)


def _tools(memory, *, found=OWN):
    tools = _make_tools(memory_service=memory, instance_to_find=found)
    # The team's agent rules are covered by their own tests; here they allow the call.
    tools._apply_team_rules = False
    tools._directory.all_instances = AsyncMock(return_value=[OWN])
    tools._shared_server_rows = AsyncMock(return_value=[TWIN])
    return tools


def test_finding_given_a_team_reference_lands_on_the_own_row():
    memory = _make_memory_service()
    memory.remember_finding = MagicMock(return_value={"finding_id": "f_1", "auto_inject": False})
    tools = _tools(memory, found=None)
    run(tools.remember_server_finding("team-a/web-1", "t", "b"))
    assert memory.remember_finding.call_args.args[0]["id"] == OWN["id"]


def test_finding_given_a_share_id_lands_on_the_own_row():
    memory = _make_memory_service()
    memory.remember_finding = MagicMock(return_value={"finding_id": "f_1", "auto_inject": False})
    tools = _tools(memory, found=None)
    run(tools.remember_server_finding(TWIN["id"], "t", "b"))
    assert memory.remember_finding.call_args.args[0]["id"] == OWN["id"]


def test_a_shared_only_server_keeps_its_own_target():
    memory = _make_memory_service()
    memory.remember_finding = MagicMock(return_value={"finding_id": "f_1", "auto_inject": False})
    tools = _tools(memory, found=None)
    tools._directory.all_instances = AsyncMock(return_value=[])
    run(tools.remember_server_finding("team-a/web-1", "t", "b"))
    assert memory.remember_finding.call_args.args[0]["id"] == TWIN["id"]


def test_get_server_memory_by_name_still_returns_the_own_rows_memory():
    memory = _make_memory_service()
    tools = _tools(memory)
    run(tools.get_server_memory("web-1"))
    assert memory.get_all_modules.call_args.args[0] == OWN["id"]


def test_get_server_memory_given_a_team_reference_reads_the_own_rows_memory():
    memory = _make_memory_service()
    tools = _tools(memory, found=None)
    run(tools.get_server_memory("team-a/web-1"))
    assert memory.get_all_modules.call_args.args[0] == OWN["id"]


def _built_target(memory):
    return memory.build_report.call_args.args[0]["id"]


def test_build_given_a_team_reference_builds_the_own_row():
    memory = _make_memory_service()
    tools = _tools(memory, found=None)
    run(tools.build_server_memory("team-a/web-1"))
    assert _built_target(memory) == OWN["id"]


def test_refresh_given_a_share_id_builds_the_own_row():
    memory = _make_memory_service()
    tools = _tools(memory, found=None)
    run(tools.refresh_server_memory(TWIN["id"]))
    assert _built_target(memory) == OWN["id"]


def test_build_then_read_through_either_alias_reaches_the_same_record():
    memory = _make_memory_service()
    tools = _tools(memory, found=None)
    for alias in ("team-a/web-1", TWIN["id"]):
        memory.build_report.reset_mock()
        memory.get_all_modules.reset_mock()
        run(tools.build_server_memory(alias))
        run(tools.get_server_memory(alias))
        assert _built_target(memory) == memory.get_all_modules.call_args.args[0] == OWN["id"]


def test_a_shared_only_server_is_still_built_under_its_own_id():
    memory = _make_memory_service()
    tools = _tools(memory, found=None)
    tools._directory.all_instances = AsyncMock(return_value=[])
    run(tools.build_server_memory("team-a/web-1"))
    assert _built_target(memory) == TWIN["id"]


def test_build_keeps_the_opt_out_of_the_team_reference():
    memory = _make_memory_service()
    tools = _tools(memory, found=None)
    tools._config_manager.get().memory.is_instance_disabled = (
        lambda iid, name: iid == TWIN["id"]
    )
    out = run(tools.build_server_memory(TWIN["id"]))
    assert "opt_out" in out
    memory.build_report.assert_not_called()


def _listed_ids(out):
    import json

    return [entry["instance_id"] for entry in json.loads(out)]


def test_listing_leaves_out_the_team_copy_of_an_own_server():
    entries = [
        {"instance_id": OWN["id"], "name": "web-1", "provider": "aws"},
        {"instance_id": TWIN["id"], "name": "web-1", "provider": "team a"},
    ]
    memory = _make_memory_service(list_all_return=entries)
    memory.list_all = MagicMock(return_value=entries)
    tools = _tools(memory)
    tools._directory.cached_provider_rows = MagicMock(return_value=[OWN])
    tools._directory.custom_rows = MagicMock(return_value=[])
    assert _listed_ids(run(tools.list_server_memories())) == [OWN["id"]]


def test_listing_keeps_the_copy_of_a_shared_only_server():
    entries = [{"instance_id": TWIN["id"], "name": "web-1", "provider": "shared"}]
    memory = _make_memory_service(list_all_return=entries)
    memory.list_all = MagicMock(return_value=entries)
    tools = _tools(memory)
    tools._directory.cached_provider_rows = MagicMock(return_value=[])
    tools._directory.custom_rows = MagicMock(return_value=[])
    assert _listed_ids(run(tools.list_server_memories())) == [TWIN["id"]]


def test_listing_still_works_when_the_fleet_cannot_be_read():
    entries = [{"instance_id": OWN["id"], "name": "web-1", "provider": "aws"}]
    memory = _make_memory_service(list_all_return=entries)
    memory.list_all = MagicMock(return_value=entries)
    tools = _tools(memory)
    tools.connection_rows = AsyncMock(side_effect=RuntimeError("offline"))
    assert _listed_ids(run(tools.list_server_memories())) == [OWN["id"]]
