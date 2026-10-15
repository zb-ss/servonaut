"""Team shared servers listed beside the user's own servers.

A team's shared server becomes a server-list row (``shared_row``); one that
is also one of the user's own servers is listed once, as the user's own row
marked as shared (``fold_shared``).
"""
from __future__ import annotations

import asyncio
import copy
from types import SimpleNamespace

import pytest
from textual.app import App, ComposeResult

from servonaut.screens._demo_resolve import replace_instances
from servonaut.services.redaction_service import RedactionService
from servonaut.services.shared_servers import (
    SHARED_STATE,
    as_shared_row,
    fold_shared,
    fold_shared_rows,
    load_shared_servers,
    shared_row,
)
from servonaut.utils.instance_resolver import (
    AmbiguousInstanceError,
    describe_candidate,
    is_aws_row,
    resolve_unique,
)
from servonaut.widgets.instance_table import SHARED_MARK, InstanceTable

TEAM = {"slug": "ops", "name": "Ops"}


def _server(**changes):
    server = {
        "id": "srv-1",
        "name": "web-1",
        "hostname": "web.example.com",
        "port": 2222,
        "login_user": "deploy",
        "username": "deploy",
        "instance_id": None,
        "region": "eu-west-1",
        "status": "active",
        "credential_binding": {"source": "servonaut_vault", "vault_id": "v-1"},
        "ssh_ca": {"enrolled": True},
    }
    server.update(changes)
    return server


def _own(**changes):
    row = {
        "id": "i-0abc", "name": "app-1", "state": "running",
        "public_ip": "9.9.9.9", "private_ip": "10.0.0.5", "provider": "AWS",
    }
    row.update(changes)
    return row


class TestSharedRow:
    def test_fills_the_fields_every_connection_path_reads(self):
        row = shared_row(_server(), TEAM)

        assert row["id"] == "srv-1"
        assert row["name"] == "web-1"
        assert row["public_ip"] == row["private_ip"] == "web.example.com"
        assert row["username"] == "deploy"
        assert row["port"] == 2222
        assert row["state"] == SHARED_STATE
        assert row["provider"] == "Team Ops"
        assert row["is_shared"] is True
        assert row["team_slug"] == "ops"
        assert row["team_name"] == "Ops"

    def test_keeps_the_team_record_that_drives_the_connection(self):
        row = shared_row(_server(), TEAM)

        assert row["credential_binding"] == {"source": "servonaut_vault", "vault_id": "v-1"}
        assert row["ssh_ca"] == {"enrolled": True}

    def test_never_changes_the_record_it_was_given(self):
        server = _server()
        before = copy.deepcopy(server)
        shared_row(server, TEAM)["credential_binding"]["vault_id"] = "changed"
        assert server == before

    @pytest.mark.parametrize("port", [None, 0, 70000, True, "22"])
    def test_a_missing_or_invalid_port_is_the_ssh_default(self, port):
        assert shared_row(_server(port=port), TEAM)["port"] == 22

    def test_a_team_without_a_name_is_shown_by_its_slug(self):
        assert shared_row(_server(), {"slug": "ops"})["provider"] == "Team ops"

    def test_is_never_taken_for_an_aws_instance(self):
        assert not is_aws_row(shared_row(_server(), TEAM))
        assert is_aws_row(_own())

    def test_a_vault_target_record_becomes_a_row_with_its_host(self):
        target = {**_server(), "is_shared": True, "team_slug": "ops"}
        row = as_shared_row(target)
        assert row["public_ip"] == "web.example.com"
        assert row["team_slug"] == "ops"
        assert as_shared_row(row) == row


class TestFoldShared:
    def test_a_shared_copy_of_an_own_server_is_listed_once_as_the_own_row(self):
        own = _own()
        shared = shared_row(_server(instance_id="i-0abc"), TEAM)

        listed, shared_by = fold_shared([own, shared])

        assert listed == [own]
        assert shared_by == {id(own): ["Ops"]}

    def test_matches_the_public_address_and_port(self):
        own = _own(public_ip="web.example.com", port=2222, is_custom=True)
        listed, shared_by = fold_shared([own, shared_row(_server(), TEAM)])
        assert listed == [own]
        assert shared_by[id(own)] == ["Ops"]

    def test_a_different_port_on_the_same_host_is_another_server(self):
        own = _own(public_ip="web.example.com", is_custom=True)  # port 22
        assert len(fold_shared_rows([own, shared_row(_server(), TEAM)])) == 2

    def test_private_addresses_are_never_compared(self):
        own = _own(public_ip="", private_ip="10.0.0.5")
        shared = shared_row(_server(hostname="10.0.0.5", port=22), TEAM)
        assert len(fold_shared_rows([own, shared])) == 2

    def test_two_teams_sharing_one_own_server_are_both_named(self):
        own = _own()
        rows = [
            own,
            shared_row(_server(instance_id="i-0abc"), TEAM),
            shared_row(_server(id="srv-2", instance_id="i-0abc"), {"slug": "dev", "name": "Dev"}),
        ]
        listed, shared_by = fold_shared(rows)
        assert listed == [own]
        assert shared_by[id(own)] == ["Ops", "Dev"]

    def test_a_server_only_the_team_has_is_listed_in_its_place(self):
        own = _own()
        shared = shared_row(_server(), TEAM)
        assert fold_shared_rows([own, shared]) == [own, shared]


class _Teams:
    def __init__(self, teams, servers, failing=()):
        self.teams = teams
        self.servers = servers
        self.failing = set(failing)
        self.team_lookups = 0

    async def list_teams(self):
        self.team_lookups += 1
        return self.teams

    async def list_shared_servers(self, slug):
        if slug in self.failing:
            raise RuntimeError("503 Service Unavailable")
        return [dict(server) for server in self.servers.get(slug, [])]


class TestLoadSharedServers:
    def test_lists_every_team_s_servers_as_rows(self):
        service = _Teams(
            [TEAM, {"slug": "dev", "name": "Dev"}],
            {"ops": [_server()], "dev": [_server(id="srv-2", name="build-1")]},
        )
        found = asyncio.run(load_shared_servers(service))
        assert [(row["team_slug"], row["name"]) for row in found.rows] == [
            ("ops", "web-1"), ("dev", "build-1"),
        ]
        assert [team["slug"] for team in found.teams] == ["ops", "dev"]
        assert found.problems == []

    def test_a_team_that_fails_is_reported_and_the_others_still_list(self):
        service = _Teams(
            [TEAM, {"slug": "dev", "name": "Dev"}],
            {"dev": [_server(id="srv-2", name="build-1")]},
            failing={"ops"},
        )
        found = asyncio.run(load_shared_servers(service))
        assert [row["name"] for row in found.rows] == ["build-1"]
        assert found.problems == ["team Ops: 503 Service Unavailable"]

    def test_a_known_team_list_is_not_asked_again(self):
        service = _Teams([TEAM], {"ops": [_server()]})
        asyncio.run(load_shared_servers(service, [TEAM]))
        assert service.team_lookups == 0


class TestReferences:
    def test_team_slash_name_picks_the_shared_server(self):
        own = _own(name="web-1")
        shared = shared_row(_server(), TEAM)
        assert resolve_unique("ops/web-1", [own, shared]) is shared

    def test_a_bare_name_both_have_lists_the_team_reference(self):
        own = _own(name="web-1")
        shared = shared_row(_server(), TEAM)
        with pytest.raises(AmbiguousInstanceError) as caught:
            resolve_unique("web-1", [own, shared])
        assert "ops/web-1 (srv-1, team)" in str(caught.value)
        assert describe_candidate(shared) == "ops/web-1 (srv-1, team)"


def _app(rows):
    return SimpleNamespace(instances=rows, demo_mode=False, redaction_service=None)


class TestFleetSlice:
    def test_refreshing_the_own_servers_keeps_the_shared_ones(self):
        app = _app([])
        replace_instances(app, "shared", [shared_row(_server(), TEAM)])
        replace_instances(app, None, [_own()])
        # The user's own servers first, the team's after them.
        assert [row["name"] for row in app.instances] == ["app-1", "web-1"]

    def test_the_shared_slice_is_replaced_on_its_own(self):
        app = _app([])
        replace_instances(app, None, [_own()])
        replace_instances(app, "shared", [shared_row(_server(), TEAM)])
        replace_instances(app, "shared", [])
        assert [row["name"] for row in app.instances] == ["app-1"]

    def test_a_full_fleet_with_shared_rows_replaces_them(self):
        app = _app([])
        replace_instances(app, "shared", [shared_row(_server(), TEAM)])
        replace_instances(app, None, [_own(), shared_row(_server(id="srv-2", name="db-1"), TEAM)])
        assert [row["name"] for row in app.instances] == ["app-1", "db-1"]

    def test_a_custom_server_refresh_leaves_the_shared_rows(self):
        app = _app([])
        replace_instances(app, "shared", [shared_row(_server(), TEAM)])
        replace_instances(app, "custom", [{"id": "custom-x", "name": "x", "is_custom": True}])
        assert {row["name"] for row in app.instances} == {"web-1", "x"}


class TestDemoMode:
    def test_the_team_name_host_and_login_get_stand_ins(self):
        row = shared_row(
            _server(hostname="web.acme-corp.io", login_user="acme-admin", username="acme-admin"),
            {"slug": "acme", "name": "Acme Platform"},
        )
        RedactionService().redact_instance(row)

        shown = repr(row).lower()
        assert "acme-corp" not in shown
        assert "acme platform" not in shown
        assert "acme-admin" not in shown
        assert row["provider"].startswith("Team ")
        # The slug is how the team API is addressed; it is never displayed.
        assert row["team_slug"] == "acme"

    def test_a_shared_copy_of_an_own_server_still_folds(self):
        redaction = RedactionService()
        own = _own(id="i-0123456789abcdef0")
        shared = shared_row(_server(instance_id="i-0123456789abcdef0"), TEAM)
        redaction.redact_instance(own)
        redaction.redact_instance(shared)
        assert fold_shared_rows([own, shared]) == [own]


class _Host(App):
    def compose(self) -> ComposeResult:
        yield InstanceTable()


def _cell_text(table: InstanceTable, row: int, column: str) -> str:
    return str(table.get_cell_at((row, [c.key for c in table._shown_columns].index(column))))


@pytest.mark.asyncio
async def test_the_table_lists_a_shared_own_server_once_with_a_mark() -> None:
    own = _own(name="app-1", id="i-0abc")
    rows = [
        own,
        shared_row(_server(instance_id="i-0abc", name="app-shared"), TEAM),
        shared_row(_server(id="srv-2", name="build-1", hostname="build.example.com"), TEAM),
    ]
    app = _Host()
    async with app.run_test(size=(220, 12)) as pilot:
        table = app.query_one(InstanceTable)
        table.populate(rows)
        await pilot.pause()

        assert table.row_count == 2
        assert _cell_text(table, 0, "name") == f"app-1{SHARED_MARK}"
        assert _cell_text(table, 1, "name") == "build-1"
        assert _cell_text(table, 1, "provider") == "Team Ops"
        assert _cell_text(table, 1, "state") == SHARED_STATE

        table.filter("shared")
        assert [row["name"] for row in table._filtered_instances] == ["app-1", "build-1"]
        table.filter("ops")
        assert [row["name"] for row in table._filtered_instances] == ["app-1", "build-1"]
        table.filter("app-1")
        assert [row["name"] for row in table._filtered_instances] == ["app-1"]


# ---------------------------------------------------------------------------
# Every connection path: the team's login; the user's own configured key
# until a team key or certificate replaces it
# ---------------------------------------------------------------------------


def _connection_service(default_username: str = "ec2-user"):
    from unittest.mock import MagicMock

    from servonaut.config.schema import AppConfig
    from servonaut.services.connection_service import ConnectionService

    manager = MagicMock()
    manager.get.return_value = AppConfig(default_username=default_username)
    return ConnectionService(manager), manager


def _ssh_service():
    from unittest.mock import MagicMock

    ssh = MagicMock()
    ssh.get_key_path.return_value = "~/.ssh/default.pem"
    ssh.discover_key.return_value = None
    return ssh


def test_the_keyword_scan_uses_the_team_login():
    from servonaut.services.scan_service import ScanService

    connections, manager = _connection_service()
    scan = ScanService.__new__(ScanService)
    scan._config_manager = manager
    target = scan._resolve_target(shared_row(_server(), TEAM), _ssh_service(), connections)
    assert (target.host, target.username, target.key_path) == (
        "web.example.com", "deploy", "~/.ssh/default.pem",
    )


def test_file_transfers_use_the_team_login():
    from servonaut.screens.scp_transfer import SCPTransferScreen

    connections, manager = _connection_service()
    ssh = _ssh_service()
    screen = SimpleNamespace(app=SimpleNamespace(
        connection_service=connections, config_manager=manager, ssh_service=ssh,
    ))
    options = SCPTransferScreen._transfer_options(screen, shared_row(_server(), TEAM))
    assert (options["host"], options["username"], options["key_path"], options["port"]) == (
        "web.example.com", "deploy", "~/.ssh/default.pem", 2222,
    )


def test_the_file_browser_uses_the_team_login():
    from servonaut.screens.file_browser import build_remote_tree

    connections, manager = _connection_service()
    app = SimpleNamespace(
        connection_service=connections, config_manager=manager, ssh_service=_ssh_service(),
    )
    tree = build_remote_tree(app, shared_row(_server(), TEAM))
    assert (tree._username, tree._key_path, tree._port) == ("deploy", "~/.ssh/default.pem", 2222)


def test_server_memory_probes_use_the_team_login():
    from unittest.mock import AsyncMock, patch

    from servonaut.services.memory.service import MemoryService

    connections, manager = _connection_service()
    ssh = _ssh_service()
    ssh._config_manager = manager
    ssh.build_ssh_command.return_value = ["ssh"]
    memory = MemoryService.__new__(MemoryService)
    memory._ssh_service, memory._connection_service = ssh, connections
    memory._vault_runtime = memory._vault_leases = None
    # No team key here (a vault-bound server without a vault refuses to connect).
    runner = MemoryService._make_ssh_runner(memory, shared_row(_server(credential_binding=None), TEAM))
    with patch("servonaut.utils.ssh_utils.run_ssh_subprocess", new=AsyncMock(return_value=(b"Linux", b""))):
        asyncio.run(runner("uname"))
    command = ssh.build_ssh_command.call_args.kwargs
    assert (command["host"], command["username"], command["key_path"]) == (
        "web.example.com", "deploy", "~/.ssh/default.pem",
    )
    assert command.get("port") == 2222


def test_a_provider_listed_for_the_first_time_goes_before_the_team_servers():
    app = _app([])
    replace_instances(app, None, [_own()])
    replace_instances(app, "shared", [shared_row(_server(), TEAM)])
    replace_instances(app, "hetzner", [{"id": "42", "name": "cache-1", "is_hetzner": True}])
    assert [row["name"] for row in app.instances] == ["app-1", "cache-1", "web-1"]



def test_the_teams_key_login_stays_with_the_teams_key():
    row = shared_row(_server(username=None), TEAM)
    assert row["login_user"] == "deploy"
    assert row["username"] == ""

    from servonaut.services.shared_servers import shared_login

    assert shared_login(row, None, "ec2-user") == "ec2-user"
    assert shared_login(shared_row(_server(), TEAM), None, "ec2-user") == "deploy"
    rule = SimpleNamespace(username="admin")
    assert shared_login(shared_row(_server(), TEAM), rule, "ec2-user") == "admin"
