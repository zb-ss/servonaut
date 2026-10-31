"""Memory probes, log probes and keyword scans connect like the server list does.

A server of the user's own without a local key connects with a team's vault key
when a team shares it, and the hop to a bastion uses the bastion's vault key.
Both need the team rows and the fleet, which the services get from a rows
supplier that is asked per build (the rows change while the app runs).
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory import MemoryService
from servonaut.services.memory.store import MemoryStore
from servonaut.services.scan_service import ScanService
from tests.test_bastion_vault_hop import (
    APP, APP_RULE, BASTION, TEAM_BASTION, _Runtime, _hop, _service,
)
from tests.test_ssh_host_keys import (
    _proxy_command,
    known_hosts,  # noqa: F401 - fixture
    posix_hop,  # noqa: F401 - fixture
)
from tests.test_team_key_fallback import OWN, _team_row, lease  # noqa: F401 - fixture
from tests.test_vault_ssh_paths import _connection_service


def _memory_service(tmp_path, connection_service, ssh_service=None):
    ssh_service = ssh_service or MagicMock()
    # No key file for the key pair on this computer.
    ssh_service.get_key_path.return_value = None
    ssh_service.discover_key.return_value = None
    ssh_service.build_ssh_command.return_value = ["ssh", "host", "true"]
    return MemoryService(
        store=MemoryStore(root=tmp_path), config=MemoryConfig(),
        ssh_service=ssh_service, connection_service=connection_service,
    ), ssh_service


def _run_first_command(service, instance):
    async def go():
        # The runner imports run_ssh_subprocess when it is made.
        with patch("servonaut.utils.ssh_utils.run_ssh_subprocess", AsyncMock(return_value=(b"ok", b""))):
            runner = service._make_ssh_runner(instance)
            return await runner("uname -a")

    return asyncio.run(go())


def _supplier(team_rows=(), fleet_rows=None):
    calls = []

    def supply():
        calls.append(1)
        return list(team_rows), list(fleet_rows if fleet_rows is not None else team_rows)

    supply.calls = calls
    return supply


class TestMemoryRunner:
    def test_an_own_server_without_a_key_connects_with_the_teams_key(self, tmp_path, lease):  # noqa: F811
        service, ssh_service = _memory_service(tmp_path, _connection_service())
        service.set_vault_runtime(_TeamOnlyRuntime(lease))
        service.set_connection_rows(_supplier([_team_row()]))

        _run_first_command(service, dict(OWN))

        kwargs = ssh_service.build_ssh_command.call_args.kwargs
        assert kwargs["identity_agent"] == lease.identity_agent
        assert kwargs["username"] == "deploy"
        assert kwargs.get("key_path") is None

    def test_an_unrelated_team_row_is_never_used(self, tmp_path, lease):  # noqa: F811
        service, ssh_service = _memory_service(tmp_path, _connection_service())
        runtime = _TeamOnlyRuntime(lease)
        service.set_vault_runtime(runtime)
        other = _team_row(instance_id="i-other", hostname="8.8.8.8", id="srv-2")
        service.set_connection_rows(_supplier([other]))

        _run_first_command(service, dict(OWN))

        assert runtime.asked == [OWN["id"]]
        assert ssh_service.build_ssh_command.call_args.kwargs.get("identity_agent") is None

    def test_the_hop_uses_the_bastions_vault_key(self, tmp_path, known_hosts, posix_hop):  # noqa: F811
        hop = _hop(tmp_path)
        service, ssh_service = _memory_service(tmp_path, _service(APP_RULE))
        ssh_service.get_key_path.return_value = "/keys/app.pem"
        runtime = _Runtime({"i-0b": hop})
        service.set_vault_runtime(runtime)
        service.set_connection_rows(_supplier([], [APP, BASTION]))

        _run_first_command(service, dict(APP))

        proxy_args = ssh_service.build_ssh_command.call_args.kwargs["proxy_args"]
        assert f'IdentityAgent="{hop.identity_agent}"' in _proxy_command(proxy_args)
        assert runtime.asked.count("i-0b") == 1

    def test_the_hop_uses_the_teams_bastion_key(self, tmp_path, known_hosts, posix_hop):  # noqa: F811
        hop = _hop(tmp_path)
        service, ssh_service = _memory_service(tmp_path, _service(APP_RULE))
        ssh_service.get_key_path.return_value = "/keys/app.pem"
        service.set_vault_runtime(_Runtime({"srv-9": hop}))
        service.set_connection_rows(_supplier([TEAM_BASTION], [APP, BASTION, TEAM_BASTION]))

        _run_first_command(service, dict(APP))

        proxy_args = ssh_service.build_ssh_command.call_args.kwargs["proxy_args"]
        assert f'IdentityAgent="{hop.identity_agent}"' in _proxy_command(proxy_args)

    def test_the_rows_are_asked_per_runner_not_once(self, tmp_path, lease):  # noqa: F811
        service, _ = _memory_service(tmp_path, _connection_service())
        service.set_vault_runtime(_TeamOnlyRuntime(lease))
        supply = _supplier([_team_row()])
        service.set_connection_rows(supply)

        _run_first_command(service, dict(OWN))
        _run_first_command(service, dict(OWN))

        assert len(supply.calls) == 2

    def test_a_failing_supplier_leaves_the_connection_as_it_was(self, tmp_path, lease):  # noqa: F811
        service, ssh_service = _memory_service(tmp_path, _connection_service())
        service.set_vault_runtime(_TeamOnlyRuntime(lease))

        async def broken():
            raise RuntimeError("service down")

        service.set_connection_rows(broken)

        stdout, _stderr, code = _run_first_command(service, dict(OWN))

        assert code == 0 and stdout == "ok"
        assert ssh_service.build_ssh_command.call_args.kwargs.get("identity_agent") is None


class TestKeywordScan:
    def test_a_scan_connects_with_the_teams_key(self, lease):  # noqa: F811
        scan = ScanService(MagicMock())
        scan.set_vault_runtime(_TeamOnlyRuntime(lease))
        scan.set_connection_rows(_supplier([_team_row()]))
        ssh_service = MagicMock()
        ssh_service.get_key_path.return_value = None
        ssh_service.discover_key.return_value = None
        ssh_service.build_ssh_command.return_value = ["ssh"]
        connection_service = _connection_service()
        target = scan._resolve_target(dict(OWN), ssh_service, connection_service)

        target = asyncio.run(scan._with_vault(target, dict(OWN), connection_service))
        target.argv("ls")

        kwargs = ssh_service.build_ssh_command.call_args.kwargs
        assert kwargs["identity_agent"] == lease.identity_agent

    def test_an_unrelated_team_row_is_not_used_by_a_scan(self, lease):  # noqa: F811
        scan = ScanService(MagicMock())
        runtime = _TeamOnlyRuntime(lease)
        scan.set_vault_runtime(runtime)
        scan.set_connection_rows(_supplier([_team_row(instance_id="i-other", hostname="8.8.8.8")]))
        ssh_service = MagicMock()
        ssh_service.get_key_path.return_value = None
        ssh_service.discover_key.return_value = None
        connection_service = _connection_service()
        target = scan._resolve_target(dict(OWN), ssh_service, connection_service)

        asyncio.run(scan._with_vault(target, dict(OWN), connection_service))

        assert runtime.asked == [OWN["id"]]


class TestLogProbe:
    def test_the_log_prober_passes_the_rows_to_the_log_viewer(self):
        from servonaut.services.memory.modules.logs import LogsProber

        viewer = MagicMock()
        viewer.probe_log_paths = AsyncMock(return_value=[])
        prober = LogsProber(viewer, MagicMock(), MagicMock())
        team = [_team_row()]
        prober.set_connection_rows(team, [OWN, *team])

        asyncio.run(prober.probe(SimpleNamespace(instance=dict(OWN))))

        kwargs = viewer.probe_log_paths.call_args.kwargs
        assert kwargs["team_rows"] == team and kwargs["rows"] == [OWN, *team]

    def test_the_log_viewer_resolves_with_the_team_rows(self, lease):  # noqa: F811
        from servonaut.services.log_viewer_service import LogViewerService

        config = MagicMock(log_viewer_default_paths=["/var/log/syslog"], log_viewer_custom_paths={})
        manager = MagicMock()
        manager.get.return_value = config
        viewer = LogViewerService(manager)
        viewer.set_vault_runtime(_TeamOnlyRuntime(lease))
        ssh_service = MagicMock()
        ssh_service.get_key_path.return_value = None
        ssh_service.discover_key.return_value = None
        ssh_service.build_ssh_command.return_value = ["ssh"]

        with patch.object(viewer, "_lookup_cached_log_paths", return_value=None), \
                patch("servonaut.services.log_viewer_service.run_ssh_subprocess",
                      AsyncMock(return_value=(b"", b""))):
            asyncio.run(viewer.probe_log_paths(
                dict(OWN), ssh_service, _connection_service(), team_rows=[_team_row()],
            ))

        assert ssh_service.build_ssh_command.call_args.kwargs["identity_agent"] == lease.identity_agent


class TestBuildReportRows:
    def test_one_build_asks_the_supplier_once_and_hands_the_rows_to_the_logs_prober(self, tmp_path):
        service, _ = _memory_service(tmp_path, _connection_service())
        prober = MagicMock()
        prober.name = "logs"
        prober.probe = AsyncMock(side_effect=RuntimeError("stop"))
        service._probers = [prober]
        supply = _supplier([_team_row()])
        service.set_connection_rows(supply)

        asyncio.run(service.build_report(dict(OWN), ["logs"]))

        assert len(supply.calls) == 1
        prober.set_connection_rows.assert_called_once()


class _TeamOnlyRuntime:
    """A vault runtime that holds a lease for the team's shared row only."""

    agent_key_ttl_seconds = 3600
    is_unlocked = True

    def __init__(self, lease):
        self._lease = lease
        self.asked: list[str] = []

    async def resolve_ssh(self, instance):
        self.asked.append(str(instance.get("id")))
        return self._lease if instance.get("is_shared") is True else None


class TestCliSupplier:
    @staticmethod
    def _fleet(rows):
        return SimpleNamespace(instances=lambda: list(rows))

    def test_shared_rows_and_the_cached_fleet(self):
        from servonaut.cli.memory import _connection_rows_supplier

        shared = [_team_row()]
        teams = SimpleNamespace(list_teams=AsyncMock(return_value=[{"slug": "ops"}]))
        with patch(
            "servonaut.services.shared_servers.load_shared_servers",
            AsyncMock(return_value=SimpleNamespace(rows=shared)),
        ) as load:
            supply = _connection_rows_supplier(SimpleNamespace(teams=teams), self._fleet([OWN]))
            team_rows, fleet_rows = asyncio.run(supply())
            asyncio.run(supply())

        assert team_rows == shared and fleet_rows == [OWN, *shared]
        # Read once per run, not once per build.
        assert load.await_count == 1

    def test_a_failed_team_read_leaves_the_local_fleet(self):
        from servonaut.cli.memory import _connection_rows_supplier

        teams = SimpleNamespace(list_teams=AsyncMock(side_effect=RuntimeError("offline")))
        supply = _connection_rows_supplier(SimpleNamespace(teams=teams), self._fleet([OWN]))

        assert asyncio.run(supply()) == ([], [OWN])

    def test_the_headless_service_is_wired_with_it(self, monkeypatch):
        from servonaut.cli import memory as cli_memory

        monkeypatch.setattr(cli_memory, "_vault_runtime", lambda: SimpleNamespace(teams=None))
        _config, service, _fleet = cli_memory._init_headless_services()

        assert service._connection_rows is not None


class TestMcpSupplier:
    def test_the_fleet_is_custom_cached_and_shared_rows(self):
        from servonaut.mcp.tools import ServonautTools

        shared = [_team_row()]
        directory = SimpleNamespace(
            custom_rows=lambda: [{"id": "c-1"}],
            cached_provider_rows=lambda provider: [{"id": f"{provider}-1"}],
        )
        tools = SimpleNamespace(_directory=directory, _shared_server_rows=AsyncMock(return_value=shared))

        team_rows, fleet = asyncio.run(ServonautTools.connection_rows(tools))

        assert team_rows == shared
        assert [row["id"] for row in fleet] == ["c-1", "aws-1", "ovh-1", "hetzner-1", "srv-1"]


class TestAppSupplier:
    def test_demo_mode_reads_the_real_records(self):
        from servonaut.app import ServonautApp

        real = [dict(OWN), _team_row()]
        app = SimpleNamespace(
            demo_mode=True, redaction_service=object(),
            instances=[{"id": "demo-1", "name": "demo-server"}],
            _instances_pristine=real,
        )

        team_rows, fleet_rows = ServonautApp._connection_rows(app)

        assert [row["id"] for row in team_rows] == ["srv-1"]
        assert [row["id"] for row in fleet_rows] == [OWN["id"], "srv-1"]
