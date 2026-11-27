"""Every in-app SSH path uses a server's Servonaut Vault key when it has one.

Each test gives the path a vault runtime whose lease holds the key and checks
that the ssh/scp argv is built from the lease (private agent, public identity
file, pinned host keys, bound login) instead of the local key file.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services.ssh_credentials import VaultCredentialError, VaultLeaseCache

CUSTOM = {
    "id": "custom-web-1", "name": "web-1", "is_custom": True, "provider": "custom",
    "host": "192.0.2.10", "public_ip": "192.0.2.10", "username": "deploy", "port": 2222,
    "ssh_key": "/keys/web1",
}


@pytest.fixture()
def lease(tmp_path):
    agent = tmp_path / "agent.sock"
    agent.touch()
    return SimpleNamespace(
        source="vault", identity_agent=str(agent), identity_file=str(tmp_path / "key.pub"),
        certificate_path=None, known_hosts_path=str(tmp_path / "known_hosts"),
        login_user="deploy", target_host="192.0.2.10", target_port=2222,
    )


def _runtime(lease):
    runtime = MagicMock()
    runtime.agent_key_ttl_seconds = 3600
    runtime.resolve_ssh = AsyncMock(return_value=lease)
    return runtime


def _assert_vault_identity(kwargs, lease):
    assert kwargs["identity_agent"] == lease.identity_agent
    assert kwargs["identity_file"] == lease.identity_file
    assert kwargs["known_hosts_file"] == lease.known_hosts_path
    assert kwargs.get("key_path") is None


def _connection_service():
    service = MagicMock()
    service.resolve_profile.return_value = None
    service.get_target_host.side_effect = lambda inst, profile: inst.get("public_ip") or inst.get("host")
    service.get_target_port.side_effect = lambda inst: inst.get("port")
    service.get_proxy_args.return_value = []
    service.get_extra_options.return_value = []
    return service


# ---------------------------------------------------------------------------
# Shared services (also used by the MCP tools and the CLI)
# ---------------------------------------------------------------------------

def test_memory_probes_use_the_vault_key(tmp_path, lease):
    from servonaut.config.schema import MemoryConfig
    from servonaut.services.memory import MemoryService
    from servonaut.services.memory.store import MemoryStore

    ssh_service = MagicMock()
    ssh_service.build_ssh_command.return_value = ["ssh", "web-1", "true"]
    service = MemoryService(
        store=MemoryStore(root=tmp_path), config=MemoryConfig(),
        ssh_service=ssh_service, connection_service=_connection_service(),
    )
    runtime = _runtime(lease)
    service.set_vault_runtime(runtime, VaultLeaseCache())

    async def run_twice():
        # The runner binds the subprocess helper when it is made: patch first.
        with patch("servonaut.utils.ssh_utils.run_ssh_subprocess", AsyncMock(return_value=(b"ok", b""))):
            runner = service._make_ssh_runner(dict(CUSTOM))
            await runner("uname -a")
            await runner("uptime")

    asyncio.run(run_twice())

    _assert_vault_identity(ssh_service.build_ssh_command.call_args.kwargs, lease)
    # One lease for the runner's commands.
    runtime.resolve_ssh.assert_awaited_once()


def test_a_memory_probe_reports_an_unusable_vault_key(tmp_path):
    from servonaut.config.schema import MemoryConfig
    from servonaut.services.memory import MemoryService
    from servonaut.services.memory.store import MemoryStore

    service = MemoryService(
        store=MemoryStore(root=tmp_path), config=MemoryConfig(),
        ssh_service=MagicMock(), connection_service=_connection_service(),
    )
    runtime = MagicMock(resolve_ssh=AsyncMock(side_effect=RuntimeError("locked")))
    service.set_vault_runtime(runtime)
    runner = service._make_ssh_runner(dict(CUSTOM))

    with pytest.raises(VaultCredentialError):
        asyncio.run(runner("uname -a"))


def test_log_access_uses_the_vault_key(lease):
    from servonaut.services.log_viewer_service import LogViewerService

    config = MagicMock(log_viewer_default_paths=["/var/log/syslog"], log_viewer_custom_paths={})
    config_manager = MagicMock()
    config_manager.get.return_value = config
    service = LogViewerService(config_manager)
    service.set_vault_runtime(_runtime(lease))
    ssh_service = MagicMock()
    ssh_service.build_ssh_command.return_value = ["ssh"]

    with patch.object(service, "_lookup_cached_log_paths", return_value=None), \
            patch("servonaut.services.log_viewer_service.run_ssh_subprocess",
                  AsyncMock(return_value=(b"/var/log/syslog\n", b""))):
        paths = asyncio.run(service.probe_log_paths(dict(CUSTOM), ssh_service, _connection_service()))

    assert paths == ["/var/log/syslog"]
    _assert_vault_identity(ssh_service.build_ssh_command.call_args.kwargs, lease)


def test_keyword_scans_use_the_vault_key(lease):
    from servonaut.services.scan_service import ScanService

    service = ScanService(MagicMock())
    service.set_vault_runtime(_runtime(lease))
    ssh_service = MagicMock()
    ssh_service.build_ssh_command.return_value = ["ssh"]
    target = service._resolve_target(dict(CUSTOM), ssh_service, _connection_service())

    target = asyncio.run(service._with_vault(target, dict(CUSTOM), _connection_service()))
    target.argv("ls -la /srv")

    _assert_vault_identity(ssh_service.build_ssh_command.call_args.kwargs, lease)
    assert ssh_service.build_ssh_command.call_args.args[2] is None  # no local key


def test_an_unusable_vault_key_stops_a_scan_with_its_reason():
    from servonaut.services.scan_service import ScanConnectionError, ScanService

    service = ScanService(MagicMock())
    service.set_vault_runtime(MagicMock(resolve_ssh=AsyncMock(side_effect=RuntimeError("locked"))))
    target = service._resolve_target(dict(CUSTOM), MagicMock(), _connection_service())

    with pytest.raises(ScanConnectionError, match="could not be used"):
        asyncio.run(service._with_vault(target, dict(CUSTOM), _connection_service()))


# ---------------------------------------------------------------------------
# TUI screens and widgets
# ---------------------------------------------------------------------------

def _app(lease, **extra):
    app = MagicMock()
    app.demo_mode = False
    app.redaction_service = None
    app.vault_command_service = _runtime(lease) if lease is not None else None
    app.vault_lease_cache = VaultLeaseCache()
    app.connection_service = _connection_service()
    app.ssh_service.build_ssh_command.return_value = ["ssh"]
    for key, value in extra.items():
        setattr(app, key, value)
    return app


def _with_app(obj, app):
    return patch.object(type(obj), "app", new_callable=lambda: property(lambda self: app))


def test_run_command_uses_the_vault_key(lease):
    from servonaut.screens.command_overlay import CommandOverlay

    overlay = CommandOverlay(dict(CUSTOM))
    app = _app(lease)
    overlay._connection = dict(CUSTOM)
    overlay._host, overlay._username, overlay._key_path = "192.0.2.10", "deploy", "/keys/web1"
    overlay._proxy_args, overlay._port, overlay._extra_options = [], 2222, []
    started = []

    with _with_app(overlay, app), \
            patch.object(overlay, "run_worker", side_effect=lambda work, **_kw: started.append(work)):
        asyncio.run(overlay._resolve_and_run("bash -ic uptime", MagicMock()))

    _assert_vault_identity(app.ssh_service.build_ssh_command.call_args.kwargs, lease)
    assert len(started) == 1  # the ssh run itself, in a thread


def test_run_command_refuses_an_unusable_vault_key():
    from servonaut.screens.command_overlay import CommandOverlay

    overlay = CommandOverlay(dict(CUSTOM))
    app = _app(None)
    app.vault_command_service = MagicMock(resolve_ssh=AsyncMock(side_effect=RuntimeError("locked")))
    overlay._connection = dict(CUSTOM)
    overlay._host, overlay._username, overlay._key_path = "192.0.2.10", "deploy", "/keys/web1"
    overlay._proxy_args, overlay._port, overlay._extra_options = [], 2222, []
    output = MagicMock()

    with _with_app(overlay, app), patch.object(overlay, "run_worker") as run_worker:
        asyncio.run(overlay._resolve_and_run("bash -ic uptime", output))

    run_worker.assert_not_called()
    app.ssh_service.build_ssh_command.assert_not_called()
    assert "could not be used" in output.append_error.call_args.args[0]


def test_browsing_files_uses_the_vault_key(lease):
    from servonaut.widgets.remote_tree import RemoteTree

    app = _app(lease)
    tree = RemoteTree(dict(CUSTOM), app.ssh_service, app.connection_service, "deploy", ["/"])

    with _with_app(tree, app), \
            patch("servonaut.widgets.remote_tree.run_ssh",
                  return_value=SimpleNamespace(returncode=0, stdout="", stderr="")):
        asyncio.run(tree._apply_vault())
        tree._run_ls("ls -la /")

    _assert_vault_identity(app.ssh_service.build_ssh_command.call_args.kwargs, lease)


def test_file_transfers_use_the_vault_key(lease):
    from servonaut.screens.scp_transfer import SCPTransferScreen

    screen = SCPTransferScreen.__new__(SCPTransferScreen)
    screen._transfer_direction = "upload"
    app = _app(lease)
    app.scp_service.build_upload_command.return_value = ["scp"]
    app.config_manager.get.return_value.default_username = "ubuntu"

    with _with_app(screen, app):
        command = asyncio.run(screen._vault_transfer_command(dict(CUSTOM), "/tmp/a", "/srv/a"))

    assert command == ["scp"]
    kwargs = app.scp_service.build_upload_command.call_args.kwargs
    _assert_vault_identity(kwargs, lease)
    assert kwargs["username"] == "deploy"


def test_quick_ssh_from_the_fleet_uses_the_vault_key(lease):
    from servonaut.screens.instance_list import InstanceListScreen

    screen = object.__new__(InstanceListScreen)
    app = _app(lease)
    app.terminal_service.launch_ssh_in_terminal.return_value = True
    conn = {"host": "192.0.2.10", "username": "deploy", "key_path": "/keys/web1",
            "proxy_args": [], "port": 2222, "extra_options": [], "profile": None}

    with _with_app(screen, app), patch.object(screen, "_maybe_show_memory_prompt"), \
            patch.object(screen, "_maybe_pull_annotations"):
        asyncio.run(screen._launch_ssh(dict(CUSTOM), dict(CUSTOM), conn))

    _assert_vault_identity(app.ssh_service.build_ssh_command.call_args.kwargs, lease)
    app.terminal_service.launch_ssh_in_terminal.assert_called_once()


def test_the_app_hands_the_vault_to_every_ssh_service():
    from servonaut.app import ServonautApp

    services = [MagicMock(), MagicMock(), MagicMock()]
    host = SimpleNamespace(
        vault_command_service=object(),
        memory_service=services[0], log_viewer_service=services[1], scan_service=services[2],
        _connection_rows=lambda: ([], []),
        bw_ssh_keys=None,
    )
    host._wire_bw_keys = lambda: ServonautApp._wire_bw_keys(host)
    host._forget_bw_keys = lambda: ServonautApp._forget_bw_keys(host)

    ServonautApp._wire_vault_ssh(host)

    for service in services:
        service.set_vault_runtime.assert_called_once_with(host.vault_command_service, host.vault_lease_cache)
    # The services that connect on their own are asked for the team rows and the fleet.
    for service in (services[0], services[2]):
        service.set_connection_rows.assert_called_once_with(host._connection_rows)
    assert isinstance(host.vault_lease_cache, VaultLeaseCache)


def test_binding_a_new_key_drops_the_servers_cached_lease(lease):
    from servonaut.services.ssh_credentials import vault_lease

    cache = VaultLeaseCache()
    runtime = _runtime(lease)
    asyncio.run(vault_lease(dict(CUSTOM), runtime, cache=cache))

    cache.forget(dict(CUSTOM))  # what Use Vault Key does after a bind
    asyncio.run(vault_lease(dict(CUSTOM), runtime, cache=cache))

    assert runtime.resolve_ssh.await_count == 2


def test_the_bitwarden_provider_reaches_services_wired_before_it_exists():
    """A signed-in user's services are wired before the provider is built."""
    from servonaut.app import ServonautApp

    services = [MagicMock(), MagicMock(), MagicMock()]
    provider = object()
    host = SimpleNamespace(
        memory_service=services[0], log_viewer_service=services[1], scan_service=services[2],
        bw_ssh_keys=provider,
    )

    ServonautApp._wire_bw_keys(host)

    for service in services:
        service.set_bw_keys.assert_called_once_with(provider)


def test_a_signed_in_start_hands_the_bitwarden_provider_to_every_service(tmp_path):
    """The real init path: paid services are wired before the provider exists."""
    from unittest.mock import patch

    from servonaut.app import ServonautApp

    app = ServonautApp(config_path=tmp_path / "config.json")
    auth = MagicMock(is_authenticated=True)
    with patch("servonaut.services.auth_service.AuthService", return_value=auth), \
            patch.object(ServonautApp, "init_paid_services",
                         autospec=True, side_effect=ServonautApp.init_paid_services) as paid:
        app._init_services()

    paid.assert_called()
    assert app.bw_ssh_keys is not None
    assert app.memory_service._bw_keys is app.bw_ssh_keys
    assert app.log_viewer_service._bw_keys is app.bw_ssh_keys
    assert app.scan_service._bw_keys is app.bw_ssh_keys


def test_the_app_tools_read_the_apps_unlocked_bitwarden_session(tmp_path):
    """The AI chat and relay tools use the app's in-memory unlock (the owner's choice, disclosed in the UI)."""
    from servonaut.app import ServonautApp

    app = ServonautApp(config_path=tmp_path / "config.json")
    app._init_services()
    app.bw_session_service = MagicMock()
    app.bw_session_service.session.return_value = "unlocked-session"

    getter = app.servonaut_tools._bw_session_getter
    assert getter is not None
    assert getter() == "unlocked-session"
    app.bw_session_service.session.return_value = None
    assert getter() is None


def _signed_out_app(tmp_path):
    from servonaut.app import ServonautApp

    app = ServonautApp(config_path=tmp_path / "config.json")
    app._init_services()
    app.bw_ssh_keys = MagicMock()
    return app


def test_locking_bitwarden_drops_the_cached_key_files(tmp_path):
    app = _signed_out_app(tmp_path)
    app.bw_session_service.lock()
    app.bw_ssh_keys.forget_keys.assert_called_once_with()


def test_signing_out_drops_the_cached_key_files(tmp_path):
    app = _signed_out_app(tmp_path)
    app.on_user_logout()
    app.bw_ssh_keys.forget_keys.assert_called_once_with()
    app.bw_ssh_keys.forget_refs.assert_called_once_with()


def test_signing_in_drops_the_cached_key_files(tmp_path):
    app = _signed_out_app(tmp_path)
    app._wire_vault_ssh()
    app.bw_ssh_keys.forget_keys.assert_called_once_with()
