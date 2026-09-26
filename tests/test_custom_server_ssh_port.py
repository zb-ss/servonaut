"""Custom servers on a non-default SSH port reach that port on every surface.

A custom server stores its own ``port``. Each test builds the real argv
through the real SSH/SCP/connection services and asserts ``-p`` (``-P`` for
scp) carries the port, and that AWS instances and custom servers on port 22
still get no port flag.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import List, Optional
from unittest.mock import MagicMock, patch

import pytest
from textual.app import App

from servonaut.config.schema import AppConfig, CustomServer, ScanRule
from servonaut.screens.command_overlay import CommandOverlay
from servonaut.screens.scp_transfer import SCPTransferScreen
from servonaut.services.connection_service import ConnectionService
from servonaut.services.custom_server_service import CustomServerService
from servonaut.services.scan_service import ScanService
from servonaut.services.scp_service import SCPService
from servonaut.services.ssh_service import SSHService
from servonaut.widgets.remote_tree import RemoteTree


def _config_manager(config: Optional[AppConfig] = None) -> MagicMock:
    manager = MagicMock()
    manager.get.return_value = config or AppConfig(default_username="ec2-user")
    return manager


def _custom_instance(port: int = 2222) -> dict:
    server = CustomServer(
        name="web-1", host="10.0.0.5", username="deploy",
        ssh_key="/keys/web-1.pem", port=port,
    )
    return CustomServerService(_config_manager()).to_instance_dict(server)


def _aws_instance() -> dict:
    return {
        "id": "i-0abc1234", "name": "web-2", "state": "running",
        "public_ip": "9.9.9.9", "private_ip": "10.0.0.6", "region": "us-east-1",
        "key_name": "",
    }


def _port_flag(argv: List[str], flag: str = "-p") -> Optional[str]:
    return argv[argv.index(flag) + 1] if flag in argv else None


class _Services:
    """The real service graph a screen reaches through ``self.app``."""

    def __init__(self, config: Optional[AppConfig] = None) -> None:
        self.config_manager = _config_manager(config)
        self.connection_service = ConnectionService(self.config_manager)
        self.ssh_service = SSHService(self.config_manager)
        self.scp_service = SCPService()


# ---------------------------------------------------------------------------
# Command overlay
# ---------------------------------------------------------------------------

class _OverlayHost(App):
    def __init__(self, instance: dict) -> None:
        super().__init__()
        services = _Services()
        self.config_manager = services.config_manager
        self.connection_service = services.connection_service
        self.ssh_service = services.ssh_service
        self.command_history = None
        self.demo_mode = False
        self.redaction_service = None
        self._instance = instance

    def on_mount(self) -> None:
        self.push_screen(CommandOverlay(self._instance))


async def _overlay_argv(instance: dict) -> List[str]:
    app = _OverlayHost(instance)
    with patch.object(CommandOverlay, "_run_ssh_command") as run:
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            app.screen._execute_command("uptime")
            await app.screen.workers.wait_for_complete()
    run.assert_called_once()
    return run.call_args.args[0]


@pytest.mark.asyncio
async def test_command_overlay_uses_custom_server_port():
    argv = await _overlay_argv(_custom_instance(2222))
    assert _port_flag(argv) == "2222"
    assert "deploy@10.0.0.5" in argv


@pytest.mark.asyncio
@pytest.mark.parametrize("instance", [_custom_instance(22), _aws_instance()])
async def test_command_overlay_default_port_adds_no_flag(instance):
    assert _port_flag(await _overlay_argv(instance)) is None


# ---------------------------------------------------------------------------
# Scan service
# ---------------------------------------------------------------------------

async def _scan_argvs(instance: dict) -> List[List[str]]:
    config = AppConfig(
        default_username="ec2-user",
        default_scan_paths=["/srv/app"],
        scan_rules=[ScanRule(name="all", match_conditions={}, scan_commands=["uptime"])],
    )
    services = _Services(config)
    scan = ScanService(services.config_manager)
    ok = SimpleNamespace(returncode=0, stdout="output", stderr="")
    with patch("servonaut.services.scan_service.subprocess.run", return_value=ok) as run:
        results = await scan.scan_server(
            instance, services.ssh_service, services.connection_service,
        )
    assert len(results) == 2  # one path scan + one command scan
    # Connection check, path scan, command scan.
    return [c.args[0] for c in run.call_args_list]


@pytest.mark.asyncio
async def test_scan_uses_custom_server_port_for_paths_and_commands():
    argvs = await _scan_argvs(_custom_instance(2222))
    assert [_port_flag(argv) for argv in argvs] == ["2222"] * 3


@pytest.mark.asyncio
@pytest.mark.parametrize("instance", [_custom_instance(22), _aws_instance()])
async def test_scan_default_port_adds_no_flag(instance):
    assert [_port_flag(argv) for argv in await _scan_argvs(instance)] == [None] * 3


# ---------------------------------------------------------------------------
# Remote file tree
# ---------------------------------------------------------------------------

def _tree_argv(instance: dict) -> List[str]:
    services = _Services()
    tree = RemoteTree(
        instance=instance,
        ssh_service=services.ssh_service,
        connection_service=services.connection_service,
        username="deploy",
        scan_paths=["/srv"],
    )
    listing = "total 0\ndrwxr-xr-x 2 root root 4096 Jan  1 00:00 app\n"
    ok = SimpleNamespace(returncode=0, stdout=listing, stderr="")
    with patch("servonaut.widgets.remote_tree.subprocess.run", return_value=ok) as run:
        tree._fetch_directory_contents("/srv")
    return run.call_args.args[0]


def test_remote_tree_uses_custom_server_port():
    assert _port_flag(_tree_argv(_custom_instance(2222))) == "2222"


@pytest.mark.parametrize("instance", [_custom_instance(22), _aws_instance()])
def test_remote_tree_default_port_adds_no_flag(instance):
    assert _port_flag(_tree_argv(instance)) is None


# ---------------------------------------------------------------------------
# SCP transfer screen
# ---------------------------------------------------------------------------

def _scp_argv(instance: dict, direction: str) -> List[str]:
    services = _Services(AppConfig(default_username="ec2-user", default_key="/keys/default.pem"))
    app = SimpleNamespace(
        config_manager=services.config_manager,
        connection_service=services.connection_service,
        ssh_service=services.ssh_service,
        scp_service=services.scp_service,
    )
    screen_cls = type("_HostedSCPTransferScreen", (SCPTransferScreen,),
                      {"app": property(lambda self: app)})
    screen = screen_cls(instance)
    screen._transfer_direction = direction
    return screen._build_transfer_command(instance, "/tmp/local.txt", "/srv/remote.txt")


@pytest.mark.parametrize("direction", ["upload", "download"])
def test_scp_transfer_uses_custom_server_connection(direction):
    argv = _scp_argv(_custom_instance(2222), direction)
    assert _port_flag(argv, "-P") == "2222"
    # The custom server's own login and key, not the AWS defaults.
    assert _port_flag(argv, "-i") == "/keys/web-1.pem"
    assert any(arg.startswith("deploy@10.0.0.5:") for arg in argv)


@pytest.mark.parametrize("instance", [_custom_instance(22), _aws_instance()])
def test_scp_transfer_default_port_adds_no_flag(instance):
    argv = _scp_argv(instance, "upload")
    assert _port_flag(argv, "-P") is None
    assert _port_flag(argv, "-p") is None


def test_scp_transfer_aws_keeps_default_user_and_key():
    argv = _scp_argv(_aws_instance(), "download")
    assert _port_flag(argv, "-i") == "/keys/default.pem"
    assert argv[-2].startswith("ec2-user@9.9.9.9:")
