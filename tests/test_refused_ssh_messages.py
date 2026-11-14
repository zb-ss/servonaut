"""A connection Servonaut refuses is shown as its own message, not as a failure.

The refusal text says what to fix ("Not connecting: ... allow it: run
"servonaut team options" ..."). Every screen that starts an SSH or SCP
connection shows exactly that text as an error notice, with no prefix, and
logs no traceback.
"""
from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from rich.text import Text

from servonaut.utils.ssh_option_policy import SSHOptionRefused

REFUSAL = (
    "Not connecting: the custom server 'web-1' came from team Ops and sets ProxyCommand, "
    "which runs a program on this computer. To allow it, run "
    '"servonaut team options" or open Settings > Connections.'
)
INSTANCE = {
    "id": "custom-1", "name": "web-1", "is_custom": True, "public_ip": "10.0.0.5",
    "username": "deploy", "port": 22, "state": "running",
}


def _with_app(obj, app):
    return patch.object(type(obj), "app", new_callable=lambda: property(lambda self: app))


def _app() -> MagicMock:
    app = MagicMock()
    app.demo_mode = False
    app.redaction_service = None
    app.instances = [dict(INSTANCE)]
    app.vault_command_service = None
    app.vault_lease_cache = None
    app.connection_service.resolve_profile.return_value = None
    app.connection_service.get_extra_options.return_value = []
    app.ssh_service.get_key_path.return_value = None
    app.ssh_service.discover_key.return_value = None
    app.ssh_service.build_ssh_command.side_effect = SSHOptionRefused(REFUSAL)
    app.config_manager.get.return_value.default_username = "ec2-user"
    return app


def _assert_plain_refusal(app, caplog) -> None:
    assert app.notify.call_count == 1
    call = app.notify.call_args
    assert call.args[0] == REFUSAL
    assert call.kwargs.get("severity") == "error"
    assert call.kwargs.get("markup") is False
    assert not [r for r in caplog.records if r.exc_info or r.levelno >= logging.ERROR]


def test_the_server_actions_ssh_launch_shows_the_refusal_as_it_is(caplog) -> None:
    from servonaut.screens.server_actions import ServerActionsScreen
    from unittest.mock import AsyncMock

    screen = object.__new__(ServerActionsScreen)
    screen._instance = dict(INSTANCE)
    app = _app()
    ref = SimpleNamespace(source="local", local_key_path=None, login_user=None)
    resolver = MagicMock(resolve=AsyncMock(return_value=ref))
    caplog.set_level(logging.DEBUG)
    with _with_app(screen, app), patch.object(screen, "_ssh_ref_resolver", AsyncMock(return_value=resolver)):
        asyncio.run(screen._resolve_and_launch_ssh(MagicMock()))
    _assert_plain_refusal(app, caplog)


def test_quick_ssh_from_the_fleet_shows_the_refusal_as_it_is(caplog) -> None:
    from servonaut.screens.instance_list import InstanceListScreen

    screen = object.__new__(InstanceListScreen)
    app = _app()
    conn = {"host": "10.0.0.5", "username": "deploy", "key_path": None, "proxy_args": [],
            "port": 22, "extra_options": [], "profile": None}
    caplog.set_level(logging.DEBUG)
    with _with_app(screen, app):
        asyncio.run(screen._launch_ssh(dict(INSTANCE), dict(INSTANCE), conn))
    _assert_plain_refusal(app, caplog)


def test_quick_ssh_setup_shows_the_refusal_as_it_is(caplog) -> None:
    from servonaut.screens.instance_list import InstanceListScreen

    screen = object.__new__(InstanceListScreen)
    app = _app()
    app.connection_service.get_proxy_args.side_effect = SSHOptionRefused(REFUSAL)
    app.connection_service.resolve_profile.return_value = SimpleNamespace(
        username="deploy", bastion_host="jump-1",
    )
    app.connection_service.get_target_host.return_value = "10.0.0.5"
    screen._get_selected_running_instance = lambda: dict(INSTANCE)
    caplog.set_level(logging.DEBUG)
    with _with_app(screen, app), patch(
        "servonaut.screens.instance_list.connection_instance", lambda a, i: i,
    ):
        screen.action_ssh_connect()
    _assert_plain_refusal(app, caplog)


def test_a_refused_file_transfer_shows_the_refusal_as_it_is(caplog) -> None:
    from servonaut.screens.scp_transfer import SCPTransferScreen

    screen = object.__new__(SCPTransferScreen)
    app = _app()
    status = MagicMock()
    screen.query_one = lambda *a, **k: status
    event = SimpleNamespace(worker=SimpleNamespace(
        name="scp_transfer", is_finished=True, error=SSHOptionRefused(REFUSAL), result=None,
    ))
    caplog.set_level(logging.DEBUG)
    with _with_app(screen, app):
        screen.on_worker_state_changed(event)
    _assert_plain_refusal(app, caplog)
    assert REFUSAL in status.update.call_args.args[0].plain


def test_a_refused_log_fetch_shows_the_refusal_as_it_is(caplog) -> None:
    from unittest.mock import AsyncMock

    from servonaut.screens.ai_analysis import AIAnalysisScreen

    screen = object.__new__(AIAnalysisScreen)
    screen._instance = dict(INSTANCE)
    status = MagicMock()
    screen.query_one = lambda *a, **k: status
    screen._set_buttons_disabled = lambda *a, **k: None
    app = _app()
    conn = {"host": "10.0.0.5", "username": "deploy", "key_path": None, "proxy_args": [],
            "port": 22, "extra_options": []}
    app.log_viewer_service.resolve_connection = AsyncMock(return_value=conn)
    app.log_viewer_service.classify_log_file.return_value = "plain"
    app.log_viewer_service.get_tail_command.return_value = "tail -n 200 /var/log/syslog"
    caplog.set_level(logging.DEBUG)
    with _with_app(screen, app), patch(
        "servonaut.screens.ai_analysis.connection_instance", lambda a, i: i,
    ), patch("servonaut.screens.ai_analysis.team_rows", lambda a: []), patch(
        "servonaut.screens.ai_analysis.fleet_rows", lambda a: [],
    ):
        asyncio.run(screen._do_fetch_log("/var/log/syslog"))
    _assert_plain_refusal(app, caplog)
    assert status.update.call_args.args[0].plain == REFUSAL


def test_a_refused_directory_listing_shows_the_refusal_as_it_is(caplog) -> None:
    from servonaut.widgets.remote_tree import RemoteTree

    tree = object.__new__(RemoteTree)
    node = MagicMock()
    loading = MagicMock()
    tree._pending_fetch = (node, loading, "/srv")
    tree.refresh = lambda *a, **k: None
    event = SimpleNamespace(worker=SimpleNamespace(
        group="fetch_dir", is_finished=True, error=SSHOptionRefused(REFUSAL), result=None,
    ))
    caplog.set_level(logging.DEBUG)
    tree.on_worker_state_changed(event)
    label = node.add.call_args.args[0]
    assert isinstance(label, Text) and label.plain == REFUSAL
    assert not [r for r in caplog.records if r.exc_info or r.levelno >= logging.ERROR]
