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
    app = _app()
    caplog.set_level(logging.DEBUG)
    with _with_app(tree, app):
        tree.on_worker_state_changed(event)
    label = node.add.call_args.args[0]
    assert isinstance(label, Text) and label.plain == REFUSAL
    # The row is cut to the tree's width: the notice carries the whole message.
    _assert_plain_refusal(app, caplog)


def test_a_refused_log_probe_in_the_analysis_screen_shows_the_refusal_as_it_is(caplog) -> None:
    from unittest.mock import AsyncMock

    from servonaut.screens.ai_analysis import AIAnalysisScreen

    screen = object.__new__(AIAnalysisScreen)
    screen._instance = dict(INSTANCE)
    status = MagicMock()
    screen.query_one = lambda *a, **k: status
    screen._set_buttons_disabled = lambda *a, **k: None
    app = _app()
    app.log_viewer_service._resolve_connection.return_value = {"host": "10.0.0.5"}
    app.log_viewer_service.probe_log_paths = AsyncMock(side_effect=SSHOptionRefused(REFUSAL))
    caplog.set_level(logging.DEBUG)
    with _with_app(screen, app), patch(
        "servonaut.screens.ai_analysis.connection_instance", lambda a, i: i,
    ), patch("servonaut.screens.ai_analysis.fleet_rows", lambda a: []):
        asyncio.run(screen._do_probe_and_pick())
    _assert_plain_refusal(app, caplog)
    assert status.update.call_args.args[0].plain == REFUSAL


@pytest.mark.parametrize("message", ["web[/x]-1 [bold]", "a\\"])
def test_an_unreadable_log_probe_error_is_drawn_as_text_not_markup(message) -> None:
    from unittest.mock import AsyncMock

    from servonaut.screens.ai_analysis import AIAnalysisScreen

    screen = object.__new__(AIAnalysisScreen)
    screen._instance = dict(INSTANCE)
    status = MagicMock()
    screen.query_one = lambda *a, **k: status
    screen._set_buttons_disabled = lambda *a, **k: None
    app = _app()
    app.log_viewer_service._resolve_connection.return_value = {"host": "10.0.0.5"}
    app.log_viewer_service.probe_log_paths = AsyncMock(side_effect=RuntimeError(message))
    with _with_app(screen, app), patch(
        "servonaut.screens.ai_analysis.connection_instance", lambda a, i: i,
    ), patch("servonaut.screens.ai_analysis.fleet_rows", lambda a: []):
        asyncio.run(screen._do_probe_and_pick())
    shown = status.update.call_args.args[0]
    assert not isinstance(shown, str) and shown.plain == f"Error: {message}"


def test_a_refused_log_probe_in_the_log_viewer_shows_the_refusal_as_it_is(caplog) -> None:
    from unittest.mock import AsyncMock

    from servonaut.screens.log_viewer import LogViewerScreen

    screen = object.__new__(LogViewerScreen)
    screen._instance = dict(INSTANCE)
    screen._connection_instance = lambda: dict(INSTANCE)
    output = MagicMock()
    screen.query_one = lambda *a, **k: output
    app = _app()
    app.log_viewer_service.probe_log_paths = AsyncMock(side_effect=SSHOptionRefused(REFUSAL))
    caplog.set_level(logging.DEBUG)
    with _with_app(screen, app), patch("servonaut.screens.log_viewer.fleet_rows", lambda a: []):
        asyncio.run(screen._probe_and_start())
    _assert_plain_refusal(app, caplog)
    written = [c.args[0] for c in output.write.call_args_list]
    assert any(isinstance(w, Text) and w.plain == REFUSAL for w in written)
    assert not any("Error probing logs" in str(w) for w in written)


# The credential flows run in a worker with the default error handling, so an
# exception that escapes them ends the app. These tests run the real worker.

def _native_ref(source: str):
    from servonaut.services.ssh_ref_resolver import ResolvedSshRef

    return ResolvedSshRef(
        source=source, login_user="deploy", identity_agent="/agent", identity_file="/id",
        known_hosts_path="/kh", lease=SimpleNamespace(target_host=None, target_port=None),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["vault", "ca"])
@pytest.mark.parametrize("flow", ["connect", "verify"])
async def test_a_refused_vault_or_ca_connection_shows_one_plain_notice_and_the_app_keeps_running(
    source, flow, caplog,
) -> None:
    from unittest.mock import AsyncMock

    from servonaut.screens.server_actions import _VAULT_SOURCE
    from tests.test_vault_busy_surfaces import _ServerHost, _server_screen

    app = _ServerHost()
    app.ssh_service.build_ssh_command.side_effect = SSHOptionRefused(REFUSAL)
    app.connection_service.resolve_profile.return_value = None
    app.connection_service.get_target_host.return_value = "10.0.0.5"
    resolver = MagicMock(resolve=AsyncMock(return_value=_native_ref(source)))
    caplog.set_level(logging.DEBUG)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _server_screen(app)
        screen._ssh_ref_resolver = AsyncMock(return_value=resolver)
        screen._bastion_hop = AsyncMock(return_value=(True, None))
        if flow == "verify":
            screen._vault_binding_source = _VAULT_SOURCE
            screen.action_verify_ssh()
        else:
            screen.action_action_3()
        await screen.workers.wait_for_complete()
        await pilot.pause()
        assert app._exception is None
        assert [message for message, _ in app.notes] == [REFUSAL]
        assert app.notes[0][1].get("severity") == "error"
        assert app.notes[0][1].get("markup") is False
        assert not [r for r in caplog.records if r.exc_info or r.levelno >= logging.ERROR]
