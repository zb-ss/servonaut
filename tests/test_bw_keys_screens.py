"""Bitwarden keys on the command overlay, quick connect and the log viewer.

Without a Bitwarden ref every screen builds the ssh command it builds today;
with a readable key it uses the key file; the Bitwarden cause is shown only
when ssh then refuses the login.
"""
from __future__ import annotations

import asyncio
import io
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.screens.command_overlay import CommandOverlay
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.log_viewer import LogViewerScreen
from servonaut.services.log_viewer_service import LogViewerService
from servonaut.services.ssh_credentials import VaultLeaseCache
from servonaut.utils.ssh_names import SSHRefusal
from tests._bw_fixtures import key_provider, no_ref_provider, unavailable_provider

BW_KEY = "/tmp/bw-test"
LOCKED = (
    "Bitwarden is locked, so this server's Bitwarden key was not used. "
    "Unlock it under Settings > Bitwarden SSH and retry."
)
REFUSED = "deploy@web-1: Permission denied (publickey)."

OWN = {
    "id": "i-abc123", "name": "web-1", "provider": "aws", "public_ip": "192.0.2.10",
    "private_ip": "10.0.0.5", "region": "eu-west-2", "key_name": "prod-key",
}
KEY_FILE = "/home/user/.ssh/prod-key.pem"
CONN = {
    "host": "192.0.2.10", "username": "ec2-user", "key_path": KEY_FILE,
    "proxy_args": ["-J", "jump"], "port": 2222, "extra_options": ["-o", "ConnectTimeout=5"],
}
KWARGS = (
    "host", "username", "key_path", "proxy_args", "port", "extra_options",
    "identity_agent", "identity_file", "certificate_file", "known_hosts_file",
)


def _lease(tmp_path, certificate=False):
    agent = tmp_path / "agent.sock"
    agent.touch()
    return SimpleNamespace(
        source="vault", identity_agent=str(agent), identity_file=str(tmp_path / "key.pub"),
        certificate_path=str(tmp_path / "cert.pub") if certificate else None,
        known_hosts_path=str(tmp_path / "known_hosts"),
        login_user="deploy", target_host="192.0.2.10", target_port=22,
    )


def _runtime(lease):
    runtime = MagicMock()
    runtime.agent_key_ttl_seconds = 3600
    runtime.resolve_ssh = AsyncMock(return_value=lease)
    return runtime


@pytest.fixture(params=["local_key", "no_key", "vault_lease", "ca_lease"])
def scenario(request, tmp_path):
    """(conn, vault runtime) for one connection type."""
    conn = dict(CONN)
    runtime = None
    if request.param == "no_key":
        conn["key_path"] = None
    elif request.param == "vault_lease":
        runtime = _runtime(_lease(tmp_path))
    elif request.param == "ca_lease":
        runtime = _runtime(_lease(tmp_path, certificate=True))
        conn["key_path"] = None
    return conn, runtime


def _app(runtime=None, provider=None):
    app = MagicMock(spec=[])
    app.demo_mode = False
    app.redaction_service = None
    app.instances = [OWN]
    app.vault_command_service = runtime
    app.vault_lease_cache = VaultLeaseCache()
    app.connection_service = MagicMock(resolve_profile=MagicMock(return_value=None))
    app.ssh_service = MagicMock()
    app.ssh_service.build_ssh_command.return_value = ["ssh"]
    app.terminal_service = MagicMock()
    app.terminal_service.launch_ssh_in_terminal.return_value = True
    app.notify = MagicMock()
    if provider is not None:
        app.bw_ssh_keys = provider
    return app


def _with_app(obj, app):
    return patch.object(type(obj), "app", new_callable=lambda: property(lambda self: app))


def _built(app) -> dict:
    kwargs = app.ssh_service.build_ssh_command.call_args.kwargs
    return {name: kwargs.get(name) for name in KWARGS}


# --- the three callers -----------------------------------------------------

def _overlay(conn):
    screen = CommandOverlay(dict(OWN))
    screen._connection = dict(OWN)
    screen._host, screen._username, screen._key_path = conn["host"], conn["username"], conn["key_path"]
    screen._proxy_args, screen._port, screen._extra_options = conn["proxy_args"], conn["port"], conn["extra_options"]
    return screen


def _run_overlay(conn, app) -> CommandOverlay:
    screen = _overlay(conn)
    with _with_app(screen, app), patch.object(screen, "run_worker"):
        asyncio.run(screen._resolve_and_run("uptime", MagicMock()))
    return screen


def _run_quick_connect(conn, app) -> None:
    screen = object.__new__(InstanceListScreen)
    with _with_app(screen, app), patch.object(screen, "_maybe_show_memory_prompt"), \
            patch.object(screen, "_maybe_pull_annotations"):
        asyncio.run(screen._launch_ssh(dict(OWN), dict(OWN), {**conn, "profile": None}))


def _log_service(runtime, provider, conn):
    config = MagicMock()
    config.get.return_value = SimpleNamespace(default_username="ec2-user", log_viewer_tail_lines=100)
    service = LogViewerService(config)
    service.set_vault_runtime(runtime, VaultLeaseCache())
    if provider is not None:
        service.set_bw_keys(provider)
    connection_service = MagicMock(resolve_profile=MagicMock(return_value=None))
    connection_service.get_target_host.return_value = conn["host"]
    connection_service.get_proxy_args.return_value = []
    connection_service.get_extra_options.return_value = conn["extra_options"]
    return service, connection_service


def _run_log_viewer(conn, runtime, provider, *, reason_app_attr=True):
    service, connection_service = _log_service(runtime, provider, conn)
    app = _app(runtime)
    app.log_viewer_service = service
    app.connection_service = connection_service
    app.config_manager = service._config_manager
    app.ssh_service.get_key_path.return_value = conn["key_path"]
    app.ssh_service.discover_key.return_value = conn["key_path"]
    app.ssh_service.build_ssh_command.side_effect = SSHRefusal("stop here")
    screen = LogViewerScreen(dict(OWN))
    screen._content_buffer = []
    with _with_app(screen, app), patch.object(screen, "_stop_stream", AsyncMock()), \
            patch.object(screen, "query_one", MagicMock()):
        asyncio.run(screen._start_stream("/var/log/syslog"))
    return screen, app


class TestUnchangedWithoutARef:
    def test_command_overlay(self, scenario):
        conn, runtime = scenario
        plain = _app(runtime)
        with_provider = _app(runtime, no_ref_provider())
        _run_overlay(conn, plain)
        _run_overlay(conn, with_provider)
        assert _built(plain) == _built(with_provider)
        assert not hasattr(plain, "bw_ssh_keys")

    def test_quick_connect(self, scenario):
        conn, runtime = scenario
        plain = _app(runtime)
        with_provider = _app(runtime, no_ref_provider())
        _run_quick_connect(conn, plain)
        _run_quick_connect(conn, with_provider)
        assert _built(plain) == _built(with_provider)

    def test_log_viewer(self, scenario):
        conn, runtime = scenario
        _, plain = _run_log_viewer(conn, runtime, None)
        _, with_provider = _run_log_viewer(conn, runtime, no_ref_provider())
        assert _built(plain) == _built(with_provider)


# --- a readable Bitwarden key ------------------------------------------------

class TestBitwardenKey:
    def test_command_overlay_uses_the_key(self):
        app = _app(None, key_provider(BW_KEY))
        _run_overlay(CONN, app)
        assert _built(app)["key_path"] == BW_KEY

    def test_quick_connect_uses_the_key(self):
        app = _app(None, key_provider(BW_KEY))
        _run_quick_connect(CONN, app)
        assert _built(app)["key_path"] == BW_KEY

    def test_log_viewer_uses_the_key(self):
        _, app = _run_log_viewer(CONN, None, key_provider(BW_KEY))
        assert _built(app)["key_path"] == BW_KEY

    @pytest.mark.parametrize("run", ["overlay", "quick"])
    def test_a_vault_lease_wins(self, tmp_path, run):
        lease = _lease(tmp_path)
        app = _app(_runtime(lease), key_provider(BW_KEY))
        (_run_overlay if run == "overlay" else _run_quick_connect)(CONN, app)
        built = _built(app)
        assert built["identity_agent"] == lease.identity_agent
        assert built["key_path"] != BW_KEY

    def test_log_viewer_vault_lease_wins(self, tmp_path):
        lease = _lease(tmp_path)
        _, app = _run_log_viewer(CONN, _runtime(lease), key_provider(BW_KEY))
        assert _built(app)["identity_agent"] == lease.identity_agent
        assert _built(app)["key_path"] != BW_KEY


# --- command overlay: the cause, only when ssh refuses ----------------------

class _FinishedSsh:
    def __init__(self, returncode):
        self.stdout, self.stderr = io.BytesIO(b""), io.BytesIO(b"")
        self.returncode, self._exit = None, returncode

    def wait(self):
        self.returncode = self._exit
        return self._exit


def _run_ssh(reason, log, returncode):
    from pathlib import Path

    def popen(argv, *args, **kwargs):
        argv = [str(part) for part in argv]
        Path(argv[argv.index("-E") + 1]).write_text(log + "\n" if log else "")
        return _FinishedSsh(returncode)

    screen = CommandOverlay(dict(OWN))
    screen._bw_key_reason = reason
    output = MagicMock()
    app = _app()
    app.call_from_thread = lambda func, *args: func(*args)
    with _with_app(screen, app), patch("servonaut.screens.command_overlay.subprocess.Popen", popen):
        screen._run_ssh_command(["ssh", "deploy@web-1", "uptime"], output)
    return screen, output, app


def _shown(output) -> list[str]:
    return [call.args[0] for call in output.append_error.call_args_list]


class TestOverlayNotice:
    def test_refused_login_names_the_bitwarden_cause(self):
        screen, output, _ = _run_ssh("BwSessionMissingError", REFUSED, 255)
        assert LOCKED in screen._output_lines
        assert LOCKED in _shown(output)

    def test_a_working_connection_shows_nothing(self):
        screen, output, _ = _run_ssh("BwSessionMissingError", "", 0)
        assert not any("Bitwarden" in line for line in screen._output_lines)
        assert not any("Bitwarden" in str(part) for part in _shown(output))

    def test_without_a_reason_a_refusal_is_as_today(self):
        screen, _, _ = _run_ssh(None, REFUSED, 255)
        assert not any("Bitwarden" in line for line in screen._output_lines)
        assert REFUSED in screen._output_lines


# --- log viewer reader thread ------------------------------------------------

def _reader(reason, stderr):
    screen = LogViewerScreen({"name": "web-1"})
    screen._bw_key_reason = reason
    screen._process = SimpleNamespace(stdout=io.BytesIO(b""), stderr=io.BytesIO(stderr))
    screen._reader_thread_fn()
    lines = []
    while not screen._line_queue.empty():
        lines.append(screen._line_queue.get_nowait())
    return lines


class TestLogViewerNotice:
    def test_notice_follows_the_ssh_error_line(self):
        lines = _reader("BwSessionMissingError", b"deploy@web-1: Permission denied (publickey).\n")
        assert lines[0].startswith("SSH error:")
        assert lines[1] == LOCKED

    def test_no_notice_when_the_stream_works(self):
        assert not any("Bitwarden" in str(line) for line in _reader("BwSessionMissingError", b""))

    def test_no_notice_without_a_reason(self):
        assert not any("Bitwarden" in str(line) for line in _reader(None, b"Permission denied (publickey).\n"))

    def test_start_stream_keeps_the_reason(self):
        screen, _ = _run_log_viewer(CONN, None, unavailable_provider())
        assert screen._bw_key_reason == "BwSessionMissingError"


# --- quick connect with an unreadable key -------------------------------------

def test_quick_connect_with_an_unreadable_key_is_as_today():
    plain, unavailable = _app(), _app(None, unavailable_provider())
    _run_quick_connect(CONN, plain)
    _run_quick_connect(CONN, unavailable)
    assert _built(plain) == _built(unavailable)
    assert [c.args[0] for c in unavailable.notify.call_args_list] == [
        "SSH session launched for web-1",
    ]


# --- the overlay's next command after unlocking --------------------------------

def _apply_overlay(screen, app) -> None:
    with _with_app(screen, app):
        asyncio.run(screen._apply_vault())


def _refuse_in_overlay(screen, app) -> None:
    """ssh refuses the overlay's next command (its private log says so)."""
    from pathlib import Path

    def popen(argv, *args, **kwargs):
        argv = [str(part) for part in argv]
        Path(argv[argv.index("-E") + 1]).write_text(REFUSED + "\n")
        return _FinishedSsh(255)

    app.call_from_thread = lambda func, *args: func(*args)
    with _with_app(screen, app), patch("servonaut.screens.command_overlay.subprocess.Popen", popen):
        screen._run_ssh_command(["ssh", "deploy@web-1", "uptime"], MagicMock())


def _bw_key_provider(key_path):
    provider = key_provider(key_path)

    async def apply(conn, instance):
        return {**conn, "key_path": key_path, "key_source": "bw_personal",
                "bw_item_id": "33333333-3333-4333-8333-333333333333"}

    provider.apply.side_effect = apply
    provider.key_refused = MagicMock()
    return provider


def test_overlay_next_command_after_a_refusal_and_unlocking_uses_the_key():
    screen = _overlay(CONN)
    _apply_overlay(screen, _app(None, unavailable_provider()))
    assert screen._bw_key_reason == "BwSessionMissingError"
    _refuse_in_overlay(screen, _app(None, unavailable_provider()))
    provider = key_provider(BW_KEY)
    _apply_overlay(screen, _app(None, provider))
    assert screen._key_path == BW_KEY and screen._bw_key_reason is None
    assert provider.apply.await_args.args[0]["key_path"] == KEY_FILE


def test_overlay_does_not_resolve_before_every_command_while_a_reason_is_set():
    screen = _overlay(CONN)
    provider = unavailable_provider()
    _apply_overlay(screen, _app(None, provider))
    _apply_overlay(screen, _app(None, provider))
    assert provider.apply.await_count == 1


def test_overlay_keeps_a_used_key_for_later_commands(tmp_path):
    key = tmp_path / "bw-test"
    key.write_text("key")
    screen = _overlay(CONN)
    provider = key_provider(str(key))
    _apply_overlay(screen, _app(None, provider))
    _apply_overlay(screen, _app(None, provider))
    assert provider.apply.await_count == 1


def test_overlay_drops_a_refused_bitwarden_key_and_reads_it_again(tmp_path):
    key = tmp_path / "bw-key"
    key.write_text("key")
    provider = _bw_key_provider(str(key))
    app = _app(None, provider)
    screen = _overlay(CONN)
    _apply_overlay(screen, app)
    _refuse_in_overlay(screen, app)
    provider.key_refused.assert_called_once()
    assert provider.key_refused.call_args.args[0]["bw_item_id"] == "33333333-3333-4333-8333-333333333333"
    _apply_overlay(screen, app)
    assert provider.apply.await_count == 2


def test_overlay_resolves_again_when_the_key_file_is_gone(tmp_path):
    key = tmp_path / "bw-key"
    key.write_text("key")
    provider = _bw_key_provider(str(key))
    screen = _overlay(CONN)
    _apply_overlay(screen, _app(None, provider))
    key.unlink()  # forget_keys ran
    _apply_overlay(screen, _app(None, provider))
    assert provider.apply.await_count == 2
