"""Tests for the ``servonaut hetzner ...`` CLI dispatcher."""

from __future__ import annotations

import argparse
import io
import json
import os
import signal
import sys
import time
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.cli import hetzner as cli_hetzner
from servonaut.cli.hetzner import (
    _EXIT_DECLINED,
    _EXIT_GENERIC_ERROR,
    _EXIT_NOT_CONFIGURED,
    _EXIT_SUCCESS,
    _EXIT_VALIDATION,
    add_hetzner_parser,
    handle_hetzner_command,
)


def _make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='subcommand')
    add_hetzner_parser(sub)
    return parser


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------

class TestArgparse:
    def test_list_parses(self):
        parser = _make_parser()
        args = parser.parse_args(['hetzner', 'list', '--json'])
        assert args.hetzner_command == 'list'
        assert args.json is True

    def test_create_requires_name(self):
        parser = _make_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(['hetzner', 'create'])

    def test_create_repeatable_ssh_keys(self):
        parser = _make_parser()
        args = parser.parse_args([
            'hetzner', 'create', 'demo', '--ssh-key', 'a', '--ssh-key', 'b',
        ])
        assert args.ssh_keys == ['a', 'b']
        assert args.no_wait is False

    def test_destroy_requires_identifier(self):
        parser = _make_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(['hetzner', 'destroy'])

    def test_ssh_keys_add_requires_source(self):
        parser = _make_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(['hetzner', 'ssh-keys', 'add', 'name'])
        # Either flag is fine
        a = parser.parse_args([
            'hetzner', 'ssh-keys', 'add', 'name', '--public-key', 'ssh-ed25519 X',
        ])
        assert a.public_key == 'ssh-ed25519 X'


# ---------------------------------------------------------------------------
# Handler tests — patch _build_service to inject a mock
# ---------------------------------------------------------------------------

@pytest.fixture
def mocked_service():
    """Patch _build_service to return a controllable mock."""
    svc = MagicMock()
    with patch.object(cli_hetzner, '_build_service', return_value=svc):
        yield svc


class _TerminalStdin(io.StringIO):
    """Standard input that reports itself as a terminal."""

    def isatty(self) -> bool:
        return True


@pytest.fixture
def terminal_stdin(monkeypatch):
    """``create`` only asks y/N on a terminal; pytest's stdin is not one."""
    monkeypatch.setattr(sys, 'stdin', _TerminalStdin())


def _run_cli(parser: argparse.ArgumentParser, argv: list) -> tuple[int, str, str]:
    args = parser.parse_args(argv)
    out_buf, err_buf = io.StringIO(), io.StringIO()
    with redirect_stdout(out_buf), redirect_stderr(err_buf):
        rc = handle_hetzner_command(args)
    return rc, out_buf.getvalue(), err_buf.getvalue()


class TestListHandler:
    def test_table_render(self, mocked_service):
        mocked_service.fetch_instances_cached = AsyncMock(return_value=[
            {
                "id": "1", "name": "demo-1", "type": "cx22",
                "state": "running", "public_ip": "1.2.3.4", "region": "fsn1",
            },
        ])
        rc, out, _ = _run_cli(_make_parser(), ['hetzner', 'list'])
        assert rc == _EXIT_SUCCESS
        assert "demo-1" in out
        assert "1.2.3.4" in out

    def test_json_output(self, mocked_service):
        instances = [{"id": "1", "name": "demo"}]
        mocked_service.fetch_instances_cached = AsyncMock(return_value=instances)
        rc, out, _ = _run_cli(_make_parser(), ['hetzner', 'list', '--json'])
        assert rc == _EXIT_SUCCESS
        assert json.loads(out) == instances

    def test_state_filter(self, mocked_service):
        mocked_service.fetch_instances_cached = AsyncMock(return_value=[
            {"id": "1", "name": "alpha-running", "state": "running"},
            {"id": "2", "name": "bravo-stopped", "state": "off"},
        ])
        rc, out, _ = _run_cli(_make_parser(), [
            'hetzner', 'list', '--state', 'running',
        ])
        assert rc == _EXIT_SUCCESS
        assert "alpha-running" in out
        assert "bravo-stopped" not in out

    def test_api_error(self, mocked_service):
        mocked_service.fetch_instances_cached = AsyncMock(
            side_effect=RuntimeError("rate-limit"),
        )
        rc, _, err = _run_cli(_make_parser(), ['hetzner', 'list'])
        assert rc == _EXIT_GENERIC_ERROR
        assert "rate-limit" in err


@pytest.mark.usefixtures("terminal_stdin")
class TestCreateHandler:
    def test_happy(self, mocked_service):
        mocked_service.create_server = AsyncMock(return_value={
            "id": "555", "name": "demo-1", "type": "cx22",
            "state": "running", "public_ip": "1.2.3.4", "region": "fsn1",
        })
        rc, out, _ = _run_cli(_make_parser(), [
            'hetzner', 'create', 'demo-1',
        ])
        assert rc == _EXIT_SUCCESS
        assert "Created Hetzner server" in out
        mocked_service.create_server.assert_awaited_once()

    def test_validation_error_exit_code(self, mocked_service):
        mocked_service.create_server = AsyncMock(
            side_effect=ValueError("bad name"),
        )
        rc, _, err = _run_cli(_make_parser(), [
            'hetzner', 'create', 'demo',
        ])
        assert rc == _EXIT_VALIDATION
        assert "bad name" in err

    def test_no_wait_flag(self, mocked_service):
        mocked_service.create_server = AsyncMock(return_value={
            "id": "1", "name": "demo", "type": "cx22", "state": "pending",
            "public_ip": "", "region": "fsn1",
        })
        rc, _, _ = _run_cli(_make_parser(), [
            'hetzner', 'create', 'demo', '--no-wait',
        ])
        assert rc == _EXIT_SUCCESS
        kwargs = mocked_service.create_server.call_args.kwargs
        assert kwargs['wait_until_running'] is False


@pytest.mark.usefixtures("terminal_stdin")
class TestCreateConfirmation:
    """``hetzner create`` shows what it will create and asks y/N first."""

    @pytest.fixture
    def service(self, tmp_path):
        pytest.importorskip("hcloud")
        from types import SimpleNamespace

        from servonaut.config.schema import HetznerConfig
        from servonaut.services.hetzner_service import HetznerService

        svc = HetznerService(HetznerConfig(
            enabled=True, api_token="t",
            cache_path=str(tmp_path / "cache.json"),
            audit_path=str(tmp_path / "audit.jsonl"),
        ))
        client = MagicMock()
        client.ssh_keys.get_by_name.return_value = SimpleNamespace(id=11, name="deploy")
        client.servers.create.return_value = SimpleNamespace(server=SimpleNamespace(
            id=555, name="web-2", status="initializing",
            public_net=None, server_type=SimpleNamespace(name="cx32"),
            location=SimpleNamespace(name="nbg1"), created=None, labels={},
        ))
        svc._get_client = lambda: client
        svc.client_mock = client
        with patch.object(cli_hetzner, '_build_service', return_value=svc):
            yield svc

    ARGV = [
        'hetzner', 'create', 'web-2', '--type', 'cx32', '--image', 'debian-12',
        '--location', 'nbg1', '--ssh-key', 'deploy', '--no-wait',
    ]

    def _answer(self, monkeypatch, answer):
        def fake_input(*_args):
            if answer is None:
                raise EOFError
            return answer
        monkeypatch.setattr('builtins.input', fake_input)

    @pytest.mark.parametrize("answer", ["n", "", "no", None])
    def test_anything_but_yes_creates_nothing(self, service, monkeypatch, answer):
        self._answer(monkeypatch, answer)
        rc, out, _ = _run_cli(_make_parser(), self.ARGV)
        assert rc == _EXIT_DECLINED
        assert "About to create Hetzner server 'web-2':" in out
        for line in ("type:      cx32", "image:     debian-12",
                     "location:  nbg1", "SSH keys:  deploy", "Create it? [y/N]"):
            assert line in out
        assert "Cancelled." in out
        service.client_mock.servers.create.assert_not_called()

    def test_yes_creates_the_summarised_server(self, service, monkeypatch):
        self._answer(monkeypatch, "y")
        rc, out, _ = _run_cli(_make_parser(), self.ARGV)
        assert rc == _EXIT_SUCCESS
        assert "Created Hetzner server 'web-2'" in out
        service.client_mock.servers.create.assert_called_once()

    def test_yes_flag_skips_the_question(self, service, monkeypatch):
        monkeypatch.setattr('builtins.input', MagicMock(side_effect=AssertionError("asked")))
        rc, out, _ = _run_cli(_make_parser(), self.ARGV + ['--yes'])
        assert rc == _EXIT_SUCCESS
        assert "About to create" not in out
        service.client_mock.servers.create.assert_called_once()

    def test_json_keeps_the_question_off_stdout(self, service, monkeypatch):
        self._answer(monkeypatch, "yes")
        rc, out, err = _run_cli(_make_parser(), self.ARGV + ['--json'])
        assert rc == _EXIT_SUCCESS
        assert json.loads(out)["name"] == "web-2"
        assert "Create it? [y/N]" in err

    def test_ctrl_c_at_the_question_cancels_and_creates_nothing(
        self, service, monkeypatch, tmp_path,
    ):
        def press_ctrl_c(*_args):
            os.kill(os.getpid(), signal.SIGINT)
            # With Python's default handler the interrupt is raised while
            # this waits. A handler that only cancels the asyncio task lets
            # the wait end and the "y" through.
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                time.sleep(0.01)
            return "y"

        monkeypatch.setattr('builtins.input', press_ctrl_c)
        try:
            rc, out, _ = _run_cli(_make_parser(), self.ARGV)
        except KeyboardInterrupt:
            pytest.fail("Ctrl-C escaped the question instead of cancelling it")

        assert rc == _EXIT_DECLINED
        assert "Cancelled." in out
        service.client_mock.servers.create.assert_not_called()
        audit = (tmp_path / "audit.jsonl").read_text()
        assert "declined: not confirmed" in audit
        # The prompt hands SIGINT back to whoever handled it before.
        assert signal.getsignal(signal.SIGINT) is signal.default_int_handler

    def test_refusal_is_reported_without_asking(self, service, monkeypatch):
        # No key anywhere: the create is refused before any question.
        monkeypatch.setattr('builtins.input', MagicMock(side_effect=AssertionError("asked")))
        argv = [a for a in self.ARGV if a not in ('--ssh-key', 'deploy')]
        rc, _, err = _run_cli(_make_parser(), argv)
        assert rc == _EXIT_GENERIC_ERROR
        assert "Refusing to create a Hetzner server without SSH keys" in err
        service.client_mock.servers.create.assert_not_called()


class TestCreateWithoutATerminal:
    def test_refuses_without_asking_and_points_at_yes(self, monkeypatch):
        # Not a terminal and not at EOF: an answer is waiting, but a script
        # must not be asked at all.
        monkeypatch.setattr(sys, 'stdin', io.StringIO("y\n"))
        build = MagicMock(side_effect=AssertionError("service built"))
        monkeypatch.setattr(cli_hetzner, '_build_service', build)

        rc, out, err = _run_cli(_make_parser(), ['hetzner', 'create', 'web-2'])

        assert rc == _EXIT_DECLINED
        assert "--yes" in err
        assert "Create it?" not in out + err
        build.assert_not_called()
        assert sys.stdin.read() == "y\n"

    def test_yes_creates_without_a_terminal(self, mocked_service, monkeypatch):
        monkeypatch.setattr(sys, 'stdin', io.StringIO(""))
        mocked_service.create_server = AsyncMock(return_value={
            "id": "555", "name": "web-2", "type": "cx22",
            "state": "running", "public_ip": "9.9.9.9", "region": "fsn1",
        })

        rc, _, _ = _run_cli(_make_parser(), ['hetzner', 'create', 'web-2', '--yes'])

        assert rc == _EXIT_SUCCESS
        assert mocked_service.create_server.call_args.kwargs['confirm'] is None


class TestDestroyHandler:
    def test_yes_flag_skips_prompt(self, mocked_service):
        mocked_service.delete_server = AsyncMock(return_value=True)
        rc, out, _ = _run_cli(_make_parser(), [
            'hetzner', 'destroy', 'demo-1', '--yes',
        ])
        assert rc == _EXIT_SUCCESS
        assert "Deleted Hetzner server" in out

    def test_typed_confirm_required_without_yes(self, mocked_service, monkeypatch):
        monkeypatch.setattr('builtins.input', lambda _: 'wrong-name')
        rc, _, err = _run_cli(_make_parser(), [
            'hetzner', 'destroy', 'demo-1',
        ])
        assert rc == _EXIT_DECLINED
        assert "Confirmation mismatch" in err
        mocked_service.delete_server.assert_not_called() if hasattr(
            mocked_service.delete_server, "assert_not_called",
        ) else None

    def test_typed_confirm_match_proceeds(self, mocked_service, monkeypatch):
        mocked_service.delete_server = AsyncMock(return_value=True)
        monkeypatch.setattr('builtins.input', lambda _: 'demo-1')
        rc, out, _ = _run_cli(_make_parser(), [
            'hetzner', 'destroy', 'demo-1',
        ])
        assert rc == _EXIT_SUCCESS
        assert "Deleted Hetzner server" in out


class TestSshKeysHandlers:
    def test_list_table(self, mocked_service):
        mocked_service.list_ssh_keys = AsyncMock(return_value=[
            {"id": "1", "name": "laptop", "fingerprint": "aa:bb"},
        ])
        rc, out, _ = _run_cli(_make_parser(), ['hetzner', 'ssh-keys', 'list'])
        assert rc == _EXIT_SUCCESS
        assert "laptop" in out

    def test_add_with_inline(self, mocked_service):
        mocked_service.create_ssh_key = AsyncMock(return_value={
            "id": "9", "name": "laptop", "fingerprint": "aa:bb",
        })
        rc, out, _ = _run_cli(_make_parser(), [
            'hetzner', 'ssh-keys', 'add', 'laptop',
            '--public-key', 'ssh-ed25519 AAAA',
        ])
        assert rc == _EXIT_SUCCESS
        assert "Registered SSH key" in out

    def test_add_with_file(self, mocked_service, tmp_path):
        keyfile = tmp_path / "id_ed25519.pub"
        keyfile.write_text("ssh-ed25519 AAAA test\n")
        mocked_service.create_ssh_key = AsyncMock(return_value={
            "id": "9", "name": "laptop", "fingerprint": "aa:bb",
        })
        rc, out, _ = _run_cli(_make_parser(), [
            'hetzner', 'ssh-keys', 'add', 'laptop',
            '--public-key-file', str(keyfile),
        ])
        assert rc == _EXIT_SUCCESS
        assert "Registered SSH key" in out

    def test_add_rejects_unrecognised_prefix(self, mocked_service):
        rc, _, err = _run_cli(_make_parser(), [
            'hetzner', 'ssh-keys', 'add', 'laptop',
            '--public-key', 'PRIVATE KEY-----',
        ])
        assert rc == _EXIT_VALIDATION
        assert "must start with" in err

    def test_add_missing_file_returns_validation(self, mocked_service, tmp_path):
        rc, _, err = _run_cli(_make_parser(), [
            'hetzner', 'ssh-keys', 'add', 'laptop',
            '--public-key-file', str(tmp_path / "absent"),
        ])
        assert rc == _EXIT_VALIDATION
        assert "reading public key file" in err


class TestServerTypesHandler:
    def test_table(self, mocked_service):
        mocked_service.list_server_types = AsyncMock(return_value=[
            {
                "id": "1", "name": "cx22", "description": "CX 22",
                "cores": 2, "memory_gb": 4, "disk_gb": 40,
                "architecture": "x86", "hourly_price_gross": "0.005",
                "monthly_price_gross": "3.79", "currency": "EUR",
            },
        ])
        rc, out, _ = _run_cli(_make_parser(), ['hetzner', 'server-types'])
        assert rc == _EXIT_SUCCESS
        assert "cx22" in out
        assert "EUR" in out


class TestTestConnectionHandler:
    def test_success_returns_zero(self, mocked_service):
        mocked_service.test_connection = AsyncMock(return_value={
            "success": True, "message": "OK", "server_count": 0,
        })
        rc, out, _ = _run_cli(_make_parser(), ['hetzner', 'test-connection'])
        assert rc == _EXIT_SUCCESS
        assert "OK" in out

    def test_failure_returns_nonzero(self, mocked_service):
        mocked_service.test_connection = AsyncMock(return_value={
            "success": False, "message": "401",
        })
        rc, _, err = _run_cli(_make_parser(), ['hetzner', 'test-connection'])
        assert rc == _EXIT_GENERIC_ERROR
        assert "401" in err
