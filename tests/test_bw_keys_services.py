"""Scan, log viewer and memory services and a server's Bitwarden SSH key."""
from __future__ import annotations

import asyncio
import subprocess
from subprocess import CalledProcessError
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.log_viewer_service import LogViewerService
from servonaut.services.memory import MemoryService
from servonaut.services.memory.store import MemoryStore
from servonaut.services.scan_service import ScanConnectionError, ScanService
from tests._bw_fixtures import key_provider, no_ref_provider, unavailable_provider
from tests.test_vault_ssh_paths import CUSTOM, _connection_service, _runtime, lease  # noqa: F401

LOCKED = "Bitwarden is locked, so this server's Bitwarden key was not used. Unlock it under Settings > Bitwarden SSH and retry."
REFUSED = "SSH refused the login. Check the server's SSH key, login user or vault binding."
NO_KEY = {k: v for k, v in CUSTOM.items() if k != "ssh_key"}


def _case(name, lease):
    """(instance, vault runtime or None) for one connection type."""
    if name == "local_key":
        return dict(CUSTOM), None
    if name == "no_key":
        return dict(NO_KEY), None
    if name == "vault_lease":
        return dict(CUSTOM), _runtime(lease)
    ca = type(lease)(**{**vars(lease), "certificate_path": "/tmp/cert-cert.pub"})
    return dict(CUSTOM), _runtime(ca)


CASES = ["local_key", "no_key", "vault_lease", "ca_lease"]


# --- scan ---------------------------------------------------------------

def _scan(runtime=None, provider="unset"):
    service = ScanService(MagicMock())
    if runtime is not None:
        service.set_vault_runtime(runtime)
    if provider != "unset":
        service.set_bw_keys(provider)
    return service


def _scan_target(service, instance):
    ssh_service = MagicMock()
    connection_service = _connection_service()
    target = service._resolve_target(instance, ssh_service, connection_service)
    return target, connection_service


def _with_vault(service, instance):
    target, connection_service = _scan_target(service, instance)
    return target, asyncio.run(service._with_vault(target, instance, connection_service))


@pytest.mark.parametrize("name", CASES)
def test_scan_unchanged_without_a_bitwarden_ref(name, lease):
    instance, runtime = _case(name, lease)
    target, plain = _with_vault(_scan(runtime), instance)
    target2, with_none = _with_vault(_scan(runtime, no_ref_provider()), instance)
    if name in ("local_key", "no_key"):
        assert plain is target and with_none is target2
    else:
        assert with_none.identity_agent == plain.identity_agent
        assert with_none.identity_file == plain.identity_file
        assert with_none.known_hosts_file == plain.known_hosts_file
        assert with_none.certificate_file == plain.certificate_file
        assert with_none.host == plain.host and with_none.port == plain.port
    assert with_none.bw_key_reason is None and with_none.key_path == plain.key_path


def test_scan_uses_the_bitwarden_key():
    target, resolved = _with_vault(_scan(provider=key_provider("/tmp/bw-test")), dict(CUSTOM))
    assert resolved.key_path == "/tmp/bw-test"
    for field in ("host", "username", "proxy_args", "port", "extra_options"):
        assert getattr(resolved, field) == getattr(target, field)
    assert resolved.bw_key_reason is None


def test_scan_vault_lease_wins_over_the_bitwarden_key(lease):
    provider = key_provider("/tmp/bw-test")
    _, resolved = _with_vault(_scan(_runtime(lease), provider), dict(CUSTOM))
    assert resolved.key_path is None and resolved.identity_agent == lease.identity_agent
    provider.apply.assert_not_awaited()


def test_scan_unavailable_key_keeps_the_local_key_and_names_the_cause():
    target, resolved = _with_vault(_scan(provider=unavailable_provider()), dict(CUSTOM))
    assert resolved.key_path == target.key_path == "/keys/web1"
    assert resolved.bw_key_reason == "BwSessionMissingError"


def _check(service, target, result=None, error=None):
    if error is not None:
        service._run_ssh = AsyncMock(side_effect=error)
    else:
        service._run_ssh = AsyncMock(return_value=result)
    asyncio.run(service._check_connection(target))


def _result(code, stderr=""):
    return subprocess.CompletedProcess([], code, stdout="", stderr=stderr)


def test_scan_refused_login_names_the_bitwarden_cause():
    service = _scan(provider=unavailable_provider())
    _, resolved = _with_vault(service, dict(CUSTOM))
    with pytest.raises(ScanConnectionError) as info:
        _check(service, resolved, _result(255, "deploy@web-1: Permission denied (publickey)."))
    assert info.value.describe(redact=True) == f"authentication failed ({LOCKED})"


def test_scan_other_failures_and_success_do_not_name_the_cause():
    service = _scan(provider=unavailable_provider())
    _, resolved = _with_vault(service, dict(CUSTOM))
    with pytest.raises(ScanConnectionError) as info:
        _check(service, resolved, _result(255, "ssh: connect to host web-1 port 22: Connection refused"))
    assert info.value.hint != LOCKED and "Bitwarden" not in info.value.describe(redact=False)
    _check(service, resolved, _result(0))


def test_scan_without_set_bw_keys_passes_none():
    service = _scan()
    with patch("servonaut.services.ssh_credentials.resolve_with_vault", AsyncMock(return_value={"host": "h"})) as mocked:
        _with_vault(service, dict(CUSTOM))
    assert mocked.await_args.kwargs["bw_keys"] is None


# --- log viewer -----------------------------------------------------------

def _viewer(runtime=None, provider="unset"):
    service = LogViewerService(MagicMock())
    if runtime is not None:
        service.set_vault_runtime(runtime)
    if provider != "unset":
        service.set_bw_keys(provider)
    return service


def _conn(service, instance):
    ssh_service = MagicMock()
    ssh_service.get_key_path.return_value = None
    ssh_service.discover_key.return_value = None
    return asyncio.run(service.resolve_connection(instance, ssh_service, _connection_service()))


@pytest.mark.parametrize("name", CASES)
def test_log_viewer_unchanged_without_a_bitwarden_ref(name, lease):
    instance, runtime = _case(name, lease)
    plain = _conn(_viewer(runtime), instance)
    assert _conn(_viewer(runtime, no_ref_provider()), instance) == plain
    if name == "local_key":
        assert plain["key_path"] == "/keys/web1" and "key_source" not in plain
        assert "bw_key_unavailable" not in plain


def test_log_viewer_uses_the_bitwarden_key():
    conn = _conn(_viewer(provider=key_provider("/tmp/bw-test")), dict(CUSTOM))
    assert conn["key_path"] == "/tmp/bw-test" and conn["key_source"] == "bw_personal"


def test_log_viewer_vault_lease_wins(lease):
    provider = key_provider("/tmp/bw-test")
    conn = _conn(_viewer(_runtime(lease), provider), dict(CUSTOM))
    assert conn["key_path"] != "/tmp/bw-test"
    provider.apply.assert_not_awaited()


def test_log_viewer_carries_the_reason():
    conn = _conn(_viewer(provider=unavailable_provider()), dict(CUSTOM))
    assert conn["key_path"] == "/keys/web1" and conn["bw_key_unavailable"] == "BwSessionMissingError"


def test_log_viewer_without_set_bw_keys_passes_none():
    with patch("servonaut.services.ssh_credentials.resolve_with_vault", AsyncMock(return_value={})) as mocked:
        _conn(_viewer(), dict(CUSTOM))
    assert mocked.await_args.kwargs["bw_keys"] is None


# --- memory ---------------------------------------------------------------

def _memory(tmp_path, runtime=None, provider="unset"):
    ssh_service = MagicMock()
    ssh_service.build_ssh_command.return_value = ["ssh", "web-1", "true"]
    service = MemoryService(
        store=MemoryStore(root=tmp_path), config=MemoryConfig(),
        ssh_service=ssh_service, connection_service=_connection_service(),
    )
    if runtime is not None:
        service.set_vault_runtime(runtime)
    if provider != "unset":
        service.set_bw_keys(provider)
    return service, ssh_service


def _run_command(service, instance, side_effect=None):
    mock = AsyncMock(side_effect=side_effect) if side_effect else AsyncMock(return_value=(b"ok", b""))

    async def go():
        with patch("servonaut.utils.ssh_utils.run_ssh_subprocess", mock):
            runner = service._make_ssh_runner(instance, multiplex=False)
            out = await runner("uname -a")
        return runner, out

    return asyncio.run(go())


def _build_kwargs(ssh_service):
    return dict(ssh_service.build_ssh_command.call_args.kwargs)


@pytest.mark.parametrize("name", CASES)
def test_memory_unchanged_without_a_bitwarden_ref(name, lease, tmp_path):
    instance, runtime = _case(name, lease)
    service, ssh = _memory(tmp_path / "a", runtime)
    _run_command(service, instance)
    service2, ssh2 = _memory(tmp_path / "b", runtime, no_ref_provider())
    _run_command(service2, instance)
    assert _build_kwargs(ssh) == _build_kwargs(ssh2)


def test_memory_uses_the_bitwarden_key(tmp_path):
    service, ssh = _memory(tmp_path, provider=key_provider("/tmp/bw-test"))
    _run_command(service, dict(CUSTOM))
    assert _build_kwargs(ssh)["key_path"] == "/tmp/bw-test"


def test_memory_vault_lease_wins(lease, tmp_path):
    provider = key_provider("/tmp/bw-test")
    service, ssh = _memory(tmp_path, _runtime(lease), provider)
    _run_command(service, dict(CUSTOM))
    assert _build_kwargs(ssh).get("key_path") is None
    provider.apply.assert_not_awaited()


def _refused():
    err = CalledProcessError(255, ["ssh"], output=b"", stderr=b"")
    err.diagnostics = "deploy@web-1: Permission denied (publickey)."
    return err


def test_memory_refused_login_names_the_bitwarden_cause(tmp_path):
    service, _ = _memory(tmp_path, provider=unavailable_provider())
    runner, _out = _run_command(service, dict(CUSTOM), side_effect=_refused())
    assert runner.connection_problem.reason == "ssh_auth_failed"
    assert runner.connection_problem.message == f"{REFUSED} {LOCKED}"


def test_memory_refused_login_without_a_reason_is_unchanged(tmp_path):
    service, _ = _memory(tmp_path, provider=no_ref_provider())
    runner, _out = _run_command(service, dict(CUSTOM), side_effect=_refused())
    assert runner.connection_problem.message == REFUSED


def test_memory_connecting_build_records_no_problem(tmp_path):
    service, _ = _memory(tmp_path, provider=unavailable_provider())
    runner, _out = _run_command(service, dict(CUSTOM))
    assert runner.connection_problem is None


def test_memory_without_set_bw_keys_passes_none(tmp_path):
    service, _ = _memory(tmp_path)
    with patch("servonaut.services.ssh_credentials.resolve_with_vault", AsyncMock(return_value={"host": "h", "username": "u"})) as mocked:
        _run_command(service, dict(CUSTOM))
    assert mocked.await_args.kwargs["bw_keys"] is None


@pytest.mark.parametrize("cls_path", [
    "servonaut.services.log_viewer_service.LogViewerService",
    "servonaut.services.scan_service.ScanService",
    "servonaut.services.memory.service.MemoryService",
])
def test_a_service_built_without_init_has_no_bitwarden_provider(cls_path):
    """Stand-ins made with __new__ (as some tests and callers do) still work."""
    import importlib

    module_name, _, class_name = cls_path.rpartition(".")
    cls = getattr(importlib.import_module(module_name), class_name)
    assert cls.__new__(cls)._bw_keys is None


# --- a refused Bitwarden key is dropped -----------------------------------

_ITEM = "33333333-3333-4333-8333-333333333333"


def _bw_conn_provider(key_path="/tmp/bw-test"):
    provider = key_provider(key_path)

    async def apply(conn, instance):
        return {**conn, "key_path": key_path, "key_source": "bw_personal", "bw_item_id": _ITEM}

    provider.apply.side_effect = apply
    provider.key_refused = MagicMock()
    return provider


def test_scan_refused_bitwarden_key_is_dropped():
    provider = _bw_conn_provider()
    service = _scan(provider=provider)
    _, resolved = _with_vault(service, dict(CUSTOM))
    with pytest.raises(ScanConnectionError):
        _check(service, resolved, _result(255, "deploy@web-1: Permission denied (publickey)."))
    provider.key_refused.assert_called_once_with(
        {"key_path": "/tmp/bw-test", "key_source": "bw_personal", "bw_item_id": _ITEM},
    )
    # The next scan resolves again (each scan does), so the key is read again.
    _with_vault(service, dict(CUSTOM))
    assert provider.apply.await_count == 2


def test_scan_other_failures_keep_the_bitwarden_key():
    provider = _bw_conn_provider()
    service = _scan(provider=provider)
    _, resolved = _with_vault(service, dict(CUSTOM))
    with pytest.raises(ScanConnectionError):
        _check(service, resolved, _result(255, "ssh: connect to host web-1 port 22: Connection refused"))
    provider.key_refused.assert_not_called()


def test_scan_item_id_never_reaches_the_ssh_builder():
    service = _scan(provider=_bw_conn_provider())
    _, resolved = _with_vault(service, dict(CUSTOM))
    resolved.argv("true")
    kwargs = resolved.ssh_service.build_ssh_command.call_args.kwargs
    assert "bw_item_id" not in kwargs and "key_source" not in kwargs


def test_memory_refused_bitwarden_key_is_dropped(tmp_path):
    provider = _bw_conn_provider()
    service, ssh = _memory(tmp_path, provider=provider)
    runner, _out = _run_command(service, dict(CUSTOM), side_effect=_refused())
    assert runner.connection_problem.reason == "ssh_auth_failed"
    refused = provider.key_refused.call_args.args[0]
    assert refused["bw_item_id"] == _ITEM and refused["key_source"] == "bw_personal"
    assert "bw_item_id" not in _build_kwargs(ssh)
    # The next build resolves again, so the key is read again.
    _run_command(service, dict(CUSTOM))
    assert provider.apply.await_count == 2


def test_memory_connecting_build_keeps_the_bitwarden_key(tmp_path):
    provider = _bw_conn_provider()
    service, _ = _memory(tmp_path, provider=provider)
    _run_command(service, dict(CUSTOM))
    provider.key_refused.assert_not_called()
