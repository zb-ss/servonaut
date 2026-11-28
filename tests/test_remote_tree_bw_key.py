"""RemoteTree: Bitwarden key, authentication label and the notice on a refused login."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from servonaut.services.bw_key_notice import bw_key_notice
from servonaut.widgets.remote_tree import RemoteCredentialError, RemoteTree
from tests._bw_fixtures import key_provider, no_ref_provider, unavailable_provider

_LS_OUTPUT = (
    "total 8\n"
    "drwxr-xr-x 3 root root 4096 Jan  1 00:00 .\n"
    "drwxr-xr-x 3 root root 4096 Jan  1 00:00 ..\n"
    "drwxr-xr-x 2 root root 4096 Jan  1 00:00 shared\n"
)
_REFUSED = "deploy@web-1: Permission denied (publickey)."
_LOCKED_NOTICE = (
    "Bitwarden is locked, so this server's Bitwarden key was not used. "
    "Unlock it under Settings > Bitwarden SSH and retry."
)


def _completed(returncode: int, stdout: str = "", stderr: str = ""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _connection_service():
    service = MagicMock()
    service.resolve_profile.return_value = None
    service.get_target_host.return_value = "192.0.2.10"
    service.get_target_port.return_value = 22
    service.get_extra_options.return_value = []
    service.get_proxy_args.return_value = []
    return service


def _make_tree(*, instance=None, key="/keys/web1", literal_paths=False, **kwargs) -> RemoteTree:
    ssh = MagicMock()
    ssh.get_key_path.return_value = key
    ssh.discover_key.return_value = None
    ssh.build_ssh_command.side_effect = lambda **kw: ["ssh", "host", kw["remote_command"]]
    instance = instance or {
        "id": "custom-web-1", "name": "web-1", "is_custom": True,
        "provider": "custom", "ssh_key": key,
    }
    return RemoteTree(
        instance=instance, ssh_service=ssh, connection_service=_connection_service(),
        username="deploy", scan_paths=["/srv"], literal_paths=literal_paths, **kwargs,
    )


def _app(runtime=None, **extra):
    return SimpleNamespace(
        vault_command_service=runtime, vault_lease_cache=None, instances=[], **extra,
    )


def _lease(tmp_path, **overrides):
    agent = tmp_path / "agent.sock"
    agent.touch()
    values = {
        "source": "vault", "identity_agent": str(agent),
        "identity_file": str(tmp_path / "key.pub"), "certificate_path": None,
        "known_hosts_path": str(tmp_path / "known_hosts"), "login_user": "deploy",
        "target_host": "192.0.2.10", "target_port": 22,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _runtime(lease):
    from unittest.mock import AsyncMock
    runtime = MagicMock()
    runtime.agent_key_ttl_seconds = 3600
    runtime.resolve_ssh = AsyncMock(return_value=lease)
    return runtime


def _apply_and_list(tree: RemoteTree, app) -> dict:
    with patch.object(RemoteTree, "app", new_callable=PropertyMock, return_value=app):
        asyncio.run(tree._apply_vault())
    with patch("servonaut.widgets.remote_tree.subprocess.run",
               return_value=_completed(0, _LS_OUTPUT)):
        tree._run_ls("true")
    return tree._ssh_service.build_ssh_command.call_args.kwargs


def _refuse(tree: RemoteTree) -> list:
    calls: list = []

    def _run(cmd, **kw):
        calls.append(cmd[-1])
        return _completed(255, stderr=_REFUSED)

    with patch("servonaut.widgets.remote_tree.subprocess.run", side_effect=_run):
        try:
            tree._fetch_directory_contents("/srv")
        except RuntimeError as exc:
            calls.append(exc)
    return calls


# ---------------------------------------------------------------------------
# Step 0: nothing changes without a Bitwarden ref
# ---------------------------------------------------------------------------

def _case_local(tmp_path):
    return _make_tree(), None, {"key_path": "/keys/web1"}


def _case_no_key(tmp_path):
    instance = {"id": "custom-web-1", "name": "web-1", "is_custom": True, "provider": "custom"}
    return _make_tree(instance=instance, key=None), None, {"key_path": None}


def _case_vault(tmp_path):
    lease = _lease(tmp_path)
    return _make_tree(), _runtime(lease), {"key_path": None, "identity_file": lease.identity_file}


def _case_ca(tmp_path):
    cert = str(tmp_path / "cert.pub")
    lease = _lease(tmp_path, certificate_path=cert)
    return _make_tree(), _runtime(lease), {"key_path": None, "certificate_file": cert}


def _case_options(tmp_path):
    options = {
        "host": "192.0.2.10", "username": "deploy", "key_path": None, "port": 22,
        "identity_agent": "/run/agent.sock", "identity_file": "/keys/id.pub",
        "known_hosts_file": "/keys/known_hosts",
    }
    tree = _make_tree(connection_options=options)
    return tree, None, {
        "key_path": None, "identity_agent": "/run/agent.sock",
        "identity_file": "/keys/id.pub", "known_hosts_file": "/keys/known_hosts",
    }


@pytest.mark.parametrize("case", [_case_local, _case_no_key, _case_vault, _case_ca, _case_options])
class TestUnchangedWithoutBitwardenRef:
    def test_kwargs_equal_with_and_without_a_provider(self, case, tmp_path):
        tree, runtime, expected = case(tmp_path)
        plain = _apply_and_list(tree, _app(runtime))
        tree2, runtime2, _ = case(tmp_path)
        with_provider = _apply_and_list(tree2, _app(runtime2, bw_ssh_keys=no_ref_provider()))
        assert plain == with_provider
        for name, value in expected.items():
            assert plain[name] == value
        assert tree._bw_key_reason is None or case is _case_options


def test_local_key_kwargs_literal(tmp_path):
    kwargs = _apply_and_list(_make_tree(), _app())
    assert kwargs == {
        "host": "192.0.2.10", "username": "deploy", "key_path": "/keys/web1",
        "remote_command": "true", "proxy_args": [], "port": 22, "extra_options": [],
    }


# ---------------------------------------------------------------------------
# Error label and path message
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("literal", [True, False])
@pytest.mark.parametrize("text", [
    _REFUSED, "deploy@web-1: Permission denied (publickey,password).",
])
def test_login_refusal_is_labelled_authentication_failed(literal, text):
    tree = _make_tree(literal_paths=literal)
    assert tree._error_label(text, login_refused=True) == "🔑 Authentication failed"


@pytest.mark.parametrize("literal", [True, False])
def test_refusal_words_from_a_remote_error_are_not_an_authentication_failure(literal):
    text = "ls: cannot open directory 'deploy@web-1: Permission denied (publickey).': Permission denied"
    assert _make_tree(literal_paths=literal)._error_label(text) != "🔑 Authentication failed"


def test_remote_permission_error_keeps_its_label():
    tree = _make_tree(literal_paths=True)
    assert tree._error_label("ls: cannot open directory '/mnt/efs': Permission denied") == "🔒 Permission denied"


def test_remote_permission_error_still_retries_with_sudo():
    tree = _make_tree()
    calls = []

    def _run(cmd, **kw):
        calls.append(cmd[-1])
        if cmd[-1].startswith("sudo -n"):
            return _completed(0, _LS_OUTPUT)
        return _completed(2, stderr="ls: cannot open directory '/mnt/efs': Permission denied")

    with patch("servonaut.widgets.remote_tree.subprocess.run", side_effect=_run):
        tree._fetch_directory_contents("/mnt/efs")
    assert len(calls) == 2 and calls[1].startswith("sudo -n")


# ---------------------------------------------------------------------------
# Refused login: no sudo retry, Bitwarden notice only with a reason
# ---------------------------------------------------------------------------

def test_refused_login_runs_once_and_raises_the_ssh_text():
    from servonaut.widgets.remote_tree import RemoteLoginRefusedError

    calls = _refuse(_make_tree())
    assert len(calls) == 2 and not any("sudo -n" in c for c in calls[:1])
    assert type(calls[1]) is RemoteLoginRefusedError and str(calls[1]) == _REFUSED


@pytest.mark.parametrize("literal", [True, False])
def test_refusal_words_with_a_remote_exit_code_are_a_folder_error(literal):
    """ls exiting 2 with ssh's refusal words in a file name: a folder error, sudo allowed."""
    from servonaut.widgets.remote_tree import RemoteLoginRefusedError

    tree = _make_tree(literal_paths=literal)
    tree._bw_key_reason = "BwSessionMissingError"
    calls = []
    stderr = "deploy@web-1: Permission denied (publickey)."

    def _run(cmd, **kw):
        calls.append(cmd[-1])
        return _completed(2, stderr=stderr)

    with patch("servonaut.widgets.remote_tree.subprocess.run", side_effect=_run):
        with pytest.raises(RuntimeError) as info:
            tree._fetch_directory_contents("/srv")
    assert not isinstance(info.value, RemoteLoginRefusedError)
    assert "Bitwarden" not in str(info.value)
    assert any("sudo -n" in c for c in calls)
    assert tree._login_refused is False


def test_a_refusal_line_with_exit_255_is_a_refusal_without_a_sudo_retry():
    calls = _refuse(_make_tree(literal_paths=True))
    assert not any("sudo -n" in str(c) for c in calls)


def test_refused_login_with_reason_raises_the_notice():
    tree = _make_tree()
    tree._bw_key_reason = "BwSessionMissingError"
    calls = _refuse(tree)
    assert len(calls) == 2
    assert isinstance(calls[1], RemoteCredentialError) and str(calls[1]) == _LOCKED_NOTICE


def test_successful_listing_with_reason_shows_no_bitwarden_text():
    tree = _make_tree()
    tree._bw_key_reason = "BwSessionMissingError"
    with patch("servonaut.widgets.remote_tree.subprocess.run",
               return_value=_completed(0, _LS_OUTPUT)):
        entries = tree._fetch_directory_contents("/srv")
    assert [e["name"] for e in entries] == ["shared"]
    assert "Bitwarden" not in repr(entries)


def test_connection_options_tree_with_reason_raises_the_cli_notice():
    options = {"host": "192.0.2.10", "username": "deploy", "key_path": None, "port": 22}
    tree = _make_tree(connection_options=options, bw_key_reason="BwCliMissingError")
    calls = _refuse(tree)
    assert str(calls[-1]) == bw_key_notice("BwCliMissingError")


# ---------------------------------------------------------------------------
# _apply_vault with a provider
# ---------------------------------------------------------------------------

def test_apply_vault_uses_the_bitwarden_key():
    tree = _make_tree()
    kwargs = _apply_and_list(tree, _app(bw_ssh_keys=key_provider("/tmp/bw-test")))
    assert tree._key_path == "/tmp/bw-test" and kwargs["key_path"] == "/tmp/bw-test"
    assert tree._bw_key_reason is None


def test_apply_vault_unavailable_keeps_the_original_key_and_records_the_reason():
    tree = _make_tree()
    kwargs = _apply_and_list(tree, _app(bw_ssh_keys=unavailable_provider()))
    assert tree._key_path == "/keys/web1" and kwargs["key_path"] == "/keys/web1"
    assert tree._bw_key_reason == "BwSessionMissingError"


def test_vault_lease_wins_over_the_bitwarden_key(tmp_path):
    lease = _lease(tmp_path)
    tree = _make_tree()
    provider = key_provider()
    kwargs = _apply_and_list(tree, _app(_runtime(lease), bw_ssh_keys=provider))
    assert kwargs["key_path"] is None
    assert kwargs["identity_file"] == lease.identity_file
    provider.apply.assert_not_awaited()


# ---------------------------------------------------------------------------
# A resolution without the Bitwarden key is not final
# ---------------------------------------------------------------------------

def _apply(tree: RemoteTree, app) -> None:
    with patch.object(RemoteTree, "app", new_callable=PropertyMock, return_value=app):
        asyncio.run(tree._apply_vault())


def _refuse_listing(tree: RemoteTree, app) -> None:
    """A listing ssh refuses (through the async path, which drops a refused key)."""
    with patch.object(RemoteTree, "app", new_callable=PropertyMock, return_value=app), \
            patch("servonaut.widgets.remote_tree.subprocess.run",
                  return_value=_completed(255, stderr=_REFUSED)):
        with pytest.raises(RuntimeError):
            asyncio.run(tree._fetch_directory_async("/srv"))


def test_retry_after_a_refusal_and_unlocking_uses_the_bitwarden_key():
    tree = _make_tree()
    _refuse_listing(tree, _app(bw_ssh_keys=unavailable_provider()))
    assert tree._bw_key_reason == "BwSessionMissingError"
    tree.retry("/srv")
    kwargs = _apply_and_list(tree, _app(bw_ssh_keys=key_provider("/tmp/bw-test")))
    assert kwargs["key_path"] == "/tmp/bw-test"
    assert tree._bw_key_reason is None


def test_refresh_after_a_refusal_and_unlocking_uses_the_bitwarden_key():
    tree = _make_tree()
    _refuse_listing(tree, _app(bw_ssh_keys=unavailable_provider()))
    with patch.object(RemoteTree, "cancel_loads"):
        tree.refresh_paths()
    _apply(tree, _app(bw_ssh_keys=key_provider("/tmp/bw-test")))
    assert tree._key_path == "/tmp/bw-test" and tree._bw_key_reason is None


def test_resolution_starts_again_from_the_original_connection():
    tree = _make_tree()
    provider = unavailable_provider()
    _refuse_listing(tree, _app(bw_ssh_keys=provider))
    _apply(tree, _app(bw_ssh_keys=provider))
    first, second = (call.args[0] for call in provider.apply.await_args_list)
    assert first == second and first["key_path"] == "/keys/web1"


def test_a_working_listing_with_a_reason_is_not_resolved_again():
    tree = _make_tree()
    provider = unavailable_provider()
    _apply(tree, _app(bw_ssh_keys=provider))
    tree.retry("/srv")
    _apply(tree, _app(bw_ssh_keys=provider))
    assert provider.apply.await_count == 1


def test_without_a_retry_the_unavailable_resolution_is_reused():
    tree = _make_tree()
    provider = unavailable_provider()
    _apply(tree, _app(bw_ssh_keys=provider))
    _apply(tree, _app(bw_ssh_keys=provider))
    assert provider.apply.await_count == 1


def test_a_used_bitwarden_key_stays_cached_after_a_retry(tmp_path):
    tree = _make_tree()
    key = tmp_path / "bw-test"
    key.write_text("key")  # the provider's file is still in place
    provider = key_provider(str(key))
    _apply(tree, _app(bw_ssh_keys=provider))
    tree.retry("/srv")
    _apply(tree, _app(bw_ssh_keys=provider))
    assert provider.apply.await_count == 1


def test_connection_options_tree_is_never_resolved_again():
    options = {"host": "192.0.2.10", "username": "deploy", "key_path": None, "port": 22}
    tree = _make_tree(connection_options=options, bw_key_reason="BwSessionMissingError")
    provider = key_provider("/tmp/bw-test")
    tree.retry("/srv")
    _apply(tree, _app(bw_ssh_keys=provider))
    provider.apply.assert_not_awaited()
    assert tree._key_path is None


# ---------------------------------------------------------------------------
# A refused Bitwarden key is dropped; a removed key file is resolved again
# ---------------------------------------------------------------------------

def _bw_conn_provider(key_path: str):
    """A provider whose key is read from *key_path*, with key_refused recorded."""
    from unittest.mock import MagicMock as _Mock

    provider = key_provider(key_path)

    async def apply(conn, instance):
        return {**conn, "key_path": key_path, "key_source": "bw_personal",
                "bw_item_id": "33333333-3333-4333-8333-333333333333"}

    provider.apply.side_effect = apply
    provider.key_refused = _Mock()
    return provider


def test_a_refused_bitwarden_key_is_dropped_and_read_again(tmp_path):
    key = tmp_path / "bw-key"
    key.write_text("key")
    provider = _bw_conn_provider(str(key))
    app = _app(bw_ssh_keys=provider)
    tree = _make_tree()
    _refuse_listing(tree, app)
    provider.key_refused.assert_called_once()
    refused = provider.key_refused.call_args.args[0]
    assert refused["bw_item_id"] == "33333333-3333-4333-8333-333333333333"
    tree.retry("/srv")
    _apply(tree, app)
    assert provider.apply.await_count == 2


def test_a_refusal_without_bitwarden_drops_nothing():
    provider = no_ref_provider()
    provider.key_refused = MagicMock()
    tree = _make_tree()
    _refuse_listing(tree, _app(bw_ssh_keys=provider))
    _apply(tree, _app(bw_ssh_keys=provider))
    assert provider.apply.await_count == 1


def test_a_removed_key_file_is_resolved_again(tmp_path):
    key = tmp_path / "bw-key"
    key.write_text("key")
    provider = _bw_conn_provider(str(key))
    tree = _make_tree()
    _apply(tree, _app(bw_ssh_keys=provider))
    key.unlink()  # forget_keys ran: Bitwarden locked, signed out, ref edited
    _apply(tree, _app(bw_ssh_keys=provider))
    assert provider.apply.await_count == 2


def test_the_bitwarden_item_id_never_reaches_the_ssh_builder(tmp_path):
    key = tmp_path / "bw-key"
    key.write_text("key")
    tree = _make_tree()
    kwargs = _apply_and_list(tree, _app(bw_ssh_keys=_bw_conn_provider(str(key))))
    assert "bw_item_id" not in kwargs and "key_source" not in kwargs
