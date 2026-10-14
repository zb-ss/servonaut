"""The shared vault overlay every in-app SSH path applies (services/ssh_credentials)."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.ssh_credentials import (
    VaultCredentialError,
    VaultLeaseCache,
    apply_vault_lease,
    lease_key,
    resolve_with_vault,
    ssh_identity_kwargs,
    vault_lease,
)

LOCAL = {
    "host": "192.0.2.10", "username": "deploy", "key_path": "/keys/web1",
    "proxy_args": [], "port": 2222, "extra_options": ["ServerAliveInterval=30"],
}
CUSTOM = {"id": "custom-web-1", "name": "web-1", "is_custom": True, "provider": "custom"}


def _lease(tmp_path, **overrides):
    agent = tmp_path / "agent.sock"
    agent.touch()
    values = {
        "source": "vault",
        "identity_agent": str(agent),
        "identity_file": str(tmp_path / "key.pub"),
        "certificate_path": None,
        "known_hosts_path": str(tmp_path / "known_hosts"),
        "login_user": "deploy",
        "target_host": "192.0.2.10",
        "target_port": 2222,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _runtime(lease=None, *, raises=None, ttl=3600):
    runtime = MagicMock()
    runtime.agent_key_ttl_seconds = ttl
    runtime.resolve_ssh = AsyncMock(return_value=lease, side_effect=raises)
    return runtime


def _resolve(conn, instance, runtime, cache=None, connection_service=None):
    return asyncio.run(resolve_with_vault(
        conn, instance, vault_runtime=runtime,
        connection_service=connection_service or MagicMock(resolve_profile=MagicMock(return_value=None)),
        cache=cache,
    ))


class TestResolveWithVault:
    def test_no_vault_runtime_keeps_the_local_connection(self):
        assert _resolve(LOCAL, CUSTOM, None) == LOCAL

    def test_a_server_without_a_vault_credential_keeps_its_local_key(self):
        assert _resolve(LOCAL, CUSTOM, _runtime(None)) == LOCAL

    def test_a_vault_lease_replaces_the_local_key(self, tmp_path):
        lease = _lease(tmp_path, login_user="ops", target_host="198.51.100.7", target_port=22)

        conn = _resolve(LOCAL, CUSTOM, _runtime(lease))

        assert conn["key_path"] is None
        assert conn["identity_agent"] == lease.identity_agent
        assert conn["identity_file"] == lease.identity_file
        assert conn["known_hosts_path"] == lease.known_hosts_path
        assert (conn["username"], conn["host"], conn["port"]) == ("ops", "198.51.100.7", 22)
        assert conn["extra_options"] == LOCAL["extra_options"]
        assert conn["key_source"] == "vault_vault"

    def test_a_bastion_profile_reaches_the_jump_host_through_the_private_agent(self, tmp_path):
        lease = _lease(tmp_path)
        profile = object()
        connection_service = MagicMock()
        connection_service.resolve_profile.return_value = profile
        connection_service.get_proxy_args.return_value = ["-J", "bastion"]

        conn = _resolve({**LOCAL, "proxy_args": ["-J", "old"]}, CUSTOM, _runtime(lease),
                        connection_service=connection_service)

        connection_service.get_proxy_args.assert_called_once_with(profile, identity_agent=lease.identity_agent)
        assert conn["proxy_args"] == ["-J", "bastion"]

    def test_an_unusable_vault_credential_fails_closed(self):
        runtime = _runtime(raises=RuntimeError("locked"))

        with pytest.raises(VaultCredentialError, match="could not be used"):
            _resolve(LOCAL, CUSTOM, runtime)

    def test_a_team_server_bound_to_the_vault_never_falls_back(self):
        shared = {**CUSTOM, "is_shared": True, "credential_binding": {"source": "servonaut_vault"}}

        with pytest.raises(VaultCredentialError, match="not available"):
            _resolve(LOCAL, shared, None)
        with pytest.raises(VaultCredentialError, match="unavailable"):
            _resolve(LOCAL, shared, _runtime(None))

    def test_a_lease_without_its_host_pins_is_refused(self, tmp_path):
        with pytest.raises(VaultCredentialError, match="host-key file"):
            _resolve(LOCAL, CUSTOM, _runtime(_lease(tmp_path, known_hosts_path="")))


class TestLeaseCache:
    def test_a_lease_is_reused_while_its_key_is_loaded(self, tmp_path):
        clock = [1000.0]
        cache = VaultLeaseCache(clock=lambda: clock[0])
        runtime = _runtime(_lease(tmp_path), ttl=600)

        first = asyncio.run(vault_lease(CUSTOM, runtime, cache=cache))
        clock[0] += 500
        second = asyncio.run(vault_lease(CUSTOM, runtime, cache=cache))

        assert first is second
        runtime.resolve_ssh.assert_awaited_once()

    def test_a_lease_close_to_expiry_is_resolved_again(self, tmp_path):
        clock = [1000.0]
        cache = VaultLeaseCache(clock=lambda: clock[0])
        runtime = _runtime(_lease(tmp_path), ttl=600)

        asyncio.run(vault_lease(CUSTOM, runtime, cache=cache))
        clock[0] += 590  # within the expiry margin
        asyncio.run(vault_lease(CUSTOM, runtime, cache=cache))

        assert runtime.resolve_ssh.await_count == 2

    def test_a_lease_whose_agent_is_gone_is_resolved_again(self, tmp_path):
        cache = VaultLeaseCache()
        lease = _lease(tmp_path)
        runtime = _runtime(lease)

        asyncio.run(vault_lease(CUSTOM, runtime, cache=cache))
        (tmp_path / "agent.sock").unlink()
        asyncio.run(vault_lease(CUSTOM, runtime, cache=cache))

        assert runtime.resolve_ssh.await_count == 2

    def test_servers_with_the_same_name_in_two_accounts_get_their_own_leases(self):
        prod = {"id": "i-1", "provider": "aws", "account": "prod"}
        staging = {"id": "i-1", "provider": "aws", "account": "staging"}

        assert lease_key(prod) != lease_key(staging)

    def test_forget_drops_a_servers_lease(self, tmp_path):
        cache = VaultLeaseCache()
        runtime = _runtime(_lease(tmp_path))
        asyncio.run(vault_lease(CUSTOM, runtime, cache=cache))

        cache.forget(CUSTOM)
        asyncio.run(vault_lease(CUSTOM, runtime, cache=cache))

        assert runtime.resolve_ssh.await_count == 2


def test_identity_kwargs_name_the_builder_arguments(tmp_path):
    conn = apply_vault_lease(LOCAL, _lease(tmp_path, certificate_path="/c.pub"),
                             instance=CUSTOM, connection_service=None)

    assert ssh_identity_kwargs(conn) == {
        "identity_agent": conn["identity_agent"],
        "identity_file": conn["identity_file"],
        "certificate_file": "/c.pub",
        "known_hosts_file": conn["known_hosts_path"],
    }
