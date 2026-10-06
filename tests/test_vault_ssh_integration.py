"""Native Vault SSH resolution must remain agent-only and fail closed."""

from __future__ import annotations

import asyncio
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import AppConfig, SSHConfig
from servonaut.services.ssh_ref_resolver import SshRefResolver, VaultResolutionError
from servonaut.services.ssh_service import SSHService


def _run(coroutine: object) -> object:
    return asyncio.run(coroutine)  # type: ignore[arg-type]


def _instance() -> dict[str, object]:
    return {
        "id": "c2a4e6f8-1b3d-4f5a-9c7e-0a2b4c6d8e1f",
        "is_shared": True,
        "team_slug": "team-a",
        "credential_binding": {"source": "servonaut_vault", "vault_id": "vault-1"},
    }


class _Runtime:
    async def resolve_ssh(self, instance: dict[str, object]) -> object:
        return SimpleNamespace(
            source="vault",
            identity_agent="/tmp/agent.sock",
            identity_file="/tmp/agent-key.pub",
            certificate_path=None,
            known_hosts_path="/tmp/known_hosts",
            login_user="deploy",
            host_keys=("ssh-ed25519 AAAA",),
            public_key="ssh-ed25519 AAAA",
            vault_id="vault-1",
            vault_item_id="item-1",
            binding={"vault_id": "vault-1"},
        )


def _resolver(runtime: object) -> SshRefResolver:
    ssh = MagicMock()
    ssh.get_key_path.return_value = "/home/test/.ssh/local"  # leak-guard:allow — generic test path
    return SshRefResolver(MagicMock(), MagicMock(), ssh, vault_runtime=runtime)


def test_native_vault_precedes_legacy_refs_and_carries_only_agent_metadata() -> None:
    resolved = _run(_resolver(_Runtime()).resolve(_instance()))
    assert resolved is not None
    assert resolved.source == "vault"
    assert resolved.vault_id == "vault-1"
    assert resolved.vault_item_id == "item-1"
    assert resolved.login_user == "deploy"
    assert resolved.local_key_path is None
    assert not hasattr(resolved.lease, "private_key")


def test_native_binding_failure_never_falls_back_to_a_local_key() -> None:
    class FailingRuntime:
        async def resolve_ssh(self, instance: dict[str, object]) -> None:
            raise ValueError("invalid signature")

    with pytest.raises(VaultResolutionError):
        _run(_resolver(FailingRuntime()).resolve(_instance()))


def test_native_binding_without_a_runtime_never_falls_back_to_a_local_key() -> None:
    with pytest.raises(VaultResolutionError):
        _run(_resolver(None).resolve(_instance()))


def test_native_binding_without_a_lease_never_falls_back_to_a_local_key() -> None:
    class EmptyRuntime:
        async def resolve_ssh(self, instance: dict[str, object]) -> None:
            return None

    with pytest.raises(VaultResolutionError):
        _run(_resolver(EmptyRuntime()).resolve(_instance()))


def test_native_binding_without_a_public_identity_file_never_falls_back() -> None:
    class IncompleteRuntime:
        async def resolve_ssh(self, instance: dict[str, object]) -> object:
            return SimpleNamespace(
                source="vault", identity_agent="/tmp/agent.sock",
                known_hosts_path="/tmp/known-hosts", login_user="deploy",
            )

    with pytest.raises(VaultResolutionError, match="public identity file"):
        _run(_resolver(IncompleteRuntime()).resolve(_instance()))


def test_native_command_uses_private_agent_with_a_public_identity_file() -> None:
    manager = MagicMock()
    manager.get.return_value = AppConfig(ssh=SSHConfig())
    command = SSHService(manager).build_ssh_command(
        host="web-1.example.net",
        username="deploy",
        identity_agent="/tmp/agent.sock",
        identity_file="/tmp/agent-key.pub",
        certificate_file="/tmp/device-cert.pub",
        known_hosts_file="/tmp/known_hosts",
        extra_options=["HostKeyAlias=aws:example:i-12345678"],
    )
    assert "-i" not in command
    assert "IdentityAgent=/tmp/agent.sock" in command
    assert "IdentitiesOnly=yes" in command
    assert "IdentityFile=/tmp/agent-key.pub" in command
    assert "CertificateFile=/tmp/device-cert.pub" in command
    assert "UserKnownHostsFile=/tmp/known_hosts" in command
    assert "HostKeyAlias=aws:example:i-12345678" not in command
    assert "StrictHostKeyChecking=yes" in command


def test_native_command_effectively_uses_only_verified_host_key_policy() -> None:
    manager = MagicMock()
    manager.get.return_value = AppConfig(ssh=SSHConfig())
    command = SSHService(manager).build_ssh_command(
        host="web-1.example.net",
        username="deploy",
        identity_agent="/tmp/agent.sock",
        identity_file="/tmp/agent-key.pub",
        known_hosts_file="/tmp/known_hosts",
    )
    probe = subprocess.run(
        ["ssh", "-F", "/dev/null", "-G", *command[1:]],
        check=True,
        capture_output=True,
        text=True,
    )
    effective = dict(
        line.split(" ", 1) for line in probe.stdout.splitlines() if " " in line
    )
    assert effective["stricthostkeychecking"] == "true"
    assert effective["userknownhostsfile"] == "/tmp/known_hosts"
