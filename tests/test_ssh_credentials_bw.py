"""Bitwarden keys in the shared SSH overlay (services/ssh_credentials.resolve_with_vault).

``TestConnectionTypesUnchanged`` records what every connection type resolves
to today, as literal expected conns: they were written and run against the
code before the optional ``bw_keys`` provider existed, and must not be edited
to follow a change in behaviour.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.shared_servers import shared_row
from servonaut.services.ssh_credentials import VaultCredentialError, resolve_with_vault
from servonaut.services.api_client import APIError
from tests._bw_fixtures import key_provider, no_ref_provider, unavailable_provider
from tests.test_bastion_vault_hop import (
    APP,
    APP_RULE,
    BASTION,
    PROFILE,
    _Runtime,
    _hop,
    _service,
    known_hosts,  # noqa: F401 - fixture
    posix_hop,  # noqa: F401 - fixture
)
from tests.test_ssh_credentials import CUSTOM, LOCAL, _lease, _runtime

OPS = {"slug": "ops", "name": "Ops", "role": "member", "id": "team-1"}
BINDING = {"source": "servonaut_vault", "vault_id": "vault-1", "item_id": "item-1"}
OWN_AWS = {
    "id": "i-abc123", "name": "web-1", "provider": "aws", "public_ip": "9.9.9.9",
    "private_ip": "10.0.0.5", "region": "eu-west-2", "key_name": "prod-key",
}
NO_KEY_CONN = {
    "host": "9.9.9.9", "username": "ec2-user", "key_path": None,
    "proxy_args": [], "port": None, "extra_options": [],
}
HOST_KEY_OPTIONS = ["HostKeyAlias=web-1", "StrictHostKeyChecking=yes"]


def _no_profile() -> MagicMock:
    return MagicMock(resolve_profile=MagicMock(return_value=None))


@dataclass
class Case:
    """One connection type: its inputs and the conn it resolves to without a Bitwarden key."""

    conn: dict
    instance: dict
    expected: dict
    runtime: Any = None
    service: Any = None
    team_rows: list = field(default_factory=list)
    rows: Optional[list] = None
    # A vault, CA or team lease is produced: a Bitwarden ref must never be consulted.
    lease: bool = False


def _run(case: Case, **extra: Any) -> dict:
    return asyncio.run(resolve_with_vault(
        case.conn, case.instance, vault_runtime=case.runtime,
        connection_service=case.service if case.service is not None else _no_profile(),
        team_rows=case.team_rows, rows=case.rows, **extra,
    ))


def _lease_expected(conn: dict, lease: Any, *, key_source: str, **changes: Any) -> dict:
    return {
        **conn, "username": lease.login_user, "key_path": None,
        "identity_agent": lease.identity_agent, "identity_file": lease.identity_file,
        "certificate_path": lease.certificate_path, "known_hosts_path": lease.known_hosts_path,
        "host": lease.target_host, "port": lease.target_port, "key_source": key_source,
        **changes,
    }


# ---------------------------------------------------------------------------
# One builder per connection type
# ---------------------------------------------------------------------------

def _g1_local_key(tmp_path) -> Case:
    return Case(conn=dict(LOCAL), instance=dict(CUSTOM), runtime=_runtime(None), expected={
        "host": "192.0.2.10", "username": "deploy", "key_path": "/keys/web1",
        "proxy_args": [], "port": 2222, "extra_options": ["ServerAliveInterval=30"],
    })


def _g2_no_key(tmp_path) -> Case:
    # ssh-agent, macOS Keychain or the Bitwarden desktop SSH agent holds the key.
    conn = {"host": "192.0.2.10", "username": "deploy", "key_path": None,
            "proxy_args": [], "port": 22, "extra_options": []}
    return Case(conn=dict(conn), instance=dict(CUSTOM), runtime=_runtime(None), expected={
        "host": "192.0.2.10", "username": "deploy", "key_path": None,
        "proxy_args": [], "port": 22, "extra_options": [],
    })


def _g3_aws(tmp_path) -> Case:
    instance = {"id": "i-0abc1234", "name": "web-1", "public_ip": "192.0.2.10",
                "region": "eu-west-2", "key_name": "prod-key"}
    conn = {"host": "192.0.2.10", "username": "ec2-user", "key_path": "/home/user/.ssh/prod-key.pem",
            "proxy_args": [], "port": None, "extra_options": []}
    return Case(conn=dict(conn), instance=instance, runtime=_runtime(None), expected={
        "host": "192.0.2.10", "username": "ec2-user", "key_path": "/home/user/.ssh/prod-key.pem",
        "proxy_args": [], "port": None, "extra_options": [],
    })


def _g4_ovh(tmp_path) -> Case:
    instance = {"id": "ovh-1", "name": "web-1", "provider": "OVH", "is_ovh": True,
                "public_ip": "192.0.2.10", "key_name": "ovh-account-key"}
    conn = {"host": "192.0.2.10", "username": "debian", "key_path": "/home/user/.ssh/ovh-account-key",
            "proxy_args": [], "port": None, "extra_options": []}
    return Case(conn=dict(conn), instance=instance, runtime=_runtime(None), expected={
        "host": "192.0.2.10", "username": "debian", "key_path": "/home/user/.ssh/ovh-account-key",
        "proxy_args": [], "port": None, "extra_options": [],
    })


def _g5_hetzner(tmp_path) -> Case:
    instance = {"id": "hz-1", "name": "web-1", "provider": "hetzner", "is_hetzner": True,
                "public_ip": "192.0.2.10", "username": "root"}
    conn = {"host": "192.0.2.10", "username": "root", "key_path": "/home/user/.ssh/hz",
            "proxy_args": [], "port": None, "extra_options": []}
    return Case(conn=dict(conn), instance=instance, runtime=_runtime(None), expected={
        "host": "192.0.2.10", "username": "root", "key_path": "/home/user/.ssh/hz",
        "proxy_args": [], "port": None, "extra_options": [],
    })


def _g6_personal_lease(tmp_path) -> Case:
    lease = _lease(tmp_path, source="personal", login_user="ops", target_host="198.51.100.7", target_port=22)
    return Case(conn=dict(LOCAL), instance=dict(CUSTOM), runtime=_runtime(lease), lease=True, expected={
        "host": "198.51.100.7", "username": "ops", "key_path": None,
        "proxy_args": [], "port": 22, "extra_options": ["ServerAliveInterval=30"],
        "identity_agent": str(tmp_path / "agent.sock"),
        "identity_file": str(tmp_path / "key.pub"),
        "certificate_path": None,
        "known_hosts_path": str(tmp_path / "known_hosts"),
        "key_source": "vault_personal",
    })


def _g7_ca_lease(tmp_path) -> Case:
    cert = str(tmp_path / "key-cert.pub")
    lease = _lease(tmp_path, source="ca", certificate_path=cert)
    return Case(conn=dict(LOCAL), instance=dict(CUSTOM), runtime=_runtime(lease), lease=True, expected={
        "host": "192.0.2.10", "username": "deploy", "key_path": None,
        "proxy_args": [], "port": 2222, "extra_options": ["ServerAliveInterval=30"],
        "identity_agent": str(tmp_path / "agent.sock"),
        "identity_file": str(tmp_path / "key.pub"),
        "certificate_path": cert,
        "known_hosts_path": str(tmp_path / "known_hosts"),
        "key_source": "vault_ca",
    })


def _team_row(**changes) -> dict:
    server = {"id": "srv-1", "name": "web-1", "hostname": "192.0.2.10", "credential_binding": dict(BINDING)}
    server.update(changes)
    return shared_row(server, OPS)


def _g8_team_shared_row(tmp_path) -> Case:
    lease = _lease(tmp_path)
    return Case(conn=dict(LOCAL), instance=_team_row(), runtime=_runtime(lease), lease=True, expected={
        "host": "192.0.2.10", "username": "deploy", "key_path": None,
        "proxy_args": [], "port": 2222, "extra_options": ["ServerAliveInterval=30"],
        "identity_agent": str(tmp_path / "agent.sock"),
        "identity_file": str(tmp_path / "key.pub"),
        "certificate_path": None,
        "known_hosts_path": str(tmp_path / "known_hosts"),
        "key_source": "vault_vault",
    })


def _team_runtime(team_lease=None, team_error=None) -> MagicMock:
    """A vault runtime that holds a lease for the team's row only."""

    async def resolve_ssh(instance):
        if instance.get("is_shared") is True:
            if team_error is not None:
                raise team_error
            return team_lease
        return None

    runtime = MagicMock()
    runtime.agent_key_ttl_seconds = 3600
    runtime.resolve_ssh = AsyncMock(side_effect=resolve_ssh)
    return runtime


def _team_route_service() -> MagicMock:
    service = _no_profile()
    service.get_extra_options = MagicMock(return_value=["HostKeyAlias=web-1"])
    return service


def _g9_team_key_fallback(tmp_path) -> Case:
    lease = _lease(tmp_path, target_host="9.9.9.9", target_port=22)
    return Case(
        conn=dict(NO_KEY_CONN), instance=dict(OWN_AWS), runtime=_team_runtime(lease),
        service=_team_route_service(), team_rows=[_team_row(hostname="9.9.9.9", instance_id="i-abc123")],
        lease=True, expected={
            "host": "9.9.9.9", "username": "deploy", "key_path": None,
            "proxy_args": [], "port": 22, "extra_options": ["HostKeyAlias=web-1"],
            "profile": None,
            "identity_agent": str(tmp_path / "agent.sock"),
            "identity_file": str(tmp_path / "key.pub"),
            "certificate_path": None,
            "known_hosts_path": str(tmp_path / "known_hosts"),
            "key_source": "vault_vault",
            "key_team": "Ops",
        },
    )


def _g10_fallback_not_used(tmp_path) -> Case:
    conn = {**NO_KEY_CONN, "key_path": "/home/user/.ssh/prod-key.pem"}
    return Case(
        conn=dict(conn), instance=dict(OWN_AWS), runtime=_team_runtime(_lease(tmp_path)),
        team_rows=[_team_row(hostname="9.9.9.9", instance_id="i-abc123")], expected=dict(conn),
    )


def _bastion_conn(service) -> dict:
    return {"host": "10.0.1.21", "username": "ec2-user", "key_path": "/keys/app.pem",
            "proxy_args": service.get_proxy_args(PROFILE), "port": None}


def _g11_profile_without_bastion_key(tmp_path) -> Case:
    service = _service(APP_RULE)
    conn = _bastion_conn(service)
    return Case(
        conn=dict(conn), instance=dict(APP), runtime=_Runtime(), service=service,
        rows=[APP, BASTION], expected={**conn, "profile": PROFILE},
    )


def _g12_bastion_with_vault_key(tmp_path) -> Case:
    service = _service(APP_RULE)
    conn = _bastion_conn(service)
    hop = _hop(tmp_path)
    return Case(
        conn=dict(conn), instance=dict(APP), runtime=_Runtime({"i-0b": hop}), service=service,
        rows=[APP, BASTION],
        expected={**conn, "profile": PROFILE, "proxy_args": service.get_proxy_args(PROFILE, hop=hop)},
    )


def _g12_target_lease_and_bastion_lease(tmp_path) -> Case:
    service = _service(APP_RULE)
    conn = _bastion_conn(service)
    hop = _hop(tmp_path)
    agent = tmp_path / "target-agent.sock"
    agent.touch()
    lease = _lease(
        tmp_path, identity_agent=str(agent), login_user="admin", target_host="10.0.1.21", target_port=22,
    )
    return Case(
        conn=dict(conn), instance=dict(APP), runtime=_Runtime({"i-0a": lease, "i-0b": hop}), service=service,
        rows=[APP, BASTION], lease=True,
        expected={
            **conn, "profile": PROFILE, "username": "admin", "key_path": None,
            "identity_agent": str(agent), "identity_file": str(tmp_path / "key.pub"),
            "certificate_path": None, "known_hosts_path": str(tmp_path / "known_hosts"),
            "host": "10.0.1.21", "port": 22, "key_source": "vault_vault",
            "proxy_args": service.get_proxy_args(PROFILE, hop=hop),
        },
    )


def _g13_host_key_options_local(tmp_path) -> Case:
    conn = {**LOCAL, "extra_options": list(HOST_KEY_OPTIONS)}
    return Case(conn=dict(conn), instance=dict(CUSTOM), runtime=_runtime(None), expected={
        "host": "192.0.2.10", "username": "deploy", "key_path": "/keys/web1",
        "proxy_args": [], "port": 2222,
        "extra_options": ["HostKeyAlias=web-1", "StrictHostKeyChecking=yes"],
    })


def _g13_host_key_options_lease(tmp_path) -> Case:
    conn = {**LOCAL, "extra_options": list(HOST_KEY_OPTIONS)}
    lease = _lease(tmp_path)
    return Case(conn=dict(conn), instance=dict(CUSTOM), runtime=_runtime(lease), lease=True, expected={
        "host": "192.0.2.10", "username": "deploy", "key_path": None,
        "proxy_args": [], "port": 2222,
        "extra_options": ["HostKeyAlias=web-1", "StrictHostKeyChecking=yes"],
        "identity_agent": str(tmp_path / "agent.sock"),
        "identity_file": str(tmp_path / "key.pub"),
        "certificate_path": None,
        "known_hosts_path": str(tmp_path / "known_hosts"),
        "key_source": "vault_vault",
    })


BUILDERS = {
    "G1_local_key": _g1_local_key,
    "G2_no_key": _g2_no_key,
    "G3_aws": _g3_aws,
    "G4_ovh": _g4_ovh,
    "G5_hetzner": _g5_hetzner,
    "G6_personal_lease": _g6_personal_lease,
    "G7_ca_lease": _g7_ca_lease,
    "G8_team_shared_row": _g8_team_shared_row,
    "G9_team_key_fallback": _g9_team_key_fallback,
    "G10_fallback_not_used": _g10_fallback_not_used,
    "G11_profile": _g11_profile_without_bastion_key,
    "G12_bastion_lease": _g12_bastion_with_vault_key,
    "G12_target_and_bastion_lease": _g12_target_lease_and_bastion_lease,
    "G13_host_key_options_local": _g13_host_key_options_local,
    "G13_host_key_options_lease": _g13_host_key_options_lease,
}


@pytest.mark.usefixtures("posix_hop", "known_hosts")
class TestConnectionTypesUnchanged:
    """Without a provider every connection type resolves exactly as before."""

    def test_g1_local_key_file(self, tmp_path):
        case = _g1_local_key(tmp_path)
        assert _run(case) == case.expected

    def test_g2_no_key_leaves_the_agent_to_ssh(self, tmp_path):
        case = _g2_no_key(tmp_path)
        result = _run(case)
        assert result == case.expected
        assert "identity_agent" not in result

    def test_g3_aws_ec2_with_a_discovered_key(self, tmp_path):
        case = _g3_aws(tmp_path)
        assert _run(case) == case.expected

    def test_g4_ovh_account_key(self, tmp_path):
        case = _g4_ovh(tmp_path)
        assert _run(case) == case.expected

    def test_g5_hetzner(self, tmp_path):
        case = _g5_hetzner(tmp_path)
        assert _run(case) == case.expected

    def test_g6_personal_vault_lease(self, tmp_path):
        case = _g6_personal_lease(tmp_path)
        assert _run(case) == case.expected

    def test_g7_ssh_ca_certificate_lease(self, tmp_path):
        case = _g7_ca_lease(tmp_path)
        assert _run(case) == case.expected

    def test_g8_team_shared_row_lease(self, tmp_path):
        case = _g8_team_shared_row(tmp_path)
        assert _run(case) == case.expected

    def test_g9_team_key_fallback(self, tmp_path):
        case = _g9_team_key_fallback(tmp_path)
        assert _run(case) == case.expected

    def test_g10_team_key_fallback_not_used_with_a_local_key(self, tmp_path):
        case = _g10_fallback_not_used(tmp_path)
        assert _run(case) == case.expected == case.conn

    def test_g11_bastion_profile_without_a_bastion_vault_key(self, tmp_path):
        case = _g11_profile_without_bastion_key(tmp_path)
        assert _run(case) == case.expected

    def test_g12_bastion_with_its_own_vault_lease(self, tmp_path):
        case = _g12_bastion_with_vault_key(tmp_path)
        assert _run(case) == case.expected

    def test_g12_target_and_bastion_leases(self, tmp_path):
        case = _g12_target_lease_and_bastion_lease(tmp_path)
        assert _run(case) == case.expected

    def test_g13_host_key_options_of_a_local_key(self, tmp_path):
        case = _g13_host_key_options_local(tmp_path)
        assert _run(case) == case.expected

    def test_g13_host_key_options_of_a_lease(self, tmp_path):
        case = _g13_host_key_options_lease(tmp_path)
        assert _run(case) == case.expected

    @pytest.mark.parametrize("name", list(BUILDERS))
    def test_a_provider_that_finds_no_ref_changes_nothing(self, name, tmp_path):
        case = BUILDERS[name](tmp_path)
        provider = no_ref_provider()

        assert _run(case, bw_keys=provider) == case.expected
        # A lease wins before the provider is asked; without one it is asked and finds nothing.
        assert provider.apply.await_count == (0 if case.lease else 1)

    @pytest.mark.parametrize("name", [
        "G6_personal_lease", "G7_ca_lease", "G8_team_shared_row", "G9_team_key_fallback",
        "G12_target_and_bastion_lease", "G13_host_key_options_lease",
    ])
    def test_a_vault_ca_or_team_key_wins_over_a_bitwarden_ref(self, name, tmp_path):
        case = BUILDERS[name](tmp_path)
        assert case.lease
        provider = key_provider()

        assert _run(case, bw_keys=provider) == case.expected
        provider.apply.assert_not_awaited()


@pytest.mark.usefixtures("posix_hop", "known_hosts")
class TestBitwardenKeys:
    def test_a_bitwarden_key_wins_over_a_local_key(self, tmp_path):
        case = _g1_local_key(tmp_path)

        assert _run(case, bw_keys=key_provider()) == {
            **LOCAL, "key_path": "/tmp/bw-test", "key_source": "bw_personal",
        }

    def test_a_bitwarden_key_for_a_server_without_a_key(self, tmp_path):
        case = _g2_no_key(tmp_path)

        assert _run(case, bw_keys=key_provider()) == {
            **case.expected, "key_path": "/tmp/bw-test", "key_source": "bw_personal",
        }

    def test_a_team_ref_names_its_source(self, tmp_path):
        case = _g1_local_key(tmp_path)

        result = _run(case, bw_keys=key_provider("/tmp/bw-team", "team"))

        assert (result["key_path"], result["key_source"]) == ("/tmp/bw-team", "bw_team")

    def test_the_route_of_a_profile_is_unchanged(self, tmp_path):
        case = _g11_profile_without_bastion_key(tmp_path)

        assert _run(case, bw_keys=key_provider()) == {
            **case.expected, "key_path": "/tmp/bw-test", "key_source": "bw_personal",
        }

    def test_a_ref_on_the_target_does_not_alter_the_bastion_hop(self, tmp_path):
        case = _g12_bastion_with_vault_key(tmp_path)

        assert _run(case, bw_keys=key_provider()) == {
            **case.expected, "key_path": "/tmp/bw-test", "key_source": "bw_personal",
        }

    def test_a_failed_team_lease_falls_back_to_the_bitwarden_key(self, tmp_path):
        case = _g9_team_key_fallback(tmp_path)
        case.runtime = _team_runtime(team_error=RuntimeError("vault locked"))
        provider = key_provider()

        result = _run(case, bw_keys=provider)

        assert result == {**NO_KEY_CONN, "key_path": "/tmp/bw-test", "key_source": "bw_personal"}
        provider.apply.assert_awaited_once()
        assert provider.apply.await_args.args[1] == OWN_AWS

    def test_a_team_without_a_lease_falls_back_to_the_bitwarden_key(self, tmp_path):
        case = _g9_team_key_fallback(tmp_path)
        case.runtime = _team_runtime(team_lease=None)
        provider = key_provider()

        result = _run(case, bw_keys=provider)

        assert result == {**NO_KEY_CONN, "key_path": "/tmp/bw-test", "key_source": "bw_personal"}
        provider.apply.assert_awaited_once()

    def test_a_rate_limited_team_lookup_raises_without_asking_the_provider(self, tmp_path):
        case = _g9_team_key_fallback(tmp_path)
        case.runtime = _team_runtime(team_error=APIError(code="rate_limited", message="slow down", status=429))
        provider = key_provider()

        with pytest.raises(VaultCredentialError):
            _run(case, bw_keys=provider, raise_rate_limited=True)

        provider.apply.assert_not_awaited()

    def test_a_rate_limited_lookup_is_an_ordinary_failure_when_the_caller_cannot_wait(self, tmp_path):
        case = _g9_team_key_fallback(tmp_path)
        case.runtime = _team_runtime(team_error=APIError(code="rate_limited", message="slow down", status=429))
        provider = key_provider()

        _run(case, bw_keys=provider)

        provider.apply.assert_awaited_once()


@pytest.mark.usefixtures("posix_hop", "known_hosts")
class TestBitwardenKeyUnavailable:
    @pytest.mark.parametrize("name", [
        "G1_local_key", "G2_no_key", "G3_aws", "G4_ovh", "G5_hetzner", "G10_fallback_not_used",
        "G11_profile", "G12_bastion_lease", "G13_host_key_options_local",
    ])
    def test_the_connection_stays_as_before_and_names_the_reason(self, name, tmp_path):
        case = BUILDERS[name](tmp_path)

        result = _run(case, bw_keys=unavailable_provider())

        assert result == {**case.expected, "bw_key_unavailable": "BwSessionMissingError"}

    def test_the_reason_is_whatever_the_provider_reports(self, tmp_path):
        case = _g1_local_key(tmp_path)

        result = _run(case, bw_keys=unavailable_provider("BwCliMissingError"))

        assert result["bw_key_unavailable"] == "BwCliMissingError"
        assert result["key_path"] == "/keys/web1"


class TestFailClosedWithAProvider:
    """A vault credential that cannot be used still stops the connection."""

    def _resolve(self, instance, runtime, provider):
        return asyncio.run(resolve_with_vault(
            dict(LOCAL), instance, vault_runtime=runtime, connection_service=_no_profile(), bw_keys=provider,
        ))

    def test_an_unusable_vault_credential(self):
        provider = key_provider()

        with pytest.raises(VaultCredentialError, match="could not be used"):
            self._resolve(CUSTOM, _runtime(raises=RuntimeError("locked")), provider)

        provider.apply.assert_not_awaited()

    def test_a_team_server_bound_to_the_vault(self):
        shared = {**CUSTOM, "is_shared": True, "credential_binding": {"source": "servonaut_vault"}}
        provider = key_provider()

        with pytest.raises(VaultCredentialError, match="not available"):
            self._resolve(shared, None, provider)
        with pytest.raises(VaultCredentialError, match="unavailable"):
            self._resolve(shared, _runtime(None), provider)

        provider.apply.assert_not_awaited()

    def test_a_lease_without_its_host_pins(self, tmp_path):
        provider = key_provider()

        with pytest.raises(VaultCredentialError, match="host-key file"):
            self._resolve(CUSTOM, _runtime(_lease(tmp_path, known_hosts_path="")), provider)

        provider.apply.assert_not_awaited()
