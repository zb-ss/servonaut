"""A fleet refresh asks the vault once per server and once per bastion.

Every probe command of a build starts at the same moment and resolves the
server's credentials first; without single-flighting each of them (and each
of the four servers a fleet scan runs at once) sent its own lookup, and the
Servonaut service rate-limited the whole computer. A refused lookup waits once
for the service's Retry-After.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.api_client import APIError
from servonaut.services.memory import MemoryService
from servonaut.services.memory.service import VAULT_RATE_LIMITED
from servonaut.services.memory.store import MemoryStore
from servonaut.services.ssh_credentials import VaultCredentialError, VaultLeaseCache, vault_lease
from tests.test_bastion_vault_hop import APP, APP_RULE, BASTION, _Runtime, _hop, _service
from tests.test_ssh_host_keys import known_hosts, posix_hop  # noqa: F401 - fixtures
from tests.test_vault_ssh_paths import CUSTOM, _connection_service


def _rate_limited(retry_after: str | None = "2") -> APIError:
    headers = {"retry-after": retry_after} if retry_after is not None else None
    return APIError(code="rate_limited", message="slow down", status=429, response_headers=headers)


class _CountingRuntime:
    """A vault runtime whose lookups take a moment and are counted."""

    agent_key_ttl_seconds = 3600
    is_unlocked = True

    def __init__(self, lease, *, fail_first=0, error=None):
        self._lease = lease
        self.calls = 0
        self._fail_first = fail_first
        self._error = error

    async def resolve_ssh(self, instance):
        self.calls += 1
        await asyncio.sleep(0.02)
        if self.calls <= self._fail_first:
            raise self._error
        return self._lease


@pytest.fixture()
def lease(tmp_path):
    agent = tmp_path / "agent.sock"
    agent.touch()
    return SimpleNamespace(
        source="vault", identity_agent=str(agent), identity_file=str(tmp_path / "key.pub"),
        certificate_path=None, known_hosts_path=str(tmp_path / "known_hosts"),
        login_user="deploy", target_host="192.0.2.10", target_port=2222,
    )


def _service_with(tmp_path, runtime, *, config=None, connection_service=None, cache=None):
    ssh_service = MagicMock()
    ssh_service.build_ssh_command.return_value = ["ssh", "web-1", "true"]
    service = MemoryService(
        store=MemoryStore(root=tmp_path), config=config or MemoryConfig(),
        ssh_service=ssh_service, connection_service=connection_service or _connection_service(),
    )
    service.set_vault_runtime(runtime, cache)
    return service, ssh_service


async def _run_many(service, instance, count):
    with patch("servonaut.utils.ssh_utils.run_ssh_subprocess", AsyncMock(return_value=(b"ok", b""))):
        runner = service._make_ssh_runner(instance)
        return await asyncio.gather(*(runner(f"echo {n}") for n in range(count)), return_exceptions=True)


class TestRunnerSingleFlight:
    def test_eight_concurrent_first_commands_resolve_once(self, tmp_path, lease):
        runtime = _CountingRuntime(lease)
        service, _ = _service_with(tmp_path, runtime)
        supplied = []

        async def rows():
            supplied.append(1)
            await asyncio.sleep(0.01)
            return [], []

        service.set_connection_rows(rows)

        results = asyncio.run(_run_many(service, dict(CUSTOM), 8))

        assert all(code == 0 for _out, _err, code in results)
        assert runtime.calls == 1
        assert len(supplied) == 1

    def test_a_failed_resolution_is_shared_by_every_waiting_command(self, tmp_path, lease):
        runtime = _CountingRuntime(lease, fail_first=99, error=RuntimeError("locked"))
        service, _ = _service_with(tmp_path, runtime)

        results = asyncio.run(_run_many(service, dict(CUSTOM), 8))

        assert all(isinstance(r, VaultCredentialError) for r in results)
        assert runtime.calls == 1


class TestLeaseSingleFlight:
    def test_concurrent_lookups_of_one_server_share_one_lease(self, lease):
        runtime = _CountingRuntime(lease)
        cache = VaultLeaseCache()

        async def go():
            return await asyncio.gather(*(vault_lease(dict(CUSTOM), runtime, cache=cache) for _ in range(8)))

        leases = asyncio.run(go())

        assert runtime.calls == 1 and all(item is lease for item in leases)

    def test_two_servers_behind_one_bastion_share_one_bastion_lease(self, tmp_path, known_hosts, posix_hop):  # noqa: F811
        app_2 = {**APP, "id": "i-0d", "name": "app-2"}
        runtime = _Runtime({"i-0b": _hop(tmp_path)})
        original = runtime.resolve_ssh

        async def slow(instance):
            await asyncio.sleep(0.02)
            return await original(instance)

        runtime.resolve_ssh = slow
        cache = VaultLeaseCache()

        from servonaut.services.ssh_credentials import resolve_with_vault

        async def go():
            service = _service(APP_RULE)
            return await asyncio.gather(*(
                resolve_with_vault(
                    {"host": "", "username": "", "proxy_args": [], "port": None}, target,
                    vault_runtime=runtime, connection_service=service, cache=cache,
                    rows=[APP, app_2, BASTION],
                ) for target in (APP, app_2)
            ))

        asyncio.run(go())

        assert runtime.asked.count("i-0b") == 1

    def test_a_cancelled_caller_does_not_fail_the_others(self, lease):
        runtime = _CountingRuntime(lease)
        cache = VaultLeaseCache()

        async def go():
            first = asyncio.create_task(vault_lease(dict(CUSTOM), runtime, cache=cache))
            second = asyncio.create_task(vault_lease(dict(CUSTOM), runtime, cache=cache))
            await asyncio.sleep(0)
            first.cancel()
            return await second

        assert asyncio.run(go()) is lease
        assert runtime.calls == 1


class TestRateLimit:
    def test_a_rate_limited_lookup_waits_for_retry_after_once_then_succeeds(self, tmp_path, lease):
        runtime = _CountingRuntime(lease, fail_first=1, error=_rate_limited("2"))
        service, _ = _service_with(tmp_path, runtime)
        sleeps = []

        async def fake_sleep(seconds):
            sleeps.append(seconds)

        with patch("servonaut.services.memory.service._wait", fake_sleep):
            results = asyncio.run(_run_many(service, dict(CUSTOM), 4))

        assert all(code == 0 for _out, _err, code in results)
        assert sleeps == [2.0]
        assert runtime.calls == 2

    def test_a_second_refusal_fails_the_server_with_the_rate_limit_reason(self, tmp_path, lease):
        runtime = _CountingRuntime(lease, fail_first=99, error=_rate_limited("2"))
        service, _ = _service_with(tmp_path, runtime)

        async def fake_sleep(seconds):
            return None

        with patch("servonaut.services.memory.service._wait", fake_sleep):
            runner = None

            async def go():
                nonlocal runner
                runner = service._make_ssh_runner(dict(CUSTOM))
                with pytest.raises(VaultCredentialError):
                    await runner("uname -a")
                # Every later command fails the same way without asking again.
                with pytest.raises(VaultCredentialError):
                    await runner("uptime")

            asyncio.run(go())

        assert runtime.calls == 2
        assert runner.connection_problem.reason == VAULT_RATE_LIMITED == "vault_rate_limited"
        assert "limiting requests" in runner.connection_problem.message
        assert "web-1" not in runner.connection_problem.message

    def test_a_wait_longer_than_the_bound_fails_without_waiting(self, tmp_path, lease):
        runtime = _CountingRuntime(lease, fail_first=99, error=_rate_limited("600"))
        service, _ = _service_with(tmp_path, runtime, config=MemoryConfig(vault_rate_limit_max_wait_seconds=5))
        sleeps = []

        async def fake_sleep(seconds):
            sleeps.append(seconds)

        async def go():
            runner = service._make_ssh_runner(dict(CUSTOM))
            with pytest.raises(VaultCredentialError):
                await runner("uname -a")
            return runner

        with patch("servonaut.services.memory.service._wait", fake_sleep):
            runner = asyncio.run(go())

        assert sleeps == [] and runtime.calls == 1
        assert runner.connection_problem.reason == VAULT_RATE_LIMITED

    def test_another_refusal_is_not_retried_and_keeps_its_reason(self, tmp_path, lease):
        runtime = _CountingRuntime(lease, fail_first=99, error=RuntimeError("locked"))
        service, _ = _service_with(tmp_path, runtime)

        async def go():
            runner = service._make_ssh_runner(dict(CUSTOM))
            with pytest.raises(VaultCredentialError):
                await runner("uname -a")
            return runner

        runner = asyncio.run(go())

        assert runtime.calls == 1
        assert runner.connection_problem.reason == "vault_credential_unavailable"

    def test_the_build_report_names_the_rate_limit(self, tmp_path, lease):
        runtime = _CountingRuntime(lease, fail_first=99, error=_rate_limited("2"))
        service, _ = _service_with(tmp_path, runtime)
        prober = MagicMock()
        prober.name = "os"

        async def probe(runner):
            await runner("uname -a")

        prober.probe = probe

        async def no_sleep(seconds):
            return None

        service._probers = [prober]
        with patch("servonaut.services.memory.service._wait", no_sleep):
            report = asyncio.run(service.build_report(dict(CUSTOM), ["os"]))

        assert report.failures[0].reason == VAULT_RATE_LIMITED


def test_a_cli_run_shares_one_lease_cache(monkeypatch):
    from servonaut.cli import memory as cli_memory

    monkeypatch.setattr(cli_memory, "_vault_runtime", lambda: SimpleNamespace(teams=None))
    _config, service, _fleet = cli_memory._init_headless_services()

    assert isinstance(service._vault_leases, VaultLeaseCache)


class TestRateLimitWait:
    def test_a_refused_lookup_reports_the_services_retry_after(self):
        from servonaut.services.ssh_credentials import rate_limit_wait

        wrapped = VaultCredentialError("could not be used")
        wrapped.__cause__ = _rate_limited("7")

        assert rate_limit_wait(wrapped) == (True, 7.0)

    def test_paused_binding_reads_report_the_remaining_pause(self):
        from servonaut.services.ssh_credentials import rate_limit_wait
        from servonaut.services.vault.binding_reads import BindingReadsPaused

        wrapped = VaultCredentialError("could not be used")
        wrapped.__cause__ = BindingReadsPaused("limiting requests", retry_after=12.5)

        assert rate_limit_wait(wrapped) == (True, 12.5)

    def test_other_failures_are_not_rate_limits(self):
        from servonaut.services.ssh_credentials import rate_limit_wait

        wrapped = VaultCredentialError("locked")
        wrapped.__cause__ = RuntimeError("locked")

        assert rate_limit_wait(wrapped) == (False, None)
