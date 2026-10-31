"""Further guarantees of a memory build's ssh runner (reachability, cleanup, routes)."""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig, ConnectionProfile
from servonaut.services.memory.modules.logs import LogsProber
from servonaut.services.memory.service import _is_multiplex_error
from servonaut.services.ssh_credentials import VaultLeaseCache, vault_lease
from tests.test_memory_ssh_connections import (
    BASTION, DROP, FakeSsh, _Patches, _control_path, _control_values, _failure, _memory_service, _no_wait, _patched,
    _row, _use,
)
from tests.test_vault_ssh_paths import CUSTOM


class _SlowFake(FakeSsh):
    """A fake whose commands named in *slow* take much longer than the others."""

    def __init__(self, behaviour=None, slow=()):
        super().__init__(behaviour)
        self._slow = tuple(slow)

    async def __call__(self, argv, timeout: float = 30, *, check: bool = False):
        if argv and argv[-1] in self._slow:
            await asyncio.sleep(0.2)
        return await super().__call__(argv, timeout, check=check)


def _run(coro_fn, fake):
    with _Patches(_patched(fake, _no_wait)):
        return asyncio.run(coro_fn())


class TestReachabilityVerdict:
    def test_a_late_answer_overturns_an_early_failure(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path)

        def behaviour(fake, argv):
            return _failure(DROP) if argv[-1] == "bad" else (b"ok", b"")

        fake = _SlowFake(behaviour, slow=("good",))

        async def go():
            runner = service._make_ssh_runner(_row(1))
            await asyncio.gather(runner("bad"), runner("good"))
            return runner

        runner = _run(go, fake)

        assert runner.commands_answered == 1 and runner.connection_problem is None

    def test_failures_with_nothing_answering_are_the_servers_verdict(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path)
        fake = _SlowFake(lambda f, argv: _failure(DROP), slow=("slow-bad",))

        async def go():
            runner = service._make_ssh_runner(_row(1))
            await asyncio.gather(runner("bad"), runner("slow-bad"))
            return runner

        runner = _run(go, fake)

        assert runner.connection_problem is not None

    def test_an_os_error_after_an_answer_fails_only_that_command(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path)

        def behaviour(fake, argv):
            return OSError("fork failed") if argv[-1] == "second" else (b"ok", b"")

        fake = FakeSsh(behaviour)

        async def go():
            runner = service._make_ssh_runner(_row(1))
            await runner("first")
            result = await runner("second")
            return runner, result

        runner, result = _run(go, fake)

        assert result[2] == 1 and runner.connection_problem is None


class TestCleanup:
    def test_a_cancelled_build_waits_for_the_master_to_exit(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path, profile=BASTION)
        fake = FakeSsh(delay=0.1)

        async def go():
            runner = service._make_ssh_runner(_row(1), multiplex=True)
            await runner("a")
            directory = Path(_control_path(fake.of_kind("master")[0])).parent
            closing = asyncio.ensure_future(runner.close())
            await asyncio.sleep(0.03)
            closing.cancel()
            with pytest.raises(asyncio.CancelledError):
                await closing
            # The cancel reaches the caller only after the exit has finished.
            return fake.active["exit"], directory.exists(), len(fake.of_kind("exit"))

        running, exists, exits = _run(go, fake)

        assert (running, exists, exits) == (0, False, 1)

    def test_the_exit_gets_its_configured_budget(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path, profile=BASTION, ssh_close_timeout_seconds=7)
        fake = FakeSsh()

        async def go():
            runner = service._make_ssh_runner(_row(1), multiplex=True)
            await runner("a")
            await runner.close()

        _run(go, fake)

        assert ("exit", 7.0) in fake.timeouts

    def test_a_failed_exit_is_survived_and_the_directory_removed(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path, profile=BASTION)

        def behaviour(fake, argv):
            return _failure("Control socket connect: No such file") if fake.kind(argv) == "exit" else (b"ok", b"")

        fake = FakeSsh(behaviour)

        async def go():
            runner = service._make_ssh_runner(_row(1), multiplex=True)
            await runner("a")
            directory = Path(_control_path(fake.of_kind("master")[0])).parent
            await runner.close()
            return directory

        assert not _run(go, fake).exists()


class TestRoute:
    def test_custom_servers_behind_one_vault_hop_share_the_bastion_cap(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path, profile=BASTION, ssh_max_connections_per_bastion=1)
        fake = FakeSsh()
        rows = [{"id": f"c-{n}", "name": f"app-{n}", "is_custom": True, "host": f"10.0.0.{n}", "username": "u"}
                for n in (1, 2, 3)]

        async def hop(*args, **kwargs):
            return SimpleNamespace(identity_agent="/agent", target_host=None)

        async def go():
            runners = [service._make_ssh_runner(row) for row in rows]
            return await asyncio.gather(*(r("true") for r in runners))

        with patch("servonaut.services.ssh_credentials.bastion_lease", hop):
            _run(go, fake)

        assert fake.peak["command"] == 1


class TestMultiplexErrorMarkers:
    def test_an_unrelated_bad_option_is_not_a_multiplexing_error(self):
        assert not _is_multiplex_error("/etc/ssh/ssh_config line 3: Bad configuration option: frobnicate")

    def test_a_multiplexing_option_it_rejects_is(self):
        assert _is_multiplex_error("command-line line 0: Bad configuration option: controlpersist")


class TestLeaseSharing:
    def test_the_lookup_ends_when_its_last_waiter_goes(self):
        cache = VaultLeaseCache()
        gate = asyncio.Event()
        started = []

        async def resolve_ssh(instance):
            started.append(1)
            await gate.wait()
            return SimpleNamespace(identity_agent="/a", identity_file="/i", known_hosts_path="/k")

        runtime = SimpleNamespace(resolve_ssh=resolve_ssh, agent_key_ttl_seconds=60, is_unlocked=True)

        async def go():
            only = asyncio.ensure_future(vault_lease(dict(CUSTOM), runtime, cache=cache))
            await asyncio.sleep(0.01)
            only.cancel()
            await asyncio.sleep(0.01)
            return [t for t in asyncio.all_tasks() if "_fetch_lease" in repr(t) and not t.done()]

        assert asyncio.run(go()) == []

    def test_the_lookup_survives_while_another_waiter_remains(self):
        cache = VaultLeaseCache()
        gate = asyncio.Event()
        lease = SimpleNamespace(identity_agent="/a", identity_file="/i", known_hosts_path="/k")

        async def resolve_ssh(instance):
            await gate.wait()
            return lease

        runtime = SimpleNamespace(resolve_ssh=resolve_ssh, agent_key_ttl_seconds=60, is_unlocked=True)

        async def go():
            first = asyncio.ensure_future(vault_lease(dict(CUSTOM), runtime, cache=cache))
            second = asyncio.ensure_future(vault_lease(dict(CUSTOM), runtime, cache=cache))
            await asyncio.sleep(0.01)
            first.cancel()
            await asyncio.sleep(0.01)
            gate.set()
            return await second

        assert asyncio.run(go()) is lease


class TestLogsProberRows:
    def test_a_build_uses_the_rows_carried_by_its_own_runner(self):
        seen = {}

        async def probe(instance, ssh_service, connection_service, **kwargs):
            seen.update(kwargs)
            return []

        viewer = MagicMock()
        viewer.probe_log_paths = probe
        prober = LogsProber(viewer, MagicMock(), MagicMock())
        prober.set_connection_rows(["other-build-team"], ["other-build-fleet"])

        async def runner(command):
            return "", "", 0

        runner.instance = {"id": "i-1"}
        runner.connection_rows = (["team"], ["fleet"])
        asyncio.run(prober.probe(runner))

        assert seen["team_rows"] == ["team"] and seen["rows"] == ["fleet"]


class TestNoRealSshInUnitTests:
    def test_starting_ssh_is_refused_and_recorded(self):
        from tests.conftest import SSH_LAUNCH_VIOLATIONS

        async def go():
            await asyncio.create_subprocess_exec("ssh", "-V")

        with pytest.raises(AssertionError, match="replace the subprocess seam"):
            asyncio.run(go())
        assert SSH_LAUNCH_VIOLATIONS == ["ssh"]
        SSH_LAUNCH_VIOLATIONS.clear()  # this test provoked it on purpose

    @pytest.mark.parametrize("program", ["ssh", "ssh.exe", b"ssh", "/usr/bin/ssh", Path("/usr/bin/SCP.EXE"), "C:\\Windows\\sftp.exe"])
    def test_every_spelling_of_an_ssh_client_is_recognised(self, program):
        from tests.conftest import _is_ssh_program

        assert _is_ssh_program(program)

    def test_other_programs_are_not(self):
        from tests.conftest import _is_ssh_program

        assert not _is_ssh_program("sshd-helper") and not _is_ssh_program("/bin/echo")

    def test_synchronous_launches_are_refused_too(self):
        import subprocess

        from tests.conftest import SSH_LAUNCH_VIOLATIONS

        with pytest.raises(AssertionError):
            subprocess.run(["ssh", "-V"])
        with pytest.raises(AssertionError):
            subprocess.Popen(["/usr/bin/ssh.exe", "-V"])
        assert len(SSH_LAUNCH_VIOLATIONS) == 2
        SSH_LAUNCH_VIOLATIONS.clear()

    def test_a_refusal_swallowed_by_the_code_under_test_is_still_recorded(self):
        from tests.conftest import SSH_LAUNCH_VIOLATIONS

        async def production_code():
            try:
                await asyncio.create_subprocess_exec("ssh", "-V")
            except Exception:  # noqa: BLE001 - what the probers do with it
                return "swallowed"

        assert asyncio.run(production_code()) == "swallowed"
        # The teardown would fail this test; the self-test consumes the record.
        assert SSH_LAUNCH_VIOLATIONS == ["ssh"]
        SSH_LAUNCH_VIOLATIONS.clear()
