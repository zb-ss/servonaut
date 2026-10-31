"""A memory build shares one SSH connection and is gentle on a bastion.

Every probe command used to open its own connection (two handshakes through a
bastion), so a fleet refresh sent a bastion's sshd dozens at once and it
dropped some. A build now opens one master connection per server (not on
Windows), the connections through one bastion are capped across concurrent
builds, and a dropped connection is only the server's verdict when nothing
answered and one retry also failed.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Callable, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.schema import ConnectionProfile, MemoryConfig
from servonaut.services.memory import MemoryService
from servonaut.services.memory.interfaces import ModuleResult
from servonaut.services.memory.store import MemoryStore
from servonaut.utils.ssh_utils import SSHCalledProcessError, SSHOutput

DROP = "kex_exchange_identification: Connection closed by remote host\nConnection closed by UNKNOWN port 65535"
REFUSED = "user@10.0.0.5: Permission denied (publickey)."


def _argv_of(host: str, username: str, remote_command: Optional[str], extra_options: List[str]) -> List[str]:
    argv = ["ssh"]
    for option in extra_options:
        argv += ["-o", option]
    argv += ["--", f"{username}@{host}"]
    if remote_command:
        argv.append(remote_command)
    return argv


def _fake_build(host, username, key_path=None, proxy_args=None, remote_command=None, port=None,
                extra_options=None, **_identity):
    return _argv_of(host, username, remote_command, list(extra_options or []))


def _failure(diagnostics: str, code: int = 255) -> SSHCalledProcessError:
    return SSHCalledProcessError(code, ["ssh"], output=b"", stderr=b"", diagnostics=diagnostics)


class FakeSsh:
    """Stands in for ``run_ssh_subprocess``: records every run and what ran at once."""

    def __init__(self, behaviour: Optional[Callable[["FakeSsh", List[str]], Any]] = None, delay: float = 0.01):
        self.calls: List[List[str]] = []
        self.behaviour = behaviour or (lambda fake, argv: (b"ok", b""))
        self.delay = delay
        self.active = {"master": 0, "exit": 0, "command": 0}
        self.peak = {"master": 0, "exit": 0, "command": 0}

    @staticmethod
    def kind(argv: List[str]) -> str:
        if "-O" in argv:
            return "exit"
        return "master" if "-N" in argv else "command"

    def of_kind(self, kind: str) -> List[List[str]]:
        return [argv for argv in self.calls if self.kind(argv) == kind]

    async def daemonizing(self, argv, stderr_path, timeout: float = 30):
        return await self(argv, timeout, check=True)

    async def __call__(self, argv, timeout: float = 30, *, check: bool = False):
        argv = list(argv)
        kind = self.kind(argv)
        self.calls.append(argv)
        self.active[kind] += 1
        self.peak[kind] = max(self.peak[kind], self.active[kind])
        try:
            await asyncio.sleep(self.delay)
            result = self.behaviour(self, argv)
        finally:
            self.active[kind] -= 1
        if isinstance(result, BaseException):
            raise result
        if kind == "master":
            # A real master leaves its control socket in the directory.
            (Path(_control_path(argv)).parent / "socket").touch()
        return SSHOutput(result[0], result[1], 0, "")


def _connection_service(profile: Optional[ConnectionProfile] = None) -> MagicMock:
    service = MagicMock()
    service.resolve_profile.return_value = profile
    service.get_target_host.return_value = "10.0.0.5"
    service.get_proxy_args.return_value = []
    service.get_extra_options.return_value = []
    return service


def _memory_service(tmp_path: Path, *, profile=None, **config) -> MemoryService:
    ssh_service = MagicMock()
    ssh_service.get_key_path.return_value = "/keys/k"
    ssh_service.build_ssh_command.side_effect = _fake_build
    return MemoryService(
        store=MemoryStore(root=tmp_path / "store"), config=MemoryConfig(**config),
        ssh_service=ssh_service, connection_service=_connection_service(profile),
    )


def _row(index: int = 1) -> dict:
    return {"id": f"i-{index:04d}", "name": f"web-{index}", "provider": "aws", "private_ip": "10.0.0.5",
            "region": "eu-west-2", "key_name": "k"}


class _Prober:
    """Runs *commands* concurrently through the build's runner."""

    def __init__(self, commands: List[str], name: str = "os", sequential: bool = False, fail: bool = False):
        self.name, self._commands, self._sequential, self._fail = name, commands, sequential, fail
        self.ttl_seconds = 60

    async def probe(self, runner: Any) -> ModuleResult:
        if self._fail:
            raise RuntimeError("probe failed")
        if self._sequential:
            outputs = [await runner(command) for command in self._commands]
        else:
            outputs = await asyncio.gather(*(runner(command) for command in self._commands))
        return ModuleResult(module=self.name, instance_id="", observed={"codes": [o[2] for o in outputs]})


def _patched(fake: FakeSsh, wait: Optional[Callable] = None):
    stack = [
        patch("servonaut.utils.ssh_utils.run_ssh_subprocess", fake),
        patch("servonaut.services.memory.ssh_mux.run_ssh_subprocess", fake),
        patch("servonaut.services.memory.ssh_mux.run_ssh_daemonizing", fake.daemonizing),
    ]
    if wait is not None:
        stack.append(patch("servonaut.services.memory.service._wait", wait))
    return stack


class _Patches:
    def __init__(self, patches):
        self._patches = patches

    def __enter__(self):
        for item in self._patches:
            item.start()

    def __exit__(self, *exc):
        for item in reversed(self._patches):
            item.stop()


def _use(monkeypatch, os_name: str) -> None:
    monkeypatch.setattr("servonaut.services.memory.ssh_mux.get_os", lambda: os_name)


async def _no_wait(seconds: float) -> None:
    return None


def _control_path(argv: List[str]) -> str:
    return next(o for o in argv if o.startswith("ControlPath="))[len("ControlPath="):]


# ---------------------------------------------------------------------------
# Multiplexing
# ---------------------------------------------------------------------------


class TestMultiplexing:
    @pytest.mark.parametrize("os_name", ["linux", "darwin"])
    def test_one_master_serves_every_command(self, tmp_path, monkeypatch, os_name):
        _use(monkeypatch, os_name)
        service = _memory_service(tmp_path)
        service._probers = [_Prober(["a", "b", "c", "d"])]
        fake = FakeSsh()

        with _Patches(_patched(fake, _no_wait)):
            report = asyncio.run(service.build_report(_row(), ["os"]))

        assert report.successes["os"].observed["codes"] == [0, 0, 0, 0]
        [master] = fake.of_kind("master")
        assert "-f" in master and "ControlMaster=yes" in master
        assert any(o.startswith("ControlPersist=") for o in master)
        commands = fake.of_kind("command")
        assert len(commands) == 4
        for argv in commands:
            assert "ControlMaster=no" in argv and _control_path(argv) == _control_path(master)

    def test_the_control_socket_directory_is_private_and_short(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path)
        service._probers = [_Prober(["a"])]
        seen: dict = {}

        def behaviour(fake, argv):
            if fake.kind(argv) == "master":
                directory = Path(_control_path(argv)).parent
                seen["mode"] = directory.stat().st_mode & 0o777
                seen["path"] = _control_path(argv)
            return (b"ok", b"")

        with _Patches(_patched(FakeSsh(behaviour), _no_wait)):
            asyncio.run(service.build_report(_row(), ["os"]))

        assert seen["mode"] == 0o700
        # ssh binds <path>.<16 characters> first.
        assert len(seen["path"]) + 17 <= 100

    def test_windows_gets_no_multiplexing(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path)
        service._probers = [_Prober(["a", "b"])]
        fake = FakeSsh()

        with _Patches(_patched(fake, _no_wait)):
            report = asyncio.run(service.build_report(_row(), ["os"]))

        assert report.successes["os"].observed["codes"] == [0, 0]
        assert fake.of_kind("master") == [] and fake.of_kind("exit") == []
        assert not any(o.startswith("Control") for argv in fake.calls for o in argv)

    def test_without_a_private_directory_the_commands_connect_on_their_own(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")

        def refuse(**_kwargs):
            raise PermissionError("read-only")

        monkeypatch.setattr("servonaut.services.memory.ssh_mux.tempfile.mkdtemp", refuse)
        service = _memory_service(tmp_path)
        service._probers = [_Prober(["a", "b"])]
        fake = FakeSsh()

        with _Patches(_patched(fake, _no_wait)):
            report = asyncio.run(service.build_report(_row(), ["os"]))

        assert report.successes["os"].observed["codes"] == [0, 0] and fake.of_kind("master") == []

    def test_a_runner_made_outside_a_build_is_not_multiplexed(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path)
        fake = FakeSsh()

        async def go():
            runner = service._make_ssh_runner(_row())
            return await runner("uptime")

        with _Patches(_patched(fake, _no_wait)):
            asyncio.run(go())

        assert fake.of_kind("master") == []


class TestMasterIsClosed:
    @staticmethod
    def _assert_closed(fake: FakeSsh) -> None:
        [master] = fake.of_kind("master")
        [exit_call] = fake.of_kind("exit")
        assert _control_path(exit_call) == _control_path(master)
        assert not Path(_control_path(master)).parent.exists()

    def test_after_a_build(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path)
        service._probers = [_Prober(["a"])]
        fake = FakeSsh()

        with _Patches(_patched(fake, _no_wait)):
            asyncio.run(service.build_report(_row(), ["os"]))

        self._assert_closed(fake)

    def test_after_a_failed_build(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path)
        # One module fails after the master is up; the other opened it.
        service._probers = [_Prober(["a"], name="os"), _Prober([], name="runtimes", fail=True)]
        fake = FakeSsh()

        with _Patches(_patched(fake, _no_wait)):
            report = asyncio.run(service.build_report(_row(), ["os", "runtimes"]))

        assert [f.module for f in report.failures] == ["runtimes"]
        self._assert_closed(fake)

    def test_after_a_cancelled_build(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path)
        service._probers = [_Prober(["a", "b"], sequential=True)]

        def behaviour(fake, argv):
            return (b"ok", b"")

        fake = FakeSsh(behaviour, delay=0.2)

        async def go():
            task = asyncio.ensure_future(service.build_report(_row(), ["os"]))
            while not fake.of_kind("command"):
                await asyncio.sleep(0.01)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        with _Patches(_patched(fake, _no_wait)):
            asyncio.run(go())

        self._assert_closed(fake)

    def test_a_master_that_never_opened_leaves_nothing_behind(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path)
        service._probers = [_Prober(["a"])]
        created: List[Path] = []

        def behaviour(fake, argv):
            if fake.kind(argv) == "master":
                created.append(Path(_control_path(argv)).parent)
                return _failure(REFUSED)
            return (b"ok", b"")

        with _Patches(_patched(FakeSsh(behaviour), _no_wait)):
            asyncio.run(service.build_report(_row(), ["os"]))

        assert created and not created[0].exists()


    def test_a_retried_master_reuses_the_builds_one_directory(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path)
        service._probers = [_Prober(["a"])]
        directories: List[Path] = []

        def behaviour(fake, argv):
            if fake.kind(argv) == "master":
                directories.append(Path(_control_path(argv)).parent)
                return _failure(DROP)
            return (b"ok", b"")

        with _Patches(_patched(FakeSsh(behaviour), _no_wait)):
            asyncio.run(service.build_report(_row(), ["os"]))

        assert len(directories) == 2 and len(set(directories)) == 1
        assert not directories[0].exists()


class TestMasterFailures:
    def test_a_refused_login_is_the_verdict_at_once(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path)
        service._probers = [_Prober(["a", "b"])]
        fake = FakeSsh(lambda fake, argv: _failure(REFUSED))

        with _Patches(_patched(fake, _no_wait)):
            report = asyncio.run(service.build_report(_row(), ["os"]))

        assert len(fake.of_kind("master")) == 1 and fake.of_kind("command") == []
        assert report.failures[0].reason == "ssh_auth_failed"

    def test_one_transient_drop_of_the_master_is_retried(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path)
        service._probers = [_Prober(["a", "b"])]
        waits: List[float] = []

        async def wait(seconds):
            waits.append(seconds)

        def behaviour(fake, argv):
            if fake.kind(argv) == "master" and len(fake.of_kind("master")) == 1:
                return _failure(DROP)
            return (b"ok", b"")

        fake = FakeSsh(behaviour)
        with _Patches(_patched(fake, wait)):
            report = asyncio.run(service.build_report(_row(), ["os"]))

        assert report.successes["os"].observed["codes"] == [0, 0]
        assert len(fake.of_kind("master")) == 2 and waits == [MemoryConfig().ssh_connect_retry_backoff_seconds]

    def test_two_failed_attempts_make_the_server_unreachable(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path)
        service._probers = [_Prober(["a", "b"])]
        fake = FakeSsh(lambda fake, argv: _failure(DROP))

        with _Patches(_patched(fake, _no_wait)):
            report = asyncio.run(service.build_report(_row(), ["os"]))

        assert len(fake.of_kind("master")) == 2 and fake.of_kind("command") == []
        assert report.failures[0].reason == "ssh_unreachable"

    def test_a_ssh_that_cannot_multiplex_falls_back_to_direct_connections(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path)
        service._probers = [_Prober(["a", "b"])]

        def behaviour(fake, argv):
            if fake.kind(argv) == "master":
                return _failure("command-line: line 0: Bad configuration option: controlpersist")
            return (b"ok", b"")

        fake = FakeSsh(behaviour)
        with _Patches(_patched(fake, _no_wait)):
            report = asyncio.run(service.build_report(_row(), ["os"]))

        assert report.successes["os"].observed["codes"] == [0, 0]
        assert len(fake.of_kind("master")) == 1
        commands = fake.of_kind("command")
        assert len(commands) == 2 and not any(o.startswith("Control") for argv in commands for o in argv)


# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------

BASTION = ConnectionProfile(name="via-bastion", bastion_host="9.9.9.9", bastion_user="ec2-user")


class TestConnectionCaps:
    def test_servers_behind_one_bastion_never_exceed_the_cap(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")  # no multiplexing: every command connection counts
        service = _memory_service(tmp_path, profile=BASTION, ssh_max_connections_per_bastion=2)
        service._probers = [_Prober(["a", "b", "c", "d"])]
        fake = FakeSsh()

        async def go():
            return await asyncio.gather(*(service.build_report(_row(n), ["os"]) for n in (1, 2, 3)))

        with _Patches(_patched(fake, _no_wait)):
            reports = asyncio.run(go())

        assert all(r.successes["os"].observed["codes"] == [0, 0, 0, 0] for r in reports)
        assert fake.peak["command"] == 2

    def test_the_cap_gates_the_masters_when_multiplexing(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path, profile=BASTION, ssh_max_connections_per_bastion=2)
        service._probers = [_Prober(["a"])]
        fake = FakeSsh()

        async def go():
            return await asyncio.gather(*(service.build_report(_row(n), ["os"]) for n in (1, 2, 3, 4)))

        with _Patches(_patched(fake, _no_wait)):
            asyncio.run(go())

        assert len(fake.of_kind("master")) == 4 and fake.peak["master"] == 2

    def test_servers_behind_different_bastions_do_not_share_a_cap(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path, profile=BASTION, ssh_max_connections_per_bastion=1)
        other = ConnectionProfile(name="other", bastion_host="9.9.9.8")
        profiles = {"i-0001": BASTION, "i-0002": other}
        service._connection_service.resolve_profile.side_effect = lambda inst: profiles[inst["id"]]
        service._probers = [_Prober(["a"])]
        fake = FakeSsh()

        async def go():
            return await asyncio.gather(*(service.build_report(_row(n), ["os"]) for n in (1, 2)))

        with _Patches(_patched(fake, _no_wait)):
            asyncio.run(go())

        assert fake.peak["command"] == 2

    def test_the_same_host_on_another_port_is_another_bastion(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path, profile=BASTION, ssh_max_connections_per_bastion=1)
        other_port = ConnectionProfile(name="other", bastion_host=BASTION.bastion_host, ssh_port=2222)
        profiles = {"i-0001": BASTION, "i-0002": other_port}
        service._connection_service.resolve_profile.side_effect = lambda inst: profiles[inst["id"]]
        service._probers = [_Prober(["a"])]
        fake = FakeSsh()

        async def go():
            return await asyncio.gather(*(service.build_report(_row(n), ["os"]) for n in (1, 2)))

        with _Patches(_patched(fake, _no_wait)):
            asyncio.run(go())

        assert fake.peak["command"] == 2

    def test_a_server_without_multiplexing_is_capped_by_itself(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path, ssh_max_connections_per_server=3)
        service._probers = [_Prober([str(n) for n in range(8)])]
        fake = FakeSsh()

        with _Patches(_patched(fake, _no_wait)):
            report = asyncio.run(service.build_report(_row(), ["os"]))

        assert report.successes["os"].observed["codes"] == [0] * 8
        assert fake.peak["command"] == 3


# ---------------------------------------------------------------------------
# What decides a server's verdict
# ---------------------------------------------------------------------------


def _runner_run(service, fake, commands, *, wait=_no_wait, sequential=True):
    async def go():
        runner = service._make_ssh_runner(_row())
        if sequential:
            results = [await runner(c) for c in commands]
        else:
            results = await asyncio.gather(*(runner(c) for c in commands))
        return runner, results

    with _Patches(_patched(fake, wait)):
        return asyncio.run(go())


class TestVerdict:
    def test_one_transient_drop_does_not_make_the_server_unreachable(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path)
        waits: List[float] = []

        async def wait(seconds):
            waits.append(seconds)

        fake = FakeSsh(lambda f, argv: _failure(DROP) if len(f.calls) == 1 else (b"ok", b""))

        runner, [(stdout, _err, code)] = _runner_run(service, fake, ["uptime"], wait=wait)

        assert (stdout, code) == ("ok", 0)
        assert runner.connection_problem is None
        assert waits == [MemoryConfig().ssh_connect_retry_backoff_seconds]

    def test_a_drop_that_repeats_is_the_servers_verdict(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path)
        fake = FakeSsh(lambda f, argv: _failure(DROP))

        runner, [(_out, _err, code), (_o2, message, code2)] = _runner_run(service, fake, ["a", "b"])

        assert code == 255 and len(fake.calls) == 2  # the first command: attempt + one retry
        assert runner.connection_problem.reason == "ssh_unreachable"
        assert code2 == 255 and message == runner.connection_problem.message  # no third connection

    def test_a_drop_after_other_commands_answered_fails_only_that_command(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path)
        waits: List[float] = []

        async def wait(seconds):
            waits.append(seconds)

        fake = FakeSsh(lambda f, argv: _failure(DROP) if len(f.calls) == 2 else (b"ok", b""))

        runner, results = _runner_run(service, fake, ["a", "b", "c"], wait=wait)

        assert [code for _o, _e, code in results] == [0, 255, 0]
        assert runner.connection_problem is None and waits == [] and len(fake.calls) == 3

    def test_a_refused_login_is_never_retried(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path)
        fake = FakeSsh(lambda f, argv: _failure(REFUSED))

        runner, [(_o, _e, code)] = _runner_run(service, fake, ["a"])

        assert code == 255 and len(fake.calls) == 1
        assert runner.connection_problem.reason == "ssh_auth_failed"

    def test_a_timeout_before_any_answer_is_retried_once(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path)
        fake = FakeSsh(lambda f, argv: asyncio.TimeoutError() if len(f.calls) == 1 else (b"ok", b""))

        runner, [(_o, _e, code)] = _runner_run(service, fake, ["a"])

        assert code == 0 and len(fake.calls) == 2

    def test_a_repeated_timeout_still_times_out(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path)
        fake = FakeSsh(lambda f, argv: asyncio.TimeoutError())

        async def go():
            runner = service._make_ssh_runner(_row())
            with pytest.raises(asyncio.TimeoutError):
                await runner("a")
            return runner

        with _Patches(_patched(fake, _no_wait)):
            runner = asyncio.run(go())

        assert len(fake.calls) == 2 and runner.commands_answered == 0

    def test_a_remote_command_that_exits_nonzero_is_not_a_connection_failure(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path)
        error = SSHCalledProcessError(1, ["ssh"], output=b"partial", stderr=b"", diagnostics="")
        fake = FakeSsh(lambda f, argv: error)

        runner, [(stdout, _e, code)] = _runner_run(service, fake, ["false"])

        assert (stdout, code) == ("partial", 1) and len(fake.calls) == 1
        assert runner.commands_answered == 1 and runner.connection_problem is None


class TestMasterOpenIgnoresInheritedPipes:
    """``ssh -f`` can leave its master holding ssh's output descriptors."""

    @staticmethod
    def _fake_ssh(tmp_path: Path) -> tuple[Path, Path]:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        pid_file = tmp_path / "sleeper.pid"
        script = bin_dir / "ssh"
        # The parent exits 0 once "authenticated"; the forked child keeps stderr.
        script.write_text(f"#!/bin/sh\nsleep 30 &\necho $! > {pid_file}\nexit 0\n")
        script.chmod(0o755)
        return bin_dir, pid_file

    def test_open_returns_when_the_parent_exits_not_when_the_pipes_close(self, tmp_path, monkeypatch):
        import signal
        import time

        from servonaut.services.memory.ssh_mux import ControlMaster

        bin_dir, pid_file = self._fake_ssh(tmp_path)
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setattr("servonaut.services.memory.ssh_mux.get_os", lambda: "linux")
        master = ControlMaster(persist_seconds=5, connect_timeout=3)

        async def go():
            started = time.monotonic()
            opened = await master.open(lambda options: ["ssh", *[x for o in options for x in ("-o", o)], "--", "u@h"])
            return opened, time.monotonic() - started

        try:
            opened, took = asyncio.run(go())
        finally:
            if pid_file.exists():
                try:
                    os.kill(int(pid_file.read_text()), signal.SIGKILL)
                except (ProcessLookupError, ValueError):
                    pass
            asyncio.run(master.close(None))

        assert opened is True and took < 2
