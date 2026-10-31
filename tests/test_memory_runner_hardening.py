"""The shared connection cannot silently turn into ungated direct connections.

Commands bound to the build's master carry a proxy that always fails, so a
master that died makes them fail fast; the runner then reopens it once under
the gates or goes back to gated direct connections.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import ConnectionProfile
from servonaut.services.api_client import APIError
from servonaut.services.memory.ssh_mux import ControlMaster
from servonaut.services.ssh_credentials import (
    VaultCredentialError, VaultLeaseCache, rate_limit_wait, resolve_with_vault,
)
from tests.test_bastion_vault_hop import APP, APP_RULE, BASTION as BASTION_ROW, _Runtime, _service
from tests.test_memory_ssh_connections import (
    BASTION, DROP, FakeSsh, _control_path, _failure, _memory_service, _no_wait, _patched, _Patches, _Prober, _row, _use,
)


def _build(service, fake, count=1):
    async def go():
        return await asyncio.gather(*(service.build_report(_row(n), ["os"]) for n in range(1, count + 1)))

    with _Patches(_patched(fake, _no_wait)):
        return asyncio.run(go())


class TestBoundCommandsNeverDialOnTheirOwn:
    def test_a_bound_command_carries_a_failing_proxy_and_no_route(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path, profile=BASTION)
        service._probers = [_Prober(["a"])]
        service._connection_service.get_proxy_args.return_value = ["-o", "ProxyCommand=ssh bastion"]
        fake = FakeSsh()
        _build(service, fake)

        calls = service._ssh_service.build_ssh_command.call_args_list
        master = next(c.kwargs for c in calls if c.kwargs["remote_command"] is None and "ControlMaster=yes" in c.kwargs["extra_options"])
        bound = next(c.kwargs for c in calls if c.kwargs["remote_command"] == "a")
        assert master["proxy_args"] == ["-o", "ProxyCommand=ssh bastion"]
        assert bound["proxy_args"] == []
        assert bound["extra_options"][0] == "ProxyCommand=false"

    def test_a_dead_master_is_reopened_once_and_the_command_retried(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path, profile=BASTION)
        service._probers = [_Prober(["a", "b", "c"], sequential=True)]
        state = {"killed": False}

        def behaviour(fake, argv):
            if fake.kind(argv) == "command" and "b" == argv[-1] and not state["killed"]:
                state["killed"] = True
                Path(_control_path(argv)).unlink()
                return _failure(DROP)
            return (b"ok", b"")

        fake = FakeSsh(behaviour)
        [report] = _build(service, fake)

        assert len(fake.of_kind("master")) == 2
        assert all("ControlMaster=no" in " ".join(a) for a in fake.of_kind("command"))
        assert report.successes["os"].observed["codes"] == [0, 0, 0]

    def test_without_a_working_master_commands_connect_gated(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path, profile=BASTION, ssh_max_connections_per_bastion=1)
        service._probers = [_Prober(["a", "b", "c", "d"], sequential=False)]
        masters = {"n": 0}

        def behaviour(fake, argv):
            kind = fake.kind(argv)
            if kind == "master":
                masters["n"] += 1
                return _failure(DROP) if masters["n"] > 1 else (b"", b"")
            if kind == "command" and "ControlMaster=no" in argv and not masters.get("gone"):
                masters["gone"] = True
                Path(_control_path(argv)).unlink()
                return _failure(DROP)
            return (b"ok", b"")

        fake = FakeSsh(behaviour)
        [report] = _build(service, fake)

        assert len(fake.of_kind("master")) == 3 or len(fake.of_kind("master")) >= 2
        direct = [a for a in fake.of_kind("command") if not any(o.startswith("ControlPath") for o in a)]
        assert direct and fake.peak["command"] <= 4
        assert report.successes["os"].observed["codes"].count(0) >= 3

    def test_the_master_is_reopened_only_once(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path, profile=BASTION)
        service._probers = [_Prober(["a", "b", "c", "d"], sequential=True)]

        def behaviour(fake, argv):
            if fake.kind(argv) == "command" and "ControlMaster=no" in argv and Path(_control_path(argv)).exists():
                Path(_control_path(argv)).unlink()
                return _failure(DROP)
            return (b"ok", b"")

        fake = FakeSsh(behaviour)
        _build(service, fake)

        assert len(fake.of_kind("master")) == 2


def test_a_real_ssh_without_its_master_fails_fast_instead_of_dialling(tmp_path):
    import shutil
    import subprocess

    ssh = shutil.which("ssh")
    if ssh is None:
        pytest.skip("no OpenSSH client")
    result = subprocess.run(
        [ssh, "-o", "ProxyCommand=false", "-o", "ProxyJump=nobody@127.0.0.1:1", "-o", "BatchMode=yes",
         "-o", "ControlMaster=no", "-o", f"ControlPath={tmp_path}/none", "-F", "/dev/null", "-v", "127.0.0.1", "true"],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 255
    assert "Executing proxy command: exec false" in result.stderr
    assert "Connecting to 127.0.0.1" not in result.stderr


class TestBastionHopRateLimit:
    @staticmethod
    def _limited():
        return APIError(code="rate_limited", message="slow", status=429, response_headers={"retry-after": "3"})

    def _resolve(self, **flags):
        runtime = _Runtime(raises={"i-0b": self._limited()})
        conn = {"host": "10.0.1.21", "username": "ec2-user", "key_path": "/keys/app.pem", "proxy_args": [], "port": None}
        return asyncio.run(resolve_with_vault(
            conn, APP, vault_runtime=runtime, connection_service=_service(APP_RULE),
            rows=[APP, BASTION_ROW], **flags,
        ))

    def test_a_refused_hop_lookup_reaches_the_retry_wrapper(self):
        with pytest.raises(VaultCredentialError) as caught:
            self._resolve(raise_rate_limited=True)
        assert rate_limit_wait(caught.value) == (True, 3.0)

    def test_other_callers_keep_the_own_hop_setup(self):
        resolved = self._resolve()
        assert resolved["host"] == "10.0.1.21"


class TestGateFollowsTheRouteInUse:
    def test_a_direct_team_route_takes_no_bastion_gate(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path, profile=BASTION, ssh_max_connections_per_bastion=1)
        service._probers = [_Prober(["a", "b"])]
        fake = FakeSsh()

        async def direct_route(conn, instance, **kwargs):
            return {**conn, "profile": None, "proxy_args": []}

        with patch("servonaut.services.ssh_credentials.resolve_with_vault", direct_route):
            _build(service, fake)

        assert fake.peak["command"] == 2
        assert service._bastion_gates == {}


class TestSocketDirectory:
    @pytest.mark.parametrize("name", ["with space", "with%percent"])
    def test_a_directory_ssh_would_misread_turns_multiplexing_off(self, tmp_path, name, caplog):
        bad = tmp_path / name
        bad.mkdir()
        master = ControlMaster(persist_seconds=5, connect_timeout=3, socket_dir=str(bad))
        with patch("servonaut.services.memory.ssh_mux.get_os", lambda: "linux"):
            assert asyncio.run(master.open(lambda options: ["ssh", *options])) is False
        assert "space or '%'" in caplog.text
        assert list(bad.iterdir()) == []

    def test_the_length_limit_counts_bytes(self, tmp_path):
        base = tmp_path / ("é" * 20)
        base.mkdir()
        master = ControlMaster(persist_seconds=5, connect_timeout=3, socket_dir=str(base))
        in_characters = len(str(base)) + len("/sv-") + 8 + 1 + 1 + 17
        # Fits when counted in characters, not when counted in bytes (20 more).
        with patch("servonaut.services.memory.ssh_mux.get_os", lambda: "linux"), patch(
            "servonaut.services.memory.ssh_mux._SOCKET_PATH_LIMIT", in_characters + 10,
        ):
            assert master._prepare_dir() is False


class TestCancellationDuringCleanup:
    def test_a_cancelled_close_still_ends_the_master(self, tmp_path, monkeypatch):
        _use(monkeypatch, "linux")
        service = _memory_service(tmp_path, profile=BASTION)
        fake = FakeSsh(delay=0.05)

        async def go():
            runner = service._make_ssh_runner(_row(1), multiplex=True)
            await runner("a")
            directory = Path(_control_path(fake.of_kind("master")[0])).parent
            closing = asyncio.ensure_future(runner.close())
            for _ in range(2):
                await asyncio.sleep(0.01)
                closing.cancel()
            await asyncio.sleep(0.3)
            return directory

        with _Patches(_patched(fake, _no_wait)):
            directory = asyncio.run(go())

        assert len(fake.of_kind("exit")) == 1 and not directory.exists()


class TestSurvivingMutations:
    def test_a_newer_lookup_survives_an_older_one_finishing(self):
        cache = VaultLeaseCache()
        key = ("aws", "", "i-1")
        release = asyncio.Event()

        async def go():
            async def slow_old():
                await release.wait()
                return "old"

            old = asyncio.ensure_future(cache.single_flight(key, slow_old))
            await asyncio.sleep(0)
            cache.forget({"provider": "aws", "id": "i-1"})
            started = []

            async def new_fetch():
                started.append(1)
                await asyncio.sleep(0.05)
                return "new"

            fresh = asyncio.ensure_future(cache.single_flight(key, new_fetch))
            await asyncio.sleep(0)
            release.set()
            await old
            await asyncio.sleep(0)
            # The old lookup finished while the new one is in flight: a third
            # caller must still join the new one.
            joined = await cache.single_flight(key, new_fetch)
            return await fresh, joined, len(started)

        assert asyncio.run(go()) == ("new", "new", 1)

    def test_one_cancelled_prober_does_not_cancel_the_shared_resolution(self, tmp_path, monkeypatch):
        _use(monkeypatch, "windows")
        service = _memory_service(tmp_path)
        fake = FakeSsh(delay=0.05)

        async def go():
            runner = service._make_ssh_runner(_row(1))
            first = asyncio.ensure_future(runner("a"))
            second = asyncio.ensure_future(runner("b"))
            await asyncio.sleep(0)
            first.cancel()
            return await second

        with _Patches(_patched(fake, _no_wait)):
            assert asyncio.run(go())[2] == 0

    def test_bastion_names_differing_in_case_share_one_gate(self, tmp_path):
        service = _memory_service(tmp_path)
        upper = ConnectionProfile(name="u", bastion_host="Bastion.Example")
        lower = ConnectionProfile(name="l", bastion_host="bastion.example")
        assert service._bastion_gate(upper) is service._bastion_gate(lower)
