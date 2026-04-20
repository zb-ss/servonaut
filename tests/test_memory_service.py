"""Unit tests for MemoryService (T2 additions).

Tests:
  - Parallel execution: three probers with mocked async probe(), one sleeps 0.5s.
    MemoryService.build should finish in < 0.7s (they run concurrently).
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.interfaces import ModuleProberInterface, ModuleResult
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import MemoryStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro: Any) -> Any:
    """Run a coroutine synchronously."""
    return asyncio.run(coro)


class _MockProber(ModuleProberInterface):
    """Prober that returns a fixed result after an optional delay."""

    def __init__(self, name: str, delay: float = 0.0) -> None:
        self.name = name
        self.ttl_seconds = 3600
        self._delay = delay

    async def probe(self, ssh_runner: Any) -> ModuleResult:
        if self._delay:
            await asyncio.sleep(self._delay)
        return ModuleResult(
            module=self.name,
            instance_id="",
            observed={"key": "value"},
            probed_at="2026-04-20T00:00:00+00:00",
            ttl_seconds=self.ttl_seconds,
        )


# ---------------------------------------------------------------------------
# Parallel execution test
# ---------------------------------------------------------------------------

class TestParallelExecution:
    def test_three_probers_complete_concurrently(self, tmp_path: Path) -> None:
        """Three probers (one sleeps 0.5s) should finish in < 0.7s total."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        probers = [
            _MockProber("fast_a", delay=0.0),
            _MockProber("slow_one", delay=0.5),
            _MockProber("fast_b", delay=0.0),
        ]
        service = MemoryService(store=store, config=config, probers=probers)
        instance = {"id": "i-parallel-test", "name": "test", "provider": "custom"}

        start = time.monotonic()
        results = _run(service.build(instance))
        elapsed = time.monotonic() - start

        assert set(results.keys()) == {"fast_a", "slow_one", "fast_b"}
        assert elapsed < 0.7, (
            f"Expected parallel execution to complete in < 0.7s, got {elapsed:.3f}s. "
            "Probers may be running sequentially."
        )

    def test_build_returns_empty_when_disabled(self, tmp_path: Path) -> None:
        """build() returns {} when memory is disabled in config."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig(enabled=False)
        service = MemoryService(store=store, config=config, probers=[_MockProber("os")])

        results = _run(service.build({"id": "i-disabled", "name": "x", "provider": "custom"}))
        assert results == {}

    def test_build_returns_empty_when_instance_opted_out(self, tmp_path: Path) -> None:
        """build() returns {} when the instance has memory_disabled=true."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig(
            per_server_overrides={"i-optout": {"memory_disabled": True}}
        )
        service = MemoryService(store=store, config=config, probers=[_MockProber("os")])

        results = _run(service.build({"id": "i-optout", "name": "x", "provider": "custom"}))
        assert results == {}

    def test_prober_exception_does_not_abort_others(self, tmp_path: Path) -> None:
        """A prober that raises should not cancel the remaining probers."""
        class _ExplodingProber(ModuleProberInterface):
            name = "exploder"
            ttl_seconds = 3600

            async def probe(self, ssh_runner: Any) -> ModuleResult:
                raise RuntimeError("This prober is broken")

        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        probers = [
            _ExplodingProber(),
            _MockProber("healthy"),
        ]
        service = MemoryService(store=store, config=config, probers=probers)

        results = _run(service.build({"id": "i-robust", "name": "x", "provider": "custom"}))
        # The healthy prober should still complete.
        assert "healthy" in results
        # The broken prober may or may not be in results (base class catches it).

    def test_module_filter_selects_only_requested(self, tmp_path: Path) -> None:
        """build() with modules=['os'] only probes the os module."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        probers = [
            _MockProber("os"),
            _MockProber("runtimes"),
            _MockProber("services"),
        ]
        service = MemoryService(store=store, config=config, probers=probers)

        results = _run(service.build(
            {"id": "i-filter", "name": "x", "provider": "custom"},
            modules=["os"],
        ))
        assert set(results.keys()) == {"os"}


# ---------------------------------------------------------------------------
# SSH subprocess zombie prevention
# ---------------------------------------------------------------------------

class TestSshSubprocessZombieKill:
    """Verify that run_ssh_subprocess kills the process on both TimeoutError
    and CancelledError so no zombie SSH processes linger past the deadline."""

    @pytest.mark.asyncio
    async def test_process_killed_on_timeout(self) -> None:
        """A subprocess that hangs past ``timeout`` must be killed."""
        from unittest.mock import AsyncMock, MagicMock, patch

        mock_proc = MagicMock()
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock(return_value=None)
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
        # _transport attribute (accessed in finally block)
        mock_proc._transport = None

        with patch(
            "servonaut.utils.ssh_utils.asyncio.create_subprocess_exec",
            return_value=mock_proc,
        ), patch(
            "servonaut.utils.ssh_utils.asyncio.wait_for",
            side_effect=asyncio.TimeoutError,
        ):
            from servonaut.utils.ssh_utils import run_ssh_subprocess
            with pytest.raises(asyncio.TimeoutError):
                await run_ssh_subprocess(["ssh", "example.com", "echo hi"], timeout=5)

        mock_proc.kill.assert_called_once()
        mock_proc.wait.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_killed_on_cancellation(self) -> None:
        """A subprocess must be killed when the caller cancels the coroutine
        (external CancelledError propagating from asyncio.wait_for timeout)."""
        from unittest.mock import AsyncMock, MagicMock, patch

        mock_proc = MagicMock()
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock(return_value=None)
        mock_proc._transport = None

        with patch(
            "servonaut.utils.ssh_utils.asyncio.create_subprocess_exec",
            return_value=mock_proc,
        ), patch(
            "servonaut.utils.ssh_utils.asyncio.wait_for",
            side_effect=asyncio.CancelledError,
        ):
            from servonaut.utils.ssh_utils import run_ssh_subprocess
            with pytest.raises(asyncio.CancelledError):
                await run_ssh_subprocess(["ssh", "example.com", "echo hi"], timeout=5)

        mock_proc.kill.assert_called_once()
        mock_proc.wait.assert_called_once()


# ---------------------------------------------------------------------------
# _real_runner — SSH runner returned by _make_ssh_runner for non-custom instances
# ---------------------------------------------------------------------------

class TestRealRunnerNonCustom:
    """_real_runner returned for a non-custom (AWS-style) instance.

    run_ssh_subprocess is imported locally inside _make_ssh_runner, so the
    closure captures the real function object directly.  To control what it
    returns we patch asyncio.create_subprocess_exec (the underlying primitive)
    instead of the higher-level wrapper.
    """

    def _make_service_and_instance(self, tmp_path: Path):
        """Helper that builds a MemoryService + AWS-style instance dict."""
        from unittest.mock import MagicMock

        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()

        mock_ssh_service = MagicMock()
        mock_ssh_service.build_ssh_command.return_value = ["ssh", "1.2.3.4", "uname -a"]
        mock_ssh_service.get_key_path.return_value = "/home/user/.ssh/id_rsa"
        mock_ssh_service.discover_key.return_value = None
        mock_ssh_service._config_manager = MagicMock()
        mock_ssh_service._config_manager.get.return_value = MagicMock(default_username="ec2-user")

        mock_conn_service = MagicMock()
        mock_conn_service.resolve_profile.return_value = MagicMock(username="ec2-user")
        mock_conn_service.get_target_host.return_value = "1.2.3.4"
        mock_conn_service.get_proxy_args.return_value = []
        mock_conn_service.get_extra_options.return_value = []

        service = MemoryService(
            store=store,
            config=config,
            ssh_service=mock_ssh_service,
            connection_service=mock_conn_service,
        )

        instance = {
            "id": "i-abc123",
            "name": "web-01",
            "provider": "aws",
            "public_ip": "1.2.3.4",
            "key_name": "my-key",
        }
        return service, instance

    @pytest.mark.asyncio
    async def test_happy_path_decodes_stdout(self, tmp_path: Path) -> None:
        """run_ssh_subprocess returns bytes; _real_runner decodes to str."""
        from unittest.mock import AsyncMock, MagicMock, patch

        service, instance = self._make_service_and_instance(tmp_path)

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"Linux web-01 5.15.0\n", b""))
        mock_proc._transport = None

        with patch(
            "servonaut.utils.ssh_utils.asyncio.create_subprocess_exec",
            return_value=mock_proc,
        ):
            runner = service._make_ssh_runner(instance)
            stdout, stderr, rc = await runner("uname -a")

        assert "Linux web-01 5.15.0" in stdout
        assert stderr == ""
        assert rc == 0

    @pytest.mark.asyncio
    async def test_timeout_is_reraised(self, tmp_path: Path) -> None:
        """asyncio.TimeoutError from run_ssh_subprocess must propagate."""
        from unittest.mock import AsyncMock, MagicMock, patch

        service, instance = self._make_service_and_instance(tmp_path)
        instance["id"] = "i-timeout"

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock(return_value=None)
        mock_proc._transport = None

        with patch(
            "servonaut.utils.ssh_utils.asyncio.create_subprocess_exec",
            return_value=mock_proc,
        ), patch(
            "servonaut.utils.ssh_utils.asyncio.wait_for",
            side_effect=asyncio.TimeoutError,
        ):
            runner = service._make_ssh_runner(instance)
            with pytest.raises(asyncio.TimeoutError):
                await runner("sleep 60")

    @pytest.mark.asyncio
    async def test_generic_exception_returns_error_tuple(self, tmp_path: Path) -> None:
        """Any non-timeout exception from run_ssh_subprocess returns ('', error_msg, 1)."""
        from unittest.mock import AsyncMock, MagicMock, patch

        service, instance = self._make_service_and_instance(tmp_path)
        instance["id"] = "i-err"

        # Patch create_subprocess_exec itself to raise, simulating a deep failure.
        with patch(
            "servonaut.utils.ssh_utils.asyncio.create_subprocess_exec",
            side_effect=OSError("Connection refused"),
        ):
            runner = service._make_ssh_runner(instance)
            stdout, stderr, rc = await runner("whoami")

        assert stdout == ""
        assert "Connection refused" in stderr
        assert rc == 1


# ---------------------------------------------------------------------------
# _real_runner — custom server branch
# ---------------------------------------------------------------------------

class TestRealRunnerCustomServer:
    """_make_ssh_runner uses a different branch for is_custom=True instances."""

    @pytest.mark.asyncio
    async def test_custom_server_uses_instance_fields(self, tmp_path: Path) -> None:
        """Custom server runner resolves host/user/port from the instance dict."""
        from unittest.mock import AsyncMock, MagicMock, patch

        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()

        mock_ssh_service = MagicMock()
        mock_ssh_service.build_ssh_command.return_value = ["ssh", "-p", "2222", "10.0.0.5", "id"]

        mock_conn_service = MagicMock()
        mock_conn_service.get_extra_options.return_value = []

        service = MemoryService(
            store=store,
            config=config,
            ssh_service=mock_ssh_service,
            connection_service=mock_conn_service,
        )

        # A custom (non-AWS) server instance.
        instance = {
            "id": "custom-server-1",
            "name": "my-vps",
            "provider": "ovh",
            "is_custom": True,
            "public_ip": "10.0.0.5",
            "username": "deploy",
            "ssh_key": "/home/user/.ssh/vps_key",
            "port": 2222,
        }

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"uid=1000(deploy)\n", b""))
        mock_proc._transport = None

        with patch(
            "servonaut.utils.ssh_utils.asyncio.create_subprocess_exec",
            return_value=mock_proc,
        ):
            runner = service._make_ssh_runner(instance)
            stdout, stderr, rc = await runner("id")

        assert "uid=1000" in stdout
        assert rc == 0

        # Verify build_ssh_command was called with the custom server fields.
        call_kwargs = mock_ssh_service.build_ssh_command.call_args
        assert call_kwargs is not None
        # host from public_ip, username from instance dict, port from instance dict
        assert call_kwargs.kwargs.get("host") == "10.0.0.5" or \
               (call_kwargs.args and "10.0.0.5" in str(call_kwargs))


# ---------------------------------------------------------------------------
# _make_ssh_runner stub — no services wired
# ---------------------------------------------------------------------------

class TestMakeSshRunnerStub:
    """When ssh_service or connection_service is None, a stub runner is returned."""

    @pytest.mark.asyncio
    async def test_stub_runner_raises_not_implemented(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        # No ssh_service or connection_service
        service = MemoryService(store=store, config=config)

        instance = {"id": "i-stub", "name": "stub", "provider": "custom"}
        runner = service._make_ssh_runner(instance)

        with pytest.raises(NotImplementedError, match="SSH runner not wired"):
            await runner("echo hello")


# ---------------------------------------------------------------------------
# get_summary / write_summary end-to-end
# ---------------------------------------------------------------------------

class TestGetAndWriteSummary:
    """get_summary returns Markdown; write_summary persists it with mode 0o600."""

    @pytest.mark.asyncio
    async def test_get_summary_contains_module_data(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        service = MemoryService(store=store, config=config)

        # Seed two modules.
        os_data = {
            "module": "os", "instance_id": "i-gs",
            "probed_at": "2026-04-19T12:00:00+00:00",
            "ttl_seconds": 86400, "sudo_used": False,
            "truncated": False, "partial": False,
            "observed": {"pretty_name": "Debian 12", "kernel": "6.1.0", "version_id": "12", "arch": "x86_64"},
            "declared": {}, "raw_output": "",
        }
        runtimes_data = {
            "module": "runtimes", "instance_id": "i-gs",
            "probed_at": "2026-04-19T12:00:00+00:00",
            "ttl_seconds": 604800, "sudo_used": False,
            "truncated": False, "partial": False,
            "observed": {"python": "Python 3.11.2", "node": None},
            "declared": {}, "raw_output": "",
        }
        store.save_module("i-gs", "os", os_data, provider="custom")
        store.save_module("i-gs", "runtimes", runtimes_data, provider="custom")

        instance_meta = {"id": "i-gs", "name": "debian-box", "provider": "custom"}
        summary = await service.get_summary(instance_meta)

        assert "## Identity" in summary
        assert "Debian 12" in summary
        assert "## Runtimes" in summary
        assert "python" in summary

    @pytest.mark.asyncio
    async def test_get_summary_respects_max_tokens(self, tmp_path: Path) -> None:
        """get_summary with max_tokens=100 (400 chars) trims long summaries."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        service = MemoryService(store=store, config=config)

        # Build a large runtimes module with many entries.
        big_runtimes = {f"runtime_{i:03d}": f"v{i}.0.0" for i in range(50)}
        data = {
            "module": "runtimes", "instance_id": "i-big",
            "probed_at": "2026-04-19T12:00:00+00:00",
            "ttl_seconds": 86400, "sudo_used": False,
            "truncated": False, "partial": False,
            "observed": big_runtimes, "declared": {}, "raw_output": "",
        }
        store.save_module("i-big", "runtimes", data, provider="custom")

        instance_meta = {"id": "i-big", "name": "big-server", "provider": "custom"}
        summary = await service.get_summary(instance_meta, max_tokens=100)

        # 100 tokens * 4 chars = 400 char cap
        assert len(summary) <= 400

    @pytest.mark.asyncio
    async def test_write_summary_file_has_restricted_mode(self, tmp_path: Path) -> None:
        """write_summary creates summary.md with mode 0o600."""
        import stat

        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        service = MemoryService(store=store, config=config)

        os_data = {
            "module": "os", "instance_id": "i-mode",
            "probed_at": "2026-04-19T12:00:00+00:00",
            "ttl_seconds": 86400, "sudo_used": False,
            "truncated": False, "partial": False,
            "observed": {"pretty_name": "Alpine Linux", "kernel": "6.6.0",
                         "version_id": "3.19", "arch": "x86_64"},
            "declared": {}, "raw_output": "",
        }
        store.save_module("i-mode", "os", os_data, provider="custom")

        instance_meta = {"id": "i-mode", "name": "alpine-box", "provider": "custom"}
        path = await service.write_summary(instance_meta)

        assert path.exists()
        file_mode = stat.S_IMODE(path.stat().st_mode)
        assert file_mode == 0o600, f"Expected 0o600 but got {oct(file_mode)}"

        content = path.read_text(encoding="utf-8")
        assert "Alpine Linux" in content

    @pytest.mark.asyncio
    async def test_write_summary_path_is_under_instance_dir(self, tmp_path: Path) -> None:
        """write_summary returns a path inside the expected provider/instance directory."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        service = MemoryService(store=store, config=config)

        instance_meta = {"id": "i-path-check", "name": "path-server", "provider": "aws"}
        path = await service.write_summary(instance_meta)

        # Provider "aws" maps to slug "aws".
        expected = tmp_path / "aws" / "i-path-check" / "summary.md"
        assert path == expected


# ---------------------------------------------------------------------------
# build() — disabled_modules config path
# ---------------------------------------------------------------------------

class TestBuildDisabledModules:
    """build() skips modules listed in config.disabled_modules."""

    def test_disabled_module_is_not_probed(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig(disabled_modules=["runtimes"])

        probed = []

        class _TrackingProber(MagicMock):
            name = "runtimes"
            ttl_seconds = 3600

            async def probe(self, ssh_runner):
                probed.append(self.name)
                from servonaut.services.memory.interfaces import ModuleResult
                return ModuleResult(module="runtimes", instance_id="", observed={"node": "v20"})

        prober = _TrackingProber()
        prober.name = "runtimes"

        service = MemoryService(store=store, config=config, probers=[prober])
        result = asyncio.run(service.build({"id": "i-disabled-mod", "name": "x", "provider": "custom"}))

        # The disabled module must not appear in results and must not have been probed.
        assert "runtimes" not in result
        assert "runtimes" not in probed

    def test_wildcard_modules_param_runs_all_enabled(self, tmp_path: Path) -> None:
        """modules=['*'] behaves the same as modules=None (run all enabled)."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()

        class _OsProber(MagicMock):
            name = "os"
            ttl_seconds = 3600

            async def probe(self, ssh_runner):
                from servonaut.services.memory.interfaces import ModuleResult
                return ModuleResult(module="os", instance_id="", observed={"pretty_name": "Ubuntu"})

        prober = _OsProber()
        prober.name = "os"

        service = MemoryService(store=store, config=config, probers=[prober])
        results = asyncio.run(service.build(
            {"id": "i-wildcard", "name": "x", "provider": "custom"},
            modules=["*"],
        ))
        assert "os" in results

    def test_no_probers_returns_empty(self, tmp_path: Path) -> None:
        """When no probers are configured, build() returns {} immediately."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        service = MemoryService(store=store, config=config, probers=[])
        results = asyncio.run(service.build({"id": "i-noprobers", "name": "x", "provider": "custom"}))
        assert results == {}


# ---------------------------------------------------------------------------
# build() — cancellation behaviour
# ---------------------------------------------------------------------------

class TestBuildCancellation:
    """build() cancellation leaves whatever partial state was written before cancel."""

    @pytest.mark.asyncio
    async def test_cancelled_task_does_not_corrupt_store(self, tmp_path: Path) -> None:
        """Cancelling build() mid-flight doesn't leave partial writes that break
        subsequent get() calls (store must remain consistent)."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()

        class _SlowProber(MagicMock):
            name = "os"
            ttl_seconds = 3600

            async def probe(self, ssh_runner):
                await asyncio.sleep(10)  # long enough to be cancelled
                from servonaut.services.memory.interfaces import ModuleResult
                return ModuleResult(module="os", instance_id="", observed={"pretty_name": "Ubuntu"})

        prober = _SlowProber()
        prober.name = "os"

        service = MemoryService(store=store, config=config, probers=[prober])
        instance = {"id": "i-cancel", "name": "cancel-box", "provider": "custom"}

        # Spawn build() and cancel it after a short delay.
        task = asyncio.create_task(service.build(instance))
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        # After cancellation, the store must be readable (not corrupted).
        # The module was never written (cancelled before completion).
        data = store.get_module("i-cancel", "os", "custom")
        # Either None (not written) or a valid dict — both are acceptable.
        assert data is None or isinstance(data, dict)


# ---------------------------------------------------------------------------
# MemoryService convenience methods — refresh, get, clear, list_all
# ---------------------------------------------------------------------------

class TestServiceConvenienceMethods:
    """refresh, get, clear, list_all — thin wrappers over the store."""

    def test_refresh_delegates_to_build(self, tmp_path: Path) -> None:
        """refresh() produces the same results as build() for MVP (identical impl)."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        probers = [_MockProber("os")]
        service = MemoryService(store=store, config=config, probers=probers)
        instance = {"id": "i-refresh", "name": "x", "provider": "custom"}

        results = asyncio.run(service.refresh(instance))
        assert "os" in results

    def test_get_returns_stored_module(self, tmp_path: Path) -> None:
        """get() reads the stored JSON dict for a module."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        service = MemoryService(store=store, config=config)

        data = {
            "module": "os", "instance_id": "i-get",
            "probed_at": "2026-04-19T12:00:00+00:00",
            "ttl_seconds": 86400, "sudo_used": False,
            "truncated": False, "partial": False,
            "observed": {"pretty_name": "Fedora 40"},
            "declared": {}, "raw_output": "",
        }
        store.save_module("i-get", "os", data, provider="custom")

        result = service.get("i-get", "os", provider="custom")
        assert result is not None
        assert result["observed"]["pretty_name"] == "Fedora 40"

    def test_get_returns_none_for_missing_module(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        service = MemoryService(store=store, config=config)
        assert service.get("i-missing", "os", provider="custom") is None

    def test_clear_removes_stored_module(self, tmp_path: Path) -> None:
        """clear() deletes stored module data."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        service = MemoryService(store=store, config=config)

        data = {
            "module": "os", "instance_id": "i-clear",
            "probed_at": "2026-04-19T12:00:00+00:00",
            "ttl_seconds": 86400, "sudo_used": False,
            "truncated": False, "partial": False,
            "observed": {"pretty_name": "Ubuntu"}, "declared": {}, "raw_output": "",
        }
        store.save_module("i-clear", "os", data, provider="custom")
        assert service.get("i-clear", "os", provider="custom") is not None

        service.clear("i-clear", modules=["os"], provider="custom")
        assert service.get("i-clear", "os", provider="custom") is None

    def test_list_all_returns_index_entries(self, tmp_path: Path) -> None:
        """list_all() returns a list of index entries for known instances."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        service = MemoryService(store=store, config=config)

        store.update_index(
            instance_id="i-listed",
            name="listed-server",
            provider="custom",
            modules=["os"],
        )

        entries = service.list_all()
        assert any(e["instance_id"] == "i-listed" for e in entries)

    def test_list_all_empty_store(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        service = MemoryService(store=store, config=config)
        assert service.list_all() == []


# ---------------------------------------------------------------------------
# _make_ssh_runner — edge cases in the non-custom branch
# ---------------------------------------------------------------------------

class TestRealRunnerEdgeCases:
    """Edge cases in _make_ssh_runner for non-custom instances."""

    @pytest.mark.asyncio
    async def test_key_discovered_when_get_key_path_returns_none(self, tmp_path: Path) -> None:
        """When get_key_path returns None but key_name is set, discover_key is called."""
        from unittest.mock import AsyncMock, MagicMock, patch

        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()

        mock_ssh_service = MagicMock()
        # get_key_path returns None → triggers discover_key fallback
        mock_ssh_service.get_key_path.return_value = None
        mock_ssh_service.discover_key.return_value = "/home/user/.ssh/discovered.pem"
        mock_ssh_service.build_ssh_command.return_value = ["ssh", "1.2.3.4", "hostname"]
        mock_ssh_service._config_manager = MagicMock()
        mock_ssh_service._config_manager.get.return_value = MagicMock(default_username="ec2-user")

        mock_conn_service = MagicMock()
        mock_conn_service.resolve_profile.return_value = None  # no profile
        mock_conn_service.get_target_host.return_value = "1.2.3.4"
        mock_conn_service.get_proxy_args.return_value = []
        mock_conn_service.get_extra_options.return_value = []

        service = MemoryService(
            store=store, config=config,
            ssh_service=mock_ssh_service,
            connection_service=mock_conn_service,
        )

        instance = {
            "id": "i-discover",
            "name": "discover-box",
            "provider": "aws",
            "public_ip": "1.2.3.4",
            "key_name": "my-key-pair",  # present → triggers discover_key
        }

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"discover-box\n", b""))
        mock_proc._transport = None

        with patch(
            "servonaut.utils.ssh_utils.asyncio.create_subprocess_exec",
            return_value=mock_proc,
        ):
            runner = service._make_ssh_runner(instance)
            stdout, _, rc = await runner("hostname")

        # discover_key was called with the key_name value
        mock_ssh_service.discover_key.assert_called_once_with("my-key-pair")
        assert rc == 0

    @pytest.mark.asyncio
    async def test_config_manager_attribute_error_falls_back_to_ec2_user(
        self, tmp_path: Path
    ) -> None:
        """When _config_manager raises AttributeError, username falls back to 'ec2-user'."""
        from unittest.mock import AsyncMock, MagicMock, patch

        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()

        mock_ssh_service = MagicMock()
        mock_ssh_service.get_key_path.return_value = None
        mock_ssh_service.discover_key.return_value = None
        mock_ssh_service.build_ssh_command.return_value = ["ssh", "1.2.3.4", "whoami"]
        # _config_manager.get() raises AttributeError → must be caught gracefully.
        mock_ssh_service._config_manager = MagicMock()
        mock_ssh_service._config_manager.get.side_effect = AttributeError("no config_manager")

        mock_conn_service = MagicMock()
        mock_conn_service.resolve_profile.return_value = None  # no profile → username falls through
        mock_conn_service.get_target_host.return_value = "1.2.3.4"
        mock_conn_service.get_proxy_args.return_value = []
        mock_conn_service.get_extra_options.return_value = []

        service = MemoryService(
            store=store, config=config,
            ssh_service=mock_ssh_service,
            connection_service=mock_conn_service,
        )

        instance = {"id": "i-noconfig", "name": "box", "provider": "aws", "public_ip": "1.2.3.4"}

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"ec2-user\n", b""))
        mock_proc._transport = None

        with patch(
            "servonaut.utils.ssh_utils.asyncio.create_subprocess_exec",
            return_value=mock_proc,
        ):
            runner = service._make_ssh_runner(instance)
            stdout, _, rc = await runner("whoami")

        # Should succeed; username defaulted to "ec2-user".
        assert rc == 0
        # build_ssh_command was called with username="ec2-user"
        call_kw = mock_ssh_service.build_ssh_command.call_args
        assert call_kw.kwargs.get("username") == "ec2-user"


# ---------------------------------------------------------------------------
# build() — prober that raises TimeoutError (lines 172-173)
# ---------------------------------------------------------------------------

class TestBuildTimeoutIsolation:
    """When a prober's probe() raises asyncio.TimeoutError, build() handles it gracefully."""

    def test_probe_timeout_returns_none_for_that_module(self, tmp_path: Path) -> None:
        """A prober whose probe() raises TimeoutError doesn't abort others."""
        class _TimeoutProber(ModuleProberInterface):
            name = "slow"
            ttl_seconds = 3600

            async def probe(self, ssh_runner):
                raise asyncio.TimeoutError("probe timed out")

        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        probers = [_TimeoutProber(), _MockProber("healthy")]
        service = MemoryService(store=store, config=config, probers=probers)

        results = asyncio.run(service.build({"id": "i-timeout-probe", "name": "x", "provider": "custom"}))

        # healthy prober must still succeed
        assert "healthy" in results
        # timed-out prober must not appear
        assert "slow" not in results
