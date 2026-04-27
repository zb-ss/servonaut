"""Unit tests for servonaut.cli.memory (T4 CLI subcommands).

Covers:
  - Exit codes 0, 1, 2, 3, 4.
  - ``memory annotate`` via ``$EDITOR=true`` monkeypatch.
  - ``memory pin`` good path + bad syntax.
  - Snapshot stdout for ``memory show --format summary``.
  - Rate-limit: ``--all`` with 10 fake instances, concurrent ≤ 5.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.interfaces import ModuleResult
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import MemoryStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_inst(name: str = "test-server", iid: str = "i-abc123", provider: str = "custom") -> Dict[str, Any]:
    return {"id": iid, "name": name, "provider": provider, "public_ip": "1.2.3.4"}


def _make_memory_service(tmp_path: Path, enabled: bool = True) -> MemoryService:
    """Real MemoryService with isolated tmp storage and no SSH wiring."""
    store = MemoryStore(root=tmp_path)
    config = MemoryConfig(enabled=enabled)
    return MemoryService(store=store, config=config, probers=[])


def _make_args(**kwargs: Any) -> argparse.Namespace:
    defaults = {
        "memory_command": None,
        "instance": None,
        "json": False,
        "modules": None,
        "all": False,
        "format": "summary",
        "stale": False,
        "module": None,
        "out": None,
        "force": False,
        "dot_expr": None,
        "value": None,
        "debug": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _fake_config(enabled: bool = True, disabled_instance: Optional[str] = None) -> Any:
    """Return a minimal config-like object with a .memory attribute."""
    overrides: Dict[str, Dict[str, Any]] = {}
    if disabled_instance:
        overrides[disabled_instance] = {"memory_disabled": True}
    mem_cfg = MemoryConfig(enabled=enabled, per_server_overrides=overrides)

    cfg = MagicMock()
    cfg.memory = mem_cfg
    return cfg


# ---------------------------------------------------------------------------
# Import smoketest
# ---------------------------------------------------------------------------

class TestImport:
    def test_run_memory_importable(self) -> None:
        from servonaut.cli.memory import run_memory  # noqa: F401


# ---------------------------------------------------------------------------
# Exit code 0 — success paths
# ---------------------------------------------------------------------------

class TestExitCode0:
    def test_build_success(self, tmp_path: Path, capsys: Any) -> None:
        from servonaut.cli.memory import _cmd_build

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)

        # Stub build to return a fake ModuleResult mapping.
        result = ModuleResult(module="os", instance_id="i-abc123", probed_at="2026-04-21T00:00:00+00:00")
        memory_service.build = AsyncMock(return_value={"os": result})

        args = _make_args(memory_command="build", instance="i-abc123")
        config = _fake_config()
        rc = _cmd_build(args, config, memory_service, inst)

        assert rc == 0
        captured = capsys.readouterr()
        assert "os" in captured.out

    def test_show_summary_returns_0(self, tmp_path: Path, capsys: Any) -> None:
        from servonaut.cli.memory import _cmd_show

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)
        summary_text = "# Server Memory\n\n## Identity\n- id: ubuntu\n"
        memory_service.get_summary = AsyncMock(return_value=summary_text)

        args = _make_args(memory_command="show", instance="i-abc123", format="summary")
        config = _fake_config()
        rc = _cmd_show(args, config, memory_service, inst)

        assert rc == 0
        captured = capsys.readouterr()
        assert "Server Memory" in captured.out

    def test_pin_good_path(self, tmp_path: Path, capsys: Any) -> None:
        from servonaut.cli.memory import _cmd_pin

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)

        # Seed an os module so pin can succeed
        store = memory_service._store
        store.save_module("i-abc123", "os", {
            "module": "os",
            "instance_id": "i-abc123",
            "probed_at": "2026-04-21T00:00:00+00:00",
            "ttl_seconds": 86400,
            "sudo_used": False,
            "truncated": False,
            "partial": False,
            "observed": {"arch": "x86_64"},
            "declared": {},
            "raw_output": "",
        }, provider="custom")

        args = _make_args(memory_command="pin", instance="i-abc123", dot_expr="os.arch", value="arm64")
        config = _fake_config()
        rc = _cmd_pin(args, config, memory_service, inst)

        assert rc == 0
        captured = capsys.readouterr()
        assert "arm64" in captured.out

        # Verify it was actually persisted
        data = store.get_module("i-abc123", "os", "custom")
        assert data["declared"]["arch"]["value"] == "arm64"
        assert "pinned_by" in data["declared"]["arch"]


# ---------------------------------------------------------------------------
# Exit code 1 — instance not found
# ---------------------------------------------------------------------------

class TestExitCode1:
    def test_resolve_missing_instance(self, tmp_path: Path, capsys: Any) -> None:
        from servonaut.cli.memory import _resolve_or_exit

        aws_service = MagicMock()
        aws_service._cache = MagicMock()
        aws_service._cache.load_any.return_value = []
        custom_service = MagicMock()
        custom_service.list_as_instances.return_value = []

        args = _make_args(instance="does-not-exist")
        result = _resolve_or_exit(args, aws_service, custom_service, None, use_json=False)

        assert result is None
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower() or "not found" in captured.out.lower()

    def test_pin_missing_module(self, tmp_path: Path, capsys: Any) -> None:
        from servonaut.cli.memory import _cmd_pin

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)
        # No os module seeded — pin should fail

        args = _make_args(memory_command="pin", instance="i-abc123", dot_expr="os.arch", value="arm64")
        config = _fake_config()
        rc = _cmd_pin(args, config, memory_service, inst)

        assert rc == 1
        captured = capsys.readouterr()
        assert "os" in captured.err


# ---------------------------------------------------------------------------
# Exit code 2 — opt-out
# ---------------------------------------------------------------------------

class TestExitCode2:
    def test_opt_out_disabled_globally(self, tmp_path: Path, capsys: Any) -> None:
        from servonaut.cli.memory import _check_opt_out

        config = _fake_config(enabled=False)
        opted_out = _check_opt_out("i-abc123", config, use_json=False)

        assert opted_out is True

    def test_opt_out_per_server(self, tmp_path: Path, capsys: Any) -> None:
        from servonaut.cli.memory import _check_opt_out

        config = _fake_config(enabled=True, disabled_instance="i-abc123")
        opted_out = _check_opt_out("i-abc123", config, use_json=False)

        assert opted_out is True

    def test_opt_out_json_error_envelope(self, tmp_path: Path, capsys: Any) -> None:
        import json as _json
        from servonaut.cli.memory import _check_opt_out

        config = _fake_config(enabled=False)
        opted_out = _check_opt_out("i-abc123", config, use_json=True)

        assert opted_out is True
        captured = capsys.readouterr()
        payload = _json.loads(captured.out)
        assert payload["error"]["code"] == "opt_out"


# ---------------------------------------------------------------------------
# Exit code 3 — partial failure under --all
# ---------------------------------------------------------------------------

class TestExitCode3:
    def test_build_all_partial_failure(self, tmp_path: Path, capsys: Any) -> None:
        from servonaut.cli.memory import _cmd_build_all

        memory_service = _make_memory_service(tmp_path)
        # First two instances succeed; last one fails
        call_count = 0

        async def _mock_build(inst: Dict[str, Any], modules: Any) -> Dict[str, Any]:
            nonlocal call_count
            call_count += 1
            if inst.get("id") == "fail-3":
                raise RuntimeError("SSH timeout")
            return {}

        memory_service.build = _mock_build

        instances = [
            _make_inst(iid="i-1"),
            _make_inst(iid="i-2"),
            _make_inst(iid="fail-3"),
        ]

        aws_service = MagicMock()
        aws_service._cache = MagicMock()
        aws_service._cache.load_any.return_value = instances
        custom_service = MagicMock()
        custom_service.list_as_instances.return_value = []

        args = _make_args(memory_command="build", all=True, modules=None, json=False)
        config = _fake_config()
        rc = _cmd_build_all(args, config, memory_service, aws_service, custom_service, None)

        assert rc == 3


# ---------------------------------------------------------------------------
# Exit code 4 — usage error
# ---------------------------------------------------------------------------

class TestExitCode4:
    def test_pin_bad_syntax_no_dot(self, tmp_path: Path, capsys: Any) -> None:
        from servonaut.cli.memory import _cmd_pin

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)

        args = _make_args(memory_command="pin", instance="i-abc123", dot_expr="no-dot-here", value="x")
        config = _fake_config()
        rc = _cmd_pin(args, config, memory_service, inst)

        assert rc == 4
        captured = capsys.readouterr()
        assert "dot" in captured.err.lower() or "module.field" in captured.err.lower()

    def test_pin_bad_syntax_two_dots(self, tmp_path: Path, capsys: Any) -> None:
        from servonaut.cli.memory import _cmd_pin

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)

        args = _make_args(memory_command="pin", instance="i-abc123", dot_expr="a.b.c", value="x")
        config = _fake_config()
        rc = _cmd_pin(args, config, memory_service, inst)

        assert rc == 4


# ---------------------------------------------------------------------------
# memory annotate — shells out to $EDITOR
# ---------------------------------------------------------------------------

class TestAnnotate:
    def test_annotate_calls_editor(self, tmp_path: Path, monkeypatch: Any) -> None:
        """$EDITOR=true must be called with the annotations path."""
        from servonaut.cli.memory import _cmd_annotate

        monkeypatch.setenv("EDITOR", "true")
        monkeypatch.delenv("VISUAL", raising=False)

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)
        # Point the store at our tmp_path
        memory_service._store = MemoryStore(root=tmp_path)

        calls: List[Any] = []
        import subprocess as _subprocess

        def _fake_run(cmd: Any, **kwargs: Any) -> Any:
            calls.append(cmd)
            return MagicMock(returncode=0)

        monkeypatch.setattr(_subprocess, "run", _fake_run)

        args = _make_args(memory_command="annotate", instance="i-abc123")
        config = _fake_config()
        rc = _cmd_annotate(args, config, memory_service, inst)

        assert rc == 0
        assert len(calls) == 1
        editor_call = calls[0]
        assert editor_call[0] == "true"
        # Annotations file must exist with mode 0o600
        path = memory_service._store.get_annotations_path("i-abc123", "custom")
        assert path.exists()
        import stat as _stat
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600

    def test_annotate_fallback_to_vi(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Falls back to 'vi' when neither $VISUAL nor $EDITOR is set."""
        from servonaut.cli.memory import _cmd_annotate
        import subprocess as _subprocess

        monkeypatch.delenv("VISUAL", raising=False)
        monkeypatch.delenv("EDITOR", raising=False)

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)
        memory_service._store = MemoryStore(root=tmp_path)

        calls: List[Any] = []

        def _fake_run(cmd: Any, **kwargs: Any) -> Any:
            calls.append(cmd)
            return MagicMock(returncode=0)

        monkeypatch.setattr(_subprocess, "run", _fake_run)

        args = _make_args(memory_command="annotate", instance="i-abc123")
        config = _fake_config()
        _cmd_annotate(args, config, memory_service, inst)

        assert calls[0][0] == "vi"


# ---------------------------------------------------------------------------
# memory show snapshot
# ---------------------------------------------------------------------------

class TestShowSnapshot:
    def test_show_summary_snapshot(self, tmp_path: Path, capsys: Any) -> None:
        """Summary output should contain the instance heading."""
        from servonaut.cli.memory import _cmd_show

        inst = _make_inst(name="prod-web-01", iid="i-deadbeef")
        memory_service = _make_memory_service(tmp_path)

        expected = "# Server Memory: prod-web-01\n\n## Identity\n- id: ubuntu\n"
        memory_service.get_summary = AsyncMock(return_value=expected)

        args = _make_args(memory_command="show", instance="i-deadbeef", format="summary")
        config = _fake_config()
        rc = _cmd_show(args, config, memory_service, inst)

        assert rc == 0
        captured = capsys.readouterr()
        assert "prod-web-01" in captured.out
        assert "Identity" in captured.out

    def test_show_json_format(self, tmp_path: Path, capsys: Any) -> None:
        """JSON format should dump all modules as valid JSON."""
        import json as _json
        from servonaut.cli.memory import _cmd_show

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)

        # Seed a module
        store = memory_service._store
        store.save_module("i-abc123", "os", {
            "module": "os", "instance_id": "i-abc123",
            "probed_at": "2026-04-21T00:00:00+00:00",
            "ttl_seconds": 86400, "sudo_used": False,
            "truncated": False, "partial": False,
            "observed": {"id": "ubuntu"}, "declared": {}, "raw_output": "",
        }, provider="custom")

        args = _make_args(memory_command="show", instance="i-abc123", format="json")
        config = _fake_config()
        rc = _cmd_show(args, config, memory_service, inst)

        assert rc == 0
        captured = capsys.readouterr()
        data = _json.loads(captured.out)
        assert "os" in data
        assert data["os"]["observed"]["id"] == "ubuntu"


# ---------------------------------------------------------------------------
# Rate-limit: --all concurrent ≤ 5
# ---------------------------------------------------------------------------

class TestBuildAllRateLimit:
    def test_max_concurrent_never_exceeds_5(self, tmp_path: Path) -> None:
        """--all with 10 instances must never run more than 5 builds concurrently."""
        from servonaut.cli.memory import _build_all

        max_concurrent = 0
        current_concurrent = 0
        lock = asyncio.Lock()

        async def _mock_build(inst: Dict[str, Any], modules: Any) -> Dict[str, Any]:
            nonlocal max_concurrent, current_concurrent
            async with lock:
                current_concurrent += 1
                if current_concurrent > max_concurrent:
                    max_concurrent = current_concurrent
            # Simulate some work
            await asyncio.sleep(0.05)
            async with lock:
                current_concurrent -= 1
            return {}

        memory_service = _make_memory_service(tmp_path)
        memory_service.build = _mock_build

        instances = [_make_inst(iid=f"i-{n:03d}") for n in range(10)]

        failures = asyncio.run(_build_all(instances, memory_service, modules=None))

        assert not failures, f"Unexpected failures: {failures}"
        assert max_concurrent <= 5, (
            f"Concurrency exceeded limit: max_concurrent={max_concurrent}"
        )

    def test_build_all_collects_failures(self, tmp_path: Path) -> None:
        """Failures from individual instances are collected, not raised."""
        from servonaut.cli.memory import _build_all

        async def _mock_build(inst: Dict[str, Any], modules: Any) -> Dict[str, Any]:
            if inst.get("id") == "i-bad":
                raise RuntimeError("probe failed")
            return {}

        memory_service = _make_memory_service(tmp_path)
        memory_service.build = _mock_build

        instances = [_make_inst(iid="i-001"), _make_inst(iid="i-bad"), _make_inst(iid="i-002")]
        failures = asyncio.run(_build_all(instances, memory_service, modules=None))

        assert len(failures) == 1
        failed_id, exc = failures[0]
        assert failed_id == "i-bad"
        assert "probe failed" in str(exc)


# ---------------------------------------------------------------------------
# clear subcommand
# ---------------------------------------------------------------------------

class TestClear:
    def test_clear_all(self, tmp_path: Path, capsys: Any) -> None:
        from servonaut.cli.memory import _cmd_clear

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)

        # Seed a module so there is something to clear
        memory_service._store.save_module("i-abc123", "os", {
            "module": "os", "instance_id": "i-abc123",
            "probed_at": "2026-04-21T00:00:00+00:00",
            "ttl_seconds": 86400, "sudo_used": False,
            "truncated": False, "partial": False,
            "observed": {}, "declared": {}, "raw_output": "",
        }, provider="custom")

        args = _make_args(memory_command="clear", instance="i-abc123", all=True, modules=None)
        config = _fake_config()
        rc = _cmd_clear(args, config, memory_service, inst)

        assert rc == 0
        # Module should be gone
        assert memory_service._store.get_module("i-abc123", "os", "custom") is None

    def test_clear_specific_module(self, tmp_path: Path, capsys: Any) -> None:
        from servonaut.cli.memory import _cmd_clear

        inst = _make_inst()
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        memory_service = MemoryService(store=store, config=config, probers=[])

        for mod in ("os", "runtimes"):
            store.save_module("i-abc123", mod, {
                "module": mod, "instance_id": "i-abc123",
                "probed_at": "2026-04-21T00:00:00+00:00",
                "ttl_seconds": 86400, "sudo_used": False,
                "truncated": False, "partial": False,
                "observed": {}, "declared": {}, "raw_output": "",
            }, provider="custom")

        args = _make_args(memory_command="clear", instance="i-abc123", modules=["os"], all=False)
        cfg = _fake_config()
        _cmd_clear(args, cfg, memory_service, inst)

        assert store.get_module("i-abc123", "os", "custom") is None
        assert store.get_module("i-abc123", "runtimes", "custom") is not None


# ---------------------------------------------------------------------------
# stale_modules helper (store contract)
# ---------------------------------------------------------------------------

class TestStaleModules:
    def test_no_data_returns_empty(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        stale = store.stale_modules("i-abc123", config, provider="custom")
        assert stale == []

    def test_fresh_module_not_stale(self, tmp_path: Path) -> None:
        from datetime import datetime, timezone
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        store.save_module("i-abc123", "os", {
            "module": "os", "instance_id": "i-abc123",
            "probed_at": datetime.now(tz=timezone.utc).isoformat(),
            "ttl_seconds": 86400,
            "sudo_used": False, "truncated": False, "partial": False,
            "observed": {}, "declared": {}, "raw_output": "",
        }, provider="custom")
        stale = store.stale_modules("i-abc123", config, provider="custom")
        assert "os" not in stale

    def test_expired_module_is_stale(self, tmp_path: Path) -> None:
        from datetime import datetime, timedelta, timezone
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        old_ts = (datetime.now(tz=timezone.utc) - timedelta(days=2)).isoformat()
        store.save_module("i-abc123", "os", {
            "module": "os", "instance_id": "i-abc123",
            "probed_at": old_ts,
            "ttl_seconds": 86400,
            "sudo_used": False, "truncated": False, "partial": False,
            "observed": {}, "declared": {}, "raw_output": "",
        }, provider="custom")
        stale = store.stale_modules("i-abc123", config, provider="custom")
        assert "os" in stale


# ---------------------------------------------------------------------------
# B.3 — run_memory dispatch and additional coverage
# ---------------------------------------------------------------------------

class TestRunMemoryDispatch:
    """Test run_memory routes correctly to each subcommand handler."""

    def _make_headless_mocks(self, tmp_path: Path):
        """Return (config, memory_service, aws, custom, ovh) mocks."""
        memory_service = _make_memory_service(tmp_path)
        aws_service = MagicMock()
        aws_service._cache = MagicMock()
        aws_service._cache.load_any.return_value = [_make_inst()]
        custom_service = MagicMock()
        custom_service.list_as_instances.return_value = []
        config = _fake_config()
        return config, memory_service, aws_service, custom_service, None

    def test_run_memory_no_subcommand_returns_usage_error(self, tmp_path: Path, capsys: Any) -> None:
        """run_memory without a subcommand returns exit code 4 immediately."""
        from servonaut.cli.memory import run_memory

        args = _make_args(memory_command=None, instance="i-abc123")
        rc = run_memory(args)
        assert rc == 4

    def test_run_memory_build_dispatch(self, tmp_path: Path, monkeypatch: Any) -> None:
        """run_memory dispatches 'build' to _cmd_build."""
        from servonaut.cli import memory as mem_mod

        config, memory_service, aws_service, custom_service, ovh = self._make_headless_mocks(tmp_path)

        build_called = []

        def _fake_cmd_build(args, cfg, svc, inst):
            build_called.append(inst)
            return 0

        monkeypatch.setattr(mem_mod, "_init_headless_services",
                            lambda: (config, memory_service, aws_service, custom_service, ovh))
        monkeypatch.setattr(mem_mod, "_cmd_build", _fake_cmd_build)

        args = _make_args(memory_command="build", instance="test-server")
        rc = mem_mod.run_memory(args)

        assert rc == 0
        assert len(build_called) == 1

    def test_run_memory_refresh_dispatch(self, tmp_path: Path, monkeypatch: Any) -> None:
        """run_memory dispatches 'refresh' to _cmd_refresh."""
        from servonaut.cli import memory as mem_mod

        config, memory_service, aws_service, custom_service, ovh = self._make_headless_mocks(tmp_path)
        refresh_called = []

        def _fake_cmd_refresh(args, cfg, svc, inst):
            refresh_called.append(True)
            return 0

        monkeypatch.setattr(mem_mod, "_init_headless_services",
                            lambda: (config, memory_service, aws_service, custom_service, ovh))
        monkeypatch.setattr(mem_mod, "_cmd_refresh", _fake_cmd_refresh)

        args = _make_args(memory_command="refresh", instance="test-server")
        rc = mem_mod.run_memory(args)

        assert rc == 0
        assert refresh_called

    def test_run_memory_show_dispatch(self, tmp_path: Path, monkeypatch: Any) -> None:
        """run_memory dispatches 'show' to _cmd_show."""
        from servonaut.cli import memory as mem_mod

        config, memory_service, aws_service, custom_service, ovh = self._make_headless_mocks(tmp_path)
        show_called = []

        def _fake_cmd_show(args, cfg, svc, inst):
            show_called.append(True)
            return 0

        monkeypatch.setattr(mem_mod, "_init_headless_services",
                            lambda: (config, memory_service, aws_service, custom_service, ovh))
        monkeypatch.setattr(mem_mod, "_cmd_show", _fake_cmd_show)

        args = _make_args(memory_command="show", instance="test-server")
        rc = mem_mod.run_memory(args)

        assert rc == 0
        assert show_called

    def test_run_memory_export_dispatch(self, tmp_path: Path, monkeypatch: Any) -> None:
        """run_memory dispatches 'export' to _cmd_export."""
        from servonaut.cli import memory as mem_mod

        config, memory_service, aws_service, custom_service, ovh = self._make_headless_mocks(tmp_path)
        export_called = []

        def _fake_cmd_export(args, cfg, svc, inst):
            export_called.append(True)
            return 0

        monkeypatch.setattr(mem_mod, "_init_headless_services",
                            lambda: (config, memory_service, aws_service, custom_service, ovh))
        monkeypatch.setattr(mem_mod, "_cmd_export", _fake_cmd_export)

        args = _make_args(memory_command="export", instance="test-server")
        rc = mem_mod.run_memory(args)

        assert rc == 0
        assert export_called

    def test_run_memory_clear_dispatch(self, tmp_path: Path, monkeypatch: Any) -> None:
        """run_memory dispatches 'clear' to _cmd_clear."""
        from servonaut.cli import memory as mem_mod

        config, memory_service, aws_service, custom_service, ovh = self._make_headless_mocks(tmp_path)
        clear_called = []

        def _fake_cmd_clear(args, cfg, svc, inst):
            clear_called.append(True)
            return 0

        monkeypatch.setattr(mem_mod, "_init_headless_services",
                            lambda: (config, memory_service, aws_service, custom_service, ovh))
        monkeypatch.setattr(mem_mod, "_cmd_clear", _fake_cmd_clear)

        args = _make_args(memory_command="clear", instance="test-server")
        rc = mem_mod.run_memory(args)

        assert rc == 0
        assert clear_called

    def test_run_memory_unknown_subcommand_returns_4(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Unknown subcommand returns exit code 4."""
        from servonaut.cli import memory as mem_mod

        config, memory_service, aws_service, custom_service, ovh = self._make_headless_mocks(tmp_path)

        monkeypatch.setattr(mem_mod, "_init_headless_services",
                            lambda: (config, memory_service, aws_service, custom_service, ovh))

        args = _make_args(memory_command="no_such_cmd", instance="test-server")
        rc = mem_mod.run_memory(args)

        assert rc == 4


class TestShowStaleFilter:
    """Tests for the --stale flag in _cmd_show."""

    def test_show_stale_json_filters_modules(self, tmp_path: Path, capsys: Any) -> None:
        """--stale with --format json returns only stale modules."""
        import json as _json
        from datetime import datetime, timedelta, timezone
        from servonaut.cli.memory import _cmd_show

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)
        store = memory_service._store

        now = datetime.now(tz=timezone.utc)
        fresh_ts = now.isoformat()
        stale_ts = (now - timedelta(days=2)).isoformat()

        for mod, ts in [("os", fresh_ts), ("runtimes", stale_ts)]:
            store.save_module("i-abc123", mod, {
                "module": mod, "instance_id": "i-abc123",
                "probed_at": ts,
                "ttl_seconds": 86400, "sudo_used": False,
                "truncated": False, "partial": False,
                "observed": {"key": mod}, "declared": {}, "raw_output": "",
            }, provider="custom")

        args = _make_args(memory_command="show", instance="i-abc123",
                          format="json", stale=True)
        config = _fake_config()
        rc = _cmd_show(args, config, memory_service, inst)

        assert rc == 0
        captured = capsys.readouterr()
        data = _json.loads(captured.out)
        # Only the stale "runtimes" module should appear
        assert "runtimes" in data
        assert "os" not in data

    def test_show_markdown_format_calls_get_summary_large_tokens(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        """--format markdown calls get_summary with max_tokens=1_000_000."""
        from servonaut.cli.memory import _cmd_show

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)

        tokens_used = []

        async def _fake_get_summary(inst_meta, max_tokens=1500):
            tokens_used.append(max_tokens)
            return "# Markdown summary\n"

        memory_service.get_summary = _fake_get_summary

        args = _make_args(memory_command="show", instance="i-abc123", format="markdown")
        config = _fake_config()
        rc = _cmd_show(args, config, memory_service, inst)

        assert rc == 0
        assert tokens_used == [1_000_000]
        captured = capsys.readouterr()
        assert "Markdown summary" in captured.out

    def test_show_single_module_returns_module_data(self, tmp_path: Path, capsys: Any) -> None:
        """--module <name> prints only that module's data."""
        import json as _json
        from servonaut.cli.memory import _cmd_show

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)
        store = memory_service._store

        store.save_module("i-abc123", "runtimes", {
            "module": "runtimes", "instance_id": "i-abc123",
            "probed_at": "2026-04-21T00:00:00+00:00",
            "ttl_seconds": 86400, "sudo_used": False,
            "truncated": False, "partial": False,
            "observed": {"python": "3.11"}, "declared": {}, "raw_output": "",
        }, provider="custom")

        args = _make_args(memory_command="show", instance="i-abc123",
                          format="json", module="runtimes")
        config = _fake_config()
        rc = _cmd_show(args, config, memory_service, inst)

        assert rc == 0
        captured = capsys.readouterr()
        data = _json.loads(captured.out)
        assert data["observed"]["python"] == "3.11"

    def test_show_single_module_not_found_returns_1(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        """--module <missing> returns exit code 1."""
        from servonaut.cli.memory import _cmd_show

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)

        args = _make_args(memory_command="show", instance="i-abc123",
                          format="json", module="nonexistent")
        config = _fake_config()
        rc = _cmd_show(args, config, memory_service, inst)

        assert rc == 1


class TestExportCommand:
    def test_export_writes_to_custom_path(self, tmp_path: Path, capsys: Any) -> None:
        """--out <path> writes summary to the given path."""
        from servonaut.cli.memory import _cmd_export

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)
        memory_service.get_summary = AsyncMock(return_value="# Summary\ncontent")

        out_path = tmp_path / "custom_export.md"
        args = _make_args(memory_command="export", instance="i-abc123",
                          out=str(out_path))
        config = _fake_config()
        rc = _cmd_export(args, config, memory_service, inst)

        assert rc == 0
        assert out_path.read_text() == "# Summary\ncontent"
        captured = capsys.readouterr()
        assert "custom_export.md" in captured.out

    def test_export_default_path_calls_write_summary(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        """Without --out, write_summary is called and path is printed."""
        from servonaut.cli.memory import _cmd_export

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)
        expected_path = tmp_path / "summary.md"
        memory_service.write_summary = AsyncMock(return_value=expected_path)

        args = _make_args(memory_command="export", instance="i-abc123", out=None)
        config = _fake_config()
        rc = _cmd_export(args, config, memory_service, inst)

        assert rc == 0
        memory_service.write_summary.assert_awaited_once()
        captured = capsys.readouterr()
        assert "summary.md" in captured.out


class TestRefreshCommand:
    def test_refresh_success_prints_modules(self, tmp_path: Path, capsys: Any) -> None:
        """_cmd_refresh prints refreshed module names on success."""
        from servonaut.cli.memory import _cmd_refresh

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)
        memory_service.refresh = AsyncMock(
            return_value={"os": MagicMock(), "runtimes": MagicMock()}
        )

        args = _make_args(memory_command="refresh", instance="i-abc123")
        config = _fake_config()
        rc = _cmd_refresh(args, config, memory_service, inst)

        assert rc == 0
        captured = capsys.readouterr()
        assert "os" in captured.out or "runtimes" in captured.out


# ---------------------------------------------------------------------------
# Additional coverage tests (B.3)
# ---------------------------------------------------------------------------

class TestBuildJsonFormat:
    def test_build_json_format_outputs_valid_json(self, tmp_path: Path, capsys: Any) -> None:
        """--json flag dumps build result as JSON."""
        import json as _json
        from servonaut.cli.memory import _cmd_build

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)
        result = ModuleResult(module="os", instance_id="i-abc123", probed_at="2026-04-21T00:00:00+00:00")
        result.observed = {"arch": "x86_64"}
        memory_service.build = AsyncMock(return_value={"os": result})

        args = _make_args(memory_command="build", instance="i-abc123", json=True)
        config = _fake_config()
        rc = _cmd_build(args, config, memory_service, inst)

        assert rc == 0
        captured = capsys.readouterr()
        data = _json.loads(captured.out)
        assert "os" in data
        assert "observed_keys" in data["os"]

    def test_build_no_probers_prints_info(self, tmp_path: Path, capsys: Any) -> None:
        """_cmd_build with empty results prints no-modules message."""
        from servonaut.cli.memory import _cmd_build

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)
        memory_service.build = AsyncMock(return_value={})

        args = _make_args(memory_command="build", instance="i-abc123")
        config = _fake_config()
        rc = _cmd_build(args, config, memory_service, inst)

        assert rc == 0
        captured = capsys.readouterr()
        assert "No modules probed" in captured.out or "disabled" in captured.out


class TestBuildAllNoInstances:
    def test_cmd_build_all_no_instances_returns_not_found(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        """_cmd_build_all returns exit 1 when no instances found."""
        from servonaut.cli.memory import _cmd_build_all

        memory_service = _make_memory_service(tmp_path)
        aws_service = MagicMock()
        aws_service._cache = MagicMock()
        aws_service._cache.load_any.return_value = []
        custom_service = MagicMock()
        custom_service.list_as_instances.return_value = []

        args = _make_args(memory_command="build", all=True, modules=None, json=False)
        config = _fake_config()
        rc = _cmd_build_all(args, config, memory_service, aws_service, custom_service, None)

        assert rc == 1


class TestCheckOptOutJsonEnvelope:
    def test_check_opt_out_per_server_json_envelope(self, tmp_path: Path, capsys: Any) -> None:
        """_check_opt_out with use_json=True emits JSON envelope for per-server opt-out."""
        import json as _json
        from servonaut.cli.memory import _check_opt_out

        config = _fake_config(disabled_instance="i-abc123")
        opted_out = _check_opt_out("i-abc123", config, use_json=True)

        assert opted_out is True
        captured = capsys.readouterr()
        payload = _json.loads(captured.out)
        assert payload["error"]["code"] == "opt_out"


class TestResolveOrExitJsonError:
    def test_resolve_or_exit_json_envelope_on_not_found(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        """_resolve_or_exit with use_json=True emits JSON error envelope."""
        import json as _json
        from servonaut.cli.memory import _resolve_or_exit

        aws_service = MagicMock()
        aws_service._cache = MagicMock()
        aws_service._cache.load_any.return_value = []
        custom_service = MagicMock()
        custom_service.list_as_instances.return_value = []

        args = _make_args(instance="no-such-instance")
        result = _resolve_or_exit(args, aws_service, custom_service, None, use_json=True)

        assert result is None
        captured = capsys.readouterr()
        payload = _json.loads(captured.out)
        assert payload["error"]["code"] == "not_found"


class TestRunMemoryBuildNoInstance:
    def test_build_without_all_and_without_instance_is_usage_error(
        self, tmp_path: Path, monkeypatch: Any, capsys: Any
    ) -> None:
        """'memory build' with no --all and no instance returns exit 4."""
        from servonaut.cli import memory as mem_mod

        memory_service = _make_memory_service(tmp_path)
        aws_service = MagicMock()
        aws_service._cache = MagicMock()
        aws_service._cache.load_any.return_value = []
        custom_service = MagicMock()
        custom_service.list_as_instances.return_value = []
        config = _fake_config()

        monkeypatch.setattr(mem_mod, "_init_headless_services",
                            lambda: (config, memory_service, aws_service, custom_service, None))

        args = _make_args(memory_command="build", instance=None, all=False)
        rc = mem_mod.run_memory(args)
        assert rc == 4


class TestAnnotateFileModeAndUpdate:
    def test_annotate_creates_file_with_secure_mode(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """annotate creates annotations file with mode 0o600."""
        import stat as _stat
        import subprocess as _subprocess
        from servonaut.cli.memory import _cmd_annotate

        monkeypatch.setenv("EDITOR", "true")
        monkeypatch.delenv("VISUAL", raising=False)

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)
        # Use the tmp_path store so we can check file mode
        from servonaut.services.memory.store import MemoryStore
        memory_service._store = MemoryStore(root=tmp_path)

        monkeypatch.setattr(_subprocess, "run", lambda cmd, **kw: MagicMock(returncode=0))

        args = _make_args(memory_command="annotate", instance="i-abc123")
        config = _fake_config()
        rc = _cmd_annotate(args, config, memory_service, inst)

        assert rc == 0
        path = memory_service.get_annotations_path("i-abc123", "custom")
        assert path.exists()
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600


class TestPinModuleError:
    def test_pin_value_error_returns_usage_error(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        """_cmd_pin with invalid module name (fails validation) returns exit 4."""
        from servonaut.cli.memory import _cmd_pin

        inst = _make_inst()
        memory_service = _make_memory_service(tmp_path)

        # Use an expression that parses ok but fails validation via MemoryService.pin
        # by triggering ValueError from _validate_module_name (e.g. module="OS")
        args = _make_args(
            memory_command="pin", instance="i-abc123",
            dot_expr="OS.arch", value="x86_64"  # uppercase triggers validation error
        )
        config = _fake_config()
        rc = _cmd_pin(args, config, memory_service, inst)
        # Should fail with usage error (4) since "OS" is invalid module name
        assert rc == 4


class TestInitHeadlessServicesOvhSkipped:
    def test_init_without_ovh_config_sets_none(self, monkeypatch: Any) -> None:
        """_init_headless_services succeeds when OVH is not configured."""
        from servonaut.cli import memory as mem_mod

        class _FakeConfigManager:
            def get(self):
                import types
                cfg = types.SimpleNamespace()
                cfg.cache_ttl_seconds = 3600
                cfg.keyword_store_path = "/tmp/kw.json"
                cfg.command_history_path = "/tmp/ch.json"
                mem = __import__("servonaut.config.schema", fromlist=["MemoryConfig"]).MemoryConfig
                cfg.memory = mem()
                cfg.ovh = types.SimpleNamespace(enabled=False, application_key="", client_id="")
                return cfg

        def _fake_config_manager():
            return _FakeConfigManager()

        import servonaut.config.manager as cm_mod
        monkeypatch.setattr(cm_mod, "ConfigManager", _fake_config_manager)

        # _init_headless_services calls ConfigManager() internally;
        # with OVH disabled it must succeed and return ovh_service=None.
        result = mem_mod._init_headless_services()
        assert len(result) == 5
        assert result[4] is None  # ovh_service is None when disabled
