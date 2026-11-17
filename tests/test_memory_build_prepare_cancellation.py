"""Cancellation during connection preparation must not abandon probe coroutines."""
from __future__ import annotations

import asyncio
import gc
import warnings
from pathlib import Path
from typing import Any

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.interfaces import ModuleProberInterface, ModuleResult
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import MemoryStore
from tests._async_bounds import STEP_TIMEOUT_SECONDS


class _UnstartedProber(ModuleProberInterface):
    name = "os"
    ttl_seconds = 3600

    def __init__(self) -> None:
        self.calls = 0

    async def probe(self, ssh_runner: Any) -> ModuleResult:
        self.calls += 1
        raise AssertionError("probing must wait for successful preparation")


class _HeldPreparation:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.close_calls = 0

    async def prepare(self) -> None:
        self.entered.set()
        await self.release.wait()

    async def close(self) -> None:
        self.close_calls += 1


def test_cancel_during_prepare_leaves_no_unawaited_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancel at the prepare boundary and collect after the task/loop retire."""
    store = MemoryStore(root=tmp_path)
    prober = _UnstartedProber()
    service = MemoryService(store=store, config=MemoryConfig(), probers=[prober])

    async def exercise() -> None:
        runner = _HeldPreparation()
        monkeypatch.setattr(service, "_make_ssh_runner", lambda *a, **kw: runner)
        build = asyncio.create_task(service.build_report({
            "id": "server-1", "name": "server-1", "provider": "custom",
        }))
        try:
            await asyncio.wait_for(runner.entered.wait(), STEP_TIMEOUT_SECONDS)
            assert prober.calls == 0
            assert build.cancel()
            with pytest.raises(asyncio.CancelledError):
                await build
            assert runner.close_calls == 1
            assert prober.calls == 0
            assert store.get_module("server-1", "os", "custom") is None
        finally:
            if not build.done():
                build.cancel()
                try:
                    await build
                except asyncio.CancelledError:
                    pass

    # Capture rather than suppress runtime warnings: even an unrelated one fails.
    # Retire the loop first so its task/exception references cannot defer the leak
    # until a later test's collection. No production coroutine is manually closed.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", RuntimeWarning)
        asyncio.run(exercise())
        gc.collect()
    assert not caught, [(item.category.__name__, str(item.message)) for item in caught]
