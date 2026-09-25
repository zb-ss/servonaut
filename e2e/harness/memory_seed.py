"""Seed a home's local server memory, written through the real memory store.

:func:`seed_memory` stores module snapshots for one host exactly as a probe
would (the dict ``MemoryService`` persists for a ``ModuleResult``) and
indexes the host, so Memory Sync, the Fleet Memory screen and team sharing
see a server that was probed before, without an SSH round-trip.

Journeys put a distinctive marker in the observed values: an uploaded
envelope must never contain it in the clear.

The provider directory follows the service: an instance dict without a
``provider`` key (an AWS cache row) is stored as ``custom``.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any, Mapping

from e2e.harness.fleet import AwsHost


def provider_of(host: AwsHost) -> str:
    """The provider slug ``MemoryService`` files *host*'s memory under."""
    return host.cache_row().get("provider", "custom")


def memory_root(home: Path) -> Path:
    return home / ".servonaut" / "memory"


def seed_memory(
    home: Path,
    host: AwsHost,
    modules: Mapping[str, Mapping[str, Any]],
    *,
    probed_at: dt.datetime | None = None,
) -> None:
    """Store *modules* (``{module: observed values}``) for *host* in *home*."""
    from servonaut.services.memory.store import MemoryStore

    store = MemoryStore(root=memory_root(home))
    stamp = (probed_at or dt.datetime.now(dt.timezone.utc)).isoformat()
    for module, observed in modules.items():
        store.save_module(
            host.instance_id,
            module,
            {
                "module": module,
                "instance_id": host.instance_id,
                "probed_at": stamp,
                "ttl_seconds": 86400,
                "sudo_used": False,
                "truncated": False,
                "partial": False,
                "observed": dict(observed),
                "declared": {},
                "raw_output": " ".join(f"{k}={v}" for k, v in observed.items()),
            },
            provider_of(host),
        )
    store.update_index(host.instance_id, host.name, provider_of(host), list(modules))


def read_module(home: Path, host: AwsHost, module: str) -> dict[str, Any] | None:
    """The module snapshot the local store holds for *host*."""
    from servonaut.services.memory.store import MemoryStore

    return MemoryStore(root=memory_root(home)).get_module(
        host.instance_id, module, provider_of(host)
    )
