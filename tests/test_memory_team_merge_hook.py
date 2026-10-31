"""The team-copy merge runs when the shared servers are listed."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from servonaut.app import ServonautApp
from servonaut.services.memory.team_merge import TeamMergeReport
from tests.test_memory_team_merge import _own, _shared


def _app(rows):
    app = ServonautApp.__new__(ServonautApp)
    app.memory_service = MagicMock()
    app.memory_sync_service = MagicMock()
    app.instances = rows
    app.demo_mode = False
    app.notify = MagicMock()
    return app


def test_a_worker_with_its_own_group_is_started_when_shares_are_listed():
    app = _app([_own(), _shared()])
    started = {}
    app.run_worker = lambda coro, **kw: (started.update(kw), coro.close())
    app.reconcile_team_memory()
    assert started["group"] == "memory_team_merge"


def test_nothing_runs_without_shared_rows():
    app = _app([_own()])
    app.run_worker = MagicMock()
    app.reconcile_team_memory()
    app.run_worker.assert_not_called()


def test_the_user_is_told_once_what_was_merged(monkeypatch):
    app = _app([_own(), _shared()])

    async def merged(*args, **kwargs):
        return TeamMergeReport(copies=2, notes=3, findings=1)

    monkeypatch.setattr("servonaut.services.memory.team_merge.merge_team_copies", merged)
    asyncio.run(app._do_reconcile_team_memory(app.instances))
    app.notify.assert_called_once_with(
        "Merged 2 team copies into your servers: 3 notes, 1 findings.", markup=False,
    )
    app.memory_sync_service.set_folded_instance_ids.assert_called_once_with({_shared()["id"]})


def test_a_failed_merge_is_silent_and_leaves_the_copies(monkeypatch):
    app = _app([_own(), _shared()])

    async def boom(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr("servonaut.services.memory.team_merge.merge_team_copies", boom)
    asyncio.run(app._do_reconcile_team_memory(app.instances))
    app.notify.assert_not_called()


def test_a_twin_that_loads_after_the_shared_rows_is_merged():
    # Shared rows first, then the provider row the share is a copy of.
    app = _app([_shared()])
    seen = []

    async def record(rows):
        seen.append([row["id"] for row in rows])

    app._do_reconcile_team_memory = record
    app.run_worker = lambda coro, **kw: asyncio.run(coro)
    app.reconcile_team_memory()
    app.instances = [_shared(), _own()]
    app.reconcile_team_memory()
    assert seen == [[_shared()["id"]], [_shared()["id"], _own()["id"]]]
