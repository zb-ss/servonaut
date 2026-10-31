"""The team-copy merge runs when the shared servers are listed."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

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
        "Merged 2 team copies into your servers: 3 notes, 1 finding.", markup=False,
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


def test_the_upload_hold_ends_when_the_merge_ends_even_if_it_fails(monkeypatch):
    app = _app([_own(), _shared()])

    async def boom(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr("servonaut.services.memory.team_merge.merge_team_copies", boom)
    asyncio.run(app._do_reconcile_team_memory(app.instances))
    app.memory_sync_service.release_share_hold.assert_called_once_with()


def test_reconcile_says_whether_it_started_a_worker():
    app = _app([_own()])
    app.run_worker = MagicMock()
    assert app.reconcile_team_memory() is False
    app.instances = [_own(), _shared()]
    assert app.reconcile_team_memory() is True


def test_the_app_holds_share_keyed_uploads_from_the_start(tmp_path):
    app = ServonautApp(config_path=tmp_path / "config.json")
    app._init_services()
    app.api_client, app.auth_service = MagicMock(), MagicMock()
    app._init_memory_cloud_services()
    assert app.memory_sync_service._awaiting_folds is True


def test_a_failed_merge_leaves_the_shares_queued_notes_in_the_queue(tmp_path):
    from servonaut.config.schema import MemoryConfig
    from tests.test_memory_sync_service import _make_module_result, _make_service
    from tests.test_memory_team_merge import OWN_ID, SHARE_ID, _put_copy, _service

    service = _service(tmp_path / "mem")
    service._config = MemoryConfig(per_server_overrides={OWN_ID: {"memory_disabled": True}})
    _put_copy(service, notes="team note")
    sync = _make_service(tmp_path=tmp_path)
    sync.enqueue_module({"id": SHARE_ID, "name": "web-1"}, "os", _make_module_result())
    app = _app([_own(), _shared()])
    app.memory_service, app.memory_sync_service = service, sync
    app.fleet_service = None
    asyncio.run(app._do_reconcile_team_memory(app.instances))
    assert sync.pending_count(SHARE_ID) == 1
    assert (tmp_path / "mem" / "team team a" / SHARE_ID / "annotations.md").is_file()
