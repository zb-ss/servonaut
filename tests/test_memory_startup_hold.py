"""Share-keyed uploads wait for every inventory load of this run to settle."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

from servonaut.app import ServonautApp
from tests.test_memory_sync_service import _make_module_result, _make_service
from tests.test_memory_team_merge import SHARE_ID, _own, _service, _shared


def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "servonaut.services.memory.sync_service.encrypt_envelope",
        lambda *a, **k: SimpleNamespace(to_dict=lambda: {}),
    )
    sync = _make_service(tmp_path=tmp_path / "sync")
    sync.enqueue_module({"id": SHARE_ID, "name": "web-1"}, "os", _make_module_result())
    posted = []

    async def post(path, json):
        posted.extend(e["instance_id"] for e in json["envelopes"])
        return {"accepted": [], "rejected": []}

    sync._api.post = post
    app = ServonautApp.__new__(ServonautApp)
    app.memory_service = _service(tmp_path / "mem")
    app.memory_sync_service = sync
    app.fleet_service = None
    app.demo_mode = False
    app.notify = MagicMock()
    sync.hold_unfolded_shares()
    return app, sync, posted


def _reconcile(app, rows):
    app.instances = rows
    asyncio.run(app._do_reconcile_team_memory(rows))


def test_a_drain_between_the_shared_load_and_the_own_load_sends_nothing(tmp_path, monkeypatch):
    app, sync, posted = _setup(tmp_path, monkeypatch)
    app.expect_team_memory_load("shared")
    app.expect_team_memory_load("aws")

    app.settle_team_memory_load("shared")
    _reconcile(app, [_shared()])          # shared rows only: the own twin is not loaded yet
    asyncio.run(sync.drain_now())
    assert posted == []                   # still held

    app.settle_team_memory_load("aws")
    _reconcile(app, [_own(), _shared()])  # now the share is known to fold
    asyncio.run(sync.drain_now())
    assert posted == []                   # folded: never sent
    assert sync.pending_count(SHARE_ID) == 1


def test_a_member_only_share_goes_out_once_every_load_settled(tmp_path, monkeypatch):
    app, sync, posted = _setup(tmp_path, monkeypatch)
    app.expect_team_memory_load("shared")
    app.expect_team_memory_load("ovh")
    app.settle_team_memory_load("shared")
    _reconcile(app, [_shared(instance_id=None, hostname="8.8.8.8")])
    asyncio.run(sync.drain_now())
    assert posted == []
    app.settle_team_memory_load("ovh")
    _reconcile(app, [_shared(instance_id=None, hostname="8.8.8.8")])
    asyncio.run(sync.drain_now())
    assert posted == [SHARE_ID]


def test_a_replaced_load_does_not_release_early(tmp_path, monkeypatch):
    app, sync, posted = _setup(tmp_path, monkeypatch)
    app.expect_team_memory_load("aws")   # the first worker
    app.expect_team_memory_load("aws")   # an exclusive restart
    app.settle_team_memory_load("aws")   # the first one is cancelled
    app.release_team_memory_hold()
    assert sync._awaiting_folds is True
    app.settle_team_memory_load("aws")
    app.release_team_memory_hold()
    assert sync._awaiting_folds is False


def test_the_screen_registers_every_load_before_anything_can_release(tmp_path, monkeypatch):
    """Signed out, the shared load needs no worker: the AWS load must still hold the uploads."""
    from servonaut.screens.instance_list import InstanceListScreen

    app, sync, posted = _setup(tmp_path, monkeypatch)
    screen = InstanceListScreen.__new__(InstanceListScreen)
    started = []
    screen._load_on_mount = lambda: (
        screen._fetch_shared_servers_signed_out(),
        screen._expect_team_memory_load("aws"),
    )
    screen._fetch_shared_servers_signed_out = screen._release_team_memory_hold
    monkeypatch.setattr(InstanceListScreen, "app", property(lambda self: app))
    screen.on_mount()
    assert sync._awaiting_folds is True        # the AWS load is still outstanding
    app.settle_team_memory_load("aws")
    app.release_team_memory_hold()
    assert sync._awaiting_folds is False
