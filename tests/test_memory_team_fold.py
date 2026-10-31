"""Memory lists, probes and injects each server once, whoever shares it.

A team's shared server that is also one of the user's own servers is the
same machine: Fleet Memory, the fleet scan and the chat scope work from the
user's own row, as the server list does.
"""
from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock

from servonaut.screens.fleet_memory import FleetMemoryScreen
from servonaut.services.memory.team_fold import memory_fleet_rows
from servonaut.services.shared_servers import shared_row

TEAM = {"slug": "team-a", "name": "Team A", "id": 7}


def _bind_app(widget: Any, app: Any) -> None:
    """Give one widget instance a fake ``app`` without touching its class.

    Assigning ``app`` on the production class would leak into every later
    test in the process, so the instance gets a private subclass instead.
    """
    widget.__class__ = type(
        widget.__class__.__name__, (widget.__class__,), {"app": property(lambda self: app)}
    )



def _own(**changes: Any) -> Dict[str, Any]:
    row = {
        "id": "i-0abc0abc0abc0abc0", "name": "web-1", "state": "running",
        "public_ip": "9.9.9.9", "private_ip": "10.0.0.5",
    }
    row.update(changes)
    return row


def _shared(**changes: Any) -> Dict[str, Any]:
    server = {
        "id": "11111111-aaaa-bbbb-cccc-000000000001", "name": "web-1",
        "hostname": "9.9.9.9", "instance_id": "i-0abc0abc0abc0abc0",
        "username": "deploy",
    }
    server.update(changes)
    return shared_row(server, TEAM)


def _app(rows: List[Dict[str, Any]], **extra: Any) -> MagicMock:
    app = MagicMock()
    app.demo_mode = False
    app.redaction_service = None
    app.instances = rows
    for key, value in extra.items():
        setattr(app, key, value)
    return app


class TestMemoryFleetRows:
    def test_own_row_absorbs_its_team_twin(self):
        own, twin = _own(), _shared()
        assert memory_fleet_rows(_app([own, twin])) == [own]

    def test_shared_only_row_stays(self):
        twin = _shared(instance_id=None, hostname="8.8.8.8")
        assert memory_fleet_rows(_app([_own(), twin])) == [_own(), twin]

    def test_unconfirmed_twin_is_not_folded(self):
        twin = _shared(instance_id="i-0def0def0def0def0", hostname="8.8.8.8")
        assert twin in memory_fleet_rows(_app([_own(), twin]))

    def test_demo_mode_folds_real_records_and_shows_redacted_ones(self):
        own, twin = _own(), _shared()
        fake_own = {**own, "id": "i-fake0001", "public_ip": "1.2.3.4"}
        fake_twin = {**twin, "id": "fake-share", "public_ip": "1.2.3.5"}
        redaction = MagicMock()
        redaction.real_instance_id.side_effect = {
            "i-fake0001": own["id"], "fake-share": twin["id"],
        }.get
        app = _app(
            [fake_own, fake_twin], demo_mode=True, redaction_service=redaction,
            _instances_pristine=[own, twin],
        )
        assert memory_fleet_rows(app) == [fake_own]


class TestFleetMemoryTable:
    def test_one_row_per_server(self):
        screen = object.__new__(FleetMemoryScreen)
        screen._rows = []
        table = MagicMock()
        screen.query_one = MagicMock(return_value=table)
        own, twin = _own(), _shared()
        app = _app([own, twin], memory_service=None)
        _bind_app(screen, app)
        screen._populate_table()
        assert [row["id"] for row in screen._rows] == [own["id"]]

    def test_scan_gets_the_folded_rows(self):
        screen = object.__new__(FleetMemoryScreen)
        screen._rows = []
        screen._scanning = False
        screen._set_progress = MagicMock()
        own, twin = _own(), _shared()
        scan = MagicMock()
        scan.eligible_instances.side_effect = lambda rows, stale_only: list(rows)
        app = _app(
            [own, twin], memory_service=MagicMock(), fleet_scan_service=scan,
            _fleet_manual_scan_in_progress=False,
        )
        app.start_fleet_manual_scan.return_value = True
        _bind_app(screen, app)
        screen._launch_bulk_scan(stale_only=False)
        assert app.start_fleet_manual_scan.call_args.args[0] == [own]


class TestChatScope:
    def test_prompt_naming_a_server_with_a_team_twin_gets_one_scope(self):
        from servonaut.services.ai_memory_injector import resolve_instance_scope

        own, twin = _own(), _shared()
        scopes = resolve_instance_scope(
            prompt="why is web-1 slow", candidate_instances=[twin, own],
        )
        assert [scope.id for scope in scopes] == [own["id"]]

    def test_chat_injection_scope_is_the_own_row(self):
        from servonaut.widgets.chat_panel import ChatPanel

        own, twin = _own(), _shared()
        panel = object.__new__(ChatPanel)
        memory = MagicMock()
        config = MagicMock()
        config.chat_inject_server_memory_decision = "allowed"
        config.chat_inject_server_memory = True
        app = _app([twin, own], memory_service=memory)
        app.config_manager.get.return_value = config
        _bind_app(panel, app)
        seen: List[Any] = []

        def build(**kwargs: Any):
            seen.extend(kwargs["instances"])
            return "<block>", MagicMock(as_log_kv=lambda: "")

        import servonaut.services.ai_memory_injector as injector

        original = injector.build_memory_context
        injector.build_memory_context = build
        try:
            body = panel._build_memory_injection(instance=twin, prompt="why is web-1 slow")
        finally:
            injector.build_memory_context = original
        assert body == "<block>"
        assert [scope.id for scope in seen] == [own["id"]]


class TestMergedFleet:
    def test_hidden_share_ids_are_left_out(self):
        import asyncio

        from servonaut.services.memory.fleet_service import FleetService

        memory = MagicMock()
        memory.list_all.return_value = [
            {"instance_id": "i-0abc0abc0abc0abc0", "name": "web-1", "provider": "aws", "modules": ["os"]},
            {"instance_id": "share-1", "name": "web-1", "provider": "team a", "modules": ["os"]},
        ]
        service = FleetService(api_client=MagicMock(), memory_service=memory)

        async def no_remote():
            raise RuntimeError("offline")

        service.get_remote_fleet = no_remote
        rows = asyncio.run(service.get_merged_fleet(hidden_ids={"share-1"}))
        assert [row["id"] for row in rows] == ["i-0abc0abc0abc0abc0"]


class TestSharedRowKeying:
    def test_memory_of_a_shared_row_is_never_filed_under_the_team_label(self):
        from servonaut.services.memory.provider import instance_provider

        row = _shared(instance_id=None, hostname="8.8.8.8")
        assert row["provider"] == "Team Team A"
        assert instance_provider(row) == "shared"

    def test_a_team_label_with_spaces_never_reaches_the_path(self, tmp_path):
        from servonaut.services.memory.provider import instance_provider
        from servonaut.services.memory.store import MemoryStore

        row = _shared(instance_id=None, hostname="8.8.8.8")
        store = MemoryStore(root=tmp_path)
        store.save_module(row["id"], "os", {"probed_at": "2026-01-01T00:00:00+00:00"}, instance_provider(row))
        assert [p.name for p in tmp_path.iterdir()] == ["shared"]


class TestWritesLandOnTheOwnRow:
    def test_the_memory_screen_of_a_team_copy_works_on_the_own_row(self):
        from servonaut.screens.memory import MemoryScreen

        own, twin = _own(), _shared()
        app = _app([own, twin])
        screen = MemoryScreen(twin)
        _bind_app(screen, app)
        assert screen._target["id"] == own["id"]

    def test_a_shared_only_row_keeps_its_own_target(self):
        from servonaut.screens.memory import MemoryScreen

        twin = _shared(instance_id=None, hostname="8.8.8.8")
        app = _app([_own(), twin])
        screen = MemoryScreen(twin)
        _bind_app(screen, app)
        assert screen._target["id"] == twin["id"]
