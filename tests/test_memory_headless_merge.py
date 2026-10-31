"""The team-copy merge from the CLI and the MCP server (no sync service)."""
from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from servonaut.cli import memory as mem_mod
from servonaut.services.accounts.headless import CachedFleet
from servonaut.services.aws_service import AWSService
from servonaut.services.memory import headless_merge
from servonaut.services.memory.headless_merge import HeadlessTeamMerge, pass_key
from servonaut.services.memory.team_merge import SYNC_LOCKED, SYNC_OFF, sync_state
from tests.test_memory_cli import _fake_config, _make_args
from tests.test_memory_team_merge import (
    OWN_ID,
    SHARE_ID,
    _own,
    _put_copy,
    _service,
    _shared,
)
from tests.test_memory_team_merge_v3 import _marker

ROWS = [_own(), _shared()]


@pytest.fixture
def key_cache(tmp_path, monkeypatch):
    path = tmp_path / "keys" / "keys.json"
    monkeypatch.setattr("servonaut.services.memory.sync_service._KEY_CACHE_PATH", path)
    return path


class TestSyncStandIn:
    def test_no_keypair_cache_means_off(self, key_cache):
        assert headless_merge.headless_sync_state() is None
        assert sync_state(headless_merge.headless_sync_state()) == SYNC_OFF

    def test_a_keypair_cache_means_locked(self, key_cache):
        key_cache.parent.mkdir(parents=True)
        key_cache.write_text("{}")
        assert sync_state(headless_merge.headless_sync_state()) == SYNC_LOCKED

    def test_the_public_helper_reads_the_default_path(self, key_cache):
        from servonaut.services.memory.sync_service import local_keypair_cache_exists

        assert local_keypair_cache_exists() is False
        key_cache.parent.mkdir(parents=True)
        key_cache.write_text("{}")
        assert local_keypair_cache_exists() is True


class TestPassKey:
    def test_pairs_each_share_with_its_own_twin(self):
        assert pass_key(ROWS) == frozenset({(SHARE_ID, OWN_ID)})

    def test_a_member_row_pairs_with_nothing(self):
        member = [_shared(instance_id=None, hostname="5.6.7.8")]
        assert pass_key(member) == frozenset({(SHARE_ID, "")})

    def test_no_shared_rows_is_an_empty_key(self):
        assert pass_key([_own()]) == frozenset()


class TestRunner:
    def test_merges_a_copy_without_a_sync_service(self, tmp_path, key_cache):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        report = asyncio.run(HeadlessTeamMerge(service).run(ROWS))
        assert report.copies == 1
        assert service.read_annotations(OWN_ID, "aws") == "team note"
        assert not _marker(tmp_path).get("remote_pending")  # sync is off

    def test_locked_when_a_keypair_cache_exists(self, tmp_path, key_cache):
        key_cache.parent.mkdir(parents=True)
        key_cache.write_text("{}")
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        asyncio.run(HeadlessTeamMerge(service).run(ROWS))
        assert _marker(tmp_path)["remote_pending"] is True

    def test_runs_once_per_distinct_key(self, tmp_path, key_cache):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        runner = HeadlessTeamMerge(service)
        assert asyncio.run(runner.run(ROWS)) is not None
        service.write_annotations(OWN_ID, "", "aws")
        assert asyncio.run(runner.run(ROWS)) is None
        other = ROWS + [_shared(id="22222222-aaaa-bbbb-cccc-000000000002", instance_id="i-0def")]  # leak-guard:allow
        assert asyncio.run(runner.run(other)) is not None

    def test_no_shared_rows_runs_nothing(self, tmp_path, key_cache):
        assert asyncio.run(HeadlessTeamMerge(_service(tmp_path)).run([_own()])) is None

    def test_a_failure_is_logged_not_raised_and_not_repeated(self, tmp_path, key_cache, monkeypatch, caplog):
        calls = []

        async def boom(*args, **kwargs):
            calls.append(1)
            raise RuntimeError("secret detail")

        monkeypatch.setattr(headless_merge, "merge_team_copies", boom)
        runner = HeadlessTeamMerge(_service(tmp_path))
        with caplog.at_level(logging.WARNING):
            assert asyncio.run(runner.run(ROWS)) is None
            assert asyncio.run(runner.run(ROWS)) is None
        assert len(calls) == 1
        assert "secret detail" not in caplog.text and "RuntimeError" in caplog.text

    def test_a_skipped_pass_is_tried_again(self, tmp_path, key_cache):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        from servonaut.utils.file_lock import FileLock

        holder = FileLock(service._store.root / "team_merge.lock")
        assert holder.try_acquire()
        runner = HeadlessTeamMerge(service)
        try:
            assert asyncio.run(runner.run(ROWS)).skipped is True
        finally:
            holder.release()
        assert asyncio.run(runner.run(ROWS)).copies == 1

    def test_concurrent_callers_share_one_pass(self, tmp_path, key_cache):
        service = _service(tmp_path)
        _put_copy(service, notes="team note")
        runner = HeadlessTeamMerge(service)

        async def both():
            return await asyncio.gather(runner.run(ROWS), runner.run(ROWS))

        reports = asyncio.run(both())
        assert sorted(r is None for r in reports) == [False, True]


class TestCliTrigger:
    def _setup(self, tmp_path, monkeypatch, *, rows=True):
        service = _service(tmp_path / "mem")
        _put_copy(service, notes="team note")
        aws = MagicMock(spec=AWSService)
        aws.get_cached_instances.return_value = [_own()]
        custom = MagicMock()
        custom.list_as_instances.return_value = []
        fleet = CachedFleet(custom, aws=aws)
        if rows:
            service.set_connection_rows(lambda: ([ROWS[1]], list(ROWS)))
        monkeypatch.setattr(mem_mod, "_init_headless_services",
                            lambda: (_fake_config(), service, fleet))
        monkeypatch.setattr(mem_mod, "_init_headless_sync_services", lambda *a: (None, None))
        for name in ("build", "refresh", "show", "export", "annotate", "pin", "clear", "pull"):
            monkeypatch.setattr(mem_mod, f"_cmd_{name}" if name != "pull" else "_cmd_pull_annotations",
                                lambda *a, **k: 0)
        return service

    @pytest.mark.parametrize("command", ["build", "refresh", "show", "export", "annotate", "pin", "pull"])
    def test_these_subcommands_run_a_pass_first(self, tmp_path, monkeypatch, capsys, key_cache, command):
        service = self._setup(tmp_path, monkeypatch)
        rc = mem_mod.run_memory(_make_args(memory_command=command, instance="web-1"))
        assert rc == 0
        assert service.read_annotations(OWN_ID, "aws") == "team note"
        captured = capsys.readouterr()
        assert "Merged 1 team copy" in captured.err and captured.out == ""

    def test_build_all_runs_a_pass_first(self, tmp_path, monkeypatch, capsys, key_cache):
        service = self._setup(tmp_path, monkeypatch)
        monkeypatch.setattr(mem_mod, "_cmd_build_all", lambda *a, **k: 0)
        mem_mod.run_memory(_make_args(memory_command="build", all=True))
        assert service.read_annotations(OWN_ID, "aws") == "team note"

    def test_clear_runs_no_pass(self, tmp_path, monkeypatch, capsys, key_cache):
        service = self._setup(tmp_path, monkeypatch)
        mem_mod.run_memory(_make_args(memory_command="clear", instance="web-1"))
        assert service.read_annotations(OWN_ID, "aws") == "" and capsys.readouterr().err == ""

    def test_purge_runs_no_pass(self, tmp_path, monkeypatch, capsys, key_cache):
        service = self._setup(tmp_path, monkeypatch)
        monkeypatch.setattr(mem_mod, "_cmd_purge", lambda *a, **k: 0)
        mem_mod.run_memory(_make_args(memory_command="purge"))
        assert service.read_annotations(OWN_ID, "aws") == ""

    def test_signed_out_has_no_shared_rows_and_no_pass(self, tmp_path, monkeypatch, capsys, key_cache):
        service = self._setup(tmp_path, monkeypatch, rows=False)
        assert mem_mod.run_memory(_make_args(memory_command="show", instance="web-1")) == 0
        assert service.read_annotations(OWN_ID, "aws") == "" and capsys.readouterr().err == ""

    def test_a_failed_pass_never_fails_the_command(self, tmp_path, monkeypatch, capsys, key_cache):
        self._setup(tmp_path, monkeypatch)

        async def boom(*args, **kwargs):
            raise RuntimeError("nope")

        monkeypatch.setattr(headless_merge, "merge_team_copies", boom)
        assert mem_mod.run_memory(_make_args(memory_command="show", instance="web-1")) == 0
        assert capsys.readouterr().err == ""

    def test_a_pass_that_merged_nothing_prints_nothing(self, tmp_path, monkeypatch, capsys, key_cache):
        service = self._setup(tmp_path, monkeypatch)
        mem_mod.run_memory(_make_args(memory_command="show", instance="web-1"))
        capsys.readouterr()
        mem_mod.run_memory(_make_args(memory_command="show", instance="web-1"))
        assert capsys.readouterr().err == ""
