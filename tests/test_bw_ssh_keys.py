"""Tests for servonaut.services.bw_ssh_keys.BwSshKeyProvider."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services.bw_errors import (
    BwCliMissingError,
    BwItemNotFoundError,
    BwItemShapeError,
    BwSessionMissingError,
)
from servonaut.services.bw_ssh_keys import BwSshKeyProvider
from servonaut.services.ssh_ref_resolver import ResolvedSshRef

KEY_BODY = "-----BEGIN OPENSSH PRIVATE KEY-----\ndummy-body\n-----END OPENSSH PRIVATE KEY-----\n"  # leak-guard:allow - synthetic key fixture
ITEM_ID = "33333333-3333-4333-8333-333333333333"
INSTANCE = {"id": "i-web1", "provider": "aws"}
CONN = {
    "host": "192.0.2.10", "username": "deploy", "port": 22,
    "key_path": "/home/user/.ssh/id", "proxy_args": [], "extra_options": {},
}


@pytest.fixture(autouse=True)
def redirect_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    return tmp_path


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _ref_service(ref_payload=None, rollup=None, rollup_error=None):
    svc = MagicMock()
    svc.get_personal_instance_ref = AsyncMock(return_value=ref_payload)
    if rollup_error is not None:
        svc.list_personal_instances = AsyncMock(side_effect=rollup_error)
    elif rollup is not None:
        svc.list_personal_instances = AsyncMock(return_value=rollup)
    else:
        del svc.list_personal_instances
    return svc


def _payload():
    return {
        "ssh_credential_provider": "bitwarden_pm",
        "ssh_credential_ref": {"item_id": ITEM_ID},
    }


def _make(ref_service=None, team_service=None, resolver=None, clock=None, session_getter=None):
    resolver = resolver or MagicMock(resolve_ssh_key=MagicMock(return_value=KEY_BODY))
    factory = MagicMock(return_value=resolver)
    provider = BwSshKeyProvider(
        ref_service=lambda: ref_service,
        team_service=lambda: team_service,
        ssh_service=MagicMock(),
        session_getter=session_getter,
        resolver_factory=factory,
        **({"clock": clock} if clock else {}),
    )
    return provider, factory, resolver


def _run(coro):
    return asyncio.run(coro)


class TestHappyPath:
    def test_personal_ref(self, redirect_home):
        getter = lambda: "tok"  # noqa: E731
        provider, factory, _ = _make(_ref_service(_payload()), session_getter=getter)
        result = _run(provider.apply(CONN, INSTANCE))
        path = Path(result["key_path"])
        assert path.is_file()
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.name.startswith("bw-")
        assert path.parent == redirect_home / ".servonaut" / "tmp"
        assert result["key_source"] == "bw_personal"
        assert result["bw_item_id"] == ITEM_ID
        assert {k: v for k, v in result.items() if k not in ("key_path", "key_source", "bw_item_id")} == {
            k: v for k, v in CONN.items() if k != "key_path"
        }
        factory.assert_called_once_with(session_getter=getter)

    def test_shared_team_ref(self):
        team = MagicMock()
        team.get_team_server_ssh_ref = AsyncMock(return_value=_payload())
        instance = {"id": "srv-1", "provider": "aws", "is_shared": True,
                    "team_slug": "acme", "shared_server_id": "srv-1"}
        fake_ref = ResolvedSshRef(source="team", item_id=ITEM_ID, team_slug="acme")
        provider, _, _ = _make(_ref_service(), team)
        with patch("servonaut.services.bw_ssh_keys.SshRefResolver") as cls:
            cls.return_value.resolve = AsyncMock(return_value=fake_ref)
            result = _run(provider.apply(CONN, instance))
        assert result["key_source"] == "bw_team"

    def test_no_ref(self):
        provider, factory, _ = _make(_ref_service(None))
        assert _run(provider.apply(CONN, INSTANCE)) is None
        factory.assert_not_called()

    def test_signed_out(self):
        provider, _, _ = _make(None, None)
        assert _run(provider.apply(CONN, INSTANCE)) is None

    def test_lookup_raising(self):
        svc = _ref_service()
        svc.get_personal_instance_ref = AsyncMock(side_effect=RuntimeError("boom"))
        provider, _, _ = _make(svc)
        assert _run(provider.apply(CONN, INSTANCE)) is None

    def test_same_item_one_resolver_call(self):
        provider, factory, resolver = _make(_ref_service(_payload()))
        a = _run(provider.apply(CONN, INSTANCE))
        b = _run(provider.apply(CONN, {"id": "i-web2", "provider": "aws"}))
        assert a["key_path"] == b["key_path"]
        assert resolver.resolve_ssh_key.call_count == 1

    def test_deleted_file_recreated(self):
        provider, _, resolver = _make(_ref_service(_payload()))
        first = _run(provider.apply(CONN, INSTANCE))["key_path"]
        Path(first).unlink()
        second = _run(provider.apply(CONN, INSTANCE))["key_path"]
        assert Path(second).is_file()
        assert resolver.resolve_ssh_key.call_count == 2


class TestRollupAndMemo:
    def test_absent_from_rollup_with_a_ref_gets_its_key(self):
        """The roll-up may leave out a freshly saved ref: the server is looked up anyway."""
        clock = _Clock()
        svc = _ref_service(_payload(), rollup=[{"provider": "aws", "instance_id": "other"}])
        provider, factory, _ = _make(svc, clock=clock)
        result = _run(provider.apply(CONN, INSTANCE))
        assert result["key_source"] == "bw_personal" and result["bw_item_id"] == ITEM_ID
        assert Path(result["key_path"]).is_file()
        clock.now += 59  # inside the ref TTL: remembered
        _run(provider.apply(CONN, INSTANCE))
        assert svc.get_personal_instance_ref.await_count == 1
        factory.assert_called()

    def test_absent_from_rollup_without_a_ref_is_looked_up_once(self):
        clock = _Clock()
        svc = _ref_service(None, rollup=[{"provider": "aws", "instance_id": "other"}])
        provider, factory, _ = _make(svc, clock=clock)
        assert _run(provider.apply(CONN, INSTANCE)) is None
        clock.now += 59
        assert _run(provider.apply(CONN, INSTANCE)) is None
        assert svc.get_personal_instance_ref.await_count == 1
        factory.assert_not_called()

    def test_absent_from_rollup_a_failed_lookup_leaves_the_conn(self):
        """No evidence of a ref: a failed lookup is not reported as BwRefLookupFailed."""
        svc = _ref_service(rollup=[{"provider": "aws", "instance_id": "other"}])
        svc.get_personal_instance_ref = AsyncMock(side_effect=RuntimeError("api down"))
        provider, _, _ = _make(svc)
        assert _run(provider.apply(CONN, INSTANCE)) is None
        svc.get_personal_instance_ref.assert_awaited_once()

    def test_rollup_hit_does_lookup(self):
        svc = _ref_service(_payload(), rollup=[{"provider": "aws", "instance_id": "i-web1"}])
        provider, _, _ = _make(svc)
        assert _run(provider.apply(CONN, INSTANCE)) is not None
        svc.get_personal_instance_ref.assert_awaited()

    def test_rollup_error_is_an_outage_with_no_per_server_lookups(self):
        svc = _ref_service(_payload(), rollup_error=RuntimeError("x"))
        provider, factory, _ = _make(svc)
        assert _run(provider.apply(CONN, INSTANCE)) is None
        svc.get_personal_instance_ref.assert_not_awaited()
        factory.assert_not_called()

    def test_memo_and_forget(self):
        svc = _ref_service(None)
        clock = _Clock()
        provider, _, _ = _make(svc, clock=clock)
        _run(provider.apply(CONN, INSTANCE))
        _run(provider.apply(CONN, INSTANCE))
        assert svc.get_personal_instance_ref.await_count == 1
        provider.forget_refs()
        _run(provider.apply(CONN, INSTANCE))
        assert svc.get_personal_instance_ref.await_count == 2

    def test_memo_expires(self):
        svc = _ref_service(None)
        clock = _Clock()
        provider, _, _ = _make(svc, clock=clock)
        _run(provider.apply(CONN, INSTANCE))
        clock.now += 1000
        _run(provider.apply(CONN, INSTANCE))
        assert svc.get_personal_instance_ref.await_count == 2


class TestUnavailable:
    @pytest.mark.parametrize("exc,code", [
        (BwCliMissingError("x"), "BwCliMissingError"),
        (BwSessionMissingError("x"), "BwSessionMissingError"),
        (BwItemNotFoundError("x"), "BwItemNotFoundError"),
        (BwItemShapeError("x"), "BwItemShapeError"),
        (RuntimeError("x"), "BwKeyUnreadable"),
    ])
    def test_resolver_failure(self, exc, code):
        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=exc))
        provider, _, _ = _make(_ref_service(_payload()), resolver=resolver)
        result = _run(provider.apply(CONN, INSTANCE))
        assert result == {**CONN, "bw_key_unavailable": code}
        _run(provider.apply(CONN, INSTANCE))
        assert resolver.resolve_ssh_key.call_count == 2

    def test_write_failure(self):
        provider, _, resolver = _make(_ref_service(_payload()))
        with patch("servonaut.services.bw_ssh_keys.persistent_bw_ssh_key",
                   side_effect=OSError("disk")):
            result = _run(provider.apply(CONN, INSTANCE))
            assert result == {**CONN, "bw_key_unavailable": "BwKeyUnreadable"}
            _run(provider.apply(CONN, INSTANCE))
        assert resolver.resolve_ssh_key.call_count == 2

    def test_log_has_type_only(self, caplog):
        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=BwSessionMissingError("secret-detail")))
        provider, _, _ = _make(_ref_service(_payload()), resolver=resolver)
        with caplog.at_level(logging.DEBUG):
            _run(provider.apply(CONN, INSTANCE))
        assert "secret-detail" not in caplog.text
        assert "dummy-body" not in caplog.text
        assert "BwSessionMissingError" in caplog.text


# ---------------------------------------------------------------------------
# Bounded key-file cache: forget_keys, TTL
# ---------------------------------------------------------------------------

def _instances(count):
    return [{"id": f"i-web{n}", "provider": "aws"} for n in range(1, count + 1)]


class TestKeyFileCache:
    def test_forget_keys_for_an_item_removes_the_file_and_reads_again(self):
        provider, _, resolver = _make(_ref_service(_payload()))
        first = _run(provider.apply(CONN, INSTANCE))["key_path"]
        provider.forget_keys(ITEM_ID)
        assert not Path(first).exists()
        second = _run(provider.apply(CONN, INSTANCE))["key_path"]
        assert Path(second).is_file()
        assert resolver.resolve_ssh_key.call_count == 2

    def test_forget_keys_for_another_item_keeps_the_file(self):
        provider, _, resolver = _make(_ref_service(_payload()))
        first = _run(provider.apply(CONN, INSTANCE))["key_path"]
        provider.forget_keys("55555555-5555-4555-8555-555555555555")
        assert Path(first).is_file()
        assert _run(provider.apply(CONN, INSTANCE))["key_path"] == first
        assert resolver.resolve_ssh_key.call_count == 1

    def test_forget_all_keys_overwrites_with_zeros_before_removing(self):
        provider, _, _ = _make(_ref_service(_payload()))
        path = _run(provider.apply(CONN, INSTANCE))["key_path"]
        with patch("servonaut.services.bw_ssh_keys.remove_bw_ssh_key") as remove:
            provider.forget_keys()
        # A file still there (the mock removed nothing) is retried at once.
        assert remove.call_args_list and {c.args[0] for c in remove.call_args_list} == {path}
        assert provider._keys == {}

    def test_forget_all_keys_removes_the_files(self):
        provider, _, _ = _make(_ref_service(_payload()))
        path = _run(provider.apply(CONN, INSTANCE))["key_path"]
        provider.forget_keys()
        assert not Path(path).exists()

    def test_forget_refs_with_the_edited_item_drops_its_key(self):
        provider, _, resolver = _make(_ref_service(_payload()))
        path = _run(provider.apply(CONN, INSTANCE))["key_path"]
        provider.forget_refs([ITEM_ID])
        assert not Path(path).exists()
        _run(provider.apply(CONN, INSTANCE))
        assert resolver.resolve_ssh_key.call_count == 2

    def _ttl_provider(self, resolver, clock, **kwargs):
        return BwSshKeyProvider(
            ref_service=lambda: _ref_service(_payload()), team_service=lambda: None,
            ssh_service=MagicMock(), resolver_factory=MagicMock(return_value=resolver),
            clock=clock, ref_ttl_seconds=10_000, key_ttl_seconds=30, **kwargs,
        )

    def test_an_unchanged_key_on_re_read_keeps_its_path_and_writes_no_file(self):
        clock = _Clock()
        resolver = MagicMock(resolve_ssh_key=MagicMock(return_value=KEY_BODY))
        provider = self._ttl_provider(resolver, clock)
        held = _run(provider.apply(CONN, INSTANCE))["key_path"]
        clock.now += 31
        with patch("servonaut.services.bw_ssh_keys.persistent_bw_ssh_key") as write:
            assert _run(provider.apply(CONN, INSTANCE))["key_path"] == held
        write.assert_not_called()
        assert resolver.resolve_ssh_key.call_count == 2
        clock.now += 29  # read time refreshed: not due yet
        _run(provider.apply(CONN, INSTANCE))
        assert resolver.resolve_ssh_key.call_count == 2

    def test_a_rotated_key_gets_a_new_path_and_the_old_one_goes_after_the_grace(self):
        clock = _Clock()
        rotated = KEY_BODY.replace("dummy-body", "rotated-body")
        # The rotated key stays rotated: the applies past its TTL read it again.
        # (An exhausted side_effect list would raise StopIteration in the worker
        # thread, which Python 3.10 cannot hand to the awaiting future: a hang.)
        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=[KEY_BODY, rotated, rotated, rotated]))
        provider = self._ttl_provider(resolver, clock, superseded_grace_seconds=100)
        old = _run(provider.apply(CONN, INSTANCE))["key_path"]
        clock.now += 31
        new = _run(provider.apply(CONN, INSTANCE))["key_path"]
        assert new != old
        assert Path(new).read_text() == rotated
        assert Path(old).read_text() == KEY_BODY  # untouched while it may be in use
        clock.now += 99
        _run(provider.apply(CONN, INSTANCE))
        assert Path(old).is_file()
        clock.now += 2
        _run(provider.apply(CONN, INSTANCE))
        assert not Path(old).exists() and Path(new).is_file()

    @pytest.mark.parametrize("exc", [
        BwSessionMissingError("locked"), BwCliMissingError("x"), OSError("io"), TimeoutError("slow"),
        BwItemShapeError("a crashed or garbled bw run"),
    ])
    def test_a_passing_re_read_failure_keeps_the_file_and_waits_a_ttl(self, exc):
        clock = _Clock()
        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=[KEY_BODY, exc]))
        provider = self._ttl_provider(resolver, clock)
        held = _run(provider.apply(CONN, INSTANCE))["key_path"]
        clock.now += 31
        for _ in range(5):  # five connections: one bw run, not one each
            result = _run(provider.apply(CONN, INSTANCE))
            assert result["key_path"] == held and "bw_key_unavailable" not in result
        assert resolver.resolve_ssh_key.call_count == 2
        assert Path(held).read_text() == KEY_BODY

    def test_a_shape_error_on_the_first_read_names_the_shape(self):
        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=BwItemShapeError("shape")))
        provider = self._ttl_provider(resolver, _Clock())
        result = _run(provider.apply(CONN, INSTANCE))
        assert result == {**CONN, "bw_key_unavailable": "BwItemShapeError"}

    @pytest.mark.parametrize("exc, code", [
        (BwItemNotFoundError("gone"), "BwItemNotFoundError"),
    ])
    def test_a_re_read_finding_the_item_gone_forgets_the_key(self, exc, code):
        clock = _Clock()
        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=[KEY_BODY, exc]))
        provider = self._ttl_provider(resolver, clock)
        held = _run(provider.apply(CONN, INSTANCE))["key_path"]
        clock.now += 31
        result = _run(provider.apply(CONN, INSTANCE))
        assert result == {**CONN, "bw_key_unavailable": code}
        assert not Path(held).exists()

    def test_no_existing_key_file_is_ever_opened_for_writing(self):
        """Rotation, refusals and re-reads only create new files."""
        import builtins

        clock = _Clock()
        rotated = KEY_BODY.replace("dummy-body", "rotated-body")
        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=[KEY_BODY, KEY_BODY, rotated, rotated]))
        provider = self._ttl_provider(resolver, clock)
        written = []
        real_open, real_os_open = builtins.open, os.open

        def spy_open(file, mode="r", *args, **kwargs):
            if any(flag in mode for flag in "wa+") and os.path.exists(file):
                written.append(file)
            return real_open(file, mode, *args, **kwargs)

        def spy_os_open(path, flags, *args, **kwargs):
            if flags & (os.O_WRONLY | os.O_RDWR) and os.path.exists(path):
                written.append(path)
            return real_os_open(path, flags, *args, **kwargs)

        with patch("builtins.open", spy_open), patch("os.open", spy_os_open):
            first = _run(provider.apply(CONN, INSTANCE))
            provider.key_refused(first)
            _run(provider.apply(CONN, INSTANCE))  # same key: kept
            clock.now += 31
            _run(provider.apply(CONN, INSTANCE))  # rotated: a new file
            second = _run(provider.apply(CONN, {"id": "i-web2", "provider": "aws"}))
            provider.key_refused(second)
            _run(provider.apply(CONN, INSTANCE))
        assert written == []

    def test_a_forget_during_the_read_is_honoured(self):
        holder = {}

        def read(_item_id):
            holder["provider"].forget_keys()  # signed out while bw ran
            return KEY_BODY

        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=read))
        provider, _, _ = _make(_ref_service(_payload()), resolver=resolver)
        holder["provider"] = provider
        assert _run(provider.apply(CONN, INSTANCE)) is None  # connect as before
        assert resolver.resolve_ssh_key.call_count == 1
        assert provider._keys == {}
        tmp = Path.home() / ".servonaut" / "tmp"
        assert not tmp.exists() or list(tmp.iterdir()) == []


# ---------------------------------------------------------------------------
# Single-flight: concurrent fleet callers share one roll-up and one key read
# ---------------------------------------------------------------------------

class TestSingleFlight:
    def test_concurrent_callers_share_one_rollup_and_one_key_read(self):
        import time as _time

        rows = [{"provider": "aws", "instance_id": inst["id"]} for inst in _instances(5)]
        svc = _ref_service(_payload())

        async def slow_rollup():
            await asyncio.sleep(0.02)
            return rows

        svc.list_personal_instances = AsyncMock(side_effect=slow_rollup)

        def slow_read(_item_id):
            _time.sleep(0.05)
            return KEY_BODY

        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=slow_read))
        provider, _, _ = _make(svc, resolver=resolver)

        async def fleet():
            return await asyncio.gather(*(provider.apply(CONN, inst) for inst in _instances(5)))

        results = _run(fleet())
        assert svc.list_personal_instances.await_count == 1
        assert resolver.resolve_ssh_key.call_count == 1
        assert len({r["key_path"] for r in results}) == 1

    def test_a_shared_failure_is_not_remembered(self):
        import time as _time

        calls = {"n": 0}

        def read(_item_id):
            calls["n"] += 1
            _time.sleep(0.02)
            if calls["n"] == 1:
                raise BwSessionMissingError("locked")
            return KEY_BODY

        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=read))
        provider, _, _ = _make(_ref_service(_payload()), resolver=resolver)

        async def fleet():
            return await asyncio.gather(*(provider.apply(CONN, inst) for inst in _instances(3)))

        failed = _run(fleet())
        assert [r["bw_key_unavailable"] for r in failed] == ["BwSessionMissingError"] * 3
        assert resolver.resolve_ssh_key.call_count == 1
        unlocked = _run(provider.apply(CONN, INSTANCE))
        assert Path(unlocked["key_path"]).is_file()
        assert resolver.resolve_ssh_key.call_count == 2


# ---------------------------------------------------------------------------
# A refused login drops the key it used
# ---------------------------------------------------------------------------

class TestKeyRefused:
    def test_a_refusal_has_the_key_read_again_without_removing_it(self):
        provider, _, resolver = _make(_ref_service(_payload()))
        conn = _run(provider.apply(CONN, INSTANCE))
        provider.key_refused(conn)
        assert Path(conn["key_path"]).is_file()
        again = _run(provider.apply(CONN, INSTANCE))
        assert again["key_path"] == conn["key_path"]  # the same key: same file
        assert resolver.resolve_ssh_key.call_count == 2

    def test_a_refusal_on_one_server_leaves_the_shared_file_working_for_another(self):
        rotated = KEY_BODY.replace("dummy-body", "rotated-body")
        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=[KEY_BODY, rotated]))
        provider, _, _ = _make(_ref_service(_payload()), resolver=resolver)
        web1 = _run(provider.apply(CONN, INSTANCE))
        web2 = _run(provider.apply(CONN, {"id": "i-web2", "provider": "aws"}))
        assert web1["key_path"] == web2["key_path"]
        provider.key_refused(web1)
        _run(provider.apply(CONN, INSTANCE))  # web-1 reads a rotated key
        assert Path(web2["key_path"]).read_text() == KEY_BODY  # web-2's file still works

    def test_a_stale_refusal_changes_nothing(self):
        clock = _Clock()
        rotated = KEY_BODY.replace("dummy-body", "rotated-body")
        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=[KEY_BODY, rotated]))
        provider = BwSshKeyProvider(
            ref_service=lambda: _ref_service(_payload()), team_service=lambda: None,
            ssh_service=MagicMock(), resolver_factory=MagicMock(return_value=resolver),
            clock=clock, ref_ttl_seconds=10_000, key_ttl_seconds=30,
        )
        old = _run(provider.apply(CONN, INSTANCE))
        clock.now += 31
        new = _run(provider.apply(CONN, INSTANCE))
        provider.key_refused(old)  # a connection that still held the old file
        assert _run(provider.apply(CONN, INSTANCE))["key_path"] == new["key_path"]
        assert resolver.resolve_ssh_key.call_count == 2
        assert Path(old["key_path"]).is_file()

    @pytest.mark.parametrize("conn", [
        dict(CONN),
        {**CONN, "key_source": "local", "bw_item_id": ITEM_ID},
        {**CONN, "key_source": "bw_personal"},
    ])
    def test_a_conn_without_a_bitwarden_key_changes_nothing(self, conn):
        provider, _, resolver = _make(_ref_service(_payload()))
        path = _run(provider.apply(CONN, INSTANCE))["key_path"]
        provider.key_refused(conn)
        assert Path(path).is_file()
        _run(provider.apply(CONN, INSTANCE))
        assert resolver.resolve_ssh_key.call_count == 1


# ---------------------------------------------------------------------------
# A failed ref lookup is not "no ref"
# ---------------------------------------------------------------------------

class TestFailedRefLookup:
    def _failing(self, rollup):
        svc = _ref_service(rollup=rollup)
        svc.get_personal_instance_ref = AsyncMock(side_effect=RuntimeError("api down"))
        return svc

    def test_a_server_the_rollup_lists_gets_a_reason(self):
        svc = self._failing([{"provider": "aws", "instance_id": "i-web1"}])
        provider, factory, _ = _make(svc)
        result = _run(provider.apply(CONN, INSTANCE))
        assert result == {**CONN, "bw_key_unavailable": "BwRefLookupFailed"}
        factory.assert_not_called()

    def test_without_a_rollup_the_connection_is_unchanged(self):
        svc = _ref_service()
        svc.get_personal_instance_ref = AsyncMock(side_effect=RuntimeError("api down"))
        provider, _, _ = _make(svc)
        assert _run(provider.apply(CONN, INSTANCE)) is None

    def test_the_failure_is_retried_after_a_short_pause_not_the_full_ttl(self):
        clock = _Clock()
        svc = self._failing([{"provider": "aws", "instance_id": "i-web1"}])
        provider = BwSshKeyProvider(
            ref_service=lambda: svc, team_service=lambda: None, ssh_service=MagicMock(),
            resolver_factory=MagicMock(return_value=MagicMock(
                resolve_ssh_key=MagicMock(return_value=KEY_BODY),
            )),
            clock=clock, ref_ttl_seconds=10_000, failed_lookup_ttl_seconds=15,
        )
        _run(provider.apply(CONN, INSTANCE))
        _run(provider.apply(CONN, INSTANCE))
        assert svc.get_personal_instance_ref.await_count == 1
        clock.now += 16
        svc.get_personal_instance_ref = AsyncMock(return_value=_payload())
        provider._rollup = None  # the roll-up's own memo is not under test here
        result = _run(provider.apply(CONN, INSTANCE))
        assert result["key_source"] == "bw_personal"

    def test_the_reason_has_a_notice(self):
        from servonaut.services.bw_key_notice import bw_key_notice

        assert "could not be looked up" in bw_key_notice("BwRefLookupFailed")
        assert "could not be looked up" in bw_key_notice("BwRefLookupFailed", headless=True)


# ---------------------------------------------------------------------------
# A hanging or failing Servonaut API
# ---------------------------------------------------------------------------

class TestApiOutage:
    BOUND = 0.05

    def _hanging_service(self):
        svc = MagicMock()

        async def hang(*_args, **_kwargs):
            await asyncio.Event().wait()

        svc.list_personal_instances = AsyncMock(side_effect=hang)
        svc.get_personal_instance_ref = AsyncMock(side_effect=hang)
        return svc

    def _provider(self, svc, clock=None):
        return BwSshKeyProvider(
            ref_service=lambda: svc, team_service=lambda: None, ssh_service=MagicMock(),
            resolver_factory=MagicMock(), lookup_timeout_seconds=self.BOUND,
            **({"clock": clock} if clock else {}),
        )

    def test_a_hanging_api_costs_one_bounded_rollup_and_no_per_server_lookups(self):
        import time as _time

        svc = self._hanging_service()
        provider = self._provider(svc)

        async def fleet():
            results = []
            for inst in [{"id": f"i-web{n}", "provider": "aws"} for n in range(1, 6)]:
                start = _time.monotonic()
                results.append(await provider.apply(CONN, inst))
                assert _time.monotonic() - start < self.BOUND + 0.5
            return results

        assert _run(fleet()) == [None] * 5
        assert svc.list_personal_instances.await_count == 1
        svc.get_personal_instance_ref.assert_not_awaited()

    def test_the_outage_lasts_the_ref_ttl(self):
        clock = _Clock()
        svc = _ref_service(_payload(), rollup_error=RuntimeError("api down"))
        provider = BwSshKeyProvider(
            ref_service=lambda: svc, team_service=lambda: None, ssh_service=MagicMock(),
            resolver_factory=MagicMock(return_value=MagicMock(
                resolve_ssh_key=MagicMock(return_value=KEY_BODY),
            )),
            clock=clock, ref_ttl_seconds=60, failed_lookup_ttl_seconds=15,
        )
        assert _run(provider.apply(CONN, INSTANCE)) is None
        clock.now += 30  # past the failed-lookup memo, inside the ref TTL
        assert _run(provider.apply(CONN, INSTANCE)) is None
        assert svc.list_personal_instances.await_count == 1
        clock.now += 31
        svc.list_personal_instances = AsyncMock(return_value=[{"instance_id": "i-web1"}])
        assert _run(provider.apply(CONN, INSTANCE))["key_source"] == "bw_personal"

    def test_a_hanging_per_server_lookup_is_bounded(self):
        """Without a roll-up lister, per-server lookups still run, each bounded."""
        svc = self._hanging_service()
        del svc.list_personal_instances
        provider = self._provider(svc)
        assert _run(provider.apply(CONN, INSTANCE)) is None
        svc.get_personal_instance_ref.assert_awaited()

    def test_an_outage_leaves_other_servers_resolving_as_before(self, lease_like):
        """Vault, CA and local-key servers resolve exactly as without the provider."""
        from servonaut.services.ssh_credentials import resolve_with_vault

        svc = self._hanging_service()
        provider = self._provider(svc)
        conn, instance, runtime = lease_like

        async def both():
            plain = await resolve_with_vault(
                dict(conn), instance, vault_runtime=runtime, connection_service=None,
            )
            with_provider = await resolve_with_vault(
                dict(conn), instance, vault_runtime=runtime, connection_service=None,
                bw_keys=provider,
            )
            return plain, with_provider

        plain, with_provider = _run(both())
        assert plain == with_provider


    def test_a_timed_out_lookup_does_not_cancel_a_token_refresh(self, tmp_path, monkeypatch):
        """The lookup's 401 starts a refresh; the wait times out; the rotated pair is still stored."""
        import json as _json
        import time as _time

        import httpx

        from servonaut.services.api_client import APIClient
        from servonaut.services.auth_service import AuthService
        from servonaut.services.bw_ssh_config_service import BwSshConfigService

        auth_file = tmp_path / "auth.json"
        auth_file.write_text(_json.dumps({
            "access_token": "test-access-0", "refresh_token": "test-refresh-0",
            "expires_at": _time.time() - 1, "plan": "solo", "entitlements": {},
            "entitlements_fetched_at": 0,
        }))
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        auth = AuthService()
        server = {"valid": "test-refresh-0", "count": 0}

        class _Resp:
            def __init__(self, status_code, payload):
                self.status_code, self._payload = status_code, payload
                self.headers, self.text = {}, _json.dumps(payload)

            def json(self):
                return self._payload

        async def post_refresh(_url, refresh_token):
            if refresh_token != server["valid"]:
                return _Resp(400, {"error": {"code": "invalid_grant", "message": "revoked"}})
            server["count"] += 1
            server["valid"] = f"test-refresh-{server['count']}"
            await asyncio.sleep(0.3)  # rotated at once, answered slowly
            return _Resp(200, {
                "access_token": f"test-access-{server['count']}",
                "refresh_token": server["valid"], "expires_in": 3600,
            })

        monkeypatch.setattr(AuthService, "_post_refresh", staticmethod(post_refresh))

        def handler(request: httpx.Request) -> httpx.Response:
            if request.headers.get("Authorization") == "Bearer test-access-1":
                return httpx.Response(200, json={"instances": []})
            return httpx.Response(401, json={"error": {"code": "unauthorized", "message": "expired"}})

        api = APIClient(auth)
        api.transport = httpx.MockTransport(handler)
        refs = BwSshConfigService(api, refs_cache_path=tmp_path / "refs.json")
        provider = BwSshKeyProvider(
            ref_service=lambda: refs, team_service=lambda: None, ssh_service=MagicMock(),
            lookup_timeout_seconds=0.1,
        )

        async def go():
            result = await provider.apply(CONN, {"id": "i-web1", "provider": "aws"})
            await asyncio.sleep(0.5)  # the refresh started by the lookup finishes
            held = auth._token.refresh_token
            return result, held, await auth.refresh_token()

        result, held, ok = _run(go())
        assert result is None  # the outage: connect as before
        assert held == "test-refresh-1"  # the rotated pair was stored
        assert ok is True and not auth._refresh_grant_revoked and auth.is_authenticated


@pytest.fixture(params=["local_key", "vault", "ca"])
def lease_like(request, tmp_path):
    """(conn, instance, vault runtime) for one connection type."""
    conn = dict(CONN)
    instance = {"id": "custom-web-1", "name": "web-1", "is_custom": True, "provider": "custom"}
    if request.param == "local_key":
        return conn, instance, None
    agent = tmp_path / "agent.sock"
    agent.touch()
    lease = SimpleNamespace(
        source="vault", identity_agent=str(agent), identity_file=str(tmp_path / "key.pub"),
        certificate_path=str(tmp_path / "cert.pub") if request.param == "ca" else None,
        known_hosts_path=str(tmp_path / "known_hosts"), login_user="deploy",
        target_host="192.0.2.10", target_port=22,
    )
    runtime = MagicMock()
    runtime.agent_key_ttl_seconds = 3600
    runtime.resolve_ssh = AsyncMock(return_value=lease)
    return conn, instance, runtime


# ---------------------------------------------------------------------------
# forget_refs invalidates lookups in flight
# ---------------------------------------------------------------------------

class TestForgetRefsInFlight:
    def test_a_lookup_in_flight_does_not_store_its_answer_after_forget_refs(self):
        svc = _ref_service(None)
        provider, _, _ = _make(svc)
        answers = iter([_payload(), None])  # crossed: a stale ref; looked up again: none

        async def lookup_then_forget(*_args):
            if svc.get_personal_instance_ref.await_count == 1:
                provider.forget_refs()
            return next(answers)

        svc.get_personal_instance_ref = AsyncMock(side_effect=lookup_then_forget)
        assert _run(provider.apply(CONN, INSTANCE)) is None
        assert svc.get_personal_instance_ref.await_count == 2
        assert [value for _, value in provider._ref_memo.values()] == [None]

    def test_a_rollup_read_in_flight_does_not_store_its_answer_after_forget_refs(self):
        holder = {}
        svc = _ref_service(_payload())

        async def rollup_then_forget():
            if svc.list_personal_instances.await_count == 1:
                holder["provider"].forget_refs()
                return [{"provider": "aws", "instance_id": "stale"}]
            return [{"provider": "aws", "instance_id": "fresh"}]

        svc.list_personal_instances = AsyncMock(side_effect=rollup_then_forget)
        provider, _, _ = _make(svc)
        holder["provider"] = provider
        _run(provider.apply(CONN, INSTANCE))
        assert svc.list_personal_instances.await_count == 2
        assert provider._rollup[1] == frozenset({"fresh"})  # the crossed answer was not kept


# ---------------------------------------------------------------------------
# Races with forget_refs / forget_keys, cancelled cleanup, failed removals
# ---------------------------------------------------------------------------

class TestRacesAndCleanup:
    def test_a_ref_lookup_crossing_forget_refs_is_looked_up_again(self):
        """The ref was removed in the editor while its lookup was in flight."""
        svc = _ref_service(rollup=[{"provider": "aws", "instance_id": "i-web1"}])
        holder = {}

        async def removed_meanwhile(*_args):
            if not holder.get("forgot"):
                holder["forgot"] = True
                holder["provider"].forget_refs([ITEM_ID])
                return _payload()  # the answer from before the removal
            return None  # the ref is gone now

        svc.get_personal_instance_ref = AsyncMock(side_effect=removed_meanwhile)
        provider, factory, _ = _make(svc)
        holder["provider"] = provider
        assert _run(provider.apply(CONN, INSTANCE)) is None
        assert ITEM_ID not in provider._keys
        factory.assert_not_called()

    def test_a_forget_while_the_file_is_compared_never_returns_a_removed_path(self, monkeypatch):
        import threading

        from servonaut.services import bw_ssh_keys

        clock = _Clock()
        resolver = MagicMock(resolve_ssh_key=MagicMock(return_value=KEY_BODY))
        provider = BwSshKeyProvider(
            ref_service=lambda: _ref_service(_payload()), team_service=lambda: None,
            ssh_service=MagicMock(), resolver_factory=MagicMock(return_value=resolver),
            clock=clock, ref_ttl_seconds=10_000, key_ttl_seconds=30,
        )
        real_holds = bw_ssh_keys._holds_key

        async def go():
            loop = asyncio.get_running_loop()
            await provider.apply(CONN, INSTANCE)
            forgot = {}

            def holds(path, body):
                answer = real_holds(path, body)
                if not forgot:
                    forgot["done"] = True
                    done = threading.Event()
                    loop.call_soon_threadsafe(lambda: (provider.forget_keys(), done.set()))
                    done.wait(2)
                return answer

            monkeypatch.setattr(bw_ssh_keys, "_holds_key", holds)
            clock.now += 31
            return await provider.apply(CONN, INSTANCE)

        second = _run(go())
        assert second is None  # forgotten mid-read: connect as before
        assert provider._keys == {}
        tmp = Path.home() / ".servonaut" / "tmp"
        assert not tmp.exists() or list(tmp.iterdir()) == []

    def _rotations(self, clock, grace=100):
        bodies = [KEY_BODY.replace("dummy-body", f"body-{n}") for n in range(3)]
        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=bodies))
        provider = BwSshKeyProvider(
            ref_service=lambda: _ref_service(_payload()), team_service=lambda: None,
            ssh_service=MagicMock(), resolver_factory=MagicMock(return_value=resolver),
            clock=clock, ref_ttl_seconds=10_000, key_ttl_seconds=30,
            superseded_grace_seconds=grace,
        )
        return provider

    def test_a_cancelled_apply_during_grace_removal_leaves_the_files_for_forget_keys(self, monkeypatch):
        import threading

        from servonaut.services import bw_ssh_keys

        clock = _Clock()
        provider = self._rotations(clock)
        real_remove = bw_ssh_keys._remove_quietly
        started, release = threading.Event(), threading.Event()

        def slow_remove(path):
            started.set()
            release.wait(2)
            return real_remove(path)

        async def go():
            await provider.apply(CONN, INSTANCE)
            for _ in range(2):  # two rotations: two superseded files
                clock.now += 31
                await provider.apply(CONN, INSTANCE)
            superseded = [path for _, path, _ in provider._superseded]
            assert len(superseded) == 2
            clock.now += 200  # both past their grace
            monkeypatch.setattr(bw_ssh_keys, "_remove_quietly", slow_remove)
            task = asyncio.ensure_future(provider.apply(CONN, INSTANCE))
            await asyncio.to_thread(started.wait, 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            release.set()
            monkeypatch.setattr(bw_ssh_keys, "_remove_quietly", real_remove)
            await asyncio.sleep(0.05)
            provider.forget_keys()  # Bitwarden locked
            return superseded

        superseded = _run(go())
        assert [path for path in superseded if Path(path).exists()] == []

    def test_a_failed_removal_is_retried_on_the_next_apply(self, monkeypatch):
        from servonaut.utils import ephemeral_key

        provider, _, _ = _make(_ref_service(_payload()))
        path = _run(provider.apply(CONN, INSTANCE))["key_path"]
        real_unlink = ephemeral_key.os.unlink
        failures = {"left": 2}  # forget_keys tries, then retries once

        def unlink_fails_once(target, *args, **kwargs):
            if target == path and failures["left"]:
                failures["left"] -= 1
                raise PermissionError(13, "in use")
            return real_unlink(target, *args, **kwargs)

        monkeypatch.setattr(ephemeral_key.os, "unlink", unlink_fails_once)
        provider.forget_keys()  # Bitwarden locked; the file is in use once
        assert Path(path).exists()
        assert path in provider._pending_removal
        assert path in ephemeral_key._live_bw_key_paths  # the exit sweeper still has it
        _run(provider.apply(CONN, {"id": "i-other", "provider": "aws"}))
        assert not Path(path).exists()
        assert provider._pending_removal == []

    def test_a_failed_removal_is_retried_by_forget_keys(self, monkeypatch):
        from servonaut.utils import ephemeral_key

        provider, _, _ = _make(_ref_service(_payload()))
        path = _run(provider.apply(CONN, INSTANCE))["key_path"]
        real_unlink = ephemeral_key.os.unlink
        failures = {"left": 2}  # forget_keys tries, then retries once

        def unlink_fails_once(target, *args, **kwargs):
            if target == path and failures["left"]:
                failures["left"] -= 1
                raise PermissionError(13, "in use")
            return real_unlink(target, *args, **kwargs)

        monkeypatch.setattr(ephemeral_key.os, "unlink", unlink_fails_once)
        provider.forget_keys()
        provider.forget_keys()
        assert not Path(path).exists() and provider._pending_removal == []


class TestGenerationChecks:
    OLD = "33333333-3333-4333-8333-333333333333"
    NEW = "44444444-4444-4444-8444-444444444444"

    def test_a_ref_edit_during_the_key_read_does_not_apply_the_old_item(self):
        """forget_refs([OLD]) after the ref was set to NEW, 50 ms into apply."""
        import time as _time

        svc = _ref_service()
        current_item = {"id": self.OLD}

        async def ref(*_args):
            return {
                "ssh_credential_provider": "bitwarden_pm",
                "ssh_credential_ref": {"item_id": current_item["id"]},
            }

        svc.get_personal_instance_ref = AsyncMock(side_effect=ref)
        reads = []

        def read(item_id):
            reads.append(item_id)
            if item_id == self.OLD:
                _time.sleep(0.1)  # bw is slow; the edit lands meanwhile
            return KEY_BODY.replace("dummy-body", f"body-{item_id[:4]}")

        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=read))
        provider, _, _ = _make(svc, resolver=resolver)

        async def go():
            task = asyncio.ensure_future(provider.apply(CONN, INSTANCE))
            await asyncio.sleep(0.05)
            current_item["id"] = self.NEW  # the editor saved NEW ...
            provider.forget_refs([self.OLD])  # ... and forgets OLD
            return await task

        result = _run(go())
        assert result is None or result.get("bw_item_id") == self.NEW
        assert self.OLD not in provider._keys
        files = [p.read_text() for p in (Path.home() / ".servonaut" / "tmp").iterdir()]
        assert not any("body-1111" in body for body in files)

    def test_a_ref_edit_after_the_key_read_drops_the_old_item(self):
        """The edit lands between the key read and apply's answer."""
        svc = _ref_service()
        current_item = {"id": self.OLD}
        holder = {}

        async def ref(*_args):
            return {
                "ssh_credential_provider": "bitwarden_pm",
                "ssh_credential_ref": {"item_id": current_item["id"]},
            }

        svc.get_personal_instance_ref = AsyncMock(side_effect=ref)

        def read(item_id):
            if item_id == self.OLD:
                # Saved meanwhile, without naming OLD (a sign-in forget_refs()).
                current_item["id"] = self.NEW
                holder["loop"].call_soon_threadsafe(holder["provider"].forget_refs)
            return KEY_BODY.replace("dummy-body", f"body-{item_id[:4]}")

        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=read))
        provider, _, _ = _make(svc, resolver=resolver)
        holder["provider"] = provider

        async def go():
            holder["loop"] = asyncio.get_running_loop()
            return await provider.apply(CONN, INSTANCE)

        result = _run(go())
        assert result["bw_item_id"] == self.NEW
        assert self.OLD not in provider._keys
        files = [p.read_text() for p in (Path.home() / ".servonaut" / "tmp").iterdir()]
        assert not any("body-1111" in body for body in files)

    def test_a_forget_keys_during_a_gated_read_leaves_no_key_file(self):
        import threading

        gate, started = threading.Event(), threading.Event()

        def read(_item_id):
            started.set()
            gate.wait(2)
            return KEY_BODY

        resolver = MagicMock(resolve_ssh_key=MagicMock(side_effect=read))
        provider, _, _ = _make(_ref_service(_payload()), resolver=resolver)

        async def go():
            task = asyncio.ensure_future(provider.apply(CONN, INSTANCE))
            await asyncio.to_thread(started.wait, 2)
            provider.forget_keys()  # signed out while bw runs
            gate.set()
            return await task

        result = _run(go())
        assert result is None  # connect as before
        assert provider._keys == {}
        assert resolver.resolve_ssh_key.call_count == 1
        tmp = Path.home() / ".servonaut" / "tmp"
        assert not tmp.exists() or list(tmp.iterdir()) == []


# ---------------------------------------------------------------------------
# No Bitwarden refs at all: an empty roll-up and an empty local mirror
# ---------------------------------------------------------------------------

class TestNoRefsAnywhere:
    def _service(self, *, local_refs, rollup=()):
        svc = _ref_service(_payload(), rollup=list(rollup))
        if local_refs == "missing":
            del svc.has_local_refs
        elif local_refs == "raises":
            svc.has_local_refs = MagicMock(side_effect=OSError("io"))
        else:
            svc.has_local_refs = MagicMock(return_value=local_refs)
        return svc

    def test_an_empty_rollup_and_no_local_refs_skip_the_lookup(self):
        clock = _Clock()
        svc = self._service(local_refs=False)
        provider, factory, _ = _make(svc, clock=clock)
        for _ in range(3):
            assert _run(provider.apply(CONN, INSTANCE)) is None
            clock.now += 19  # all inside the 60 s ref TTL
        svc.get_personal_instance_ref.assert_not_awaited()
        assert svc.list_personal_instances.await_count == 1
        svc.has_local_refs.assert_called_once()
        factory.assert_not_called()

    def test_an_empty_rollup_with_local_refs_looks_up_and_applies_the_key(self):
        svc = self._service(local_refs=True)
        provider, _, _ = _make(svc)
        result = _run(provider.apply(CONN, INSTANCE))
        assert result["key_source"] == "bw_personal" and result["bw_item_id"] == ITEM_ID
        svc.get_personal_instance_ref.assert_awaited_once()

    def test_a_server_absent_from_a_non_empty_rollup_is_looked_up(self):
        svc = self._service(local_refs=False, rollup=[{"provider": "aws", "instance_id": "other"}])
        provider, _, _ = _make(svc)
        assert _run(provider.apply(CONN, INSTANCE))["key_source"] == "bw_personal"
        svc.has_local_refs.assert_not_called()  # only asked when the roll-up is empty

    @pytest.mark.parametrize("local_refs", ["missing", "raises"])
    def test_a_service_that_cannot_say_is_looked_up(self, local_refs):
        svc = self._service(local_refs=local_refs)
        provider, _, _ = _make(svc)
        assert _run(provider.apply(CONN, INSTANCE))["key_source"] == "bw_personal"
        svc.get_personal_instance_ref.assert_awaited_once()

    def test_a_ref_saved_here_is_used_after_forget_refs(self):
        svc = self._service(local_refs=False)
        provider, _, _ = _make(svc)
        assert _run(provider.apply(CONN, INSTANCE)) is None
        svc.has_local_refs.return_value = True  # the editor saved a ref ...
        provider.forget_refs()  # ... and forgets the remembered lookups
        assert _run(provider.apply(CONN, INSTANCE))["key_source"] == "bw_personal"

    def test_team_shared_servers_are_still_looked_up(self):
        team = MagicMock()
        team.get_team_server_ssh_ref = AsyncMock(return_value=_payload())
        svc = self._service(local_refs=False)
        instance = {"id": "srv-1", "provider": "aws", "is_shared": True,
                    "team_slug": "acme", "shared_server_id": "srv-1"}
        fake_ref = ResolvedSshRef(source="team", item_id=ITEM_ID, team_slug="acme")
        provider, _, _ = _make(svc, team)
        with patch("servonaut.services.bw_ssh_keys.SshRefResolver") as cls:
            cls.return_value.resolve = AsyncMock(return_value=fake_ref)
            assert _run(provider.apply(CONN, instance))["key_source"] == "bw_team"
        svc.list_personal_instances.assert_not_awaited()

    def test_an_outage_still_skips_lookups(self):
        svc = _ref_service(_payload(), rollup_error=RuntimeError("api down"))
        svc.has_local_refs = MagicMock(return_value=True)
        provider, _, _ = _make(svc)
        assert _run(provider.apply(CONN, INSTANCE)) is None
        svc.get_personal_instance_ref.assert_not_awaited()
