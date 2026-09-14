"""Real-loopback tests for the bounded authenticated relay handover protocol."""
from __future__ import annotations

import asyncio
import json
import math
import os
import stat
import subprocess
import sys

import pytest

from servonaut.services import relay_control
from servonaut.services.relay_control import (
    CONTROL_PROTOCOL_VERSION,
    CONTROL_TIMEOUT_ENV,
    ControlRecord,
    LocalControlServer,
    request_relay_release,
)
from servonaut.services.relay_lock import RelayLock

_VALID_TOKEN = "a" * 43


def _run(coroutine):
    return asyncio.run(coroutine)


async def _request(port: int, payload: bytes) -> dict[str, object]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(payload)
        await writer.drain()
        return json.loads((await reader.readuntil(b"\n")).decode("utf-8"))
    finally:
        writer.close()
        await writer.wait_closed()


def test_authenticated_request_releases_lock_after_callback(tmp_path):
    record_path = tmp_path / "relay-control.json"
    lock_path = tmp_path / "relay.lock"
    lock = RelayLock(mode="tui", path=lock_path).acquire()
    callback_observations: list[bool] = []

    async def release() -> None:
        lock.release()
        callback_observations.append(lock.is_held)

    async def scenario():
        server = LocalControlServer(record_path, lock_path=lock_path)
        record = await server.start(release)
        response = await request_relay_release(record_path, lock_path)
        assert response.ok is True
        assert response.released is True
        for _ in range(20):
            if not record_path.exists():
                break
            await asyncio.sleep(0.01)
        assert not record_path.exists()
        assert server.is_running is False
        assert record.port > 0
        await server.close()

    _run(scenario())
    assert callback_observations == [False]
    assert lock.is_held is False


def test_close_waits_for_pending_bind_and_removes_published_record(tmp_path, monkeypatch):
    record_path = tmp_path / "relay-control.json"
    server = LocalControlServer(record_path)
    bind_entered = asyncio.Event()
    permit_bind = asyncio.Event()
    original_start_server = relay_control.asyncio.start_server

    async def delayed_start_server(*args, **kwargs):
        bind_entered.set()
        await permit_bind.wait()
        return await original_start_server(*args, **kwargs)

    async def release() -> None:
        return None

    monkeypatch.setattr(relay_control.asyncio, "start_server", delayed_start_server)

    async def scenario():
        start_task = asyncio.create_task(server.start(release))
        await asyncio.wait_for(bind_entered.wait(), timeout=0.2)
        close_task = asyncio.create_task(server.close())
        await asyncio.sleep(0)
        assert close_task.done() is False

        permit_bind.set()
        record = await start_task
        await close_task

        assert server.is_running is False
        assert not record_path.exists()
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", record.port)

        replacement = LocalControlServer(record_path)
        try:
            next_record = await replacement.start(release)
            assert next_record.port > 0
            assert record_path.exists()
        finally:
            await replacement.close()

    _run(scenario())


def test_cancelled_close_cleans_partial_client_and_all_owned_state(tmp_path):
    record_path = tmp_path / "relay-control.json"
    server = LocalControlServer(record_path)
    close_lock_held = asyncio.Event()
    permit_close = asyncio.Event()

    async def release() -> None:
        return None

    async def hold_close_lock() -> None:
        async with server._close_lock:
            close_lock_held.set()
            await permit_close.wait()

    async def scenario():
        record = await server.start(release)
        reader, writer = await asyncio.open_connection("127.0.0.1", record.port)
        try:
            writer.write(b'{"protocol_version":1')
            await writer.drain()

            holder = asyncio.create_task(hold_close_lock())
            await asyncio.wait_for(close_lock_held.wait(), timeout=0.2)
            close_task = asyncio.create_task(server.close())
            await asyncio.sleep(0)
            close_task.cancel()
            await asyncio.sleep(0)
            close_task.cancel()
            permit_close.set()
            with pytest.raises(asyncio.CancelledError):
                await close_task
            await holder

            assert server.is_running is False
            assert not record_path.exists()
            assert server._record is None
            assert server._release_callback is None
            assert server._release_started is False
            assert await asyncio.wait_for(reader.read(), timeout=0.2) == b""
            with pytest.raises(OSError):
                await asyncio.open_connection("127.0.0.1", record.port)

            replacement = LocalControlServer(record_path)
            try:
                next_record = await replacement.start(release)
                assert next_record.port > 0
            finally:
                await replacement.close()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    _run(scenario())


def test_completed_release_cleans_up_when_ack_drain_fails(tmp_path, monkeypatch):
    record_path = tmp_path / "relay-control.json"
    lock_path = tmp_path / "relay.lock"
    lock = RelayLock(mode="tui", path=lock_path).acquire()
    callbacks: list[str] = []

    async def release() -> None:
        lock.release()
        callbacks.append("released")

    async def fail_drain(
        _writer: asyncio.StreamWriter,
        _response: relay_control.ControlResponse,
    ) -> None:
        raise ConnectionResetError("peer reset")

    async def scenario():
        server = LocalControlServer(record_path, lock_path=lock_path)
        record = await server.start(release)
        old_port = record.port
        monkeypatch.setattr(server, "_write_response", fail_drain)
        reader, writer = await asyncio.open_connection("127.0.0.1", old_port)
        try:
            writer.write(
                json.dumps(
                    {
                        "protocol_version": CONTROL_PROTOCOL_VERSION,
                        "command": "release_relay",
                        "token": record.token,
                    }
                ).encode("utf-8")
                + b"\n"
            )
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), timeout=0.2) == b""
        finally:
            writer.close()
            await writer.wait_closed()

        for _ in range(20):
            if not server.is_running and not record_path.exists():
                break
            await asyncio.sleep(0.01)
        assert server.is_running is False
        assert not record_path.exists()
        assert lock.is_held is False
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", old_port)

        replacement_lock = RelayLock(mode="tui", path=lock_path).acquire()
        replacement = LocalControlServer(record_path, lock_path=lock_path)
        try:
            next_record = await replacement.start(lambda: None)
            assert next_record.port > 0
            assert record_path.exists()
        finally:
            await replacement.close()
            replacement_lock.release()

    _run(scenario())
    assert callbacks == ["released"]


def test_completed_release_cleans_up_when_ack_task_is_cancelled(tmp_path, monkeypatch):
    record_path = tmp_path / "relay-control.json"
    lock_path = tmp_path / "relay.lock"
    lock = RelayLock(mode="tui", path=lock_path).acquire()

    async def release() -> None:
        lock.release()

    async def cancel_during_ack(
        _writer: asyncio.StreamWriter,
        _response: relay_control.ControlResponse,
    ) -> None:
        task = asyncio.current_task()
        assert task is not None
        task.cancel()
        await asyncio.sleep(0)

    async def scenario():
        server = LocalControlServer(record_path, lock_path=lock_path)
        record = await server.start(release)
        old_port = record.port
        monkeypatch.setattr(server, "_write_response", cancel_during_ack)
        reader, writer = await asyncio.open_connection("127.0.0.1", old_port)
        try:
            writer.write(
                json.dumps(
                    {
                        "protocol_version": CONTROL_PROTOCOL_VERSION,
                        "command": "release_relay",
                        "token": record.token,
                    }
                ).encode("utf-8")
                + b"\n"
            )
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), timeout=0.2) == b""
        finally:
            writer.close()
            await writer.wait_closed()

        for _ in range(20):
            if not server.is_running and not record_path.exists():
                break
            await asyncio.sleep(0.01)
        assert server.is_running is False
        assert not record_path.exists()
        assert lock.is_held is False
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", old_port)
        await server.close()

    _run(scenario())


def test_real_loopback_peer_loses_ack_after_completed_release(tmp_path):
    record_path = tmp_path / "relay-control.json"
    lock_path = tmp_path / "relay.lock"
    lock = RelayLock(mode="tui", path=lock_path).acquire()
    release_entered = asyncio.Event()
    permit_release = asyncio.Event()

    async def release() -> None:
        lock.release()
        release_entered.set()
        await permit_release.wait()

    async def scenario():
        server = LocalControlServer(record_path, lock_path=lock_path)
        record = await server.start(release)
        old_port = record.port
        _reader, writer = await asyncio.open_connection("127.0.0.1", old_port)
        writer.write(
            json.dumps(
                {
                    "protocol_version": CONTROL_PROTOCOL_VERSION,
                    "command": "release_relay",
                    "token": record.token,
                }
            ).encode("utf-8")
            + b"\n"
        )
        await writer.drain()
        await asyncio.wait_for(release_entered.wait(), timeout=0.2)
        writer.transport.abort()
        await asyncio.sleep(0)
        permit_release.set()
        await asyncio.sleep(0.05)

        assert server.is_running is False
        assert not record_path.exists()
        assert lock.is_held is False
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", old_port)

        replacement_lock = RelayLock(mode="tui", path=lock_path).acquire()
        replacement = LocalControlServer(record_path, lock_path=lock_path)
        try:
            await replacement.start(lambda: None)
            assert record_path.exists()
        finally:
            await replacement.close()
            replacement_lock.release()

    _run(scenario())


def test_wrong_token_is_rejected_without_invoking_callback(tmp_path):
    record_path = tmp_path / "relay-control.json"
    calls: list[str] = []

    async def release() -> None:
        calls.append("release")

    async def scenario():
        server = LocalControlServer(record_path)
        record = await server.start(release)
        response = await _request(
            record.port,
            json.dumps(
                {
                    "protocol_version": CONTROL_PROTOCOL_VERSION,
                    "command": "release_relay",
                    "token": "wrong",
                }
            ).encode("utf-8")
            + b"\n",
        )
        assert response == {
            "ok": False,
            "released": False,
            "error": "Invalid control request.",
        }
        assert record_path.exists()
        await server.close()

    _run(scenario())
    assert calls == []


def test_non_ascii_token_is_rejected_and_connection_is_closed(tmp_path):
    record_path = tmp_path / "relay-control.json"
    calls: list[str] = []

    async def release() -> None:
        calls.append("release")

    async def scenario():
        server = LocalControlServer(record_path)
        record = await server.start(release)
        reader, writer = await asyncio.open_connection("127.0.0.1", record.port)
        try:
            writer.write(
                json.dumps(
                    {
                        "protocol_version": CONTROL_PROTOCOL_VERSION,
                        "command": "release_relay",
                        "token": "你好",
                    }
                ).encode("utf-8")
                + b"\n"
            )
            await writer.drain()
            response = json.loads((await reader.readuntil(b"\n")).decode("utf-8"))
            assert response["ok"] is False
            assert await asyncio.wait_for(reader.read(), timeout=0.2) == b""
        finally:
            writer.close()
            await server.close()

    _run(scenario())
    assert calls == []


def test_oversize_or_missing_newline_never_invokes_callback(tmp_path):
    record_path = tmp_path / "relay-control.json"
    calls: list[str] = []

    async def release() -> None:
        calls.append("release")

    async def scenario():
        server = LocalControlServer(record_path, timeout_seconds=0.05)
        record = await server.start(release)
        response = await _request(record.port, b"x" * 4097)
        assert response["ok"] is False
        await server.close()

    _run(scenario())
    assert calls == []


def test_request_rejects_stale_record_before_connecting(tmp_path):
    record_path = tmp_path / "relay-control.json"
    lock_path = tmp_path / "relay.lock"
    record_path.write_text(
        json.dumps(
            {
                "protocol_version": CONTROL_PROTOCOL_VERSION,
                "pid": os.getpid(),
                "port": 1,
                "token": _VALID_TOKEN,
            }
        )
    )

    response = _run(request_relay_release(record_path, lock_path, timeout_seconds=0.05))

    assert response.ok is False
    assert response.error == "TUI relay lock is not active."


def test_close_preserves_a_replacement_record(tmp_path):
    record_path = tmp_path / "relay-control.json"

    async def release() -> None:
        return None

    async def scenario():
        server = LocalControlServer(record_path)
        await server.start(release)
        replacement = {
            "protocol_version": CONTROL_PROTOCOL_VERSION,
            "pid": os.getpid() + 1,
            "port": 12345,
            "token": _VALID_TOKEN,
        }
        record_path.write_text(json.dumps(replacement))
        await server.close()
        assert json.loads(record_path.read_text()) == replacement

    _run(scenario())


def test_posix_record_is_private(tmp_path):
    if os.name == "nt":
        return
    record_path = tmp_path / "relay-control.json"

    async def release() -> None:
        return None

    async def scenario():
        server = LocalControlServer(record_path)
        await server.start(release)
        assert stat.S_IMODE(record_path.stat().st_mode) == 0o600
        await server.close()

    _run(scenario())


def test_startup_failure_removes_a_published_record(tmp_path, monkeypatch):
    record_path = tmp_path / "relay-control.json"
    original_write = relay_control._write_record

    def write_then_fail(path, record):
        original_write(path, record)
        raise OSError("simulated post-write failure")

    async def release() -> None:
        return None

    monkeypatch.setattr(relay_control, "_write_record", write_then_fail)

    async def scenario():
        server = LocalControlServer(record_path)
        try:
            await server.start(release)
        except OSError:
            pass
        else:
            raise AssertionError("start must fail")
        assert not record_path.exists()

    _run(scenario())


def test_windows_acl_failure_fails_closed(tmp_path, monkeypatch):
    record_path = tmp_path / "relay-control.json"
    record = ControlRecord(CONTROL_PROTOCOL_VERSION, os.getpid(), 12345, _VALID_TOKEN)
    monkeypatch.setattr(relay_control.sys, "platform", "win32")
    monkeypatch.setattr(relay_control, "_apply_windows_current_user_acl", lambda _: False)

    try:
        relay_control._write_record(record_path, record)
    except OSError:
        pass
    else:
        raise AssertionError("ACL failure must fail closed")
    assert not record_path.exists()


def test_windows_acl_is_applied_before_token_write(tmp_path, monkeypatch):
    record_path = tmp_path / "relay-control.json"
    record = ControlRecord(CONTROL_PROTOCOL_VERSION, os.getpid(), 12345, _VALID_TOKEN)
    acl_calls: list[bytes] = []
    monkeypatch.setattr(relay_control.sys, "platform", "win32")

    def reject_acl(path):
        acl_calls.append(path.read_bytes())
        return False

    monkeypatch.setattr(relay_control, "_apply_windows_current_user_acl", reject_acl)
    try:
        relay_control._write_record(record_path, record)
    except OSError:
        pass
    else:
        raise AssertionError("ACL failure must fail closed")
    assert acl_calls == [b""]
    assert not record_path.exists()


def test_windows_sid_and_acl_use_injected_absolute_system_helpers(monkeypatch, tmp_path):
    system_directory = tmp_path / "Windows" / "System32"
    system_directory.mkdir(parents=True)
    whoami = system_directory / "whoami.exe"
    icacls = system_directory / "icacls.exe"
    whoami.touch()
    icacls.touch()
    calls: list[list[str]] = []

    def run(argv, **_kwargs):
        calls.append(argv)
        if argv[0] == str(whoami):
            return subprocess.CompletedProcess(
                argv,
                0,
                stdout='"LOCAL\\user","S-1-5-21-1-2-3-4"\r\n',
            )
        return subprocess.CompletedProcess(argv, 0, stdout="")

    monkeypatch.setattr(relay_control.sys, "platform", "win32")
    monkeypatch.setattr(
        relay_control,
        "windows_system_directory",
        lambda: system_directory,
    )
    monkeypatch.setattr(relay_control.subprocess, "run", run)

    assert relay_control._windows_current_user_sid() == "S-1-5-21-1-2-3-4"
    assert relay_control._apply_windows_current_user_acl(tmp_path / "record") is True
    assert calls[0] == [str(whoami), "/user", "/fo", "csv", "/nh"]
    assert calls[1] == [str(whoami), "/user", "/fo", "csv", "/nh"]
    assert calls[2][0] == str(icacls)
    assert "*S-1-5-21-1-2-3-4:(F)" in calls[2]


def test_windows_acl_fails_closed_when_trusted_helpers_are_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr(relay_control.sys, "platform", "win32")
    monkeypatch.setattr(
        relay_control,
        "windows_system_directory",
        lambda: (_ for _ in ()).throw(OSError("unavailable")),
    )
    monkeypatch.setattr(
        relay_control.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("untrusted helper executed"),
    )

    assert relay_control._windows_current_user_sid() is None
    assert relay_control._apply_windows_current_user_acl(tmp_path / "record") is False


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows system helper discovery")
def test_windows_system_helper_ignores_hostile_cwd_and_path(monkeypatch, tmp_path):
    decoy_directory = tmp_path / "decoy"
    decoy_directory.mkdir()
    (decoy_directory / "whoami.exe").write_bytes(b"not a system helper")
    (decoy_directory / "icacls.exe").write_bytes(b"not a system helper")
    monkeypatch.chdir(decoy_directory)
    monkeypatch.setenv("PATH", str(decoy_directory))

    whoami = relay_control._windows_system_executable("whoami")
    icacls = relay_control._windows_system_executable("icacls")

    assert whoami is not None and whoami != decoy_directory / "whoami.exe"
    assert icacls is not None and icacls != decoy_directory / "icacls.exe"


def test_control_record_repr_redacts_token():
    assert _VALID_TOKEN not in repr(
        ControlRecord(CONTROL_PROTOCOL_VERSION, 1, 2, _VALID_TOKEN)
    )


def test_timeout_must_be_finite_and_positive(tmp_path):
    for value in (0, -1, math.inf, -math.inf, math.nan, True, "invalid"):
        try:
            LocalControlServer(tmp_path / "record", timeout_seconds=value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"timeout {value!r} must be rejected")

    async def invalid_request_timeout():
        for value in (math.inf, math.nan, True):
            try:
                await request_relay_release(
                    tmp_path / "record",
                    timeout_seconds=value,
                )
            except ValueError:
                continue
            raise AssertionError(f"timeout {value!r} must be rejected")

    _run(invalid_request_timeout())


def test_record_read_is_bounded(tmp_path):
    record_path = tmp_path / "relay-control.json"
    record_path.write_bytes(b"x" * (relay_control.MAX_CONTROL_MESSAGE_BYTES + 1))
    assert relay_control._read_record(record_path) is None


def test_nested_json_is_rejected_and_invalid_socket_request_closes(tmp_path):
    record_path = tmp_path / "relay-control.json"
    nested_payload = b"[" * 1500 + b"]" * 1500
    callbacks: list[str] = []

    async def release() -> None:
        callbacks.append("release")

    async def scenario():
        server = LocalControlServer(record_path)
        record = await server.start(release)
        response = await _request(record.port, nested_payload + b"\n")
        assert response["ok"] is False
        record_path.write_bytes(nested_payload)
        assert relay_control._read_record(record_path) is None
        assert relay_control._parse_response(nested_payload) == relay_control.ControlResponse(
            ok=False,
            released=False,
            error="Invalid control response.",
        )
        await server.close()

    _run(scenario())
    assert callbacks == []


def test_configured_timeout_uses_finite_environment_value(monkeypatch):
    monkeypatch.setenv(CONTROL_TIMEOUT_ENV, "3.5")
    assert relay_control.configured_control_timeout_seconds() == 3.5
    monkeypatch.setenv(CONTROL_TIMEOUT_ENV, "nan")
    assert (
        relay_control.configured_control_timeout_seconds()
        == relay_control._FALLBACK_CONTROL_TIMEOUT_SECONDS
    )


def test_untrusted_response_error_text_is_not_returned():
    response = relay_control._parse_response(
        b'{"ok":false,"released":false,"error":"untrusted diagnostic"}\n'
    )
    assert response.error == "Relay release was refused."


def test_close_terminates_a_pending_client_connection(tmp_path):
    record_path = tmp_path / "relay-control.json"

    async def release() -> None:
        return None

    async def scenario():
        server = LocalControlServer(record_path, timeout_seconds=5.0)
        record = await server.start(release)
        reader, writer = await asyncio.open_connection("127.0.0.1", record.port)
        try:
            writer.write(b'{"protocol_version":1')
            await writer.drain()
            await server.close()
            try:
                assert await asyncio.wait_for(reader.read(), timeout=0.2) == b""
            except ConnectionError:
                # A reset is also a completed close for a peer that had not
                # finished sending a valid request.
                pass
        finally:
            writer.close()

    _run(scenario())


def test_callback_cancellation_closes_the_client_and_leaves_server_clean(tmp_path):
    record_path = tmp_path / "relay-control.json"
    callbacks: list[str] = []

    async def cancel_release() -> None:
        callbacks.append("called")
        raise asyncio.CancelledError

    async def scenario():
        server = LocalControlServer(record_path)
        record = await server.start(cancel_release)
        reader, writer = await asyncio.open_connection("127.0.0.1", record.port)
        try:
            payload = json.dumps(
                {
                    "protocol_version": CONTROL_PROTOCOL_VERSION,
                    "command": "release_relay",
                    "token": record.token,
                }
            ).encode("utf-8") + b"\n"
            writer.write(payload)
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), timeout=0.2) == b""
            assert server.is_running is True
        finally:
            writer.close()
            await writer.wait_closed()
            await server.close()

    _run(scenario())
    assert callbacks == ["called"]
    assert not record_path.exists()
