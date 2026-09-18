"""Authenticated, bounded localhost handover for the TUI relay listener.

The control file is deliberately only a discovery record.  A requester also
probes the operating-system relay lock before connecting, which prevents stale
JSON from authorising a handover.
"""
from __future__ import annotations

import asyncio
import csv
import json
import math
import os
import re
import secrets
import subprocess
import sys
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from servonaut.services.process_control import windows_system_directory
from servonaut.services.relay_lock import (
    DEFAULT_LOCK_PATH,
    active_owner,
    is_pid_alive,
)

CONTROL_PROTOCOL_VERSION: Final = 1
MAX_CONTROL_MESSAGE_BYTES: Final = 4096
CONTROL_TIMEOUT_ENV: Final = "SERVONAUT_RELAY_CONTROL_TIMEOUT_SECONDS"
_FALLBACK_CONTROL_TIMEOUT_SECONDS: Final = 2.0
_RELEASE_COMMAND: Final = "release_relay"
_MIN_TOKEN_LENGTH: Final = 43
_MAX_TOKEN_LENGTH: Final = 128
_TOKEN_PATTERN: Final = re.compile(r"[A-Za-z0-9_-]+\Z")
_SID_PATTERN: Final = re.compile(r"S-\d+-\d+(?:-\d+)+\Z", re.IGNORECASE)


def _validate_timeout_seconds(value: object) -> float:
    """Accept only finite, strictly positive timeout values."""
    if isinstance(value, bool):
        raise ValueError(  # noqa: TRY004 - bool is a numerically invalid value
            "timeout_seconds must be a finite positive number"
        )
    try:
        timeout = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError("timeout_seconds must be a finite positive number") from error
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout_seconds must be a finite positive number")
    return timeout


def configured_control_timeout_seconds(value: object | None = None) -> float:
    """Return a finite environment-configured timeout or the safe fallback.

    ``value`` is an injection point for configuration loading and tests.  A
    missing or invalid environment value never disables the local boundary.
    """
    raw_value = os.environ.get(CONTROL_TIMEOUT_ENV) if value is None else value
    if raw_value is None:
        return _FALLBACK_CONTROL_TIMEOUT_SECONDS
    try:
        return _validate_timeout_seconds(raw_value)
    except ValueError:
        return _FALLBACK_CONTROL_TIMEOUT_SECONDS


DEFAULT_CONTROL_TIMEOUT_SECONDS: Final = configured_control_timeout_seconds()


@dataclass(frozen=True)
class ControlRecord:
    """Private discovery data, including a secret authentication token."""

    protocol_version: int
    pid: int
    port: int
    token: str = field(repr=False)


@dataclass(frozen=True)
class ControlResponse:
    """The bounded result returned by a control-server request."""

    ok: bool
    released: bool
    error: str | None = None


ReleaseCallback = Callable[[], Awaitable[None]]


def default_control_record_path() -> Path:
    """Resolve the runtime-owned default without freezing it at import time."""
    from servonaut.runtime import detect_runtime

    return detect_runtime().data_root / "relay-control.json"


class LocalControlServer:
    """A one-command loopback server owned by an in-process TUI relay."""

    def __init__(
        self,
        record_path: Path | None = None,
        *,
        lock_path: Path = DEFAULT_LOCK_PATH,
        timeout_seconds: float = DEFAULT_CONTROL_TIMEOUT_SECONDS,
    ) -> None:
        timeout_seconds = _validate_timeout_seconds(timeout_seconds)
        self._record_path = Path(record_path) if record_path else default_control_record_path()
        self._lock_path = Path(lock_path)
        self._timeout_seconds = timeout_seconds
        self._server: asyncio.AbstractServer | None = None
        self._record: ControlRecord | None = None
        self._release_callback: ReleaseCallback | None = None
        self._release_started = False
        self._is_closing = False
        self._close_lock = asyncio.Lock()
        self._client_writers: set[asyncio.StreamWriter] = set()

    @property
    def record_path(self) -> Path:
        """The on-disk discovery record for this server lifetime."""
        return self._record_path

    @property
    def is_running(self) -> bool:
        """Whether a listener is currently bound and its record published."""
        return self._server is not None and self._record is not None

    async def start(self, release_callback: ReleaseCallback) -> ControlRecord:
        """Bind, then atomically publish a new record for ``release_callback``."""
        if not callable(release_callback):
            raise TypeError("release_callback must be callable")
        # ``close()`` can be requested by app shutdown while an asynchronous
        # bind is pending. Serialize the whole bind-and-publish sequence so a
        # later close always observes and tears down the resource it owns.
        async with self._close_lock:
            if self.is_running:
                assert self._record is not None
                return self._record

            self._release_callback = release_callback
            self._release_started = False
            self._is_closing = False
            server = await asyncio.start_server(
                self._handle_client,
                host="127.0.0.1",
                port=0,
                limit=MAX_CONTROL_MESSAGE_BYTES,
            )
            record: ControlRecord | None = None
            try:
                sockets = server.sockets or []
                if len(sockets) != 1:
                    raise RuntimeError("Could not create a loopback control socket")
                port = sockets[0].getsockname()[1]
                record = ControlRecord(
                    protocol_version=CONTROL_PROTOCOL_VERSION,
                    pid=os.getpid(),
                    port=port,
                    token=secrets.token_urlsafe(32),
                )
                _write_record(self._record_path, record)
            except BaseException:
                server.close()
                await server.wait_closed()
                if record is not None:
                    _remove_record_if_owned(self._record_path, record)
                self._remove_owned_record()
                self._release_callback = None
                raise

            self._server = server
            self._record = record
            return record

    async def close(self) -> None:
        """Stop accepting connections and remove only this server's record.

        A caller may be cancelled during application teardown. Complete the
        owned-resource cleanup before propagating that cancellation so a
        partial unauthenticated peer cannot retain a live discovery record.
        """
        await _complete_owned_cleanup(self._close_owned_resources())

    async def _close_owned_resources(self) -> None:
        """Close this server once; safe to repeat after interrupted teardown."""
        async with self._close_lock:
            self._is_closing = True
            server = self._server
            self._server = None
            if server is not None:
                server.close()
            self._close_client_writers()
            self._remove_owned_record()
            self._record = None
            self._release_callback = None
            self._release_started = False
            if server is not None:
                await server.wait_closed()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._client_writers.add(writer)
        completed_release = False
        completed_release_cleanup = False
        try:
            response = await self._read_and_validate_request(reader)
            if self._is_closing:
                return
            if response is None:
                response = await self._release_relay()
                completed_release = response.ok
            if self._is_closing:
                return
            await self._write_response(writer, response)
            if completed_release:
                # The peer receives the acknowledgement before its discovery
                # record disappears. Waiting for ``server.wait_closed()``
                # from its own connection callback can deadlock, so this path
                # closes the accept socket without waiting on this writer.
                await self._close_after_ack(writer)
                completed_release_cleanup = True
        except asyncio.CancelledError:
            raise
        except (ConnectionError, OSError):
            # The peer may disappear while its bounded error response drains.
            pass
        finally:
            if completed_release and not completed_release_cleanup:
                # A completed handover must not leave a usable rendezvous
                # record when the acknowledgement cannot reach its peer. This
                # does not await the accept server from its own callback.
                await self._close_after_ack(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            self._client_writers.discard(writer)

    async def _close_after_ack(self, writer: asyncio.StreamWriter) -> None:
        """Close after flushing a successful response without awaiting this task."""
        async with self._close_lock:
            self._is_closing = True
            server = self._server
            self._server = None
            if server is not None:
                server.close()
            self._close_client_writers(exclude=writer)
            self._remove_owned_record()
            self._record = None
            self._release_callback = None
            self._release_started = False

    async def _read_and_validate_request(
        self,
        reader: asyncio.StreamReader,
    ) -> ControlResponse | None:
        try:
            payload = await asyncio.wait_for(
                reader.readuntil(b"\n"), timeout=self._timeout_seconds
            )
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            return _error_response("Invalid control request.")
        if len(payload) > MAX_CONTROL_MESSAGE_BYTES:
            return _error_response("Invalid control request.")
        try:
            request = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            return _error_response("Invalid control request.")
        if not isinstance(request, dict):
            return _error_response("Invalid control request.")
        record = self._record
        if record is None:
            return _error_response("Control server is unavailable.")
        version = request.get("protocol_version")
        token = request.get("token")
        if (
            not _is_plain_int(version)
            or version != CONTROL_PROTOCOL_VERSION
            or request.get("command") != _RELEASE_COMMAND
            or not _tokens_match(token, record.token)
        ):
            return _error_response("Invalid control request.")
        return None

    async def _release_relay(self) -> ControlResponse:
        if self._release_started:
            return _error_response("Relay release is already in progress.")
        callback = self._release_callback
        if callback is None:
            return _error_response("Control server is unavailable.")
        self._release_started = True
        try:
            await callback()
        except asyncio.CancelledError:
            self._release_started = False
            raise
        except Exception:  # noqa: BLE001 - callback boundary must not leak details
            self._release_started = False
            return _error_response("Relay could not be released.")
        return ControlResponse(ok=True, released=True)

    async def _write_response(
        self,
        writer: asyncio.StreamWriter,
        response: ControlResponse,
    ) -> None:
        payload = json.dumps(
            {"ok": response.ok, "released": response.released, "error": response.error},
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        # This is a programming invariant, not a peer-controlled length.
        if len(payload) > MAX_CONTROL_MESSAGE_BYTES:
            payload = b'{"ok":false,"released":false,"error":"Control error."}\n'
        writer.write(payload)
        await writer.drain()

    def _remove_owned_record(self) -> None:
        record = self._record
        if record is not None:
            _remove_record_if_owned(self._record_path, record)

    def _close_client_writers(
        self,
        *,
        exclude: asyncio.StreamWriter | None = None,
    ) -> None:
        """Close pending peers without awaiting the active callback task."""
        for client_writer in tuple(self._client_writers):
            if client_writer is not exclude:
                client_writer.close()


async def _complete_owned_cleanup(cleanup: Awaitable[None]) -> None:
    """Finish cleanup through caller cancellation, then propagate cancellation.

    Shielding keeps cancellation out of the resource-owning task. Repeated
    caller cancellation is remembered, not allowed to orphan that task, and
    is re-raised only after deterministic cleanup has finished.
    """
    cleanup_task = asyncio.ensure_future(cleanup)
    cancellation_requested = False
    while not cleanup_task.done():
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            cancellation_requested = True
    if cleanup_task.cancelled():
        raise asyncio.CancelledError
    cleanup_task.result()
    if cancellation_requested:
        raise asyncio.CancelledError


async def request_relay_release(
    record_path: Path | None = None,
    lock_path: Path = DEFAULT_LOCK_PATH,
    timeout_seconds: float = DEFAULT_CONTROL_TIMEOUT_SECONDS,
) -> ControlResponse:
    """Request a TUI relay release after validating its live lock owner.

    No listener is started here.  A stale or forged record is rejected before
    a connection attempt, and no response or exception includes the token.
    """
    timeout_seconds = _validate_timeout_seconds(timeout_seconds)
    path = Path(record_path) if record_path else default_control_record_path()
    record = _read_record(path)
    if record is None:
        return _error_response("No active TUI relay control record.")
    if not is_pid_alive(record.pid):
        return _error_response("TUI relay control record is stale.")
    owner = active_owner(Path(lock_path))
    if owner is None or owner.pid != record.pid or owner.mode != "tui":
        return _error_response("TUI relay lock is not active.")

    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                "127.0.0.1",
                record.port,
                limit=MAX_CONTROL_MESSAGE_BYTES,
            ),
            timeout=timeout_seconds,
        )
        request = json.dumps(
            {
                "protocol_version": CONTROL_PROTOCOL_VERSION,
                "command": _RELEASE_COMMAND,
                "token": record.token,
            },
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=timeout_seconds)
        payload = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=timeout_seconds)
        return _parse_response(payload)
    except (ConnectionError, OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
        return _error_response("TUI relay control is unavailable.")
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


def _write_record(path: Path, record: ControlRecord) -> None:
    """Atomically create the private discovery record, failing closed on ACLs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {
            "protocol_version": record.protocol_version,
            "pid": record.pid,
            "port": record.port,
            "token": record.token,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(prefix=".relay-control-", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        if sys.platform == "win32":
            # Do not place the token in the temporary file until its DACL has
            # been restricted to the current process identity.
            os.close(fd)
            fd = -1
            if not _apply_windows_current_user_acl(temporary_path):
                raise OSError("Could not restrict control-record permissions")
            fd = os.open(temporary_path, os.O_WRONLY | os.O_TRUNC)
        else:
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        if sys.platform == "win32" and not _apply_windows_current_user_acl(path):
            _remove_record_if_owned(path, record)
            raise OSError("Could not restrict control-record permissions")
        if sys.platform != "win32":
            os.chmod(path, 0o600)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _apply_windows_current_user_acl(path: Path) -> bool:
    """Restrict ``path`` to the native SID for this process's Windows user."""
    sid = _windows_current_user_sid()
    icacls = _windows_system_executable("icacls")
    if sid is None or icacls is None:
        return False
    try:
        result = subprocess.run(
            [
                str(icacls),
                str(path),
                "/inheritance:r",
                "/grant:r",
                f"*{sid}:(F)",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            check=False,
            timeout=DEFAULT_CONTROL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _windows_current_user_sid() -> str | None:
    """Read and validate the current process identity's SID via Windows."""
    whoami = _windows_system_executable("whoami")
    if whoami is None:
        return None
    try:
        result = subprocess.run(
            [str(whoami), "/user", "/fo", "csv", "/nh"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            shell=False,
            check=False,
            timeout=DEFAULT_CONTROL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        rows = list(csv.reader(result.stdout.splitlines()))
    except csv.Error:
        return None
    if len(rows) != 1 or len(rows[0]) != 2:
        return None
    sid = rows[0][1].strip()
    return sid if _SID_PATTERN.fullmatch(sid) else None


def _windows_system_executable(name: str) -> Path | None:
    """Return a strict-resolved Windows system executable without PATH lookup."""
    if sys.platform != "win32" or name not in {"whoami", "icacls"}:
        return None
    try:
        system_directory = windows_system_directory()
        helper = (system_directory / f"{name}.exe").resolve(strict=True)
    except (OSError, ValueError):
        return None
    try:
        helper.relative_to(system_directory)
    except ValueError:
        return None
    if helper.suffix.lower() != ".exe" or not helper.is_file():
        return None
    return helper


def _remove_record_if_owned(path: Path, owner: ControlRecord) -> None:
    """Remove a record only if its immutable ownership tuple still matches."""
    current = _read_record(path)
    if current is None:
        return
    if (
        current.pid != owner.pid
        or current.port != owner.port
        or not _tokens_match(current.token, owner.token)
    ):
        return
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError:
        return


def _read_record(path: Path) -> ControlRecord | None:
    try:
        with path.open("rb") as record_file:
            raw = record_file.read(MAX_CONTROL_MESSAGE_BYTES + 1)
        if len(raw) > MAX_CONTROL_MESSAGE_BYTES:
            return None
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(value, dict):
        return None
    version = value.get("protocol_version")
    pid = value.get("pid")
    port = value.get("port")
    token = value.get("token")
    if (
        not _is_plain_int(version)
        or version != CONTROL_PROTOCOL_VERSION
        or not _is_plain_int(pid)
        or pid <= 0
        or not _is_plain_int(port)
        or not 1 <= port <= 65535
        or not _is_control_token(token)
    ):
        return None
    return ControlRecord(version, pid, port, token)


def _parse_response(payload: bytes) -> ControlResponse:
    if len(payload) > MAX_CONTROL_MESSAGE_BYTES:
        return _error_response("Invalid control response.")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return _error_response("Invalid control response.")
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("ok"), bool)
        or not isinstance(value.get("released"), bool)
    ):
        return _error_response("Invalid control response.")
    if value["ok"] and value["released"] and value.get("error") is None:
        return ControlResponse(ok=True, released=True)
    if value["ok"] or value["released"]:
        return _error_response("Invalid control response.")
    # This service is localhost-facing but not a trusted text channel: a
    # replaced record could point at any local listener.  Never pass its
    # arbitrary error string through to the TUI or logs.
    return _error_response("Relay release was refused.")


def _error_response(error: str) -> ControlResponse:
    return ControlResponse(ok=False, released=False, error=error)


def _is_plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_control_token(value: object) -> bool:
    return (
        isinstance(value, str)
        and _MIN_TOKEN_LENGTH <= len(value) <= _MAX_TOKEN_LENGTH
        and value.isascii()
        and _TOKEN_PATTERN.fullmatch(value) is not None
    )


def _tokens_match(candidate: object, expected: object) -> bool:
    """Compare only shape-validated ASCII tokens without raising TypeError."""
    return (
        _is_control_token(candidate)
        and _is_control_token(expected)
        and secrets.compare_digest(candidate, expected)
    )
