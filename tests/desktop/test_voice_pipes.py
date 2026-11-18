"""Pipe reader ownership at voice test fixture teardown."""

import threading

import pytest

from tests._async_bounds import STEP_TIMEOUT_SECONDS
from tests.desktop import _voice_pipes


def test_teardown_preserves_the_descriptor_until_its_reader_retires() -> None:
    pipes = _voice_pipes.PipeTransport()
    started = threading.Event()
    saw_eof = threading.Event()
    release = threading.Event()
    errors = []

    def read() -> None:
        assert pipes.parent_in.read(1) == b"x"
        started.set()
        assert pipes.parent_in.read(1) == b""
        saw_eof.set()
        assert release.wait(STEP_TIMEOUT_SECONDS)

    def close() -> None:
        try:
            pipes.close()
        except BaseException as error:
            errors.append(error)

    reader = threading.Thread(target=read)
    reader.start()
    pipes.worker_out.write(b"x")
    assert started.wait(STEP_TIMEOUT_SECONDS)
    closer = threading.Thread(target=close)
    closer.start()
    try:
        assert saw_eof.wait(STEP_TIMEOUT_SECONDS)
        assert pipes.worker_out.closed
        assert not pipes.parent_in.closed
        assert closer.is_alive()
    finally:
        release.set()
        reader.join(STEP_TIMEOUT_SECONDS)
        closer.join(STEP_TIMEOUT_SECONDS)
    assert not reader.is_alive() and not closer.is_alive()
    assert not errors
    assert pipes.parent_in.closed


def test_teardown_fails_when_a_response_reader_does_not_retire(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipes = _voice_pipes.PipeTransport()
    started = threading.Event()
    release = threading.Event()

    def read() -> None:
        assert pipes.parent_in.read(1) == b"x"
        started.set()
        pipes.parent_in.read(1)
        release.wait()

    reader = threading.Thread(target=read)
    reader.start()
    pipes.worker_out.write(b"x")
    assert started.wait(STEP_TIMEOUT_SECONDS)
    # Pin a short bound only for this deliberately non-retiring test reader.
    monkeypatch.setattr(_voice_pipes, "STEP_TIMEOUT_SECONDS", 0.05)
    try:
        with pytest.raises(AssertionError, match="reader did not retire"):
            pipes.close()
    finally:
        release.set()
        reader.join(STEP_TIMEOUT_SECONDS)
    assert not reader.is_alive()


def test_teardown_can_run_on_a_thread_that_read_the_pipes() -> None:
    pipes = _voice_pipes.PipeTransport()
    pipes.worker_out.write(b"x")
    assert pipes.parent_in.read(1) == b"x"
    pipes.parent_out.write(b"y")
    assert pipes.worker_in.read(1) == b"y"
    pipes.close()
    assert pipes.parent_in.closed and pipes.worker_in.closed


def test_retiring_reader_drains_queued_bytes_before_eof() -> None:
    pipes = _voice_pipes.PipeTransport()
    started = threading.Event()
    release = threading.Event()
    received = []

    def read() -> None:
        received.append(pipes.worker_in.read(1))
        started.set()
        assert release.wait(STEP_TIMEOUT_SECONDS)
        received.append(pipes.worker_in.read(1))
        received.append(pipes.worker_in.read(1))

    reader = threading.Thread(target=read)
    reader.start()
    pipes.parent_out.write(b"xy")
    assert started.wait(STEP_TIMEOUT_SECONDS)
    pipes.parent_out.close()
    pipes.worker_in.retire_readers()
    release.set()
    reader.join(STEP_TIMEOUT_SECONDS)
    try:
        assert not reader.is_alive()
        assert received == [b"x", b"y", b""]
    finally:
        pipes.close()
