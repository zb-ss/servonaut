"""Pipe ownership and reader retirement for voice transport tests."""

from __future__ import annotations

from collections.abc import Callable, Iterable
import io
import os
import threading

from tests._async_bounds import STEP_TIMEOUT_SECONDS


def _join_threads(threads: Iterable[threading.Thread], message: str) -> None:
    current = threading.current_thread()
    for thread in threads:
        if thread is current:
            continue
        thread.join(timeout=STEP_TIMEOUT_SECONDS)
        assert not thread.is_alive(), message


class _ReadPipe(io.FileIO):
    def __init__(self, fd: int) -> None:
        super().__init__(fd, "rb")
        self._readers: set[threading.Thread] = set()
        self._reader_lock = threading.Lock()
        self._is_retiring = False

    def read(self, size: int = -1) -> bytes | None:
        reader = threading.current_thread()
        with self._reader_lock:
            if self._is_retiring and reader not in self._readers:
                return b""
            self._readers.add(reader)
        return super().read(size)

    def retire_readers(self) -> tuple[threading.Thread, ...]:
        with self._reader_lock:
            # A late reader must not start a call after the join snapshot.
            self._is_retiring = True
            return tuple(self._readers)


class PipeTransport:
    """Two unbuffered pipes that close only after their readers have stopped."""

    def __init__(self) -> None:
        p2w_r, p2w_w = os.pipe()
        w2p_r, w2p_w = os.pipe()
        self.parent_in = _ReadPipe(w2p_r)
        self.parent_out = os.fdopen(p2w_w, "wb", buffering=0)
        self.worker_in = _ReadPipe(p2w_r)
        self.worker_out = os.fdopen(w2p_w, "wb", buffering=0)
        self._emitters: list[threading.Thread] = []
        self._emitter_lock = threading.Lock()
        self._is_closing = False

    def start_event_emitter(self, emit: Callable[[], None]) -> None:
        with self._emitter_lock:
            assert not self._is_closing, "Voice transport is retiring"
            emitter = threading.Thread(target=emit, daemon=True)
            emitter.start()
            self._emitters.append(emitter)

    def close(self) -> None:
        with self._emitter_lock:
            self._is_closing = True
            emitters = tuple(self._emitters)
        _join_threads(emitters, "Voice event emitter did not retire")
        # EOF must retire both directions before either fd can be reused.
        self.worker_out.close()
        self.parent_out.close()
        try:
            readers = set(self.parent_in.retire_readers())
            readers.update(self.worker_in.retire_readers())
            _join_threads(readers, "Voice pipe reader did not retire")
        finally:
            for stream in (self.parent_in, self.worker_in):
                stream.close()
