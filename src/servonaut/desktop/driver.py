"""In-memory bounded Textual WebDriver adapter for the desktop shell.

Replaces sys.stdin and sys.stdout with bounded in-memory queues, ensuring
the process control protocol and parent watchdog streams remain completely
clean and dedicated to lifecycle management.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import queue
from collections.abc import Iterator
from threading import Event, Thread
from typing import Any, BinaryIO, Final, TextIO

from textual.app import App
from textual.drivers.web_driver import WebDriver

DEFAULT_QUEUE_CAPACITY: Final[int] = 1024
MAX_PACKET_BYTES: Final[int] = 4 * 1024 * 1024  # 4 MiB bounded packet


class DesktopDriverError(RuntimeError):
    """Base error for desktop driver adapter failures."""


class DesktopDriverBackpressureError(DesktopDriverError):
    """Raised when in-memory driver transport queues exceed capacity."""


class InMemoryInputReader:
    """Thread-safe input reader fed from an in-memory queue."""

    def __init__(self, q: queue.Queue[bytes | None], timeout: float = 0.05) -> None:
        self._queue = q
        self._timeout = timeout
        self._closed = False

    def close(self) -> None:
        """Close the reader and unblock any waiting consumer."""
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            self._queue.put_nowait(None)

    def __iter__(self) -> Iterator[bytes]:
        """Iterate over incoming bytes chunks.

        Yields empty bytes (b"") on timeout to allow XTermParser.tick() to fire.
        """
        while not self._closed:
            try:
                chunk = self._queue.get(timeout=self._timeout)
            except queue.Empty:
                yield b""
                continue
            if chunk is None or self._closed:
                break
            yield chunk


class DesktopDriverTransport:
    """Thread-safe in-memory bidirectional packet transport between host and driver."""

    def __init__(
        self,
        *,
        max_queue_size: int = DEFAULT_QUEUE_CAPACITY,
        max_packet_bytes: int = MAX_PACKET_BYTES,
    ) -> None:
        self.input_queue: queue.Queue[bytes | None] = queue.Queue(
            maxsize=max_queue_size
        )
        self.output_queue: asyncio.Queue[bytes | None] = asyncio.Queue(
            maxsize=max_queue_size
        )
        self.max_packet_bytes = max_packet_bytes
        self.ready_event = asyncio.Event()
        self._closed = False

    @property
    def is_closed(self) -> bool:
        return self._closed

    def feed_stdin(self, text: str) -> None:
        """Feed user input text as a 'D' packet into the driver."""
        payload = text.encode("utf-8")
        if len(payload) > self.max_packet_bytes:
            raise DesktopDriverBackpressureError("Input payload exceeds packet limit")
        self._put_input(b"D" + len(payload).to_bytes(4, "big") + payload)

    def feed_meta(self, meta: dict[str, object]) -> None:
        """Feed metadata dictionary as an 'M' packet into the driver."""
        payload = json.dumps(meta).encode("utf-8")
        if len(payload) > self.max_packet_bytes:
            raise DesktopDriverBackpressureError("Meta payload exceeds packet limit")
        self._put_input(b"M" + len(payload).to_bytes(4, "big") + payload)

    def feed_resize(self, width: int, height: int) -> None:
        """Feed a terminal resize metadata event."""
        self.feed_meta({"type": "resize", "width": width, "height": height})

    def feed_focus(self) -> None:
        """Feed a terminal focus metadata event."""
        self.feed_meta({"type": "focus"})

    def feed_blur(self) -> None:
        """Feed a terminal blur metadata event."""
        self.feed_meta({"type": "blur"})

    def feed_raw(self, packet: bytes) -> None:
        """Feed raw pre-framed bytes into the driver input queue."""
        if len(packet) > self.max_packet_bytes + 5:
            raise DesktopDriverBackpressureError("Raw packet exceeds limit")
        self._put_input(packet)

    def _put_input(self, packet: bytes) -> None:
        if self._closed:
            return
        try:
            self.input_queue.put_nowait(packet)
        except queue.Full:
            raise DesktopDriverBackpressureError(
                "Driver input queue backpressure exceeded"
            ) from None

    def close(self) -> None:
        """Close the transport and unblock reader/forwarder loops."""
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            self.input_queue.put_nowait(None)
        with contextlib.suppress(Exception):
            self.output_queue.put_nowait(None)


class DesktopDriver(WebDriver):
    """Textual WebDriver adapter using bounded in-memory queues instead of stdio."""

    def __init__(
        self,
        app: App[Any],
        *,
        transport: DesktopDriverTransport,
        debug: bool = False,
        mouse: bool = True,
        size: tuple[int, int] | None = None,
    ) -> None:
        # Initialize base Driver directly to bypass WebDriver's stdio registration
        super(WebDriver, self).__init__(app, debug=debug, mouse=mouse, size=size)
        self.transport = transport
        self.exit_event = Event()
        self._key_thread = Thread(
            target=self.run_input_thread,
            name="textual-desktop-input",
            daemon=True,
        )
        self._input_reader = InMemoryInputReader(transport.input_queue)
        self._write = self._write_to_transport
        self._deliveries: dict[str, BinaryIO | TextIO] = {}

    def _write_to_transport(self, data: bytes) -> None:
        """Write framed output to the in-memory output queue."""
        if data == b"__GANGLION__\n":
            # Signal readiness
            try:
                loop = self._loop
                if loop is not None and not loop.is_closed():
                    loop.call_soon_threadsafe(self.transport.ready_event.set)
                else:
                    self.transport.ready_event.set()
            except RuntimeError:
                self.transport.ready_event.set()
            return

        if len(data) > self.transport.max_packet_bytes + 5:
            raise DesktopDriverBackpressureError("Output packet exceeds limit")

        try:
            self.transport.output_queue.put_nowait(data)
        except asyncio.QueueFull as error:
            raise DesktopDriverBackpressureError(
                "Driver output queue backpressure exceeded"
            ) from error

    def stop_application_mode(self) -> None:
        """Stop application mode, signal exit, and release input reader."""
        self.exit_event.set()
        if hasattr(self, "_input_reader") and self._input_reader is not None:
            self._input_reader.close()
        self.write_meta({"type": "exit"})


def desktop_driver_class(
    transport: DesktopDriverTransport,
) -> type[WebDriver]:
    """Return a concrete WebDriver class bound to the given in-memory transport."""

    class BoundDesktopDriver(DesktopDriver):
        def __init__(self, app: App[Any], **kwargs: Any) -> None:
            super().__init__(app, transport=transport, **kwargs)

    return BoundDesktopDriver
