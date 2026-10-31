"""In-memory bounded Textual WebDriver adapter for the desktop shell.

Replaces sys.stdin and sys.stdout with bounded in-memory queues, ensuring
the process control protocol and parent watchdog streams remain completely
clean and dedicated to lifecycle management.

The child runs on the user's own machine, so links open in the system
browser from here rather than from the page, which the window would refuse.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import queue
import sys
import time
import urllib.parse
import webbrowser
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from threading import Event, Thread
from typing import Any, BinaryIO, Final, TextIO

from textual.app import App
from textual.drivers.web_driver import WebDriver

from servonaut.utils import platform_utils

logger = logging.getLogger(__name__)

DEFAULT_QUEUE_CAPACITY: Final[int] = 1024
MAX_PACKET_BYTES: Final[int] = 4 * 1024 * 1024  # 4 MiB bounded packet

# Web pages only: a link drawn from server or model text must not start
# whatever program claims another scheme.
OPENABLE_URL_SCHEMES: Final = frozenset({"http", "https"})
# One click can reach the driver twice: a Markdown link the app handles is
# also an address the terminal finds in the text. A debounce, not a tunable.
REPEAT_OPEN_SECONDS: Final = 1.0
# The longest scheme the log repeats when it refuses a link.
_LOGGED_SCHEME_CHARS: Final = 16


def is_openable_url(url: object) -> bool:
    """Whether *url* is a web address the desktop opens in the browser."""
    if not isinstance(url, str) or not url or url != url.strip():
        return False
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return parsed.scheme.lower() in OPENABLE_URL_SCHEMES and bool(parsed.netloc)


@dataclass(frozen=True)
class _OpenedLink:
    url: str
    at: float
    from_page: bool


def window_owns_clipboard(platform_name: str | None = None) -> bool:
    """Whether copies go through the window instead of the OS tools.

    On Linux the window's web view writes the clipboard itself, while the OS
    tools cannot: GNOME gives background programs no way to set it, so
    wl-copy waits for focus this window holds. pbcopy (macOS) and clip
    (Windows) work from any process; the macOS web view would refuse a copy
    that no click started.
    """
    return (platform_name or sys.platform).startswith("linux")


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
        self._page_link_opener: Callable[[str], None] | None = None

    @property
    def is_closed(self) -> bool:
        return self._closed

    def set_page_link_opener(self, opener: Callable[[str], None] | None) -> None:
        """Name who opens the links the page reports (the running driver)."""
        self._page_link_opener = opener

    def open_page_link(self, url: str) -> None:
        """Open a link the user clicked in the page's terminal, if a driver runs."""
        opener = self._page_link_opener
        if opener is not None and not self._closed:
            opener(url)

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
        self._last_opened: _OpenedLink | None = None
        self._clock: Callable[[], float] = time.monotonic
        self._clipboard_registered = False

    def write(self, data: str) -> None:
        """Write terminal output, split into packets the transport accepts.

        A large copy (OSC 52 carries the whole text) would otherwise exceed
        the packet limit. The page decodes the byte stream incrementally, so
        a split inside a character or an escape sequence is harmless.
        """
        data_bytes = data.encode("utf-8")
        limit = self.transport.max_packet_bytes
        for start in range(0, len(data_bytes), limit):
            chunk = data_bytes[start : start + limit]
            self._write(b"D" + len(chunk).to_bytes(4, "big") + chunk)

    def open_url(self, url: str, new_tab: bool = True) -> None:
        """Open a web address the app asks for in the system browser.

        Upstream hands the address to the page, but a web view does not open
        windows for a script, so the desktop opens it here.
        """
        self._open_link(url, new_tab=new_tab, from_page=False)

    def _open_page_link(self, url: str) -> None:
        """Open a link the user clicked in the page's terminal."""
        self._open_link(url, new_tab=True, from_page=True)

    def _open_link(self, url: str, *, new_tab: bool, from_page: bool) -> None:
        """Open *url* in the background (finding the browser takes a moment).

        Within ``REPEAT_OPEN_SECONDS`` the same address again is the same
        click, and so is any second link when one of the two came from the
        page: one click on a link the app draws reaches the driver from the
        app and from the terminal, perhaps as two spellings of the address.
        """
        if not is_openable_url(url):
            # The address may carry a token: log its scheme only.
            logger.warning("Not opening a link with scheme %r", _scheme_of(url))
            self._app.notify(
                "Only web links (http/https) can be opened.",
                severity="warning",
                markup=False,
            )
            return
        now = self._clock()
        last = self._last_opened
        if (
            last is not None
            and now - last.at < REPEAT_OPEN_SECONDS
            and (last.url == url or from_page or last.from_page)
        ):
            return
        self._last_opened = _OpenedLink(url, now, from_page)
        Thread(
            target=_open_in_browser,
            args=(url, 2 if new_tab else 0),
            name="desktop-open-url",
            daemon=True,
        ).start()

    def start_application_mode(self) -> None:
        """Start application mode; take the page's links; on Linux, copies."""
        super().start_application_mode()
        self.transport.set_page_link_opener(self._open_page_link)
        if window_owns_clipboard():
            platform_utils.set_clipboard_writer(self._copy_in_window)
            self._clipboard_registered = True

    def _copy_in_window(self, text: str) -> bool:
        """Hand *text* to the page (OSC 52), which writes the clipboard.

        Safe from any thread: the copy runs on the app's loop. False once the
        session is over, so callers can say the copy did not happen.
        """
        if self.transport.is_closed or self.exit_event.is_set():
            return False
        try:
            self._loop.call_soon_threadsafe(self._app.copy_to_clipboard, text)
        except RuntimeError:  # the loop has closed
            return False
        return True

    def _release_clipboard(self) -> None:
        if not self._clipboard_registered:
            return
        self._clipboard_registered = False
        if platform_utils.clipboard_writer() == self._copy_in_window:
            platform_utils.set_clipboard_writer(None)

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
        self.transport.set_page_link_opener(None)
        self._release_clipboard()
        self.exit_event.set()
        if hasattr(self, "_input_reader") and self._input_reader is not None:
            self._input_reader.close()
        self.write_meta({"type": "exit"})


def _scheme_of(url: object) -> str:
    try:
        return urllib.parse.urlsplit(str(url)).scheme[:_LOGGED_SCHEME_CHARS]
    except ValueError:
        return ""


def _open_in_browser(url: str, new: int) -> None:
    try:
        opened = webbrowser.open(url, new=new)
    except webbrowser.Error as error:
        logger.warning("Could not start a browser: %s", type(error).__name__)
        return
    if not opened:
        logger.warning("No browser accepted the link")


def desktop_driver_class(
    transport: DesktopDriverTransport,
) -> type[WebDriver]:
    """Return a concrete WebDriver class bound to the given in-memory transport."""

    class BoundDesktopDriver(DesktopDriver):
        def __init__(self, app: App[Any], **kwargs: Any) -> None:
            super().__init__(app, transport=transport, **kwargs)

    return BoundDesktopDriver
