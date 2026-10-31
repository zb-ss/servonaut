"""The desktop driver opens links in the system browser and owns copying.

A web view refuses to open windows for a script, and on Linux the OS
clipboard tools cannot reach a clipboard the focused window holds. These
tests run a real app on the desktop driver and check what reaches the
browser launcher, the page and the clipboard route.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import threading
from collections.abc import AsyncIterator, Iterator
from typing import Any
from unittest.mock import patch

import pytest
import pytest_asyncio

pytest.importorskip("textual")

from textual.app import App
from textual.widgets import Label

from servonaut.desktop import driver as driver_module
from servonaut.desktop.driver import (
    DesktopDriver,
    DesktopDriverTransport,
    desktop_driver_class,
    is_openable_url,
    window_owns_clipboard,
)
from servonaut.utils import platform_utils

WAIT_SECONDS = 5.0


class LinkApp(App[None]):
    def compose(self):
        yield Label("links")


class BrowserRecorder:
    """Stands in for webbrowser.open and records each call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []
        self.called = threading.Event()

    def __call__(self, url: str, new: int = 0) -> bool:
        self.calls.append((url, new))
        self.called.set()
        return True


@pytest.fixture
def browser() -> Iterator[BrowserRecorder]:
    recorder = BrowserRecorder()
    with patch.object(driver_module.webbrowser, "open", recorder):
        yield recorder


@pytest.fixture(autouse=True)
def no_leftover_clipboard_writer() -> Iterator[None]:
    yield
    assert platform_utils.clipboard_writer() is None, "a writer outlived its session"


async def _running_app(transport: DesktopDriverTransport) -> tuple[App[None], asyncio.Task[None]]:
    app = LinkApp(driver_class=desktop_driver_class(transport))
    task = asyncio.create_task(app.run_async(size=(80, 24)))
    await asyncio.wait_for(transport.ready_event.wait(), timeout=WAIT_SECONDS)
    return app, task


async def _stop(app: App[None], task: asyncio.Task[None], transport: DesktopDriverTransport) -> None:
    await app.action_quit()
    await asyncio.wait_for(task, timeout=WAIT_SECONDS)
    transport.close()


@pytest_asyncio.fixture
async def session() -> AsyncIterator[tuple[App[None], DesktopDriverTransport]]:
    transport = DesktopDriverTransport()
    app, task = await _running_app(transport)
    try:
        yield app, transport
    finally:
        await _stop(app, task, transport)


def _drain_output(transport: DesktopDriverTransport) -> bytes:
    """Everything the driver wrote for the page so far, unframed."""
    data = b""
    while not transport.output_queue.empty():
        packet = transport.output_queue.get_nowait()
        if packet and packet[:1] == b"D":
            data += packet[5:]
    return data


async def _wait_for(predicate: Any, desc: str) -> None:
    deadline = asyncio.get_running_loop().time() + WAIT_SECONDS
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(f"timed out waiting for {desc}")
        await asyncio.sleep(0.01)


@pytest.mark.parametrize(
    "url",
    [
        "https://servonaut.dev/docs",
        "http://example.com/a?b=1#c",
        "HTTPS://EXAMPLE.COM",
    ],
)
def test_web_addresses_are_openable(url: str) -> None:
    assert is_openable_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "mailto:support",
        "ssh://web-1",
        "https://",
        "docs/memory-sync.md",
        " https://example.com",
        "https://[broken",
        None,
        42,
    ],
)
def test_other_links_are_not_openable(url: object) -> None:
    assert not is_openable_url(url)


@pytest.mark.parametrize(
    ("platform_name", "expected"),
    [("linux", True), ("darwin", False), ("win32", False)],
)
def test_only_linux_copies_through_the_window(platform_name: str, expected: bool) -> None:
    assert window_owns_clipboard(platform_name) is expected


@pytest.mark.asyncio
async def test_a_link_opens_in_the_system_browser(session, browser) -> None:
    app, _ = session
    app.open_url("https://servonaut.dev/docs")
    assert browser.called.wait(WAIT_SECONDS)
    assert browser.calls == [("https://servonaut.dev/docs", 2)]


@pytest.mark.asyncio
async def test_a_link_for_the_same_tab_asks_for_no_new_tab(session, browser) -> None:
    app, _ = session
    app.open_url("https://servonaut.dev/pricing", new_tab=False)
    assert browser.called.wait(WAIT_SECONDS)
    assert browser.calls == [("https://servonaut.dev/pricing", 0)]


@pytest.mark.asyncio
async def test_other_schemes_are_refused_with_a_notice(session, browser, caplog) -> None:
    app, _ = session
    notices: list[tuple[str, str]] = []
    app.notify = lambda message, **kwargs: notices.append(  # type: ignore[method-assign]
        (message, kwargs.get("severity", ""))
    )
    with caplog.at_level(logging.WARNING, logger=driver_module.__name__):
        app.open_url("file:///tmp/secret-token.txt")
    await asyncio.sleep(0.05)
    assert browser.calls == []
    assert notices == [("Only web links (http/https) can be opened.", "warning")]
    # The log names the scheme, never the address.
    assert "file" in caplog.text
    assert "secret-token" not in caplog.text


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def _fake_clock(app: App[None]) -> FakeClock:
    clock = FakeClock()
    app._driver._clock = clock
    return clock


@pytest.mark.asyncio
async def test_the_same_link_twice_in_a_row_opens_once(session, browser) -> None:
    app, _ = session
    clock = _fake_clock(app)
    url = "https://servonaut.dev/docs/memory-sync"
    app.open_url(url)
    app.open_url(url)
    clock.now += 0.5
    app.open_url(url)
    # The app opening another address is another click.
    app.open_url("https://servonaut.dev/pricing")
    # The same address again, later, is a new click.
    clock.now += driver_module.REPEAT_OPEN_SECONDS + 0.1
    app.open_url(url)
    await _wait_for(lambda: len(browser.calls) >= 3, "three browser launches")
    _join_launches()
    assert sorted(browser.calls) == sorted(
        [(url, 2), ("https://servonaut.dev/pricing", 2), (url, 2)]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("page_first", [True, False])
async def test_a_click_seen_by_the_app_and_the_page_opens_one_tab(
    session, browser, page_first
) -> None:
    """Ctrl+click on a Markdown link: the app opens its target, the page the
    address it found in the text, which can be spelled differently."""
    app, transport = session
    clock = _fake_clock(app)
    app_target = "https://servonaut.dev/docs/"
    page_target = "https://servonaut.dev/docs"
    if page_first:
        transport.open_page_link(page_target)
        app.open_url(app_target)
    else:
        app.open_url(app_target)
        transport.open_page_link(page_target)
    await _wait_for(lambda: browser.calls, "a browser launch")
    _join_launches()
    assert browser.calls == [(page_target if page_first else app_target, 2)]
    # A later click on the page is a click of its own.
    clock.now += driver_module.REPEAT_OPEN_SECONDS + 0.1
    transport.open_page_link(page_target)
    await _wait_for(lambda: len(browser.calls) == 2, "a second launch")


@pytest.mark.asyncio
async def test_page_links_are_checked_like_the_apps(session, browser) -> None:
    app, transport = session
    notices: list[str] = []
    app.notify = lambda message, **kwargs: notices.append(message)  # type: ignore[method-assign]
    transport.open_page_link("javascript:alert(1)")
    await asyncio.sleep(0.05)
    _join_launches()
    assert browser.calls == []
    assert notices == ["Only web links (http/https) can be opened."]


@pytest.mark.asyncio
async def test_page_links_after_the_session_open_nothing(browser) -> None:
    transport = DesktopDriverTransport()
    app, task = await _running_app(transport)
    await _stop(app, task, transport)
    transport.open_page_link("https://servonaut.dev/")
    _join_launches()
    assert browser.calls == []


def _join_launches() -> None:
    for thread in threading.enumerate():
        if thread.name == "desktop-open-url":
            thread.join(WAIT_SECONDS)


@pytest.mark.asyncio
async def test_a_browser_that_fails_to_start_is_logged_not_raised(session, caplog) -> None:
    app, _ = session
    started = threading.Event()

    def failing_open(url: str, new: int = 0) -> bool:
        started.set()
        raise driver_module.webbrowser.Error("no runnable browser")

    with (
        patch.object(driver_module.webbrowser, "open", failing_open),
        caplog.at_level(logging.WARNING, logger=driver_module.__name__),
    ):
        app.open_url("https://servonaut.dev/")
        assert started.wait(WAIT_SECONDS)
        await _wait_for(lambda: "Could not start a browser" in caplog.text, "the log line")
    assert app.is_running


@pytest.mark.asyncio
async def test_a_large_write_is_split_into_packets_the_transport_accepts() -> None:
    transport = DesktopDriverTransport(max_packet_bytes=64)
    driver = DesktopDriver(LinkApp(), transport=transport)
    text = "é" * 100 + "x" * 37  # 237 bytes; splits land inside characters
    driver.write(text)
    packets = []
    while not transport.output_queue.empty():
        packets.append(transport.output_queue.get_nowait())
    assert len(packets) == 4
    payload = b""
    for packet in packets:
        assert packet[:1] == b"D"
        size = int.from_bytes(packet[1:5], "big")
        assert size == len(packet) - 5 <= 64
        payload += packet[5:]
    assert payload.decode("utf-8") == text
    transport.close()


@pytest.mark.asyncio
async def test_on_linux_a_copy_goes_through_the_window() -> None:
    transport = DesktopDriverTransport()
    with patch.object(driver_module, "window_owns_clipboard", lambda: True):
        app, task = await _running_app(transport)
    try:
        _drain_output(transport)
        assert platform_utils.copy_to_clipboard("café 9.9.9.9") is True
        expected = base64.b64encode("café 9.9.9.9".encode()).decode()
        written = b""

        def copied() -> bool:
            nonlocal written
            written += _drain_output(transport)
            return f"\x1b]52;c;{expected}\a".encode() in written

        await _wait_for(copied, "the OSC 52 copy for the page")
        # The app's own clipboard (in-app paste) has it too.
        assert app.clipboard == "café 9.9.9.9"
    finally:
        await _stop(app, task, transport)
    # The session over, copies go back to the OS tools.
    assert platform_utils.clipboard_writer() is None


@pytest.mark.asyncio
async def test_a_copy_from_another_thread_reaches_the_page() -> None:
    transport = DesktopDriverTransport()
    with patch.object(driver_module, "window_owns_clipboard", lambda: True):
        app, task = await _running_app(transport)
    try:
        results: list[bool] = []
        worker = threading.Thread(
            target=lambda: results.append(platform_utils.copy_to_clipboard("from a worker"))
        )
        worker.start()
        worker.join(WAIT_SECONDS)
        assert results == [True]
        await _wait_for(lambda: app.clipboard == "from a worker", "the copy on the app loop")
    finally:
        await _stop(app, task, transport)


@pytest.mark.asyncio
async def test_elsewhere_copies_keep_the_os_tools() -> None:
    transport = DesktopDriverTransport()
    with patch.object(driver_module, "window_owns_clipboard", lambda: False):
        app, task = await _running_app(transport)
    try:
        assert platform_utils.clipboard_writer() is None
    finally:
        await _stop(app, task, transport)


@pytest.mark.asyncio
async def test_a_copy_after_the_session_ended_reports_failure() -> None:
    transport = DesktopDriverTransport()
    with patch.object(driver_module, "window_owns_clipboard", lambda: True):
        app, task = await _running_app(transport)
    driver = app._driver
    assert isinstance(driver, DesktopDriver)
    await _stop(app, task, transport)
    assert driver._copy_in_window("too late") is False


@pytest.mark.asyncio
async def test_a_copy_once_the_loop_closed_reports_failure() -> None:
    transport = DesktopDriverTransport()
    driver = DesktopDriver(LinkApp(), transport=transport)
    closed = asyncio.new_event_loop()
    closed.close()
    driver._loop = closed
    assert driver._copy_in_window("too late") is False
    transport.close()


@pytest.mark.asyncio
async def test_ending_a_session_leaves_another_writer_in_place() -> None:
    transport = DesktopDriverTransport()
    with patch.object(driver_module, "window_owns_clipboard", lambda: True):
        app, task = await _running_app(transport)

    def other_writer(text: str) -> bool:
        return True

    platform_utils.set_clipboard_writer(other_writer)
    try:
        await _stop(app, task, transport)
        assert platform_utils.clipboard_writer() is other_writer
    finally:
        platform_utils.set_clipboard_writer(None)
