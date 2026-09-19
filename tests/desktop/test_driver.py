"""Tests for in-memory bounded Textual WebDriver adapter."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

import pytest

pytest.importorskip("textual")

from textual.app import App
from textual.widgets import Label

from servonaut.desktop.driver import (
    DesktopDriver,
    DesktopDriverBackpressureError,
    DesktopDriverTransport,
    desktop_driver_class,
)


class DummyApp(App[None]):
    def compose(self):
        yield Label("Test")


@pytest.mark.asyncio
async def test_driver_does_not_touch_stdio() -> None:
    """Driver must not read or write sys.__stdout__ or sys.__stdin__."""
    transport = DesktopDriverTransport()
    driver_cls = desktop_driver_class(transport)

    with (
        patch("sys.__stdout__.write") as mock_stdout,
        patch("sys.__stdin__.read") as mock_stdin,
    ):
        app = DummyApp(driver_class=driver_cls)
        task = asyncio.create_task(app.run_async(size=(80, 24)))
        await asyncio.wait_for(transport.ready_event.wait(), timeout=2.0)

        assert mock_stdout.call_count == 0
        assert mock_stdin.call_count == 0

        await app.action_quit()
        await task

    transport.close()


@pytest.mark.asyncio
async def test_driver_readiness_signal_and_output_framing() -> None:
    """Startup must trigger ready_event and frame output packets correctly."""
    transport = DesktopDriverTransport()
    driver_cls = desktop_driver_class(transport)

    app = DummyApp(driver_class=driver_cls)
    task = asyncio.create_task(app.run_async(size=(80, 24)))
    await asyncio.wait_for(transport.ready_event.wait(), timeout=2.0)
    assert transport.ready_event.is_set()

    # Drain initial terminal setup packets (b"D...")
    packets = []
    while not transport.output_queue.empty():
        packets.append(await transport.output_queue.get())

    assert len(packets) > 0
    # None of the packets should be raw __GANGLION__
    assert all(p != b"__GANGLION__\n" for p in packets)

    # First byte must be packet type 'D' or 'M'
    for p in packets:
        assert p[:1] in (b"D", b"M")
        size = int.from_bytes(p[1:5], "big")
        assert len(p[5:]) == size

    await app.action_quit()
    await task
    transport.close()


@pytest.mark.asyncio
async def test_driver_input_events_processed() -> None:
    """Input feed methods must convert to framed packets and dispatch to app."""
    transport = DesktopDriverTransport()
    driver_cls = desktop_driver_class(transport)

    received_keys = []

    class KeyRecordingApp(DummyApp):
        def on_key(self, event) -> None:
            received_keys.append(event.key)

    app = KeyRecordingApp(driver_class=driver_cls)
    task = asyncio.create_task(app.run_async(size=(80, 24)))
    await asyncio.wait_for(transport.ready_event.wait(), timeout=2.0)

    # Feed stdin key
    transport.feed_stdin("x")
    await asyncio.sleep(0.1)
    assert "x" in received_keys

    # Feed meta events
    transport.feed_resize(100, 30)
    transport.feed_focus()
    transport.feed_blur()
    await asyncio.sleep(0.1)

    # Quit via stdin 'q'
    transport.feed_stdin("q")
    await asyncio.wait_for(task, timeout=2.0)
    transport.close()


def test_input_backpressure_error() -> None:
    """Input queue overflow must raise backpressure error."""
    transport = DesktopDriverTransport(max_queue_size=2)
    transport.feed_stdin("1")
    transport.feed_stdin("2")

    with pytest.raises(DesktopDriverBackpressureError, match="backpressure exceeded"):
        transport.feed_stdin("3")
    transport.close()


@pytest.mark.asyncio
async def test_output_backpressure_error() -> None:
    """Output queue overflow must raise backpressure error."""
    transport = DesktopDriverTransport(max_queue_size=1)
    driver_cls = desktop_driver_class(transport)

    app = DummyApp(driver_class=driver_cls)
    # Fill output queue directly
    await transport.output_queue.put(b"D\x00\x00\x00\x01x")

    # Next write to transport should fail
    driver = driver_cls(app)
    with pytest.raises(DesktopDriverBackpressureError, match="backpressure exceeded"):
        driver._write_to_transport(b"D\x00\x00\x00\x01y")

    transport.close()


@pytest.mark.asyncio
async def test_clean_exit_and_close() -> None:
    """Closing the transport unblocks reader and driver cleanly."""
    transport = DesktopDriverTransport()
    driver_cls = desktop_driver_class(transport)

    app = DummyApp(driver_class=driver_cls)
    task = asyncio.create_task(app.run_async(size=(80, 24)))
    await asyncio.wait_for(transport.ready_event.wait(), timeout=2.0)

    # Stop driver
    driver = app._driver
    assert isinstance(driver, DesktopDriver)
    driver.stop_application_mode()
    assert driver.exit_event.is_set()

    # Find exit meta packet in output queue
    exit_meta_found = False
    while not transport.output_queue.empty():
        pkt = await transport.output_queue.get()
        if pkt and pkt[:1] == b"M":
            meta = json.loads(pkt[5:])
            if meta.get("type") == "exit":
                exit_meta_found = True

    assert exit_meta_found

    await app.action_quit()
    await task
    transport.close()
    assert transport.is_closed
