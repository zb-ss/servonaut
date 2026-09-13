"""Opt-in browser rendering checks using the same private bootstrap as the GUI."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

pytest.importorskip("textual_serve")
playwright = pytest.importorskip("playwright.async_api")

from scripts.desktop_probe.host import ProbeHost


async def capture_changed_screen(
    page: playwright.Page, host: ProbeHost, previous: bytes, destination: Path
) -> bytes:
    """Wait for changed, stable pixels: a received WS frame may not be painted yet."""
    last = previous
    deadline = asyncio.get_running_loop().time() + host.config.startup_seconds
    while asyncio.get_running_loop().time() < deadline:
        current = await page.screenshot()
        if current != previous and current == last:
            destination.write_bytes(current)
            return current
        last = current
        await asyncio.sleep(host.config.probe_poll_seconds)
    raise AssertionError(
        "Expected a changed and stable screen before capturing evidence"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "browser_name",
    os.environ.get("SERVONAUT_PROBE_BROWSERS", "chromium,webkit").split(","),
)
@pytest.mark.skipif(
    os.environ.get("SERVONAUT_DESKTOP_BROWSER_TEST") != "1",
    reason="Set SERVONAUT_DESKTOP_BROWSER_TEST=1 to run a real browser",
)
async def test_browser_rendering_navigation_and_rejection(
    tmp_path: Path, browser_name: str
) -> None:
    host = ProbeHost()
    await host.start()
    errors: list[str] = []
    frames = bytearray()
    rendered = asyncio.Event()
    help_rendered = asyncio.Event()
    input_sent = asyncio.Event()
    resize_sent = asyncio.Event()
    output = (
        Path(os.environ.get("SERVONAUT_PROBE_RESULTS", str(tmp_path))) / browser_name
    )
    output.mkdir(parents=True, exist_ok=True)

    def receive(payload: str | bytes) -> None:
        if isinstance(payload, bytes):
            frames.extend(payload)
            del frames[: -host.config.max_packet_bytes]
            if b"web-1" in frames:
                rendered.set()
            if b"Navigation" in frames:
                help_rendered.set()

    def sent(payload: str | bytes) -> None:
        if not isinstance(payload, str):
            return
        message = json.loads(payload)
        if message == ["stdin", "?"]:
            input_sent.set()
        if message[0] == "resize":
            resize_sent.set()

    def watch_socket(socket: playwright.WebSocket) -> None:
        socket.on("framereceived", receive)
        socket.on("framesent", sent)

    try:
        async with playwright.async_playwright() as engine:
            options = {}
            if browser_name == "chromium" and os.environ.get(
                "SERVONAUT_PROBE_BROWSER_CHANNEL"
            ):
                options["channel"] = os.environ["SERVONAUT_PROBE_BROWSER_CHANNEL"]
            browser = await getattr(engine, browser_name).launch(**options)
            try:
                page = await browser.new_page(viewport={"width": 1200, "height": 800})
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on(
                    "console",
                    lambda message: (
                        errors.append(message.text) if message.type == "error" else None
                    ),
                )
                page.on("websocket", watch_socket)
                page.on("requestfailed", lambda _: errors.append("request failed"))
                page.on(
                    "response",
                    lambda response: (
                        errors.append("HTTP failure")
                        if response.status >= 400
                        else None
                    ),
                )
                await page.goto(host.origin)
                blank = await page.screenshot()
                await page.evaluate(host.bootstrap_script())
                await asyncio.wait_for(rendered.wait(), host.config.startup_seconds)
                await page.locator(".xterm-helper-textarea").focus()
                instances = await capture_changed_screen(
                    page, host, blank, output / "instances.png"
                )
                await page.keyboard.type("?")
                await asyncio.wait_for(input_sent.wait(), host.config.startup_seconds)
                await asyncio.wait_for(
                    help_rendered.wait(), host.config.startup_seconds
                )
                await capture_changed_screen(page, host, instances, output / "help.png")
                frames.clear()
                rendered.clear()
                # xterm is a canvas: this sidebar button is at a fixed cell in
                # the deliberately fixed 1200x800 renderer fixture.
                await page.mouse.click(100, 166)
                await asyncio.wait_for(rendered.wait(), host.config.startup_seconds)
                resize_sent.clear()
                await page.set_viewport_size({"width": 1100, "height": 760})
                await asyncio.wait_for(resize_sent.wait(), host.config.startup_seconds)
                # A second page cannot authenticate merely by loading the assets.
                other = await browser.new_page()
                await other.goto(host.origin)
                status = await other.evaluate("""() => new Promise(resolve => {
                    const ws = new WebSocket(location.origin.replace('http:', 'ws:') + '/ws?width=80&height=24');
                    ws.onerror = () => resolve('rejected');
                    ws.onopen = () => { ws.close(); resolve('unexpectedly open'); };
                })""")
                assert status == "rejected"
                assert not errors
            finally:
                await browser.close()
    finally:
        await host.stop()
