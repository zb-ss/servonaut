"""Opt-in browser rendering checks using the same private bootstrap as the GUI."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Callable
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("textual_serve")
playwright = pytest.importorskip("playwright.async_api")

from scripts.desktop_probe.host import ProbeHost

PASTED_TEXT = "café Δ 你好"


async def click_cell(
    page: playwright.Page, dimensions: dict[str, int], column: int, row: int
) -> None:
    """Hit a logical canvas cell using the renderer's negotiated dimensions."""
    box = await page.locator(".xterm-screen").bounding_box()
    assert box is not None
    await page.mouse.click(
        box["x"] + (column + 0.5) * box["width"] / dimensions["width"],
        box["y"] + (row + 0.5) * box["height"] / dimensions["height"],
    )


def browser_error_category(message: str) -> str:
    """Publish fixed diagnostic labels, not credential-bearing engine messages."""
    for category in ("webgl", "websocket", "font", "canvas", "content security"):
        if category in message.lower():
            return category
    return "unclassified"


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
@pytest.mark.parametrize("has_webgl", [True, False], ids=("default", "without-webgl"))
@pytest.mark.parametrize(
    "browser_name",
    os.environ.get("SERVONAUT_PROBE_BROWSERS", "chromium,webkit").split(","),
)
@pytest.mark.skipif(
    os.environ.get("SERVONAUT_DESKTOP_BROWSER_TEST") != "1",
    reason="Set SERVONAUT_DESKTOP_BROWSER_TEST=1 to run a real browser",
)
async def test_browser_rendering_interactions_and_rejection(
    tmp_path: Path,
    browser_name: str,
    has_webgl: bool,
    record_property: Callable[[str, object], None],
) -> None:
    host = ProbeHost()
    await host.start()
    errors: list[str] = []
    dimensions: dict[str, int] = {}
    frames = bytearray()
    rendered = asyncio.Event()
    help_rendered = asyncio.Event()
    modal_rendered = asyncio.Event()
    stream_rendered = asyncio.Event()
    stream_complete = asyncio.Event()
    input_sent = asyncio.Event()
    paste_sent = asyncio.Event()
    resize_sent = asyncio.Event()
    output = (
        Path(os.environ.get("SERVONAUT_PROBE_RESULTS", str(tmp_path))) / browser_name
    )
    output.mkdir(parents=True, exist_ok=True)
    prefix = "" if has_webgl else "without-webgl-"

    def receive(payload: str | bytes) -> None:
        if isinstance(payload, bytes):
            frames.extend(payload)
            del frames[: -host.config.max_packet_bytes]
            if b"web-1" in frames:
                rendered.set()
            if b"Navigation" in frames:
                help_rendered.set()
            if b"Renderer interaction confirmation" in frames:
                modal_rendered.set()
            if b"Renderer interaction exercise" in frames:
                stream_rendered.set()
            if b"Synthetic stream complete." in frames:
                stream_complete.set()

    def sent(payload: str | bytes) -> None:
        if not isinstance(payload, str):
            return
        message = json.loads(payload)
        if message == ["stdin", "?"]:
            input_sent.set()
        if (
            isinstance(message, list)
            and len(message) == 2
            and message[0] == "stdin"
            and isinstance(message[1], str)
            and PASTED_TEXT in message[1]
        ):
            paste_sent.set()
        if message[0] == "resize":
            dimensions.update(message[1])
            resize_sent.set()

    def watch_socket(socket: playwright.WebSocket) -> None:
        query = parse_qs(urlsplit(socket.url).query)
        dimensions.update({name: int(query[name][0]) for name in ("width", "height")})
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
                if not has_webgl:
                    # Simulate software-only GPUs without replacing the real
                    # browser, Canvas renderer, WebSocket or application child.
                    await page.add_init_script("""(() => {
                        const getContext = HTMLCanvasElement.prototype.getContext;
                        HTMLCanvasElement.prototype.getContext = function(kind, ...args) {
                            if (kind.includes('webgl')) return null;
                            return getContext.call(this, kind, ...args);
                        };
                    })()""")
                page.on(
                    "pageerror",
                    lambda error: errors.append(
                        "page: " + browser_error_category(str(error))
                    ),
                )
                page.on(
                    "console",
                    lambda message: (
                        errors.append(
                            "console: " + browser_error_category(message.text)
                        )
                        if message.type == "error"
                        else None
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
                    page, host, blank, output / f"{prefix}instances.png"
                )
                # Search can have initial focus; click empty table space first.
                await click_cell(page, dimensions, 70, 20)
                await page.keyboard.type("?")
                await asyncio.wait_for(input_sent.wait(), host.config.startup_seconds)
                await asyncio.wait_for(
                    help_rendered.wait(), host.config.startup_seconds
                )
                await capture_changed_screen(
                    page, host, instances, output / f"{prefix}help.png"
                )
                frames.clear()
                rendered.clear()
                # Instances is in this logical sidebar cell, regardless of font DPI.
                await click_cell(page, dimensions, 10, 10)
                await asyncio.wait_for(rendered.wait(), host.config.startup_seconds)
                resize_sent.clear()
                await page.set_viewport_size({"width": 1100, "height": 760})
                await asyncio.wait_for(resize_sent.wait(), host.config.startup_seconds)
                frames.clear()
                await page.locator(".xterm-helper-textarea").focus()
                await page.keyboard.press("F8")
                await asyncio.wait_for(
                    modal_rendered.wait(), host.config.startup_seconds
                )
                modal = await capture_changed_screen(
                    page, host, instances, output / f"{prefix}modal.png"
                )
                # The real confirmation modal keeps its action disabled until
                # the exact phrase arrives. Enter on the disabled button must
                # leave the modal in place.
                await page.keyboard.type("CONFIRX")
                await page.keyboard.press("Tab")
                await page.keyboard.press("Enter")
                await asyncio.sleep(host.config.probe_poll_seconds * 2)
                assert b"Renderer interaction confirmation" in frames
                await page.keyboard.press("Shift+Tab")
                await page.keyboard.press("Control+A")
                await page.keyboard.type("CONFIRM")
                rendered.clear()
                await page.keyboard.press("Tab")
                await page.keyboard.press("Enter")
                await asyncio.wait_for(rendered.wait(), host.config.startup_seconds)
                await capture_changed_screen(
                    page, host, modal, output / f"{prefix}modal-dismissed.png"
                )
                frames.clear()
                await page.locator(".xterm-helper-textarea").focus()
                await page.keyboard.press("F9")
                await asyncio.wait_for(
                    stream_rendered.wait(), host.config.startup_seconds
                )
                # This deliberately dispatches a browser paste event with
                # synthetic data. It proves the browser-event → terminal →
                # WebSocket → Textual Input boundary, not OS clipboard access.
                dispatched = await page.evaluate(
                    """text => {
                        const textarea = document.querySelector('.xterm-helper-textarea');
                        const clipboard = new DataTransfer();
                        clipboard.setData('text/plain', text);
                        textarea.focus();
                        return textarea.dispatchEvent(new ClipboardEvent('paste', {
                            bubbles: true,
                            clipboardData: clipboard,
                            composed: true,
                        }));
                    }""",
                    PASTED_TEXT,
                )
                assert dispatched
                await asyncio.wait_for(paste_sent.wait(), host.config.startup_seconds)
                await asyncio.wait_for(stream_complete.wait(), host.config.startup_seconds)
                stream = await page.screenshot(path=output / f"{prefix}stream.png")
                box = await page.locator(".xterm-screen").bounding_box()
                assert box is not None
                await page.mouse.move(
                    box["x"] + box["width"] / 2,
                    box["y"] + box["height"] / 2,
                )
                await page.mouse.wheel(0, -900)
                scrolled = await capture_changed_screen(
                    page, host, stream, output / f"{prefix}stream-scrolled.png"
                )
                assert scrolled != stream
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
        record_property("child_errors", host.child.errors)
        record_property("child_transport", host.child.transport_status())
        record_property("browser_errors", errors)
