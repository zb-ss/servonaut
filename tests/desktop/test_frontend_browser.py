"""End-to-end browser qualification on Chromium and WebKit via Playwright.

Tests the mandatory E2E trio:
1. Real desktop boot / navigation and terminal canvas rendering.
2. Adjacent settings / modal navigation (HelpScreen open & dismiss).
3. Invalid bootstrap authentication rejection (terminal does not mount).
"""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path
from urllib.parse import urlparse

import pytest

pytest.importorskip("aiohttp")
pytest.importorskip("playwright.async_api")
from playwright.async_api import async_playwright

from servonaut.app import ServonautApp
from servonaut.desktop.driver import (
    DesktopDriverTransport,
    desktop_driver_class,
)
from servonaut.desktop.host import DesktopHost
from servonaut.desktop.model import SecretToken
from servonaut.runtime import detect_runtime

BROWSERS = ["chromium", "webkit"]


@pytest.fixture
def isolated_config(tmp_path: Path) -> Path:
    config_file = tmp_path / "browser_test_config.json"
    config_file.write_text("{}")
    return config_file


@pytest.fixture
def test_listener() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    return sock


@pytest.mark.asyncio
@pytest.mark.parametrize("browser_type", BROWSERS)
async def test_browser_desktop_boot_and_navigation(
    browser_type: str, test_listener: socket.socket, isolated_config: Path
) -> None:
    """Trio 1: Real desktop boot, terminal canvas rendering, zero console/CSP errors."""
    token = SecretToken.generate()
    runtime = detect_runtime()

    def app_factory(transport: DesktopDriverTransport) -> ServonautApp:
        return ServonautApp(
            runtime_layout=runtime,
            config_path=isolated_config,
            driver_class=desktop_driver_class(transport),
        )

    host = DesktopHost(
        token=token,
        listener=test_listener,
        app_factory=app_factory,
    )
    origin = await host.start()
    assigned_host = urlparse(origin).netloc

    console_errors: list[str] = []
    page_errors: list[str] = []
    requested_urls: list[str] = []

    async with async_playwright() as playwright:
        browser_launcher = getattr(playwright, browser_type)
        browser = await browser_launcher.launch()
        page = await browser.new_page()

        page.on(
            "console",
            lambda msg: (
                console_errors.append(msg.text)
                if msg.type in ("error", "warning") and "CSP" in msg.text
                else None
            ),
        )
        page.on("pageerror", lambda err: page_errors.append(str(err)))
        page.on("request", lambda req: requested_urls.append(req.url))

        # Navigate to host root
        await page.goto(origin)
        assert await page.title() == "Servonaut"

        # Bootstrap session with token
        await page.evaluate(
            "(tok) => window.startServonaut(tok)", token.encoded_value()
        )

        # Wait for terminal to connect and render first byte
        await page.wait_for_selector("body.-loaded.-first-byte", timeout=10000)
        await page.wait_for_selector("canvas.xterm-text-layer", timeout=5000)

        # Assert all requested URLs strictly match the assigned loopback origin
        assert len(requested_urls) > 0
        for url in requested_urls:
            parsed = urlparse(url)
            assert parsed.scheme in ("http", "ws")
            assert parsed.netloc == assigned_host

        # Assert no CSP errors or uncaught page exceptions
        assert len(console_errors) == 0
        assert len(page_errors) == 0

        # Assert active app is running with InstanceListScreen
        app = host._active_app
        assert isinstance(app, ServonautApp)
        assert app.is_running
        assert app.screen.__class__.__name__ == "InstanceListScreen"

        await browser.close()

    await host.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("browser_type", BROWSERS)
async def test_browser_settings_and_modal_flow(
    browser_type: str, test_listener: socket.socket, isolated_config: Path
) -> None:
    """Trio 2: Modal flow via browser keyboard input (open HelpScreen with '?', dismiss with 'q')."""
    token = SecretToken.generate()
    runtime = detect_runtime()

    def app_factory(transport: DesktopDriverTransport) -> ServonautApp:
        return ServonautApp(
            runtime_layout=runtime,
            config_path=isolated_config,
            driver_class=desktop_driver_class(transport),
        )

    host = DesktopHost(
        token=token,
        listener=test_listener,
        app_factory=app_factory,
    )
    origin = await host.start()

    async with async_playwright() as playwright:
        browser_launcher = getattr(playwright, browser_type)
        browser = await browser_launcher.launch()
        page = await browser.new_page()

        await page.goto(origin)
        await page.evaluate(
            "(tok) => window.startServonaut(tok)", token.encoded_value()
        )
        await page.wait_for_selector("body.-loaded.-first-byte", timeout=10000)

        app = host._active_app
        assert isinstance(app, ServonautApp)
        assert app.screen.__class__.__name__ == "InstanceListScreen"

        # Focus terminal input and press '?'
        await page.focus("textarea.xterm-helper-textarea")
        await page.keyboard.press("?")

        for _ in range(40):
            if app.screen.__class__.__name__ == "HelpScreen":
                break
            await asyncio.sleep(0.05)
        assert app.screen.__class__.__name__ == "HelpScreen"

        # Press 'q' to dismiss help modal
        await page.keyboard.press("q")
        for _ in range(40):
            if app.screen.__class__.__name__ == "InstanceListScreen":
                break
            await asyncio.sleep(0.05)
        assert app.screen.__class__.__name__ == "InstanceListScreen"

        await browser.close()

    await host.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("browser_type", BROWSERS)
async def test_browser_invalid_token_fails_authentication(
    browser_type: str, test_listener: socket.socket, isolated_config: Path
) -> None:
    """Trio 3: Invalid token fails handshake; terminal does not connect and app is never initialized."""
    token = SecretToken.generate()

    host = DesktopHost(
        token=token,
        listener=test_listener,
    )
    origin = await host.start()

    async with async_playwright() as playwright:
        browser_launcher = getattr(playwright, browser_type)
        browser = await browser_launcher.launch()
        page = await browser.new_page()

        await page.goto(origin)
        invalid_token = "invalid_token_1234567890123456789012345678901"
        await page.evaluate("(tok) => window.startServonaut(tok)", invalid_token)

        # Allow time for WebSocket handshake to be rejected
        await asyncio.sleep(1.0)

        # Terminal body must NOT have received first byte
        body_classes = await page.get_attribute("body", "class") or ""
        assert "-first-byte" not in body_classes

        # No application should have been constructed
        assert host._active_app is None

        await browser.close()

    await host.stop()
