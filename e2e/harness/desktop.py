"""Drive the desktop frontend in headless Chromium, inside the e2e sandbox.

The desktop app serves a small web page from a loopback server and runs the
TUI behind an authenticated WebSocket. Journeys host it in one of two ways:

- :func:`in_process_host` runs ``DesktopHost`` with the real ``ServonautApp``
  in the test process, so a journey can check the app's own state (screen
  stack, focus, table rows) next to what the page shows. The terminal is
  drawn on a canvas, so the page's DOM holds no text; what the terminal
  received is read from the WebSocket frames instead.
- :func:`desktop_child` starts the real ``python -m servonaut.desktop.child``
  through the product's own launcher (``launch_and_handshake_desktop_child``),
  with a sandbox home and the e2e guards. This is the process boundary the
  security and lifecycle journeys are about.

:func:`chromium` starts headless Chromium. It is not a Python process, so the
network guard cannot see it. Instead every destination that is not loopback
goes to a proxy port where nothing listens, no other name resolves, and every
request and WebSocket is recorded. A journey whose page reached for anything
off loopback fails, unless the browser blocked it itself (see
``allow_csp_blocked``).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import re
import signal
import socket
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Optional, Sequence, TypeVar
from urllib.parse import parse_qs, urlsplit

from e2e.harness.bootstrap import DEAD_HTTP_URL, Sandbox, load_guard
from e2e.harness.processes import require_armed

T = TypeVar("T")

GUARD = load_guard()

DEFAULT_TIMEOUT = 20.0
# The child imports the whole app and verifies the frontend bundle before it
# reports ready; a loaded CI runner needs more than the launcher's default.
CHILD_STARTUP_TIMEOUT = 30.0
CHILD_EXIT_TIMEOUT = 15.0
VIEWPORT = {"width": 1280, "height": 800}
CHILD_MODULE = "servonaut.desktop.child"
# Runs as its own process in place of the desktop window (see that file).
WINDOW_STAND_IN = Path(__file__).with_name("desktop_parent.py")
# Chromium cannot be guarded from Python. These switches give it the same
# boundary as the test process: anything that is not loopback goes to a
# proxy where nothing listens, and no name but loopback resolves.
CHROMIUM_ARGS = (
    f"--proxy-server={DEAD_HTTP_URL}",
    "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1 , EXCLUDE localhost",
)
# The failure Playwright reports for a request the page's CSP refused
# before it left the renderer.
CSP_BLOCKED = "csp"
_TEXT_KEEP_CHARS = 2 * 1024 * 1024
_ESCAPES = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI: cursor, colour, modes
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC: titles, hyperlinks
    r"|\x1bP[^\x1b]*\x1b\\"  # DCS
    r"|\x1b[()][0-9A-Za-z]"  # character sets
    r"|\x1b[@-Z\\-_]"  # single-character escapes
)


class BrowserMissingError(AssertionError):
    """Playwright's Chromium is not installed."""


class DesktopTimeout(AssertionError):
    """A condition a desktop journey waited for never became true."""


async def wait_until(
    predicate: Callable[[], T],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    desc: str = "condition",
    interval: float = 0.02,
) -> T:
    """Poll *predicate* until it is truthy and return its value."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if loop.time() >= deadline:
            raise DesktopTimeout(f"timed out after {timeout:.0f}s waiting for {desc}")
        await asyncio.sleep(interval)


def terminal_text(data: bytes) -> str:
    """The printable text in a chunk of terminal output, escapes removed."""
    return _ESCAPES.sub("", data.decode("utf-8", "replace"))


def bind_loopback_listener() -> socket.socket:
    """A listening socket on an OS-assigned loopback port."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    return listener


def playwright_driver_dir() -> str:
    """The directory of the program Playwright starts to drive the browser.

    Playwright has no public accessor for it; this private helper is what
    its own launcher calls.
    """
    from playwright._impl._driver import compute_driver_executable

    executable = compute_driver_executable()
    if isinstance(executable, tuple):  # (node, cli.js)
        executable = executable[0]
    return str(Path(executable).resolve().parent)


def is_loopback_url(url: str) -> bool:
    """True for loopback http(s)/ws(s) URLs and for URLs that need no network."""
    parts = urlsplit(url)
    if parts.scheme in ("data", "about", "blob", "chrome-error"):
        return True
    return parts.hostname is not None and GUARD.is_loopback_host(parts.hostname)


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


class DesktopPage:
    """One page showing the desktop frontend, with its terminal traffic recorded.

    ``output_mark()`` and ``text(since=...)`` let a journey wait for text the
    terminal received after an action, not text that was already there.
    """

    def __init__(self, page: Any) -> None:
        self.page = page
        self.sockets: list[Any] = []
        self.closed_sockets: list[Any] = []
        self.sent: list[Any] = []
        self.console: list[tuple[str, str]] = []
        self.page_errors: list[str] = []
        self.dimensions: dict[str, int] = {}
        self.document_response: Any = None
        self._text: list[str] = []
        self._text_start = 0
        self._text_length = 0
        page.on("websocket", self._watch_socket)
        page.on("console", lambda message: self.console.append((message.type, message.text)))
        page.on("pageerror", lambda error: self.page_errors.append(str(error)))

    # -- recording ---------------------------------------------------------

    def _watch_socket(self, socket_: Any) -> None:
        self.sockets.append(socket_)
        query = parse_qs(urlsplit(socket_.url).query)
        if "width" in query and "height" in query:
            self.dimensions = {
                "width": int(query["width"][0]),
                "height": int(query["height"][0]),
            }
        socket_.on("framereceived", self._received)
        socket_.on("framesent", self._sent)
        socket_.on("close", lambda closed: self.closed_sockets.append(closed))

    def _received(self, payload: Any) -> None:
        if not isinstance(payload, (bytes, bytearray)):
            return
        chunk = terminal_text(bytes(payload))
        self._text.append(chunk)
        self._text_length += len(chunk)
        while self._text and self._text_length - self._text_start > _TEXT_KEEP_CHARS:
            self._text_start += len(self._text.pop(0))

    def _sent(self, payload: Any) -> None:
        if not isinstance(payload, str):
            self.sent.append(payload)
            return
        try:
            message = json.loads(payload)
        except ValueError:
            self.sent.append(payload)
            return
        self.sent.append(message)
        if isinstance(message, list) and len(message) == 2 and message[0] == "resize":
            self.dimensions = {"width": message[1]["width"], "height": message[1]["height"]}

    # -- observation -------------------------------------------------------

    def output_mark(self) -> int:
        """A position in the terminal output; pass it as ``since=``."""
        return self._text_length

    def text(self, since: int = 0) -> str:
        """Printable text the terminal received after *since*."""
        joined = "".join(self._text)
        return joined[max(since - self._text_start, 0) :]

    async def wait_for_text(
        self, text: str, *, since: int = 0, timeout: float = DEFAULT_TIMEOUT
    ) -> None:
        await wait_until(
            lambda: text in self.text(since), timeout=timeout, desc=f"{text!r} on the terminal"
        )

    def stdin_sent(self, since: int = 0) -> str:
        """Everything the page sent as terminal input after message *since*."""
        return "".join(
            message[1]
            for message in self.sent[since:]
            if isinstance(message, list) and len(message) == 2 and message[0] == "stdin"
        )

    def errors(self) -> list[str]:
        """Uncaught page errors and console errors, for a clean-run assertion."""
        return self.page_errors + [text for kind, text in self.console if kind == "error"]

    async def body_classes(self) -> set[str]:
        return set((await self.page.get_attribute("body", "class") or "").split())

    # -- session -----------------------------------------------------------

    async def open(self, url: str) -> int:
        """Load *url*; return the HTTP status of the document.

        The response stays available as ``document_response``.
        """
        response = await self.page.goto(url)
        assert response is not None, f"no response for {url}"
        self.document_response = response
        return response.status

    async def start_session(self, token: str) -> None:
        """Hand the page its session token, as the desktop window does."""
        await self.page.evaluate("token => window.startServonaut(token)", token)

    async def wait_for_first_output(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        """Wait until the terminal connected and painted its first output."""
        await self.page.wait_for_selector("body.-first-byte", timeout=timeout * 1000)

    async def wait_for_socket_closed(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        """Wait until the page shows its session ended."""
        await self.page.wait_for_selector("body.-closed", state="attached", timeout=timeout * 1000)

    # -- input -------------------------------------------------------------

    async def focus_terminal(self) -> None:
        await self.page.locator(".xterm-helper-textarea").focus()

    async def type(self, text: str) -> None:
        await self.focus_terminal()
        await self.page.keyboard.type(text)

    async def press(self, *keys: str) -> None:
        await self.focus_terminal()
        for key in keys:
            await self.page.keyboard.press(key)

    async def paste(self, text: str) -> None:
        """Paste *text* the way the browser delivers a clipboard paste.

        This dispatches a real ``paste`` event with the text as clipboard
        data. It exercises page → terminal → WebSocket → app, not the
        operating system's clipboard.
        """
        before = len(self.sent)
        dispatched = await self.page.evaluate(
            """text => {
                const textarea = document.querySelector('.xterm-helper-textarea');
                const clipboard = new DataTransfer();
                clipboard.setData('text/plain', text);
                textarea.focus();
                return textarea.dispatchEvent(new ClipboardEvent('paste', {
                    bubbles: true, cancelable: true, clipboardData: clipboard, composed: true,
                }));
            }""",
            text,
        )
        assert dispatched is not None
        await wait_until(
            lambda: text in self.stdin_sent(before), desc="the pasted text sent to the app"
        )

    async def _cell_position(self, column: int, row: int) -> tuple[float, float]:
        assert self.dimensions, "the terminal has not reported its size yet"
        box = await self.page.locator(".xterm-screen").bounding_box()
        assert box is not None, "the terminal is not on the page"
        return (
            box["x"] + (column + 0.5) * box["width"] / self.dimensions["width"],
            box["y"] + (row + 0.5) * box["height"] / self.dimensions["height"],
        )

    async def click_cell(self, column: int, row: int) -> None:
        """Click the middle of one terminal cell (0-based)."""
        await self.page.mouse.click(*await self._cell_position(column, row))

    async def hover_cell(self, column: int, row: int) -> None:
        """Move the mouse over one terminal cell (0-based)."""
        await self.page.mouse.move(*await self._cell_position(column, row))

    async def resize(self, width: int, height: int) -> dict[str, int]:
        """Resize the window; return the terminal size the page then sent."""
        before = len(self.sent)
        await self.page.set_viewport_size({"width": width, "height": height})

        def resized() -> Optional[dict[str, int]]:
            for message in self.sent[before:]:
                if isinstance(message, list) and len(message) == 2 and message[0] == "resize":
                    return dict(message[1])
            return None

        return await wait_until(resized, desc=f"a resize message after {width}x{height}")


# ---------------------------------------------------------------------------
# The browser
# ---------------------------------------------------------------------------


class BrowserSession:
    """Headless Chromium with one fresh context; records every request."""

    def __init__(self, browser: Any, context: Any) -> None:
        self.browser = browser
        self.context = context
        self.pages: list[DesktopPage] = []
        self._requests: list[Any] = []
        context.on("request", self._record_request)

    def _record_request(self, request: Any) -> None:
        self._requests.append(request)

    async def new_page(self) -> DesktopPage:
        page = DesktopPage(await self.context.new_page())
        self.pages.append(page)
        return page

    def requests(self) -> list[tuple[str, Optional[str]]]:
        """(url, failure) of every request any page made, in order."""
        return [(request.url, request.failure) for request in self._requests]

    def off_loopback(self, *, allow_csp_blocked: bool = False) -> list[str]:
        """Requests and WebSockets that were meant for a non-loopback host.

        With *allow_csp_blocked*, requests the page's own CSP refused (they
        never left the renderer) are not counted.
        """
        found = [
            f"{url} ({failure or 'sent'})"
            for url, failure in self.requests()
            if not is_loopback_url(url) and not (allow_csp_blocked and failure == CSP_BLOCKED)
        ]
        found += [
            f"websocket {ws.url}"
            for page in self.pages
            for ws in page.sockets
            if not is_loopback_url(ws.url)
        ]
        return found

    async def save_artifacts(self, directory: Path) -> None:
        """Screenshots, console logs and the Playwright trace, for a failure."""
        directory.mkdir(parents=True, exist_ok=True)
        for index, page in enumerate(self.pages):
            with contextlib.suppress(Exception):
                await page.page.screenshot(path=str(directory / f"page-{index}.png"))
            lines = [f"{kind}: {text}" for kind, text in page.console]
            lines += [f"pageerror: {text}" for text in page.page_errors]
            (directory / f"page-{index}-console.log").write_text(
                "\n".join(lines) + "\n", encoding="utf-8"
            )
        requests = "".join(f"{url} -> {failure or 'ok'}\n" for url, failure in self.requests())
        (directory / "browser-requests.log").write_text(requests, encoding="utf-8")
        with contextlib.suppress(Exception):
            await self.context.tracing.stop(path=str(directory / "trace.zip"))


async def _launch(playwright: Any) -> Any:
    try:
        return await playwright.chromium.launch(args=list(CHROMIUM_ARGS))
    except Exception as exc:  # playwright raises its own Error type
        if "Executable doesn't exist" in str(exc):
            raise BrowserMissingError(
                "Playwright's Chromium is not installed; run "
                "`python -m playwright install chromium` (CI: `--with-deps`)."
            ) from None
        raise


@asynccontextmanager
async def chromium(
    artifact_dir: Path, *, allow_csp_blocked: bool = False
) -> AsyncIterator[BrowserSession]:
    """Headless Chromium kept on loopback; fails the journey on any escape.

    On failure the pages' screenshots and console, the request list and a
    Playwright trace go to *artifact_dir*.
    """
    from playwright.async_api import async_playwright

    async with async_playwright() as playwright:
        browser = await _launch(playwright)
        try:
            context = await browser.new_context(viewport=VIEWPORT, service_workers="block")
            await context.tracing.start(screenshots=True, snapshots=True)
            session = BrowserSession(browser, context)
            try:
                yield session
            except BaseException:
                await session.save_artifacts(artifact_dir)
                raise
            escapes = session.off_loopback(allow_csp_blocked=allow_csp_blocked)
            if escapes:
                await session.save_artifacts(artifact_dir)
                raise AssertionError(
                    "the page reached for hosts off loopback:\n  " + "\n  ".join(escapes)
                )
            await context.tracing.stop()
        finally:
            with contextlib.suppress(Exception):
                await browser.close()


# ---------------------------------------------------------------------------
# Hosting in this process
# ---------------------------------------------------------------------------


class _LoopPilot:
    """Just enough of Textual's Pilot for TuiDriver's waiting helpers.

    The app runs under the desktop host, not ``run_test``, so there is no
    real pilot; input only ever arrives through the browser.
    """

    async def pause(self, delay: Optional[float] = None) -> None:
        await asyncio.sleep(delay or 0)


@dataclass
class InProcessDesktop:
    """The desktop host and the real app, running in this process."""

    host: Any
    token: Any
    origin: str
    artifact_dir: Path
    notifications: list[Any] = field(default_factory=list)
    _tui: Any = None

    @property
    def app(self) -> Any:
        return self.host._active_app

    @property
    def tui(self) -> Any:
        """A TuiDriver for reading the app's state (not for input)."""
        from e2e.harness.pilot import TuiDriver

        if self._tui is None or self._tui.app is not self.app:
            assert self.app is not None, "no desktop session has started yet"
            self._tui = TuiDriver(self.app, _LoopPilot(), self.notifications, self.artifact_dir)
        return self._tui

    async def wait_for_app(self, screen: str = "InstanceListScreen") -> Any:
        """Wait until the session's app is up and showing *screen*."""
        await wait_until(lambda: self.app is not None, desc="the desktop app")
        await self.tui.wait_for_screen(screen)
        return self.app


def _recording_notify(app: Any, notifications: list[Any]) -> None:
    """Keep every notification the app shows, for assertions and artifacts."""
    from textual.notifications import Notification

    original = app.notify

    def notify(message: Any, **kwargs: Any) -> Any:
        severity = kwargs.get("severity", "information")
        notifications.append(Notification(str(message), severity=severity))
        return original(message, **kwargs)

    app.notify = notify


@asynccontextmanager
async def in_process_host(artifact_dir: Path) -> AsyncIterator[InProcessDesktop]:
    """Serve the desktop frontend and the real app from this process."""
    from servonaut.app import ServonautApp
    from servonaut.desktop.driver import desktop_driver_class
    from servonaut.desktop.host import DesktopHost
    from servonaut.desktop.model import SecretToken
    from servonaut.runtime import detect_runtime

    notifications: list[Any] = []
    runtime = detect_runtime()

    def app_factory(transport: Any) -> Any:
        app = ServonautApp(runtime_layout=runtime, driver_class=desktop_driver_class(transport))
        _recording_notify(app, notifications)
        return app

    token = SecretToken.generate()
    host = DesktopHost(token=token, listener=bind_loopback_listener(), app_factory=app_factory)
    origin = await host.start()
    desktop = InProcessDesktop(host, token, origin, artifact_dir, notifications)
    try:
        yield desktop
    except BaseException:
        if desktop.app is not None:
            with contextlib.suppress(Exception):
                desktop.tui.capture("failure")
        raise
    finally:
        await host.stop()


# ---------------------------------------------------------------------------
# The out-of-process child
# ---------------------------------------------------------------------------


@dataclass
class DesktopChild:
    """The real desktop child, started by the product's own launcher."""

    tree: Any
    token: Any
    origin: str
    sandbox: Sandbox

    @property
    def pid(self) -> int:
        return self.tree.pid

    @property
    def port(self) -> int:
        return int(self.origin.rsplit(":", 1)[1])

    def close_stdin(self) -> None:
        """Close the control pipe, as the desktop window does when it goes away."""
        assert self.tree.stdin is not None
        self.tree.stdin.close()

    async def wait_for_exit(self, timeout: float = CHILD_EXIT_TIMEOUT) -> int:
        """The child's exit status, once it has exited by itself."""
        import subprocess

        try:
            return await asyncio.to_thread(self.tree.wait, timeout)
        except subprocess.TimeoutExpired:
            raise DesktopTimeout(
                f"the desktop child (pid {self.pid}) was still running after {timeout:.0f}s"
            ) from None


def child_command() -> list[str]:
    return [sys.executable, "-m", CHILD_MODULE]


@asynccontextmanager
async def desktop_child(
    sandbox: Sandbox, *, env: dict[str, str], armed_log: Path
) -> AsyncIterator[DesktopChild]:
    """Start the desktop child with a fresh listener and token; stop it after."""
    from servonaut.desktop.model import SecretToken
    from servonaut.desktop.process_tree import launch_and_handshake_desktop_child

    listener = bind_loopback_listener()
    origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
    token = SecretToken.generate()
    try:
        tree, ready = await asyncio.to_thread(
            launch_and_handshake_desktop_child,
            child_command(),
            origin=origin,
            token=token,
            listener=listener,
            startup_timeout=CHILD_STARTUP_TIMEOUT,
            cwd=sandbox.base,
            env=env,
        )
    finally:
        # The child serves from its own copy of the socket. Dropping this one
        # means the port closes as soon as the child is gone.
        listener.close()
    try:
        assert ready.origin == origin
        require_armed(armed_log, pid=tree.pid)
        yield DesktopChild(tree, token, origin, sandbox)
    finally:
        await asyncio.to_thread(tree.close)


# ---------------------------------------------------------------------------
# Raw WebSocket handshakes
# ---------------------------------------------------------------------------


_AS_THE_PAGE_SENDS_IT = "as the page sends it"


def session_headers(
    port: int,
    token: Optional[str],
    *,
    origin: Optional[str] = _AS_THE_PAGE_SENDS_IT,
    host: Optional[str] = _AS_THE_PAGE_SENDS_IT,
    protocols: Optional[Sequence[str]] = None,
) -> list[tuple[str, str]]:
    """Upgrade headers as the page sends them; override one to go wrong.

    *origin* and *host* replace that header's value, or leave it out when
    ``None``; *protocols* replaces the offered subprotocols (by default the
    session protocol and ``auth.<token>``, or just the protocol when *token*
    is ``None``).
    """
    from servonaut.desktop.host import PROTOCOL_SUBPROTOCOL

    if host == _AS_THE_PAGE_SENDS_IT:
        host = f"127.0.0.1:{port}"
    if origin == _AS_THE_PAGE_SENDS_IT:
        origin = f"http://127.0.0.1:{port}"
    headers: list[tuple[str, str]] = []
    if host is not None:
        headers.append(("Host", host))
    if origin is not None:
        headers.append(("Origin", origin))
    if protocols is None:
        protocols = [PROTOCOL_SUBPROTOCOL] + ([f"auth.{token}"] if token is not None else [])
    if protocols:
        headers.append(("Sec-WebSocket-Protocol", ", ".join(protocols)))
    return headers


async def upgrade_status(
    port: int,
    headers: Sequence[tuple[str, str]],
    *,
    path: str = "/ws?width=80&height=24",
    timeout: float = DEFAULT_TIMEOUT,
) -> int:
    """Send one WebSocket upgrade with exactly *headers*; return the HTTP status.

    A raw request, so repeated or missing headers reach the server exactly
    as written. A 101 answer consumes the host's single session.
    """
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        lines = [
            f"GET {path} HTTP/1.1",
            *(f"{name}: {value}" for name, value in headers),
            "Connection: Upgrade",
            "Upgrade: websocket",
            "Sec-WebSocket-Version: 13",
            f"Sec-WebSocket-Key: {key}",
            "",
            "",
        ]
        writer.write("\r\n".join(lines).encode("latin-1"))
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readline(), timeout)
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
    parts = status_line.decode("latin-1").split()
    assert len(parts) >= 2, f"no HTTP status line in {status_line!r}"
    return int(parts[1])


def port_accepts_connections(port: int) -> bool:
    """True while something accepts TCP connections on the loopback *port*."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(2)
        return probe.connect_ex(("127.0.0.1", port)) == 0


# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------


def process_is_running(pid: int) -> bool:
    """True while *pid* exists and is not a zombie."""
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except OSError:
        return False
    return "\nState:\tZ" not in status


def kill_sandbox_process(pid: int, sandbox_root: Path) -> None:
    """SIGKILL *pid* if it still runs with an environment inside *sandbox_root*."""
    try:
        environ = Path(f"/proc/{pid}/environ").read_bytes()
    except OSError:
        return
    if os.fsencode(str(sandbox_root)) in environ:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
