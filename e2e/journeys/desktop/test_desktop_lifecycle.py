"""Journey: the desktop child never outlives its window or its session.

The desktop child keeps a loopback port open while it runs. It must go away
when the window that started it goes away (closes the control pipe, or dies
outright), when the user quits the app, and when the page's session ends. A
session is single-use by design, so reloading the page ends it rather than
reconnecting. Each journey runs the real child process with its own sandbox
home and watches it exit by itself.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys

import pytest

from e2e.harness import fleet
from e2e.harness.desktop import (
    CHILD_EXIT_TIMEOUT,
    CHILD_STARTUP_TIMEOUT,
    WINDOW_STAND_IN,
    kill_sandbox_process,
    port_accepts_connections,
    process_is_running,
    session_headers,
    upgrade_status,
    wait_until,
)
from e2e.harness.processes import require_armed

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_browser, pytest.mark.asyncio]

FIRST_HOST = fleet.AWS_FLEET[0].name


async def _start_session(browser, origin: str, token: str):
    page = await browser.new_page()
    assert await page.open(origin) == 200
    await page.start_session(token)
    await page.wait_for_first_output()
    await page.wait_for_text(FIRST_HOST)
    return page


async def _port_closes(port: int) -> None:
    await wait_until(
        lambda: not port_accepts_connections(port),
        timeout=CHILD_EXIT_TIMEOUT,
        desc=f"port {port} to close",
    )


async def test_the_child_exits_when_the_window_closes_its_control_pipe(desktop):
    async with desktop.child() as child, desktop.browser() as browser:
        page = await _start_session(browser, child.origin, child.token.encoded_value())
        child.close_stdin()
        assert await child.wait_for_exit() == 0
        await page.wait_for_socket_closed()
        await _port_closes(child.port)


async def test_the_child_exits_when_the_window_process_dies(desktop, journey):
    sandbox = desktop.child_sandbox()
    journey.staging.mkdir(parents=True, exist_ok=True)
    stderr_log = journey.staging / "window-stand-in.stderr.log"
    with stderr_log.open("wb") as stderr:
        parent = subprocess.Popen(
            [sys.executable, str(WINDOW_STAND_IN), str(CHILD_STARTUP_TIMEOUT)],
            env=desktop.child_env(sandbox),
            cwd=sandbox.base,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
        )
    child_pid = None
    try:
        line = await asyncio.wait_for(
            asyncio.to_thread(parent.stdout.readline), CHILD_STARTUP_TIMEOUT + 10
        )
        assert line, stderr_log.read_text(encoding="utf-8", errors="replace")
        started = json.loads(line)
        child_pid = started["pid"]
        require_armed(journey.armed_log, pid=parent.pid)
        require_armed(journey.armed_log, pid=child_pid)

        async with desktop.browser() as browser:
            page = await _start_session(browser, started["origin"], started["token"])
            # The window process is killed outright: no chance to clean up.
            os.kill(parent.pid, signal.SIGKILL)
            await asyncio.to_thread(parent.wait, CHILD_EXIT_TIMEOUT)
            await wait_until(
                lambda: not process_is_running(child_pid),
                timeout=CHILD_EXIT_TIMEOUT,
                desc="the orphaned desktop child to exit",
            )
            await page.wait_for_socket_closed()
            port = int(started["origin"].rsplit(":", 1)[1])
            await _port_closes(port)
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait()
        for stream in (parent.stdin, parent.stdout):
            stream.close()
        if child_pid is not None:
            kill_sandbox_process(child_pid, sandbox.base)


async def test_quitting_the_app_stops_the_child(desktop):
    async with desktop.child() as child, desktop.browser() as browser:
        page = await _start_session(browser, child.origin, child.token.encoded_value())
        await page.press("Control+q")
        assert await child.wait_for_exit() == 0
        await page.wait_for_socket_closed()
        await _port_closes(child.port)


async def test_reloading_the_page_ends_the_session(desktop):
    async with desktop.child() as child, desktop.browser() as browser:
        token = child.token.encoded_value()
        page = await _start_session(browser, child.origin, token)
        # The session is single-use: a reload ends it, and with it the child.
        # (The one window that could reconnect already used its token.)
        await page.page.reload(wait_until="commit")
        assert await child.wait_for_exit() == 0
        await _port_closes(child.port)
        with pytest.raises(OSError):
            await upgrade_status(child.port, session_headers(child.port, token))
