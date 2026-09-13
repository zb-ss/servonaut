"""Opt-in real-socket tests; install scripts/desktop_probe/requirements.txt."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import AsyncIterator, Callable
from dataclasses import replace

import pytest
import pytest_asyncio

aiohttp = pytest.importorskip("aiohttp")
pytest.importorskip("textual_serve")
psutil = pytest.importorskip("psutil")

from scripts.desktop_probe.host import ProbeHost, terminal_size


@pytest_asyncio.fixture
async def host(
    record_property: Callable[[str, object], None],
) -> AsyncIterator[ProbeHost]:
    instance = ProbeHost()
    await instance.start()
    try:
        yield instance
    finally:
        await instance.stop()
        record_property("child_errors", instance.child.errors)


def protocols(host: ProbeHost) -> tuple[str, str]:
    return "servonaut-probe", f"auth.{host._token}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "origin", [None, "null", "https://example.com", "http://localhost"]
)
async def test_rejects_foreign_or_missing_origin(
    host: ProbeHost, origin: str | None
) -> None:
    async with aiohttp.ClientSession() as client:
        with pytest.raises(aiohttp.WSServerHandshakeError) as error:
            await client.ws_connect(
                host.origin + "/ws?width=120&height=40",
                origin=origin,
                protocols=protocols(host),
            )
        assert error.value.status == 403
        assert host.child.process is None


@pytest.mark.asyncio
@pytest.mark.parametrize("supplied", [(), ("servonaut-probe", "auth.wrong")])
async def test_rejects_missing_or_invalid_token(
    host: ProbeHost, supplied: tuple[str, ...]
) -> None:
    async with aiohttp.ClientSession() as client:
        with pytest.raises(aiohttp.WSServerHandshakeError) as error:
            await client.ws_connect(
                host.origin + "/ws?width=120&height=40",
                origin=host.origin,
                protocols=supplied,
            )
        assert error.value.status == 403
        assert host.child.process is None


@pytest.mark.asyncio
async def test_assets_are_closed_and_do_not_disclose_token(host: ProbeHost) -> None:
    async with aiohttp.ClientSession() as client:
        for path in ("/", "/bootstrap.js", "/style.css", "/textual.js"):
            async with client.get(host.origin + path) as response:
                assert response.status == 200
                assert host._token not in await response.text()
                csp = response.headers["Content-Security-Policy"]
                assert "script-src 'self';" in csp
                assert "unsafe-eval" not in csp
                assert response.headers["Cache-Control"] == "no-store"
        for path in (
            "/static/",
            "/download/example",
            "/debug",
            "/?ping=https://example.com",
        ):
            async with client.get(host.origin + path) as response:
                assert response.status in {400, 404}
        async with client.get(host.origin, headers={"Host": "example.com"}) as response:
            assert response.status == 403


async def read_until(websocket: aiohttp.ClientWebSocketResponse, text: bytes) -> bytes:
    async def collect() -> bytes:
        result = b""
        async for message in websocket:
            if message.type == aiohttp.WSMsgType.BINARY:
                result += message.data
                if text in result:
                    return result
        raise AssertionError("Child closed before expected screen rendered")

    return await asyncio.wait_for(collect(), 20)


@pytest.mark.asyncio
async def test_real_app_help_single_session_replay_and_cleanup(host: ProbeHost) -> None:
    url = host.origin + "/ws?width=140&height=45"
    async with aiohttp.ClientSession() as client:
        websocket = await client.ws_connect(
            url, origin=host.origin, protocols=protocols(host)
        )
        assert websocket.protocol == "servonaut-probe"  # Never echo the credential.
        await read_until(websocket, b"web-1")
        await websocket.send_json(["stdin", "?"])
        await read_until(websocket, b"Navigation")
        with pytest.raises(aiohttp.WSServerHandshakeError) as error:
            await client.ws_connect(url, origin=host.origin, protocols=protocols(host))
        assert error.value.status == 409
        await websocket.close()
        await asyncio.wait_for(host.finished.wait(), 10)
        assert host.child.process.returncode == 0
        with pytest.raises(aiohttp.WSServerHandshakeError) as replay:
            await client.ws_connect(url, origin=host.origin, protocols=protocols(host))
        assert replay.value.status == 409
    await host.stop()
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", int(host.origin.rsplit(":", 1)[1]))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", [{}, ["resize", {"width": 99999, "height": 30}], ["stdin", 7]]
)
async def test_invalid_messages_close_session(host: ProbeHost, payload: object) -> None:
    async with aiohttp.ClientSession() as client:
        websocket = await client.ws_connect(
            host.origin + "/ws?width=120&height=40",
            origin=host.origin,
            protocols=protocols(host),
        )
        await read_until(websocket, b"web-1")
        await websocket.send_str(json.dumps(payload))
        async for _ in websocket:
            pass
        assert websocket.close_code == 1008


@pytest.mark.asyncio
async def test_child_crash_closes_socket(host: ProbeHost) -> None:
    async with aiohttp.ClientSession() as client:
        websocket = await client.ws_connect(
            host.origin + "/ws?width=120&height=40",
            origin=host.origin,
            protocols=protocols(host),
        )
        await read_until(websocket, b"web-1")
        host.child.process.kill()
        await asyncio.wait_for(host.finished.wait(), 10)
        assert host.child.process.returncode != 0
        async for _ in websocket:
            pass


@pytest.mark.asyncio
async def test_startup_timeout_reaps_direct_child() -> None:
    # Fixture sleeps deliberately to prove bounded readiness, not timing-based startup.
    host = ProbeHost((sys.executable, "-c", "import time; time.sleep(60)"))
    host.child.config = replace(host.config, startup_seconds=0.2, shutdown_seconds=0.2)
    await host.start()
    try:
        async with aiohttp.ClientSession() as client:
            websocket = await client.ws_connect(
                host.origin + "/ws?width=120&height=40",
                origin=host.origin,
                protocols=protocols(host),
            )
            async for _ in websocket:
                pass
            await asyncio.wait_for(host.finished.wait(), 3)
            assert host.child.process.returncode is not None
    finally:
        await host.stop()


@pytest.mark.parametrize(
    "value", [{}, {"width": True, "height": 1}, {"width": -1, "height": 1}]
)
def test_terminal_dimensions_are_bounded(value: dict) -> None:
    from scripts.desktop_probe.config import load_config

    with pytest.raises((TypeError, ValueError)):
        terminal_size(value, load_config())


@pytest.mark.asyncio
async def test_two_hosts_get_distinct_ports() -> None:
    first, second = ProbeHost(), ProbeHost()
    try:
        await asyncio.gather(first.start(), second.start())
        assert first.origin != second.origin
    finally:
        await asyncio.gather(first.stop(), second.stop())


@pytest.mark.asyncio
@pytest.mark.parametrize("dimensions", ["", "?width=0&height=1", "?width=80&height=no"])
async def test_bad_handshake_does_not_consume_session(
    host: ProbeHost, dimensions: str
) -> None:
    async with aiohttp.ClientSession() as client:
        with pytest.raises(aiohttp.WSServerHandshakeError) as error:
            await client.ws_connect(
                host.origin + "/ws" + dimensions,
                origin=host.origin,
                protocols=protocols(host),
            )
        assert error.value.status == 400
        assert not host._used
        assert host.child.process is None


@pytest.mark.asyncio
async def test_killed_parent_leaves_no_running_child_or_listener() -> None:
    # A separate process owns both the listener and the child's stdin pipe.
    source = """
import asyncio, json
from scripts.desktop_probe.host import ProbeHost
async def main():
    host = ProbeHost()
    await host.start()
    await host.child.start(120, 40)
    announced = False
    async def receive(data):
        nonlocal announced
        if not announced and b'web-1' in data:
            print(json.dumps({'pid': host.child.process.pid, 'origin': host.origin}), flush=True)
            announced = True
    await host.child.forward(receive)
asyncio.run(main())
"""
    parent = await asyncio.create_subprocess_exec(
        sys.executable,
        "-u",
        "-c",
        source,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    child = None

    def is_running() -> bool:
        try:
            # Keep the Process identity to avoid acting on a recycled PID.
            # A reparented zombie has exited; its reaping belongs to the OS.
            return child.is_running() and child.status() != psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            return False

    try:
        info = json.loads(await asyncio.wait_for(parent.stdout.readline(), 20))
        child = psutil.Process(info["pid"])
        parent.kill()
        await parent.wait()

        async def wait_for_exit() -> None:
            while is_running():
                await asyncio.sleep(0.05)

        await asyncio.wait_for(wait_for_exit(), 10)
        with pytest.raises(OSError):
            await asyncio.open_connection(
                "127.0.0.1", int(info["origin"].rsplit(":", 1)[1])
            )
    finally:
        if parent.returncode is None:
            parent.kill()
        await parent.wait()
        if child is not None and is_running():
            child.kill()


def test_native_host_thread_failure_reaches_launcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.desktop_probe.__main__ import HostThread

    runtime = HostThread()

    async def fail_after_startup() -> None:
        runtime.ready.set_result(None)
        raise ValueError("Synthetic failure after readiness")

    monkeypatch.setattr(runtime, "_serve", fail_after_startup)
    runtime.thread.start()
    with pytest.raises(RuntimeError, match="Probe host failed"):
        runtime.stop()


@pytest.mark.asyncio
async def test_child_error_before_readiness_is_bounded_and_redacted() -> None:
    from scripts.desktop_probe.config import load_config
    from scripts.desktop_probe.process import TextualChild

    # Noise larger than a pipe buffer must not block readiness/error collection.
    source = """
import sys
from scripts.desktop_probe.diagnostics import exception_hook
sys.excepthook = exception_hook
sys.stderr.write('unstructured noise' * 65536 + '\\n')
raise ValueError('auth.synthetic-credential')
"""
    child = TextualChild((sys.executable, "-c", source), load_config())
    try:
        with pytest.raises(RuntimeError, match="did not become ready"):
            await child.start(120, 40)
    finally:
        await child.stop()
    assert len(child.errors) == 1
    assert child.errors[0]["exception"] == "ValueError"
    assert "synthetic-credential" not in str(child.errors)
    assert "unstructured noise" not in str(child.errors)
