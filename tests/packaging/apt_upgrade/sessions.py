"""Real packaged TUI, desktop child, MCP and relay sessions for the APT fixture."""

from __future__ import annotations

import asyncio
import errno
import fcntl
import io
import json
import os
import pty
import pwd
import select
import socket
import struct
import subprocess
import termios
import time
from contextlib import AsyncExitStack, ExitStack
from pathlib import Path

from aiohttp import ClientSession, WSMsgType, web

from scripts.desktop_shell.window_smoke import descendants, process_parents, session_connected
from servonaut.config.schema import CONFIG_VERSION
from servonaut.desktop.control import encode_control_frame, read_child_frame
from servonaut.desktop.model import PosixListener, ReadyResponse, SecretToken, StartRequest

TIMEOUT = 25
LAUNCHER = "/usr/bin/servonaut"
DESKTOP = "/opt/servonaut/servonaut-desktop-child"
GUI = "/opt/servonaut/servonaut-desktop"
ROOT = Path("/opt/servonaut/generations")


def environment(home: Path) -> dict[str, str]:
    home.mkdir()
    return {
        "PATH": os.defpath, "HOME": str(home), "TERM": "xterm-256color",
        "LC_ALL": "C.UTF-8", "NO_PROXY": "*", "SERVONAUT_SKIP_AUTO_APPLY": "1",
        "SERVONAUT_APT_RUNTIME_POLL_SECONDS": "5",
    }


def read_until(fd: int, predicate) -> bytes:
    end = time.monotonic() + TIMEOUT
    received = bytearray()
    while time.monotonic() < end:
        if not select.select([fd], [], [], 0.1)[0]:
            continue
        try:
            part = os.read(fd, 32 * 1024)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            break
        if not part:
            break
        received.extend(part)
        if predicate(received):
            return bytes(received)
    raise AssertionError(f"Session did not produce the expected output: {received[-3000:]!r}")


def stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def spawn(stack: ExitStack, argv: list[str], home: Path, **kwargs) -> subprocess.Popen:
    log = stack.enter_context((home.parent / f"{home.name}.log").open("wb"))
    kwargs.setdefault("stderr", log)
    process = subprocess.Popen(argv, **kwargs)
    stack.callback(stop, process)
    return process


def gui(stack: ExitStack, home: Path, generation: str) -> tuple[int, int]:
    """Open the real packaged window and identify its own spawned child."""
    env = environment(home)
    user = pwd.getpwnam("nobody")
    os.chown(home, user.pw_uid, user.pw_gid)
    runtime = home / "run"
    runtime.mkdir(mode=0o700)
    os.chown(runtime, user.pw_uid, user.pw_gid)

    reading, writing = os.pipe()
    try:
        display = subprocess.Popen(
            ["Xvfb", "-displayfd", str(writing), "-nolisten", "tcp", "-screen", "0", "1280x800x24"],
            pass_fds=(writing,), user="nobody", env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        stack.callback(stop, display)
        os.close(writing)
        writing = -1
        number = read_until(reading, lambda data: b"\n" in data).decode().strip()
    finally:
        os.close(reading)
        if writing >= 0:
            os.close(writing)
    env.update({"DISPLAY": f":{number}", "GDK_BACKEND": "x11", "XDG_RUNTIME_DIR": str(runtime)})
    process = spawn(stack, [GUI], home, user="nobody", env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, start_new_session=True)
    expected = ROOT / generation
    child_log = home / ".servonaut" / "logs" / "servonaut.log"
    end = time.monotonic() + TIMEOUT
    while process.poll() is None and time.monotonic() < end:
        if child_log.is_file() and session_connected(child_log.read_text(errors="replace")):
            require_native_path(process.pid, expected / "servonaut-desktop")
            for pid in descendants(process.pid, process_parents()):
                if read_native_path(pid) == expected / "servonaut-desktop-child":
                    return process.pid, pid
        time.sleep(0.1)
    errors = (home.parent / f"{home.name}.log").read_text(errors="replace")
    logs = child_log.read_text(errors="replace")[-4000:] if child_log.is_file() else ""
    raise AssertionError(f"Packaged desktop window did not connect (status {process.poll()}):\n{errors}\n{logs}")


def read_native_path(pid: int) -> Path | None:
    entry = Path("/proc") / str(pid) / "exe"
    try:
        return entry.readlink()
    except PermissionError:
        # The offline container can omit SYS_PTRACE for root. Read the link
        # with the same user as the GUI rather than adding that capability.
        result = subprocess.run(["readlink", str(entry)], capture_output=True, text=True,
                                timeout=5, user="nobody")
        return Path(result.stdout.strip()) if result.returncode == 0 else None
    except FileNotFoundError:
        return None


def require_native_path(pid: int, expected: Path) -> None:
    actual = read_native_path(pid)
    assert actual == expected.resolve(), (actual, expected)


def tui(stack: ExitStack, home: Path) -> tuple[subprocess.Popen, int]:
    master, slave = pty.openpty()
    stack.callback(os.close, master)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 160, 0, 0))
    try:
        proc = spawn(
            stack, [LAUNCHER, "--demo"], home, stdin=slave, stdout=slave, stderr=slave,
            env=environment(home), start_new_session=True,
        )
    finally:
        os.close(slave)
    read_until(master, lambda data: b"Help" in data)
    return proc, master


def open_settings(fd: int) -> None:
    os.write(fd, b"\x10")
    read_until(fd, lambda data: b"Command" in data or b"Search" in data)
    os.write(fd, b"Settings")
    read_until(fd, lambda data: b"Settings" in data)
    os.write(fd, b"\r")
    read_until(fd, lambda data: b"General" in data)


def restart_terminal(process: subprocess.Popen, fd: int, generation: str) -> None:
    """Choose the restart and wait for the same terminal to run the new payload."""
    os.write(fd, b"\x10")
    read_until(fd, lambda data: b"Command" in data or b"Search" in data)
    os.write(fd, b"Restart Servonaut")
    read_until(fd, lambda data: b"start the installed version" in data)
    os.write(fd, b"\r")
    read_until(fd, lambda data: b"Save your work first" in data)
    os.write(fd, b"y")
    expected = (ROOT / generation / "servonaut").resolve()
    read_until(fd, lambda data: b"Help" in data and read_native_path(process.pid) == expected)


class Mcp:
    def __init__(self, stack: ExitStack, home: Path) -> None:
        self.proc = spawn(
            stack, [LAUNCHER, "--mcp"], home, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            env=environment(home),
        )
        self.pending = bytearray()
        self.counter = 0
        self.server = self.call("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "upgrade-fixture", "version": "1"},
        })["serverInfo"]
        self.send({"method": "notifications/initialized"})

    def send(self, body: dict) -> None:
        self.proc.stdin.write((json.dumps({"jsonrpc": "2.0", **body}) + "\n").encode())
        self.proc.stdin.flush()

    def call(self, method: str, params: dict | None = None) -> dict:
        self.counter += 1
        self.send({"id": self.counter, "method": method, "params": params or {}})
        end = time.monotonic() + TIMEOUT
        while time.monotonic() < end:
            if b"\n" not in self.pending:
                wait = max(0, end - time.monotonic())
                assert select.select([self.proc.stdout], [], [], wait)[0], "MCP response timed out"
                chunk = os.read(self.proc.stdout.fileno(), 64 * 1024)
                assert chunk, "Packaged MCP stdout closed"
                self.pending.extend(chunk)
                continue
            raw, _, rest = self.pending.partition(b"\n")
            self.pending[:] = rest
            message = json.loads(raw)
            assert message["jsonrpc"] == "2.0"
            if message.get("id") == self.counter:
                assert "error" not in message, message
                return message["result"]
        raise AssertionError("MCP response timed out")


async def desktop(stack: ExitStack, connections: AsyncExitStack, home: Path):
    listener = stack.enter_context(socket.socket())
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
    token = SecretToken.generate()
    proc = spawn(
        stack, [DESKTOP], home, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        env=environment(home), pass_fds=(listener.fileno(),),
    )
    request = StartRequest(origin, token, PosixListener(listener.fileno()))
    proc.stdin.write(encode_control_frame(request))
    proc.stdin.flush()
    ready = await asyncio.to_thread(
        read_until, proc.stdout.fileno(),
        lambda data: len(data) >= 4 and len(data) >= 4 + struct.unpack(">I", data[:4])[0],
    )
    assert read_child_frame(io.BytesIO(ready)) == ReadyResponse(origin)
    client = await connections.enter_async_context(ClientSession())
    ws = await connections.enter_async_context(client.ws_connect(
        f"{origin}/ws", origin=origin, protocols=("servonaut.desktop.v1", f"auth.{token.encoded_value()}"),
    ))
    await ws.send_json(["resize", {"width": 160, "height": 50}])
    await ping(ws, "before")
    return proc, ws


async def ping(ws, name: str) -> None:
    await ws.send_json(["ping", name])
    while not ws.closed:
        response = await ws.receive(timeout=TIMEOUT)
        if response.type == WSMsgType.TEXT and response.json() == ["pong", name]:
            return
    raise AssertionError("Packaged desktop WebSocket closed")


async def desktop_output(ws, needle: bytes) -> None:
    async def receive_until() -> None:
        received = bytearray()
        while not ws.closed:
            packet = await ws.receive()
            if packet.type == WSMsgType.BINARY:
                received.extend(packet.data)
                if needle in received:
                    return
        raise AssertionError(f"The packaged desktop closed before displaying {needle!r}")

    await asyncio.wait_for(receive_until(), timeout=TIMEOUT)


async def restart_desktop_child(process: subprocess.Popen, ws) -> None:
    from servonaut.services.apt_runtime import APT_RESTART_EXIT_CODE

    await ws.send_json(["stdin", "\x10"])
    await desktop_output(ws, b"Search")
    await ws.send_json(["stdin", "Restart Servonaut"])
    await desktop_output(ws, b"start the installed version")
    await ws.send_json(["stdin", "\r"])
    await desktop_output(ws, b"Save your work first")
    await ws.send_json(["stdin", "y"])
    assert await asyncio.to_thread(process.wait, TIMEOUT) == APT_RESTART_EXIT_CODE


class Relay:
    def __init__(self) -> None:
        self.connection = asyncio.Event()
        self.closed = asyncio.Event()
        self.received = asyncio.Queue()
        self.server = web.Application()
        self.server.add_routes([
            web.get("/api/cli/mercure-token", self.token),
            web.get("/hub", self.hub),
            web.post("/api/cli/heartbeat", self.heartbeat),
        ])

    async def start(self, stack: ExitStack, connections: AsyncExitStack, home: Path):
        runner = web.AppRunner(self.server)
        await runner.setup()
        connections.push_async_callback(runner.cleanup)
        listener = stack.enter_context(socket.socket())
        listener.bind(("127.0.0.1", 0))
        endpoint = f"http://127.0.0.1:{listener.getsockname()[1]}"
        await web.SockSite(runner, listener).start()
        env = environment(home)
        settings = home / ".servonaut"
        settings.mkdir()
        config = settings / "config.json"
        config.write_text(json.dumps({
            "version": CONFIG_VERSION, "ssh": {"team_options_checked": True},
            "relay": {"base_url": endpoint, "mercure_url": f"{endpoint}/hub", "heartbeat_interval": 2},
        }), encoding="utf-8")
        env.update({
            "SERVONAUT_RELAY_TOKEN": "fixture-bearer", "SERVONAUT_USER_ID": "fixture-user",
            "SERVONAUT_API_URL": endpoint, "SERVONAUT_MCP_URL": endpoint,
        })
        output = home.parent / "relay-output.log"
        stdout = stack.enter_context(output.open("wb"))
        proc = spawn(stack, [LAUNCHER, "--debug", "connect"], home, stdout=stdout, env=env,
                     stdin=subprocess.DEVNULL)
        try:
            await asyncio.wait_for(self.connection.wait(), timeout=TIMEOUT)
        except asyncio.TimeoutError as error:
            errors = (home.parent / f"{home.name}.log").read_text(errors="replace")
            logs = "\n".join(path.read_text(errors="replace")[-4000:]
                             for path in (settings / "logs").glob("*.log"))
            raise AssertionError(
                f"Relay did not start (status {proc.poll()}):\n"
                f"{output.read_text(errors='replace')}\n{errors}\n{logs}"
            ) from error
        return proc, config

    async def token(self, request: web.Request) -> web.Response:
        return web.json_response({"token": "fixture-subscriber"})

    async def hub(self, request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        await response.write(b": ready\n\n")
        self.connection.set()
        await self.closed.wait()
        return response

    async def heartbeat(self, request: web.Request) -> web.Response:
        await self.received.put((request.headers.get("X-Servonaut-Client"), await request.json()))
        # Keep the handshake unacknowledged so each attempt carries the
        # version, including in builds that predate the client header.
        return web.json_response({"ok": False}, status=503)

    async def report(self, version: str, *, require_header: bool = False) -> str:
        header, payload = await asyncio.wait_for(self.received.get(), timeout=TIMEOUT)
        assert payload["type"] == "cli.handshake" and payload["version"] == version, payload
        if require_header or header is not None:
            assert header is not None
            assert header.startswith(f"{version};") and "kind=relay" in header, header
        return payload["client_id"]


def require_generation(processes: list[subprocess.Popen], generation: str) -> None:
    for process in processes:
        assert process.poll() is None
        image = (Path("/proc") / str(process.pid) / "exe").readlink()
        assert image.parent == ROOT / generation, image
