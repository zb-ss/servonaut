"""Open the packaged desktop window and prove its page reaches the app.

Starts the frozen ``servonaut-desktop`` launcher the way a user does, with an
isolated HOME: on Linux on the X display or the Wayland compositor of the
calling environment (``xvfb-run`` or ``weston_run.sh`` in CI), on macOS in the
calling user's login session, from the executable inside the app bundle. The
check passes once the private child logs that the page opened the
authenticated session WebSocket. Getting there needs the window toolkit
binding, the native window, the page, the one-shot session hand-over and the
host to work together, so a window that stays blank never passes. The window
is then photographed; on Linux the security labels its processes run under
are recorded, and the display servers they are connected to must be exactly
the one asked for, so a Wayland window that fell back to X11 fails. The
launcher is then stopped; every process it started must exit with it.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path

from scripts.desktop_shell.model import load_desktop_target_spec
from scripts.desktop_shell.smoke_artifact import (
    DesktopSmokeError,
    DesktopSmokePolicy,
    load_desktop_smoke_policy,
)
from scripts.standalone_cli.smoke_artifact import isolated_child_environment

# servonaut.desktop.host.SESSION_CONNECTED_MESSAGE, as the child's log writes it.
SESSION_CONNECTED_LINE = "[servonaut.desktop.host] Desktop session connected"
_CHILD_LOG = Path(".servonaut") / "logs" / "servonaut.log"
_LAUNCHER_LOG = Path(".servonaut") / "logs" / "desktop.log"
# A desktop session has the system PATH; the credential-free smoke default of
# an empty one would hide tools the host's GTK stack may start.
_SYSTEM_PATH = "/usr/local/bin:/usr/bin:/bin"
# The display servers a Linux window can be opened on.
X11 = "x11"
WAYLAND = "wayland"
DISPLAY_SERVERS = (X11, WAYLAND)
_X11_VARIABLES = ("DISPLAY", "XAUTHORITY")
# Where an X server listens, by path or by the same name in the abstract
# namespace ("@").
_X11_SOCKET_RE = re.compile(r"@?/tmp/\.X11-unix/X\d+")
_SOCKET_LINK_RE = re.compile(r"socket:\[(\d+)\]")
# Linux lists processes in /proc; macOS has no /proc and asks ps.
_PS = "/bin/ps"
_PS_TIMEOUT_SECONDS = 10
_POLL_SECONDS = 0.25
_OS_RELEASE = Path("/etc/os-release")
_DIAGNOSTIC_TAIL_BYTES = 4000
_SCREENSHOT_TIMEOUT_SECONDS = 30
# Where Linux shows a process's security label: AppArmor's own file first,
# then the one every security module shares.
_SECURITY_LABEL_FILES = (Path("attr") / "apparmor" / "current", Path("attr") / "current")

# The kernel's Unix socket diagnostics (what ``ss -x`` reads), from
# linux/netlink.h, linux/sock_diag.h and linux/unix_diag.h.
_NETLINK_SOCK_DIAG = 4
_SOCK_DIAG_BY_FAMILY = 20
_NLM_F_REQUEST = 0x1
_NLM_F_DUMP = 0x300
_NLMSG_ERROR = 2
_NLMSG_DONE = 3
_UDIAG_SHOW_NAME = 0x1
_UDIAG_SHOW_PEER = 0x4
_UNIX_DIAG_NAME = 0
_UNIX_DIAG_PEER = 2
_ALL_STATES = 0xFFFFFFFF
_NO_COOKIE = 0xFFFFFFFF
_NLMSG_HEADER = struct.Struct("=IHHII")
_UNIX_DIAG_REQUEST = struct.Struct("=BBHIIIII")
_UNIX_DIAG_MESSAGE = struct.Struct("=BBBBIII")
_NETLINK_ATTRIBUTE = struct.Struct("=HH")
_NETLINK_ERROR = struct.Struct("=i")
_PEER_INODE = struct.Struct("=I")
_NETLINK_RECEIVE_BYTES = 1 << 17


@dataclass(frozen=True)
class _Photographer:
    """A tool that photographs the whole screen.

    ``names_its_file`` tools write one PNG into their working directory
    instead of taking the destination as their last argument.
    """

    program: str
    arguments: tuple[str, ...]
    names_its_file: bool = False


# ImageMagick's import on an X display; weston's screenshooter, which weston
# serves only when started with --debug; the system's screencapture (silent,
# -x) in a macOS session.
_PHOTOGRAPHERS = {
    X11: _Photographer("import", ("-window", "root")),
    WAYLAND: _Photographer("weston-screenshooter", (), names_its_file=True),
    "darwin": _Photographer("screencapture", ("-x",)),
}


class WindowSmokeError(DesktopSmokeError):
    """Raised when the packaged window does not reach an authenticated session."""


@dataclass(frozen=True)
class WindowSmokeReport:
    """Public, content-free result of one packaged-window smoke run."""

    target: str
    host_platform: str
    session_connected: bool
    connect_elapsed_ms: int
    screenshot_captured: bool
    launcher_exit_code: int
    process_tree_exited: bool
    # Command name -> the labels processes of that name ran under, such as
    # WebKit's bubblewrap under the launcher's AppArmor profile.
    process_security_labels: dict[str, list[str]] = field(default_factory=dict)
    # The display servers the window's processes were connected to, ["x11"]
    # or ["wayland"]; macOS reports none.
    display_protocols: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2) + "\n"


def host_platform(os_release: Path = _OS_RELEASE, *, system: str = sys.platform) -> str:
    """The system the window ran on, such as ``ubuntu-24.04`` or ``macos-15.6``."""
    if system == "darwin":
        version = platform.mac_ver()[0]
        return f"macos-{version}" if version else "unknown"
    fields: dict[str, str] = {}
    try:
        lines = os_release.read_text(encoding="utf-8").splitlines()
    except OSError:
        return "unknown"
    for line in lines:
        key, separator, value = line.partition("=")
        if separator:
            fields[key.strip()] = value.strip().strip('"')
    distribution, version = fields.get("ID"), fields.get("VERSION_ID")
    if not distribution or not version:
        return "unknown"
    return f"{distribution}-{version}"


def session_name(host: str, display: str, *, system: str = sys.platform) -> str:
    """Where a window ran, as its report is named: ``ubuntu-24.04-wayland``.

    A macOS login session has a single window server, so only the host.
    """
    return host if system == "darwin" else f"{host}-{display}"


def session_connected(log_text: str) -> bool:
    """Whether the child's log records the page's authenticated session."""
    return any(line.endswith(SESSION_CONNECTED_LINE) for line in log_text.splitlines())


def window_environment(
    home: Path,
    inherited: Mapping[str, str],
    *,
    system: str = sys.platform,
    display: str = X11,
) -> dict[str, str]:
    """The isolated smoke environment, plus what the window system needs.

    On Linux that is a private runtime dir and what reaches the display
    server asked for, and nothing that reaches another. A macOS app reaches
    the window server through the login session it is started in, so it
    needs no variable for it.
    """
    display_variables = {} if system == "darwin" else _display_variables(inherited, display)
    environment = isolated_child_environment(home)
    environment["PATH"] = _SYSTEM_PATH
    if system == "darwin":
        return environment
    runtime_dir = home / "runtime"
    runtime_dir.mkdir(mode=0o700, exist_ok=True)
    environment["XDG_RUNTIME_DIR"] = str(runtime_dir)
    environment.update(display_variables)
    return environment


def _display_variables(inherited: Mapping[str, str], display: str) -> dict[str, str]:
    if display == WAYLAND:
        # GTK is held to Wayland, with no X display to fall back to, and gets
        # the compositor's socket as a path, so its own runtime dir stays
        # private.
        return {"WAYLAND_DISPLAY": str(wayland_socket(inherited)), "GDK_BACKEND": WAYLAND}
    if not inherited.get("DISPLAY"):
        raise WindowSmokeError("the window smoke needs an X display; run it under xvfb-run")
    return {name: inherited[name] for name in _X11_VARIABLES if inherited.get(name)}


def wayland_socket(inherited: Mapping[str, str]) -> Path:
    """The listening socket of the compositor the calling environment names.

    WAYLAND_DISPLAY is either a path or a name in XDG_RUNTIME_DIR.
    """
    name = inherited.get("WAYLAND_DISPLAY")
    if not name:
        raise WindowSmokeError(
            "the Wayland window smoke needs a Wayland compositor; run it under weston_run.sh"
        )
    path = Path(name)
    if not path.is_absolute():
        runtime_dir = inherited.get("XDG_RUNTIME_DIR")
        if not runtime_dir:
            raise WindowSmokeError(f"WAYLAND_DISPLAY={name} is relative but XDG_RUNTIME_DIR is unset")
        path = Path(runtime_dir) / name
    try:
        listening = stat.S_ISSOCK(path.stat().st_mode)
    except OSError:
        listening = False
    if not listening:
        raise WindowSmokeError(f"no Wayland compositor listens on {path}")
    return path


def process_parents(proc_root: Path = Path("/proc")) -> dict[int, int]:
    """Map every live (non-zombie) process to its parent."""
    if not proc_root.is_dir():
        return parse_ps_parents(_ps_listing())
    parents: dict[int, int] = {}
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat_line = (entry / "stat").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # The command name may contain spaces and parentheses; the state and
        # parent follow its last closing parenthesis.
        fields = stat_line.rsplit(")", 1)[-1].split()
        if len(fields) >= 2 and fields[0] != "Z":
            parents[int(entry.name)] = int(fields[1])
    return parents


def parse_ps_parents(listing: str) -> dict[int, int]:
    """Map live processes to their parents from ``ps -o pid=,ppid=,stat=`` output."""
    parents: dict[int, int] = {}
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) < 3 or not fields[0].isdigit() or not fields[1].isdigit():
            continue
        if not fields[2].startswith("Z"):
            parents[int(fields[0])] = int(fields[1])
    return parents


def _ps_listing() -> str:
    try:
        completed = subprocess.run(
            [_PS, "-A", "-o", "pid=,ppid=,stat="],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=_PS_TIMEOUT_SECONDS,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WindowSmokeError(f"the process list could not be read: {error}") from error
    return completed.stdout


def descendants(root: int, parents: Mapping[int, int]) -> set[int]:
    """Every process below *root* in the parent map."""
    children: dict[int, list[int]] = {}
    for pid, parent in parents.items():
        children.setdefault(parent, []).append(pid)
    found: set[int] = set()
    pending = [root]
    while pending:
        for child in children.get(pending.pop(), ()):
            if child not in found:
                found.add(child)
                pending.append(child)
    return found


def security_labels(
    pids: Iterable[int], proc_root: Path = Path("/proc")
) -> dict[str, list[str]]:
    """The Linux security labels of *pids*, grouped by command name.

    Processes that exited, and hosts without a security module, add nothing.
    macOS has no such labels; the smoke reports none there.
    """
    found: dict[str, set[str]] = {}
    for pid in pids:
        entry = proc_root / str(pid)
        try:
            name = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        label = _security_label(entry)
        if label is not None:
            found.setdefault(name, set()).add(label)
    return {name: sorted(labels) for name, labels in sorted(found.items())}


def _security_label(entry: Path) -> str | None:
    for relative in _SECURITY_LABEL_FILES:
        try:
            text = (entry / relative).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        label = text.strip("\x00\n ")
        if label:
            return label
    return None


@dataclass(frozen=True)
class UnixSocket:
    """One Unix socket as the kernel reports it."""

    # The bound name, "@..." in the abstract namespace. A server's accepted
    # connections carry the name of the socket they were accepted on.
    name: str | None
    # The inode of the socket at the other end of the connection.
    peer: int | None


def display_protocols(
    pids: Iterable[int],
    *,
    wayland: Path | None,
    sockets: Mapping[int, UnixSocket] | None = None,
    proc_root: Path = Path("/proc"),
) -> list[str]:
    """The display servers *pids* are connected to: "x11", "wayland" or both.

    A client's end of a Unix socket has no name, but its peer, the end the
    server accepted, carries the name the server listens on: an X server's
    /tmp/.X11-unix/X<n>, or the compositor's *wayland* socket.
    """
    table = unix_sockets() if sockets is None else sockets
    wayland_name = None if wayland is None else os.path.normpath(wayland)
    protocols: set[str] = set()
    for inode in socket_inodes(pids, proc_root):
        entry = table.get(inode)
        peer = None if entry is None or entry.peer is None else table.get(entry.peer)
        if peer is None or peer.name is None:
            continue
        if _X11_SOCKET_RE.fullmatch(peer.name):
            protocols.add(X11)
        elif wayland_name is not None and os.path.normpath(peer.name) == wayland_name:
            protocols.add(WAYLAND)
    return sorted(protocols)


def socket_inodes(pids: Iterable[int], proc_root: Path = Path("/proc")) -> set[int]:
    """The inodes of the sockets *pids* hold open; exited processes add none."""
    inodes: set[int] = set()
    for pid in pids:
        try:
            descriptors = list((proc_root / str(pid) / "fd").iterdir())
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                match = _SOCKET_LINK_RE.fullmatch(os.readlink(descriptor))
            except OSError:
                continue
            if match:
                inodes.add(int(match.group(1)))
    return inodes


def unix_sockets() -> dict[int, UnixSocket]:
    """Every Unix socket in this network namespace by inode, as ``ss -x`` lists them."""
    request = _UNIX_DIAG_REQUEST.pack(
        socket.AF_UNIX,
        0,
        0,
        _ALL_STATES,
        0,
        _UDIAG_SHOW_NAME | _UDIAG_SHOW_PEER,
        _NO_COOKIE,
        _NO_COOKIE,
    )
    header = _NLMSG_HEADER.pack(
        _NLMSG_HEADER.size + len(request),
        _SOCK_DIAG_BY_FAMILY,
        _NLM_F_REQUEST | _NLM_F_DUMP,
        1,
        0,
    )
    try:
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, _NETLINK_SOCK_DIAG) as diagnostics:
            diagnostics.send(header + request)
            return _read_unix_diagnostics(diagnostics)
    except OSError as error:
        raise WindowSmokeError(f"the Unix sockets could not be listed: {error}") from error


def _read_unix_diagnostics(diagnostics: socket.socket) -> dict[int, UnixSocket]:
    sockets: dict[int, UnixSocket] = {}
    while True:
        data = diagnostics.recv(_NETLINK_RECEIVE_BYTES)
        if not data:
            raise OSError("the socket diagnostics ended early")
        for kind, payload in netlink_messages(data):
            if kind == _NLMSG_DONE:
                return sockets
            if kind == _NLMSG_ERROR:
                code = -_NETLINK_ERROR.unpack_from(payload)[0]
                if code:
                    raise OSError(code, os.strerror(code))
            elif kind == _SOCK_DIAG_BY_FAMILY:
                inode, entry = parse_unix_diagnostic(payload)
                sockets[inode] = entry


def netlink_messages(data: bytes) -> Iterator[tuple[int, bytes]]:
    """The (type, payload) of each netlink message in one received buffer."""
    offset = 0
    while offset + _NLMSG_HEADER.size <= len(data):
        length, kind, _flags, _sequence, _port = _NLMSG_HEADER.unpack_from(data, offset)
        if length < _NLMSG_HEADER.size or offset + length > len(data):
            raise OSError("the socket diagnostics are malformed")
        yield kind, data[offset + _NLMSG_HEADER.size : offset + length]
        offset += _aligned(length)


def parse_unix_diagnostic(payload: bytes) -> tuple[int, UnixSocket]:
    """A socket's inode, name and peer from a ``unix_diag_msg`` and its attributes."""
    inode = _UNIX_DIAG_MESSAGE.unpack_from(payload)[4]
    name: str | None = None
    peer: int | None = None
    offset = _UNIX_DIAG_MESSAGE.size
    while offset + _NETLINK_ATTRIBUTE.size <= len(payload):
        length, kind = _NETLINK_ATTRIBUTE.unpack_from(payload, offset)
        if length < _NETLINK_ATTRIBUTE.size:
            break
        value = payload[offset + _NETLINK_ATTRIBUTE.size : offset + length]
        if kind == _UNIX_DIAG_NAME:
            name = _socket_name(value)
        elif kind == _UNIX_DIAG_PEER and len(value) >= _PEER_INODE.size:
            peer = _PEER_INODE.unpack_from(value)[0]
        offset += _aligned(length)
    return inode, UnixSocket(name, peer)


def _socket_name(raw: bytes) -> str:
    # An abstract name starts with a NUL byte; ss shows it as "@".
    if raw.startswith(b"\0"):
        return "@" + os.fsdecode(raw[1:].rstrip(b"\0"))
    return os.fsdecode(raw.split(b"\0", 1)[0])


def _aligned(length: int) -> int:
    return (length + 3) & ~3


def wait_until(
    condition: Callable[[], bool],
    timeout_seconds: float,
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Poll *condition* until it holds or the timeout passes; report which."""
    deadline = clock() + timeout_seconds
    while True:
        if condition():
            return True
        if clock() >= deadline:
            return False
        sleep(_POLL_SECONDS)


def run_window_smoke(
    payload_root: Path,
    target_name: str,
    policy: DesktopSmokePolicy,
    *,
    screenshot: Path | None,
    inherited: Mapping[str, str] = os.environ,
    system: str = sys.platform,
    display: str = X11,
) -> WindowSmokeReport:
    """Launch the packaged window, wait for its session, photograph it, stop it.

    ``payload_root`` holds the launcher: the onedir payload, or the
    ``Contents/MacOS`` directory of a macOS app bundle. ``display`` is the
    display server a Linux window opens on.
    """
    if target_name not in policy.window_smoke_targets:
        raise WindowSmokeError(f"the window smoke does not cover {target_name}")
    if display not in DISPLAY_SERVERS:
        raise WindowSmokeError(f"unknown display server {display!r}")
    launcher = payload_root.resolve(strict=True) / "servonaut-desktop"
    if not launcher.is_file() or not os.access(launcher, os.X_OK):
        raise WindowSmokeError(f"packaged launcher is missing: {launcher}")

    with tempfile.TemporaryDirectory(prefix="servonaut-desktop-window-") as scratch:
        home = Path(scratch) / "home"
        home.mkdir(mode=0o700)
        environment = window_environment(home, inherited, system=system, display=display)
        stderr_path = Path(scratch) / "launcher-stderr.txt"
        with stderr_path.open("wb") as stderr:
            process = subprocess.Popen(
                [str(launcher)],
                cwd=home,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr,
            )
        started_tree: set[int] = set()
        try:
            started = time.monotonic()
            reached = wait_until(
                lambda: process.poll() is not None
                or session_connected(_read_text(home / _CHILD_LOG)),
                policy.window_session_timeout_seconds,
            )
            connect_elapsed_ms = int((time.monotonic() - started) * 1000)
            if not reached or process.poll() is not None:
                _capture_screenshot(
                    screenshot, inherited, required=False, system=system, display=display
                )
                raise WindowSmokeError(
                    _startup_failure(process, policy, reached)
                    + _diagnostics(home, stderr_path)
                )
            time.sleep(policy.window_render_settle_seconds)
            captured = _capture_screenshot(
                screenshot, inherited, required=True, system=system, display=display
            )
            started_tree = descendants(process.pid, process_parents())
            window_processes = {process.pid, *started_tree}
            labels = {} if system == "darwin" else security_labels(window_processes)
            protocols = (
                [] if system == "darwin" else _connected_display(window_processes, display, inherited)
            )
            exit_code = _stop_launcher(process, policy)
            tree_exited = wait_until(
                lambda: not started_tree & process_parents().keys(),
                policy.window_shutdown_timeout_seconds,
            )
            if not tree_exited:
                raise WindowSmokeError(
                    "processes the launcher started outlived it: "
                    f"{sorted(started_tree & process_parents().keys())}"
                )
        finally:
            _kill_leftovers(process, started_tree)

    return WindowSmokeReport(
        target=target_name,
        host_platform=host_platform(system=system),
        session_connected=True,
        connect_elapsed_ms=connect_elapsed_ms,
        screenshot_captured=captured,
        launcher_exit_code=exit_code,
        process_tree_exited=tree_exited,
        process_security_labels=labels,
        display_protocols=protocols,
    )


def _startup_failure(
    process: subprocess.Popen[bytes], policy: DesktopSmokePolicy, reached: bool
) -> str:
    code = process.poll()
    if code is not None:
        return f"the launcher exited with code {code} before the page opened its session"
    return (
        "the page did not open its authenticated session within "
        f"{policy.window_session_timeout_seconds}s (a blank window never does)"
    )


def _connected_display(
    pids: set[int], display: str, inherited: Mapping[str, str]
) -> list[str]:
    """The display servers the window is connected to, which must be *display* alone."""
    wayland = wayland_socket(inherited) if display == WAYLAND else None
    protocols = display_protocols(pids, wayland=wayland)
    if protocols != [display]:
        raise WindowSmokeError(
            f"the window was opened on {display}, but its processes were connected to "
            f"{' and '.join(protocols) or 'no display server'}"
        )
    return protocols


def _stop_launcher(
    process: subprocess.Popen[bytes], policy: DesktopSmokePolicy
) -> int:
    """Stop the launcher as a session manager would, with SIGTERM."""
    process.send_signal(signal.SIGTERM)
    try:
        return process.wait(timeout=policy.window_shutdown_timeout_seconds)
    except subprocess.TimeoutExpired as error:
        raise WindowSmokeError(
            f"the launcher ignored SIGTERM for {policy.window_shutdown_timeout_seconds}s"
        ) from error


def _kill_leftovers(process: subprocess.Popen[bytes], tree: set[int]) -> None:
    """Never leave a process of this run behind, whatever failed."""
    if process.poll() is None:
        tree = tree | descendants(process.pid, process_parents())
        process.kill()
        process.wait()
    for pid in tree & process_parents().keys():
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            continue


def _capture_screenshot(
    destination: Path | None,
    inherited: Mapping[str, str],
    *,
    required: bool,
    system: str = sys.platform,
    display: str = X11,
) -> bool:
    """Photograph the whole screen with the system's screenshot tool.

    A failed run is photographed on a best-effort basis; the photograph of a
    connected window is required.
    """
    if destination is None:
        return False
    photographer = _PHOTOGRAPHERS["darwin" if system == "darwin" else display]
    program = shutil.which(photographer.program, path=inherited.get("PATH"))
    captured = False
    if program is not None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="servonaut-window-photo-") as workdir:
            captured = _photograph(photographer, program, destination, Path(workdir), inherited)
    if required and not captured:
        raise WindowSmokeError(
            f"the display could not be photographed with {photographer.program}"
        )
    return captured


def _photograph(
    photographer: _Photographer,
    program: str,
    destination: Path,
    workdir: Path,
    inherited: Mapping[str, str],
) -> bool:
    command = [program, *photographer.arguments]
    if not photographer.names_its_file:
        command.append(str(destination))
    try:
        completed = subprocess.run(
            command,
            cwd=workdir,
            env=dict(inherited),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=_SCREENSHOT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if completed.returncode != 0:
        return False
    if photographer.names_its_file:
        photographs = list(workdir.glob("*.png"))
        if len(photographs) != 1:
            return False
        shutil.move(photographs[0], destination)
    return destination.is_file()


def _diagnostics(home: Path, stderr_path: Path) -> str:
    sections = (
        ("launcher stderr", stderr_path),
        ("launcher log", home / _LAUNCHER_LOG),
        ("child log", home / _CHILD_LOG),
    )
    return "".join(
        f"\n--- {label} (tail) ---\n{_read_text(path)[-_DIAGNOSTIC_TAIL_BYTES:]}"
        for label, path in sections
    )


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="window_smoke",
        description="Open the packaged desktop window (on an X display or a "
        "Wayland compositor on Linux, in the login session on macOS) and "
        "require its page to open the authenticated session.",
    )
    parser.add_argument("--payload-root", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--policy", type=Path, default=None)
    parser.add_argument("--evidence-dir", type=Path, default=None)
    parser.add_argument(
        "--screenshot",
        type=Path,
        default=None,
        help="PNG path for a photograph of the display, taken on failure too",
    )
    parser.add_argument(
        "--display",
        choices=DISPLAY_SERVERS,
        default=X11,
        help="Linux display server to open the window on: the X display of "
        "DISPLAY (xvfb-run) or the compositor of WAYLAND_DISPLAY (weston_run.sh)",
    )
    args = parser.parse_args(argv)

    try:
        target = load_desktop_target_spec(args.target)
        report = run_window_smoke(
            args.payload_root,
            target.name,
            load_desktop_smoke_policy(args.policy),
            screenshot=args.screenshot,
            display=args.display,
        )
    except DesktopSmokeError as error:
        sys.stderr.write(f"Window smoke failed: {error}\n")
        return 1
    session = session_name(report.host_platform, args.display)
    if args.evidence_dir is not None:
        args.evidence_dir.mkdir(parents=True, exist_ok=True)
        report_name = f"window-smoke-report-{target.name}-on-{session}.json"
        (args.evidence_dir / report_name).write_text(report.to_json(), encoding="utf-8")
    connected = "".join(f", connected to {name}" for name in report.display_protocols)
    print(
        f"Window smoke succeeded for {target.name} on {session}: "
        f"session opened after {report.connect_elapsed_ms} ms{connected}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
