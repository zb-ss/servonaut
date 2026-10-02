"""The packaged-window smoke, driven by stand-in launchers instead of a GTK build.

A stand-in launcher behaves like the frozen one where the smoke can tell: it
connects to the display server its environment names, writes the child's log
under its HOME and starts a child that exits once its parent is gone, like the
real child's parent-death watchdog. Stand-in display servers are real Unix
sockets where libxcb and libwayland look for them, so the smoke's proof of
which one the window used reads the kernel's real socket table.
"""

from __future__ import annotations

import ast
import contextlib
import dataclasses
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from scripts.desktop_shell import window_smoke
from scripts.desktop_shell.smoke_artifact import load_desktop_smoke_policy

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc and runs POSIX launchers"
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TARGET = "linux-x64-ubuntu-22.04"
_PATH = os.environ.get("PATH", "/usr/bin:/bin")
# A display number no real X server of the test host uses.
_X_DISPLAY_NUMBER = 900000 + os.getpid() % 90000
_X_SOCKET = f"\0/tmp/.X11-unix/X{_X_DISPLAY_NUMBER}"

# The child reads the pipe its parent holds, so it sees EOF when the parent dies.
_CHILD = "import sys; sys.stdin.read()"
# Like GTK, the stand-in connects to the compositor of WAYLAND_DISPLAY, or to
# the X server of DISPLAY in the abstract namespace, where libxcb looks first,
# and waits for the server's greeting.
_CONNECTS_TO_ITS_DISPLAY = """\
display = socket.socket(socket.AF_UNIX)
if os.environ.get("WAYLAND_DISPLAY"):
    display.connect(os.environ["WAYLAND_DISPLAY"])
    display.recv(1)
elif os.environ.get("DISPLAY"):
    display.connect("\\0/tmp/.X11-unix/X" + os.environ["DISPLAY"].lstrip(":"))
    display.recv(1)
"""
_LAUNCHER = """\
#!{python}
import os, socket, subprocess, sys, time
from pathlib import Path

{display_connection}
child = subprocess.Popen(
    [sys.executable, "-c", {child!r}], stdin=subprocess.PIPE, start_new_session=True
)
logs = Path(os.environ["HOME"]) / ".servonaut" / "logs"
logs.mkdir(parents=True, exist_ok=True)
(logs / "desktop.log").write_text("launcher started\\n")
sys.stderr.write("Gtk-WARNING: stand-in launcher\\n")
{wayland_requests}
{behaviour}
time.sleep(300)
"""
# Like libwayland under WAYLAND_DEBUG=client, the stand-in logs the requests
# it sends, among them the app id its window announces.
_WAYLAND_REQUESTS = """\
if os.environ.get("WAYLAND_DEBUG") == "client":
    sys.stderr.write({requests!r})
"""
_CONNECTS = """\
(logs / "servonaut.log").write_text(
    "2026-09-27 10:00:00,000 INFO    [servonaut.desktop.host] {message}\\n"
)
"""


def _product_constant(module: str, name: str) -> str:
    """A constant of the product's *module*, read without importing its dependencies."""
    tree = ast.parse((_REPO_ROOT / "src" / "servonaut" / module).read_text())
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{module} defines no {name}")


# The host's, without the host's aiohttp stack.
SESSION_CONNECTED_MESSAGE = _product_constant("desktop/host.py", "SESSION_CONNECTED_MESSAGE")


@contextlib.contextmanager
def _display_server(address: str) -> Iterator[None]:
    """Accept and greet connections on *address* until the test ends."""
    server = socket.socket(socket.AF_UNIX)
    server.bind(address)
    server.listen()
    server.settimeout(0.1)
    stop = threading.Event()
    accepted: list[socket.socket] = []

    def serve() -> None:
        while not stop.is_set():
            try:
                connection = server.accept()[0]
            except TimeoutError:
                continue
            accepted.append(connection)
            connection.sendall(b"\0")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join()
        server.close()
        for connection in accepted:
            connection.close()


@pytest.fixture
def x_display() -> Iterator[dict[str, str]]:
    """The environment of an X session with a stand-in X server."""
    with _display_server(_X_SOCKET):
        yield {"DISPLAY": f":{_X_DISPLAY_NUMBER}", "PATH": _PATH}


@pytest.fixture
def wayland_display() -> Iterator[dict[str, str]]:
    """The environment of a Wayland session with a stand-in compositor."""
    # A Unix socket path must fit in 108 bytes; pytest's tmp_path may not.
    with tempfile.TemporaryDirectory(prefix="wl-", dir="/tmp") as runtime_dir:
        with _display_server(str(Path(runtime_dir) / "wayland-test")):
            yield {"WAYLAND_DISPLAY": "wayland-test", "XDG_RUNTIME_DIR": runtime_dir, "PATH": _PATH}


@pytest.fixture
def policy() -> window_smoke.DesktopSmokePolicy:
    return dataclasses.replace(
        load_desktop_smoke_policy(),
        window_session_timeout_seconds=10,
        window_render_settle_seconds=0,
        window_shutdown_timeout_seconds=10,
    )


def _wayland_requests(app_id: str | None) -> str:
    """What libwayland logs of a window that announces *app_id*, or none."""
    requests = "[1234567.890] {Default Queue}  -> xdg_toplevel#39.set_title(\"Servonaut\")\n"
    if app_id is not None:
        requests += (
            f"[1234567.891] {{Default Queue}}  -> xdg_toplevel#39.set_app_id(\"{app_id}\")\n"
        )
    return _WAYLAND_REQUESTS.format(requests=requests)


def _payload(
    tmp_path: Path,
    behaviour: str,
    child: str = _CHILD,
    display_connection: str = _CONNECTS_TO_ITS_DISPLAY,
    app_id: str | None = window_smoke.LINUX_APP_ID,
) -> Path:
    payload = tmp_path / "payload"
    payload.mkdir()
    launcher = payload / "servonaut-desktop"
    launcher.write_text(
        _LAUNCHER.format(
            python=sys.executable,
            child=child,
            behaviour=behaviour,
            display_connection=display_connection,
            wayland_requests=_wayland_requests(app_id),
        )
    )
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR)
    return payload


def _tool(tmp_path: Path, name: str, source: str) -> Path:
    tools = tmp_path / "tools"
    tools.mkdir(exist_ok=True)
    program = tools / name
    program.write_text(f"#!{sys.executable}\nimport os, sys\nfrom pathlib import Path\n{source}")
    program.chmod(0o755)
    return tools


def _fake_import(tmp_path: Path, session: dict[str, str]) -> dict[str, str]:
    """An ImageMagick ``import`` stand-in that writes the file it is given."""
    tools = _tool(
        tmp_path,
        "import",
        "assert sys.argv[1:3] == ['-window', 'root']\n"
        "Path(sys.argv[3]).write_bytes(b'\\x89PNG')\n",
    )
    return {**session, "PATH": f"{tools}:{session['PATH']}"}


def _fake_weston_screenshooter(tmp_path: Path, session: dict[str, str]) -> dict[str, str]:
    """A ``weston-screenshooter`` stand-in: it names its file, in its working directory."""
    tools = _tool(
        tmp_path,
        "weston-screenshooter",
        "assert sys.argv[1:] == [] and os.environ['WAYLAND_DISPLAY']\n"
        "Path('wayland-screenshot-2026-09-27_10-00-00.png').write_bytes(b'\\x89PNG wayland')\n",
    )
    return {**session, "PATH": f"{tools}:{session['PATH']}"}


def test_the_marker_is_the_hosts_session_message() -> None:
    assert window_smoke.SESSION_CONNECTED_LINE.endswith(f"] {SESSION_CONNECTED_MESSAGE}")
    line = f"2026-09-27 10:00:00,000 INFO    [servonaut.desktop.host] {SESSION_CONNECTED_MESSAGE}"
    assert window_smoke.session_connected(f"earlier line\n{line}\n")
    assert not window_smoke.session_connected(
        f"2026-09-27 INFO    [servonaut.app] {SESSION_CONNECTED_MESSAGE} (quoted)\n"
    )


def test_a_connected_window_is_photographed_and_stopped_with_its_children(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy, x_display: dict[str, str]
) -> None:
    payload = _payload(tmp_path, _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE))
    screenshot = tmp_path / "shots" / "window.png"

    report = window_smoke.run_window_smoke(
        payload, _TARGET, policy, screenshot=screenshot, inherited=_fake_import(tmp_path, x_display)
    )

    assert report.session_connected is True
    assert report.screenshot_captured is True
    assert screenshot.read_bytes() == b"\x89PNG"
    assert report.launcher_exit_code == -15
    assert report.process_tree_exited is True
    written = json.loads(report.to_json())
    assert written["target"] == _TARGET
    assert written["display_protocols"] == ["x11"]
    assert written["window_app_ids"] == []
    # Whatever the host's security module says, the report carries it.
    assert all(
        labels and labels == sorted(labels)
        for labels in written["process_security_labels"].values()
    )


def test_a_blank_window_fails_after_the_bound_with_its_logs(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy, x_display: dict[str, str]
) -> None:
    payload = _payload(tmp_path, "")
    policy = dataclasses.replace(policy, window_session_timeout_seconds=1)
    screenshot = tmp_path / "window.png"

    with pytest.raises(window_smoke.WindowSmokeError) as raised:
        window_smoke.run_window_smoke(
            payload,
            _TARGET,
            policy,
            screenshot=screenshot,
            inherited=_fake_import(tmp_path, x_display),
        )

    message = str(raised.value)
    assert "did not open its authenticated session within 1s" in message
    assert "Gtk-WARNING: stand-in launcher" in message
    assert "launcher started" in message
    # The failure is photographed too.
    assert screenshot.is_file()


def test_a_launcher_that_dies_early_fails_with_its_exit_code(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy, x_display: dict[str, str]
) -> None:
    payload = _payload(tmp_path, "sys.exit(3)")

    with pytest.raises(window_smoke.WindowSmokeError, match="exited with code 3"):
        window_smoke.run_window_smoke(
            payload, _TARGET, policy, screenshot=None, inherited=x_display
        )


def test_a_child_that_outlives_the_launcher_fails_and_is_killed(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy, x_display: dict[str, str]
) -> None:
    payload = _payload(
        tmp_path,
        _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE),
        child="import time; time.sleep(300)",
    )
    policy = dataclasses.replace(policy, window_shutdown_timeout_seconds=1)
    before = window_smoke.process_parents()

    with pytest.raises(window_smoke.WindowSmokeError, match="outlived it"):
        window_smoke.run_window_smoke(
            payload, _TARGET, policy, screenshot=None, inherited=x_display
        )

    leftovers = {
        pid
        for pid in window_smoke.process_parents().keys() - before.keys()
        if "time.sleep(300)" in _cmdline(pid)
    }
    assert leftovers == set()


def _cmdline(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode()
    except OSError:
        return ""


def test_the_window_needs_a_display(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy
) -> None:
    payload = _payload(tmp_path, "")

    with pytest.raises(window_smoke.WindowSmokeError, match="needs an X display"):
        window_smoke.run_window_smoke(payload, _TARGET, policy, screenshot=None, inherited={})


def test_the_window_smoke_covers_only_its_policy_targets(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy
) -> None:
    with pytest.raises(window_smoke.WindowSmokeError, match="does not cover windows-x64"):
        window_smoke.run_window_smoke(
            tmp_path, "windows-x64", policy, screenshot=None, inherited={"DISPLAY": ":99"}
        )


def test_a_connected_window_needs_its_photograph(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy, x_display: dict[str, str]
) -> None:
    payload = _payload(tmp_path, _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE))
    no_tools = {**x_display, "PATH": str(tmp_path / "empty")}

    with pytest.raises(window_smoke.WindowSmokeError, match="could not be photographed"):
        window_smoke.run_window_smoke(
            payload, _TARGET, policy, screenshot=tmp_path / "w.png", inherited=no_tools
        )


def test_the_environment_is_isolated_but_keeps_the_display(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()

    environment = window_smoke.window_environment(
        home, {"DISPLAY": ":99", "XAUTHORITY": "/tmp/xauth", "AWS_PROFILE": "prod"}
    )

    assert environment["HOME"] == str(home)
    assert environment["DISPLAY"] == ":99"
    assert environment["XAUTHORITY"] == "/tmp/xauth"
    assert "AWS_PROFILE" not in environment
    assert "WAYLAND_DEBUG" not in environment
    assert environment["PATH"] == "/usr/local/bin:/usr/bin:/bin"
    runtime = Path(environment["XDG_RUNTIME_DIR"])
    assert runtime.is_relative_to(home)
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o700


# Wayland: the same smoke on a compositor, held there by GDK_BACKEND and by
# having no X display, and proven there by the window's socket connections.


def test_a_wayland_window_is_proven_connected_to_the_compositor_and_photographed(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy, wayland_display: dict[str, str]
) -> None:
    payload = _payload(tmp_path, _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE))
    screenshot = tmp_path / "shots" / "window.png"

    report = window_smoke.run_window_smoke(
        payload,
        _TARGET,
        policy,
        screenshot=screenshot,
        inherited=_fake_weston_screenshooter(tmp_path, wayland_display),
        display="wayland",
    )

    assert report.display_protocols == ["wayland"]
    assert report.window_app_ids == [window_smoke.LINUX_APP_ID]
    assert report.screenshot_captured is True
    assert screenshot.read_bytes() == b"\x89PNG wayland"
    assert report.process_tree_exited is True


@pytest.mark.parametrize(
    ("app_id", "announced"), [("servonaut-desktop", "servonaut-desktop"), (None, "none")]
)
def test_a_wayland_window_must_announce_the_launchers_app_id(
    tmp_path: Path,
    policy: window_smoke.DesktopSmokePolicy,
    wayland_display: dict[str, str],
    app_id: str | None,
    announced: str,
) -> None:
    payload = _payload(
        tmp_path, _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE), app_id=app_id
    )

    with pytest.raises(window_smoke.WindowSmokeError) as raised:
        window_smoke.run_window_smoke(
            payload, _TARGET, policy, screenshot=None, inherited=wayland_display, display="wayland"
        )

    assert f"announced the app id {announced}, not {window_smoke.LINUX_APP_ID}" in str(
        raised.value
    )


def test_an_x11_window_is_not_asked_for_its_app_id(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy, x_display: dict[str, str]
) -> None:
    payload = _payload(
        tmp_path, _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE), app_id="servonaut-desktop"
    )

    report = window_smoke.run_window_smoke(
        payload, _TARGET, policy, screenshot=None, inherited=x_display
    )

    assert report.window_app_ids == []


def test_app_ids_are_read_from_both_libwayland_log_formats() -> None:
    log = (
        # libwayland before 1.22 names objects with "@", which is not an address.
        '[ 12.345]  -> xdg_toplevel@12.set_app_id("dev.servonaut.Servonaut")\n'  # leak-guard:allow
        '[1234567.890] {Default Queue}  -> xdg_toplevel#39.set_title("set_app_id(\\"x\\")")\n'
        '[1234567.891] {Default Queue}  -> xdg_toplevel#39.set_app_id("dev.servonaut.Servonaut")\n'
    )

    assert window_smoke.wayland_app_ids(log) == ["dev.servonaut.Servonaut"]
    assert window_smoke.wayland_app_ids("(servonaut-desktop:42): Gtk-WARNING **: x\n") == []


def test_the_launchers_diagnostics_leave_out_libwayland_requests() -> None:
    log = (
        "[1234567.890] {Default Queue}  -> wl_display#1.get_registry(new id wl_registry#2)\n"
        "(servonaut-desktop:42): Gtk-WARNING **: the problem\n"
        "[1234567.891] {Display Queue} wl_display#1.delete_id(3)"
    )

    assert window_smoke.without_wayland_debug(log) == (
        "(servonaut-desktop:42): Gtk-WARNING **: the problem\n"
    )


def test_the_app_id_is_the_launchers_and_its_desktop_entrys() -> None:
    assert _product_constant("desktop/launcher.py", "LINUX_APP_ID") == window_smoke.LINUX_APP_ID
    entry = _REPO_ROOT / "packaging" / "deb" / f"{window_smoke.LINUX_APP_ID}.desktop"
    assert f"StartupWMClass={window_smoke.LINUX_APP_ID}" in entry.read_text().splitlines()


def test_a_wayland_window_that_falls_back_to_x11_fails(
    tmp_path: Path,
    policy: window_smoke.DesktopSmokePolicy,
    wayland_display: dict[str, str],
    x_display: dict[str, str],
) -> None:
    falls_back = (
        "display = socket.socket(socket.AF_UNIX)\n"
        f"display.connect({_X_SOCKET!r})\n"
        "display.recv(1)\n"
    )
    payload = _payload(
        tmp_path, _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE), display_connection=falls_back
    )

    with pytest.raises(window_smoke.WindowSmokeError) as raised:
        window_smoke.run_window_smoke(
            payload, _TARGET, policy, screenshot=None, inherited=wayland_display, display="wayland"
        )

    assert "opened on wayland, but its processes were connected to x11" in str(raised.value)


def test_a_window_connected_to_no_display_server_fails(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy, x_display: dict[str, str]
) -> None:
    payload = _payload(
        tmp_path, _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE), display_connection=""
    )

    with pytest.raises(window_smoke.WindowSmokeError, match="connected to no display server"):
        window_smoke.run_window_smoke(
            payload, _TARGET, policy, screenshot=None, inherited=x_display
        )


def test_a_wayland_window_needs_a_compositor(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy
) -> None:
    payload = _payload(tmp_path, "")

    x11_only = {"DISPLAY": ":99"}

    with pytest.raises(window_smoke.WindowSmokeError, match="needs a Wayland compositor"):
        window_smoke.run_window_smoke(
            payload, _TARGET, policy, screenshot=None, inherited=x11_only, display="wayland"
        )
    with pytest.raises(window_smoke.WindowSmokeError, match="unknown display server 'mir'"):
        window_smoke.run_window_smoke(
            payload, _TARGET, policy, screenshot=None, inherited=x11_only, display="mir"
        )


def test_the_wayland_environment_has_no_way_back_to_x11(
    tmp_path: Path, wayland_display: dict[str, str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    inherited = {**wayland_display, "DISPLAY": ":99", "XAUTHORITY": "/tmp/xauth"}

    environment = window_smoke.window_environment(home, inherited, display="wayland")

    socket_path = Path(wayland_display["XDG_RUNTIME_DIR"]) / "wayland-test"
    assert environment["WAYLAND_DISPLAY"] == str(socket_path)
    assert environment["GDK_BACKEND"] == "wayland"
    # libwayland logs the requests of the launcher, among them its app id.
    assert environment["WAYLAND_DEBUG"] == "client"
    assert "DISPLAY" not in environment
    assert "XAUTHORITY" not in environment
    # The window keeps its own private runtime dir.
    assert Path(environment["XDG_RUNTIME_DIR"]).is_relative_to(home)


def test_the_compositor_socket_is_found_as_libwayland_finds_it(
    wayland_display: dict[str, str], tmp_path: Path
) -> None:
    runtime_dir = wayland_display["XDG_RUNTIME_DIR"]
    expected = Path(runtime_dir) / "wayland-test"

    assert window_smoke.wayland_socket(wayland_display) == expected
    assert window_smoke.wayland_socket({"WAYLAND_DISPLAY": str(expected)}) == expected
    with pytest.raises(window_smoke.WindowSmokeError, match="XDG_RUNTIME_DIR is unset"):
        window_smoke.wayland_socket({"WAYLAND_DISPLAY": "wayland-test"})
    (tmp_path / "wayland-0").write_text("")
    with pytest.raises(window_smoke.WindowSmokeError, match="no Wayland compositor listens"):
        window_smoke.wayland_socket({"WAYLAND_DISPLAY": str(tmp_path / "wayland-0")})


def test_a_wayland_photograph_is_the_one_file_the_screenshooter_names(
    tmp_path: Path, wayland_display: dict[str, str]
) -> None:
    session = _fake_weston_screenshooter(tmp_path, wayland_display)
    destination = tmp_path / "shots" / "wayland.png"

    assert window_smoke._capture_screenshot(
        destination, session, required=True, system="linux", display="wayland"
    )
    assert destination.read_bytes() == b"\x89PNG wayland"
    with pytest.raises(window_smoke.WindowSmokeError, match="with weston-screenshooter"):
        window_smoke._capture_screenshot(
            tmp_path / "none.png",
            {**wayland_display, "PATH": str(tmp_path / "empty")},
            required=True,
            system="linux",
            display="wayland",
        )


def _diagnostic(inode: int, *attributes: tuple[int, bytes]) -> bytes:
    """A ``unix_diag_msg`` with netlink attributes, as the kernel sends it."""
    message = struct.pack("=BBBBIII", socket.AF_UNIX, socket.SOCK_STREAM, 1, 0, inode, 0, 0)
    for kind, value in attributes:
        attribute = struct.pack("=HH", 4 + len(value), kind) + value
        message += attribute + b"\0" * (-len(attribute) % 4)
    return message


def test_unix_diagnostics_give_each_socket_its_name_and_peer() -> None:
    peer = struct.pack("=I", 41)

    assert window_smoke.parse_unix_diagnostic(
        _diagnostic(40, (0, b"/run/user/1000/wayland-0\0"), (2, peer))
    ) == (40, window_smoke.UnixSocket("/run/user/1000/wayland-0", 41))
    assert window_smoke.parse_unix_diagnostic(
        _diagnostic(42, (0, b"\0/tmp/.X11-unix/X99"))
    ) == (42, window_smoke.UnixSocket("@/tmp/.X11-unix/X99", None))
    assert window_smoke.parse_unix_diagnostic(_diagnostic(43, (2, peer))) == (
        43,
        window_smoke.UnixSocket(None, 41),
    )


def test_netlink_messages_are_split_on_their_aligned_lengths() -> None:
    first = struct.pack("=IHHII", 16 + 3, 20, 2, 1, 0) + b"abc" + b"\0"
    done = struct.pack("=IHHII", 16 + 4, 3, 2, 1, 0) + b"\0" * 4

    assert list(window_smoke.netlink_messages(first + done)) == [(20, b"abc"), (3, b"\0" * 4)]
    with pytest.raises(OSError, match="malformed"):
        list(window_smoke.netlink_messages(struct.pack("=IHHII", 64, 20, 2, 1, 0)))


def test_display_protocols_follow_each_socket_to_the_server_it_reached(tmp_path: Path) -> None:
    (tmp_path / "10" / "fd").mkdir(parents=True)
    (tmp_path / "11" / "fd").mkdir(parents=True)
    for pid, descriptor, target in (
        (10, 3, "socket:[100]"),
        (10, 4, "pipe:[7]"),
        (10, 5, "/dev/null"),
        (11, 3, "socket:[102]"),
        (11, 4, "socket:[104]"),
    ):
        (tmp_path / str(pid) / "fd" / str(descriptor)).symlink_to(target)
    sockets = {
        100: window_smoke.UnixSocket(None, 101),
        101: window_smoke.UnixSocket("/tmp/wl.abc/wayland-smoke", 100),
        102: window_smoke.UnixSocket(None, 103),
        103: window_smoke.UnixSocket("@/tmp/.X11-unix/X99", 102),
        # A connection to something else, such as a session bus.
        104: window_smoke.UnixSocket(None, 105),
        105: window_smoke.UnixSocket("/run/user/1000/bus", 104),
    }
    wayland = Path("/tmp/wl.abc//wayland-smoke")

    assert window_smoke.display_protocols(
        [10, 11, 12], wayland=wayland, sockets=sockets, proc_root=tmp_path
    ) == ["wayland", "x11"]
    assert window_smoke.display_protocols(
        [10], wayland=None, sockets=sockets, proc_root=tmp_path
    ) == []
    assert window_smoke.display_protocols(
        [11], wayland=None, sockets=sockets, proc_root=tmp_path
    ) == ["x11"]


def test_process_parents_reads_proc_and_skips_zombies(tmp_path: Path) -> None:
    for pid, stat_line in {
        "10": "10 (servonaut-desktop) S 1 10 10",
        "11": "11 (Web Content (x)) S 10 10 10",
        "12": "12 (defunct) Z 10 10 10",
    }.items():
        (tmp_path / pid).mkdir()
        (tmp_path / pid / "stat").write_text(stat_line)
    (tmp_path / "self").mkdir()
    (tmp_path / "13").mkdir()  # vanished before its stat was read

    assert window_smoke.process_parents(tmp_path) == {10: 1, 11: 10}


def test_security_labels_group_the_tree_by_command_name(tmp_path: Path) -> None:
    profile = "servonaut-desktop (unconfined)\n"
    processes = {
        # AppArmor's own attribute file, as on Ubuntu.
        "10": ("servonaut-deskt", {"attr/apparmor/current": profile}),
        # Only the shared attribute file, as on older kernels.
        "11": ("bwrap", {"attr/current": profile}),
        "12": ("bwrap", {"attr/apparmor/current": profile}),
        "13": ("WebKitWebProces", {"attr/current": "unconfined\n"}),
        # No security module: the attribute cannot be read.
        "14": ("xdg-dbus-proxy", {}),
    }
    for pid, (name, attributes) in processes.items():
        (tmp_path / pid).mkdir()
        (tmp_path / pid / "comm").write_text(f"{name}\n")
        for relative, text in attributes.items():
            (tmp_path / pid / relative).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / pid / relative).write_text(text)

    labels = window_smoke.security_labels([10, 11, 12, 13, 14, 15], tmp_path)

    assert labels == {
        "WebKitWebProces": ["unconfined"],
        "bwrap": ["servonaut-desktop (unconfined)"],
        "servonaut-deskt": ["servonaut-desktop (unconfined)"],
    }


def test_descendants_walk_the_whole_tree() -> None:
    parents = {10: 1, 11: 10, 12: 11, 13: 10, 20: 1}

    assert window_smoke.descendants(10, parents) == {11, 12, 13}
    assert window_smoke.descendants(20, parents) == set()


def test_wait_until_polls_until_the_condition_or_the_deadline() -> None:
    now = [0.0]
    answers = iter([False, False, True])

    assert window_smoke.wait_until(
        lambda: next(answers), 10, clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s)
    )
    now[0] = 0.0
    assert not window_smoke.wait_until(
        lambda: False, 1, clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s)
    )


def test_main_writes_the_report_and_fails_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    report = window_smoke.WindowSmokeReport(
        target=_TARGET,
        host_platform="ubuntu-24.04",
        session_connected=True,
        connect_elapsed_ms=1200,
        screenshot_captured=True,
        launcher_exit_code=-15,
        process_tree_exited=True,
    )
    monkeypatch.setattr(window_smoke, "run_window_smoke", lambda *args, **kwargs: report)
    evidence = tmp_path / "evidence"
    argv = ["--payload-root", str(tmp_path), "--target", _TARGET, "--evidence-dir", str(evidence)]

    assert window_smoke.main(argv) == 0
    written = json.loads(
        (evidence / f"window-smoke-report-{_TARGET}-on-ubuntu-24.04-x11.json").read_text()
    )
    assert written["connect_elapsed_ms"] == 1200
    assert window_smoke.main([*argv, "--display", "wayland"]) == 0
    assert (evidence / f"window-smoke-report-{_TARGET}-on-ubuntu-24.04-wayland.json").is_file()

    def fail(*args: object, **kwargs: object) -> None:
        raise window_smoke.WindowSmokeError("blank")

    monkeypatch.setattr(window_smoke, "run_window_smoke", fail)
    assert window_smoke.main(argv) == 1
    assert "Window smoke failed: blank" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ('NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n', "ubuntu-24.04"),
        ("ID=debian\nVERSION_ID=12\n", "debian-12"),
        ("NAME=Something\n", "unknown"),
        (None, "unknown"),
    ],
)
def test_the_report_names_the_host_it_ran_on(
    tmp_path: Path, content: str | None, expected: str
) -> None:
    os_release = tmp_path / "os-release"
    if content is not None:
        os_release.write_text(content)

    assert window_smoke.host_platform(os_release) == expected


# macOS: the same smoke, from the executable inside the app bundle, in the
# login session. These run the macOS code paths against stand-ins on Linux.


def _fake_screencapture(tmp_path: Path) -> dict[str, str]:
    """A ``screencapture`` stand-in that writes the file it is given, silently."""
    tools = tmp_path / "tools"
    tools.mkdir()
    program = tools / "screencapture"
    program.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "from pathlib import Path\n"
        "assert sys.argv[1:2] == ['-x']\n"
        "Path(sys.argv[2]).write_bytes(b'\\x89PNG macOS')\n"
    )
    program.chmod(0o755)
    return {"PATH": f"{tools}:{os.environ.get('PATH', '/usr/bin:/bin')}"}


def test_a_macos_window_needs_no_x_display_and_is_photographed_with_screencapture(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(window_smoke.platform, "mac_ver", lambda: ("15.6", ("", "", ""), "arm64"))
    payload = _payload(tmp_path, _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE))
    screenshot = tmp_path / "shots" / "window.png"

    report = window_smoke.run_window_smoke(
        payload,
        "macos-arm64",
        policy,
        screenshot=screenshot,
        inherited=_fake_screencapture(tmp_path),
        system="darwin",
    )

    assert report.session_connected is True
    assert report.host_platform == "macos-15.6"
    assert screenshot.read_bytes() == b"\x89PNG macOS"
    assert report.process_tree_exited is True


def test_a_macos_window_reports_no_security_labels(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Security labels are Linux's (/proc/*/attr); macOS has none to read."""

    def linux_only(*args: object, **kwargs: object) -> None:
        raise AssertionError("macOS processes carry no Linux security label")

    monkeypatch.setattr(window_smoke, "security_labels", linux_only)
    payload = _payload(tmp_path, _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE))

    report = window_smoke.run_window_smoke(
        payload,
        "macos-x64",
        policy,
        screenshot=tmp_path / "window.png",
        inherited=_fake_screencapture(tmp_path),
        system="darwin",
    )

    assert report.process_security_labels == {}
    assert json.loads(report.to_json())["process_security_labels"] == {}


def test_a_macos_window_needs_its_photograph(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy
) -> None:
    payload = _payload(tmp_path, _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE))

    with pytest.raises(window_smoke.WindowSmokeError, match="photographed with screencapture"):
        window_smoke.run_window_smoke(
            payload,
            "macos-x64",
            policy,
            screenshot=tmp_path / "w.png",
            inherited={"PATH": str(tmp_path / "empty")},
            system="darwin",
        )


def test_the_macos_environment_is_isolated_without_display_variables(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()

    environment = window_smoke.window_environment(
        home, {"DISPLAY": ":99", "AWS_PROFILE": "prod"}, system="darwin"
    )

    assert environment["HOME"] == str(home)
    assert environment["PATH"] == "/usr/local/bin:/usr/bin:/bin"
    assert "DISPLAY" not in environment
    assert "XDG_RUNTIME_DIR" not in environment
    assert "AWS_PROFILE" not in environment


def test_ps_output_maps_live_processes_to_their_parents() -> None:
    listing = "\n".join(
        [
            "    1     0 Ss",
            "  410     1 S",
            "  411   410 R+",
            "  412   410 Z",
            "  bad line",
            "",
        ]
    )

    assert window_smoke.parse_ps_parents(listing) == {1: 0, 410: 1, 411: 410}


def test_without_proc_the_process_list_comes_from_ps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(window_smoke, "_ps_listing", lambda: "  20     1 S\n  21    20 S\n")

    assert window_smoke.process_parents(tmp_path / "no-proc") == {20: 1, 21: 20}


@pytest.mark.parametrize(("version", "expected"), [("15.6.1", "macos-15.6.1"), ("", "unknown")])
def test_the_report_names_the_macos_release(
    monkeypatch: pytest.MonkeyPatch, version: str, expected: str
) -> None:
    monkeypatch.setattr(window_smoke.platform, "mac_ver", lambda: (version, ("", "", ""), ""))

    assert window_smoke.host_platform(system="darwin") == expected


def test_the_policy_covers_the_macos_app_targets() -> None:
    assert {"macos-x64", "macos-arm64"} <= load_desktop_smoke_policy().window_smoke_targets


def test_glib_problems_are_counted_without_their_messages() -> None:
    log = "\n".join(
        [
            "(servonaut-desktop:41): Gdk-CRITICAL **: 10:00:00.000: gdk_seat_get_keyboard: failed",
            "(servonaut-desktop:41): Gdk-CRITICAL **: 10:00:00.001: gdk_seat_get_keyboard: failed",
            "(WebKitWebProcess:42): GLib-GObject-WARNING **: 10:00:00.002: invalid cast",
            "** (servonaut-desktop:41): WARNING **: 10:00:00.003: no domain",
            "Gtk-Message: 10:00:00.004: Failed to load module",
            "Gtk-WARNING: stand-in launcher",
            "a message quoting (x:1): Gtk-CRITICAL **: later on the line",
        ]
    )

    assert window_smoke.glib_problems(log) == {
        "GLib-GObject-WARNING": 1,
        "Gdk-CRITICAL": 2,
        "default-WARNING": 1,
    }
    assert window_smoke.glib_problems("") == {}


def test_a_connected_window_reports_its_launchers_glib_problems(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy, x_display: dict[str, str]
) -> None:
    complains = (
        "sys.stderr.write('(servonaut-desktop:7): Gtk-CRITICAL **: 10:00:00.000: x\\n')\n"
        "sys.stderr.flush()\n"
    )
    payload = _payload(
        tmp_path, complains + _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE)
    )

    report = window_smoke.run_window_smoke(
        payload, _TARGET, policy, screenshot=None, inherited=x_display
    )

    assert report.launcher_glib_problems == {"Gtk-CRITICAL": 1}


def test_reports_are_named_after_the_session_the_window_ran_in() -> None:
    assert window_smoke.session_name("ubuntu-26.04", "wayland", system="linux") == (
        "ubuntu-26.04-wayland"
    )
    # A macOS login session has one window server; its reports keep their names.
    assert window_smoke.session_name("macos-15.6", "x11", system="darwin") == "macos-15.6"


# weston_run.sh: the Wayland session the forward qualification opens the window
# in, run here against a stand-in compositor that listens where weston would.

_WESTON_RUN = _REPO_ROOT / "scripts" / "desktop_shell" / "weston_run.sh"
_FAKE_WESTON = """\
import socket, time

options = dict(argument.split("=", 1) for argument in sys.argv[1:] if "=" in argument)
Path(options["--log"]).write_text("stand-in weston: " + " ".join(sys.argv[1:]) + "\\n")
{behaviour}
listener = socket.socket(socket.AF_UNIX)
listener.bind(os.path.join(os.environ["XDG_RUNTIME_DIR"], options["--socket"]))
listener.listen()
time.sleep(300)
"""
_PRINTS_ITS_SESSION = (
    "import os, sys; from pathlib import Path; "
    "runtime = os.environ['XDG_RUNTIME_DIR']; "
    "print(os.environ.get('DISPLAY'), os.environ['WAYLAND_DISPLAY'], runtime, "
    "Path(runtime, os.environ['WAYLAND_DISPLAY']).is_socket()); "
    "sys.exit(int(sys.argv[1]))"
)


def _weston_run(
    tmp_path: Path, behaviour: str, status: int = 0
) -> subprocess.CompletedProcess[str]:
    tools = _tool(tmp_path, "weston", _FAKE_WESTON.format(behaviour=behaviour))
    return subprocess.run(
        ["bash", str(_WESTON_RUN), sys.executable, "-c", _PRINTS_ITS_SESSION, str(status)],
        env={"PATH": f"{tools}:{_PATH}", "DISPLAY": ":99", "XAUTHORITY": "/tmp/xauth"},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_weston_run_gives_the_command_a_wayland_session_without_x11(tmp_path: Path) -> None:
    completed = _weston_run(tmp_path, "")

    assert completed.returncode == 0, completed.stderr
    display, wayland, runtime, listening = completed.stdout.split()
    assert (display, wayland, listening) == ("None", "wayland-smoke", "True")
    # Short enough for a socket path, and gone with the compositor.
    assert runtime.startswith("/tmp/weston.")
    assert not Path(runtime).exists()


def test_weston_run_returns_the_commands_status_with_the_compositor_log(tmp_path: Path) -> None:
    completed = _weston_run(tmp_path, "", status=7)

    assert completed.returncode == 7
    assert "--- weston log (tail) ---" in completed.stderr
    assert "stand-in weston: --backend=headless --renderer=pixman" in completed.stderr


def test_weston_run_fails_when_the_compositor_does_not_start(tmp_path: Path) -> None:
    completed = _weston_run(tmp_path, "sys.exit('no headless backend')")

    assert completed.returncode == 1
    assert "weston did not start its headless compositor" in completed.stderr
    assert "stand-in weston:" in completed.stderr
    assert completed.stdout == ""
