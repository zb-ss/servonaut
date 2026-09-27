"""The packaged-window smoke, driven by stand-in launchers instead of a GTK build.

A stand-in launcher behaves like the frozen one where the smoke can tell: it
writes the child's log under its HOME and starts a child that exits once its
parent is gone, like the real child's parent-death watchdog.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from scripts.desktop_shell import window_smoke
from scripts.desktop_shell.smoke_artifact import load_desktop_smoke_policy

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc and runs POSIX launchers"
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TARGET = "linux-x64-ubuntu-22.04"
_DISPLAY = {"DISPLAY": ":99", "PATH": os.environ.get("PATH", "/usr/bin:/bin")}

# The child reads the pipe its parent holds, so it sees EOF when the parent dies.
_CHILD = "import sys; sys.stdin.read()"
_LAUNCHER = """\
#!{python}
import os, subprocess, sys, time
from pathlib import Path

child = subprocess.Popen(
    [sys.executable, "-c", {child!r}], stdin=subprocess.PIPE, start_new_session=True
)
logs = Path(os.environ["HOME"]) / ".servonaut" / "logs"
logs.mkdir(parents=True, exist_ok=True)
(logs / "desktop.log").write_text("launcher started\\n")
sys.stderr.write("Gtk-WARNING: stand-in launcher\\n")
{behaviour}
time.sleep(300)
"""
_CONNECTS = """\
(logs / "servonaut.log").write_text(
    "2026-09-27 10:00:00,000 INFO    [servonaut.desktop.host] {message}\\n"
)
"""


def _host_session_message() -> str:
    """The host's constant, read without importing the host's aiohttp stack."""
    tree = ast.parse((_REPO_ROOT / "src/servonaut/desktop/host.py").read_text())
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "SESSION_CONNECTED_MESSAGE"
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("host.py defines no SESSION_CONNECTED_MESSAGE")


SESSION_CONNECTED_MESSAGE = _host_session_message()


@pytest.fixture
def policy() -> window_smoke.DesktopSmokePolicy:
    return dataclasses.replace(
        load_desktop_smoke_policy(),
        window_session_timeout_seconds=10,
        window_render_settle_seconds=0,
        window_shutdown_timeout_seconds=10,
    )


def _payload(tmp_path: Path, behaviour: str, child: str = _CHILD) -> Path:
    payload = tmp_path / "payload"
    payload.mkdir()
    launcher = payload / "servonaut-desktop"
    launcher.write_text(
        _LAUNCHER.format(python=sys.executable, child=child, behaviour=behaviour)
    )
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR)
    return payload


def _fake_import(tmp_path: Path) -> dict[str, str]:
    """An ImageMagick ``import`` stand-in that writes the file it is given."""
    tools = tmp_path / "tools"
    tools.mkdir()
    program = tools / "import"
    program.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "from pathlib import Path\n"
        "assert sys.argv[1:3] == ['-window', 'root']\n"
        "Path(sys.argv[3]).write_bytes(b'\\x89PNG')\n"
    )
    program.chmod(0o755)
    return {**_DISPLAY, "PATH": f"{tools}:{_DISPLAY['PATH']}"}


def test_the_marker_is_the_hosts_session_message() -> None:
    assert window_smoke.SESSION_CONNECTED_LINE.endswith(f"] {SESSION_CONNECTED_MESSAGE}")
    line = f"2026-09-27 10:00:00,000 INFO    [servonaut.desktop.host] {SESSION_CONNECTED_MESSAGE}"
    assert window_smoke.session_connected(f"earlier line\n{line}\n")
    assert not window_smoke.session_connected(
        f"2026-09-27 INFO    [servonaut.app] {SESSION_CONNECTED_MESSAGE} (quoted)\n"
    )


def test_a_connected_window_is_photographed_and_stopped_with_its_children(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy
) -> None:
    payload = _payload(tmp_path, _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE))
    screenshot = tmp_path / "shots" / "window.png"

    report = window_smoke.run_window_smoke(
        payload, _TARGET, policy, screenshot=screenshot, inherited=_fake_import(tmp_path)
    )

    assert report.session_connected is True
    assert report.screenshot_captured is True
    assert screenshot.read_bytes() == b"\x89PNG"
    assert report.launcher_exit_code == -15
    assert report.process_tree_exited is True
    written = json.loads(report.to_json())
    assert written["target"] == _TARGET
    # Whatever the host's security module says, the report carries it.
    assert all(
        labels and labels == sorted(labels)
        for labels in written["process_security_labels"].values()
    )


def test_a_blank_window_fails_after_the_bound_with_its_logs(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy
) -> None:
    payload = _payload(tmp_path, "")
    policy = dataclasses.replace(policy, window_session_timeout_seconds=1)
    screenshot = tmp_path / "window.png"

    with pytest.raises(window_smoke.WindowSmokeError) as raised:
        window_smoke.run_window_smoke(
            payload, _TARGET, policy, screenshot=screenshot, inherited=_fake_import(tmp_path)
        )

    message = str(raised.value)
    assert "did not open its authenticated session within 1s" in message
    assert "Gtk-WARNING: stand-in launcher" in message
    assert "launcher started" in message
    # The failure is photographed too.
    assert screenshot.is_file()


def test_a_launcher_that_dies_early_fails_with_its_exit_code(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy
) -> None:
    payload = _payload(tmp_path, "sys.exit(3)")

    with pytest.raises(window_smoke.WindowSmokeError, match="exited with code 3"):
        window_smoke.run_window_smoke(payload, _TARGET, policy, screenshot=None, inherited=_DISPLAY)


def test_a_child_that_outlives_the_launcher_fails_and_is_killed(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy
) -> None:
    payload = _payload(
        tmp_path,
        _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE),
        child="import time; time.sleep(300)",
    )
    policy = dataclasses.replace(policy, window_shutdown_timeout_seconds=1)
    before = window_smoke.process_parents()

    with pytest.raises(window_smoke.WindowSmokeError, match="outlived it"):
        window_smoke.run_window_smoke(payload, _TARGET, policy, screenshot=None, inherited=_DISPLAY)

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
            tmp_path, "windows-x64", policy, screenshot=None, inherited=_DISPLAY
        )


def test_a_connected_window_needs_its_photograph(
    tmp_path: Path, policy: window_smoke.DesktopSmokePolicy
) -> None:
    payload = _payload(tmp_path, _CONNECTS.format(message=SESSION_CONNECTED_MESSAGE))
    no_tools = {**_DISPLAY, "PATH": str(tmp_path / "empty")}

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
    assert environment["PATH"] == "/usr/local/bin:/usr/bin:/bin"
    runtime = Path(environment["XDG_RUNTIME_DIR"])
    assert runtime.is_relative_to(home)
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o700


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
        (evidence / f"window-smoke-report-{_TARGET}-on-ubuntu-24.04.json").read_text()
    )
    assert written["connect_elapsed_ms"] == 1200

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
