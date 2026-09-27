"""Open the packaged desktop window and prove its page reaches the app.

Starts the frozen ``servonaut-desktop`` launcher the way a user does, on the X
display of the calling environment (``xvfb-run`` in CI) and with an isolated
HOME. The check passes once the private child logs that the page opened the
authenticated session WebSocket. Getting there needs the GTK binding, the
native window, the page, the one-shot session hand-over and the host to work
together, so a window that stays blank never passes. The window is then
photographed, the security labels its processes run under are recorded, and
the launcher stopped; every process it started must exit with it.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping
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
_DISPLAY_VARIABLES = ("DISPLAY", "XAUTHORITY")
_POLL_SECONDS = 0.25
_OS_RELEASE = Path("/etc/os-release")
_DIAGNOSTIC_TAIL_BYTES = 4000
_SCREENSHOT_TIMEOUT_SECONDS = 30
# Where Linux shows a process's security label: AppArmor's own file first,
# then the one every security module shares.
_SECURITY_LABEL_FILES = (Path("attr") / "apparmor" / "current", Path("attr") / "current")


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

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2) + "\n"


def host_platform(os_release: Path = _OS_RELEASE) -> str:
    """The distribution the window ran on, such as ``ubuntu-24.04``."""
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


def session_connected(log_text: str) -> bool:
    """Whether the child's log records the page's authenticated session."""
    return any(line.endswith(SESSION_CONNECTED_LINE) for line in log_text.splitlines())


def window_environment(home: Path, inherited: Mapping[str, str]) -> dict[str, str]:
    """The isolated smoke environment, plus the display and a private runtime dir."""
    missing = [name for name in ("DISPLAY",) if not inherited.get(name)]
    if missing:
        raise WindowSmokeError("the window smoke needs an X display; run it under xvfb-run")
    environment = isolated_child_environment(home)
    runtime_dir = home / "runtime"
    runtime_dir.mkdir(mode=0o700, exist_ok=True)
    environment["XDG_RUNTIME_DIR"] = str(runtime_dir)
    environment["PATH"] = _SYSTEM_PATH
    for name in _DISPLAY_VARIABLES:
        if inherited.get(name):
            environment[name] = inherited[name]
    return environment


def process_parents(proc_root: Path = Path("/proc")) -> dict[int, int]:
    """Map every live (non-zombie) process to its parent."""
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
    """The security labels of *pids*, grouped by command name.

    Processes that exited, and hosts without a security module, add nothing.
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
) -> WindowSmokeReport:
    """Launch the packaged window, wait for its session, photograph it, stop it."""
    if target_name not in policy.window_smoke_targets:
        raise WindowSmokeError(f"the window smoke does not cover {target_name}")
    launcher = payload_root.resolve(strict=True) / "servonaut-desktop"
    if not launcher.is_file() or not os.access(launcher, os.X_OK):
        raise WindowSmokeError(f"packaged launcher is missing: {launcher}")

    with tempfile.TemporaryDirectory(prefix="servonaut-desktop-window-") as scratch:
        home = Path(scratch) / "home"
        home.mkdir(mode=0o700)
        environment = window_environment(home, inherited)
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
                _capture_screenshot(screenshot, inherited, required=False)
                raise WindowSmokeError(
                    _startup_failure(process, policy, reached)
                    + _diagnostics(home, stderr_path)
                )
            time.sleep(policy.window_render_settle_seconds)
            captured = _capture_screenshot(screenshot, inherited, required=True)
            started_tree = descendants(process.pid, process_parents())
            labels = security_labels({process.pid, *started_tree})
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
        host_platform=host_platform(),
        session_connected=True,
        connect_elapsed_ms=connect_elapsed_ms,
        screenshot_captured=captured,
        launcher_exit_code=exit_code,
        process_tree_exited=tree_exited,
        process_security_labels=labels,
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
    destination: Path | None, inherited: Mapping[str, str], *, required: bool
) -> bool:
    """Photograph the whole display with ImageMagick's ``import``.

    A failed run is photographed on a best-effort basis; the photograph of a
    connected window is required.
    """
    if destination is None:
        return False
    program = shutil.which("import", path=inherited.get("PATH"))
    captured = False
    if program is not None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            completed = subprocess.run(
                [program, "-window", "root", str(destination)],
                env=dict(inherited),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=_SCREENSHOT_TIMEOUT_SECONDS,
                check=False,
            )
            captured = completed.returncode == 0 and destination.is_file()
        except (OSError, subprocess.TimeoutExpired):
            captured = False
    if required and not captured:
        raise WindowSmokeError("the display could not be photographed with import")
    return captured


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
        description="Open the packaged desktop window under an X display and "
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
    args = parser.parse_args(argv)

    try:
        target = load_desktop_target_spec(args.target)
        report = run_window_smoke(
            args.payload_root,
            target.name,
            load_desktop_smoke_policy(args.policy),
            screenshot=args.screenshot,
        )
    except DesktopSmokeError as error:
        sys.stderr.write(f"Window smoke failed: {error}\n")
        return 1
    if args.evidence_dir is not None:
        args.evidence_dir.mkdir(parents=True, exist_ok=True)
        report_name = f"window-smoke-report-{target.name}-on-{report.host_platform}.json"
        (args.evidence_dir / report_name).write_text(report.to_json(), encoding="utf-8")
    print(
        f"Window smoke succeeded for {target.name} on {report.host_platform}: "
        f"session opened after {report.connect_elapsed_ms} ms"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
