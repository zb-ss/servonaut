"""GUI session owner and pywebview window launcher.

Coordinates pre-bound socket transfer, child process tree launch and handshake,
native pywebview window creation on the main thread, and strict lifecycle cleanup.
"""

from __future__ import annotations

import contextlib
import ctypes
import logging
import socket
import subprocess
import sys
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from servonaut.desktop.bridge import DesktopBootstrapBridge
from servonaut.desktop.model import ReadyResponse, SecretToken
from servonaut.desktop.process_tree import (
    OwnedProcessTree,
    ProcessTreeError,
    launch_and_handshake_desktop_child,
)
from servonaut.runtime import (
    DistributionKind,
    RuntimeLayout,
    validate_desktop_child_argv,
)

logger = logging.getLogger(__name__)

_MB_ICONERROR: Final = 0x00000010
# Text reaches AppleScript as run arguments, never spliced into its source.
_MACOS_ALERT_SCRIPT: Final = (
    "on run argv",
    "display alert (item 1 of argv) message (item 2 of argv) as critical",
    "end run",
)


class DesktopLauncherError(RuntimeError):
    """Raised when desktop session initialization or window lifecycle fails."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.code = message


@dataclass(frozen=True, slots=True)
class DesktopLaunchRequest:
    """Configuration for launching the desktop GUI and child process."""

    runtime: RuntimeLayout
    startup_timeout: float = 5.0
    shutdown_timeout: float = 2.0
    width: int = 1024
    height: int = 768
    title: str = "Servonaut"
    renderer: str | None = None
    launcher_executable: Path | None = None
    child_argv: Sequence[str] | None = None
    log_file: Path | None = None


def _bind_loopback_listener(*, platform_name: str | None = None) -> socket.socket:
    """Bind an OS-assigned loopback port that no other socket may share."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if (platform_name or sys.platform) == "win32":
            # Without exclusive use, Windows lets another socket, even one
            # owned by a different local account, bind the same port.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
    except OSError:
        listener.close()
        raise
    return listener


def show_native_error(title: str, message: str) -> None:
    """Show a blocking error dialog where the platform has one built in.

    The packaged GUI runs without a console, so a failure it only logged
    would leave the user with nothing on screen.
    """
    try:
        if sys.platform == "win32":
            ctypes.windll.user32.MessageBoxW(None, message, title, _MB_ICONERROR)
        elif sys.platform == "darwin":
            script_args = [arg for line in _MACOS_ALERT_SCRIPT for arg in ("-e", line)]
            subprocess.run(
                ["osascript", *script_args, title, message],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except (OSError, AttributeError) as exc:
        logger.warning("Could not show the startup error dialog: %s", exc)


def _report_startup_failure(request: DesktopLaunchRequest, reason: str) -> None:
    logger.error("Desktop session could not start: %s", reason)
    message = f"Servonaut could not start ({reason})."
    if request.log_file is not None:
        message += f"\n\nDetails were written to {request.log_file}"
    show_native_error(request.title, message)


class DesktopSessionOwner:
    """Owns the lifecycle of the pre-bound socket, child process tree, and bridge."""

    def __init__(self) -> None:
        self._tree: OwnedProcessTree | None = None
        self._listener: socket.socket | None = None
        self._origin: str | None = None
        self._token: SecretToken | None = None
        self._bridge: DesktopBootstrapBridge | None = None
        self._shutdown_timeout: float = 2.0
        self._lock = threading.Lock()

    @property
    def tree(self) -> OwnedProcessTree | None:
        return self._tree

    @property
    def origin(self) -> str | None:
        return self._origin

    @property
    def bridge(self) -> DesktopBootstrapBridge | None:
        return self._bridge

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._tree is not None and self._tree.poll() is None

    def start(
        self,
        request: DesktopLaunchRequest,
        *,
        get_current_url: Callable[[], str | None],
    ) -> ReadyResponse:
        """Bind loopback socket, launch child process tree, and perform handshake.

        ``get_current_url`` reports the window's location; the page may claim
        the session token only while that is the root document.
        """
        with self._lock:
            if self._tree is not None and self._tree.poll() is None:
                raise DesktopLauncherError("session-already-started")

            # Clean up any previous stale state
            self._close_resources_unlocked()

            # Pre-bind OS-assigned loopback socket
            try:
                listener = _bind_loopback_listener()
            except OSError as exc:
                raise DesktopLauncherError(f"socket-bind-failed:{exc}") from exc
            origin = f"http://127.0.0.1:{listener.getsockname()[1]}"

            token = SecretToken.generate()

            # Resolve child command
            if request.child_argv is not None:
                child_cmd = list(request.child_argv)
            else:
                child_cmd = request.runtime.desktop_child_argv()

            if request.runtime.kind == DistributionKind.PACKAGED_DESKTOP:
                launcher_exe = request.launcher_executable or Path(sys.executable)
                try:
                    child_cmd = list(
                        validate_desktop_child_argv(
                            child_cmd,
                            runtime=request.runtime,
                            launcher_executable=launcher_exe,
                        )
                    )
                except Exception as exc:
                    listener.close()
                    raise DesktopLauncherError(f"validation-failed:{exc}") from exc

            # Spawn child process tree and perform handshake
            try:
                tree, ready = launch_and_handshake_desktop_child(
                    child_cmd,
                    origin=origin,
                    token=token,
                    listener=listener,
                    startup_timeout=request.startup_timeout,
                    cwd=request.runtime.executable_root,
                )
            except ProcessTreeError as exc:
                listener.close()
                raise DesktopLauncherError(
                    f"child-handshake-failed:{exc.code}"
                ) from exc
            except Exception as exc:
                listener.close()
                raise DesktopLauncherError(f"child-launch-failed:{exc}") from exc

            # Setup bridge
            bridge = DesktopBootstrapBridge(
                expected_origin=origin,
                token=token,
                get_current_url=get_current_url,
            )

            self._tree = tree
            self._listener = listener
            self._origin = origin
            self._token = token
            self._bridge = bridge
            self._shutdown_timeout = request.shutdown_timeout

            return ready

    def request_shutdown(self) -> None:
        """Request graceful shutdown of the owned child process tree."""
        with self._lock:
            if self._tree is not None:
                try:
                    self._tree.terminate(grace_seconds=self._shutdown_timeout)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Error terminating child process tree: %s", exc)

    def close(self) -> None:
        """Clean up process trees, sockets, and memory references idempotently."""
        with self._lock:
            self._close_resources_unlocked()

    def _close_resources_unlocked(self) -> None:
        if self._tree is not None:
            with contextlib.suppress(Exception):
                self._tree.close()
            self._tree = None

        if self._listener is not None:
            with contextlib.suppress(Exception):
                self._listener.close()
            self._listener = None

        self._bridge = None
        self._token = None
        self._origin = None


def run_desktop(request: DesktopLaunchRequest) -> int:
    """Execute the full pywebview GUI on the main thread."""
    try:
        import webview
    except ImportError as exc:
        _report_startup_failure(request, f"pywebview is unavailable: {exc}")
        return 1

    window: Any = None

    def get_current_url() -> str | None:
        if window is not None:
            with contextlib.suppress(Exception):
                return window.get_current_url()
        return None

    owner = DesktopSessionOwner()
    try:
        ready = owner.start(request, get_current_url=get_current_url)
    except Exception as exc:  # noqa: BLE001
        _report_startup_failure(request, str(exc))
        owner.close()
        return 1

    stop_monitor = threading.Event()
    child_exit_code: int | None = None

    def on_loaded() -> None:
        current_url = get_current_url()
        valid_urls = (ready.origin, f"{ready.origin}/")
        if current_url not in valid_urls:
            logger.error("Rejecting navigation outside root origin: %s", current_url)
            if window is not None:
                window.destroy()
            return

        claim_script = (
            "if (window.pywebview && window.pywebview.api) { "
            "window.pywebview.api.claim_session().then(function(tok) { "
            "if (tok && window.startServonaut) window.startServonaut(tok); "
            "}); "
            "} else { "
            "window.addEventListener('pywebviewready', function() { "
            "window.pywebview.api.claim_session().then(function(tok) { "
            "if (tok && window.startServonaut) window.startServonaut(tok); "
            "}); "
            "}); "
            "}"
        )
        with contextlib.suppress(Exception):
            window.run_js(claim_script)

    def on_closed() -> None:
        stop_monitor.set()
        owner.request_shutdown()
        owner.close()

    def monitor_child() -> None:
        nonlocal child_exit_code
        while not stop_monitor.is_set():
            if owner.tree is not None:
                code = owner.tree.poll()
                if code is not None:
                    child_exit_code = code
                    logger.warning("Child process exited with code %s", code)
                    if window is not None:
                        with contextlib.suppress(Exception):
                            window.destroy()
                    break
            stop_monitor.wait(0.2)

    monitor_thread = threading.Thread(target=monitor_child, daemon=True)
    monitor_thread.start()

    window = webview.create_window(
        title=request.title,
        url=ready.origin,
        width=request.width,
        height=request.height,
        js_api=owner.bridge,
    )
    window.events.loaded += on_loaded
    window.events.closed += on_closed

    try:
        webview.start(
            gui=request.renderer,
            debug=False,
            http_server=False,
            private_mode=True,
        )
    finally:
        stop_monitor.set()
        owner.request_shutdown()
        owner.close()

    if child_exit_code is not None and child_exit_code != 0:
        return child_exit_code
    return 0
