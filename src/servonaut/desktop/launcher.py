"""GUI session owner and pywebview window launcher.

Coordinates pre-bound socket transfer, child process tree launch and handshake,
native pywebview window creation on the main thread, and strict lifecycle cleanup.
"""

from __future__ import annotations

import contextlib
import logging
import socket
import sys
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from servonaut.desktop.bridge import DesktopBootstrapBridge
from servonaut.desktop.dialogs import DesktopDialogService
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


class DesktopSessionOwner:
    """Owns the lifecycle of the pre-bound socket, child process tree, and bridge."""

    def __init__(self) -> None:
        self._tree: OwnedProcessTree | None = None
        self._listener: socket.socket | None = None
        self._origin: str | None = None
        self._token: SecretToken | None = None
        self._bridge: DesktopBootstrapBridge | None = None
        self._dialog_service: DesktopDialogService | None = None
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
    def dialog_service(self) -> DesktopDialogService | None:
        return self._dialog_service

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._tree is not None and self._tree.poll() is None

    def start(self, request: DesktopLaunchRequest) -> ReadyResponse:
        """Bind loopback socket, launch child process tree, and perform handshake."""
        with self._lock:
            if self._tree is not None and self._tree.poll() is None:
                raise DesktopLauncherError("session-already-started")

            # Clean up any previous stale state
            self._close_resources_unlocked()

            # Pre-bind OS-assigned loopback socket
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                port = listener.getsockname()[1]
                origin = f"http://127.0.0.1:{port}"
            except Exception as exc:
                listener.close()
                raise DesktopLauncherError(f"socket-bind-failed:{exc}") from exc

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
        self._dialog_service = None


def run_desktop(request: DesktopLaunchRequest) -> int:
    """Execute the full pywebview GUI on the main thread."""
    try:
        import webview
    except ImportError as exc:
        logger.error("pywebview is required for desktop mode: %s", exc)
        return 1

    owner = DesktopSessionOwner()
    try:
        ready = owner.start(request)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to start desktop session: %s", exc)
        owner.close()
        return 1

    window: Any = None

    def get_current_url() -> str | None:
        if window is not None:
            with contextlib.suppress(Exception):
                return window.get_current_url()
        return None

    assert owner.bridge is not None
    owner.bridge.set_url_getter(get_current_url)
    dialog_service = DesktopDialogService(window_getter=lambda: window)
    owner._dialog_service = dialog_service

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
