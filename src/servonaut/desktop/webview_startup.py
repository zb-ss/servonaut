"""Private profiles and bounded Windows native window startup."""

from __future__ import annotations

import contextlib
import logging
import os
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator
from typing import Any

logger = logging.getLogger(__name__)

WEBVIEW_INIT_FAILURE = "Microsoft Edge WebView2 could not initialize. Repair the WebView2 Runtime and try again"
WEBVIEW_STARTUP_TIMEOUT = "the Windows desktop took too long to start. Restart Servonaut or repair the WebView2 Runtime"
WEBVIEW_BOOTSTRAP_FAILURE = "the Windows desktop could not connect to its local session. Restart Servonaut"
_PYWEBVIEW_INIT_ERROR = "WebView2 initialization failed"
_PYWEBVIEW_SCRIPT_ERROR = "Error occurred in script"


@contextlib.contextmanager
def private_webview_options() -> Iterator[dict[str, Any]]:
    """Hold the private profile until the native event loop returns."""
    if sys.platform != "win32":
        yield {"private_mode": True}
        return
    with tempfile.TemporaryDirectory(prefix="servonaut-wv2-", ignore_cleanup_errors=True) as storage:
        yield {"private_mode": True, "storage_path": storage}


class WindowsWebViewStartup(logging.Filter):
    """Cover initialization and the first bootstrap with one deadline."""

    def __init__(
        self,
        close_window: Callable[[], None],
        *,
        startup_seconds: float,
        close_seconds: float,
        on_unresponsive: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__()
        self._close_window = close_window
        self._startup_seconds = startup_seconds
        self._close_seconds = close_seconds
        self._on_unresponsive = on_unresponsive
        self._backend_logger = logging.getLogger("pywebview")
        self._settled = threading.Event()
        self._loop_returned = threading.Event()
        self._lock = threading.Lock()
        self._bootstrap_started = False
        self.failure: str | None = None

    def __enter__(self) -> WindowsWebViewStartup:
        self._backend_logger.addFilter(self)
        threading.Thread(target=self._monitor, daemon=True, name="webview-startup").start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._loop_returned.set()
        self._settle(WEBVIEW_INIT_FAILURE)
        self._backend_logger.removeFilter(self)

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno < logging.ERROR or self._settled.is_set():
            return True
        message = record.getMessage()
        if message.startswith(_PYWEBVIEW_INIT_ERROR):
            self._settle(WEBVIEW_INIT_FAILURE)
            # The upstream exception may contain the temporary profile path.
            return False
        if message == _PYWEBVIEW_SCRIPT_ERROR:
            self._settle(WEBVIEW_BOOTSTRAP_FAILURE)
            # A script exception may contain the bootstrap credential.
            return False
        return True

    def cancel(self) -> None:
        """Stop watching after a user closes the window."""
        self._settle(None)

    def start_bootstrap(self, callback: Callable[[], bool]) -> None:
        """One daemon callback keeps a stuck native script out of the event thread."""
        with self._lock:
            if self._settled.is_set() or self._bootstrap_started:
                return
            self._bootstrap_started = True
        threading.Thread(
            target=self._bootstrap, args=(callback,), daemon=True, name="webview-bootstrap",
        ).start()

    def _bootstrap(self, callback: Callable[[], bool]) -> None:
        if self._settled.is_set():
            return
        try:
            completed = callback()
        except Exception as exc:  # noqa: BLE001 — third-party errors may quote the script
            logger.warning("Windows desktop bootstrap failed (%s).", type(exc).__name__)
            completed = False
        self._settle(None if completed else WEBVIEW_BOOTSTRAP_FAILURE)

    def _settle(self, failure: str | None) -> None:
        with self._lock:
            if not self._settled.is_set():
                self.failure = failure
                self._settled.set()

    def _try_close(self) -> None:
        with contextlib.suppress(Exception):
            self._close_window()

    def _monitor(self) -> None:
        if not self._settled.wait(self._startup_seconds):
            self._settle(WEBVIEW_STARTUP_TIMEOUT)
        failure = self.failure
        if failure is None or self._loop_returned.is_set():
            return
        # WinForms destruction marshals to the native UI thread, which might
        # be the thread that has stalled.
        threading.Thread(target=self._try_close, daemon=True, name="webview-close").start()
        if not self._loop_returned.wait(self._close_seconds) and not self._loop_returned.is_set():
            logger.error("Windows desktop startup failed. %s.", failure)
            try:
                if self._on_unresponsive is not None:
                    self._on_unresponsive(failure)
            finally:
                os._exit(1)
