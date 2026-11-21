"""Launch the opt-in native renderer probe from a source checkout.

Install scripts/desktop_probe/requirements.txt in a separate virtual environment,
then run python -m scripts.desktop_probe. Native GTK/WebKit packages are required
on Linux. --smoke checks the first rendered frame and exits. Only synthetic data,
Instances and Help are available; this is not an installer or a production app.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import socket
import sys
import threading
import time
from concurrent.futures import Future
from importlib.metadata import version
from pathlib import Path

from servonaut.desktop.webview_startup import WindowsWebViewStartup, private_webview_options

from .config import load_config
from .host import ProbeHost


class HostThread:
    """Own the asyncio server independently of the native GUI's main thread."""

    def __init__(self) -> None:
        self.ready: Future[ProbeHost] = Future()
        self.loop: asyncio.AbstractEventLoop | None = None
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        try:
            asyncio.run(self._serve())
        except BaseException as error:  # noqa: BLE001 -- forwarded to the owning thread
            self.error = error
            if not self.ready.done():
                self.ready.set_exception(error)

    async def _serve(self) -> None:
        self.loop = asyncio.get_running_loop()
        host = ProbeHost()
        try:
            await host.start()
            self.ready.set_result(host)
            await host.finished.wait()
        finally:
            await host.stop()

    def stop(self) -> None:
        if self.loop is not None and self.loop.is_running():
            host = self.ready.result()
            self.loop.call_soon_threadsafe(host.finished.set)
        self.thread.join(load_config().shutdown_seconds * 2)
        if self.thread.is_alive():
            raise RuntimeError("Probe host did not stop")
        if self.error is not None:
            raise RuntimeError("Probe host failed; rerun its socket tests") from None


def smoke_result(
    runtime: HostThread, host: ProbeHost, rendered: bool
) -> dict[str, bool]:
    """Report only lifecycle facts, never bootstrap credentials or URLs."""
    with socket.socket() as connection:
        connection.settimeout(host.config.shutdown_seconds)
        port_released = (
            connection.connect_ex(("127.0.0.1", int(host.origin.rsplit(":", 1)[1])))
            != 0
        )
    child = host.child.process
    return {
        "native_first_frame": rendered,
        "host_stopped": not runtime.thread.is_alive() and runtime.error is None,
        "child_exit_ok": child is not None and child.returncode == 0,
        "graceful_child_stop": not host.child.forced_stop,
        "port_released": port_released,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--renderer", choices=("gtk", "edgechromium", "cocoa"))
    parser.add_argument(
        "--smoke", action="store_true", help="Exit after the first rendered frame"
    )
    args = parser.parse_args()
    import webview

    def stage(name: str) -> None:
        if args.smoke:
            print(json.dumps({"native_stage": name}), flush=True)

    config = load_config()
    rendered = threading.Event()

    runtime = HostThread()
    runtime.thread.start()
    host = runtime.ready.result(config.startup_seconds)
    stage("host-ready")
    window = webview.create_window(
        "Servonaut renderer probe",
        host.origin,
        width=config.width,
        height=config.height,
    )
    startup = WindowsWebViewStartup(
        window.destroy, startup_seconds=config.startup_seconds, close_seconds=config.shutdown_seconds,
    ) if sys.platform == "win32" else None

    def bootstrap() -> bool:
        stage("window-loaded")
        if window.get_current_url() != host.origin + "/":
            if startup is None:
                window.destroy()
            return False
        # run_js avoids evaluate_js's eval wrapper, preserving script-src 'self'.
        script = host.bootstrap_script()
        result = window.run_js(f"(() => {{ {script} return true; }})()")
        if startup is not None and result is not True and result != "true":
            return False
        stage("bootstrap-injected")
        if args.smoke:
            threading.Thread(target=finish_smoke, daemon=True).start()
        return True

    def loaded() -> None:
        if startup is None:
            bootstrap()
        else:
            startup.start_bootstrap(bootstrap)

    def closed() -> None:
        if startup is not None:
            startup.cancel()
        runtime.stop()

    def watch_child() -> None:
        runtime.thread.join()
        window.destroy()

    def finish_smoke() -> None:
        deadline = time.monotonic() + config.startup_seconds
        while time.monotonic() < deadline:
            result = window.run_js("document.body.classList.contains('-first-byte')")
            if result is True or result == "true":
                rendered.set()
                stage("first-frame")
                break
            rendered.wait(config.probe_poll_seconds)
        window.destroy()

    window.events.loaded += loaded
    window.events.closed += closed
    threading.Thread(target=watch_child, daemon=True).start()
    print(
        json.dumps(
            {
                name: version(name)
                for name in ("textual", "textual-serve", "pywebview", "aiohttp")
            }
        )
    )
    storage = None
    try:
        with private_webview_options() as options, startup or contextlib.nullcontext():
            storage_path = options.get("storage_path")
            if storage_path is not None:
                storage = Path(storage_path)
                if storage.is_dir():
                    stage("private-storage-ready")
            stage("gui-starting")
            webview.start(gui=args.renderer, debug=False, **options)
            if startup is not None and window.events.closed.is_set():
                startup.cancel()
    finally:
        stage("gui-stopped")
        runtime.stop()
    if storage is not None and not storage.exists():
        stage("private-storage-removed")
    if startup is not None and startup.failure is not None:
        stage("startup-failed")
        print(startup.failure, file=sys.stderr)
        raise SystemExit(1)
    if args.smoke:
        print(json.dumps({"child_errors": host.child.errors}))
        print(json.dumps({"child_transport": host.child.transport_status()}))
        result = smoke_result(runtime, host, rendered.is_set())
        print(json.dumps(result))
        if not all(result.values()):
            raise SystemExit(1)


if __name__ == "__main__":
    main()
