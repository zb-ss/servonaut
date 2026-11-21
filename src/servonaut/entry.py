"""Console entry. Select a generation before loading application dependencies."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from threading import Thread

_WORKER_PID = "_SERVONAUT_UPDATE_WORKER_PID"
_LEASE_ID = "_SERVONAUT_UPDATE_LEASE_ID"


def _top_flags(arguments: list[str]) -> set[str]:
    """Only options preceding the subcommand belong to the launcher."""
    flags = set()
    words = iter(arguments)
    for word in words:
        if word == "--" or not word.startswith("-"):
            break
        flags.add(word)
        if word in {"--config", "--ai-provider"}:
            next(words, "")
        elif word in {"--mcp-install", "--restore-backup"}:
            # The optional operand selects another command surface.
            break
    return flags


def _interactive(arguments: list[str]) -> bool:
    try:
        interactive = all(stream is not None and stream.isatty() for stream in (sys.stdin, sys.stdout))
    except (OSError, ValueError):
        return False
    if not interactive:
        return False
    words = iter(arguments)
    for word in words:
        if word == "--config":
            if not next(words, ""):
                return False
        elif word not in {"--debug", "--demo"} and not word.startswith("--config="):
            return False
    return True


def _role(arguments: list[str]) -> str:
    if "--mcp" in _top_flags(arguments):
        return "mcp"
    return "tui" if _interactive(arguments) else "cli"


def _dispatch() -> None:
    from servonaut.main import main as application_main
    from servonaut.services.client_identity import configure_client_identity

    configure_client_identity(kind="mcp" if _role(sys.argv[1:]) == "mcp" else "cli")
    application_main()


def _wait_worker(pid: int) -> None:
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def _reap_in_background(wait, *args) -> None:
    Thread(target=wait, args=args, daemon=True, name="servonaut-update-reaper").start()


def _wait_windows(command: list[str], environment: dict[str, str]) -> int:
    control_signals = (signal.SIGINT, signal.SIGBREAK)
    previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in control_signals}
    try:
        return subprocess.call(command, env=environment)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _run_generation(console: str, arguments: list[str],
                    worker: subprocess.Popen[bytes] | None, lease_id: str = "") -> None:
    command = [console, *arguments]
    environment = dict(os.environ)
    if lease_id:
        environment[_LEASE_ID] = lease_id
    if os.name == "nt":
        raise SystemExit(_wait_windows(command, environment))
    if worker is not None:
        environment[_WORKER_PID] = str(worker.pid)
    os.execve(console, command, environment)


def _serve_generation(store) -> None:
    from servonaut.updates.launch import log_error

    lease_id = os.environ.pop(_LEASE_ID, "")
    try:
        store.acknowledge(lease_id)
    except OSError as error:
        log_error(store, error)
    try:
        _dispatch()
    finally:
        try:
            store.unregister(lease_id)
        except Exception as error:
            log_error(store, error)


def _route(arguments: list[str]) -> None:
    from servonaut import get_version
    from servonaut.updates.generations import directory_for
    from servonaut.updates.launch import admit, fallback_routes, log_error, route_failed
    from servonaut.updates.layout import UpdateLayout, console_for
    from servonaut.updates.status import UpdateBusy

    flags = _top_flags(arguments)
    bypass = os.environ.get("SERVONAUT_SKIP_AUTO_APPLY") == "1" or "--update" in flags
    has_lease = bool(os.environ.get(_LEASE_ID))
    if bypass and not has_lease:
        _dispatch()
        return
    try:
        layout = UpdateLayout.detect()
    except Exception:  # Even an inaccessible home can prevent layout detection.
        layout = None
    if layout is None:
        _dispatch()
        return
    role, store, version = _role(arguments), layout.store, get_version()
    readonly = bool({"--version", "--help", "-h"}.intersection(flags)) or (
        "--help" in arguments or "-h" in arguments
    )
    if layout.generation is not None:
        if (readonly or bypass) and not has_lease:
            _dispatch()
        else:
            _serve_generation(store)
        return
    if bypass:
        _dispatch()
        return
    worker = None
    lease_id = ""
    try:
        if readonly:
            routes = fallback_routes(store, version)
        else:
            routes, worker, lease_id = admit(store, role, version)
    except UpdateBusy as error:
        log_error(store, error)
        routes = []
    except Exception as error:
        log_error(store, error)
        routes = fallback_routes(store, version)
    if worker is not None and os.name == "nt":
        _reap_in_background(worker.wait)
    for position, generation in enumerate(routes):
        try:
            console = str(console_for(directory_for(store, generation)))
            _run_generation(console, arguments, worker, lease_id)
        except OSError as error:
            if not readonly:
                fallback = routes[position + 1] if position + 1 < len(routes) else None
                lease_id = route_failed(store, generation, error, lease_id, fallback, role)
        except SystemExit:
            if not readonly and os.name == "nt":
                try:
                    store.unregister(lease_id, acknowledged_only=True)
                except Exception as error:
                    log_error(store, error)
            raise
    if worker is not None and os.name != "nt":
        _reap_in_background(worker.wait)
    _dispatch()


def main() -> None:
    # POSIX exec preserves child parentage. Reap the worker across the exec.
    worker_pid = os.environ.pop(_WORKER_PID, "")
    if os.name != "nt" and len(worker_pid) <= 10 and worker_pid.isascii() and worker_pid.isdigit():
        pid = int(worker_pid)
        if 0 < pid < 2**31:
            _reap_in_background(_wait_worker, pid)
    _route(sys.argv[1:])


if __name__ == "__main__":
    main()
