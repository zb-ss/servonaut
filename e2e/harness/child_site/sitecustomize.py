"""Install the e2e guards in a child process, or stop the child.

The suite puts this directory first on ``PYTHONPATH`` for every Python
process it starts, so the guards are active before the child imports anything
else. Settings come from the ``SERVONAUT_E2E_*`` environment variables. Once
armed, the child reports itself in ``SERVONAUT_E2E_ARMED_LOG``.

Python's ``site`` module ignores errors raised here, which would let a child
run unguarded. Any failure therefore ends the process at once (exit 70).

Every child also starts an owner watchdog: a daemon thread that ends the
process (exit 75) once the pytest process that owns the run, or the run's
test root, is gone. Fixture teardown normally stops children; the watchdog
covers a run that was killed before teardown, including detached children
such as a background relay listener.
"""

import os
import sys
import threading
import time

_MODULE_NAME = "_servonaut_e2e_netguard"
_EXIT_UNGUARDED = 70
_EXIT_ORPHANED = 75
_OWNER_PID = "SERVONAUT_E2E_OWNER_PID"
_OWNER_ROOT = "SERVONAUT_E2E_OWNER_ROOT"
_WATCH_SECONDS = 0.25


def _process_identity(pid):
    """(state, start time) of *pid* from /proc, or None when it is gone.

    The start time tells a reused PID apart from the original process.
    """
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii", errors="replace") as handle:
            fields = handle.read().rsplit(")", 1)[1].split()
    except (OSError, IndexError):
        return None
    return fields[0], fields[19]


def _owner_alive(pid, identity, root):
    if root and not os.path.isdir(root):
        return False
    if not os.path.exists("/proc/self/stat"):  # no /proc: signal 0 is the best check
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            pass
        return True
    current = _process_identity(pid)
    return (
        identity is not None
        and current is not None
        and current[0] not in ("Z", "X")
        and current[1] == identity[1]
    )


def _start_owner_watchdog():
    raw_pid = os.environ.get(_OWNER_PID, "")
    if not raw_pid.isdigit() or int(raw_pid) == os.getpid():
        return
    pid = int(raw_pid)
    root = os.environ.get(_OWNER_ROOT, "")
    identity = _process_identity(pid)

    def watch():
        while _owner_alive(pid, identity, root):
            time.sleep(_WATCH_SECONDS)
        try:
            sys.stderr.write("e2e: the test run that started this process is gone; stopping\n")
            sys.stderr.flush()
        finally:
            os._exit(_EXIT_ORPHANED)

    threading.Thread(target=watch, name="e2e-owner-watchdog", daemon=True).start()


def _install() -> None:
    import importlib.util

    module = sys.modules.get(_MODULE_NAME)
    if module is None:
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "netguard.py"
        )
        spec = importlib.util.spec_from_file_location(_MODULE_NAME, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load the e2e guard from {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[_MODULE_NAME] = module
        spec.loader.exec_module(module)
    module.install_from_environment()
    _start_owner_watchdog()


try:
    _install()
except BaseException as exc:  # noqa: BLE001 - any failure must stop the child
    try:
        sys.stderr.write(f"e2e guard could not be installed; stopping this process: {exc!r}\n")
        sys.stderr.flush()
    finally:
        os._exit(_EXIT_UNGUARDED)
