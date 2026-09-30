"""Where the live QA sandbox is, whether it still runs, and what it recorded.

A sandbox has a root directory holding ``state.json`` (see ``owner.py``) and
a *marker* file, and one per-user *pointer*,
``${XDG_STATE_HOME:-~/.local/state}/servonaut-qa/current.json``, naming that
state file. The pointer is the only file a sandbox writes outside its root;
it makes "the live sandbox" unambiguous for every tool that drives it,
whichever checkout the tool runs from.

The marker is also the owner's lock: the process that owns the sandbox holds
an exclusive ``flock`` on it for its whole life (:class:`OwnerLock`). "The
owner is alive" means exactly that the lock is held (:func:`owner_alive`):
the answer is the same on every OS and cannot be fooled by a process that
reused the owner's PID. Nothing signals a recorded PID unless that lock
proves it still belongs to the owner.

Standard library only (with the harness's side-effect-free ``child_guard``):
the textual-pilot-mcp host imports this module in its own interpreter.
"""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from e2e.harness import child_guard

SCHEMA = 2
SINGLE = "single"
MULTI_ACCOUNT = "multi-account"
SCENARIOS = (SINGLE, MULTI_ACCOUNT)
STATE_FILE = "state.json"
MARKER = ".servonaut-qa-sandbox"
POINTER_DIR = "servonaut-qa"
POINTER_FILE = "current.json"
CAPTURES_DIR = "captures"
DEFAULT_ROOT_NAME = ".qa-sandbox"
# Desktop requests and their answers (see owner.py and client.py).
CONTROL_DIR = "control"
# Every process of a sandbox carries this variable, set to the sandbox root.
OWNER_ROOT_ENV = "SERVONAUT_E2E_OWNER_ROOT"
# The phases an owner goes through, as its marker records them.
STARTING = "starting"
RUNNING = "running"
STOPPING = "stopping"

_START = "Start one with `python -m e2e.sandbox up` in a Servonaut checkout."
# How long an owner tries to take its lock while another process probes it.
_LOCK_ATTEMPTS = 20
_LOCK_RETRY_SECONDS = 0.05


class SandboxUnavailable(RuntimeError):
    """There is no live sandbox to use (the message says what to do)."""


def sentence(text: str) -> str:
    """*text* with its first letter capitalised (the rest untouched)."""
    return text[:1].upper() + text[1:]


# ---------------------------------------------------------------------------
# Paths and files
# ---------------------------------------------------------------------------


def state_home(env: Optional[Mapping[str, str]] = None) -> Path:
    """``$XDG_STATE_HOME``, or ``~/.local/state``, as *env* (default: os.environ) has it."""
    env = os.environ if env is None else env
    configured = env.get("XDG_STATE_HOME", "")
    if configured and os.path.isabs(configured):
        return Path(configured)
    home = env.get("HOME") or str(Path.home())
    return Path(home) / ".local" / "state"


def pointer_path(env: Optional[Mapping[str, str]] = None) -> Path:
    return state_home(env) / POINTER_DIR / POINTER_FILE


def captures_dir(env: Optional[Mapping[str, str]] = None) -> Path:
    """Where the textual-pilot-mcp snapshots of the sandbox's TUI go."""
    return state_home(env) / POINTER_DIR / CAPTURES_DIR


def default_root(repo_root: Path) -> Path:
    return repo_root / DEFAULT_ROOT_NAME


def read_json(path: Path) -> Optional[dict]:
    """The JSON object in *path*, or None when it is missing or unreadable."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_json(path: Path, data: Mapping[str, Any]) -> None:
    """Replace *path* atomically with *data*, readable by this user only."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# The owner's lock
# ---------------------------------------------------------------------------


class OwnerLock:
    """The exclusive lock the owner holds on its sandbox's marker file.

    The descriptor is not inherited by children, so the lock is released
    exactly when the owner closes it or exits, however it exits.
    """

    def __init__(self, root: Path) -> None:
        self.path = Path(root) / MARKER
        self._fd: Optional[int] = None

    def acquire(self, record: Mapping[str, Any]) -> bool:
        """Take the lock and write *record* into the marker; False if another owner holds it."""
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        for _ in range(_LOCK_ATTEMPTS):
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                # Held by an owner, or for an instant by a process probing it.
                time.sleep(_LOCK_RETRY_SECONDS)
                continue
            self._fd = fd
            self.write(record)
            return True
        os.close(fd)
        return False

    def write(self, record: Mapping[str, Any]) -> None:
        """Replace the marker's contents (it keeps its inode, and so the lock)."""
        assert self._fd is not None, "the lock is not held"
        data = (json.dumps(dict(record), sort_keys=True) + "\n").encode()
        os.ftruncate(self._fd, 0)
        os.pwrite(self._fd, data, 0)

    def release(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


def owner_alive(root: Any) -> bool:
    """True while an owner holds the lock of the sandbox at *root*."""
    try:
        fd = os.open(Path(root) / MARKER, os.O_RDONLY | os.O_CLOEXEC)
    except (OSError, TypeError):
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    finally:
        os.close(fd)
    return False


def marker(root: Any) -> Optional[dict]:
    """What the owner wrote into its marker (pid, identity, phase), if anything."""
    return read_json(Path(root) / MARKER)


def remove_stale_root(root: Path) -> bool:
    """Remove *root* if it is a sandbox root whose owner is gone; True if removed.

    Only a directory carrying the marker, with nobody holding its lock, is
    provably a finished sandbox; anything else is left alone.
    """
    if marker(root) is None or owner_alive(root):
        return False
    shutil.rmtree(root, ignore_errors=True)
    return not root.exists()


def legacy_owner_alive(record: Mapping[str, Any]) -> bool:
    """For a pointer written before the owner lock existed (schema 1).

    Only decides whether to refuse: such an owner is never signalled.
    """
    pid, identity = record.get("owner_pid"), record.get("owner_identity")
    return isinstance(pid, int) and bool(identity) and bool(
        child_guard.owner_alive(pid, tuple(identity))
    )


def legacy_message(record: Mapping[str, Any]) -> str:
    return (
        "the QA sandbox named in the pointer was started by an older version of this tool "
        f"(owner pid {record.get('owner_pid')}, checkout {record.get('repo_root')}); stop "
        f"it with `kill -TERM {record.get('owner_pid')}` (it cleans up after itself), then "
        "start a new one"
    )


# ---------------------------------------------------------------------------
# Other processes
# ---------------------------------------------------------------------------


def process_identity(pid: int) -> Optional[list[str]]:
    """What tells *pid* apart from a later process reusing the number (needs /proc)."""
    identity = child_guard.process_identity(pid)
    return list(identity) if identity is not None else None


def process_alive(pid: Any, identity: Any = None) -> bool:
    """True while *pid* runs; with *identity* (and /proc), only while it is that process."""
    if not isinstance(pid, int) or pid <= 0:
        return False
    current = child_guard.process_identity(pid)
    if current is not None:
        return current[0] not in ("Z", "X") and (not identity or current[1] == identity[1])
    if can_list_processes():
        return False  # no /proc entry: gone
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def process_command(pid: int) -> Optional[str]:
    """The command line of *pid* (``/proc``, else ``ps``), or None when it is gone."""
    if can_list_processes():
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                parts = handle.read().split(b"\0")
        except OSError:
            return None
        return b" ".join(part for part in parts if part).decode("utf-8", "replace")
    return ps_command(pid)


def ps_command(pid: int) -> Optional[str]:
    """The command line of *pid* as ``ps`` reports it (systems without /proc)."""
    try:
        output = subprocess.run(
            ["ps", "-o", "command=", "-p", str(pid)],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return output or None


def can_list_processes() -> bool:
    return os.path.isdir("/proc/self")


def sandbox_pids(root: Path) -> list[int]:
    """Every process whose environment belongs to the sandbox at *root*.

    Children carry ``SERVONAUT_E2E_OWNER_ROOT=<root>`` from the moment they
    start. Needs /proc; elsewhere the list is empty (see
    :func:`can_list_processes`).
    """
    if not can_list_processes():
        return []
    needle = os.fsencode(f"{OWNER_ROOT_ENV}={root}") + b"\0"
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit() or int(entry) == os.getpid():
            continue
        try:
            with open(f"/proc/{entry}/environ", "rb") as handle:
                environ = handle.read()
        except OSError:
            continue
        if environ.startswith(needle) or b"\0" + needle in environ:
            found.append(int(entry))
    return sorted(found)


# ---------------------------------------------------------------------------
# The live sandbox
# ---------------------------------------------------------------------------


def read_pointer(env: Optional[Mapping[str, str]] = None) -> Optional[dict]:
    return read_json(pointer_path(env))


def load_live_state(env: Optional[Mapping[str, str]] = None) -> dict:
    """``state.json`` of the live sandbox; SandboxUnavailable says why there is none."""
    pointer_file = pointer_path(env)
    pointer = read_json(pointer_file)
    if pointer is None:
        raise SandboxUnavailable(f"No QA sandbox is running ({pointer_file} is missing). {_START}")
    gone = f"The QA sandbox named in {pointer_file} is no longer running. {_START}"
    if pointer.get("schema") != SCHEMA:
        if legacy_owner_alive(pointer):
            raise SandboxUnavailable(sentence(legacy_message(pointer)) + ".")
        raise SandboxUnavailable(gone)
    root = Path(str(pointer.get("root", "")))
    if not owner_alive(root):
        raise SandboxUnavailable(gone)
    phase = (marker(root) or {}).get("phase")
    owner = f"The QA sandbox (owner pid {pointer.get('owner_pid')})"
    if phase == STOPPING:
        raise SandboxUnavailable(f"{owner} is stopping. {_START}")
    state = read_json(root / STATE_FILE)
    if state is None or phase != RUNNING:
        raise SandboxUnavailable(f"{owner} is still starting; wait for its SANDBOX READY line.")
    if state.get("schema") != SCHEMA:
        raise SandboxUnavailable(
            f"{root / STATE_FILE} has schema {state.get('schema')!r}; this checkout reads "
            f"schema {SCHEMA}. Use the checkout that started the sandbox "
            f"({state.get('repo_root')}), or restart the sandbox from this one."
        )
    return state


def watch_owner(root: Path, on_gone: Callable[[], None], *, interval: float = 0.5) -> Any:
    """Call *on_gone()* once, from a daemon thread, when the sandbox at *root* ends.

    Returns an event; setting it stops the watch without calling *on_gone*.
    """
    cancelled = threading.Event()

    def watch() -> None:
        while not cancelled.wait(interval):
            if not owner_alive(root):
                on_gone()
                return

    threading.Thread(target=watch, name="qa-sandbox-watch", daemon=True).start()
    return cancelled


def confine_after(root: Path, write_roots: list, on_confined: Callable[[], None] = lambda: None) -> Any:
    """Once the sandbox at *root* ends, let this process write below *write_roots* only.

    For a long-lived process that hosts sandbox code without the owner
    watchdog (the TUI inside a textual-pilot-mcp server): a late write would
    otherwise bring the sandbox directory back. Calls *on_confined()* after
    narrowing. Returns the watch's cancel event (see :func:`watch_owner`).
    """

    def confine() -> None:
        guard = child_guard.guard_module()
        guard.restrict_writes([str(path) for path in write_roots])
        on_confined()

    return watch_owner(root, confine)
