"""Where the live QA sandbox is, whether it still runs, and what it recorded.

A sandbox has a root directory holding ``state.json`` (see ``owner.py``) and
a *marker* file, and one per-user *pointer*,
``${XDG_STATE_HOME:-~/.local/state}/servonaut-qa/current.json``, naming that
state file. The pointer is the only file a sandbox writes outside its root;
it makes "the live sandbox" unambiguous for every tool that drives it,
whichever checkout the tool runs from. Claims on it are serialised by a lock
on its directory (:func:`pointer_lock`).

The marker is also the owner's lock: the process that owns the sandbox holds
an exclusive ``flock`` on it for its whole life (:class:`OwnerLock`). "The
owner is alive" means exactly that the lock is held (:func:`owner_alive`):
the answer is the same on every OS and cannot be fooled by a process that
reused the owner's PID. Nothing signals a recorded PID unless that lock
proves it still belongs to the owner. The owner removes the marker last,
just before it exits.

Standard library only (with the harness's side-effect-free ``child_guard``):
the textual-pilot-mcp host imports this module in its own interpreter.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional

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
# What an owner's lock tells about it (see owner_state).
ALIVE = "alive"
GONE = "gone"
UNKNOWN = "unknown"
# ``ps`` runs from the system directories with a pinned environment: the
# same start time reads the same whichever time zone or locale asks.
_PS_DIRS = "/bin:/usr/bin"
_PS_ENV = {"PATH": _PS_DIRS, "LC_ALL": "C", "TZ": "UTC"}


class SandboxUnavailable(RuntimeError):
    """There is no live sandbox to use (the message says what to do)."""


class LockUnsupported(RuntimeError):
    """The filesystem holding a sandbox root does not support ``flock``."""


class LockWaitCancelled(RuntimeError):
    """A stop was requested while waiting for the pointer lock."""


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


@contextlib.contextmanager
def pointer_lock(pointer: Path, *, waiting: Callable[[], None] = lambda: None,
                 cancelled: Callable[[], bool] = lambda: False) -> Iterator[None]:
    """Serialise claims on the pointer (the lock is its directory: no extra file).

    While another command holds it, *waiting()* is called once and the wait
    ends early with LockWaitCancelled when *cancelled()* turns true.
    """
    pointer.parent.mkdir(parents=True, exist_ok=True)
    directory = os.open(pointer.parent, os.O_RDONLY | os.O_CLOEXEC)
    try:
        told = False
        while True:
            try:
                fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not told:
                    waiting()
                    told = True
                if cancelled():
                    raise LockWaitCancelled("stopped while waiting for the pointer lock") from None
                time.sleep(_LOCK_RETRY_SECONDS)
            except OSError as exc:
                raise LockUnsupported(
                    f"cannot lock {pointer.parent} ({exc.strerror}): the per-user state "
                    "directory must be on a filesystem that supports flock"
                ) from None
        yield
    finally:
        os.close(directory)


def unknown_schema(record: Mapping[str, Any], where: Path) -> str:
    """Why a pointer or marker from another version of this tool is not touched."""
    return (
        f"{where} was written by another version of this tool (schema "
        f"{record.get('schema')!r}; this one reads {SCHEMA}). Stop that sandbox with the "
        f"checkout that started it ({record.get('repo_root', 'unknown')}), or remove {where} "
        "if it no longer runs"
    )


# ---------------------------------------------------------------------------
# The owner's lock
# ---------------------------------------------------------------------------


class OwnerLock:
    """The exclusive lock the owner holds on its sandbox's marker file.

    The descriptor is closed on ``exec`` and in any child forked without
    one, so the lock is released exactly when the owner closes it or exits,
    however it exits.
    """

    def __init__(self, root: Path) -> None:
        self.path = Path(root) / MARKER
        self._fd: Optional[int] = None

    def acquire(self, record: Mapping[str, Any]) -> bool:
        """Take the lock and write *record* into the marker; False if another owner holds it.

        Raises LockUnsupported where the filesystem cannot lock at all.
        """
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        for _ in range(_LOCK_ATTEMPTS):
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                # Held by an owner, or for an instant by a process probing it.
                time.sleep(_LOCK_RETRY_SECONDS)
                continue
            except OSError as exc:
                os.close(fd)
                raise LockUnsupported(
                    f"cannot lock {self.path} ({exc.strerror}): the sandbox root must be on "
                    "a filesystem that supports flock; choose another with --root"
                ) from None
            self._fd = fd
            os.register_at_fork(after_in_child=self._close_in_child)
            self.write(record)
            return True
        os.close(fd)
        return False

    def _close_in_child(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def write(self, record: Mapping[str, Any]) -> None:
        """Replace the marker's contents (it keeps its inode, and so the lock)."""
        assert self._fd is not None, "the lock is not held"
        data = (json.dumps(dict(record), sort_keys=True) + "\n").encode()
        os.ftruncate(self._fd, 0)
        os.pwrite(self._fd, data, 0)

    def remove(self) -> None:
        """Delete the marker while the lock is still held (the owner's last act)."""
        self.path.unlink(missing_ok=True)

    def release(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


def owner_state(root: Any) -> str:
    """ALIVE while an owner holds the lock of the sandbox at *root*, GONE when
    nobody does (or there is no marker), UNKNOWN when the lock cannot be tried."""
    try:
        fd = os.open(Path(root) / MARKER, os.O_RDONLY | os.O_CLOEXEC)
    except FileNotFoundError:
        return GONE
    except (OSError, TypeError):
        return UNKNOWN
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        return ALIVE
    except OSError:
        return UNKNOWN
    finally:
        os.close(fd)
    return GONE


def owner_alive(root: Any) -> bool:
    """True while an owner holds the lock of the sandbox at *root*."""
    return owner_state(root) == ALIVE


def marker(root: Any) -> Optional[dict]:
    """What the owner wrote into its marker (pid, identity, phase), if anything."""
    return read_json(Path(root) / MARKER)


def same_owner(record: Optional[Mapping[str, Any]], owner: Mapping[str, Any]) -> bool:
    """True when *record* (a marker or pointer) names the owner *owner* names."""
    return record is not None and all(
        record.get(key) == owner.get(key) for key in ("owner_pid", "started_at")
    )


def remove_stale_root(root: Path) -> bool:
    """Remove *root* if it is a sandbox root whose owner is gone; True if removed.

    Only a directory carrying this version's marker, with nobody holding its
    lock, is provably a finished sandbox; anything else is left alone.
    """
    found = marker(root)
    if found is None or found.get("schema") != SCHEMA or owner_state(root) != GONE:
        return False
    shutil.rmtree(root, ignore_errors=True)
    return not root.exists()


# ---------------------------------------------------------------------------
# Other processes
# ---------------------------------------------------------------------------


def can_list_processes() -> bool:
    return os.path.isdir("/proc/self")


def process_identity(pid: int) -> Optional[list[str]]:
    """What tells *pid* apart from a later process reusing the number.

    ``[state, start time]``: from /proc, or elsewhere from ``ps`` (``stat``
    and ``lstart``, the start time to the second). None when it is gone.
    """
    if can_list_processes():
        identity = child_guard.process_identity(pid)
        return list(identity) if identity is not None else None
    found = _ps(pid, "stat", "lstart")
    if not found or " " not in found:
        return None
    status, started = found.split(None, 1)
    return [status[0], started]


def process_alive(pid: Any, identity: Any = None) -> bool:
    """True while *pid* runs; with *identity*, only while it is still that process."""
    if not isinstance(pid, int) or pid <= 0:
        return False
    current = process_identity(pid)
    if current is None:
        return False
    if current[0] in ("Z", "X"):
        return False
    return not identity or current[1] == identity[1]


def process_command(pid: int) -> Optional[str]:
    """The command line of *pid* (``/proc``, else ``ps``), or None when it is gone."""
    if can_list_processes():
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                parts = handle.read().split(b"\0")
        except OSError:
            return None
        return b" ".join(part for part in parts if part).decode("utf-8", "replace")
    return _ps(pid, "command")


def _ps(pid: int, *fields: str) -> Optional[str]:
    """``ps -o <field>= ... -p <pid>`` (systems without /proc), or None.

    Runs the system's ``ps`` by path with a pinned environment, and outside
    the sandbox guard of this process (a sandbox's own PATH holds only fake
    tools, and its guard refuses other programs).
    """
    program = shutil.which("ps", path=_PS_DIRS)
    if program is None:
        return None
    guard = sys.modules.get(child_guard.GUARD_MODULE)
    try:
        with guard.suspended() if guard is not None else contextlib.nullcontext():
            output = subprocess.run(
                [program, *(f"-o{field}=" for field in fields), "-p", str(pid)], env=_PS_ENV,
                capture_output=True, text=True, timeout=10, check=False,
            ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return output or None


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
    if pointer.get("schema") != SCHEMA:
        raise SandboxUnavailable(sentence(unknown_schema(pointer, pointer_file)) + ".")
    root = Path(str(pointer.get("root", "")))
    if not owner_alive(root):
        raise SandboxUnavailable(
            f"The QA sandbox named in {pointer_file} is no longer running. {_START}"
        )
    phase = (marker(root) or {}).get("phase")
    owner = f"The QA sandbox (owner pid {pointer.get('owner_pid')})"
    if phase == STOPPING:
        raise SandboxUnavailable(f"{owner} is stopping. {_START}")
    state = read_json(root / STATE_FILE)
    if state is None or phase != RUNNING:
        raise SandboxUnavailable(f"{owner} is still starting; wait for its SANDBOX READY line.")
    if state.get("schema") != SCHEMA:
        raise SandboxUnavailable(sentence(unknown_schema(state, root / STATE_FILE)) + ".")
    return state


def watch_owner(root: Path, on_gone: Callable[[], None], *,
                owner: Optional[Mapping[str, Any]] = None, interval: float = 0.5) -> Any:
    """Call *on_gone()* once, from a daemon thread, when the sandbox at *root* ends.

    With *owner* (its ``owner_pid`` and ``started_at``), a new sandbox that
    claimed the same root in the meantime counts as the end too. A failure
    while watching counts as the end: the watch fails closed. Returns an
    event; setting it stops the watch without calling *on_gone*.
    """
    cancelled = threading.Event()

    def ended() -> bool:
        if not owner_alive(root):
            return True
        found = marker(root)  # None for an instant while the owner rewrites it
        return owner is not None and found is not None and not same_owner(found, owner)

    def watch() -> None:
        while not cancelled.wait(interval):
            try:
                if not ended():
                    continue
            except Exception:  # noqa: BLE001 - cannot tell: treat as ended
                pass
            on_gone()
            return

    threading.Thread(target=watch, name="qa-sandbox-watch", daemon=True).start()
    return cancelled


def confine_after(root: Path, write_roots: list, on_confined: Callable[[], None] = lambda: None,
                  *, owner: Optional[Mapping[str, Any]] = None) -> Any:
    """Once the sandbox at *root* ends, let this process write below *write_roots* only.

    For a long-lived process that hosts sandbox code without the owner
    watchdog (the TUI inside a textual-pilot-mcp server): a late write would
    otherwise bring the sandbox directory back, or land in the next sandbox
    started at the same root. Calls *on_confined()* after narrowing. Returns
    the watch's cancel event (see :func:`watch_owner`).
    """

    def confine() -> None:
        guard = child_guard.guard_module()
        guard.restrict_writes([str(path) for path in write_roots])
        on_confined()

    return watch_owner(root, confine, owner=owner)
