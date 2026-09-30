"""Where the live QA sandbox is, and what it recorded about itself.

A running sandbox has a root directory holding ``state.json`` (see
``owner.py`` for its contents) and one per-user *pointer*,
``${XDG_STATE_HOME:-~/.local/state}/servonaut-qa/current.json``, naming that
file. The pointer is the only file a sandbox writes outside its root; it
makes "the live sandbox" unambiguous for every tool that drives it, whichever
checkout the tool runs from.

Standard library only: the textual-pilot-mcp host (``tpmcp_host.py``) loads
this file by path, outside any package.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping, Optional

SCHEMA = 1
SINGLE = "single"
MULTI_ACCOUNT = "multi-account"
SCENARIOS = (SINGLE, MULTI_ACCOUNT)
STATE_FILE = "state.json"
# Present in every sandbox root: only a directory carrying it is ever removed.
MARKER = ".servonaut-qa-sandbox"
POINTER_DIR = "servonaut-qa"
POINTER_FILE = "current.json"
CAPTURES_DIR = "captures"
DEFAULT_ROOT_NAME = ".qa-sandbox"
# Where the owner reads a desktop request (see owner.py and client.py).
DESKTOP_REQUEST = "control/desktop-request.json"
# Every process of a sandbox carries this variable, set to the sandbox root.
OWNER_ROOT_ENV = "SERVONAUT_E2E_OWNER_ROOT"

_HARNESS_DIR = Path(__file__).resolve().parent.parent / "harness"
_CHILD_GUARD = "_servonaut_e2e_child_guard"


class SandboxUnavailable(RuntimeError):
    """There is no live sandbox to use (the message says what to do)."""


def _child_guard() -> Any:
    """The harness's child guard module (side-effect free until ``arm()``)."""
    module = sys.modules.get(_CHILD_GUARD)
    if module is None:
        spec = importlib.util.spec_from_file_location(_CHILD_GUARD, _HARNESS_DIR / "child_guard.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[_CHILD_GUARD] = module
        spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Paths
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


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------


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
# Processes
# ---------------------------------------------------------------------------


def process_identity(pid: int) -> Optional[list[str]]:
    """What tells *pid* apart from a later process reusing the number."""
    identity = _child_guard().process_identity(pid)
    return list(identity) if identity is not None else None


def is_alive(pid: Any, identity: Any) -> bool:
    """True while *pid* is still the process *identity* was recorded for."""
    if not isinstance(pid, int) or pid <= 0:
        return False
    return bool(_child_guard().owner_alive(pid, tuple(identity) if identity else None))


def owner_alive(record: Mapping[str, Any]) -> bool:
    """True while the owner named in a pointer or state record still runs."""
    return is_alive(record.get("owner_pid"), record.get("owner_identity"))


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
    start = "Start one with `python -m e2e.sandbox up` in a Servonaut checkout."
    if pointer is None:
        raise SandboxUnavailable(f"No QA sandbox is running ({pointer_file} is missing). {start}")
    if not owner_alive(pointer):
        raise SandboxUnavailable(
            f"The QA sandbox named in {pointer_file} is no longer running "
            f"(owner pid {pointer.get('owner_pid')}). {start}"
        )
    state_file = Path(str(pointer.get("state", "")))
    state = read_json(state_file)
    if state is None:
        raise SandboxUnavailable(
            f"The QA sandbox (owner pid {pointer.get('owner_pid')}) is still starting: "
            f"{state_file} does not exist yet. Wait for its SANDBOX READY line."
        )
    if state.get("schema") != SCHEMA:
        raise SandboxUnavailable(
            f"{state_file} has schema {state.get('schema')!r}; this checkout reads schema "
            f"{SCHEMA}. Use the checkout that started the sandbox "
            f"({state.get('repo_root')}), or restart the sandbox from this one."
        )
    return state
