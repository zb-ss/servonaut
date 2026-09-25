"""Keep the unit suite away from the developer's real home directory.

Several servonaut modules compute runtime paths from ``Path.home()`` when they
are imported (config, cache, auth, memory, relay lock, ...). ``tests/conftest.py``
calls :func:`isolate` before anything imports servonaut, so the whole session
runs against a throwaway home, and :func:`arm` installs an audit hook that
refuses, and records, any write that still lands under the real home.

The hook only sees this process. Child processes inherit the throwaway HOME.

This module must not import servonaut.
"""
from __future__ import annotations

import atexit
import errno
import os
import shutil
import sys
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# Per-user data locations some libraries read instead of HOME; each is pointed
# at the given directory inside the throwaway home.
_XDG_DIRECTORIES: Dict[str, Tuple[str, ...]] = {
    "XDG_CONFIG_HOME": (".config",),
    "XDG_DATA_HOME": (".local", "share"),
    "XDG_CACHE_HOME": (".cache",),
    "XDG_STATE_HOME": (".local", "state"),
}
_WINDOWS_DIRECTORIES: Dict[str, Tuple[str, ...]] = {
    "APPDATA": ("AppData", "Roaming"),
    "LOCALAPPDATA": ("AppData", "Local"),
}

# Variables that redirect a data location of their own, or name a profile
# defined in a file under the real home. Cleared so the defaults under the
# throwaway home apply, as they do on a CI runner.
_CLEARED_VARIABLES = (
    "SERVONAUT_VOICE_MODELS_DIR",
    "CODEX_HOME",
    "HF_HOME",
    "HF_HUB_CACHE",
    "HUGGINGFACE_HUB_CACHE",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
)

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC

# Audit event -> ((path argument position, dir_fd position or None), ...) for
# each path the event modifies. "open" counts only when its flags write.
_WRITE_EVENTS: Dict[str, Tuple[Tuple[int, Optional[int]], ...]] = {
    "open": ((0, None),),
    "os.mkdir": ((0, 2),),
    "os.remove": ((0, 1),),
    "os.rmdir": ((0, 1),),
    "os.rename": ((0, 2), (1, 3)),
    "os.link": ((1, 3),),
    "os.symlink": ((1, 2),),
    "os.chmod": ((0, 2),),
    "os.chown": ((0, 3),),
    "os.truncate": ((0, None),),
    "os.utime": ((0, 3),),
    "shutil.copyfile": ((1, None),),
    "shutil.copymode": ((1, None),),
    "shutil.copystat": ((1, None),),
    "shutil.copytree": ((1, None),),
    "shutil.move": ((0, None), (1, None)),
    "shutil.rmtree": ((0, 1),),
    "sqlite3.connect": ((0, None),),
}

Violation = Tuple[str, str]


class RealHomeWriteError(PermissionError):
    """Raised by the audit hook when the suite writes under the real home."""


@dataclass(frozen=True)
class Isolation:
    """The throwaway home in use and the real home it stands in for."""

    temp_home: Path
    real_home: Optional[Path]


_violations: List[Violation] = []
_violations_lock = threading.Lock()
_local = threading.local()
_guarded_home = ""
_allowed_roots: Tuple[str, ...] = ()
_hook_installed = False
_current: Optional[Isolation] = None


def real_home_directory() -> Optional[Path]:
    """The account's real home, whatever HOME says (a caller may fake it)."""
    if os.name == "posix":
        try:
            import pwd

            return Path(pwd.getpwuid(os.getuid()).pw_dir)
        except (ImportError, KeyError):
            return None
    profile = os.environ.get("USERPROFILE")
    return Path(profile) if profile else None


def isolate() -> Isolation:
    """Point this process at a throwaway home for the rest of the session.

    Must run before servonaut is imported; raises if it already was.
    """
    imported = sorted(m for m in sys.modules if m == "servonaut" or m.startswith("servonaut."))
    if imported:
        raise RuntimeError(
            "servonaut was imported before the test home was isolated "
            f"({imported[0]}), so its import-time paths point at the real home."
        )
    global _current
    real_home = real_home_directory()  # before HOME/USERPROFILE change
    temp_home = Path(tempfile.mkdtemp(prefix="servonaut-test-home-"))
    _point_environment_at(temp_home)
    if real_home is not None and not real_home.is_dir():
        real_home = None
    _current = Isolation(temp_home=temp_home, real_home=real_home)
    # atexit rather than a pytest hook: a run that stops with a usage error
    # before configuring (a missing dependency, a bad option) never reaches
    # pytest_unconfigure, and would leave the directory behind.
    atexit.register(cleanup, _current)
    return _current


def current() -> Isolation:
    """The isolation :func:`isolate` set up for this session."""
    if _current is None:
        raise RuntimeError("the test home has not been isolated")
    return _current


def arm(isolation: Isolation, allowed: Iterable[Path]) -> None:
    """Refuse writes under the real home, except below *allowed* roots.

    The throwaway home, the temporary directory, the interpreter and its
    import roots (bytecode caches) are always allowed.
    """
    global _guarded_home, _allowed_roots, _hook_installed
    if isolation.real_home is None:
        return
    home = _canonical(str(isolation.real_home))
    if os.path.dirname(home) == home:  # a filesystem root: nothing to guard
        return
    candidates = [
        *(str(path) for path in allowed),
        str(isolation.temp_home),
        tempfile.gettempdir(),
        sys.prefix,
        sys.exec_prefix,
        sys.base_prefix,
        sys.base_exec_prefix,
        *(entry for entry in sys.path if entry and os.path.isabs(entry)),
    ]
    roots: List[str] = []
    for candidate in candidates:
        root = _canonical(candidate)
        # A root that contains the whole home would re-open all of it.
        if _within(home, root) or root in roots:
            continue
        roots.append(root)
    _allowed_roots = tuple(roots)
    _guarded_home = home
    if not _hook_installed:
        sys.addaudithook(_audit_hook)  # cannot be removed; disarm() mutes it
        _hook_installed = True


def disarm() -> None:
    """Stop refusing writes (pytest's own end-of-run outputs may follow)."""
    global _guarded_home
    _guarded_home = ""


def is_armed() -> bool:
    return bool(_guarded_home)


def cleanup(isolation: Isolation) -> None:
    """Remove the throwaway home."""
    shutil.rmtree(isolation.temp_home, ignore_errors=True)


def violation_count() -> int:
    with _violations_lock:
        return len(_violations)


def violations_since(mark: int) -> List[Violation]:
    with _violations_lock:
        return list(_violations[mark:])


def all_violations() -> List[Violation]:
    with _violations_lock:
        return list(_violations)


@contextmanager
def expect_refused_writes() -> Iterator[List[Violation]]:
    """Collect, and forgive, the writes refused inside the block.

    Only for tests of the guard itself.
    """
    caught: List[Violation] = []
    with _violations_lock:
        mark = len(_violations)
    try:
        yield caught
    finally:
        with _violations_lock:
            caught.extend(_violations[mark:])
            del _violations[mark:]


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


def _point_environment_at(home: Path) -> None:
    os.environ["HOME"] = str(home)
    if os.name == "nt":
        drive, rest = os.path.splitdrive(str(home))
        os.environ["USERPROFILE"] = str(home)
        os.environ["HOMEDRIVE"] = drive
        os.environ["HOMEPATH"] = rest
        _point_directories(home, _WINDOWS_DIRECTORIES)
    _point_directories(home, _XDG_DIRECTORIES)
    for name in _CLEARED_VARIABLES:
        os.environ.pop(name, None)
    # Keep keyring calls away from the operating system's credential store.
    os.environ["PYTHON_KEYRING_BACKEND"] = "keyring.backends.null.Keyring"


def _point_directories(home: Path, mapping: Dict[str, Tuple[str, ...]]) -> None:
    for name, parts in mapping.items():
        directory = home.joinpath(*parts)
        directory.mkdir(parents=True, exist_ok=True)
        os.environ[name] = str(directory)


# ---------------------------------------------------------------------------
# Audit hook
# ---------------------------------------------------------------------------


def _canonical(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _opens_for_writing(args: Tuple[Any, ...]) -> bool:
    flags = args[2] if len(args) > 2 else None
    if isinstance(flags, int):
        return bool(flags & _WRITE_FLAGS)
    mode = args[1] if len(args) > 1 else None
    return isinstance(mode, str) and any(flag in mode for flag in "wax+")


def _absolute(value: object, dir_fd: object) -> Optional[str]:
    if value is None or isinstance(value, int):
        return None
    try:
        text = os.fspath(value)  # type: ignore[arg-type]
    except TypeError:
        return None
    if isinstance(text, bytes):
        text = os.fsdecode(text)
    if not text:
        return None
    if not os.path.isabs(text):
        if isinstance(dir_fd, int):
            try:
                base = os.readlink(f"/proc/self/fd/{dir_fd}")
            except OSError:
                return None  # cannot tell where a dir_fd-relative path points
        else:
            base = os.getcwd()
        text = os.path.join(base, text)
    return _canonical(text)


def _refused(path: str, home: str) -> bool:
    if not _within(path, home):
        return False
    return not any(_within(path, root) for root in _allowed_roots)


def _audit_hook(event: str, args: Tuple[Any, ...]) -> None:
    positions = _WRITE_EVENTS.get(event)
    home = _guarded_home
    if positions is None or not home or getattr(_local, "busy", False):
        return
    if event == "open" and not _opens_for_writing(args):
        return
    _local.busy = True
    try:
        for path_position, dir_fd_position in positions:
            if path_position >= len(args):
                continue
            dir_fd = None
            if dir_fd_position is not None and dir_fd_position < len(args):
                dir_fd = args[dir_fd_position]
            try:
                path = _absolute(args[path_position], dir_fd)
            except (OSError, ValueError):  # e.g. a deleted working directory
                continue
            if path is None or not _refused(path, home):
                continue
            with _violations_lock:
                _violations.append((event, path))
            raise RealHomeWriteError(
                errno.EACCES,
                f"test suite refused {event} under the real home directory",
                path,
            )
    finally:
        _local.busy = False
