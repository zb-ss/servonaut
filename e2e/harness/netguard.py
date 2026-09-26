"""Guards that keep every process of the e2e suite inside its sandbox.

Standard library only: ``e2e/conftest.py`` installs this module in the test
process, and ``child_site/sitecustomize.py`` installs the same file in every
Python child process the suite starts.

Network
    ``connect()``, ``sendto()`` and every name or address lookup are allowed
    for loopback only. Unix sockets are allowed inside the write roots (the
    test root). Anything else is refused with :class:`NetworkEscapeError`.

Filesystem
    An audit hook refuses reads and writes below the protected directories
    (the developer's real home), except below the allowed roots (the test
    root, the checkout, the Python installation and its import roots), and
    refuses writes outside the write roots. Paths are compared after
    resolving symlinks. Refused operations raise :class:`ProtectedPathError`.

Programs
    The same hook refuses to start any program other than the fake tools in
    the spawn directories, this Python interpreter and ``/bin/sh`` or
    ``/bin/bash``; refused starts raise :class:`SpawnEscapeError`. The one
    exception is granted by the OpenSSH pass-through of the loopback SSH
    journeys, in its own process only (:func:`allow_ssh_clients`): the real
    ``ssh`` and ``scp`` may start as ``<client> -F <sandbox config> ...``,
    with no other config, and ``scp`` only with an ``ssh`` from the fake
    tools.

Every refusal is recorded. Children write their records as JSON lines to the
file named by ``SERVONAUT_E2E_GUARD_LOG`` and, once armed, one line to
``SERVONAUT_E2E_ARMED_LOG``; the parent fails a journey whose children tried
to escape or never armed their guard.
"""

from __future__ import annotations

import errno
import ipaddress
import json
import os
import shutil
import socket
import sys
import threading
import time
from typing import Any, Iterable, Optional

ENV_LOG = "SERVONAUT_E2E_GUARD_LOG"
ENV_ARMED_LOG = "SERVONAUT_E2E_ARMED_LOG"
ENV_PROTECTED = "SERVONAUT_E2E_PROTECTED_DIRS"
ENV_ALLOWED = "SERVONAUT_E2E_ALLOWED_DIRS"
ENV_WRITE_ROOTS = "SERVONAUT_E2E_WRITE_ROOTS"
ENV_SPAWN_DIRS = "SERVONAUT_E2E_SPAWN_DIRS"

_LOOPBACK_NAMES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
)
_SHELLS = ("/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash")

# Audit events that carry filesystem paths: (argument position, whether the
# event writes there, position of the matching dir_fd argument or None).
# "open" (builtins.open, io.open_code, os.open) is classified from its mode
# and flags; its event does not carry dir_fd, so a relative path is resolved
# against the working directory.
_PATH_EVENTS: dict[str, tuple[tuple[int, bool, Optional[int]], ...]] = {
    "open": ((0, False, None),),
    "os.listdir": ((0, False, None),),
    "os.scandir": ((0, False, None),),
    "os.mkdir": ((0, True, 2),),
    "os.remove": ((0, True, 1),),
    "os.rmdir": ((0, True, 1),),
    "os.chmod": ((0, True, 2),),
    "os.chown": ((0, True, 3),),
    "os.truncate": ((0, True, None),),
    "os.utime": ((0, True, 3),),
    "os.rename": ((0, True, 2), (1, True, 3)),
    "os.link": ((0, False, 2), (1, True, 3)),
    "os.symlink": ((0, False, None), (1, True, 2)),
    "shutil.copyfile": ((0, False, None), (1, True, None)),
    "shutil.copymode": ((0, False, None), (1, True, None)),
    "shutil.copystat": ((0, False, None), (1, True, None)),
    "shutil.copytree": ((0, False, None), (1, True, None)),
    "shutil.move": ((0, True, None), (1, True, None)),
    "shutil.rmtree": ((0, True, 1),),
}
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
# Events that act on a symbolic link itself, never on its target: removing a
# link inside the test root that points elsewhere changes only the root.
_LINK_ITSELF_EVENTS = frozenset({"os.remove"})

# Audit events that start a program: event → (program position, env position
# or None). os.system carries only a command line and is always refused.
_SPAWN_EVENTS: dict[str, tuple[int, Optional[int]]] = {
    "subprocess.Popen": (0, 3),
    "os.exec": (0, 2),
    "os.posix_spawn": (0, 2),
    "os.spawn": (1, 3),
    "pty.spawn": (0, None),
}

_lock = threading.Lock()
_local = threading.local()
_violations: list[dict[str, Any]] = []
_log_path: Optional[str] = None
_network_installed = False
_audit_hook_installed = False
_protected: tuple[str, ...] = ()
_allowed: tuple[str, ...] = ()
_write_roots: tuple[str, ...] = ()
_spawn_dirs: tuple[str, ...] = ()
_spawn_programs: frozenset[str] = frozenset()
_ssh_programs: dict[str, str] = {}  # resolved path -> "ssh" or "scp"
_ssh_config: Optional[str] = None

# OpenSSH's own option strings (ssh.c, scp.c): a letter followed by ":" takes
# a value. scp's server-mode flags (d, f, t) are parsed so they can be refused.
OPENSSH_OPTSTRINGS = {
    "ssh": "1246ab:c:e:fgi:kl:m:no:p:qstvxyAB:CD:E:F:GI:J:KL:MNO:P:Q:R:S:TVw:W:XY",
    "scp": "12346ABCOTdfpqRrstvc:D:F:i:J:l:o:P:S:X:",
}

_original_connect = socket.socket.connect
_original_connect_ex = socket.socket.connect_ex
_original_sendto = socket.socket.sendto
_original_getaddrinfo = socket.getaddrinfo
_original_gethostbyname = socket.gethostbyname
_original_gethostbyname_ex = socket.gethostbyname_ex
_original_gethostbyaddr = socket.gethostbyaddr
_original_getnameinfo = socket.getnameinfo
_original_getfqdn = socket.getfqdn


class NetworkEscapeError(ConnectionRefusedError):
    """Raised instead of reaching a non-loopback host or a foreign socket."""


class ProtectedPathError(PermissionError):
    """Raised instead of touching a path outside the sandbox."""


class SpawnEscapeError(PermissionError):
    """Raised instead of starting a program the sandbox does not provide."""


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def within(path: str, root: str) -> bool:
    """True when *path* is *root* or lies below it (both already normalised)."""
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _resolve(path: str) -> str:
    return os.path.realpath(path)


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------


def violations() -> list[dict[str, Any]]:
    """Return a copy of the attempts recorded in this process."""
    with _lock:
        return list(_violations)


def clear() -> None:
    """Forget the attempts recorded in this process."""
    with _lock:
        _violations.clear()


def read_log(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Return the JSON lines in *path* (empty if none); a torn line is skipped."""
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        return []
    records = []
    for line in lines:
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except ValueError:
            continue  # a writer is mid-line
    return records


def _append(path: str, entry: dict[str, Any]) -> None:
    _local.busy = True
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
    except OSError:
        pass
    finally:
        _local.busy = False


def _record(kind: str, target: str) -> None:
    entry = {"kind": kind, "target": target, "pid": os.getpid(), "time": time.time()}
    with _lock:
        _violations.append(entry)
    if _log_path:
        _append(_log_path, entry)


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------


def is_loopback_host(host: object) -> bool:
    """Return True for loopback addresses, loopback names and wildcard binds."""
    if host is None:
        return True
    if isinstance(host, (bytes, bytearray)):
        host = bytes(host).decode("ascii", "replace")
    text = str(host).strip()
    if text == "":
        return True
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    text = text.split("%", 1)[0]
    if text.lower().rstrip(".") in _LOOPBACK_NAMES:
        return True
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    if address.is_loopback:
        return True
    mapped = getattr(address, "ipv4_mapped", None)
    return bool(mapped is not None and mapped.is_loopback)


def _is_ip_literal(host: object) -> bool:
    if isinstance(host, (bytes, bytearray)):
        host = bytes(host).decode("ascii", "replace")
    try:
        ipaddress.ip_address(str(host).strip("[]").split("%", 1)[0])
    except ValueError:
        return False
    return True


def _refused(kind: str, target: str) -> NetworkEscapeError:
    _record(kind, target)
    return NetworkEscapeError(errno.ECONNREFUSED, f"e2e network guard refused {kind} {target}")


def _check_unix_address(address: object, kind: str) -> None:
    if isinstance(address, (bytes, bytearray)):
        address = os.fsdecode(bytes(address))
    text = str(address)
    if text.startswith("\0"):
        raise _refused(kind, f"abstract unix socket {text[1:]!r}")
    path = _resolve(text if os.path.isabs(text) else os.path.join(os.getcwd(), text))
    if _write_roots and not is_writable(path):
        raise _refused(kind, f"unix socket {path}")


def _check_socket_address(sock: socket.socket, address: object, kind: str) -> None:
    try:
        family = sock.family
    except OSError:
        return
    if family == getattr(socket, "AF_UNIX", None):
        _check_unix_address(address, kind)
        return
    if family not in (socket.AF_INET, socket.AF_INET6):
        return
    if isinstance(address, tuple) and address:
        host, port = address[0], (address[1] if len(address) > 1 else "")
    else:
        host, port = address, ""
    if not is_loopback_host(host):
        raise _refused(kind, f"{host}:{port}")


def _check_name(host: object, kind: str = "resolve") -> None:
    # A forward lookup of an address literal needs no DNS; connect() checks it.
    if is_loopback_host(host) or (kind == "resolve" and _is_ip_literal(host)):
        return
    _record(kind, str(host))
    raise socket.gaierror(socket.EAI_NONAME, f"e2e network guard refused {kind} {host}")


def _guarded_connect(self: socket.socket, address: Any) -> None:
    _check_socket_address(self, address, "connect")
    return _original_connect(self, address)


def _guarded_connect_ex(self: socket.socket, address: Any) -> int:
    _check_socket_address(self, address, "connect")
    return _original_connect_ex(self, address)


def _guarded_sendto(self: socket.socket, data: Any, *args: Any) -> int:
    if args:
        _check_socket_address(self, args[-1], "sendto")
    return _original_sendto(self, data, *args)


def _guarded_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
    _check_name(host)
    return _original_getaddrinfo(host, port, *args, **kwargs)


def _guarded_gethostbyname(host: str) -> str:
    _check_name(host)
    return _original_gethostbyname(host)


def _guarded_gethostbyname_ex(host: str) -> Any:
    _check_name(host)
    return _original_gethostbyname_ex(host)


def _guarded_gethostbyaddr(host: str) -> Any:
    _check_name(host, "reverse lookup")
    return _original_gethostbyaddr(host)


def _guarded_getnameinfo(sockaddr: Any, flags: int) -> Any:
    host = sockaddr[0] if isinstance(sockaddr, tuple) and sockaddr else sockaddr
    _check_name(host, "reverse lookup")
    return _original_getnameinfo(sockaddr, flags)


def _guarded_getfqdn(name: str = "") -> str:
    # An empty name means this machine; the lookup that triggers goes through
    # the guarded gethostbyaddr.
    if name and name not in ("0.0.0.0", "::"):
        _check_name(name, "reverse lookup")
    return _original_getfqdn(name)


def install_network_guard() -> None:
    """Patch the socket module so only loopback traffic is possible."""
    global _network_installed
    if _network_installed:
        return
    socket.socket.connect = _guarded_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = _guarded_connect_ex  # type: ignore[method-assign]
    socket.socket.sendto = _guarded_sendto  # type: ignore[method-assign]
    socket.getaddrinfo = _guarded_getaddrinfo  # type: ignore[assignment]
    socket.gethostbyname = _guarded_gethostbyname  # type: ignore[assignment]
    socket.gethostbyname_ex = _guarded_gethostbyname_ex  # type: ignore[assignment]
    socket.gethostbyaddr = _guarded_gethostbyaddr  # type: ignore[assignment]
    socket.getnameinfo = _guarded_getnameinfo  # type: ignore[assignment]
    socket.getfqdn = _guarded_getfqdn  # type: ignore[assignment]
    _network_installed = True


# ---------------------------------------------------------------------------
# Filesystem and programs (one audit hook)
# ---------------------------------------------------------------------------


def _normalise(value: object, dir_fd: object = None, *, follow_final: bool = True) -> Optional[str]:
    """Absolute, symlink-free form of an audited path, or None if unknowable.

    With *follow_final* False the last component is kept as it is: the
    result names the directory entry itself, not what a link points to.
    """
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
    head, tail = os.path.split(text)
    if not follow_final and tail not in ("", ".", ".."):
        return os.path.join(_resolve(head), tail)
    return _resolve(text)


def is_protected(path: str) -> bool:
    """Return True when *path* lies below a protected, non-allowed directory."""
    if any(within(path, allowed) for allowed in _allowed):
        return False
    return any(within(path, protected) for protected in _protected)


def is_writable(path: str) -> bool:
    """Return True when writes to *path* are permitted.

    A write root ending in ``*`` is a name prefix (pytest's cache writes a
    ``pytest-cache-files-*`` directory next to ``.pytest_cache`` first).
    """
    if not _write_roots:
        return True
    return any(
        path.startswith(root[:-1]) if root.endswith("*") else within(path, root)
        for root in _write_roots
    )


def _open_writes(args: tuple[Any, ...]) -> bool:
    mode = args[1] if len(args) > 1 else None
    if isinstance(mode, str):
        return any(flag in mode for flag in "wax+")
    flags = args[2] if len(args) > 2 else 0
    return bool(isinstance(flags, int) and flags & _WRITE_FLAGS)


def _check_path_event(event: str, args: tuple[Any, ...]) -> None:
    for position, writes, dir_fd_position in _PATH_EVENTS[event]:
        if position >= len(args):
            continue
        dir_fd = None
        if dir_fd_position is not None and dir_fd_position < len(args):
            dir_fd = args[dir_fd_position]
        path = _normalise(args[position], dir_fd, follow_final=event not in _LINK_ITSELF_EVENTS)
        if path is None:
            continue
        if event == "open":
            writes = _open_writes(args)
        if is_protected(path):
            reason = "below a protected directory"
        elif writes and not is_writable(path):
            reason = "outside the test root"
        else:
            continue
        _record("filesystem", f"{event} {path}")
        raise ProtectedPathError(errno.EACCES, f"e2e guard refused {event} {reason}", path)


def _environment_path(env: object) -> str:
    if isinstance(env, dict):
        for key, value in env.items():
            name = os.fsdecode(key) if isinstance(key, bytes) else key
            if name == "PATH":
                return os.fsdecode(value) if isinstance(value, bytes) else str(value)
        return ""
    return os.environ.get("PATH", "")


def program_allowed(program: str, env: object = None) -> bool:
    """True when *program* (a path or a bare name) is one the sandbox provides."""
    if os.sep not in program:
        found = shutil.which(program, path=_environment_path(env))
        if found is None:
            return True  # nothing can run; the start fails on its own
        program = found
    path = _resolve(program)
    if path in _spawn_programs:
        return True
    return any(within(os.path.dirname(path), directory) for directory in _spawn_dirs)


def parse_openssh_argv(tool: str, args: list[str]) -> tuple[list[tuple[str, str]], list[str]]:
    """Split an ``ssh`` or ``scp`` argument list the way the client does.

    Returns ``(options, operands)``; options are ``(letter, value)`` pairs in
    order, with clustered flags (``-vF file``) taken apart. Like OpenSSH's
    getopt, parsing stops at the first operand, except that ``ssh`` parses
    options again after the destination unless ``--`` came first. Raises
    ValueError for an unknown option or a missing value.
    """
    spec = OPENSSH_OPTSTRINGS[tool]
    takes_value = {spec[i] for i in range(len(spec) - 1) if spec[i + 1] == ":"}
    letters = set(spec) - {":"}
    options: list[tuple[str, str]] = []
    operands: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return options, operands + args[index + 1:]
        if not arg.startswith("-") or arg == "-":
            operands.append(arg)
            index += 1
            if tool == "ssh" and len(operands) == 1:
                continue  # ssh reads options after the destination too
            return options, operands + args[index:]
        position = 1
        while position < len(arg):
            letter = arg[position]
            if letter not in letters:
                raise ValueError(f"unknown option -{letter}")
            if letter not in takes_value:
                options.append((letter, ""))
                position += 1
                continue
            value = arg[position + 1:]
            if not value:
                index += 1
                if index >= len(args):
                    raise ValueError(f"option -{letter} needs a value")
                value = args[index]
            options.append((letter, value))
            break
        index += 1
    return options, operands


def allow_ssh_clients(programs: dict[str, str], config: Optional[str]) -> None:
    """Allow the real OpenSSH clients in *programs* ({path: "ssh" | "scp"}).

    Called by the OpenSSH pass-through for its own process only. A client may
    then start as ``<client> -F <config> ...`` naming no other config; ``scp``
    must also take its ``ssh`` (``-S``) from the fake tools and may not run a
    local SFTP server (``-D``). Empty *programs* withdraws the allowance.
    """
    global _ssh_programs, _ssh_config
    _ssh_programs = {_resolve(p): tool for p, tool in programs.items()} if config else {}
    _ssh_config = config or None


def _ssh_client_allowed(program: str, argv: object) -> bool:
    """True for an allowed OpenSSH client started only with the sandbox config."""
    tool = _ssh_programs.get(_resolve(program)) if os.sep in program else None
    if tool is None or not isinstance(argv, (list, tuple)) or len(argv) < 3:
        return False
    words = [os.fsdecode(a) if isinstance(a, bytes) else str(a) for a in argv]
    if words[1:3] != ["-F", _ssh_config]:
        return False
    try:
        options, _operands = parse_openssh_argv(tool, words[1:])
    except ValueError:
        return False
    for letter, value in options:
        if letter == "F" and value != _ssh_config:
            return False
        if tool == "scp" and letter == "D":
            return False
        if tool == "scp" and letter == "S" and not any(
            within(os.path.dirname(_resolve(value)), d) for d in _spawn_dirs
        ):
            return False
    return True


def _spawn_argv(event: str, args: tuple[Any, ...]) -> object:
    position = {"os.spawn": 2, "pty.spawn": 0}.get(event, 1)
    return args[position] if position < len(args) else None


def _check_spawn_event(event: str, args: tuple[Any, ...]) -> None:
    if event == "os.system":
        _record("spawn", "os.system")
        raise SpawnEscapeError(errno.EACCES, "e2e guard refused os.system")
    program_position, env_position = _SPAWN_EVENTS[event]
    if program_position >= len(args):
        return
    program = args[program_position]
    if isinstance(program, (list, tuple)):  # pty.spawn passes argv
        program = program[0] if program else None
    if program is None:
        return
    program = os.fsdecode(os.fspath(program))
    env = args[env_position] if env_position is not None and env_position < len(args) else None
    if program_allowed(program, env) or _ssh_client_allowed(program, _spawn_argv(event, args)):
        return
    _record("spawn", f"{event} {program}")
    raise SpawnEscapeError(errno.EACCES, f"e2e guard refused to start {program}")


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    if getattr(_local, "busy", False):
        return
    if event in _PATH_EVENTS:
        _check_path_event(event, args)
    elif _spawn_programs and (event in _SPAWN_EVENTS or event == "os.system"):
        _check_spawn_event(event, args)


def _expand(paths: Iterable[str]) -> tuple[str, ...]:
    out: list[str] = []
    for raw in paths:
        if not raw:
            continue
        if raw.endswith("*"):
            candidates = [raw]
        else:
            candidates = [os.path.normpath(os.path.abspath(raw)), _resolve(raw)]
        for candidate in candidates:
            if candidate not in out:
                out.append(candidate)
    return tuple(out)


def install_filesystem_guard(
    protected: Iterable[str], allowed: Iterable[str], write_roots: Iterable[str] = ()
) -> None:
    """Refuse access below *protected* (unless below *allowed*) and writes
    outside *write_roots* (when any are given)."""
    global _audit_hook_installed, _protected, _allowed, _write_roots
    runtime_roots = {sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix}
    _protected = tuple(p for p in _expand(protected) if p != os.sep)
    # Import roots stay readable wherever they are (an editable install can
    # point at another checkout), unless one is a protected directory itself.
    import_roots = [
        entry
        for entry in sys.path
        if entry and os.path.isabs(entry) and _resolve(entry) not in _protected
    ]
    _allowed = _expand([*allowed, *runtime_roots, *import_roots])
    _write_roots = _expand([*write_roots, os.devnull]) if write_roots else ()
    if not _audit_hook_installed:
        sys.addaudithook(_audit_hook)
        _audit_hook_installed = True


def set_spawn_dirs(directories: Iterable[str]) -> None:
    """Allow programs from *directories* (the fake tools), this interpreter
    and the system shells; nothing else may be started."""
    global _spawn_dirs, _spawn_programs
    _spawn_dirs = tuple(_resolve(d) for d in directories if d)
    _spawn_programs = frozenset(
        _resolve(p) for p in (sys.executable, *_SHELLS) if p and os.path.exists(p)
    )


def disarm_filesystem_and_spawns() -> None:
    """Stop checking paths and program starts (the network guard stays)."""
    global _protected, _allowed, _write_roots, _spawn_dirs, _spawn_programs
    _protected = _allowed = _write_roots = _spawn_dirs = ()
    _spawn_programs = frozenset()
    allow_ssh_clients({}, None)


# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------


def install(
    *,
    log_path: Optional[str] = None,
    protected: Iterable[str] = (),
    allowed: Iterable[str] = (),
    write_roots: Iterable[str] = (),
    spawn_dirs: Optional[Iterable[str]] = None,
) -> None:
    """Install every guard. *log_path* receives one JSON line per attempt.

    ``spawn_dirs=None`` leaves program starts unchecked.
    """
    global _log_path
    _log_path = log_path
    install_network_guard()
    install_filesystem_guard(protected, allowed, write_roots)
    if spawn_dirs is not None:
        set_spawn_dirs(spawn_dirs)


def _split(name: str) -> list[str]:
    return [p for p in os.environ.get(name, "").split(os.pathsep) if p]


def install_from_environment() -> None:
    """Install every guard from ``SERVONAUT_E2E_*`` variables, then report armed."""
    install(
        log_path=os.environ.get(ENV_LOG) or None,
        protected=_split(ENV_PROTECTED),
        allowed=_split(ENV_ALLOWED),
        write_roots=_split(ENV_WRITE_ROOTS),
        spawn_dirs=_split(ENV_SPAWN_DIRS),
    )
    armed_log = os.environ.get(ENV_ARMED_LOG)
    if armed_log:
        try:
            with open("/proc/self/cmdline", "rb") as handle:
                cmdline = [os.fsdecode(part) for part in handle.read().split(b"\0") if part]
        except OSError:
            cmdline = []
        _append(armed_log, {"pid": os.getpid(), "ppid": os.getppid(), "cmdline": cmdline})
