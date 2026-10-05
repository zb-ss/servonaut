"""Run narrowly validated OpenSSH Vault-agent commands in hermetic journeys.

``SshWorld.install_clients`` replaces its normal fake ``ssh-agent`` and
``ssh-add`` programs with this pass-through. It permits only the operations
used by :class:`servonaut.services.vault.ssh_agent.PrivateSshAgent`:

* ``ssh-agent -a <owned Vault socket> -s``;
* ``ssh-add -t <bounded seconds> -`` against that socket; and
* ``ssh-agent -k`` for the same socket and a real agent process.

The helper never reads or records standard input. Its only real-tool exec is
an exact one-command allowance granted to the e2e guard after every path and
argument has been validated. Standard library only.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import sys
import time
from typing import Any


REFUSED = 255
GUARD_MODULE = "_servonaut_e2e_netguard"
MAX_TTL_SECONDS = 3600
_SOCKET_NAME = re.compile(r"agent-\d+-[0-9a-f]{16}\.sock\Z")
_VAULT_PARTS = (".servonaut", "vault", "tmp")
_SYSTEM_TOOL_DIRS = ("/usr/bin", "/bin", "/usr/local/bin", "/usr/sbin", "/sbin")


def _record(shim_dir: str, tool: str, args: list[str], rule: str) -> None:
    entry = {
        "tool": tool,
        "argv": args,
        "cwd": os.getcwd(),
        "time": time.time(),
        "rule": rule,
        "sequence": time.monotonic_ns(),
    }
    with open(os.path.join(shim_dir, "argv.jsonl"), "a", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            handle.write(json.dumps(entry) + "\n")
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _refuse(message: str) -> int:
    sys.stderr.write(f"e2e: {message}\n")
    return REFUSED


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _vault_directory(root: str) -> tuple[str | None, str]:
    """Return the active guarded home’s Vault socket directory."""
    raw_home = os.environ.get("HOME", "")
    if not raw_home or not os.path.isabs(raw_home):
        return None, "HOME is not an absolute hermetic path"
    home = os.path.normpath(raw_home)
    if home != os.path.realpath(home) or not _within(home, root):
        return None, "HOME is outside the hermetic test root"
    return os.path.join(home, *_VAULT_PARTS), ""


def _socket_problem(path: str, root: str, *, starting: bool) -> str:
    directory, problem = _vault_directory(root)
    if problem:
        return problem
    assert directory is not None
    candidate = os.path.normpath(path)
    if not os.path.isabs(path) or candidate != path or os.path.dirname(candidate) != directory:
        return "agent socket is outside the Vault custody directory"
    if _SOCKET_NAME.fullmatch(os.path.basename(candidate)) is None:
        return "agent socket does not have the Vault agent name"
    if os.path.realpath(candidate) != candidate:
        return "agent socket contains a symbolic link"

    # ``directory`` is ``<home>/.servonaut/vault/tmp``. Start the component
    # walk at that exact home, rather than trusting a separate path source.
    current = os.path.dirname(os.path.dirname(os.path.dirname(directory)))
    try:
        for part in _VAULT_PARTS:
            current = os.path.join(current, part)
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                return "Vault custody directory is not a real directory"
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            return "Vault custody directory has unsafe ownership or permissions"
        socket = os.lstat(candidate)
    except FileNotFoundError:
        return "" if starting else "agent socket does not exist"
    except OSError:
        return "agent socket could not be inspected"
    if starting:
        return "agent socket already exists"
    if stat.S_ISLNK(socket.st_mode) or not stat.S_ISSOCK(socket.st_mode):
        return "agent socket is not an owned Unix socket"
    if socket.st_uid != os.getuid():
        return "agent socket is not owned by this user"
    return ""


def _agent_problem(args: list[str], root: str, real_tool: str) -> str:
    if args[:1] == ["-a"] and len(args) == 3 and args[2] == "-s":
        return _socket_problem(args[1], root, starting=True)
    if args != ["-k"]:
        return "ssh-agent arguments are not allowed"
    socket = os.environ.get("SSH_AUTH_SOCK", "")
    problem = _socket_problem(socket, root, starting=False)
    if problem:
        return problem
    pid = os.environ.get("SSH_AGENT_PID", "")
    if not pid.isdecimal() or int(pid) <= 0:
        return "ssh-agent shutdown requires a numeric agent pid"
    try:
        executable = os.path.realpath(os.readlink(f"/proc/{pid}/exe"))
    except OSError:
        return "ssh-agent shutdown requires a live agent process"
    return "" if executable == os.path.realpath(real_tool) else "agent pid is not ssh-agent"


def _add_problem(args: list[str], root: str) -> str:
    if len(args) != 3 or args[0] != "-t" or args[2] != "-":
        return "ssh-add arguments are not allowed"
    if not args[1].isdecimal() or not 0 < int(args[1]) <= MAX_TTL_SECONDS:
        return "ssh-add TTL is not allowed"
    return _socket_problem(os.environ.get("SSH_AUTH_SOCK", ""), root, starting=False)


def _real_tool_problem(tool: str, real_tool: str) -> str:
    """Accept only the named OpenSSH binary from the fixed system tool dirs."""
    resolved = os.path.realpath(real_tool)
    if os.path.basename(resolved) != tool or os.path.dirname(resolved) not in _SYSTEM_TOOL_DIRS:
        return "agent tool is not the trusted system OpenSSH binary"
    return ""


def main(argv: list[str]) -> int:
    if len(argv) < 5:
        return _refuse("agent shim invocation is invalid")
    shim_dir, tool, real_tool, root = argv[1:5]
    args = argv[5:]
    _record(shim_dir, tool, args, "openssh-agent")
    guard: Any = sys.modules.get(GUARD_MODULE)
    if guard is None:
        return _refuse("the e2e guard is not installed in this process")
    root = os.path.realpath(root)
    if tool == "ssh-agent":
        problem = _agent_problem(args, root, real_tool)
    elif tool == "ssh-add":
        problem = _add_problem(args, root)
    else:
        problem = "agent tool is not allowed"
    problem = problem or _real_tool_problem(tool, real_tool)
    if problem:
        return _refuse(problem)
    guard.allow_ssh_agent_tool(real_tool, [real_tool, *args])
    os.execv(real_tool, [real_tool, *args])
    return REFUSED  # not reached


if __name__ == "__main__":
    sys.exit(main(sys.argv))
