"""Run the real OpenSSH ``ssh`` / ``scp`` against the suite's loopback servers.

Journeys that use :mod:`e2e.harness.sshd` replace the fake ``ssh`` and
``scp`` on the journey's PATH with a two-line script that runs::

    <python> -s openssh_shim.py <shim-dir> <tool> <real-tool> <real-ssh> <config> <root> [args...]

The shim records the call in ``<shim-dir>/argv.jsonl`` (the same log the
scripted fakes write) and then decides whether the call may run:

* The arguments are parsed exactly as OpenSSH parses them (clustered flags,
  options after the destination). The only config file allowed is the
  sandbox config; ``ssh -E`` (a log file) and ``-S`` (a control socket) are
  refused, and so are scp's local SFTP server (``-D``), its own ``-S``, its
  server modes and purely local copies.
* For ``ssh``, OpenSSH itself (``ssh -G``) reports the settings the call
  would use, command-line ``-o`` options included, with ``~`` and ``%d``
  already expanded. The host must be a loopback address (or be reached
  through jump hosts that are, each checked the same way); every file the
  settings name must be ``none``, ``/dev/null`` or inside the test root
  *<root>*; and nothing may run or load local code or reach an agent
  (``PermitLocalCommand``, ``KnownHostsCommand``, ``PKCS11Provider``,
  ``SecurityKeyProvider``, ``IdentityAgent``, ``ForwardAgent``, X11,
  ``ssh-keysign``, GSSAPI, DNS look-ups). A ProxyCommand must be a plain
  ``ssh ...`` command line, which PATH brings back through this shim.
* ``scp`` is run with ``-S <shim-dir>/ssh``, so every connection it makes
  goes through the ``ssh`` checks above.

The shim then replaces itself with the real client, ``-F <config>`` first.
It refuses to run without the e2e guard (installed by ``child_site``), and it
is the only process that asks the guard to allow the real clients
(``allow_ssh_clients``), for exactly the programs and config named on its
own command line. Standard library only.
"""

from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import shlex
import subprocess
import sys
import time
from typing import Any, Optional

REFUSED = 255
GUARD_MODULE = "_servonaut_e2e_netguard"
MAX_JUMP_DEPTH = 3

# Options refused on the command line, per client.
REFUSED_OPTIONS = {
    "ssh": {"E": "writing a log file (-E)", "S": "a control socket (-S)"},
    "scp": {
        "D": "a local SFTP server program (-D)",
        "S": "another ssh program (-S)",
        "d": "scp server mode (-d)",
        "f": "scp server mode (-f)",
        "t": "scp server mode (-t)",
    },
}
# ``ssh -G`` keys whose values are local files (several may be listed).
PATH_KEYS = (
    "identityfile",
    "certificatefile",
    "userknownhostsfile",
    "globalknownhostsfile",
    "controlpath",
    "revokedhostkeys",
)
# Settings that must have one of these values. A key ``ssh -G`` leaves out
# has its OpenSSH default, which is the safe value for each of these.
REQUIRED_SETTINGS = {
    "permitlocalcommand": {"no"},
    "knownhostscommand": {"none"},
    "pkcs11provider": {"none"},
    "securitykeyprovider": {"internal", "none"},
    "identityagent": {"none"},
    "forwardagent": {"no"},
    "forwardx11": {"no"},
    "enablesshkeysign": {"no"},
    "gssapiauthentication": {"no"},
    "canonicalizehostname": {"false", "no"},
    "verifyhostkeydns": {"false", "no"},
    "gatewayports": {"no"},
}
_NO_FILE = {"none", "/dev/null"}
# Characters that would make a ProxyCommand more than one plain command.
_SHELL_METACHARACTERS = frozenset("$`;|&<>()\\!*?[]{}\n\r'\"")


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


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return host == "localhost"


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def _argv_problem(guard: Any, tool: str, args: list[str], config: str) -> str:
    """Why the command line itself is not allowed ("" when it is)."""
    try:
        options, operands = guard.parse_openssh_argv(tool, args)
    except ValueError as exc:
        return str(exc)
    for letter, value in options:
        if letter == "F" and value != config:
            return "only the sandbox ssh config may be used"
        if letter in REFUSED_OPTIONS[tool]:
            return f"{REFUSED_OPTIONS[tool][letter]} is not allowed"
    if tool == "scp" and not any(_is_remote_operand(o) for o in operands):
        return "scp needs a remote side (local copies are not allowed)"
    return ""


def _is_remote_operand(operand: str) -> bool:
    """scp's own rule: ``scp://...``, or a ``:`` before the first ``/``."""
    if operand.startswith("scp://"):
        return True
    if operand.startswith("["):
        return "]:" in operand.split("/", 1)[0]
    return ":" in operand.split("/", 1)[0]


# ---------------------------------------------------------------------------
# Effective settings (ssh -G)
# ---------------------------------------------------------------------------


def _effective(real_ssh: str, config: str, args: list[str]) -> Optional[dict[str, list[str]]]:
    """OpenSSH's own view of the settings *args* would use (``ssh -G``)."""
    result = subprocess.run(
        [real_ssh, "-F", config, "-G", *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        return None
    settings: dict[str, list[str]] = {}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        settings.setdefault(key.lower(), []).append(value)
    return settings


def _first(settings: dict[str, list[str]], key: str, default: str = "none") -> str:
    return settings.get(key, [default])[0]


def _file_problem(settings: dict[str, list[str]], root: str) -> str:
    for key in PATH_KEYS:
        for value in settings.get(key, []):
            for path in value.split():
                if path in _NO_FILE:
                    continue
                if not os.path.isabs(path) or not _within(os.path.realpath(path), root):
                    return f"{key} {path!r} is outside the test root"
    return ""


def _settings_problem(settings: dict[str, list[str]]) -> str:
    for key, allowed in REQUIRED_SETTINGS.items():
        values = settings.get(key)
        if values is not None and values[0].lower() not in allowed:
            return f"{key} {values[0]!r} is not allowed"
    return ""


def _proxy_command_problem(command: str) -> str:
    if _SHELL_METACHARACTERS & set(command):
        return "ProxyCommand may not use shell syntax"
    words = shlex.split(command)
    if words[:1] == ["exec"]:
        words = words[1:]
    # A bare "ssh" is found on PATH, i.e. this shim again, and checked there.
    if words[:1] != ["ssh"]:
        return f"ProxyCommand {words[0] if words else ''!r} is not allowed"
    return ""


def _jump_hops(value: str) -> list[list[str]]:
    """``ssh`` arguments for each hop of a ProxyJump value (``[user@]host[:port],...``)."""
    hops = []
    for hop in value.split(","):
        hop = hop.strip().removeprefix("ssh://")
        user, _, rest = hop.rpartition("@")
        host, port = rest, ""
        if rest.startswith("["):
            host, _, tail = rest[1:].partition("]")
            port = tail[1:]
        elif rest.count(":") == 1:
            host, port = rest.split(":")
        hops.append((["-l", user] if user else []) + (["-p", port] if port else []) + [host])
    return hops


def _connection_problem(real_ssh: str, config: str, root: str, args: list[str],
                        depth: int = 0) -> str:
    """Why *args* could reach or touch something outside the sandbox ("" when not)."""
    settings = _effective(real_ssh, config, args)
    if settings is None:
        return "OpenSSH could not evaluate the connection"
    problem = _file_problem(settings, root) or _settings_problem(settings)
    if problem:
        return problem
    command = _first(settings, "proxycommand")
    if command != "none":
        return _proxy_command_problem(command)
    jump = _first(settings, "proxyjump")
    if jump != "none":
        # OpenSSH runs each hop with its own binary (not through PATH), so the
        # hops are checked here. The final destination is reached from the
        # last hop, which only forwards to loopback.
        if depth >= MAX_JUMP_DEPTH:
            return "too many jump hosts"
        for hop in _jump_hops(jump):
            problem = _connection_problem(real_ssh, config, root, hop, depth + 1)
            if problem:
                return f"jump host {hop[-1]!r}: {problem}"
        return ""
    host = _first(settings, "hostname", "")
    return "" if _is_loopback(host) else f"{host!r} is not a loopback address"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    shim_dir, tool, real_tool, real_ssh, config, root = argv[1:7]
    args = argv[7:]
    _record(shim_dir, tool, args, "openssh")
    guard = sys.modules.get(GUARD_MODULE)
    if guard is None:
        return _refuse("the e2e guard is not installed in this process")
    guard.allow_ssh_clients({real_ssh: "ssh", real_tool: tool}, config)
    problem = _argv_problem(guard, tool, args, config)
    if not problem and tool == "ssh":
        problem = _connection_problem(real_ssh, config, os.path.realpath(root), args)
    if problem:
        return _refuse(f"refused to connect: {problem}")
    extra = ["-S", os.path.join(shim_dir, "ssh")] if tool == "scp" else []
    sys.stdout.flush()
    sys.stderr.flush()
    os.execv(real_tool, [real_tool, "-F", config, *extra, *args])
    return REFUSED  # not reached


if __name__ == "__main__":
    sys.exit(main(sys.argv))
