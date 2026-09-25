"""Run the real OpenSSH ``ssh`` / ``scp`` against the suite's loopback servers.

Journeys that use :mod:`e2e.harness.sshd` replace the fake ``ssh`` and
``scp`` on the journey's PATH with a two-line script that runs::

    <python> -s openssh_shim.py <shim-dir> <tool> <real-tool> <real-ssh> <config> [args...]

The shim records the call in ``<shim-dir>/argv.jsonl`` (the same log the
scripted fakes write), then checks that the connection can only reach
loopback: it asks OpenSSH itself (``ssh -G``) where the arguments lead, and
refuses unless the host name is a loopback address. Jump hosts (ProxyJump)
are resolved and checked the same way, because OpenSSH starts each hop with
its own binary rather than through PATH; a ProxyCommand must be a bare
``ssh``, which PATH brings back through this shim. Finally it replaces
itself with the real client, always with ``-F <config>`` first, so OpenSSH
reads the sandbox config and no ``~/.ssh/config`` or system config.

The process runs with the e2e guard installed (via ``child_site``); the
guard lets it start the real clients only with exactly that ``-F`` pair.
Standard library only.
"""

from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import subprocess
import sys
import time
from typing import Optional

REFUSED = 255
# scp options that take a value (OpenSSH 9.x).
_SCP_VALUE_OPTIONS = frozenset("cDFiJloPSX")


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


def _strip_config(args: list[str], config: str) -> Optional[list[str]]:
    """Remove ``-F <config>``; None when another config file is named."""
    out: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "-F":
            if index + 1 >= len(args) or args[index + 1] != config:
                return None
            index += 2
            continue
        if arg.startswith("-F") and len(arg) > 2 and not arg.startswith("--"):
            if arg[2:] != config:
                return None
            index += 1
            continue
        out.append(arg)
        index += 1
    return out


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return host in ("localhost",)


def _effective(real_ssh: str, config: str, args: list[str]) -> Optional[dict[str, str]]:
    """OpenSSH's own view of where *args* connect (``ssh -G``)."""
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
    settings: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        settings.setdefault(key.lower(), value)
    return settings


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


def _connection_problem(real_ssh: str, config: str, args: list[str], depth: int = 0) -> str:
    """Why *args* could reach something other than loopback ("" when they cannot)."""
    settings = _effective(real_ssh, config, args)
    if settings is None:
        return "OpenSSH could not evaluate the connection"
    command = settings.get("proxycommand", "none")
    if command != "none":
        words = command.split()
        if words[:1] == ["exec"]:
            words = words[1:]
        first = words[0] if words else ""
        # A bare "ssh" is found on PATH, i.e. this shim again, and checked there.
        return "" if first == "ssh" else f"ProxyCommand {first!r} is not allowed"
    jump = settings.get("proxyjump", "none")
    if jump != "none":
        # OpenSSH runs each hop with its own binary (not through PATH), so the
        # hops are checked here. The final destination is reached from the
        # last hop, which only forwards to loopback.
        if depth >= 3:
            return "too many jump hosts"
        for hop in _jump_hops(jump):
            problem = _connection_problem(real_ssh, config, hop, depth + 1)
            if problem:
                return f"jump host {hop[-1]!r}: {problem}"
        return ""
    host = settings.get("hostname", "")
    return "" if _is_loopback(host) else f"{host!r} is not a loopback address"


def _scp_ssh_args(args: list[str]) -> tuple[list[str], list[str]]:
    """Split scp arguments into ssh options that affect routing and the hosts."""
    options: list[str] = []
    hosts: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg.startswith("-") and len(arg) > 1:
            letter = arg[1]
            value = arg[2:] or (args[index + 1] if index + 1 < len(args) else "")
            consumed = 2 if not arg[2:] and letter in _SCP_VALUE_OPTIONS else 1
            if letter == "o":
                options += ["-o", value]
            elif letter == "J":
                options += ["-J", value]
            elif letter == "P":
                options += ["-p", value]
            elif letter == "S":
                return [], ["<-S program>"]
            index += consumed
            continue
        if arg.startswith("scp://"):
            hosts.append(arg[len("scp://"):].split("/", 1)[0].rsplit("@", 1)[-1].split(":")[0])
        elif ":" in arg.split("/", 1)[0]:
            hosts.append(arg.split(":", 1)[0].rsplit("@", 1)[-1])
        index += 1
    return options, hosts


def main(argv: list[str]) -> int:
    shim_dir, tool, real_tool, real_ssh, config = argv[1:6]
    args = argv[6:]
    _record(shim_dir, tool, args, "openssh")
    stripped = _strip_config(args, config)
    if stripped is None:
        return _refuse("only the sandbox ssh config may be used")
    if tool == "ssh":
        problem = _connection_problem(real_ssh, config, stripped)
    else:
        options, hosts = _scp_ssh_args(stripped)
        problem = ""
        for host in hosts:
            if host == "<-S program>":
                problem = "scp -S is not allowed"
                break
            problem = _connection_problem(real_ssh, config, [*options, host])
            if problem:
                break
    if problem:
        return _refuse(f"refused to connect: {problem}")
    sys.stdout.flush()
    sys.stderr.flush()
    os.execv(real_tool, [real_tool, "-F", config, *stripped])
    return REFUSED  # not reached


if __name__ == "__main__":
    sys.exit(main(sys.argv))
