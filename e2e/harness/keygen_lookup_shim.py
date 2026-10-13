"""``ssh-keygen`` for the QA sandbox: real known_hosts lookups, the recording stand-in otherwise.

The sandbox's SSH clients are real, so the host keys a user accepts land in
real known_hosts files. Finding one again (``ssh-keygen -F NAME -f FILE``, as
Use Vault Key and Auto-bind do) needs the real tool; any other use goes to the
suite's recording stand-in, unchanged. The real tool runs only for that one
read-only form, on a file inside the sandbox, through the e2e guard's
one-exact-command allowance. Standard library only.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any

GUARD_MODULE = "_servonaut_e2e_netguard"
REFUSED = 255
# A known_hosts name: a host, [host]:port, or a cloud server's alias.
_NAME = re.compile(r"[A-Za-z0-9._:@\[\]-]{1,255}\Z")
_SYSTEM_TOOL_DIRS = ("/usr/bin", "/bin", "/usr/local/bin")


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _is_lookup(args: list[str], root: str) -> bool:
    if len(args) != 4 or args[0] != "-F" or args[2] != "-f" or not _NAME.match(args[1]):
        return False
    path = args[3]
    return os.path.isabs(path) and _within(os.path.realpath(path), os.path.realpath(root))


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        sys.stderr.write("e2e: ssh-keygen lookup shim invocation is invalid\n")
        return REFUSED
    real_tool, root, recorder = argv[1:4]
    args = argv[4:]
    guard: Any = sys.modules.get(GUARD_MODULE)
    if _is_lookup(args, root) and guard is not None and os.path.dirname(real_tool) in _SYSTEM_TOOL_DIRS:
        guard.allow_ssh_agent_tool(real_tool, [real_tool, *args])
        os.execv(real_tool, [real_tool, *args])
    os.execv(recorder, [recorder, *args])
    return REFUSED  # not reached


def install(shim_dir: str, real_tool: str, root: str) -> None:
    """Put the lookup pass-through in front of the recording ``ssh-keygen`` in *shim_dir*."""
    import shlex

    shim_dir = os.path.abspath(shim_dir)
    script = os.path.join(shim_dir, "ssh-keygen")
    recorder = os.path.join(shim_dir, ".ssh-keygen-recorder")
    if not os.path.exists(recorder):  # installing twice keeps the original stand-in
        with open(script, encoding="utf-8") as handle:
            recorded = handle.read()
        with open(recorder, "w", encoding="utf-8") as handle:
            handle.write(recorded)
        os.chmod(recorder, 0o755)
    words = [sys.executable, "-s", os.path.abspath(__file__), real_tool, root, recorder]
    with open(script, "w", encoding="utf-8") as handle:
        handle.write(f'#!/bin/sh\nexec {shlex.join(words)} "$@"\n')
    os.chmod(script, 0o755)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
