"""Program behind every fake tool on the suite's PATH.

Each generated shim (``ssh``, ``scp``, ``xterm`` ...) is a two-line shell
script that runs::

    <python> -I shim_runner.py <shim-dir> <tool> [arguments...]

The runner appends one JSON line per call to ``<shim-dir>/argv.jsonl`` and
answers from the first rule in ``<shim-dir>/scenario.json`` whose tool and
regular expression match. A terminal emulator shim runs the command it was
given (the SSH wrapper script), with stdin closed, so the wrapper's own logic
executes and calls the ``ssh`` shim in turn.

Standard library only; it runs in Python's isolated mode.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from typing import Any, Optional

_SHELLS = {
    "bash": ("/bin/bash", "/usr/bin/bash", "/bin/sh"),
    "sh": ("/bin/sh", "/usr/bin/sh"),
}
_TERMINAL_TIMEOUT_SECONDS = 30


def _load_rules(shim_dir: str) -> list[dict[str, Any]]:
    try:
        with open(os.path.join(shim_dir, "scenario.json"), encoding="utf-8") as handle:
            return list(json.load(handle).get("rules", []))
    except (OSError, ValueError):
        return []


def _match(rules: list[dict[str, Any]], tool: str, args: list[str]) -> Optional[dict[str, Any]]:
    joined = " ".join(args)
    for rule in rules:
        if rule.get("tool") != tool:
            continue
        if re.search(rule.get("match", ""), joined):
            return rule
    return None


def _append(shim_dir: str, record: dict[str, Any]) -> None:
    path = os.path.join(shim_dir, "argv.jsonl")
    line = json.dumps(record) + "\n"
    with open(path, "a", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            handle.write(line)
            handle.flush()
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _terminal_command(args: list[str]) -> list[str]:
    """Return the command a terminal emulator was asked to run."""
    for marker in ("-e", "--"):
        if marker in args:
            command = args[args.index(marker) + 1:]
            break
    else:
        return []
    if len(command) == 1 and " " in command[0]:
        command = command[0].split(" ", 1)
        command = [command[0], command[1].strip("'\"")]
    if command and command[0] in _SHELLS:
        for candidate in _SHELLS[command[0]]:
            if os.path.exists(candidate):
                command[0] = candidate
                break
    return command


def _run_terminal(shim_dir: str, args: list[str], sequence: int) -> int:
    command = _terminal_command(args)
    if not command:
        return 0
    transcript = os.path.join(shim_dir, f"terminal-{sequence}.log")
    with open(transcript, "wb") as output:
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=_TERMINAL_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            output.write(f"\ne2e terminal shim: {exc}\n".encode())
            return 1
    return completed.returncode


def _identity(args: list[str]) -> Optional[dict[str, Any]]:
    """The state of the ``-i`` file an ``ssh``/``scp`` call names.

    Records only metadata and a digest: a journey proves which key was
    offered, with which permissions, without the key ever being logged.
    """
    if "-i" not in args or args.index("-i") + 1 >= len(args):
        return None
    path = args[args.index("-i") + 1]
    try:
        info = os.stat(path)
        with open(path, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
    except OSError:
        return {"path": path, "exists": False}
    return {
        "path": path,
        "exists": True,
        "mode": stat.S_IMODE(info.st_mode),
        "size": info.st_size,
        "sha256": digest,
    }


def main(argv: list[str]) -> int:
    shim_dir, tool, args = argv[1], argv[2], argv[3:]
    rules = _load_rules(shim_dir)
    rule = _match(rules, tool, args)
    record: dict[str, Any] = {
        "tool": tool,
        "argv": args,
        "cwd": os.getcwd(),
        "time": time.time(),
        "rule": rule.get("name") if rule else None,
    }
    if rule and rule.get("capture_stdin"):
        record["stdin"] = sys.stdin.read()
    if rule and rule.get("inspect_identity"):
        record["identity"] = _identity(args)
    sequence = int(time.monotonic_ns())
    record["sequence"] = sequence
    _append(shim_dir, record)

    if rule is None:
        sys.stderr.write(f"e2e shim: no scenario for {tool} {' '.join(args)}\n")
        return 255 if tool in ("ssh", "scp") else 1
    if rule.get("delay"):
        time.sleep(float(rule["delay"]))
    if rule.get("action") == "run_terminal_command":
        return _run_terminal(shim_dir, args, sequence)
    if rule.get("stdout"):
        sys.stdout.write(rule["stdout"])
        sys.stdout.flush()
    if rule.get("stderr"):
        sys.stderr.write(rule["stderr"])
        sys.stderr.flush()
    return int(rule.get("rc", 0))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
