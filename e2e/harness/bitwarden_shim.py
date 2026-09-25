"""Program behind the fake Bitwarden CLIs, ``bws`` and ``bw``.

The generated shim for each tool runs::

    <python> -I bitwarden_shim.py <shim-dir> <tool> [arguments...]

It answers from a small vault kept in ``<shim-dir>/bitwarden.json`` (written
by ``e2e/harness/bitwarden.py``) and appends one JSON line per call to
``<shim-dir>/argv.jsonl``, like the other fake tools. Next to the arguments
it records which credential variables were present in its environment, by
name only, so a journey can prove a token travelled through the environment
and never on the command line.

The behaviour follows the real tools where the product depends on it:

* ``bws`` reads its access token from ``BWS_ACCESS_TOKEN`` (or
  ``--access-token``) and nothing else; it prints JSON.
* ``bw`` needs the session from ``BW_SESSION`` (or ``--session``) for vault
  reads, and reports a locked vault or a missing item on stderr with the
  messages the Bitwarden CLI uses.

Standard library only; it runs in Python's isolated mode.
"""

from __future__ import annotations

import fcntl
import json
import os
import sys
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterator, Optional

STATE_FILE = "bitwarden.json"
LOG_FILE = "argv.jsonl"
BWS_TOKEN_VARIABLE = "BWS_ACCESS_TOKEN"
BW_SESSION_VARIABLE = "BW_SESSION"
# Credential variables whose presence every call records.
WATCHED_VARIABLES = (BWS_TOKEN_VARIABLE, BW_SESSION_VARIABLE)


class Refusal(Exception):
    """The fake tool fails the way the real one would."""

    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


@contextmanager
def _vault(shim_dir: str) -> Iterator[dict[str, Any]]:
    """The vault state, locked for a read-modify-write."""
    path = os.path.join(shim_dir, STATE_FILE)
    with open(path, "r+", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            state = json.load(handle)
            before = json.dumps(state, sort_keys=True)
            yield state
            if json.dumps(state, sort_keys=True) != before:
                handle.seek(0)
                handle.truncate()
                json.dump(state, handle, indent=2)
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _record(shim_dir: str, tool: str, args: list[str], watched: list[str]) -> None:
    record = {
        "tool": tool,
        "argv": args,
        "cwd": os.getcwd(),
        "time": time.time(),
        "rule": "bitwarden-vault",
        "sequence": int(time.monotonic_ns()),
        "env": {name: bool(os.environ.get(name)) for name in watched},
    }
    with open(os.path.join(shim_dir, LOG_FILE), "a", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            handle.write(json.dumps(record) + "\n")
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def _take_option(args: list[str], *names: str) -> Optional[str]:
    """Remove ``--name value`` (or ``--name=value``) from *args*; return value."""
    for index, arg in enumerate(list(args)):
        for name in names:
            if arg == name and index + 1 < len(args):
                value = args[index + 1]
                del args[index:index + 2]
                return value
            if arg.startswith(name + "="):
                del args[index]
                return arg.split("=", 1)[1]
    return None


# ---------------------------------------------------------------------------
# bws (Secrets Manager)
# ---------------------------------------------------------------------------


def _bws(state: dict[str, Any], args: list[str]) -> Any:
    bws = state["bws"]
    _take_option(args, "--output", "-o")
    token = _take_option(args, "--access-token", "-t") or os.environ.get(BWS_TOKEN_VARIABLE)
    if not token:
        raise Refusal("Error: \n   0: Missing access token\n")
    if token != bws.get("token"):
        raise Refusal("Error: \n   0: Invalid access token\n")
    command = args[:2]
    rest = args[2:]
    if command == ["project", "list"]:
        return bws["projects"]
    if command == ["secret", "list"]:
        project = rest[0] if rest else None
        return [s for s in bws["secrets"] if project is None or s["projectId"] == project]
    if command == ["secret", "get"] and rest:
        return _bws_secret(bws, rest[0])
    if command == ["secret", "create"] and len(rest) >= 3:
        key, value, project = rest[:3]
        if not any(p["id"] == project for p in bws["projects"]):
            raise Refusal("Error: \n   0: Resource not found\n")
        secret = {
            "object": "secret",
            "id": str(uuid.uuid4()),
            "organizationId": bws["organization_id"],
            "projectId": project,
            "key": key,
            "value": value,
            "note": "",
            "creationDate": _now(),
            "revisionDate": _now(),
        }
        bws["secrets"].append(secret)
        return secret
    if command == ["secret", "edit"] and rest:
        secret = _bws_secret(bws, rest[0])
        options = rest[1:]
        for field, flag in (("key", "--key"), ("value", "--value"), ("note", "--note")):
            value = _take_option(options, flag)
            if value is not None:
                secret[field] = value
        secret["revisionDate"] = _now()
        return secret
    if command == ["secret", "delete"] and rest:
        for secret_id in rest:
            bws["secrets"].remove(_bws_secret(bws, secret_id))
        return f"{len(rest)} secret{'s' if len(rest) != 1 else ''} deleted successfully."
    raise Refusal(f"error: unrecognized subcommand '{' '.join(args)}'\n", code=2)


def _bws_secret(bws: dict[str, Any], secret_id: str) -> dict[str, Any]:
    for secret in bws["secrets"]:
        if secret["id"] == secret_id:
            return secret
    raise Refusal("Error: \n   0: Resource not found\n")


# ---------------------------------------------------------------------------
# bw (Password Manager)
# ---------------------------------------------------------------------------


def _bw(state: dict[str, Any], args: list[str]) -> Any:
    bw = state["bw"]
    session = _take_option(args, "--session") or os.environ.get(BW_SESSION_VARIABLE)
    unlocked = bool(session) and session == bw.get("session")
    if args[:1] == ["status"]:
        status = "unlocked" if unlocked else "locked"
        return {"serverUrl": None, "lastSync": _now(), "userEmail": "", "status": status}
    if args[:1] == ["unlock"]:
        variable = _take_option(args, "--passwordenv")
        password = os.environ.get(variable or "", "")
        if not password or password != bw.get("password"):
            raise Refusal("Invalid master password.\n")
        return bw["session"] if "--raw" in args else f"Your vault is now unlocked!\n{bw['session']}"
    if args[:1] == ["lock"]:
        return "Your vault is locked."
    if not unlocked:
        raise Refusal("Vault is locked.\n")
    if args[:1] == ["sync"]:
        return "Syncing complete."
    if args[:2] == ["get", "item"] and len(args) > 2:
        for item in bw["items"]:
            if item["id"] == args[2]:
                return item
        raise Refusal("Not found.\n")
    if args[:2] == ["list", "items"]:
        search = _take_option(args, "--search")
        return [i for i in bw["items"] if not search or search.lower() in i["name"].lower()]
    if args[:2] == ["list", "folders"]:
        return []
    raise Refusal(f"error: unknown command '{' '.join(args)}'\n")


def main(argv: list[str]) -> int:
    shim_dir, tool, args = argv[1], argv[2], list(argv[3:])
    _record(shim_dir, tool, list(args), list(WATCHED_VARIABLES))
    try:
        with _vault(shim_dir) as state:
            result = _bws(state, args) if tool == "bws" else _bw(state, args)
    except Refusal as refusal:
        sys.stderr.write(refusal.message)
        return refusal.code
    sys.stdout.write(result if isinstance(result, str) else json.dumps(result, indent=2))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
