"""Ephemeral SSH key file management.

Guards against the secrets-on-disk window between writing a private key
(retrieved from a secrets provider like Bitwarden) and handing it to the
``ssh -i`` process. The key lives in a private directory (``~/.servonaut/tmp/``,
mode 0700) rather than the world-readable ``/tmp``, is chmod'd to 0600 before
any bytes are written, and is best-effort overwritten with zero bytes before
unlink so that user-space filesystem cache tools cannot recover it after exit.
"""

from __future__ import annotations

import atexit
import logging
import os
import secrets
import tempfile
import time
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

# Runtime dir used by both ephemeral and persistent helpers.
_RUNTIME_SUBDIR = Path(".servonaut") / "tmp"

# Prefix for persistent BW key files so cleanup_stale_bw_keys can target them
# safely without risk of removing unrelated files.
_BW_KEY_PREFIX = "bw-"

# Prefix used by :func:`ephemeral_ssh_key`. Its with-block normally wipes the
# file on exit, but a SIGKILL / power loss inside the block leaves the
# decrypted key behind — so the startup sweep must cover this prefix too.
_EPHEMERAL_KEY_PREFIX = "servonaut-ssh-"

# All key-file prefixes the stale-sweep backstop targets. Both point at
# decrypted private keys in the same runtime dir; both need the 24h
# abnormal-exit guarantee.
_STALE_SWEEP_PREFIXES = (_BW_KEY_PREFIX, _EPHEMERAL_KEY_PREFIX)

# Live BW key files awaiting removal at process exit. A SINGLE atexit sweeper
# walks this set instead of one closure per key: long-running surfaces (the
# MCP server / relay listener call :func:`persistent_bw_ssh_key` once per
# SSH-backed tool call) would otherwise accumulate an unbounded list of dead
# atexit callbacks. :func:`remove_bw_ssh_key` discards entries as soon as the
# per-call lifecycle deletes the file.
_live_bw_key_paths: set = set()
_atexit_sweeper_registered = False


def _sweep_live_bw_keys() -> None:
    """atexit sweeper: best-effort removal of every still-live BW key file."""
    for path in list(_live_bw_key_paths):
        with suppress(OSError):
            _zero_and_unlink(path)
    _live_bw_key_paths.clear()


def persistent_bw_ssh_key(key_body: str, *, prefix: str = _BW_KEY_PREFIX) -> str:
    """Write *key_body* to a long-lived 0600 tmpfile and return its path.

    Unlike :func:`ephemeral_ssh_key` (a context-manager that wipes the file
    when the ``with``-block exits), this helper returns immediately so the
    caller can pass the path to a detached child process (e.g. an SSH session
    launched in an external terminal window) that outlives the Python process.

    Tradeoff vs ephemeral_ssh_key
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    The key stays on disk until one of:

    * The caller's per-call lifecycle deletes it via
      :func:`remove_bw_ssh_key` (the MCP/relay pattern), or
    * The shared ``atexit`` sweeper fires at normal program exit (covers the
      common TUI case — user opens SSH, then quits later), or
    * :func:`cleanup_stale_bw_keys` runs on next startup (wired into the TUI
      app, the headless MCP/relay tool construction, and the CLI ssh entry
      point) and the file is older than *max_age_seconds* (covers abnormal
      exit / crash).

    The file is placed in ``~/.servonaut/tmp/`` (mode 0700) rather than
    ``/tmp`` to prevent other users on multi-user hosts from reading it.

    Args:
        key_body: Full OpenSSH private key text (BEGIN/END markers included).
        prefix: File name prefix.  Defaults to ``"bw-"`` so stale-key sweeper
            can identify them without touching other servonaut tmpfiles.

    Returns:
        Absolute path (str) to the written key file.

    Raises:
        OSError: If the runtime root cannot be created or written to.
    """
    runtime_dir = Path.home() / _RUNTIME_SUBDIR
    os.makedirs(str(runtime_dir), mode=0o700, exist_ok=True)
    os.chmod(str(runtime_dir), 0o700)

    body = key_body if key_body.endswith("\n") else key_body + "\n"

    # Use a random suffix so concurrent BW launches for the same instance
    # don't collide.
    rand_suffix = secrets.token_hex(8)
    filename = f"{prefix}{rand_suffix}"
    tmp_path = str(runtime_dir / filename)

    # O_CREAT | O_EXCL ensures no TOCTOU race when creating the file.
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, body.encode())
    finally:
        os.close(fd)

    logger.debug(
        "Created persistent BW SSH key tmpfile at %s (size=%d bytes)",
        tmp_path,
        len(body),
    )

    # Track the file for the shared atexit sweeper so normal process exit
    # removes it. One sweeper for the whole process — per-call registration
    # would grow the atexit list unboundedly in the long-running MCP server.
    global _atexit_sweeper_registered
    _live_bw_key_paths.add(tmp_path)
    if not _atexit_sweeper_registered:
        atexit.register(_sweep_live_bw_keys)
        _atexit_sweeper_registered = True

    return tmp_path


def remove_bw_ssh_key(path: str) -> None:
    """Best-effort removal of a key file written by :func:`persistent_bw_ssh_key`.

    Zero-overwrites then unlinks *path*; missing files and permission errors
    are silently ignored (the shared ``atexit`` sweeper and
    :func:`cleanup_stale_bw_keys` — run at every entry-point startup — remain
    as backstops). The path is also dropped from the live-key registry so the
    exit sweeper does not retain it.

    Intended for per-call lifecycles — e.g. the MCP server resolves a vault
    key, runs one ssh/scp subprocess, and must delete the file in a
    ``finally`` because the process is long-running and never "exits" between
    tool calls.
    """
    with suppress(OSError):
        _zero_and_unlink(path)
    _live_bw_key_paths.discard(path)


def cleanup_stale_bw_keys(max_age_seconds: int = 86400) -> None:
    """Remove stale key files older than *max_age_seconds* from the tmp dir.

    Sweeps both key-file prefixes that can hold a decrypted private key:
    ``bw-*`` (written by :func:`persistent_bw_ssh_key`) and
    ``servonaut-ssh-*`` (written by :func:`ephemeral_ssh_key`, whose
    with-block wipe never runs after a SIGKILL / power loss).

    Called once at startup by every surface that can materialize a key file
    (``ServonautApp.on_mount``, ``mcp.server.build_headless_tools``, the CLI
    ``servonaut ssh`` entry point) so crash-left decrypted keys never persist
    past the age threshold.  Silently does nothing when the tmp dir does not
    exist yet (first-run scenario).

    Args:
        max_age_seconds: Age threshold in seconds.  Files older than this
            are considered stale and removed.  Defaults to 86400 (24 h).
    """
    runtime_dir = Path.home() / _RUNTIME_SUBDIR
    if not runtime_dir.exists():
        return

    cutoff = time.time() - max_age_seconds
    for entry in runtime_dir.iterdir():
        if not entry.name.startswith(_STALE_SWEEP_PREFIXES):
            continue
        try:
            mtime = entry.stat().st_mtime
        except OSError:
            continue
        if mtime < cutoff:
            with suppress(OSError):
                _zero_and_unlink(str(entry))
                logger.debug("Removed stale BW SSH key: %s", entry)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _zero_and_unlink(path: str) -> None:
    """Best-effort zero-overwrite then unlink *path*."""
    with suppress(OSError):
        file_size = os.path.getsize(path)
        with open(path, "r+b") as fh:
            fh.seek(0)
            fh.write(b"\x00" * file_size)
            fh.flush()
            os.fsync(fh.fileno())
    with suppress(OSError):
        os.unlink(path)


@contextmanager
def ephemeral_ssh_key(key_body: str, *, prefix: str = _EPHEMERAL_KEY_PREFIX) -> Iterator[str]:
    """Yield a 0600-permission tmpfile path containing the given SSH key body.

    The file is created in a private directory (mode 0700) inside the user's
    runtime root (~/.servonaut/tmp/) so even an errant /tmp readability bug
    can't expose it. Both the file and its containing directory are removed
    on context exit, even when an exception propagates out of the with-block.

    On exit, the file contents are best-effort overwritten with zero bytes
    before unlink. This is NOT a guaranteed secure wipe on modern SSDs (which
    may keep prior copies via wear leveling), but it removes the key from the
    filesystem cache that user-space tools can reach.

    Args:
        key_body: The OpenSSH private key text (the full PEM/OpenSSH block,
            including the BEGIN/END markers and trailing newline).
        prefix: Tmpfile name prefix for human-greppable cleanup if a crash
            leaves something behind. Defaults to ``"servonaut-ssh-"``.

    Yields:
        Absolute path to the tmpfile (str). SSH's ``-i`` accepts this path
        as-is.

    Raises:
        OSError: If the runtime root cannot be created (rare — disk full,
            permission issue on $HOME).
    """
    runtime_dir = Path.home() / ".servonaut" / "tmp"
    os.makedirs(str(runtime_dir), mode=0o700, exist_ok=True)
    # Defensively re-apply 0700 in case dir pre-existed with looser perms.
    os.chmod(str(runtime_dir), 0o700)

    # Ensure the key body ends with a newline — SSH parsers can be picky.
    body = key_body if key_body.endswith("\n") else key_body + "\n"

    tmp_file = tempfile.NamedTemporaryFile(
        prefix=prefix,
        dir=str(runtime_dir),
        delete=False,
        mode="w",
    )
    tmp_path = tmp_file.name
    try:
        # Set 0600 BEFORE writing so the key is never readable by others even
        # transiently.
        os.fchmod(tmp_file.fileno(), 0o600)
        tmp_file.write(body)
        tmp_file.flush()
        tmp_file.close()

        logger.debug(
            "Created ephemeral SSH key tmpfile at %s (size=%d bytes)",
            tmp_path,
            len(body),
        )
        yield tmp_path
    finally:
        # Best-effort zero-overwrite before unlink.
        _zero_and_unlink(tmp_path)
