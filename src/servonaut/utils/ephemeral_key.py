"""Ephemeral SSH key file management.

Guards against the secrets-on-disk window between writing a private key
(retrieved from a secrets provider like Bitwarden) and handing it to the
``ssh -i`` process. The key lives in a private directory (``~/.servonaut/tmp/``,
mode 0700) rather than the world-readable ``/tmp``, is chmod'd to 0600 before
any bytes are written, and is best-effort overwritten with zero bytes before
unlink so that user-space filesystem cache tools cannot recover it after exit.
"""

from __future__ import annotations

import logging
import os
import tempfile
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)


@contextmanager
def ephemeral_ssh_key(key_body: str, *, prefix: str = "servonaut-ssh-") -> Iterator[str]:
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
        with suppress(OSError):
            file_size = os.path.getsize(tmp_path)
            with open(tmp_path, "r+b") as wipe_fh:
                wipe_fh.seek(0)
                wipe_fh.write(b"\x00" * file_size)
                wipe_fh.flush()
                os.fsync(wipe_fh.fileno())

        with suppress(OSError):
            os.unlink(tmp_path)
