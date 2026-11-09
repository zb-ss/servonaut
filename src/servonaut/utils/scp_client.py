"""What the local ``scp`` client does with a remote path, and how to name one safely.

An ``scp`` before OpenSSH 9.0 asks the remote shell to read the remote path
(the legacy protocol), so a file name such as ``x;cmd;.log`` runs ``cmd`` there.
From 8.7 the client has ``-s``, which makes it use the SFTP protocol: the path
is sent as data and no shell reads it. Quoting the path cannot fix the legacy
mode (the client rejects the quoted name) and breaks SFTP mode (the quotes
become part of the name), so the app instead:

* passes ``-s`` and the raw path when the client has it, or
* backslash-escapes every character outside ``[A-Za-z0-9_./-]`` when it does
  not, which both the remote shell and the client's own filename check accept.

The client is asked once (``scp`` with no arguments prints its usage line) and
the answer is kept. ``warm_up`` starts that in the background at start-up so
building a command never waits for it on the UI thread.
"""
from __future__ import annotations

import logging
import re
import subprocess
import threading
from typing import Dict

from servonaut.utils.ssh_utils import background_process_kwargs

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT_SECONDS = 5.0
# The usage line is "usage: scp [-346ABCOpqRrsTv] [-c cipher] ..."; the first
# bracket lists the single-letter flags.
_FLAGS_RE = re.compile(r"usage:\s*scp\s*\[-([0-9A-Za-z]+)\]")
_SAFE_CHARS = re.compile(r"[A-Za-z0-9_./-]")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

_lock = threading.Lock()
_answers: Dict[str, bool] = {}
_probes: Dict[str, threading.Thread] = {}


def parse_sftp_flag(usage: str) -> bool:
    """Whether the usage text of an ``scp`` lists the ``-s`` flag."""
    match = _FLAGS_RE.search(usage)
    return match is not None and "s" in match.group(1)


def _probe(executable: str) -> bool:
    try:
        done = subprocess.run(
            [executable], capture_output=True, text=True, timeout=_PROBE_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL, check=False,
            # No console window flashes on Windows when the app has none.
            **background_process_kwargs(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("Could not ask %s for its options: %s", executable, exc)
        return False
    return parse_sftp_flag(done.stderr or done.stdout or "")


def _run_probe(executable: str) -> None:
    answer = _probe(executable)
    with _lock:
        _answers[executable] = answer


def warm_up(executable: str = "scp") -> None:
    """Ask *executable* about ``-s`` in the background (once)."""
    with _lock:
        if executable in _answers or executable in _probes:
            return
        thread = threading.Thread(target=_run_probe, args=(executable,), name="scp-probe", daemon=True)
        _probes[executable] = thread
    thread.start()


def supports_sftp_flag(executable: str = "scp") -> bool:
    """Whether *executable* accepts ``-s``. Asked once; later calls use the answer."""
    with _lock:
        if executable in _answers:
            return _answers[executable]
    warm_up(executable)
    with _lock:
        thread = _probes.get(executable)
    if thread is not None:
        thread.join(_PROBE_TIMEOUT_SECONDS + 1)
    with _lock:
        return _answers.get(executable, False)


def forget_answers() -> None:
    """Drop what was learned (for tests)."""
    with _lock:
        _answers.clear()
        _probes.clear()


def sftp_source_pattern(path: str) -> str:
    """*path* as a download source that matches only that file over SFTP.

    scp reads a source as a pattern: ``*``, ``?``, ``[`` and the backslash
    that escapes them are special. Braces are literal over SFTP.
    """
    return re.sub(r"([\\*?\[])", r"\\\1", path)


def legacy_remote_path(path: str) -> str:
    """*path* escaped for a remote shell that reads it (the legacy protocol).

    Every character outside ``[A-Za-z0-9_./-]`` gets a backslash; a leading
    ``~/`` stays so the remote home still expands.

    Raises:
        ValueError: *path* holds a control character or newline, which a
            backslash cannot carry through this protocol.
    """
    if _CONTROL_RE.search(path):
        raise ValueError(
            "This remote path contains a control character or a line break, which this "
            "scp client cannot transfer safely. Rename the file or upgrade OpenSSH to 8.7 or later."
        )
    prefix = ""
    if path.startswith("~/"):
        prefix, path = "~/", path[2:]
    return prefix + "".join(c if _SAFE_CHARS.match(c) else "\\" + c for c in path)
