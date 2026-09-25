"""SSH utility functions for path handling and validation."""

from __future__ import annotations
import asyncio
import atexit
import logging
import os
import signal
import subprocess
import tempfile
import threading
import weakref
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)


def expand_key_path(key_path: str) -> str:
    """Expand ~ and environment variables in key path.

    Args:
        key_path: Path to SSH key file (may contain ~ or env vars).

    Returns:
        Fully expanded absolute path.

    Examples:
        >>> expand_key_path('~/my-key.pem')
        '/home/user/my-key.pem'
    """
    return os.path.expanduser(os.path.expandvars(key_path))


def validate_key_path(key_path: str) -> bool:
    """Check if key file exists and is a regular file.

    Args:
        key_path: Path to SSH key file.

    Returns:
        True if key file exists and is a regular file.

    Examples:
        >>> validate_key_path('/path/to/nonexistent.pem')
        False
    """
    expanded = expand_key_path(key_path)
    return os.path.isfile(expanded)


def get_key_permissions(key_path: str) -> str:
    """Get key file permissions as octal string (e.g., '600').

    Args:
        key_path: Path to SSH key file.

    Returns:
        Three-digit octal permission string.

    Examples:
        >>> get_key_permissions('/path/to/key.pem')  # doctest: +SKIP
        '600'
    """
    expanded = expand_key_path(key_path)
    return oct(os.stat(expanded).st_mode)[-3:]


def parse_ssh_output(output: str) -> List[str]:
    """Split SSH command output into lines, stripping whitespace.

    Args:
        output: Raw output from SSH command.

    Returns:
        List of non-empty trimmed lines.

    Examples:
        >>> parse_ssh_output('line1\\n  line2  \\n\\nline3\\n')
        ['line1', 'line2', 'line3']
    """
    return [line.strip() for line in output.splitlines() if line.strip()]


# Names the per-run diagnostics file (see SshLog) in the environment of an
# unattended ssh, so a bastion hop built by ConnectionService writes its own
# messages there too (``ssh -E "$SERVONAUT_SSH_LOG"``).
SSH_LOG_ENV = "SERVONAUT_SSH_LOG"
_SSH_PROGRAM_NAMES = frozenset({"ssh", "ssh.exe"})
# subprocess.CREATE_NO_WINDOW, which only exists on Windows builds.
_CREATE_NO_WINDOW = 0x08000000


def background_process_kwargs() -> Dict[str, Any]:
    """Process options that keep an unattended ssh away from the user's terminal.

    POSIX gets a new session, so ssh has no controlling terminal to prompt
    on (for a password, a passphrase or an unknown bastion); Windows gets no
    console window. Processes that outlive a call should also be passed to
    ``track_background_process`` so they are stopped when Servonaut exits.
    """
    if os.name == "nt":
        return {"creationflags": _CREATE_NO_WINDOW}
    return {"start_new_session": True}


class SshLog:
    """A private file for OpenSSH's own messages (``ssh -E``).

    ssh prints its diagnostics to the same stderr as the remote command, so
    text found there proves nothing about ssh: a remote command can print
    anything. With ``-E`` ssh writes its messages to this file instead, and
    a bastion hop built by Servonaut does the same through ``SSH_LOG_ENV``.
    Only this machine's ssh processes write here.
    """

    def __init__(self) -> None:
        # mkstemp creates the file 0600 with a name nobody can predict.
        descriptor, self.path = tempfile.mkstemp(prefix="servonaut-ssh-", suffix=".log")
        os.close(descriptor)

    def command(self, argv: Sequence[Union[str, os.PathLike]]) -> List[str]:
        """*argv* with ``-E`` added when it runs ssh itself (scp has no ``-E``)."""
        args = [str(arg) for arg in argv]
        if args and os.path.basename(args[0]).lower() in _SSH_PROGRAM_NAMES:
            return [args[0], "-E", self.path, *args[1:]]
        return args

    def environment(self) -> Dict[str, str]:
        """The environment for the process, naming this file for a bastion hop."""
        return {**os.environ, SSH_LOG_ENV: self.path}

    def read(self) -> str:
        """Everything ssh wrote so far."""
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read()
        except OSError:
            return ""

    def close(self) -> None:
        """Remove the file."""
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.debug("Could not remove ssh log %s: %s", self.path, exc)

    def __enter__(self) -> "SshLog":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()


def with_diagnostics(diagnostics: str, stderr: Any) -> Any:
    """*stderr* preceded by ssh's own messages, in the same type (bytes or str).

    ssh's messages no longer arrive on stderr (see SshLog); callers that show
    or classify stderr still see them this way.
    """
    if not diagnostics:
        return stderr
    if isinstance(stderr, bytes):
        return diagnostics.encode("utf-8", errors="replace") + stderr
    if stderr is None or isinstance(stderr, str):
        return diagnostics + (stderr or "")
    return stderr


_BACKGROUND_PROCESSES: "weakref.WeakSet[Any]" = weakref.WeakSet()
_BACKGROUND_LOCK = threading.Lock()


def track_background_process(process: Any) -> None:
    """Stop *process* when Servonaut exits, even though it has its own session.

    A child in its own session no longer receives the terminal's hangup, so
    Servonaut ends it itself: at exit, and on hangup once
    ``install_hangup_cleanup`` has run.
    """
    with _BACKGROUND_LOCK:
        _BACKGROUND_PROCESSES.add(process)


def terminate_background_processes() -> None:
    """Terminate every tracked process that is still running."""
    with _BACKGROUND_LOCK:
        processes = list(_BACKGROUND_PROCESSES)
    for process in processes:
        try:
            if getattr(process, "returncode", 0) is None:
                process.terminate()
        except Exception:  # noqa: BLE001 — already gone, or its loop is closed
            pass


atexit.register(terminate_background_processes)
_HANGUP_CLEANUP_INSTALLED = False


def install_hangup_cleanup() -> None:
    """On hangup (the terminal closed), end tracked processes, then hang up as before.

    Call from the main thread. Nothing changes when hangup is ignored (for
    example under ``nohup``) or on platforms without SIGHUP.
    """
    global _HANGUP_CLEANUP_INSTALLED
    hangup = getattr(signal, "SIGHUP", None)
    if hangup is None or _HANGUP_CLEANUP_INSTALLED:
        return
    previous = signal.getsignal(hangup)
    if previous == signal.SIG_IGN:
        return

    def _on_hangup(signum: int, frame: Any) -> None:
        terminate_background_processes()
        if callable(previous):
            previous(signum, frame)
            return
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    signal.signal(hangup, _on_hangup)
    _HANGUP_CLEANUP_INSTALLED = True


class SSHOutput(tuple):
    """``(stdout, stderr)`` of a finished ssh run, with its exit status and log.

    Unpacks like the plain pair callers have always received. ``stderr``
    starts with ssh's own messages; ``diagnostics`` holds those alone (from
    the private SshLog), which is what host-key detection trusts, and
    ``returncode`` tells ssh's own failures (255) apart from the remote
    command's.
    """

    returncode: Optional[int]
    diagnostics: str

    def __new__(
        cls,
        stdout: bytes,
        stderr: bytes,
        returncode: Optional[int],
        diagnostics: str = "",
    ) -> "SSHOutput":
        output = super().__new__(cls, (stdout, stderr))
        output.returncode = returncode
        output.diagnostics = diagnostics
        return output

    def __getnewargs__(self) -> Tuple[Any, ...]:
        """Let copy, deepcopy and pickle rebuild the extra fields."""
        return (self[0], self[1], self.returncode, self.diagnostics)


class SSHCalledProcessError(subprocess.CalledProcessError):
    """``CalledProcessError`` for an ssh run, carrying ssh's own messages."""

    def __init__(self, returncode: int, cmd: Any, output: Any = None,
                 stderr: Any = None, diagnostics: str = "") -> None:
        super().__init__(returncode, cmd, output=output, stderr=stderr)
        self.diagnostics = diagnostics


def ssh_returncode(output: Sequence[bytes]) -> Optional[int]:
    """The exit status of a ``run_ssh_subprocess`` result (None if unknown)."""
    return getattr(output, "returncode", None)


def ssh_diagnostics(output: Any) -> str:
    """ssh's own messages for a ``run_ssh_subprocess`` result ('' if unknown)."""
    return getattr(output, "diagnostics", None) or ""


def run_ssh(argv: Sequence[Union[str, os.PathLike]], **kwargs: Any) -> subprocess.CompletedProcess:
    """``subprocess.run`` for an unattended ssh or scp.

    ssh writes its own messages to a private SshLog; the result's
    ``diagnostics`` holds them and ``stderr`` starts with them. The process
    has no terminal to prompt on (see ``background_process_kwargs``).
    """
    with SshLog() as log:
        result = subprocess.run(
            log.command(argv), env=log.environment(),
            **background_process_kwargs(), **kwargs,
        )
        diagnostics = log.read()
    result.diagnostics = diagnostics
    result.stderr = with_diagnostics(diagnostics, result.stderr)
    return result


async def run_ssh_subprocess(
    ssh_cmd: Sequence[Union[str, os.PathLike]],
    timeout: float = 30,
    *,
    check: bool = False,
) -> SSHOutput:
    """Run an SSH command as a subprocess, returning (stdout, stderr).

    The result also carries ``returncode`` and ``diagnostics`` (see
    SSHOutput). The process has no terminal to prompt on (see
    ``background_process_kwargs``).

    With ``check=True``, raise ``SSHCalledProcessError`` with captured output
    on a nonzero exit status. Properly closes the transport to prevent
    'Event loop is closed' errors on application shutdown.
    """
    log = SshLog()
    try:
        proc = await asyncio.create_subprocess_exec(
            *log.command(ssh_cmd),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=log.environment(),
            **background_process_kwargs(),
        )
        track_background_process(proc)
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            diagnostics = log.read()
            stderr = with_diagnostics(diagnostics, stderr)
            if check and proc.returncode:
                raise SSHCalledProcessError(
                    proc.returncode, ssh_cmd, output=stdout, stderr=stderr,
                    diagnostics=diagnostics,
                )
            return SSHOutput(stdout, stderr, proc.returncode, diagnostics)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            # Kill the subprocess on both internal timeout and external cancellation
            # so that no zombie SSH processes linger past the caller's deadline.
            try:
                proc.kill()
            except ProcessLookupError:
                pass  # The process can exit between cancellation and kill.
            await proc.wait()
            raise
        finally:
            # Explicitly close transport to avoid __del__ errors after event loop closes
            transport = getattr(proc, '_transport', None)
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass
    finally:
        log.close()
