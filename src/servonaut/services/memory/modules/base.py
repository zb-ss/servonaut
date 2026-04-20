"""Abstract base class for memory module probers.

All concrete probers inherit ``ModuleProber`` and implement ``_commands()`` plus
``_parse()``.  The base class handles:

- Per-command 5 s wall-clock timeout (``asyncio.wait_for``).
- Per-command 16 KB stdout cap with global ``truncated`` flag.
- Sudo failure detection with optional ``_fallback_commands()`` override.
- Always returns a ``ModuleResult`` — never raises.
- Belt-and-suspenders write-guard: raises ``ValueError`` at construction if any
  command contains write-implying tokens (``>``, ``>>``, ``tee``, ``install``,
  ``mv``, ``cp``).
"""

from __future__ import annotations

import asyncio
import logging
import re
import shlex
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Tuple

from servonaut.services.memory.interfaces import ModuleProberInterface, ModuleResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum wall-clock seconds for a single command execution.
_CMD_TIMEOUT_SECONDS: float = 5.0

# Maximum bytes captured from a single command's stdout.
_MAX_OUTPUT_BYTES: int = 16 * 1024  # 16 KB

# Write-blocking token sets.
# These exact command names are always blocked regardless of arguments.
_BLOCKED_COMMANDS: frozenset = frozenset({"tee", "install", "mv", "cp", "dd"})

# Tokens that indicate stderr redirection to /dev/null or to stdout — safe.
# Anything matching these exact strings is allowed even though they start with ">".
_STDERR_REDIRECT_ALLOWLIST: frozenset = frozenset({
    "2>/dev/null",
    "2>>/dev/null",
    "2>&1",
})

# Substrings in sudo stderr that indicate sudo is not available.
_SUDO_UNAVAILABLE_MARKERS: Tuple[str, ...] = (
    "sudo",
    "a terminal is required",
    "password",
    "not found",
    "no tty present",
)

# Async SSH runner type: (command: str) -> (stdout, stderr, returncode)
SshRunner = Callable[[str], Any]  # returns Awaitable[tuple[str, str, int]]


# ---------------------------------------------------------------------------
# Write-guard helper
# ---------------------------------------------------------------------------

_FD_REDIRECT_RE: re.Pattern = re.compile(r"^(\d+)>>?")
"""Matches numeric file-descriptor redirects like ``1>``, ``1>>``, ``3>``."""


def _token_is_forbidden_redirect(token: str) -> bool:
    """Return True if *token* represents a forbidden output redirect.

    Safe redirections that are explicitly allowed:
    - ``2>/dev/null``, ``2>>/dev/null`` — stderr to null
    - ``2>&1`` — stderr to stdout

    Forbidden redirections (any file descriptor except 2):
    - Bare ``>`` or ``>>``
    - ``1>`` / ``1>>`` / ``N>`` / ``N>>`` for any N ≠ 2
    - ``&>`` / ``&>>`` — combined stdout+stderr redirect (writes stdout)

    Args:
        token: A single shell token (already split by ``shlex.split``).

    Returns:
        ``True`` if the token is a forbidden redirect.
    """
    if token in _STDERR_REDIRECT_ALLOWLIST:
        return False

    # Bare output redirects.
    if token == ">" or token == ">>":
        return True

    # Combined stdout+stderr redirect (&> or &>>).
    if token.startswith("&>"):
        return True

    # FD-qualified redirects: N> or N>> where N is a digit sequence.
    m = _FD_REDIRECT_RE.match(token)
    if m:
        fd = int(m.group(1))
        # fd=2 redirects (stderr) are safe; everything else is a write.
        return fd != 2

    # Token starts with > (e.g. >/etc/bar) — bare redirect with no space.
    if token.startswith(">"):
        return True

    return False


def _token_is_sed_dash_i(tokens: List[str], idx: int) -> bool:
    """Return True if *tokens[idx]* is ``sed`` followed by a ``-i`` argument.

    ``sed -i`` modifies files in-place and is therefore forbidden.
    ``sed`` without ``-i`` (e.g. ``sed 's/x/y/'``) is safe.

    Args:
        tokens: Full token list for the command.
        idx: Index of the ``"sed"`` token.

    Returns:
        ``True`` if a ``-i`` flag appears anywhere in the remaining tokens.
    """
    for subsequent in tokens[idx + 1:]:
        if subsequent.startswith("-") and "i" in subsequent.lstrip("-"):
            return True
    return False


def _assert_no_writes(commands: List[str], context: str) -> None:
    """Raise ``ValueError`` if any command would write to the remote host.

    Uses ``shlex.split`` to tokenise each command, then inspects every token
    deterministically.  This avoids the false-negative class of regex-based
    guards (e.g. ``echo hi >>/tmp/evil`` with no space after ``>>``).

    Allowed:
    - ``2>/dev/null``, ``2>>/dev/null``, ``2>&1`` — stderr redirections
    - All read-only commands that do not match any forbidden token

    Forbidden:
    - Any token in ``_BLOCKED_COMMANDS`` (``tee``, ``install``, ``mv``,
      ``cp``, ``dd``)
    - Any output redirect token (``>``, ``>>``, ``1>``, ``&>``, etc.)
      except stderr-to-null / stderr-to-stdout variants
    - ``sed -i`` (in-place file modification)

    Args:
        commands: List of allowlisted command strings to check.
        context: Human-readable label used in the error message.

    Raises:
        ValueError: On the first forbidden token found.
    """
    for cmd in commands:
        try:
            tokens = shlex.split(cmd)
        except ValueError:
            # shlex couldn't parse (e.g. unmatched quotes) — conservatively reject.
            raise ValueError(
                f"[{context}] Command could not be parsed by shlex: {cmd!r}"
            )

        for idx, token in enumerate(tokens):
            # Blocked command names.
            if token in _BLOCKED_COMMANDS:
                raise ValueError(
                    f"[{context}] Command contains forbidden write token "
                    f"({token!r}): {cmd!r}"
                )

            # sed -i: in-place edit.
            if token == "sed" and _token_is_sed_dash_i(tokens, idx):
                raise ValueError(
                    f"[{context}] Command contains forbidden write token "
                    f"('sed -i' performs in-place file edit): {cmd!r}"
                )

            # Output redirect tokens.
            if _token_is_forbidden_redirect(token):
                raise ValueError(
                    f"[{context}] Command contains forbidden write token "
                    f"(output redirect {token!r}): {cmd!r}"
                )


# ---------------------------------------------------------------------------
# ModuleProber base class
# ---------------------------------------------------------------------------

class ModuleProber(ModuleProberInterface, ABC):
    """Concrete base for all memory module probers.

    Subclasses must implement:
    - ``name`` (class-level ``str`` attribute)
    - ``ttl_seconds`` (class-level ``int`` attribute)
    - ``_commands() -> List[str]``
    - ``_parse(raw_output: str) -> Dict[str, Any]``

    Optional override:
    - ``_fallback_commands() -> List[str]`` — run when sudo is unavailable.

    Args:
        requires_sudo: Whether the primary commands require sudo.
        sudo_optional: If True, proceed without sudo on sudo failure (with
            ``partial=True``).  If False, the entire module is marked partial.
    """

    # Subclasses MUST set these as class-level attributes or constructor args.
    name: str
    ttl_seconds: int

    def __init__(
        self,
        requires_sudo: bool = False,
        sudo_optional: bool = False,
    ) -> None:
        self.requires_sudo = requires_sudo
        self.sudo_optional = sudo_optional

        # Belt-and-suspenders: validate command lists at instantiation time.
        _assert_no_writes(self._commands(), f"{self.__class__.__name__}._commands")
        fallbacks = self._fallback_commands()
        if fallbacks:
            _assert_no_writes(
                fallbacks,
                f"{self.__class__.__name__}._fallback_commands",
            )

    # ------------------------------------------------------------------
    # Abstract interface for subclasses
    # ------------------------------------------------------------------

    @abstractmethod
    def _commands(self) -> List[str]:
        """Return the ordered list of allowlisted commands to run."""

    def _fallback_commands(self) -> List[str]:
        """Return fallback commands used when sudo is unavailable.

        Override this in subclasses that have a meaningful degraded path.
        The default implementation returns an empty list (no fallback).
        """
        return []

    @abstractmethod
    def _parse(self, raw_output: str) -> Dict[str, Any]:
        """Parse aggregated raw_output into a structured ``observed`` dict.

        Args:
            raw_output: Concatenated stdout from all executed commands,
                formatted as ``"<cmd> →\\n<stdout>\\n\\n"``.

        Returns:
            Dict of key → observed value.  Missing / unavailable items
            should be ``None`` rather than omitted.
        """

    # ------------------------------------------------------------------
    # probe() — the main entry point called by MemoryService
    # ------------------------------------------------------------------

    async def probe(self, ssh_runner: SshRunner) -> ModuleResult:
        """Run the allowlisted command set and return a ``ModuleResult``.

        This implementation is the single-source-of-truth for the probe
        lifecycle.  It must not raise; all exceptions are captured and
        reflected in ``partial=True`` + a descriptive ``raw_output``.

        Args:
            ssh_runner: Async callable ``(command: str) -> (stdout, stderr, returncode)``.

        Returns:
            A fully populated ``ModuleResult``.
        """
        truncated = False
        partial = False
        sudo_used = False
        raw_parts: List[str] = []

        try:
            commands = self._commands()
            sudo_failed = False

            for cmd in commands:
                stdout, did_truncate, cmd_sudo_failed = await self._run_command(
                    ssh_runner, cmd
                )
                if did_truncate:
                    truncated = True
                if cmd_sudo_failed:
                    sudo_failed = True
                raw_parts.append(f"{cmd} →\n{stdout}\n")

            # If sudo failed and we have a fallback, use it.
            if sudo_failed and self._fallback_commands():
                partial = True
                raw_parts.append("[sudo unavailable — running fallback commands]\n")
                for cmd in self._fallback_commands():
                    stdout, did_truncate, _ = await self._run_command(ssh_runner, cmd)
                    if did_truncate:
                        truncated = True
                    raw_parts.append(f"{cmd} →\n{stdout}\n")
            elif sudo_failed:
                partial = True
                raw_parts.append("[sudo unavailable — no fallback; module is partial]\n")

            raw_output = "\n".join(raw_parts)
            observed = self._parse(raw_output)

        except Exception as exc:  # noqa: BLE001 — never propagate
            logger.error(
                "Prober %s raised an unexpected exception: %s",
                self.name,
                exc,
                exc_info=True,
            )
            raw_output = f"[ERROR] {type(exc).__name__}: {exc}"
            observed = {}
            partial = True

        return ModuleResult(
            module=self.name,
            instance_id="",  # MemoryService stamps this before persisting.
            observed=observed,
            sudo_used=sudo_used,
            truncated=truncated,
            partial=partial,
            probed_at=datetime.now(tz=timezone.utc).isoformat(),
            ttl_seconds=self.ttl_seconds,
            raw_output=raw_output,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run_command(
        self,
        ssh_runner: SshRunner,
        cmd: str,
    ) -> Tuple[str, bool, bool]:
        """Execute *cmd* via *ssh_runner* with timeout and size caps.

        Args:
            ssh_runner: Async callable that executes the command.
            cmd: Shell command string to execute.

        Returns:
            A 3-tuple of (stdout_str, did_truncate, sudo_failed).
        """
        did_truncate = False
        sudo_failed = False

        try:
            stdout_str, stderr_str, _returncode = await asyncio.wait_for(
                ssh_runner(cmd),
                timeout=_CMD_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            logger.warning("Command timed out after %ss: %s", _CMD_TIMEOUT_SECONDS, cmd)
            return "<timeout>", False, False
        except Exception as exc:  # noqa: BLE001
            logger.error("ssh_runner raised for command %r: %s", cmd, exc)
            return f"<error: {exc}>", False, False

        # Truncate if oversized.
        encoded = stdout_str.encode("utf-8", errors="replace")
        if len(encoded) > _MAX_OUTPUT_BYTES:
            stdout_str = encoded[:_MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
            did_truncate = True

        # Detect sudo failure from stderr.
        stderr_lower = stderr_str.lower() if isinstance(stderr_str, str) else ""
        if any(marker in stderr_lower for marker in _SUDO_UNAVAILABLE_MARKERS):
            # Only treat as sudo failure if the command actually tried sudo.
            if "sudo" in cmd.lower():
                sudo_failed = True

        return stdout_str, did_truncate, sudo_failed
