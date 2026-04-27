"""Git module prober — discovers tracked git working trees on common app dirs.

The prober runs a bounded ``find`` for ``.git`` directories under typical
server deployment locations (``/opt``, ``/var/www``, ``/home``, ``/srv``),
then for each discovered checkout records its current branch and origin
remote URL.

Allowlisted commands:
  - find /opt /var/www /home /srv -maxdepth 4 -name .git -prune 2>/dev/null
  - git -C <path> rev-parse --abbrev-ref HEAD 2>/dev/null
  - git -C <path> remote get-url origin 2>/dev/null

To keep probe time bounded the discovery result is capped at
``_MAX_CHECKOUTS`` (20) before any ``git -C`` calls happen.  The base
class enforces the global 5s-per-command timeout; this module packs all
per-checkout ``git -C`` calls into a single compound shell command using
``&& echo; git ...`` separators so one subprocess covers them all.

TTL: 1 day — git branches change often enough to make multi-day caches
stale, but frequently enough to justify the TTL.
"""

from __future__ import annotations

import re
import shlex
from typing import Any, Dict, List, Optional

from .base import ModuleProber

# ---------------------------------------------------------------------------
# Module configuration
# ---------------------------------------------------------------------------

_TTL_1_DAY = 86400

_MAX_CHECKOUTS = 20

# Scan roots — kept small and well-known so probes finish in seconds even
# on dense servers.
_SCAN_ROOTS = ("/opt", "/var/www", "/home", "/srv")

_FIND_CMD = (
    f"find {' '.join(_SCAN_ROOTS)} -maxdepth 4 -name .git -prune 2>/dev/null"
)

# Regex: we allow letters, digits, ``/``, ``_``, ``-``, and ``.`` in paths.
# Anything outside that charset is a strong signal of probe-output corruption
# or a shell-metacharacter smuggling attempt, so we skip the checkout rather
# than feed it to ``git -C``.
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_\-./]+$")


class GitProber(ModuleProber):
    """Discover git checkouts on common server deployment paths."""

    name = "git"
    ttl_seconds = _TTL_1_DAY

    def __init__(self) -> None:
        super().__init__(requires_sudo=False, sudo_optional=False)
        # Discovered checkout paths populated lazily in ``probe`` / ``_commands``.
        self._checkouts: List[str] = []
        self._initialised = False

    def _commands(self) -> List[str]:
        """Return the initial discovery command only.

        The per-checkout ``git -C`` commands are issued during ``probe``
        after parsing the discovery output.  To do this we override ``probe``
        below rather than relying on the base-class command loop.

        The returned list is used by the base class for the write-guard at
        construction time — only the discovery find is checked here.
        """
        return [_FIND_CMD]

    def _parse(self, raw_output: str) -> Dict[str, Any]:
        """Parse the aggregated output into the final observed dict.

        The output is the base-class standard format: each command's stdout
        appears after its ``<cmd> →`` header, in order.  We walk the sections
        and assemble the ``checkouts`` list.
        """
        find_section = _extract_section(raw_output, _FIND_CMD)
        discovered = _parse_find_output(find_section)

        checkouts: List[Dict[str, Any]] = []
        for path in discovered[:_MAX_CHECKOUTS]:
            repo_root = path[:-5] if path.endswith("/.git") else path
            branch_cmd = _branch_cmd_for(repo_root)
            remote_cmd = _remote_cmd_for(repo_root)
            branch_section = _extract_section(raw_output, branch_cmd)
            remote_section = _extract_section(raw_output, remote_cmd)
            branch = _first_stripped_line(branch_section)
            remote_url = _first_stripped_line(remote_section)
            checkouts.append({
                "path": repo_root,
                "branch": branch,
                "remote_url": remote_url,
            })

        return {"checkouts": checkouts}

    async def probe(self, ssh_runner: Any) -> Any:
        """Two-phase probe: run ``find``, then the bounded per-checkout ``git`` calls.

        We override ``probe`` (rather than adding to ``_commands``) because the
        checkout list is only known after the ``find`` returns.  The output of
        every command is concatenated in the standard ``<cmd> →\\n<stdout>``
        format so ``_parse`` sees the same shape it would from the base class.
        """
        from .base import (
            _CMD_TIMEOUT_SECONDS,
            _MAX_OUTPUT_BYTES,
            _SUDO_UNAVAILABLE_MARKERS,  # noqa: F401 — unused here but imported for consistency
        )
        from servonaut.services.memory.interfaces import ModuleResult
        from datetime import datetime, timezone
        import asyncio
        import logging

        logger = logging.getLogger(__name__)

        truncated = False
        partial = False
        raw_parts: List[str] = []

        try:
            # Phase 1: discovery.
            stdout, did_truncate = await _run_once(
                ssh_runner, _FIND_CMD, _CMD_TIMEOUT_SECONDS, _MAX_OUTPUT_BYTES
            )
            if did_truncate:
                truncated = True
            # Runner-level errors are captured by _run_once and inlined as
            # ``<error: ...>`` or ``<timeout>``; treat either as a partial probe.
            if _is_error_marker(stdout):
                partial = True
            raw_parts.append(f"{_FIND_CMD} →\n{stdout}\n")

            discovered = _parse_find_output(stdout)

            # Phase 2: per-checkout git queries — bounded list, one SSH call
            # per command so the timeout/truncation semantics match the base
            # class exactly and sanitisation is trivial.
            for path in discovered[:_MAX_CHECKOUTS]:
                repo_root = path[:-5] if path.endswith("/.git") else path
                if not _SAFE_PATH_RE.fullmatch(repo_root):
                    # Skip paths that contain characters outside the safe set;
                    # these are extremely unusual on real servers and would be
                    # a signal of corrupted probe output.
                    partial = True
                    raw_parts.append(
                        f"[skipped unsafe checkout path: {repo_root!r}]\n"
                    )
                    continue

                for cmd in (_branch_cmd_for(repo_root), _remote_cmd_for(repo_root)):
                    stdout, did_truncate = await _run_once(
                        ssh_runner, cmd, _CMD_TIMEOUT_SECONDS, _MAX_OUTPUT_BYTES
                    )
                    if did_truncate:
                        truncated = True
                    raw_parts.append(f"{cmd} →\n{stdout}\n")

            raw_output = "\n".join(raw_parts)
            observed = self._parse(raw_output)
        except Exception as exc:  # noqa: BLE001 — never propagate
            logger.error(
                "GitProber raised: %s", exc, exc_info=True
            )
            raw_output = f"[ERROR] {type(exc).__name__}: {exc}"
            observed = {"checkouts": []}
            partial = True

        return ModuleResult(
            module=self.name,
            instance_id="",
            observed=observed,
            sudo_used=False,
            truncated=truncated,
            partial=partial,
            probed_at=datetime.now(tz=timezone.utc).isoformat(),
            ttl_seconds=self.ttl_seconds,
            raw_output=raw_output,
        )


# ---------------------------------------------------------------------------
# Helpers — kept module-private and pure so they're easy to unit-test.
# ---------------------------------------------------------------------------

def _parse_find_output(find_output: str) -> List[str]:
    """Return the list of ``.git`` directories printed by ``find``.

    Lines that don't start with one of our scan roots are discarded.
    Results are deduplicated while preserving discovery order.
    """
    seen: set = set()
    out: List[str] = []
    for raw_line in find_output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("<"):
            continue
        if not any(line.startswith(root + "/") or line == root for root in _SCAN_ROOTS):
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def _branch_cmd_for(repo_root: str) -> str:
    """Return the exact ``git -C`` branch-lookup command for *repo_root*."""
    return f"git -C {shlex.quote(repo_root)} rev-parse --abbrev-ref HEAD 2>/dev/null"


def _remote_cmd_for(repo_root: str) -> str:
    """Return the exact ``git -C`` origin-URL command for *repo_root*."""
    return f"git -C {shlex.quote(repo_root)} remote get-url origin 2>/dev/null"


def _is_error_marker(text: str) -> bool:
    """Return True if *text* is one of the base-class error sentinels.

    The base ``_run_command`` helper substitutes ``<timeout>`` or
    ``<error: ...>`` for failed commands.  The git prober uses this helper
    to detect when the ``find`` phase couldn't run at all so it can mark the
    overall probe as ``partial``.
    """
    if not text:
        return False
    stripped = text.lstrip()
    return stripped.startswith("<timeout>") or stripped.startswith("<error:")


def _first_stripped_line(section: str) -> Optional[str]:
    """Return the first non-empty, non-error line of *section* or ``None``."""
    if not section:
        return None
    for raw_line in section.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("<") or line.startswith("["):
            continue
        return line
    return None


def _extract_section(raw_output: str, cmd_prefix: str) -> str:
    """Extract the stdout block for *cmd_prefix* from *raw_output*."""
    marker = f"{cmd_prefix} →"
    start = raw_output.find(marker)
    if start == -1:
        return ""
    content_start = raw_output.find("\n", start)
    if content_start == -1:
        return ""
    content_start += 1

    next_marker = raw_output.find(" →\n", content_start)
    if next_marker == -1:
        return raw_output[content_start:]

    line_start = raw_output.rfind("\n", content_start, next_marker)
    if line_start == -1:
        return raw_output[content_start:next_marker]
    return raw_output[content_start:line_start]


async def _run_once(
    ssh_runner: Any,
    cmd: str,
    timeout_seconds: float,
    max_output_bytes: int,
) -> tuple[str, bool]:
    """Run *cmd* via *ssh_runner* with timeout and size caps.

    Returns (stdout_str, did_truncate).  Never raises: timeouts and runner
    errors are reflected in the returned string.
    """
    import asyncio
    import logging

    logger = logging.getLogger(__name__)
    did_truncate = False
    try:
        stdout_str, stderr_str, _rc = await asyncio.wait_for(
            ssh_runner(cmd), timeout=timeout_seconds
        )
    except asyncio.TimeoutError:
        logger.warning("Git prober command timed out: %s", cmd)
        return "<timeout>", False
    except Exception as exc:  # noqa: BLE001
        logger.error("Git prober ssh_runner raised for %r: %s", cmd, exc)
        return f"<error: {exc}>", False

    encoded = stdout_str.encode("utf-8", errors="replace")
    if len(encoded) > max_output_bytes:
        stdout_str = encoded[:max_output_bytes].decode("utf-8", errors="replace")
        did_truncate = True
    return stdout_str, did_truncate
