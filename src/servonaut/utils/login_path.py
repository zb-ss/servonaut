"""Repair PATH for macOS GUI launches and share the well-known bin dirs.

A macOS app started from the Dock or by a GUI client inherits launchd's
minimal PATH (/usr/bin:/bin:/usr/sbin:/sbin), so Homebrew-installed CLIs
(bw, bws, brew, ...) are invisible to ``shutil.which``. ``merge_login_path``
asks the user's login shell for its PATH and merges it in, falling back to
the well-known directories when the shell cannot answer in time.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import secrets
import signal
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping, MutableMapping
from pathlib import Path
from typing import Final

logger = logging.getLogger(__name__)

# A startup bound; SERVONAUT_LOGIN_PATH_TIMEOUT_SECONDS overrides it.
_DEFAULT_PROBE_TIMEOUT_SECONDS: Final = 3.0
_TIMEOUT_ENV_VAR: Final = "SERVONAUT_LOGIN_PATH_TIMEOUT_SECONDS"

ProbeFunc = Callable[[str, float, Mapping[str, str]], "str | None"]


def well_known_bin_dirs(home: Path | None = None) -> tuple[Path, ...]:
    """Return the platform-invariant directories CLIs are commonly installed in.

    This is the single source for these locations; other modules (for example
    updates/profile.py) derive their candidates from it.
    """
    base = home if home is not None else Path.home()
    return (
        Path("/opt/homebrew/bin"),
        Path("/opt/homebrew/sbin"),
        Path("/usr/local/bin"),
        base / ".local" / "bin",
    )


def probe_login_shell_path(
    shell: str, timeout: float, environ: Mapping[str, str]
) -> str | None:
    """Ask a login interactive shell for its PATH; None when it cannot answer.

    The PATH is read only from between two random markers so rc-file output
    cannot corrupt it. The shell runs in its own session so a timeout kills
    the whole process group.
    """
    marker = f"__SERVONAUT_PATH_{secrets.token_hex(8)}__"
    script = (
        f"printf '%s' '{marker}'; /usr/bin/printenv PATH; printf '%s' '{marker}'"
    )
    try:
        proc = subprocess.Popen(
            [shell, "-ilc", script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(environ),
            start_new_session=True,
        )
    except (OSError, ValueError):
        return None

    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        # A shell that printed the PATH but then hung (an rc file waiting on
        # something) still answered: keep what it wrote before the kill.
        out = exc.output
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired):
            out, _ = proc.communicate(timeout=1)
        return _path_between_markers(out, marker)
    except (OSError, ValueError):
        return None

    return _path_between_markers(out, marker)


def _path_between_markers(out: bytes | None, marker: str) -> str | None:
    """The PATH the probe printed between its two markers, or None."""
    text = (out or b"").decode("utf-8", errors="replace")
    match = re.search(re.escape(marker) + r"(.*?)" + re.escape(marker), text, re.S)
    if match is None:
        return None
    value = match.group(1).strip()
    return value or None


def merged_path(
    current: str,
    login: str | None,
    extra_dirs: Iterable[Path],
    *,
    prefer_current: bool = False,
) -> str:
    """Merge PATH sources, then append the existing extras.

    Login entries come first, then current; with *prefer_current* the
    current entries come first (a launcher's PATH, for example an MCP
    client's, keeps precedence and only gains what it lacks).
    """
    login_parts = login.split(os.pathsep) if login else []
    current_parts = current.split(os.pathsep)
    candidates = (
        current_parts + login_parts if prefer_current else login_parts + current_parts
    )
    candidates.extend(str(d) for d in extra_dirs if d.is_dir())
    kept = [c for c in candidates if c and os.path.isabs(c)]
    return os.pathsep.join(dict.fromkeys(kept))


def _resolve_shell(environ: Mapping[str, str]) -> str | None:
    shell = environ.get("SHELL")
    if not shell:
        try:
            import pwd

            shell = pwd.getpwuid(os.getuid()).pw_shell
        except (ImportError, KeyError, OSError):
            return None
    if shell and os.path.isabs(shell) and os.access(shell, os.X_OK):
        return shell
    return None


def _probe_timeout(environ: Mapping[str, str]) -> float:
    raw = environ.get(_TIMEOUT_ENV_VAR)
    if raw is None:
        return _DEFAULT_PROBE_TIMEOUT_SECONDS
    try:
        return float(raw)
    except ValueError:
        return _DEFAULT_PROBE_TIMEOUT_SECONDS


def merge_login_path(
    *,
    environ: MutableMapping[str, str] | None = None,
    platform: str | None = None,
    probe: ProbeFunc | None = None,
    prefer_current: bool = False,
) -> bool:
    """Merge the login shell's PATH into ``environ`` on macOS; never raises.

    Login entries go first (a Dock launch's PATH is launchd's minimal one);
    with *prefer_current* the inherited entries stay first and the login and
    well-known entries are appended (a process started by another program,
    such as an MCP client, keeps the PATH it was given). Returns True when
    PATH changed. A no-op on other platforms.
    """
    try:
        env = os.environ if environ is None else environ
        if (sys.platform if platform is None else platform) != "darwin":
            return False
        run_probe = probe if probe is not None else probe_login_shell_path

        login: str | None = None
        shell = _resolve_shell(env)
        timeout = _probe_timeout(env)
        if shell is not None and timeout > 0:
            try:
                login = run_probe(shell, timeout, env)
            except Exception:  # noqa: BLE001 - PATH repair must never stop startup
                login = None

        current = env.get("PATH", "")
        new_path = merged_path(
            current, login, well_known_bin_dirs(), prefer_current=prefer_current
        )
        added = len(new_path.split(os.pathsep)) - len(current.split(os.pathsep))
        logger.info(
            "Login PATH merge: probe answered=%s, entries added=%d",
            login is not None,
            added,
        )
        if new_path != current:
            env["PATH"] = new_path
            return True
        return False
    except Exception:  # noqa: BLE001 - PATH repair must never stop startup
        logger.warning("Login PATH merge failed")
        return False
