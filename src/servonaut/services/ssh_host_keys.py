"""Host-key verification for every ssh/scp command Servonaut builds.

Servonaut drives the system OpenSSH client, so host-key verification is a
matter of the options it passes. This module is the single place those
options come from:

* ``StrictHostKeyChecking`` follows ``ssh.host_key_checking``
  (``accept-new`` by default, ``yes`` or ``off``).
* ``UserKnownHostsFile`` lists Servonaut's own file under the data root
  first, so newly accepted keys are recorded there, followed by the user's
  ``~/.ssh/known_hosts``, so hosts they already trust keep working.

It also recognises OpenSSH's refusal output, so a changed key is reported
as a changed key, with the command that removes the stale entry, instead of
as a generic connection failure.

Every path handed to ssh is absolute. OpenSSH expands ``~`` from the
password database rather than ``$HOME``, so a literal ``~`` would escape a
sandboxed home.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional

from servonaut.config.schema import (
    DEFAULT_HOST_KEY_CHECKING,
    normalize_host_key_checking,
)
from servonaut.runtime import data_root_for_home

logger = logging.getLogger(__name__)

HOST_KEY_CHECKING_OFF = "off"
KNOWN_HOSTS_FILENAME = "known_hosts"

HOST_KEY_CHANGED = "changed"
HOST_KEY_UNKNOWN = "unknown"
HOST_KEY_UNVERIFIED = "unverified"

# Printed by OpenSSH only when it refused the connection. The large
# "REMOTE HOST IDENTIFICATION HAS CHANGED" banner alone is not enough: with
# verification off, ssh prints it and connects anyway.
_REFUSAL_MARKERS = (
    "host key verification failed",
    "you have requested strict checking",
)
_CHANGED_RE = re.compile(
    r"host key for (\S+) has changed and you have requested strict checking",
    re.IGNORECASE,
)
_UNKNOWN_RE = re.compile(
    r"no (?:\S+ )?host key is known for (\S+) and you have requested strict checking",
    re.IGNORECASE,
)
_OFFENDING_RE = re.compile(r"Offending \S+ key in (.+):\d+\s*$", re.MULTILINE)
_REMOVE_WITH_RE = re.compile(
    r"ssh-keygen -f (['\"])(.+?)\1 -R (['\"])(.+?)\3",
)


def servonaut_known_hosts_path() -> Path:
    """Return Servonaut's own known_hosts file, under the data root."""
    return data_root_for_home(Path.home()) / KNOWN_HOSTS_FILENAME


def user_known_hosts_path() -> Path:
    """Return the user's OpenSSH known_hosts file as an absolute path."""
    return Path.home() / ".ssh" / KNOWN_HOSTS_FILENAME


def ensure_known_hosts_file(path: Path) -> None:
    """Create *path* owner-only (directory 0700, file 0600) if it is missing.

    Left to itself, ssh would create the file with the process umask. An
    existing file is not touched. Failure is logged rather than raised:
    ssh still verifies against the user's known_hosts and reports a key it
    cannot record.
    """
    if path.exists():
        return
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # O_EXCL refuses a path that appeared meanwhile, symlinks included.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    except OSError as exc:
        logger.warning("Could not create known_hosts file %s: %s", path, exc)
        return
    os.close(descriptor)


def _ssh_config_word(value: str) -> str:
    """Double-quote one path for a multi-value ssh_config option."""
    return f'"{value}"'


@dataclass(frozen=True)
class HostKeyPolicy:
    """The host-key options for one ssh/scp invocation.

    Attributes:
        mode: A value from ``HOST_KEY_CHECKING_MODES``.
        known_hosts_file: Servonaut's own file; new keys are recorded here.
        user_known_hosts_file: The user's file, consulted second.
    """

    mode: str
    known_hosts_file: Path
    user_known_hosts_file: Path

    @classmethod
    def from_ssh_config(cls, ssh_config: Any = None) -> "HostKeyPolicy":
        """Build the policy for ``config.ssh`` (defaults when None)."""
        raw_mode = getattr(ssh_config, "host_key_checking", DEFAULT_HOST_KEY_CHECKING)
        return cls(
            mode=normalize_host_key_checking(raw_mode),
            known_hosts_file=servonaut_known_hosts_path(),
            user_known_hosts_file=user_known_hosts_path(),
        )

    @property
    def verifies_host_keys(self) -> bool:
        """True unless verification is switched off."""
        return self.mode != HOST_KEY_CHECKING_OFF

    def ssh_options(self, *, discard_keys_when_off: bool = True) -> List[str]:
        """Return the ``-o`` arguments that apply this policy.

        When verifying, Servonaut's known_hosts file is created (owner-only)
        first, so ssh never creates it with looser permissions.

        Args:
            discard_keys_when_off: In ``off`` mode, also send keys to
                ``/dev/null``. The main ssh/scp commands always did; the
                bastion hop and the connectivity probe never did, and pass
                False so ``off`` keeps their previous argv exactly.
        """
        if not self.verifies_host_keys:
            options = ["-o", "StrictHostKeyChecking=no"]
            if discard_keys_when_off:
                options += ["-o", "UserKnownHostsFile=/dev/null"]
            return options
        ensure_known_hosts_file(self.known_hosts_file)
        known_hosts = " ".join(
            _ssh_config_word(str(path))
            for path in (self.known_hosts_file, self.user_known_hosts_file)
        )
        return [
            "-o", f"StrictHostKeyChecking={self.mode}",
            "-o", f"UserKnownHostsFile={known_hosts}",
        ]


def known_hosts_name(host: str, port: Optional[int] = None) -> str:
    """Return *host* as OpenSSH writes it in known_hosts (``[host]:port``)."""
    if port is None or port == 22:
        return host
    return f"[{host}]:{port}"


@dataclass(frozen=True)
class HostKeyProblem:
    """A connection OpenSSH refused because it could not verify the host key.

    Attributes:
        kind: ``HOST_KEY_CHANGED``, ``HOST_KEY_UNKNOWN`` or
            ``HOST_KEY_UNVERIFIED``.
        host: The host as OpenSSH names it (``web-1`` or ``[web-1]:2222``);
            a bastion when the bastion hop was the one refused.
        known_hosts_file: The file holding the stale key (changed), or
            Servonaut's own file otherwise.
    """

    kind: str
    host: str
    known_hosts_file: str

    @property
    def reason_code(self) -> str:
        """Machine-readable reason, e.g. for an audit row."""
        return f"ssh_host_key_{self.kind}"

    @property
    def recovery_command(self) -> Optional[str]:
        """The command that removes a stale key, for a changed key only."""
        if self.kind != HOST_KEY_CHANGED:
            return None
        return (
            f"ssh-keygen -R {shlex.quote(self.host)} "
            f"-f {shlex.quote(self.known_hosts_file)}"
        )

    @property
    def message(self) -> str:
        """A concise, plain-text explanation with the next step."""
        if self.kind == HOST_KEY_CHANGED:
            return (
                f"SSH host key for {self.host} has changed, so the connection "
                "was refused. The server may have been rebuilt or re-keyed, "
                "or the connection may be intercepted. Once you have "
                "confirmed the new key is genuine, remove the old one and "
                f"reconnect: {self.recovery_command}"
            )
        if self.kind == HOST_KEY_UNKNOWN:
            return (
                f"SSH host key for {self.host} is not known and "
                'ssh.host_key_checking is "yes", so the connection was '
                f"refused. Add the host's verified key to "
                f"{self.known_hosts_file}, or set ssh.host_key_checking to "
                '"accept-new" to trust a new host on first connect.'
            )
        return (
            f"SSH host key verification failed for {self.host}, so the "
            "connection was refused. Check the host's entries in "
            f"{self.known_hosts_file} and your own known_hosts file."
        )


def detect_host_key_problem(
    stderr: str,
    *,
    host: Optional[str] = None,
    port: Optional[int] = None,
    known_hosts_file: Optional[Path] = None,
) -> Optional[HostKeyProblem]:
    """Recognise a host-key refusal in ssh/scp stderr.

    Call this for an invocation that failed: a remote command that itself
    runs ssh can print the same text on success paths.

    Args:
        stderr: Captured standard error of the ssh/scp process.
        host: The target host, named when OpenSSH's output does not.
        port: The target port, for the ``[host]:port`` form.
        known_hosts_file: Servonaut's known_hosts file (defaults to
            :func:`servonaut_known_hosts_path`).

    Returns:
        The problem, or None when stderr shows no host-key refusal.
    """
    if not stderr:
        return None
    lowered = stderr.lower()
    if not any(marker in lowered for marker in _REFUSAL_MARKERS):
        return None

    default_file = str(known_hosts_file or servonaut_known_hosts_path())
    fallback_host = known_hosts_name(host, port) if host else "the server"

    changed = _CHANGED_RE.search(stderr)
    if changed or "remote host identification has changed" in lowered:
        remove_with = _REMOVE_WITH_RE.search(stderr)
        offending = _OFFENDING_RE.search(stderr)
        named_host = (
            changed.group(1) if changed
            else remove_with.group(4) if remove_with
            else fallback_host
        )
        stale_file = (
            offending.group(1).strip() if offending
            else remove_with.group(2) if remove_with
            else default_file
        )
        return HostKeyProblem(HOST_KEY_CHANGED, named_host.rstrip("."), stale_file)

    unknown = _UNKNOWN_RE.search(stderr)
    if unknown:
        return HostKeyProblem(HOST_KEY_UNKNOWN, unknown.group(1).rstrip("."), default_file)
    return HostKeyProblem(HOST_KEY_UNVERIFIED, fallback_host, default_file)


class HostKeyVerificationError(Exception):
    """Raised where a host-key refusal must stop the remaining work."""

    def __init__(self, problem: HostKeyProblem) -> None:
        super().__init__(problem.message)
        self.problem = problem
