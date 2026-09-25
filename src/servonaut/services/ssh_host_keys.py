"""Host-key verification for every ssh/scp command Servonaut builds.

Servonaut drives the system OpenSSH client, so host-key verification is a
matter of the options it passes. This module is the single place those
options come from:

* ``StrictHostKeyChecking`` follows ``ssh.host_key_checking``
  (``accept-new`` by default, ``yes`` or ``off``).
* ``UserKnownHostsFile`` lists Servonaut's own file under the data root
  first, so newly accepted keys are recorded there, followed by the user's
  ``~/.ssh/known_hosts``, so hosts they already trust keep working.
* Cloud instances are pinned by a stable ``HostKeyAlias``
  (``provider:region:instance-id``) rather than by IP address: private
  addresses repeat across networks and public ones are recycled.

It also recognises OpenSSH's refusal output, so a changed key is reported
as a changed key instead of as a generic connection failure. That output
reaches Servonaut through the same stream as a remote command's own
stderr, so a removal command is only suggested when the reported host and
file are ones this connection actually used.

Every path handed to ssh is absolute. OpenSSH expands ``~`` from the
password database rather than ``$HOME``, so a literal ``~`` would escape a
sandboxed home.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, FrozenSet, List, Optional, Sequence

from servonaut.config.schema import (
    DEFAULT_HOST_KEY_CHECKING,
    normalize_host_key_checking,
)
from servonaut.runtime import data_root_for_home

logger = logging.getLogger(__name__)

HOST_KEY_CHECKING_OFF = "off"
KNOWN_HOSTS_FILENAME = "known_hosts"

# ``off`` reproduces what each command sent before verification existed:
# the ssh/scp commands discarded keys, the bastion hop and the connectivity
# probe only disabled the check.
OFF_OPTIONS: Sequence[str] = (
    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
)
OFF_OPTIONS_KEEP_KNOWN_HOSTS: Sequence[str] = ("-o", "StrictHostKeyChecking=no")
# The ``servonaut servers verify`` probe trusted new hosts and refused a
# changed key even before the setting existed.
OFF_OPTIONS_ACCEPT_NEW: Sequence[str] = ("-o", "StrictHostKeyChecking=accept-new")

HOST_KEY_CHANGED = "changed"
HOST_KEY_UNKNOWN = "unknown"
HOST_KEY_UNVERIFIED = "unverified"

# OpenSSH exits with 255 for its own failures, including a refused key.
SSH_FAILURE_EXIT_CODE = 255

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
_REMOVE_WITH_RE = re.compile(r"ssh-keygen -f (['\"])(.+?)\1 -R (['\"])(.+?)\3")

_AWS_INSTANCE_ID_RE = re.compile(r"i-[0-9a-f]{8,17}")
# Characters kept in an alias. Everything else, including the ',' '*' '?'
# '!' and '[' that carry meaning in a known_hosts host field, becomes '_'.
_ALIAS_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._/@-]")


def servonaut_known_hosts_path() -> Path:
    """Return Servonaut's own known_hosts file, under the data root."""
    return data_root_for_home(Path.home()) / KNOWN_HOSTS_FILENAME


def user_known_hosts_path() -> Path:
    """Return the user's OpenSSH known_hosts file as an absolute path."""
    return Path.home() / ".ssh" / KNOWN_HOSTS_FILENAME


def _is_trusted_file(path: Path) -> bool:
    """True for a regular file, not a symlink, that only its owner can change."""
    try:
        info = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode):
        return False  # a symlink, or anything else that is not a plain file
    if os.name == "nt":
        return True
    return info.st_uid == os.geteuid() and not info.st_mode & 0o022


def ensure_known_hosts_file(path: Path) -> bool:
    """Create *path* owner-only when missing; report whether ssh may use it.

    A new file is created 0600 in a 0700 directory; left to itself, ssh
    would create it with the process umask. An existing file is not
    changed. It is refused when it is a symlink, not a regular file, owned
    by someone else, or writable by group or others: anyone who can write
    it can add a key that ssh would then trust.
    """
    try:
        path.lstat()
    except FileNotFoundError:
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            # O_EXCL refuses a path that appeared meanwhile, symlinks included.
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        except FileExistsError:
            pass
        except OSError as exc:
            logger.warning("Could not create known_hosts file %s: %s", path, exc)
            return False
    except OSError as exc:
        logger.warning("Could not inspect known_hosts file %s: %s", path, exc)
        return False
    if _is_trusted_file(path):
        return True
    logger.warning(
        "Not using %s for host keys: it must be a regular file owned by you "
        "and not writable by group or others.", path,
    )
    return False


def ssh_config_word(value: str, *, expansions: int = 1) -> Optional[str]:
    """Quote *value* as one word of a multi-value ssh_config option.

    Args:
        value: The literal text, typically a path.
        expansions: How many times OpenSSH percent-expands the text before
            using it: once for an option on the command line, twice inside
            a ProxyCommand hop (the outer ssh expands the ProxyCommand, the
            hop's ssh expands its own option).

    Returns:
        The quoted word, or None when OpenSSH cannot be given the text
        literally: it expands ``${NAME}`` and has no escape for it.
    """
    if "${" in value:
        return None
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("%", "%" * (2 ** expansions))
    return f'"{escaped}"'


def proxy_command_word(value: str) -> str:
    """Quote *value* for a ProxyCommand: ssh expands ``%``, then ``sh`` runs it."""
    return shlex.quote(value.replace("%", "%%"))


def home_relative(path: str) -> str:
    """Show *path* under the home directory as ``~/...``.

    Messages can leave this machine (MCP clients, the relay, hosted AI), so
    they carry no home directory or user name.
    """
    home = str(Path.home())
    if path == home:
        return "~"
    prefix = home.rstrip("/\\") + os.sep
    if path.startswith(prefix):
        return "~/" + path[len(prefix):].replace(os.sep, "/")
    return path


def _shell_path(path: str) -> str:
    """Quote *path* for a POSIX shell, keeping a leading ``~/`` expandable."""
    shown = home_relative(path)
    if shown.startswith("~/"):
        return "~/" + shlex.quote(shown[2:])
    return shlex.quote(shown)


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

    def known_hosts_files(self) -> List[Path]:
        """The files ssh is told to use, in order.

        Servonaut's own file is created when missing and left out when it
        cannot be trusted; the user's file then still verifies. A path
        OpenSSH cannot take literally is left out as well.
        """
        files = []
        if ensure_known_hosts_file(self.known_hosts_file):
            files.append(self.known_hosts_file)
        files.append(self.user_known_hosts_file)
        usable = [path for path in files if ssh_config_word(str(path)) is not None]
        if len(usable) < len(files):
            logger.warning("Skipping a known_hosts path containing '${': %s", files)
        return usable

    def ssh_options(
        self,
        *,
        off_options: Sequence[str] = OFF_OPTIONS,
        expansions: int = 1,
    ) -> List[str]:
        """Return the ``-o`` arguments that apply this policy.

        Args:
            off_options: What ``off`` sends: the options the calling
                command sent before verification existed.
            expansions: Percent expansions the values go through (2 inside
                a ProxyCommand hop).
        """
        if not self.verifies_host_keys:
            return list(off_options)
        words = [
            ssh_config_word(str(path), expansions=expansions)
            for path in self.known_hosts_files()
        ]
        return [
            "-o", f"StrictHostKeyChecking={self.mode}",
            "-o", f"UserKnownHostsFile={' '.join(w for w in words if w)}",
            # Neither prompt about nor rewrite keys a server offers later.
            "-o", "UpdateHostKeys=no",
        ]


def known_hosts_name(host: str, port: Optional[int] = None) -> str:
    """Return *host* as OpenSSH writes it in known_hosts (``[host]:port``)."""
    if port is None or port == 22:
        return host
    return f"[{host}]:{port}"


def _instance_provider(instance: dict) -> Optional[str]:
    if instance.get("is_custom"):
        return None
    if instance.get("is_hetzner"):
        return "hetzner"
    if instance.get("is_ovh"):
        return "ovh"
    if _AWS_INSTANCE_ID_RE.fullmatch(str(instance.get("id") or "")):
        return "aws"
    return None


def host_key_alias(instance: Any) -> Optional[str]:
    """Return the stable known_hosts name for a cloud instance.

    AWS, OVH and Hetzner instances are named ``provider:region:instance-id``.
    Custom servers, and anything unrecognised, keep their host name.
    """
    if not isinstance(instance, dict):
        return None
    provider = _instance_provider(instance)
    instance_id = str(instance.get("id") or "")
    if provider is None or not instance_id:
        return None
    region = str(instance.get("region") or "")
    return ":".join(
        _ALIAS_UNSAFE_RE.sub("_", part) for part in (provider, region, instance_id)
    )


def host_key_alias_options(instance: Any, policy: HostKeyPolicy) -> List[str]:
    """``KEY=VALUE`` entries pinning *instance* by alias (empty when off)."""
    alias = host_key_alias(instance) if policy.verifies_host_keys else None
    return [f"HostKeyAlias={alias}"] if alias else []


@dataclass(frozen=True)
class HostKeyTarget:
    """The names OpenSSH may report for one connection.

    Attributes:
        name: The target as known_hosts names it: its alias, or
            ``host`` / ``[host]:port``.
        address_name: The target's address form, when an alias is used.
        bastion: The bastion hop's known_hosts name, if any.
    """

    name: str
    address_name: Optional[str] = None
    bastion: Optional[str] = None

    @classmethod
    def for_connection(
        cls,
        host: str,
        port: Optional[int] = None,
        *,
        instance: Any = None,
        profile: Any = None,
    ) -> "HostKeyTarget":
        """Describe a connection to *host*, through *profile*'s bastion if any."""
        address = known_hosts_name(str(host or ""), port)
        alias = host_key_alias(instance)
        bastion = None
        if (
            profile is not None
            and getattr(profile, "bastion_host", None)
            and not getattr(profile, "proxy_command", None)
        ):
            bastion = known_hosts_name(profile.bastion_host, getattr(profile, "ssh_port", None))
        return cls(
            name=alias or address,
            address_name=address if alias else None,
            bastion=bastion,
        )

    @property
    def names(self) -> FrozenSet[str]:
        """Every name a genuine refusal for this connection can report."""
        return frozenset(n for n in (self.name, self.address_name, self.bastion) if n)


@dataclass(frozen=True)
class HostKeyProblem:
    """A connection OpenSSH refused because it could not verify the host key.

    Attributes:
        kind: ``HOST_KEY_CHANGED``, ``HOST_KEY_UNKNOWN`` or
            ``HOST_KEY_UNVERIFIED``.
        host: The host as OpenSSH names it (an alias, ``web-1`` or
            ``[web-1]:2222``); a bastion when the bastion hop was refused.
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
        """The command that removes a stale key, for a verified change only."""
        if self.kind != HOST_KEY_CHANGED:
            return None
        return f"ssh-keygen -R {shlex.quote(self.host)} -f {_shell_path(self.known_hosts_file)}"

    @property
    def message(self) -> str:
        """A concise, plain-text explanation with the next step, for a person."""
        if self.kind == HOST_KEY_CHANGED:
            return (
                f"SSH host key for {self.host} has changed, so the connection "
                "was refused. The server may have been rebuilt or re-keyed, "
                "or the connection may be intercepted. Once you have "
                "confirmed the new key is genuine, remove the old one and "
                f"reconnect: {self.recovery_command}"
            )
        return self._not_changed_message()

    @property
    def agent_message(self) -> str:
        """The explanation for an automated client (MCP, relay, hosted AI).

        It asks for a person to verify the key: an agent must never clear a
        pin on its own.
        """
        if self.kind == HOST_KEY_CHANGED:
            return (
                f"SSH host key for {self.host} has changed, so the connection "
                "was refused. This can mean the server was rebuilt or "
                "re-keyed, or that the connection is being intercepted. Do "
                "not remove the stored key automatically: a person must first "
                "verify the server's new key fingerprint out of band, for "
                "example in the provider's console. Only then remove the old "
                f"entry with: {self.recovery_command}"
            )
        return self._not_changed_message()

    def _not_changed_message(self) -> str:
        shown_file = home_relative(self.known_hosts_file)
        if self.kind == HOST_KEY_UNKNOWN:
            return (
                f"SSH host key for {self.host} is not known and "
                'ssh.host_key_checking is "yes", so the connection was '
                f"refused. Add the host's verified key to {shown_file}, or "
                'set ssh.host_key_checking to "accept-new" to trust a new '
                "host on first connect."
            )
        return (
            f"SSH host key verification failed for {self.host}, so the "
            "connection was refused. Check the host's entries in "
            f"{shown_file} and your own known_hosts file before connecting "
            "again."
        )


def detect_host_key_problem(
    stderr: str,
    returncode: Optional[int],
    target: HostKeyTarget,
    policy: HostKeyPolicy,
    *,
    stdout: Any = None,
) -> Optional[HostKeyProblem]:
    """Recognise a host-key refusal in the output of a failed ssh/scp run.

    OpenSSH's messages share stderr with the remote command's, so the text
    alone proves nothing: ssh must have failed itself (exit 255) without
    printing anything to stdout. A removal command is offered only when the
    reported host is this connection's target or bastion and the reported
    file is one this connection passed to ssh; otherwise the refusal is
    reported without one.

    Args:
        stderr: Captured standard error of the ssh/scp process.
        returncode: Its exit status (None when unknown).
        target: The names this connection can legitimately report.
        policy: The policy the command was built with.
        stdout: Captured standard output, if any.

    Returns:
        The problem, or None when this is not a host-key refusal.
    """
    if returncode != SSH_FAILURE_EXIT_CODE or stdout or not stderr:
        return None
    lowered = stderr.lower()
    if not any(marker in lowered for marker in _REFUSAL_MARKERS):
        return None

    names = target.names
    own_file = str(policy.known_hosts_file)
    changed = _CHANGED_RE.search(stderr)
    if changed or "remote host identification has changed" in lowered:
        remove_with = _REMOVE_WITH_RE.search(stderr)
        offending = _OFFENDING_RE.search(stderr)
        host = changed.group(1) if changed else (remove_with.group(4) if remove_with else None)
        stale_file = (
            offending.group(1).strip() if offending
            else remove_with.group(2) if remove_with else None
        )
        passed_files = {os.path.normpath(str(p)) for p in policy.known_hosts_files()}
        if (
            host in names
            and stale_file is not None
            and os.path.normpath(stale_file) in passed_files
        ):
            return HostKeyProblem(HOST_KEY_CHANGED, host, stale_file)
        return HostKeyProblem(HOST_KEY_UNVERIFIED, target.name, own_file)

    unknown = _UNKNOWN_RE.search(stderr)
    if unknown and unknown.group(1) in names:
        return HostKeyProblem(HOST_KEY_UNKNOWN, unknown.group(1), own_file)
    return HostKeyProblem(HOST_KEY_UNVERIFIED, target.name, own_file)


class HostKeyVerificationError(Exception):
    """Raised where a host-key refusal must stop the remaining work."""

    def __init__(self, problem: HostKeyProblem) -> None:
        super().__init__(problem.message)
        self.problem = problem
