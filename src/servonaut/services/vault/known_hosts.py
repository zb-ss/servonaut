"""Scoped host-CA known-hosts files for Team SSH certificate connections."""

from __future__ import annotations

import os
import re
import stat
import tempfile
import uuid
from pathlib import Path
from typing import Iterable

from servonaut.services.ssh_host_keys import pinned_host_key_options

from .ca_client import CertificateValidationError, validate_openssh_public_key


_TEAM_SLUG_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


class KnownHostsError(ValueError):
    """An unsafe Team host-CA known-hosts value was supplied."""


class TeamKnownHosts:
    """Write a Team-scoped file that never grants a wildcard host trust."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir or Path.home() / ".servonaut" / "known_hosts.d"

    def write(
        self,
        team_slug: str,
        host_ca_public_key: str,
        hosts: Iterable[str | tuple[str, int]],
        binding_pins: Iterable[str] = (),
    ) -> Path:
        """Atomically write one strict @cert-authority line and pinned hosts."""
        if not _TEAM_SLUG_RE.fullmatch(team_slug):
            raise KnownHostsError("team slug has an invalid shape")
        host_values = sorted({self._format_host(host) for host in hosts})
        if not host_values:
            raise KnownHostsError("at least one enrolled host is required")
        try:
            validate_openssh_public_key(host_ca_public_key)
        except CertificateValidationError as exc:
            raise KnownHostsError("host CA must be an OpenSSH public key") from exc
        pin_values = [self._validate_pin(pin) for pin in binding_pins]
        self._ensure_private_base_dir()
        # Every connection lease owns its trust file.  Reusing one team path
        # lets a second connection replace the first connection's host scope.
        target = self.base_dir / f"{team_slug}-{uuid.uuid4().hex}.known_hosts"
        lines = [
            f"@cert-authority {','.join(host_values)} {host_ca_public_key.strip()}\n",
            *[f"{pin}\n" for pin in pin_values],
        ]
        fd, temp_name = tempfile.mkstemp(dir=self.base_dir, prefix=f".{team_slug}.", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.writelines(lines)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, target)
            os.chmod(target, 0o600)
            self._assert_private_file(target)
        except BaseException:
            Path(temp_name).unlink(missing_ok=True)
            raise
        return target

    def _ensure_private_base_dir(self) -> None:
        """Create a private directory without following an unsafe parent link."""
        missing: list[Path] = []
        current = self.base_dir
        while True:
            try:
                info = current.lstat()
                break
            except FileNotFoundError:
                missing.append(current)
                current = current.parent
            except OSError as exc:
                raise KnownHostsError("could not inspect Team known_hosts directory") from exc
        self._assert_safe_directory(current, allow_home=current == Path.home())
        for directory in reversed(missing):
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                pass
            self._assert_safe_directory(directory)
        self._assert_safe_directory(self.base_dir)

    @staticmethod
    def _assert_safe_directory(path: Path, *, allow_home: bool = False) -> None:
        try:
            info = path.lstat()
        except OSError as exc:
            raise KnownHostsError("could not inspect Team known_hosts directory") from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise KnownHostsError("Team known_hosts directory is not a real directory")
        if info.st_uid != os.getuid() or (not allow_home and info.st_mode & 0o077):
            raise KnownHostsError("Team known_hosts directory has unsafe ownership or permissions")

    @staticmethod
    def _assert_private_file(path: Path) -> None:
        try:
            info = path.lstat()
        except OSError as exc:
            raise KnownHostsError("could not inspect Team known_hosts file") from exc
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise KnownHostsError("Team known_hosts file is not a regular file")
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise KnownHostsError("Team known_hosts file has unsafe ownership or permissions")

    @staticmethod
    def ssh_options(path: Path) -> list[str]:
        """Return host-verification options that cannot silently fall back."""
        return pinned_host_key_options(path)

    @staticmethod
    def _validate_host(host: str) -> str:
        value = host.strip()
        if not value or value == "*" or any(char.isspace() for char in value):
            raise KnownHostsError("host entries must be explicit, non-wildcard names")
        if any(character in value for character in "*!?"):
            raise KnownHostsError("host entries must not contain wildcards")
        return value

    @classmethod
    def _format_host(cls, host: str | tuple[str, int]) -> str:
        if isinstance(host, tuple):
            if len(host) != 2 or isinstance(host[1], bool) or not isinstance(host[1], int) or not 1 <= host[1] <= 65535:
                raise KnownHostsError("SSH endpoint has an invalid port")
            hostname = cls._validate_host(host[0])
            return hostname if host[1] == 22 else f"[{hostname}]:{host[1]}"
        return cls._validate_host(host)

    @staticmethod
    def _validate_pin(pin: str) -> str:
        value = pin.strip()
        if not value or value.startswith("@cert-authority") or "\n" in value:
            raise KnownHostsError("binding pin is not a valid known_hosts line")
        return value
