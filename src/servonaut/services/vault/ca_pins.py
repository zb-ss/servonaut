"""Persistent, per-team SSH CA fingerprints with fail-closed TOFU."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path


class CaPinMismatchError(RuntimeError):
    """A server presented a different CA than the locally pinned CA."""


@dataclass(frozen=True)
class CaPins:
    user_ca_fingerprint: str
    host_ca_fingerprint: str


class CaPinStore:
    """Store CA pins in a local owner-only JSON file."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path.home() / ".servonaut" / "vault" / "ca_pins.json"

    def verify_or_pin(self, team_slug: str, pins: CaPins) -> CaPins:
        """Pin first sight, or reject a changed user or host CA fingerprint."""
        data = self._read()
        teams = data.setdefault("teams", {})
        previous = teams.get(team_slug)
        if previous is not None:
            old = CaPins(
                user_ca_fingerprint=str(previous.get("user_ca_fingerprint", "")),
                host_ca_fingerprint=str(previous.get("host_ca_fingerprint", "")),
            )
            if old != pins:
                raise CaPinMismatchError(
                    "The team SSH CA changed; verify the new fingerprint before replacing the pin"
                )
            return old
        teams[team_slug] = {
            "user_ca_fingerprint": pins.user_ca_fingerprint,
            "host_ca_fingerprint": pins.host_ca_fingerprint,
        }
        self._write(data)
        return pins

    def replace_after_confirmation(self, team_slug: str, pins: CaPins) -> None:
        """Replace a pin only after the caller has completed an explicit UI check."""
        data = self._read()
        data.setdefault("teams", {})[team_slug] = {
            "user_ca_fingerprint": pins.user_ca_fingerprint,
            "host_ca_fingerprint": pins.host_ca_fingerprint,
        }
        self._write(data)

    def _read(self) -> dict[str, object]:
        self._ensure_private_parent(create=False)
        try:
            raw = json.loads(self._read_private_file())
        except FileNotFoundError:
            return {"format": 1, "teams": {}}
        except (OSError, json.JSONDecodeError) as exc:
            raise CaPinMismatchError("Could not safely read local SSH CA pins") from exc
        if not isinstance(raw, dict) or raw.get("format") != 1 or not isinstance(raw.get("teams"), dict):
            raise CaPinMismatchError("Local SSH CA pins have an unsupported format")
        return raw

    def _write(self, data: dict[str, object]) -> None:
        parent = self._ensure_private_parent(create=True)
        self._assert_safe_file_if_present()
        fd, temporary = tempfile.mkstemp(dir=parent, prefix=".ca_pins.", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
            self._assert_safe_file_if_present()
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def _ensure_private_parent(self, *, create: bool) -> Path:
        parent = self.path.parent
        if not parent.exists() and create:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not parent.exists():
            return parent
        try:
            info = parent.lstat()
        except OSError as exc:
            raise CaPinMismatchError("Could not inspect SSH CA pin directory") from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise CaPinMismatchError("SSH CA pin directory is not a real directory")
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise CaPinMismatchError("SSH CA pin directory has unsafe ownership or permissions")
        return parent

    def _assert_safe_file_if_present(self) -> None:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise CaPinMismatchError("Could not inspect SSH CA pin file") from exc
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise CaPinMismatchError("SSH CA pin file is not a real private file")
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise CaPinMismatchError("SSH CA pin file has unsafe ownership or permissions")

    def _read_private_file(self) -> str:
        self._assert_safe_file_if_present()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise CaPinMismatchError("Could not open SSH CA pin file safely") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise CaPinMismatchError("SSH CA pin file changed to an unsafe type or mode")
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                return handle.read()
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
