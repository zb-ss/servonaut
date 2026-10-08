"""Persistent, per-team SSH CA fingerprints with fail-closed TOFU."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows has no flock
    fcntl = None  # type: ignore[assignment]

from .errors import VaultUserError


class CaPinMismatchError(VaultUserError):
    """A server presented a different CA than the locally pinned CA.

    Its messages are fixed client text, so every surface shows them as-is.
    """

    # Reported to the service as an enrolment result's error code.
    code = "ca_pin_mismatch"


# Retired user CA fingerprints remembered per team, to refuse a key's return.
_RETIRED_KEPT = 32

# After a changed-CA refusal: how the user re-establishes trust on purpose.
CA_CHANGED = (
    "The team SSH CA changed; compare the new fingerprints with the ones on the team's "
    "SSH access page in the web app, then accept them with `servonaut ca trust --team {team}`"
)


@dataclass(frozen=True)
class CaPins:
    user_ca_fingerprint: str
    host_ca_fingerprint: str


class CaPinStore:
    """Store CA pins in a local owner-only JSON file."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path.home() / ".servonaut" / "vault" / "ca_pins.json"

    def verify_or_pin(
        self,
        team_slug: str,
        pins: CaPins,
        *,
        user_ca_generation: int | None = None,
        previous_user_fingerprints: Iterable[str] = (),
        next_user_fingerprint: str | None = None,
    ) -> CaPins:
        """Pin first sight, or reject a CA that changed outside a rollover.

        A user CA rollover replaces the user CA on purpose. The change is
        accepted only when it moves forward and is continuous with the pin:
        - the generation number grows (when both are known), and the key was
          never this team's user CA before, so a retired key cannot return;
        - the service lists the pinned user CA as retired, or this device saw
          the new key (or one now retired) announced as the next generation.
        The host CA has no rollover, so any change to it still fails.
        """
        previous_fingerprints = set(previous_user_fingerprints)
        with self._locked():
            data = self._read()
            teams = data.setdefault("teams", {})
            stored = teams.get(team_slug)
            if stored is not None and not isinstance(stored, dict):
                raise CaPinMismatchError("Local SSH CA pins have an unsupported format")
            record = dict(stored or {})
            retired = self._retired(stored or {})
            if stored is not None:
                self._check_continuity(team_slug, stored, pins, user_ca_generation, previous_fingerprints)
                if stored.get("user_ca_fingerprint") != pins.user_ca_fingerprint:
                    retired.append(str(stored.get("user_ca_fingerprint", "")))
            # Every key seen retired stays retired, even one this device never pinned.
            retired.extend(sorted(previous_fingerprints))
            retired = list(dict.fromkeys(key for key in retired if key and key != pins.user_ca_fingerprint))
            if retired:
                record["retired_user_ca_fingerprints"] = retired[-_RETIRED_KEPT:]
            record.update(user_ca_fingerprint=pins.user_ca_fingerprint, host_ca_fingerprint=pins.host_ca_fingerprint)
            if user_ca_generation is not None:
                record["user_ca_generation"] = user_ca_generation
            if next_user_fingerprint is None:
                record.pop("user_ca_next_fingerprint", None)
            else:
                record["user_ca_next_fingerprint"] = next_user_fingerprint
            if record != stored:
                teams[team_slug] = record
                self._write(data)
        return pins

    @classmethod
    def _check_continuity(
        cls, team_slug: str, stored: dict, pins: CaPins, generation: int | None, previous: set[str],
    ) -> None:
        if stored.get("host_ca_fingerprint") != pins.host_ca_fingerprint:
            raise CaPinMismatchError(CA_CHANGED.format(team=team_slug))
        pinned_user = stored.get("user_ca_fingerprint")
        pinned_generation = stored.get("user_ca_generation")
        if pinned_user == pins.user_ca_fingerprint:
            # The same key cannot move to an earlier generation.
            if isinstance(pinned_generation, int) and generation is not None and generation != pinned_generation:
                raise CaPinMismatchError(CA_CHANGED.format(team=team_slug))
            return
        moved_backwards = (
            pins.user_ca_fingerprint in cls._retired(stored)
            or (isinstance(pinned_generation, int) and (generation is None or generation <= pinned_generation))
        )
        announced = stored.get("user_ca_next_fingerprint")
        continuous = pinned_user in previous or (
            isinstance(announced, str) and (announced == pins.user_ca_fingerprint or announced in previous)
        )
        if moved_backwards or not continuous:
            raise CaPinMismatchError(CA_CHANGED.format(team=team_slug))

    @staticmethod
    def _retired(stored: dict) -> list[str]:
        retired = stored.get("retired_user_ca_fingerprints")
        return [item for item in retired if isinstance(item, str)] if isinstance(retired, list) else []

    def pinned(self, team_slug: str) -> CaPins | None:
        """The pins held for *team_slug*, or ``None`` before first sight."""
        entry = self._read().get("teams", {}).get(team_slug)
        if not isinstance(entry, dict):
            return None
        return CaPins(
            user_ca_fingerprint=str(entry.get("user_ca_fingerprint", "")),
            host_ca_fingerprint=str(entry.get("host_ca_fingerprint", "")),
        )

    def replace_after_confirmation(
        self, team_slug: str, pins: CaPins, *, user_ca_generation: int | None = None,
    ) -> None:
        """Replace a pin only after the caller has completed an explicit UI check."""
        with self._locked():
            data = self._read()
            teams = data.setdefault("teams", {})
            stored = teams.get(team_slug) if isinstance(teams.get(team_slug), dict) else {}
            retired = self._retired(stored)
            if stored.get("user_ca_fingerprint") not in (None, pins.user_ca_fingerprint):
                retired.append(str(stored["user_ca_fingerprint"]))
            # Keep fields this version does not know; the trusted CA starts afresh.
            record: dict[str, object] = {
                key: value for key, value in stored.items()
                if key not in {"user_ca_next_fingerprint", "user_ca_generation", "retired_user_ca_fingerprints"}
            }
            record.update(user_ca_fingerprint=pins.user_ca_fingerprint, host_ca_fingerprint=pins.host_ca_fingerprint)
            if retired:
                record["retired_user_ca_fingerprints"] = [item for item in retired if item != pins.user_ca_fingerprint][-_RETIRED_KEPT:]
            if user_ca_generation is not None:
                record["user_ca_generation"] = user_ca_generation
            teams[team_slug] = record
            self._write(data)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialise read-modify-write between the TUI, ``connect`` and the CLI."""
        if fcntl is None:  # pragma: no cover - platforms without flock
            yield
            return
        parent = self._ensure_private_parent(create=True)
        fd = os.open(parent / ".ca_pins.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

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
