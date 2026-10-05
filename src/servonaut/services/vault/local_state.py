"""Authenticated local state used to detect server rollback attempts.

The vault API is not a source of trust.  This tiny store holds only public
trust anchors and monotonic counters; private key material lives in
``identity_store``.  It deliberately refuses symlinks and loose permissions
because its contents decide which server responses the client may accept.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any


class LocalStateError(RuntimeError):
    """Raised when trusted local state is absent, malformed, or unsafe."""


class VaultLocalState:
    """Persist public pins and monotonic version/revision observations."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or Path.home() / ".servonaut" / "vault" / "state.json"

    def load(self) -> dict[str, Any]:
        """Return the persisted state, or an empty state before first use."""
        if not self._path.exists():
            return {"v": 1, "identity_pins": {}, "vault_heads": {}, "item_revisions": {}, "ca_audit_heads": {}}
        _require_safe_file(self._path)
        try:
            with self._path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise LocalStateError("Vault local state cannot be read safely") from exc
        if not isinstance(data, dict) or data.get("v") != 1:
            raise LocalStateError("Vault local state has an unsupported format")
        for key in ("identity_pins", "vault_heads", "item_revisions", "ca_audit_heads"):
            if not isinstance(data.get(key, {}), dict):
                raise LocalStateError("Vault local state has an invalid shape")
        return data

    def save(self, state: dict[str, Any]) -> None:
        """Atomically persist an already validated public state document."""
        if not isinstance(state, dict) or state.get("v") != 1:
            raise LocalStateError("Refusing to save an unsupported local-state format")
        _ensure_safe_directory(self._path.parent)
        if self._path.exists():
            _require_safe_file(self._path)
        encoded = json.dumps(state, separators=(",", ":"), sort_keys=True).encode("utf-8")
        fd, temporary_name = tempfile.mkstemp(
            dir=self._path.parent,
            prefix=f".{self._path.name}.",
            suffix=".tmp",
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self._path)
            os.chmod(self._path, 0o600)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise

    def pin_identity(self, user_id: int, fingerprint: str) -> None:
        """Pin a user's identity fingerprint on first verified observation."""
        if type(user_id) is not int or user_id < 1:
            raise LocalStateError("Identity user id must be a positive integer")
        state = self.load()
        pins = state["identity_pins"]
        key = str(user_id)
        previous = pins.get(key)
        if previous is not None and previous != fingerprint:
            raise LocalStateError("Identity fingerprint changed and needs explicit confirmation")
        pins[key] = fingerprint
        self.save(state)

    def record_vault_head(self, vault_id: str, version: int, record_hash: str) -> None:
        """Record a verified chain head, rejecting a rollback locally."""
        if type(version) is not int or version < 1 or not record_hash:
            raise LocalStateError("Invalid verified vault head")
        state = self.load()
        previous = state["vault_heads"].get(vault_id)
        if isinstance(previous, dict):
            previous_version = previous.get("version")
            if type(previous_version) is not int or previous_version < 1:
                raise LocalStateError("Stored vault head has an invalid version")
            if previous_version > version:
                raise LocalStateError("Vault version rollback detected")
        state["vault_heads"][vault_id] = {"version": version, "record_hash": record_hash}
        self.save(state)

    def record_item_revision(self, item_id: str, revision: int) -> None:
        """Record a verified item revision, rejecting a rollback locally."""
        if type(revision) is not int or revision < 1:
            raise LocalStateError("Invalid verified item revision")
        state = self.load()
        previous = state["item_revisions"].get(item_id, 0)
        if type(previous) is not int or previous < 0:
            raise LocalStateError("Stored item revision is invalid")
        if previous > revision:
            raise LocalStateError("Vault item revision rollback detected")
        state["item_revisions"][item_id] = revision
        self.save(state)

    def record_ca_audit_head(self, team_slug: str, head_hash: str) -> None:
        """Persist an independently verified issuance-log head per team."""
        if not isinstance(team_slug, str) or not team_slug:
            raise LocalStateError("CA audit team slug is invalid")
        if not isinstance(head_hash, str) or len(head_hash) != 44:
            raise LocalStateError("CA audit head hash is invalid")
        state = self.load()
        state.setdefault("ca_audit_heads", {})[team_slug] = head_hash
        self.save(state)

    def record_break_glass_reports(self, keys: list[str], *, keep: int = 1000) -> None:
        """Remember which break-glass events were reported, so scans report each once."""
        if not all(isinstance(key, str) and key for key in keys):
            raise LocalStateError("break-glass report keys are invalid")
        state = self.load()
        known = [key for key in state.get("break_glass_reported", []) if isinstance(key, str)]
        known.extend(key for key in keys if key not in known)
        state["break_glass_reported"] = known[-keep:]
        self.save(state)


def _ensure_safe_directory(path: Path) -> None:
    """Create a private, non-symlinked state directory."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise LocalStateError("Vault state directory is not a real directory")
    if info.st_mode & 0o077:
        os.chmod(path, 0o700)


def _require_safe_file(path: Path) -> None:
    """Reject symlinks, directories, and group/world-readable state files."""
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise LocalStateError("Vault state path is not a regular file")
    if info.st_mode & 0o077:
        raise LocalStateError("Vault state file permissions are too broad")
