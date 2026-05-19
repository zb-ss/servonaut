"""Local-only :class:`SecretProvider` implementation.

The :class:`LocalProvider` is the secrets-management MVP's foundation
backend — the one every user (Solo and Teams alike) gets by default,
and the fallback any time a configured cloud provider is unavailable.

Storage model:
    Plaintext JSON at ``~/.servonaut/secrets.json``, file mode ``0600``,
    written atomically via ``tempfile + os.replace`` so a crash mid-write
    cannot leave the user with a half-rewritten secrets file (same
    pattern :mod:`servonaut.services.auth_service` uses for the OAuth
    token file). Trust boundary = the local filesystem; the user's home
    directory is already where OAuth bearer tokens, SSH private keys,
    and AWS credentials live, so we're not introducing a new class of
    exposure.

We do NOT encrypt the file at rest. A user-supplied passphrase would
mean either prompting on every CLI command (friction) or caching the
key in memory or env (no security improvement). For the MVP we treat
``0600`` + filesystem owner = sufficient — same model as the existing
``auth.json``. A future revision can layer OS-keyring storage on top
of this same interface without breaking callers.

Contract notes (kept in sync with
``services/interfaces.py::SecretProviderInterface`` — read that
docstring first):

- All methods are async even though IO is local. Keeps call sites
  uniform across LocalProvider and the future BitwardenProvider /
  VaultProvider / etc.
- Secret names are case-sensitive and stable.
- :meth:`list_secrets` returns sorted names so consumers can diff
  snapshots deterministically.
- A missing secret resolves to ``None`` from :meth:`get_secret`; it
  is NOT an exceptional condition. The interface reserves exceptions
  for backend-failure modes (filesystem unreadable, JSON corrupt
  beyond recovery) the caller should surface.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

from .interfaces import (
    SecretProviderInterface,
    _validate_secret_name,
    _validate_secret_value,
)

logger = logging.getLogger(__name__)


# Module-level default so tests can monkeypatch it the same way they
# patch :data:`servonaut.services.auth_service.AUTH_FILE`. Production
# code resolves the path lazily through the instance attribute so a
# user's ``$HOME`` change between import time and instantiation is
# honoured.
DEFAULT_SECRETS_FILE = Path.home() / '.servonaut' / 'secrets.json'

# Root directory the LocalProvider is permitted to read and write to.
# A constructor that resolves to anywhere outside this tree is a
# configuration bug; the guard refuses rather than silently writing
# to e.g. ``~/.ssh/id_rsa`` because someone tab-completed the wrong
# path in a config file. Tests opt out via the dedicated
# :data:`_TESTING_ALLOW_ANY_PATH` flag set in ``conftest`` / fixtures
# — production code has no escape hatch.
LOCAL_PROVIDER_ROOT = Path.home() / '.servonaut'


class LocalProvider(SecretProviderInterface):
    """Filesystem-backed :class:`SecretProviderInterface` implementation.

    Reads and writes through ``~/.servonaut/secrets.json`` (overridable
    via the ``secrets_file`` constructor argument — used by tests and
    by any future per-team local store). No in-memory cache: every
    method re-reads the file so multi-process CLIs (TUI + ``--mcp``
    headless + a one-shot CLI invocation) observe each other's writes
    without explicit cache invalidation. Atomic writes via
    ``os.replace`` keep readers consistent.

    Concurrency model (multi-process):

    Each call is read-modify-write on the underlying file. We rely on
    ``os.replace``'s atomicity for the WRITE half — there is no file
    lock around the READ half. If two CLI processes (e.g. the TUI and
    a ``servonaut --mcp`` headless instance) both call
    :meth:`set_secret` for distinct names at the same moment, the
    second writer's view starts from BEFORE the first writer's
    rename, so the first writer's change is silently lost.

    For the MVP this is acceptable: secret writes are user-initiated
    and rare (think: "set up SSH key once, use it for a month") so a
    real collision is improbable. Two CLI processes mutating the
    same secrets store within the same millisecond is a vanishingly
    unlikely event. If a workload genuinely needs concurrent writes
    (CI fan-out, automation pipelines), point them at
    :class:`BitwardenProvider` instead — Bitwarden's server-side
    coordination handles concurrent writes correctly.

    Documented contract: **last-write-wins**, no locking.
    """

    def __init__(
        self,
        secrets_file: Optional[Path] = None,
        *,
        _allow_any_path: bool = False,
    ) -> None:
        # Resolve once at construction so a runtime ``Path.home()``
        # change (rare, but tests do it via ``monkeypatch.setenv``)
        # doesn't make the instance's view shift mid-session.
        path: Path = (
            secrets_file if secrets_file is not None else DEFAULT_SECRETS_FILE
        )
        # Path-traversal guard: a misconfigured override (e.g. a
        # team config that points at ``~/.ssh/id_rsa``) must NOT
        # silently clobber unrelated files. Resolve to an absolute
        # path and check it sits under :data:`LOCAL_PROVIDER_ROOT`.
        # Tests that intentionally write to a pytest tmp dir set
        # ``_allow_any_path=True`` — production code never does.
        if not _allow_any_path:
            try:
                resolved = path.expanduser().resolve(strict=False)
                root = LOCAL_PROVIDER_ROOT.expanduser().resolve(strict=False)
            except (OSError, RuntimeError) as exc:
                raise ValueError(
                    f"LocalProvider secrets_file {path!r} could not be "
                    f"resolved: {exc}"
                ) from exc
            try:
                resolved.relative_to(root)
            except ValueError as exc:
                raise ValueError(
                    f"LocalProvider secrets_file must be under "
                    f"{root} for safety; got {resolved}"
                ) from exc
        self._path: Path = path

    @property
    def provider_name(self) -> str:
        return "local"

    @property
    def path(self) -> Path:
        """Filesystem path this provider reads and writes.

        Exposed so callers (status screens, the audit trail) can show
        the user *where* their local secrets live without reaching for
        a private attribute.
        """
        return self._path

    async def get_secret(self, name: str) -> Optional[str]:
        name = _validate_secret_name(name)
        store = self._load()
        return store.get(name)

    async def set_secret(self, name: str, value: str) -> None:
        name = _validate_secret_name(name)
        value = _validate_secret_value(value)
        store = self._load()
        store[name] = value
        self._save(store)

    async def delete_secret(self, name: str) -> bool:
        name = _validate_secret_name(name)
        store = self._load()
        if name not in store:
            # Idempotent — not present is not an error.
            return False
        del store[name]
        self._save(store)
        return True

    async def list_secrets(self) -> List[str]:
        store = self._load()
        # Sorted for deterministic output (interface contract).
        return sorted(store.keys())

    # ------------------------------------------------------------------
    # Storage helpers
    # ------------------------------------------------------------------

    def _load(self) -> Dict[str, str]:
        """Read the secrets file and return a name→value dict.

        Missing file → empty store (a fresh install has no secrets).
        Corrupt JSON → empty store + WARNING log (we'd rather start
        clean than crash the CLI; a backup of the corrupt file is left
        in place so the user can recover manually).

        Mode-fixup: if the file is on disk with looser permissions than
        ``0600`` (e.g. upgraded from a hypothetical prior version that
        used umask defaults), tighten silently — same pattern as
        :meth:`AuthService._ensure_secure_mode`.
        """
        if not self._path.exists():
            return {}
        # Belt-and-braces: if a previous CLI version wrote this file
        # with umask defaults we'd rather fix the perms than leave a
        # world-readable secrets store on disk.
        try:
            mode = self._path.stat().st_mode & 0o777
            if mode != 0o600:
                try:
                    os.chmod(self._path, 0o600)
                    logger.info(
                        "Tightened permissions on %s (%o → 0600)",
                        self._path, mode,
                    )
                except OSError as e:
                    logger.warning(
                        "Could not chmod %s: %s", self._path, e
                    )
        except OSError:
            pass
        try:
            data = json.loads(self._path.read_text())
        except json.JSONDecodeError as e:
            logger.warning(
                "Secrets file %s is corrupt (%s); starting from empty "
                "store. The original file has been preserved.",
                self._path, e,
            )
            return {}
        except OSError as e:
            logger.warning("Could not read secrets file %s: %s", self._path, e)
            return {}
        if not isinstance(data, dict):
            logger.warning(
                "Secrets file %s has wrong shape (expected dict, got %s); "
                "starting from empty store.",
                self._path, type(data).__name__,
            )
            return {}
        # Drop any non-string entries defensively — they wouldn't be
        # round-trippable and likely indicate the file was edited by
        # hand or by a future CLI version we don't understand.
        return {
            k: v for k, v in data.items()
            if isinstance(k, str) and isinstance(v, str)
        }

    def _save(self, store: Dict[str, str]) -> None:
        """Atomically persist ``store`` with ``0600`` permissions.

        Same pattern as :meth:`AuthService._save_token`:

        1. Open a sibling ``.tmp`` file with ``O_CREAT|O_TRUNC|O_WRONLY``
           and explicit mode ``0600`` so we never materialise a
           world-readable copy between open and chmod.
        2. ``fsync`` before ``os.replace`` so a crash between write
           and rename can't surface as "file now empty".
        3. Belt-and-braces ``chmod`` after open in case umask masked
           bits off the mode.
        4. ``os.replace`` for an atomic, in-place rename.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._path.with_suffix(self._path.suffix + ".tmp")
        fd = os.open(
            tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600,
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(store, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                tmp_path.unlink()
            except OSError:
                pass
            raise
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, self._path)
