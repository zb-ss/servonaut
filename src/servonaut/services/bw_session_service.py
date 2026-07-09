"""Bitwarden CLI auth-state + vault discovery service.

The *discovery* half that :class:`servonaut.services.bw_resolver.BwResolver`
lacks: detect the ``bw`` auth state, unlock the vault (holding the session key
in memory for the app lifetime), ensure a dedicated "Servonaut" folder, and list
items so the user can browse-and-pick instead of pasting an item UUID.

Security invariants (match project conventions, mirror ``bitwarden_provider``):

- The master password and the session key are passed to ``bw`` via ``env=``
  only, **never on argv** (argv is world-readable via ``ps``). The session key
  is held in memory only and is redacted from every log line.
- Every subprocess call carries an explicit timeout.
- Read-only except the user-initiated vault writes (*create folder*,
  *create ssh-key item*, *sync*) — writes to the Bitwarden vault, not the
  local filesystem — acceptable per the design.
- Item payloads for ``bw create`` are piped via **stdin** (base64-encoded
  JSON), never placed on argv: the payload can carry a private key.
- Item summaries carry names / usernames / fingerprints only. The private-key
  body (``.sshKey.privateKey``) is **never** copied into a DTO.
"""

from __future__ import annotations

import asyncio
import base64
import enum
import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from servonaut.services.bw_errors import (
    BwCliMissingError,
    BwCreateError,
    BwListError,
    BwSessionMissingError,
    BwUnauthenticatedError,
    BwUnlockFailedError,
)

logger = logging.getLogger(__name__)

_BW_TIMEOUT_SECONDS: int = 20

# Bitwarden CipherType for native SSH-key items (introduced in BW 2023.10).
_SSH_KEY_ITEM_TYPE: int = 5

# Default folder we scope listings to. Overridable from settings.
DEFAULT_FOLDER_NAME: str = "Servonaut"

# Env var name we hand to ``bw unlock --passwordenv``. The value lives only in
# the spawned child's environment for the duration of the call — never on argv.
_MASTER_PW_ENV: str = "BW_MASTERPW"

# stderr fragments that mean "no usable session" (locked vault / logged out).
_LOCKED_STDERR_PHRASES: tuple[str, ...] = (
    "Vault is locked",
    "Mac failed",
    "Session key is invalid",
)
_UNAUTHENTICATED_STDERR_PHRASES: tuple[str, ...] = (
    "You are not logged in",
    "not logged in",
)
_BAD_PASSWORD_PHRASES: tuple[str, ...] = (
    "Invalid master password",
    "Username or password is incorrect",
)


class BwAuthState(enum.Enum):
    """The four Bitwarden CLI auth states the picker UX branches on."""

    NOT_INSTALLED = "not_installed"
    UNAUTHENTICATED = "unauthenticated"
    LOCKED = "locked"
    UNLOCKED = "unlocked"


@dataclass(frozen=True)
class BwItemSummary:
    """Lightweight, list-safe view of a Bitwarden item.

    Deliberately omits any secret material: an SSH item's private key
    (``.sshKey.privateKey``) is *never* carried here — only enough to render a
    pick list and produce the chosen ``item_id``.
    """

    id: str
    name: str
    type: int
    username: Optional[str] = None
    has_ssh_key: bool = False
    folder_id: Optional[str] = None
    fingerprint: Optional[str] = None


class BwSessionService:
    """``bw`` auth-state, in-memory session, and vault listing.

    Construct without arguments (purely local — shells out to the ``bw`` binary,
    no API client). The unlocked session is held in memory for the app lifetime;
    re-unlock on next launch (keyring "remember on this device" is a deferred
    follow-up).
    """

    def __init__(self, bw_binary: str = "bw") -> None:
        self._bw_binary = bw_binary
        self._session: Optional[str] = None

    # ------------------------------------------------------------------
    # subprocess plumbing
    # ------------------------------------------------------------------

    def _which(self) -> Optional[str]:
        """Return the resolved ``bw`` path, or ``None`` when not on PATH."""
        return shutil.which(self._bw_binary)

    def _assert_installed(self) -> None:
        if self._which() is None:
            raise BwCliMissingError(
                f"Bitwarden CLI ({self._bw_binary!r}) not found on PATH. "
                "Install it from https://bitwarden.com/help/cli/ and ensure it is on your PATH."
            )

    async def _run(
        self,
        args: List[str],
        *,
        env: Optional[dict] = None,
        input_text: Optional[str] = None,
        check_session: bool = False,
    ) -> "subprocess.CompletedProcess[str]":
        """Run ``bw`` off the event loop with a timeout.

        ``args`` are the arguments AFTER the binary (e.g. ``["status"]``).
        ``env`` overlays the process environment (used to inject the session /
        master password without touching argv). ``input_text`` is piped to the
        child's stdin — the only acceptable channel for item payloads, which
        may contain private-key material (argv is world-readable via ``ps``).
        """
        cmd = [self._bw_binary, *args]
        kwargs: dict = {
            "capture_output": True,
            "text": True,
            "timeout": _BW_TIMEOUT_SECONDS,
            "env": env if env is not None else dict(os.environ),
        }
        if input_text is not None:
            kwargs["input"] = input_text
        return await asyncio.to_thread(subprocess.run, cmd, **kwargs)

    def _session_env(self) -> dict:
        """Build an env carrying the in-memory ``BW_SESSION``, or raise if absent.

        Falls back to an ambient ``BW_SESSION`` (a user who unlocked + exported
        by hand) for back-compat. Raises :class:`BwSessionMissingError` when no
        session is available at all.
        """
        env = dict(os.environ)
        session = self._session or env.get("BW_SESSION")
        if not session:
            raise BwSessionMissingError(
                "Bitwarden vault is locked. Unlock it first (the picker will prompt you)."
            )
        env["BW_SESSION"] = session
        return env

    @staticmethod
    def _classify_session_error(stderr: str) -> None:
        """Raise the right exception for a locked / logged-out ``bw`` failure."""
        if any(p in stderr for p in _UNAUTHENTICATED_STDERR_PHRASES):
            raise BwUnauthenticatedError(
                "You are not logged in to Bitwarden. Run `bw login` in your terminal first."
            )
        if any(p in stderr for p in _LOCKED_STDERR_PHRASES):
            raise BwSessionMissingError(
                "Bitwarden vault is locked or the session expired. Unlock it and retry."
            )

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    async def status(self) -> BwAuthState:
        """Return the current Bitwarden CLI auth state.

        Maps ``bw status`` (``{"status": "unauthenticated"|"locked"|"unlocked"}``)
        onto :class:`BwAuthState`, gating on ``shutil.which`` first. Any
        unexpected failure is treated conservatively as ``UNAUTHENTICATED`` so
        the UX falls back to guidance rather than a half-open picker.

        The held in-memory session is injected into the child env (never argv):
        without ``BW_SESSION``, ``bw status`` reports ``locked`` even while a
        valid session exists, which would re-prompt for the master password on
        every status-gated action. Including it also validates the session — an
        expired one correctly reports ``locked`` again.
        """
        if self._which() is None:
            return BwAuthState.NOT_INSTALLED

        env: Optional[dict] = None
        if self._session:
            env = dict(os.environ)
            env["BW_SESSION"] = self._session

        try:
            result = await self._run(["status"], env=env)
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("bw status failed: %s", exc)
            return BwAuthState.UNAUTHENTICATED

        try:
            payload = json.loads(result.stdout or "{}")
            raw_state = payload.get("status", "")
        except (json.JSONDecodeError, AttributeError):
            logger.debug("bw status returned non-JSON output")
            return BwAuthState.UNAUTHENTICATED

        return {
            "unlocked": BwAuthState.UNLOCKED,
            "locked": BwAuthState.LOCKED,
            "unauthenticated": BwAuthState.UNAUTHENTICATED,
        }.get(raw_state, BwAuthState.UNAUTHENTICATED)

    async def unlock(self, master_password: str, remember: bool = False) -> None:
        """Unlock the vault and capture the session key into memory.

        Runs ``bw unlock --raw`` with the master password supplied via
        ``--passwordenv`` (env, never argv). On success, ``--raw`` prints only
        the session key, which we store for :meth:`session`.

        ``remember`` is reserved for the deferred keyring "remember on this
        device" path and is a no-op in v1 (kept in the signature so callers
        don't churn).
        """
        self._assert_installed()

        env = dict(os.environ)
        env[_MASTER_PW_ENV] = master_password
        try:
            result = await self._run(
                ["unlock", "--raw", "--passwordenv", _MASTER_PW_ENV],
                env=env,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise BwUnlockFailedError(f"Bitwarden unlock failed: {exc}") from exc

        stderr = result.stderr or ""
        if result.returncode != 0:
            self._classify_session_error(stderr)
            if any(p in stderr for p in _BAD_PASSWORD_PHRASES):
                raise BwUnlockFailedError("Invalid master password.")
            raise BwUnlockFailedError(
                "Bitwarden unlock failed. Check your master password and try again."
            )

        session = (result.stdout or "").strip()
        if not session:
            raise BwUnlockFailedError(
                "Bitwarden unlock returned no session key. Try again."
            )
        # NOTE: never log `session` — it is equivalent to vault access.
        self._session = session
        if remember:
            logger.debug("bw unlock: 'remember on this device' is not yet supported (v1).")

    def session(self) -> Optional[str]:
        """Return the in-memory session key (for env injection); never log it."""
        return self._session

    def is_unlocked(self) -> bool:
        """True when an in-memory session is held (cheap, no subprocess)."""
        return bool(self._session)

    def lock(self) -> None:
        """Drop the in-memory session (does not call ``bw lock``)."""
        self._session = None

    async def ensure_servonaut_folder(self, name: str = DEFAULT_FOLDER_NAME) -> str:
        """Return the id of the ``name`` folder, creating it if absent. Idempotent.

        Lists folders via ``bw list folders``; on a miss, creates the folder by
        feeding the base64-encoded JSON object to ``bw create folder`` on stdin
        (equivalent to ``echo '{"name": ...}' | bw encode | bw create folder``).
        """
        self._assert_installed()
        env = self._session_env()

        try:
            result = await self._run(["list", "folders"], env=env)
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise BwListError(f"Could not list Bitwarden folders: {exc}") from exc

        stderr = result.stderr or ""
        if result.returncode != 0:
            self._classify_session_error(stderr)
            raise BwListError("Could not list Bitwarden folders.")

        try:
            folders = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise BwListError(f"Bitwarden returned malformed folder data: {exc}") from exc

        for folder in folders:
            if isinstance(folder, dict) and folder.get("name") == name and folder.get("id"):
                return str(folder["id"])

        return await self._create_folder(name, env)

    async def _create_folder(self, name: str, env: dict) -> str:
        """Create a vault folder named ``name`` and return its id.

        The base64-encoded JSON payload is piped via stdin (same mechanism as
        :meth:`create_ssh_key_item`), never placed on argv.
        """
        encoded = base64.b64encode(json.dumps({"name": name}).encode()).decode()
        try:
            result = await self._run(
                ["create", "folder"], env=env, input_text=encoded
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise BwListError(f"Could not create the {name!r} folder: {exc}") from exc

        if result.returncode != 0:
            self._classify_session_error(result.stderr or "")
            raise BwListError(f"Could not create the {name!r} Bitwarden folder.")

        try:
            created = json.loads(result.stdout or "{}")
            folder_id = created["id"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise BwListError(
                f"Bitwarden did not return an id for the new {name!r} folder."
            ) from exc
        return str(folder_id)

    async def create_ssh_key_item(
        self,
        name: str,
        private_key: str,
        public_key: str,
        key_fingerprint: str,
        folder_id: Optional[str] = None,
    ) -> str:
        """Create a native SSH-key item (type 5) in the vault; return its id.

        The item JSON — which carries the private key — is base64-encoded and
        piped to ``bw create item`` via **stdin only**. It never touches argv,
        any log line, an exception message, or the local filesystem.
        """
        self._assert_installed()
        env = self._session_env()

        item = {
            "type": _SSH_KEY_ITEM_TYPE,
            "name": name,
            "notes": None,
            "folderId": folder_id,
            "sshKey": {
                "privateKey": private_key,
                "publicKey": public_key,
                "keyFingerprint": key_fingerprint,
            },
        }
        encoded = base64.b64encode(json.dumps(item).encode()).decode()

        try:
            result = await self._run(
                ["create", "item"], env=env, input_text=encoded
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            # NOTE: exc for TimeoutExpired/OSError never echoes stdin content.
            raise BwCreateError(f"Could not create the Bitwarden item: {exc}") from exc

        stderr = result.stderr or ""
        if result.returncode != 0:
            self._classify_session_error(stderr)
            # Defense-in-depth: this is the one code path whose stdin payload
            # carries a decrypted private key, and "bw never echoes stdin on
            # stderr" is a behavioral observation, not a contract. Only
            # classified known phrases surface (above); everything else gets a
            # fixed generic message — raw stderr is never excerpted into the
            # exception (it would flow into notify() and str(exc) in logs).
            raise BwCreateError(
                f"Could not create the Bitwarden item (bw exited with code "
                f"{result.returncode})."
            )

        try:
            created = json.loads(result.stdout or "{}")
            item_id = created["id"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise BwCreateError(
                "Bitwarden did not return an id for the new item."
            ) from exc
        return str(item_id)

    async def sync_now(self) -> None:
        """Best-effort ``bw sync`` so the new item shows up across devices.

        Purely an optimization — every failure (locked session, network,
        timeout) is swallowed with a debug log; correctness never depends on it.
        """
        try:
            env = self._session_env()
            result = await self._run(["sync"], env=env)
            if result.returncode != 0:
                logger.debug("bw sync failed (rc=%s); ignoring.", result.returncode)
        except Exception as exc:  # noqa: BLE001 - best-effort by design
            logger.debug("bw sync failed: %s; ignoring.", exc)

    async def list_items(
        self,
        folder_id: Optional[str] = None,
        search: Optional[str] = None,
        ssh_only: bool = True,
    ) -> List[BwItemSummary]:
        """List vault items as secret-free :class:`BwItemSummary` DTOs.

        Runs ``bw list items [--folderid id] [--search q]``. When ``ssh_only``
        (the default), only native SSH-key items are returned. The private-key
        body is never read into the summary.
        """
        self._assert_installed()
        env = self._session_env()

        args = ["list", "items"]
        if folder_id:
            args += ["--folderid", folder_id]
        if search:
            args += ["--search", search]

        try:
            result = await self._run(args, env=env)
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise BwListError(f"Could not list Bitwarden items: {exc}") from exc

        stderr = result.stderr or ""
        if result.returncode != 0:
            self._classify_session_error(stderr)
            raise BwListError("Could not list Bitwarden items.")

        try:
            items = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise BwListError(f"Bitwarden returned malformed item data: {exc}") from exc

        summaries: List[BwItemSummary] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            summary = self._to_summary(item)
            if ssh_only and not summary.has_ssh_key:
                continue
            summaries.append(summary)
        return summaries

    @staticmethod
    def _to_summary(item: dict) -> BwItemSummary:
        """Map a raw ``bw`` item dict to a secret-free summary DTO."""
        item_type = item.get("type")
        ssh_key = item.get("sshKey")
        has_ssh_key = item_type == _SSH_KEY_ITEM_TYPE or isinstance(ssh_key, dict)

        login = item.get("login")
        username = login.get("username") if isinstance(login, dict) else None

        # The fingerprint is a public hash — safe in a summary. The private-key
        # body is deliberately never read out of ``sshKey``.
        fingerprint: Optional[str] = None
        if isinstance(ssh_key, dict):
            raw_fingerprint = ssh_key.get("keyFingerprint")
            if isinstance(raw_fingerprint, str) and raw_fingerprint:
                fingerprint = raw_fingerprint

        return BwItemSummary(
            id=str(item.get("id", "")),
            name=str(item.get("name", "")),
            type=int(item_type) if isinstance(item_type, int) else 0,
            username=username,
            has_ssh_key=has_ssh_key,
            folder_id=item.get("folderId"),
            fingerprint=fingerprint,
        )
