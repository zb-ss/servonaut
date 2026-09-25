"""A fake Bitwarden for journeys: the ``bws`` and ``bw`` CLIs and their vault.

:class:`FakeBitwarden` installs the fake tools a journey asks for into its
shim directory (they stay off ``PATH`` otherwise) and holds the vault they
answer from::

    vault = FakeBitwarden(journey.shims, tools=("bws",))
    project = vault.add_project("servers")
    vault.add_secret(project, "db/web-1", "fabricated-value")

Secrets Manager (``bws``) holds projects and secrets behind an access token;
the Password Manager (``bw``) holds SSH-key items behind a master password
and a session. Every token, password, id and key here is fabricated at run
time: nothing reaches a real Bitwarden, and nothing secret-shaped is
committed. Each one is registered for redaction from failure artifacts. The
calls are recorded in the shim log (``ShimSet.calls``) with secret arguments
as digests (see :func:`e2e.harness.bitwarden_shim.digest`) and the
credential variables each call saw, by name only.
"""

from __future__ import annotations

import datetime as dt
import fcntl
import json
import secrets
import uuid
from contextlib import contextmanager
from typing import Any, Iterator, Optional, Sequence

from e2e.harness.artifacts import register_secret
from e2e.harness.bootstrap import HARNESS_DIR
from e2e.harness.shims import ShimSet

RUNNER = HARNESS_DIR / "bitwarden_shim.py"
STATE_FILE = "bitwarden.json"
TOOLS = ("bws", "bw")


def fabricated_ssh_key() -> tuple[str, str]:
    """A (private, public) pair shaped like an OpenSSH key, but not one.

    The markers are assembled at run time so no key-shaped literal is
    committed; the body is random text no SSH client would accept.
    """
    marker = "OPENSSH " + "PRIVATE KEY"
    body = secrets.token_urlsafe(48)
    private = f"-----BEGIN {marker}-----\n{body}\n-----END {marker}-----\n"
    public = f"ssh-ed25519 {secrets.token_urlsafe(32)} e2e-fabricated"
    return private, public


class FakeBitwarden:
    """The vault behind the fake ``bws``/``bw`` tools of one journey."""

    def __init__(self, shims: ShimSet, *, tools: Sequence[str] = TOOLS) -> None:
        unknown = set(tools) - set(TOOLS)
        if unknown:
            raise ValueError(f"unknown Bitwarden tools: {sorted(unknown)}")
        self._shims = shims
        self._path = shims.directory / STATE_FILE
        # Fabricated credentials, new for every journey.
        self.access_token = f"bws-fake-{secrets.token_hex(8)}"
        self.master_password = f"bw-fake-{secrets.token_hex(8)}"
        self.session = f"bw-session-fake-{secrets.token_hex(8)}"
        register_secret(self.access_token, self.master_password, self.session)
        self._path.write_text(
            json.dumps(
                {
                    "bws": {
                        "token": self.access_token,
                        "organization_id": str(uuid.uuid4()),
                        "projects": [],
                        "secrets": [],
                    },
                    "bw": {
                        "password": self.master_password,
                        "session": self.session,
                        "items": [],
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        for tool in tools:
            shims.install(tool, RUNNER)

    def calls(self, tool: str) -> list[Any]:
        """Recorded calls to one fake tool (``ShimCall``s, oldest first)."""
        return self._shims.calls(tool)

    @contextmanager
    def _state(self) -> Iterator[dict[str, Any]]:
        with self._path.open("r+", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                state = json.load(handle)
                yield state
                handle.seek(0)
                handle.truncate()
                json.dump(state, handle, indent=2)
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    # ------------------------------------------------------------------
    # Secrets Manager (bws)
    # ------------------------------------------------------------------

    def add_project(self, name: str) -> str:
        """Create a project the access token can see; return its id."""
        project_id = str(uuid.uuid4())
        with self._state() as state:
            state["bws"]["projects"].append(
                {
                    "object": "project",
                    "id": project_id,
                    "organizationId": state["bws"]["organization_id"],
                    "name": name,
                    "creationDate": _now(),
                    "revisionDate": _now(),
                }
            )
        return project_id

    def add_secret(self, project_id: str, key: str, value: str) -> str:
        """Store a secret in *project_id*; return its id."""
        register_secret(value)
        secret_id = str(uuid.uuid4())
        with self._state() as state:
            state["bws"]["secrets"].append(
                {
                    "object": "secret",
                    "id": secret_id,
                    "organizationId": state["bws"]["organization_id"],
                    "projectId": project_id,
                    "key": key,
                    "value": value,
                    "note": "",
                    "creationDate": _now(),
                    "revisionDate": _now(),
                }
            )
        return secret_id

    def secrets(self, project_id: Optional[str] = None) -> dict[str, str]:
        """The stored secrets as ``{key: value}``, optionally for one project."""
        with self._state() as state:
            rows = list(state["bws"]["secrets"])
        return {
            row["key"]: row["value"]
            for row in rows
            if project_id is None or row["projectId"] == project_id
        }

    # ------------------------------------------------------------------
    # Password Manager (bw)
    # ------------------------------------------------------------------

    def add_ssh_key_item(self, name: str, private_key: str, public_key: str) -> str:
        """Store a native SSH-key item (the 2023.10+ shape); return its id."""
        register_secret(private_key)
        item_id = str(uuid.uuid4())
        with self._state() as state:
            state["bw"]["items"].append(
                {
                    "object": "item",
                    "id": item_id,
                    "organizationId": None,
                    "folderId": None,
                    "type": 5,
                    "name": name,
                    "notes": None,
                    "favorite": False,
                    "sshKey": {
                        "privateKey": private_key,
                        "publicKey": public_key,
                        "keyFingerprint": "SHA256:" + secrets.token_urlsafe(32),
                    },
                    "collectionIds": [],
                    "revisionDate": _now(),
                }
            )
        return item_id


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
