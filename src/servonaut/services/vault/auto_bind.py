"""Bind vault SSH keys to the servers they are named after.

A server is matched to the vault key named like its cloud key pair (an AWS
instance's ``key_name``, the key it was launched with; a custom server's key
file) or, failing that, like the server itself. Names compare without case and without a key-file
extension, so ``web-1.pem`` matches a server called ``Web-1``. Two different
keys with the same name are ambiguous and left for the user to choose; the
same key imported twice is not.

Binding still pins host keys this machine already trusts (from earlier SSH
connections), never keys fetched for the occasion, and a server that already
has a vault key is left alone.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Optional

from servonaut.services.ssh_host_keys import trusted_host_keys

from .errors import vault_failure_reason
from .personal_targets import instance_provider

# Extensions a private key file commonly carries; the key's name is the rest.
_KEY_FILE_SUFFIXES = (".pem", ".key", ".ppk", ".openssh", ".priv")

# Signed binding reads run a few at a time.
_BINDING_READS = 6

MATCHED_BY_KEY_PAIR = "key pair"
MATCHED_BY_KEY_FILE = "key file"  # a custom server's own key file
MATCHED_BY_SERVER_NAME = "server name"

# Row states, in the order the review lists them.
READY = "ready"
ALREADY_BOUND = "bound"
AMBIGUOUS = "ambiguous"
NO_HOST_KEYS = "no_host_keys"
NO_ADDRESS = "no_address"
NO_LOGIN = "no_login"
NO_KEY = "no_key"
CHECK_FAILED = "check_failed"

# Why a row cannot be bound, in the user's terms.
STATUS_TEXT = {
    READY: "Ready to bind",
    ALREADY_BOUND: "Already has a vault key: change it with Use Vault Key",
    AMBIGUOUS: "Several different keys have this name: choose one with Use Vault Key",
    NO_HOST_KEYS: "No trusted host key yet: connect once with SSH and check its fingerprint",
    NO_ADDRESS: "No address to connect to",
    NO_LOGIN: "No login user: set one in a connection rule or the default username",
    NO_KEY: "No vault key with this server's key pair or name",
    CHECK_FAILED: "Could not check this server's vault key",
}


# The same, short enough for a table column.
STATUS_LABEL = {
    READY: "ready",
    ALREADY_BOUND: "has a vault key",
    AMBIGUOUS: "name is ambiguous",
    NO_HOST_KEYS: "no trusted host key",
    NO_ADDRESS: "no address",
    NO_LOGIN: "no login user",
    NO_KEY: "no matching key",
    CHECK_FAILED: "check failed",
}


def normalize_key_name(name: str) -> str:
    """*name* as it is compared: lower case, without a directory or key-file extension."""
    text = name.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in _KEY_FILE_SUFFIXES:
        if text.endswith(suffix) and len(text) > len(suffix):
            return text[: -len(suffix)]
    return text


@dataclass(frozen=True)
class KeyMatch:
    """The vault key found for a server, or an ambiguous name (``item_id`` is ``None``)."""

    item_id: Optional[str]
    name: str
    matched_by: str

    @property
    def ambiguous(self) -> bool:
        return self.item_id is None


def match_ssh_key(instance: Mapping[str, Any], keys: Iterable[Mapping[str, Any]]) -> Optional[KeyMatch]:
    """The vault key named like *instance*'s key pair, else like the server.

    *keys* are ``ssh_key_choices`` rows: ``item_id``, ``name`` (``None`` when
    unknown) and ``fingerprint``.
    """
    named = [key for key in keys if isinstance(key.get("name"), str) and key["name"].strip()]
    # A custom server's key_name is the key file it is set up with.
    by_key = MATCHED_BY_KEY_FILE if instance.get("is_custom") is True else MATCHED_BY_KEY_PAIR
    for matched_by, wanted in (
        (by_key, instance.get("key_name")),
        (MATCHED_BY_SERVER_NAME, instance.get("name")),
    ):
        if not isinstance(wanted, str) or not wanted.strip():
            continue
        target = normalize_key_name(wanted)
        hits = sorted(
            (key for key in named if normalize_key_name(key["name"]) == target),
            key=lambda key: str(key["item_id"]),
        )
        if not hits:
            continue
        if len({key.get("fingerprint") or key["item_id"] for key in hits}) > 1:
            return KeyMatch(None, str(hits[0]["name"]), matched_by)
        return KeyMatch(str(hits[0]["item_id"]), str(hits[0]["name"]), matched_by)
    return None


@dataclass
class AutoBindRow:
    """One server in an auto-bind review."""

    # The server's record as given (not a copy), so a caller can map rows back.
    instance: Mapping[str, Any]
    status: str
    match: Optional[KeyMatch] = None
    host: Optional[str] = None
    port: int = 22
    login: Optional[str] = None
    host_keys: list[str] = field(default_factory=list)
    # After binding: None (not tried), "bound", or the failure reason.
    result: Optional[str] = None

    @property
    def ready(self) -> bool:
        return self.status == READY

    @property
    def status_label(self) -> str:
        if self.result == "bound":
            return "bound"
        if self.result is not None:
            return "binding failed"
        return STATUS_LABEL[self.status]

    @property
    def status_text(self) -> str:
        if self.result == "bound":
            return "Bound"
        if self.result is not None:
            return f"Binding failed ({self.result})"
        return STATUS_TEXT[self.status]


def is_personal_server(instance: Mapping[str, Any]) -> bool:
    """Whether *instance* is one of the user's own servers (not a team's)."""
    if instance.get("is_shared") is True:
        return False
    return instance.get("is_custom") is True or instance_provider(instance).lower() in {"aws", "ovh", "hetzner"}


async def plan_auto_bind(
    service: Any,
    instances: Sequence[Mapping[str, Any]],
    keys: Sequence[Mapping[str, Any]],
    *,
    host_keys_for: Callable[[Mapping[str, Any], str, Optional[int]], list[str]] | None = None,
) -> list[AutoBindRow]:
    """Review rows for *instances*: which key each would get, and why not when it can't.

    *service* is the ``VaultCommandService``. A server is checked for an
    existing binding only once it has a key, an address and a login; its
    trusted host keys (by default, those in this computer's known_hosts
    files) are read off the event loop.
    """
    read_host_keys = host_keys_for or trusted_host_keys
    rows = [_row(service, instance, keys) for instance in instances if is_personal_server(instance)]
    gate = asyncio.Semaphore(_BINDING_READS)

    async def check(row: AutoBindRow) -> None:
        if row.status != READY:
            return
        async with gate:
            try:
                binding = await service.personal_binding(row.instance)
            except Exception:  # shown on the row; the other servers still get their answer
                row.status = CHECK_FAILED
                return
        if binding is not None:
            row.status = ALREADY_BOUND
            return
        port = row.port if row.port != 22 else None
        row.host_keys = await asyncio.to_thread(read_host_keys, row.instance, str(row.host), port)
        if not row.host_keys:
            row.status = NO_HOST_KEYS

    await asyncio.gather(*(check(row) for row in rows))
    order = (READY, ALREADY_BOUND, AMBIGUOUS, NO_HOST_KEYS, NO_ADDRESS, NO_LOGIN, CHECK_FAILED, NO_KEY)
    return sorted(rows, key=lambda row: (order.index(row.status), str(row.instance.get("name") or "").lower()))


def _row(service: Any, instance: Mapping[str, Any], keys: Sequence[Mapping[str, Any]]) -> AutoBindRow:
    match = match_ssh_key(instance, keys)
    host, port = service.ssh_destination(instance)
    row = AutoBindRow(instance=instance, status=READY, match=match, port=port if isinstance(port, int) else 22)
    if match is None:
        row.status = NO_KEY
    elif match.ambiguous:
        row.status = AMBIGUOUS
    elif not isinstance(host, str) or not host:
        row.status = NO_ADDRESS
    else:
        row.host = host
        row.login = service.ssh_login(instance)
        if not row.login:
            row.status = NO_LOGIN
    return row


async def apply_auto_bind(
    service: Any,
    rows: Sequence[AutoBindRow],
    *,
    vault_id: str,
    on_progress: Callable[[int, AutoBindRow], None] | None = None,
) -> None:
    """Bind each ready row in turn, recording ``"bound"`` or the failure reason.

    A server that gained a vault key since the review is not replaced.
    """
    for index, row in enumerate(rows):
        if not row.ready or row.match is None or row.match.item_id is None:
            continue
        if on_progress is not None:
            on_progress(index, row)
        custom = row.instance.get("is_custom") is True
        try:
            await service.bind_personal(
                vault_id=vault_id,
                item_id=row.match.item_id,
                provider=instance_provider(row.instance),
                instance_id=str(row.instance.get("name") or "") if custom else str(row.instance.get("id") or ""),
                hostname=str(row.host),
                port=row.port,
                login=str(row.login),
                host_keys=list(row.host_keys),
                replace_existing=False,
            )
        except Exception as exc:  # one server's failure does not stop the others
            row.result = vault_failure_reason(exc)
        else:
            row.result = "bound"


__all__ = [
    "AutoBindRow", "KeyMatch", "MATCHED_BY_KEY_FILE", "MATCHED_BY_KEY_PAIR", "MATCHED_BY_SERVER_NAME",
    "apply_auto_bind", "is_personal_server", "match_ssh_key", "normalize_key_name", "plan_auto_bind",
]
