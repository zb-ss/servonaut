"""Bind vault SSH keys to the servers they are named after.

A server with a key file set for it (``instance_keys``, the key its own SSH
connection uses) is matched to that key first: by the file's public-key
fingerprint, else by the file's name. Otherwise, or when that key is not in
the vault, it is matched to the vault key named like its cloud key pair (an AWS
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
import logging
import tempfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from servonaut.services.shared_servers import is_same_server, is_shared_row
from servonaut.services.ssh_host_keys import ensure_known_hosts_file, read_host_keys_from_file, trusted_host_keys

from .ec2_host_keys import (
    EC2ConsoleHostKeys,
    fetch_ec2_console_output_sync,
    parse_ec2_console_output,
    verify_fetched_host_keys,
)
from .errors import vault_failure_reason
from .personal_targets import instance_provider

logger = logging.getLogger(__name__)

# Extensions a private key file commonly carries; the key's name is the rest.
_KEY_FILE_SUFFIXES = (".pem", ".key", ".ppk", ".openssh", ".priv")

# Signed binding reads run a few at a time.
_BINDING_READS = 6

# Host key visits run a few at a time.
_HOST_KEY_VISITS = 4

# A private key file larger than this is not read: no SSH key is that big.
_KEY_FILE_MAX_BYTES = 64 * 1024

MATCHED_BY_CONFIGURED_KEY = "configured key file"  # the key file set for the server (instance_keys)
MATCHED_BY_KEY_PAIR = "key pair"
MATCHED_BY_KEY_FILE = "key file"  # a custom server's own key file
MATCHED_BY_SERVER_NAME = "server name"

# Where a row's login comes from.
LOGIN_FROM_SHARE = "team share"  # the login the team's shared server names
LOGIN_FROM_SERVER = "server"  # the server's own record (a custom server's username)
LOGIN_FROM_RULE = "connection rule"
LOGIN_FROM_ACCOUNT = "account defaults"  # an OVH account's SSH defaults
LOGIN_FROM_DEFAULT = "default username"  # only the configured default (or root)

# Row states, in the order the review lists them.
READY = "ready"
FETCHED = "fetched"
ALREADY_BOUND = "bound"
AMBIGUOUS = "ambiguous"
NO_HOST_KEYS = "no_host_keys"
FETCH_FAILED = "fetch_failed"
HOST_KEY_MISMATCH = "host_key_mismatch"
NO_ADDRESS = "no_address"
NO_LOGIN = "no_login"
NO_KEY = "no_key"
CHECK_FAILED = "check_failed"

# Why a row cannot be bound, in the user's terms.
STATUS_TEXT = {
    READY: "Ready to bind",
    FETCHED: "Fetched host key: check fingerprint before binding",
    ALREADY_BOUND: "Already has a vault key: change it with Use Vault Key",
    AMBIGUOUS: "Several different keys have this name: choose one with Use Vault Key",
    NO_HOST_KEYS: "No trusted host key yet: run with --fetch-host-keys to fetch and review it",
    FETCH_FAILED: "Could not fetch host key",
    HOST_KEY_MISMATCH: "Host key differs from AWS first-boot key: do not bind",
    NO_ADDRESS: "No address to connect to",
    NO_LOGIN: "No login user: set one in a connection rule or the default username",
    NO_KEY: "No vault key with this server's key pair or name",
    CHECK_FAILED: "Could not check this server's vault key",
}


# The same, short enough for a table column.
STATUS_LABEL = {
    READY: "ready",
    FETCHED: "fetched: check fingerprint",
    ALREADY_BOUND: "has a vault key",
    AMBIGUOUS: "name is ambiguous",
    NO_HOST_KEYS: "no trusted host key",
    FETCH_FAILED: "could not fetch host key",
    HOST_KEY_MISMATCH: "host key differs from AWS",
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


@dataclass(frozen=True)
class ConfiguredKey:
    """The key file set for a server (``instance_keys``): its file name and, when readable, fingerprint."""

    name: str
    fingerprint: Optional[str] = None


def key_file_fingerprint(path: Path) -> Optional[str]:
    """The SHA256 fingerprint of the SSH key in *path*; None when it cannot be read.

    The key's ``.pub`` file is read first, else the private key when it is not
    passphrase-protected (OpenSSH or PEM format). Nothing read is kept.
    """
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_private_key,
        load_ssh_private_key,
    )

    from .crypto import ssh_public_fingerprint

    public = path.with_name(path.name + ".pub")
    try:
        if public.is_file() and public.stat().st_size <= _KEY_FILE_MAX_BYTES:
            return ssh_public_fingerprint(public.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        pass  # an unreadable .pub: the private key may still say
    try:
        if path.stat().st_size > _KEY_FILE_MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    for load in (load_ssh_private_key, load_pem_private_key):
        try:
            key = load(data, password=None)
            line = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
            return ssh_public_fingerprint(line)
        except (TypeError, ValueError, UnsupportedAlgorithm, AttributeError):
            continue  # not this format, or protected by a passphrase
    return None


def _mapped_key_path(service: Any, instance: Mapping[str, Any]) -> Optional[str]:
    """The key file the user set for *instance* (``instance_keys``), as configured."""
    instance_keys = getattr(getattr(service, "config", None), "instance_keys", None)
    if not isinstance(instance_keys, Mapping):
        return None
    path = instance_keys.get(str(instance.get("id") or ""))
    return path.strip() if isinstance(path, str) and path.strip() else None


def configured_key(service: Any, instance: Optional[Mapping[str, Any]]) -> Optional[ConfiguredKey]:
    """The key file set for *instance* when that file exists; None otherwise.

    A custom server's own key file is matched by its name already
    (``MATCHED_BY_KEY_FILE``).
    """
    if instance is None or instance.get("is_custom") is True:
        return None
    raw = _mapped_key_path(service, instance)
    if raw is None:
        return None
    path = Path(raw).expanduser()
    if not path.is_file():
        return None
    return ConfiguredKey(path.name, key_file_fingerprint(path))


def match_ssh_key(
    instance: Mapping[str, Any],
    keys: Iterable[Mapping[str, Any]],
    *,
    own_instance: Optional[Mapping[str, Any]] = None,
    configured: Optional[ConfiguredKey] = None,
) -> Optional[KeyMatch]:
    """The vault key set for the server, else the one named like *instance*'s key pair, else like the server.

    *keys* are ``ssh_key_choices`` rows: ``item_id``, ``name`` (``None`` when
    unknown) and ``fingerprint``. *configured* (the key file set for the
    server) is matched first: by its fingerprint, else by its file name.
    When *own_instance* is given, its key-pair name (or key file if custom)
    and server name are checked next.
    """
    keys = list(keys)
    if configured is not None and configured.fingerprint is not None:
        same = sorted(
            (key for key in keys if key.get("fingerprint") == configured.fingerprint),
            key=lambda key: str(key["item_id"]),
        )
        if same:
            key = same[0]
            return KeyMatch(str(key["item_id"]), str(key.get("name") or configured.name), MATCHED_BY_CONFIGURED_KEY)
    named = [key for key in keys if isinstance(key.get("name"), str) and key["name"].strip()]
    candidates: list[tuple[str, Any]] = []
    if configured is not None and configured.fingerprint is None:
        candidates.append((MATCHED_BY_CONFIGURED_KEY, configured.name))
    if own_instance is not None:
        by_key = MATCHED_BY_KEY_FILE if own_instance.get("is_custom") is True else MATCHED_BY_KEY_PAIR
        candidates.append((by_key, own_instance.get("key_name")))
        candidates.append((MATCHED_BY_SERVER_NAME, own_instance.get("name")))
    else:
        by_key = MATCHED_BY_KEY_FILE if instance.get("is_custom") is True else MATCHED_BY_KEY_PAIR
        candidates.append((by_key, instance.get("key_name")))
    candidates.append((MATCHED_BY_SERVER_NAME, instance.get("name")))

    for matched_by, wanted in candidates:
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
    # One of the LOGIN_FROM_* values; None when unknown.
    login_source: Optional[str] = None
    host_keys: list[str] = field(default_factory=list)
    verified: bool = False
    verification_source: Optional[str] = None
    fetch_error: Optional[str] = None
    mismatch_detail: Optional[str] = None
    team: Optional[str] = None
    own_instance: Optional[Mapping[str, Any]] = None
    # After binding: None (not tried), "bound", or the failure reason.
    result: Optional[str] = None
    skipped: Optional[str] = None
    binding_result: Optional[Mapping[str, Any]] = None
    # What the user should know before binding (shown with the row).
    notes: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return self.status in {READY, FETCHED}

    @property
    def status_label(self) -> str:
        if self.result == "bound":
            return "bound"
        if self.result is not None:
            return "binding failed"
        if self.status == ALREADY_BOUND and self.team:
            return "has a team key"
        return STATUS_LABEL.get(self.status, self.status)

    def status_text_for(self, surface: str = "cli") -> str:
        if self.result == "bound":
            return "Bound"
        if self.result is not None:
            return f"Binding failed ({self.result})"
        if self.status == FETCH_FAILED and self.fetch_error:
            return f"Could not fetch host key: {self.fetch_error}"
        if self.status == HOST_KEY_MISMATCH and self.mismatch_detail:
            return self.mismatch_detail
        if self.status == ALREADY_BOUND and self.team:
            return "Already has a team key: team keys are never replaced automatically."
        if self.status == NO_LOGIN and self.team:
            return "No login user: set the login on the shared server (Teams → Shared Servers)."
        if self.status == NO_HOST_KEYS:
            if surface == "tui":
                return "No trusted host key yet: press f (Fetch host keys) to fetch and review it"
            return "No trusted host key yet: run with --fetch-host-keys to fetch and review it"
        return STATUS_TEXT.get(self.status, self.status)

    @property
    def status_text(self) -> str:
        return self.status_text_for("cli")


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
    team: Optional[str] = None,
    host_keys_for: Callable[[Mapping[str, Any], str, Optional[int]], list[str]] | None = None,
) -> list[AutoBindRow]:
    """Review rows for *instances*: which key each would get, and why not when it can't.

    *service* is the ``VaultCommandService``. A server is checked for an
    existing binding only once it has a key, an address and a login; its
    trusted host keys (by default, those in this computer's known_hosts
    files) are read off the event loop.
    """
    read_host_keys = host_keys_for or trusted_host_keys

    if team is None:
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
    else:
        own_instances = [inst for inst in instances if not is_shared_row(inst)]
        shared_instances = [
            inst for inst in instances
            if is_shared_row(inst) and inst.get("team_slug") == team
        ]
        rows = []
        for shared in shared_instances:
            matching_own = next((own for own in own_instances if is_same_server(shared, own)), None)
            rows.append(_team_row(service, shared, keys, team=team, own_instance=matching_own))

        async def check_team(row: AutoBindRow) -> None:
            if row.status != READY:
                return
            port = row.port if row.port != 22 else None
            found_keys = await asyncio.to_thread(read_host_keys, row.instance, str(row.host), port)
            if not found_keys and row.own_instance:
                found_keys = await asyncio.to_thread(read_host_keys, row.own_instance, str(row.host), port)
            row.host_keys = found_keys
            if not row.host_keys:
                row.status = NO_HOST_KEYS

        await asyncio.gather(*(check_team(row) for row in rows))

    order = (
        READY, FETCHED, ALREADY_BOUND, AMBIGUOUS, NO_HOST_KEYS,
        FETCH_FAILED, HOST_KEY_MISMATCH, NO_ADDRESS, NO_LOGIN, CHECK_FAILED, NO_KEY,
    )
    return sorted(rows, key=lambda row: (order.index(row.status), str(row.instance.get("name") or "").lower()))


def _configured_key_note(configured: Optional[ConfiguredKey], match: Optional[KeyMatch]) -> Optional[str]:
    """Why the key file set for the server was not the match, when it was readable and not."""
    if configured is None or configured.fingerprint is None:
        return None
    if match is not None and match.matched_by == MATCHED_BY_CONFIGURED_KEY:
        return None
    note = f"The key file set for this server ({configured.name}) is not in this vault"
    if match is None or match.ambiguous:
        return f"{note}: import it, or choose a key with Use Vault Key."
    return f"{note}: this key was matched by its {match.matched_by} instead. Check that it logs in."


def _login_and_source(service: Any, instance: Mapping[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """``service.ssh_login_source(instance)``; the login alone from a service without it."""
    with_source = getattr(service, "ssh_login_source", None)
    if callable(with_source):
        login, source = with_source(instance)
    else:
        login, source = service.ssh_login(instance), None
    return (login.strip(), source) if isinstance(login, str) and login.strip() else (None, None)


def _default_login_note(row: AutoBindRow, *, team: bool) -> Optional[str]:
    """A warning when the row's login is only the default username."""
    if row.login_source != LOGIN_FROM_DEFAULT or not row.login or row.match is None or row.match.ambiguous:
        return None
    where = "a connection rule or on the team's shared server" if team else "a connection rule"
    return (
        f"The login {row.login} is only the default username: if this server's system uses "
        f"another login (ubuntu, ec2-user, admin...), set it in {where} before binding."
    )


def _row(service: Any, instance: Mapping[str, Any], keys: Sequence[Mapping[str, Any]]) -> AutoBindRow:
    configured = configured_key(service, instance)
    match = match_ssh_key(instance, keys, configured=configured)
    host, port = service.ssh_destination(instance)
    row = AutoBindRow(instance=instance, status=READY, match=match, port=port if isinstance(port, int) else 22)
    note = _configured_key_note(configured, match)
    if note:
        row.notes.append(note)
    if match is None:
        row.status = NO_KEY
    elif match.ambiguous:
        row.status = AMBIGUOUS
    elif not isinstance(host, str) or not host:
        row.status = NO_ADDRESS
    else:
        row.host = host
        row.login, row.login_source = _login_and_source(service, instance)
        if not row.login:
            row.status = NO_LOGIN
    note = _default_login_note(row, team=False)
    if note:
        row.notes.append(note)
    return row


def _team_row(
    service: Any,
    shared: Mapping[str, Any],
    keys: Sequence[Mapping[str, Any]],
    *,
    team: str,
    own_instance: Optional[Mapping[str, Any]] = None,
) -> AutoBindRow:
    configured = configured_key(service, own_instance) or configured_key(service, shared)
    match = match_ssh_key(shared, keys, own_instance=own_instance, configured=configured)
    host = str(shared.get("hostname") or shared.get("host") or shared.get("public_ip") or "").strip()
    raw_port = shared.get("port")
    port = raw_port if isinstance(raw_port, int) and 1 <= raw_port <= 65535 else 22
    row = AutoBindRow(
        instance=shared,
        status=READY,
        match=match,
        host=host or None,
        port=port,
        team=team,
        own_instance=own_instance,
    )
    note = _configured_key_note(configured, match)
    if note:
        row.notes.append(note)
    login = shared.get("login_user")
    if isinstance(login, str) and login.strip():
        row.login, row.login_source = login.strip(), LOGIN_FROM_SHARE
    elif own_instance is not None:
        row.login, row.login_source = _login_and_source(service, own_instance)
    note = _default_login_note(row, team=True)
    if note:
        row.notes.append(note)

    if shared.get("credential_binding") is not None:
        row.status = ALREADY_BOUND
        return row
    if match is None:
        row.status = NO_KEY
    elif match.ambiguous:
        row.status = AMBIGUOUS
    elif not host:
        row.status = NO_ADDRESS
    elif not row.login:
        row.status = NO_LOGIN
    return row


async def apply_auto_bind(
    service: Any,
    rows: Sequence[AutoBindRow],
    *,
    vault_id: str,
    team: Optional[str] = None,
    reviewed_fetched: bool = False,
    on_progress: Callable[[int, AutoBindRow], None] | None = None,
) -> None:
    """Bind each ready row in turn, recording ``"bound"`` or the failure reason.

    A server that gained a vault key since the review is not replaced.
    Unverified fetched rows require reviewed_fetched=True to bind; otherwise
    they are skipped with result "not reviewed".
    """
    for index, row in enumerate(rows):
        if not row.ready or row.match is None or row.match.item_id is None:
            continue
        if row.status == FETCHED and not row.verified and not reviewed_fetched:
            row.result = "not reviewed"
            continue
        if on_progress is not None:
            on_progress(index, row)

        team_slug = row.team or team
        if team_slug:
            try:
                res = await service.bind(
                    vault_id=vault_id,
                    server=str(row.instance.get("id")),
                    item_id=row.match.item_id,
                    team=team_slug,
                    login=row.login,
                    pin_host_key=False,
                    host_keys=list(row.host_keys),
                    replace_existing=False,
                )
            except Exception as exc:
                row.result = vault_failure_reason(exc)
            else:
                row.result = "bound"
                row.binding_result = res if isinstance(res, Mapping) else None
        else:
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


def _visit_target(service: Any, row: AutoBindRow) -> Mapping[str, Any]:
    """The record a host-key visit to *row*'s server logs in with.

    A team's shared row names no key of the user's (no key pair, no key
    file), so the user's own record of the same server logs in, as their own
    ``servonaut ssh`` does. A key the user mapped to the shared row itself
    (``instance_keys``) still wins: that row is then the one known to log in.
    """
    if row.own_instance is None or _mapped_key_path(service, row.instance) is not None:
        return row.instance
    return row.own_instance


async def fetch_host_keys_for_rows(
    service: Any,
    rows: Sequence[AutoBindRow],
    *,
    on_progress: Optional[Callable[[int, AutoBindRow], None]] = None,
    host_keys_for: Optional[Callable[[Mapping[str, Any], str, Optional[int]], list[str]]] = None,
    console_output_reader: Optional[Callable[[Mapping[str, Any]], str]] = None,
    accounts: Optional[Any] = None,
    max_concurrency: int = _HOST_KEY_VISITS,
) -> None:
    """Fetch and verify host keys for rows whose status is NO_HOST_KEYS.

    For AWS instances:
    1. Checks EC2 console output. If the KEYS block is well-formed, uses those
       keys directly as row.host_keys, marks row.verified = True ('verified by
       AWS console output') and skips the SSH visit.
    2. If only the FINGERPRINTS block is present, visits the server once,
       reads its recorded host key, and compares fingerprints. If matching,
       marks row.verified = True. If differing, sets status = HOST_KEY_MISMATCH
       with a removal command.
    3. If neither block is usable, visits the server and marks row.verified = False
       with the reason in verification_source.

    For non-AWS instances:
    Visits the server once, reads the recorded host key, and marks row.verified = False
    ('not verified: compare with the server's console or your provider').

    Concurrency is bounded by *max_concurrency* (default _HOST_KEY_VISITS = 4).
    A failure on one row stays on its row and never stops the others.
    """
    target_rows = [row for row in rows if row.status == NO_HOST_KEYS]
    if not target_rows:
        return

    gate = asyncio.Semaphore(max_concurrency)
    completed_count = 0
    completed_lock = asyncio.Lock()

    def _read_console(inst: Mapping[str, Any]) -> str:
        if console_output_reader is not None:
            return console_output_reader(inst)
        return fetch_ec2_console_output_sync(
            inst,
            accounts=accounts or getattr(service, "accounts", None),
        )

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_file = Path(temp_dir) / "known_hosts"
        ensure_known_hosts_file(temp_file)

        async def fetch_one(row: AutoBindRow) -> None:
            nonlocal completed_count
            async with gate:
                await _fetch_row(row, temp_file)
                async with completed_lock:
                    completed_count += 1
                    current_completed = completed_count
                if on_progress is not None:
                    on_progress(current_completed, row)

        async def _fetch_row(row: AutoBindRow, temp_kh: Path) -> None:
            inst = row.own_instance or row.instance
            is_aws = (not inst.get("is_custom") and instance_provider(inst).lower() == "aws")
            console_res: Optional[EC2ConsoleHostKeys] = None

            if is_aws:
                try:
                    raw_console = await asyncio.to_thread(_read_console, inst)
                    console_res = parse_ec2_console_output(raw_console)
                except Exception as exc:
                    logger.debug("ec2:GetConsoleOutput failed for %s: %s", inst.get("id"), exc, exc_info=True)
                    code = ""
                    if hasattr(exc, "response") and isinstance(getattr(exc, "response"), Mapping):
                        code = str(exc.response.get("Error", {}).get("Code", ""))
                    if not code:
                        msg = str(exc).lower()
                        if "accessdenied" in msg or "unauthorizedoperation" in msg:
                            code = "AccessDenied"
                        elif "throttl" in msg or "requestlimitexceeded" in msg:
                            code = "Throttling"
                    if code in {"AccessDenied", "UnauthorizedOperation"}:
                        console_res = EC2ConsoleHostKeys(
                            source="not verified: no permission to read the console output (ec2:GetConsoleOutput)",
                            error="no permission to read the console output (ec2:GetConsoleOutput)",
                        )
                    elif code in {"Throttling", "RequestLimitExceeded"}:
                        console_res = EC2ConsoleHostKeys(
                            source="not verified: AWS throttled the console read; fetch again later",
                            error="AWS throttled the console read; fetch again later",
                        )
                    else:
                        console_res = EC2ConsoleHostKeys(
                            source="not verified: could not read the console output",
                            error="could not read the console output",
                        )

                # 1. KEYS block is present and well-formed: use directly without connecting
                if console_res.has_keys_block and console_res.keys:
                    row.host_keys = list(console_res.keys)
                    row.status = FETCHED
                    row.verified = True
                    row.verification_source = "verified by AWS console output"
                    return

            # Visit the server once so its host key is recorded into temporary storage
            failure: Optional[str] = None
            try:
                failure = await service.visit_for_host_key(
                    _visit_target(service, row),
                    login=row.login,
                    known_hosts_path=temp_kh,
                )
            except Exception as exc:
                failure = str(exc)

            if failure:
                row.status = FETCH_FAILED
                row.fetch_error = failure.strip().rstrip(".")
                return

            port = row.port if row.port != 22 else None
            try:
                if host_keys_for is not None:
                    keys = await asyncio.to_thread(host_keys_for, row.instance, str(row.host), port)
                    if not keys and row.own_instance:
                        keys = await asyncio.to_thread(host_keys_for, row.own_instance, str(row.host), port)
                else:
                    keys = await asyncio.to_thread(
                        read_host_keys_from_file,
                        temp_kh,
                        row.instance,
                        str(row.host),
                        port,
                        own_instance=row.own_instance,
                    )
            except Exception as exc:
                keys = []

            if not keys:
                row.status = FETCH_FAILED
                row.fetch_error = "the connection worked, but no host key was recorded for it"
                return

            row.host_keys = keys

            if is_aws and console_res is not None:
                if console_res.has_fingerprints_block:
                    verified, reason = verify_fetched_host_keys(keys, console_res)
                    if reason == "mismatch":
                        row.status = HOST_KEY_MISMATCH
                        row.verified = False
                        row.host_keys = []
                        row.mismatch_detail = (
                            "The server answered with a different host key than AWS recorded at first boot: "
                            "do not bind, check the server."
                        )
                        return
                    if verified:
                        row.status = FETCHED
                        row.verified = True
                        row.verification_source = "verified by AWS console output"
                        return
                    # Fingerprints present but didn't match key types
                    row.status = FETCHED
                    row.verified = False
                    row.verification_source = reason
                    return

                # Neither block was usable on AWS
                row.status = FETCHED
                row.verified = False
                reason_text = console_res.error or console_res.source or "the console output no longer holds the first-boot host keys"
                if not reason_text.startswith("not verified:"):
                    reason_text = f"not verified: {reason_text}"
                row.verification_source = reason_text
                return

            # Non-AWS instance
            row.status = FETCHED
            row.verified = False
            row.verification_source = "not verified: compare with the server's console or your provider"

        await asyncio.gather(*(fetch_one(row) for row in target_rows))


__all__ = [
    "FETCHED", "FETCH_FAILED", "HOST_KEY_MISMATCH", "READY", "ALREADY_BOUND", "AMBIGUOUS",
    "NO_HOST_KEYS", "NO_ADDRESS", "NO_LOGIN", "NO_KEY", "CHECK_FAILED", "_HOST_KEY_VISITS",
    "AutoBindRow", "ConfiguredKey", "KeyMatch",
    "LOGIN_FROM_ACCOUNT", "LOGIN_FROM_DEFAULT", "LOGIN_FROM_RULE", "LOGIN_FROM_SERVER", "LOGIN_FROM_SHARE", "MATCHED_BY_CONFIGURED_KEY", "MATCHED_BY_KEY_FILE", "MATCHED_BY_KEY_PAIR", "MATCHED_BY_SERVER_NAME",
    "apply_auto_bind", "configured_key", "fetch_host_keys_for_rows", "key_file_fingerprint", "is_personal_server", "match_ssh_key", "normalize_key_name", "plan_auto_bind",
]
