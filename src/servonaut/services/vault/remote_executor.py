"""Concrete, pinned OpenSSH transport for the CA enrollment template.

Remote commands necessarily pass through the SSH exec protocol's remote shell.
This module only sends fixed, client-owned templates and passes paths as shell
positional parameters; it never executes server-supplied shell text.
"""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import tempfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Awaitable, Callable, Iterator, Mapping, Sequence

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_ssh_private_key,
    load_ssh_public_key,
)

from servonaut.services.bw_resolver import BwResolver
from servonaut.services.connection_service import server_connection
from servonaut.services.ssh_host_keys import ensure_known_hosts_file, servonaut_known_hosts_path
from servonaut.services.ssh_ref_resolver import ResolvedSshRef
from servonaut.utils.ephemeral_key import ephemeral_ssh_key

from .ca_enrollment import BREAK_GLASS_AUTHORIZED_KEYS, CommandResult, EnrollmentError, HostExecutor
from .ssh_agent import PrivateSshAgent


_ALLOWED_COMMANDS = {
    ("sshd", "-V"), ("sshd", "-T"), ("sshd", "-t"),
    ("systemctl", "reload", "ssh"), ("systemctl", "reload", "sshd"), ("true",),
}
# Never changes an existing directory: only a missing parent is created, with
# the given mode (chmodding /etc/ssh would stop sshd reading per-user files).
_WRITE_TEMPLATE = (
    "set -eu; target=$1; mode=$2; dirmode=$3; directory=${target%/*}; "
    "if [ ! -d \"$directory\" ]; then install -d -m \"$dirmode\" -- \"$directory\"; fi; "
    "temporary=$(mktemp \"${target}.tmp.XXXXXX\"); "
    "trap 'rm -f -- \"$temporary\"' EXIT; cat >\"$temporary\"; chmod \"$mode\" \"$temporary\"; "
    "mv -f -- \"$temporary\" \"$target\"; trap - EXIT"
)
_LOGIN_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
# Read-only: sshd's journal entries, then the classic auth logs. Both are read
# because a host may keep either or both; duplicates are removed by the caller.
_AUTH_LOG_TEMPLATE = (
    "set -u; hours=$1; "
    "if command -v journalctl >/dev/null 2>&1; then "
    "journalctl --no-pager -q -o short-iso _COMM=sshd --since \"-${hours}h\" 2>/dev/null || true; fi; "
    "for f in /var/log/auth.log /var/log/secure; do "
    "if [ -f \"$f\" ] && [ ! -L \"$f\" ]; then tail -n 20000 -- \"$f\"; fi; done; exit 0"
)


class SshHostExecutor(HostExecutor):
    """Run the fixed enrollment operations over a strictly pinned SSH route."""

    def __init__(
        self, server: Mapping[str, Any], ssh_service: Any, connection_service: Any,
        ssh_ref_resolver: Any, *, lease: Any | None = None, default_username: str = "root",
        bw_resolver: BwResolver | None = None, known_hosts_path: Path | None = None,
        proof_certificate_supplier: Callable[[], Awaitable[Any]] | None = None,
        timeout_seconds: int = 30,
    ) -> None:
        self.server = dict(server)
        self.ssh_service = ssh_service
        self.connection_service = connection_service
        self.ssh_ref_resolver = ssh_ref_resolver
        self.lease = lease
        self.default_username = default_username
        self.bw_resolver = bw_resolver or BwResolver()
        self.known_hosts_path = known_hosts_path or servonaut_known_hosts_path()
        self.proof_certificate_supplier = proof_certificate_supplier
        self.timeout_seconds = timeout_seconds
        self._resolved: ResolvedSshRef | None = None
        self._connection: dict[str, Any] | None = None

    async def run(self, argv: Sequence[str]) -> CommandResult:
        await self._prepare()
        command = tuple(argv)
        if command not in _ALLOWED_COMMANDS:
            raise EnrollmentError("Enrollment attempted a command outside its local template")
        return await self._exec(self._privileged(command))

    async def read_auth_log(self, since_hours: int) -> str:
        """Return the host's recent SSH authentication log lines (read-only)."""
        if isinstance(since_hours, bool) or not isinstance(since_hours, int) or not 1 <= since_hours <= 720:
            raise EnrollmentError("The auth-log window must be between 1 and 720 hours")
        await self._prepare()
        result = await self._exec(self._privileged(("sh", "-c", _AUTH_LOG_TEMPLATE, "sh", str(since_hours))))
        if result.returncode != 0:
            raise EnrollmentError("Could not read the host's SSH authentication log")
        return result.stdout

    async def read_file(self, path: Path) -> bytes:
        await self._prepare(); self._safe_path(path)
        result = await self._exec(self._privileged(("sh", "-c", "[ ! -L \"$1\" ] || exit 72; cat -- \"$1\"", "sh", str(path))))
        if result.returncode != 0:
            raise FileNotFoundError(str(path))
        return result.stdout_bytes

    async def write_atomic(self, path: Path, content: bytes, mode: int) -> None:
        await self._prepare(); self._safe_path(path)
        if mode not in {0o600, 0o644}:
            raise EnrollmentError("Enrollment requested an unsafe file mode")
        result = await self._exec(
            self._privileged((
                "sh", "-c", _WRITE_TEMPLATE, "sh", str(path), format(mode, "o"),
                # Managed sshd directories are world-readable; .ssh directories are not.
                "700" if str(path) == str(BREAK_GLASS_AUTHORIZED_KEYS) else "755",
            )),
            stdin=content,
        )
        if result.returncode != 0:
            raise EnrollmentError("Could not atomically write enrollment file")

    async def remove(self, path: Path) -> None:
        await self._prepare(); self._safe_path(path)
        result = await self._exec(self._privileged(("sh", "-c", "rm -f -- \"$1\"", "sh", str(path))))
        if result.returncode != 0:
            raise EnrollmentError("Could not remove enrollment file")

    async def prove_certificate_login(self) -> bool:
        """Use one newly issued automation lease for a strict ``true`` proof."""
        if self.proof_certificate_supplier is None:
            raise EnrollmentError("No fresh automation certificate supplier is configured")
        proof_lease = await self.proof_certificate_supplier()
        if not all(isinstance(getattr(proof_lease, name, None), str) and getattr(proof_lease, name)
                   for name in ("identity_agent", "certificate_path", "known_hosts_path", "login_user")):
            raise EnrollmentError("Automation certificate supplier returned an invalid lease")
        old_lease = self.lease
        try:
            self.lease = proof_lease
            result = await self._exec(("true",))
            return result.returncode == 0
        finally:
            self.lease = old_lease
            close = getattr(proof_lease, "close", None)
            if callable(close):
                close()

    async def rotate_authorized_key(
        self, login: str, old_public_key: str, new_public_key: str,
        proof_new_key: Callable[[], Awaitable[bool]],
    ) -> bool:
        """Swap one exact authorized_keys line only after an independent fresh proof."""
        if not _LOGIN_RE.fullmatch(login) or not _public_key(old_public_key) or not _public_key(new_public_key):
            raise EnrollmentError("SSH key rotation received invalid login or public key material")
        path = await self._authorized_keys_path(login)
        original = await self._read_user_file(path, login)
        await self.append_authorized_key(login, new_public_key)
        try:
            if not await proof_new_key():
                raise EnrollmentError("New SSH key login proof failed")
            await self.remove_authorized_key(login, old_public_key)
            return True
        except BaseException:
            await self._write_user_file(path, original, login)
            raise

    async def append_authorized_key(self, login: str, new_public_key: str) -> None:
        """Append one exact public key line to a validated login home only."""
        if not _LOGIN_RE.fullmatch(login) or not _public_key(new_public_key):
            raise EnrollmentError("SSH key rotation received invalid login or public key material")
        path = await self._authorized_keys_path(login)
        original = await self._read_user_file(path, login)
        new_line = new_public_key.strip()
        lines = original.decode("utf-8", "strict").splitlines()
        if _key_material(new_line) not in {_key_material(line) for line in lines}:
            separator = b"" if not original else b"\n"
            await self._write_user_file(path, original.rstrip(b"\n") + separator + new_line.encode("ascii") + b"\n", login)

    async def remove_authorized_key(self, login: str, old_public_key: str) -> None:
        """Remove only lines whose key material exactly matches the old public key."""
        if not _LOGIN_RE.fullmatch(login) or not _public_key(old_public_key):
            raise EnrollmentError("SSH key rotation received invalid login or public key material")
        path = await self._authorized_keys_path(login)
        original = await self._read_user_file(path, login)
        old_material = _key_material(old_public_key)
        lines = original.decode("utf-8", "strict").splitlines()
        remaining = [line for line in lines if _key_material(line) != old_material]
        if len(remaining) == len(lines):
            raise EnrollmentError("Current SSH key is not present in the login authorized_keys file")
        await self._write_user_file(path, ("\n".join(remaining) + "\n").encode("utf-8"), login)

    async def verify_new_key(self, login: str, new_private_key: bytes) -> bool:
        """Prove a fresh key through a private agent and this executor's strict pins."""
        if not _LOGIN_RE.fullmatch(login):
            raise EnrollmentError("SSH key rotation received an invalid login")
        agent = PrivateSshAgent.start()
        try:
            agent.add_private_key(new_private_key)
            with _public_identity_file(new_private_key) as identity_file:
                old_lease = self.lease
                # Prove the new key against the same pinned host keys the
                # current credential was verified with.
                pinned = getattr(old_lease, "known_hosts_path", None) or str(self.known_hosts_path)
                self.lease = SimpleNamespace(
                    identity_agent=str(agent.socket_path), certificate_path=None,
                    identity_file=str(identity_file), known_hosts_path=str(pinned), login_user=login,
                )
                try:
                    return (await self._exec(("true",))).returncode == 0
                finally:
                    self.lease = old_lease
        finally:
            agent.close()

    async def _authorized_keys_path(self, login: str) -> Path:
        await self._prepare()
        result = await self._exec(self._privileged(("getent", "passwd", login)))
        if result.returncode != 0:
            raise EnrollmentError("Could not resolve the requested SSH login home directory")
        fields = result.stdout.rstrip("\n").split(":")
        if len(fields) != 7 or fields[0] != login or not fields[5].startswith("/") or ".." in Path(fields[5]).parts:
            raise EnrollmentError("Resolved SSH login has an unsafe home directory")
        return Path(fields[5]) / ".ssh" / "authorized_keys"

    async def _read_user_file(self, path: Path, login: str) -> bytes:
        result = await self._exec(self._privileged(
            ("sh", "-c", "[ ! -L \"$1\" ] || exit 72; cat -- \"$1\"", "sh", str(path)), login
        ))
        if result.returncode != 0:
            raise EnrollmentError("Could not read login authorized_keys")
        return result.stdout_bytes

    async def _write_user_file(self, path: Path, content: bytes, login: str) -> None:
        result = await self._exec(
            self._privileged(("sh", "-c", _WRITE_TEMPLATE, "sh", str(path), "600", "700"), login), stdin=content,
        )
        if result.returncode != 0:
            raise EnrollmentError("Could not atomically update login authorized_keys")

    def _privileged(self, argv: tuple[str, ...], owned_by: str | None = None) -> tuple[str, ...]:
        connection = self._connection
        if connection is not None and connection["username"] in {"root", owned_by}:
            return argv
        return ("sudo", "-n", "--", *argv)

    async def _exec(self, remote_argv: tuple[str, ...], *, stdin: bytes | None = None) -> CommandResult:
        connection, resolved = await self._prepare()
        remote_command = shlex.join(remote_argv)
        key_path = resolved.local_key_path if resolved and resolved.source == "local" else None
        lease = self.lease or (resolved.lease if resolved else None)
        kwargs: dict[str, Any] = {
            "host": connection["host"], "username": connection["username"],
            "key_path": key_path, "proxy_args": connection["proxy_args"], "port": connection["port"],
            "extra_options": connection["extra_options"], "remote_command": remote_command,
            "known_hosts_file": str(self.known_hosts_path),
        }
        if lease is not None:
            lease_known_hosts = Path(lease.known_hosts_path)
            if not lease_known_hosts.exists() or not ensure_known_hosts_file(lease_known_hosts):
                raise EnrollmentError("Native SSH lease has no safe pinned known_hosts file")
            identity_file = getattr(lease, "identity_file", None)
            if not isinstance(identity_file, str) or not Path(identity_file).is_file():
                raise EnrollmentError("Native SSH lease has no public identity file")
            kwargs.update(identity_agent=lease.identity_agent, certificate_file=lease.certificate_path,
                          identity_file=identity_file, known_hosts_file=str(lease_known_hosts))
            kwargs["username"] = lease.login_user
        with self._bw_key(resolved) as bw_key:
            if bw_key is not None:
                kwargs["key_path"] = bw_key
            command = self.ssh_service.build_ssh_command(**kwargs)
            process = await asyncio.create_subprocess_exec(
                *command, stdin=asyncio.subprocess.PIPE if stdin is not None else None,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(stdin), self.timeout_seconds)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                process.kill()
                await process.wait()
                raise
        return CommandResult(process.returncode or 0, stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace"), stdout)

    async def _prepare(self) -> tuple[dict[str, Any], ResolvedSshRef | None]:
        if self._connection is not None:
            return self._connection, self._resolved
        resolved = await self.ssh_ref_resolver.resolve(self.server)
        connection = server_connection(self.server, self.connection_service, self.ssh_service, self.default_username)
        # Shared rows carry ``hostname``/``port`` rather than IP fields.
        connection["host"] = connection["host"] or self.server.get("hostname") or self.server.get("host")
        connection["port"] = connection["port"] or self.server.get("port")
        lease = self.lease or (resolved.lease if resolved else None)
        if lease is not None:
            connection["username"] = lease.login_user
            # Connect exactly where the lease's pinned known_hosts entry points.
            connection["host"] = getattr(lease, "target_host", None) or connection["host"]
            connection["port"] = getattr(lease, "target_port", None) or connection["port"]
        elif resolved is None:
            raise EnrollmentError("No existing SSH credential is available for enrollment")
        elif not self.known_hosts_path.exists() or not ensure_known_hosts_file(self.known_hosts_path):
            # Without a Vault or CA lease nothing pins the host: an already
            # trusted known_hosts entry is the only acceptable anchor.
            raise EnrollmentError("A safe existing known_hosts file is required for host enrollment")
        self._resolved, self._connection = resolved, connection
        return connection, resolved

    @staticmethod
    def _safe_path(path: Path) -> None:
        value = str(path)
        if value == str(BREAK_GLASS_AUTHORIZED_KEYS):
            return  # the one file outside /etc/ssh an enrollment may touch (break-glass line)
        if not path.is_absolute() or ".." in path.parts or not value.startswith("/etc/ssh/"):
            raise EnrollmentError("Enrollment requested an unsafe remote path")

    @contextmanager
    def _bw_key(self, resolved: ResolvedSshRef | None) -> Iterator[str | None]:
        if resolved is None or resolved.source not in {"personal", "team"}:
            yield None
            return
        if not resolved.item_id:
            raise EnrollmentError("Bitwarden SSH reference has no item id")
        with ephemeral_ssh_key(self.bw_resolver.resolve_ssh_key(resolved.item_id)) as key_path:
            yield key_path


def make_remote_executor_factory(
    ssh_service: Any, connection_service: Any, ssh_ref_resolver: Any, *, default_username: str = "root",
    bw_resolver: BwResolver | None = None, timeout_seconds: int = 30,
) -> Callable[[Mapping[str, Any], Any | None], SshHostExecutor]:
    """Capture existing services for ``VaultCommandService.remote_executor_factory``."""
    return lambda server, lease: SshHostExecutor(
        server, ssh_service, connection_service, ssh_ref_resolver, lease=lease,
        default_username=default_username, bw_resolver=bw_resolver, timeout_seconds=timeout_seconds,
    )


_KEY_TYPE_RE = re.compile(r"^(?:ssh-[a-z0-9-]+|ecdsa-sha2-[a-z0-9-]+|sk-[a-z0-9@.-]+)(?:-cert-v01@openssh\.com)?$")


def _key_material(line: str) -> str | None:
    """Return ``"<type> <base64>"`` of an authorized_keys line, ignoring options and comment.

    authorized_keys lines may start with options (``from="…",no-pty``) and end
    with a comment, so lines are compared by the key they grant, not as text.
    """
    fields = line.strip().split()
    for index, field in enumerate(fields[:-1]):
        if _KEY_TYPE_RE.fullmatch(field):
            return f"{field} {fields[index + 1]}"
    return None


def _public_key(value: str) -> bool:
    """Accept a single canonical user key, including security-key variants."""
    if not isinstance(value, str) or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return False
    fields = value.split(" ", 2)
    if len(fields) < 2 or not fields[0] or not fields[1] or (len(fields) == 3 and not fields[2]):
        return False
    try:
        parsed = load_ssh_public_key((fields[0] + " " + fields[1]).encode("ascii"))
    except (TypeError, ValueError, UnicodeError):
        return False
    return parsed.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii") == fields[0] + " " + fields[1]


@contextmanager
def _public_identity_file(private_key: bytes) -> Iterator[Path]:
    """Materialize only an ephemeral public identity for an agent-backed proof."""
    try:
        public_key = load_ssh_private_key(private_key, password=None).public_key().public_bytes(
            Encoding.OpenSSH, PublicFormat.OpenSSH
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise EnrollmentError("New SSH key could not be parsed for proof") from exc
    fd, temporary = tempfile.mkstemp(prefix=".servonaut-public-identity-", suffix=".pub")
    path = Path(temporary)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(public_key + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        yield path
    finally:
        path.unlink(missing_ok=True)
