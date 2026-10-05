"""Versioned, client-owned SSH CA host enrolment and KRL delivery."""

from __future__ import annotations

import base64
import hashlib
import re
import struct
import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Awaitable, Callable, Mapping, Protocol, Sequence

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_ssh_public_identity
from cryptography.hazmat.primitives.serialization.ssh import SSHCertificateType

from .crypto import openssh_fingerprint
from .errors import VaultUserError


SCRIPT_VERSION = "1"
MANAGED_DIR = PurePosixPath("/etc/ssh/servonaut")
DROP_IN = PurePosixPath("/etc/ssh/sshd_config.d/50-servonaut.conf")
HOST_CERTIFICATE = PurePosixPath("/etc/ssh/ssh_host_ed25519_key-cert.pub")
BREAK_GLASS_AUTHORIZED_KEYS = PurePosixPath("/root/.ssh/authorized_keys")
# What an enrolment writes, shown on the confirmation screens.
MANAGED_PATHS_SUMMARY = f"{MANAGED_DIR}/, {DROP_IN}, {HOST_CERTIFICATE}"


class EnrollmentError(VaultUserError):
    """A host-enrolment payload or host action failed safely (fixed, user-safe text)."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    stdout_bytes: bytes = b""


class HostExecutor(Protocol):
    """Injected SSH transport for client-owned enrollment templates.

    SSH exec runs through the remote shell on many servers. Implementations
    may use it only for fixed local templates, never server-supplied scripts.
    """

    async def run(self, argv: Sequence[str]) -> CommandResult: ...

    async def read_file(self, path: PurePosixPath) -> bytes: ...

    async def write_atomic(self, path: PurePosixPath, content: bytes, mode: int) -> None: ...

    async def remove(self, path: PurePosixPath) -> None: ...


@dataclass(frozen=True)
class EnrollmentStep:
    name: str
    status: str
    detail: str = ""


@dataclass(frozen=True)
class EnrollmentResult:
    status: str
    steps: tuple[EnrollmentStep, ...]
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "steps": [step.__dict__ for step in self.steps],
            "error_code": self.error_code,
        }


def validate_enrollment_params(params: Mapping[str, Any]) -> None:
    """Reject server parameters that would change the CLI's trusted template."""
    if params.get("script_version") != SCRIPT_VERSION:
        raise EnrollmentError("Unsupported SSH CA enrolment script version")
    if params.get("managed_dir") != str(MANAGED_DIR) or params.get("drop_in") != str(DROP_IN):
        raise EnrollmentError("SSH CA enrolment requested unsafe managed paths")
    server = params.get("server") or {}
    if not isinstance(server.get("hostname"), str) or not server["hostname"]:
        raise EnrollmentError("SSH CA enrolment is missing a host name")
    principals = params.get("principals_by_login")
    if not isinstance(principals, Mapping) or not principals:
        raise EnrollmentError("SSH CA enrolment has no login principals")
    for login, values in principals.items():
        if not _safe_login(str(login)) or not isinstance(values, Sequence) or not values:
            raise EnrollmentError("SSH CA enrolment has invalid login principals")
        if any(not isinstance(value, str) or "\n" in value for value in values):
            raise EnrollmentError("SSH CA enrolment has unsafe principal text")
    if not _openssh_key_list(params.get("user_ca_public_keys")) or not _openssh_key(params.get("host_ca_public_key")):
        raise EnrollmentError("SSH CA enrolment has invalid CA public keys")
    host_principals = params.get("host_principals")
    if not isinstance(host_principals, Sequence) or not host_principals or any(not isinstance(value, str) or "\n" in value for value in host_principals):
        raise EnrollmentError("SSH CA enrolment has invalid host principals")
    try:
        krl = base64.b64decode(str(params.get("krl", "")), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise EnrollmentError("SSH CA enrolment has an invalid KRL") from exc
    if not krl:
        raise EnrollmentError("SSH CA enrolment KRL is empty")


class CaEnrollmentExecutor:
    """Apply only the v1 local template after a host-name confirmation."""

    def __init__(self, executor: HostExecutor, *, host_ca_public_key: str, team: str | None = None) -> None:
        self.executor = executor
        if not _openssh_key(host_ca_public_key):
            raise EnrollmentError("Pinned host CA key is invalid")
        self.host_ca_public_key = host_ca_public_key
        self.team = team

    async def execute(
        self,
        params: Mapping[str, Any],
        *,
        confirmed_host_name: str,
        request_host_certificate: Callable[[str], Awaitable[str]],
        prove_certificate_login: Callable[[], Awaitable[bool]],
    ) -> EnrollmentResult:
        validate_enrollment_params(params)
        hostname = str(params["server"]["hostname"])
        if confirmed_host_name != hostname:
            raise EnrollmentError("Host name confirmation did not match")
        kind = str(params.get("kind"))
        if kind == "unenroll":
            return await self._unenroll(params)
        if kind not in {"enroll", "refresh"}:
            raise EnrollmentError("Unsupported SSH CA enrolment kind")
        steps: list[EnrollmentStep] = []
        snapshot: dict[PurePosixPath, bytes | None] = {}
        try:
            await self._precheck()
            steps.append(EnrollmentStep("precheck", "ok"))
            snapshot = await self._snapshot(params)
            await self._write_managed_files(params)
            steps.append(EnrollmentStep("managed_files", "ok"))
            host_public_key = (await self.executor.read_file(PurePosixPath("/etc/ssh/ssh_host_ed25519_key.pub"))).decode("ascii").strip()
            host_certificate = await request_host_certificate(host_public_key)
            self._verify_host_certificate(host_certificate, host_public_key, params)
            await self.executor.write_atomic(HOST_CERTIFICATE, (host_certificate + "\n").encode(), 0o644)
            steps.append(EnrollmentStep("host_certificate", "ok"))
            await self.executor.write_atomic(DROP_IN, self._drop_in(params).encode(), 0o644)
            await self._append_break_glass(params)
            test = await self.executor.run(["sshd", "-t"])
            if test.returncode != 0:
                raise EnrollmentError("sshd_config_test_failed")
            steps.append(EnrollmentStep("sshd_config_test", "ok"))
            await self._reload()
            steps.append(EnrollmentStep("reload", "ok"))
            if not await prove_certificate_login():
                raise EnrollmentError("certificate_login_proof_failed")
            steps.append(EnrollmentStep("certificate_login_proof", "ok"))
            return EnrollmentResult("succeeded", tuple(steps))
        except Exception as exc:
            reason = _safe_error_code(exc)
            if not snapshot:
                # Failed before the snapshot, so before any host write: the
                # host is unchanged and there is nothing to restore or reload.
                steps.append(EnrollmentStep("rollback", "ok", "nothing was written"))
                return EnrollmentResult("rolled_back", tuple(steps), reason)
            try:
                await self._restore(snapshot)
                steps.append(EnrollmentStep("rollback", "ok"))
                return EnrollmentResult("rolled_back", tuple(steps), reason)
            except Exception:
                steps.append(EnrollmentStep("rollback", "failed", reason))
                return EnrollmentResult("failed", tuple(steps), "rollback_failed")

    def _verify_host_certificate(
        self, host_certificate: str, host_public_key: str, params: Mapping[str, Any]
    ) -> None:
        try:
            certificate = load_ssh_public_identity(host_certificate.encode("ascii"))
            certificate.verify_cert_signature()
            signer = certificate.signature_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
            subject = certificate.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
            principals = tuple(value.decode("utf-8") for value in certificate.valid_principals)
        except Exception as exc:
            raise EnrollmentError("Server returned an invalid host certificate") from exc
        if certificate.type is not SSHCertificateType.HOST:
            raise EnrollmentError("Server returned a user certificate for host enrollment")
        if _openssh_fingerprint(signer) != _openssh_fingerprint(self.host_ca_public_key):
            raise EnrollmentError("Host certificate was not signed by the pinned host CA")
        if _key_without_comment(subject) != _key_without_comment(host_public_key):
            raise EnrollmentError("Host certificate subject does not match the enrolled host key")
        if principals != tuple(params["host_principals"]):
            raise EnrollmentError("Host certificate principals differ from the enrollment request")
        now = int(time.time())
        if certificate.valid_after > now + 120 or certificate.valid_before <= now:
            raise EnrollmentError("Host certificate has an invalid validity window")

    async def _precheck(self) -> None:
        version = await self.executor.run(["sshd", "-V"])
        effective = await self.executor.run(["sshd", "-T"])
        version_text = version.stdout + version.stderr
        if version.returncode != 0 or effective.returncode != 0 or not _openssh_at_least_82(version_text):
            raise EnrollmentError("sshd_precheck_failed")
        values = _effective_config(effective.stdout)
        for key in ("trustedusercakeys", "authorizedprincipalsfile", "revokedkeys"):
            value = values.get(key, "none")
            if value.lower() not in {"none", ""}:
                raise EnrollmentError("foreign_ca_config")

    async def _write_managed_files(self, params: Mapping[str, Any]) -> None:
        await self.executor.write_atomic(
            MANAGED_DIR / "revoked.krl", base64.b64decode(str(params["krl"])), 0o644
        )
        await self.executor.write_atomic(
            MANAGED_DIR / "user_ca_keys.pub",
            ("\n".join(params["user_ca_public_keys"]) + "\n").encode(),
            0o644,
        )
        for login, principals in params["principals_by_login"].items():
            await self.executor.write_atomic(
                MANAGED_DIR / "principals" / str(login),
                ("\n".join(principals) + "\n").encode(),
                0o644,
            )

    async def _snapshot(self, params: Mapping[str, Any]) -> dict[PurePosixPath, bytes | None]:
        paths = [DROP_IN, MANAGED_DIR / "revoked.krl", MANAGED_DIR / "user_ca_keys.pub", PurePosixPath("/etc/ssh/ssh_host_ed25519_key-cert.pub")]
        paths.extend(MANAGED_DIR / "principals" / str(login) for login in params["principals_by_login"])
        if params.get("break_glass"):
            paths.append(_break_glass_path(params["break_glass"]))
        snapshot: dict[PurePosixPath, bytes | None] = {}
        for path in paths:
            try:
                snapshot[path] = await self.executor.read_file(path)
            except (FileNotFoundError, OSError):
                snapshot[path] = None
        return snapshot

    async def _restore(self, snapshot: Mapping[PurePosixPath, bytes | None]) -> None:
        """Put the host back the way the snapshot found it.

        The sshd configuration goes back and is reloaded FIRST: a running sshd
        whose RevokedKeys file has disappeared refuses every public-key login,
        including the connection this rollback needs next.
        """
        if DROP_IN in snapshot:
            await self._put_back(DROP_IN, snapshot[DROP_IN])
        test = await self.executor.run(["sshd", "-t"])
        if test.returncode != 0:
            raise EnrollmentError("sshd_config_test_failed")
        await self._reload()
        for path, content in snapshot.items():
            if path != DROP_IN:
                await self._put_back(path, content)

    async def _put_back(self, path: PurePosixPath, content: bytes | None) -> None:
        if content is None:
            await self.executor.remove(path)
            return
        # authorized_keys must stay owner-only; the managed files are world-readable.
        mode = 0o600 if path == BREAK_GLASS_AUTHORIZED_KEYS else 0o644
        await self.executor.write_atomic(path, content, mode)

    async def _append_break_glass(self, params: Mapping[str, Any]) -> None:
        spec = params.get("break_glass")
        if spec is None:
            return
        path = _break_glass_path(spec)
        marker = f"servonaut-break-glass:{spec['item_id']}"
        line = _break_glass_line(spec, marker)
        try:
            existing = (await self.executor.read_file(path)).decode("utf-8")
        except (FileNotFoundError, OSError):
            existing = ""
        if marker not in existing:
            await self.executor.write_atomic(path, (existing.rstrip("\n") + "\n" + line + "\n").lstrip("\n").encode(), 0o600)

    def _drop_in(self, params: Mapping[str, Any]) -> str:
        server_id = (params.get("server") or {}).get("id") if isinstance(params.get("server"), Mapping) else None
        owner = [f"script v{SCRIPT_VERSION}"]
        if isinstance(self.team, str) and _HEADER_TOKEN_RE.fullmatch(self.team):
            owner.append(f"team {self.team}")
        if isinstance(server_id, str) and _HEADER_TOKEN_RE.fullmatch(server_id):
            owner.append(f"server {server_id}")
        return (
            f"# Managed by Servonaut ({', '.join(owner)}). Do not edit.\n"
            f"TrustedUserCAKeys {MANAGED_DIR}/user_ca_keys.pub\n"
            f"AuthorizedPrincipalsFile {MANAGED_DIR}/principals/%u\n"
            f"RevokedKeys {MANAGED_DIR}/revoked.krl\n"
            "HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub\n"
        )

    async def _reload(self) -> None:
        first = await self.executor.run(["systemctl", "reload", "ssh"])
        if first.returncode != 0:
            second = await self.executor.run(["systemctl", "reload", "sshd"])
            if second.returncode != 0:
                raise EnrollmentError("sshd_reload_failed")

    async def _unenroll(self, params: Mapping[str, Any]) -> EnrollmentResult:
        steps: list[EnrollmentStep] = []
        snapshot = await self._snapshot(params)
        try:
            # Drop the configuration and reload before deleting the files it
            # names: the running sshd must never point at a missing KRL.
            await self.executor.remove(DROP_IN)
            test = await self.executor.run(["sshd", "-t"])
            if test.returncode != 0:
                raise EnrollmentError("sshd_config_test_failed")
            await self._reload()
            for path in (MANAGED_DIR / "revoked.krl", MANAGED_DIR / "user_ca_keys.pub"):
                await self.executor.remove(path)
            for login in params.get("principals_by_login", {}):
                await self.executor.remove(MANAGED_DIR / "principals" / str(login))
            spec = params.get("break_glass")
            if spec is not None:
                await self._remove_break_glass(spec)
            return EnrollmentResult("succeeded", (EnrollmentStep("unenroll", "ok"),))
        except Exception as exc:
            try:
                await self._restore(snapshot)
                steps.append(EnrollmentStep("rollback", "ok"))
                return EnrollmentResult("rolled_back", tuple(steps), _safe_error_code(exc))
            except Exception:
                steps.append(EnrollmentStep("rollback", "failed"))
                return EnrollmentResult("failed", tuple(steps), "rollback_failed")

    async def _remove_break_glass(self, spec: Mapping[str, Any]) -> None:
        path = _break_glass_path(spec)
        marker = f"servonaut-break-glass:{spec['item_id']}"
        try:
            lines = (await self.executor.read_file(path)).decode("utf-8").splitlines()
        except (FileNotFoundError, OSError):
            return
        remaining = [line for line in lines if marker not in line]
        await self.executor.write_atomic(path, ("\n".join(remaining) + ("\n" if remaining else "")).encode(), 0o600)


@dataclass(frozen=True)
class KrlDeliveryReport:
    krl_version: int
    results: tuple[dict[str, str], ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {"krl_version": self.krl_version, "results": list(self.results)}


async def deliver_krl(
    executor_by_server: Mapping[str, HostExecutor],
    krl: bytes,
    expected_sha256_b64: str,
    krl_version: int,
) -> KrlDeliveryReport:
    """Verify then atomically replace the KRL. SSHD reload is intentionally omitted."""
    actual = base64.b64encode(hashlib.sha256(krl).digest()).decode("ascii")
    if actual != expected_sha256_b64:
        raise EnrollmentError("KRL SHA-256 verification failed")
    _validate_krl(krl, krl_version)
    results: list[dict[str, str]] = []
    for server_id, executor in executor_by_server.items():
        try:
            await executor.write_atomic(MANAGED_DIR / "revoked.krl", krl, 0o644)
            results.append({"server_id": server_id, "status": "delivered"})
        except Exception:
            results.append({"server_id": server_id, "status": "failed", "error": "write_failed"})
    return KrlDeliveryReport(krl_version, tuple(results))


def _effective_config(output: str) -> dict[str, str]:
    return {
        key.lower(): value.strip()
        for line in output.splitlines()
        if (parts := line.split(maxsplit=1)) and len(parts) == 2
        for key, value in [parts]
    }


def _safe_login(value: str) -> bool:
    return bool(value) and value[0].islower() and all(character.islower() or character.isdigit() or character in "_-" for character in value)


def _openssh_key(value: object) -> bool:
    return isinstance(value, str) and value.startswith(("ssh-ed25519 ", "ecdsa-sha2-")) and "\n" not in value


def _openssh_key_list(value: object) -> bool:
    return isinstance(value, Sequence) and bool(value) and all(_openssh_key(item) for item in value)


_ERROR_CODE_RE = re.compile(r"[a-z0-9_]{1,64}")
_HEADER_TOKEN_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")


def enrollment_error_code(error: BaseException) -> str:
    """A short snake_case code for an enrollment result, as the API requires.

    Client-authored reasons become a slug of their text; anything else is
    named only by its class, so server text never reaches the report.
    """
    if isinstance(error, VaultUserError):
        text = str(error)
        if _ERROR_CODE_RE.fullmatch(text):
            return text
        slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:64].rstrip("_")
        return slug or "enrollment_failed"
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", type(error).__name__)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    return name[:64] if _ERROR_CODE_RE.fullmatch(name[:64]) else "enrollment_failed"


def _safe_error_code(error: Exception) -> str:
    return enrollment_error_code(error)


def _openssh_at_least_82(value: str) -> bool:
    match = re.search(r"OpenSSH[_ ](\d+)\.(\d+)", value)
    return match is not None and (int(match.group(1)), int(match.group(2))) >= (8, 2)


def _validate_krl(krl: bytes, expected_version: int | None = None) -> None:
    # RFC 5656/OpenSSH KRL header: magic, format, version, generated date.
    if len(krl) < 28:
        raise EnrollmentError("KRL is too short")
    magic, format_version, version = struct.unpack(">QIQ", krl[:20])
    if magic != 0x5353484B524C0A00 or format_version != 1:
        raise EnrollmentError("KRL is not an OpenSSH v1 KRL")
    if expected_version is not None and version != expected_version:
        raise EnrollmentError("KRL version does not match the server response")


def _break_glass_path(spec: Mapping[str, Any]) -> PurePosixPath:
    if spec.get("login") != "root" or not _openssh_key(spec.get("public_key")) or not isinstance(spec.get("item_id"), str):
        raise EnrollmentError("Break-glass configuration is invalid")
    return BREAK_GLASS_AUTHORIZED_KEYS


def _break_glass_line(spec: Mapping[str, Any], marker: str) -> str:
    cidrs = spec.get("from_cidrs") or []
    if not isinstance(cidrs, Sequence) or any(not isinstance(cidr, str) or any(char.isspace() for char in cidr) for cidr in cidrs):
        raise EnrollmentError("Break-glass source restrictions are invalid")
    restriction = f'from="{",".join(cidrs)}" ' if cidrs else ""
    return f"{restriction}{spec['public_key']} {marker}"


def _key_without_comment(value: str) -> str:
    return " ".join(value.split()[:2])


def _openssh_fingerprint(value: str) -> str:
    try:
        return openssh_fingerprint(base64.b64decode(value.split()[1], validate=True))
    except (IndexError, ValueError, UnicodeError) as exc:
        raise EnrollmentError("OpenSSH key is invalid") from exc
