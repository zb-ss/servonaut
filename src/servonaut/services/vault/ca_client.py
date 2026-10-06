"""Signed SSH certificate authority client for a Team Vault device."""

from __future__ import annotations

import base64
import inspect
import json
import os
import re
import tempfile
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_ssh_public_identity,
    load_ssh_private_key,
    load_ssh_public_key,
)
from cryptography.hazmat.primitives.serialization.ssh import SSHCertificateType

from .ca_pins import CaPinStore, CaPins
from .crypto import openssh_fingerprint


_TEAM_SLUG_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
_CLOCK_SKEW_SECONDS = 120


class CertificateValidationError(RuntimeError):
    """A certificate or CA response does not meet the local security policy."""


class SignedRequestClient(Protocol):
    async def request_signed(
        self, method: str, path: str, body: dict[str, Any] | None, device: object
    ) -> dict[str, Any]: ...

    async def get(self, path: str) -> dict[str, Any]: ...


class DeviceSshKeyStore(Protocol):
    """Adapter supplied by identity_store; private bytes are encrypted at rest."""

    def get_device_ssh_private_key(self) -> bytes | None: ...

    def store_device_ssh_private_key(self, private_key: bytes) -> None: ...


@dataclass(frozen=True)
class CaStatus:
    enabled: bool
    user_ca_public_key: str | None
    host_ca_public_key: str | None
    user_ca_fingerprint: str | None
    host_ca_fingerprint: str | None
    policy: Mapping[str, Any]
    logins_by_server: Mapping[str, tuple[str, ...]]
    krl_version: int | None
    raw: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "user_ca_fingerprint": self.user_ca_fingerprint,
            "host_ca_fingerprint": self.host_ca_fingerprint,
            "policy": dict(self.policy),
            "logins_by_server": {key: list(value) for key, value in self.logins_by_server.items()},
            "krl_version": self.krl_version,
        }


@dataclass(frozen=True)
class DeviceSshKey:
    private_key: bytes
    public_key: str
    fingerprint: str


@dataclass(frozen=True)
class IssuedCertificate:
    certificate_path: Path
    certificate: str
    serial: int
    principals: tuple[str, ...]
    logins_by_server: Mapping[str, tuple[str, ...]]
    valid_after: datetime
    valid_before: datetime
    renew_after: datetime
    ca_fingerprint: str
    server_ids: tuple[str, ...] = ()
    purpose: str = "interactive"

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_path": str(self.certificate_path),
            "serial": self.serial,
            "principals": list(self.principals),
            "logins_by_server": {key: list(value) for key, value in self.logins_by_server.items()},
            "valid_after": self.valid_after.isoformat(),
            "valid_before": self.valid_before.isoformat(),
            "renew_after": self.renew_after.isoformat(),
            "ca_fingerprint": self.ca_fingerprint,
        }


class CertificateAuthorityClient:
    """Issue and locally validate certificates for one team and one device."""

    def __init__(
        self,
        api_client: SignedRequestClient,
        team_slug: str,
        device_signer: object,
        device_id: str,
        key_store: DeviceSshKeyStore,
        *,
        pins: CaPinStore | None = None,
        certificate_dir: Path | None = None,
    ) -> None:
        if not _TEAM_SLUG_RE.fullmatch(team_slug) or not _DEVICE_ID_RE.fullmatch(device_id):
            raise ValueError("team slug or device id has an invalid shape")
        self.api_client = api_client
        self.team_slug = team_slug
        self.device_signer = device_signer
        self.device_id = device_id
        self.key_store = key_store
        self.pins = pins or CaPinStore()
        self.certificate_dir = certificate_dir or Path.home() / ".servonaut" / "certs"

    @property
    def _base_path(self) -> str:
        return f"/api/v1/teams/{self.team_slug}/ssh-ca"

    async def get_status(self) -> CaStatus:
        response = await self.api_client.get(self._base_path)
        enabled = bool(response.get("enabled", False))
        user_ca = response.get("user_ca") or {}
        host_ca = response.get("host_ca") or {}
        user_key = str(user_ca.get("public_key", "")) or None
        host_key = str(host_ca.get("public_key", "")) or None
        user_fingerprint = str(user_ca.get("fingerprint", "")) or None
        host_fingerprint = str(host_ca.get("fingerprint", "")) or None
        if enabled:
            if not all((user_key, host_key, user_fingerprint, host_fingerprint)):
                raise CertificateValidationError("Enabled SSH CA response is incomplete")
            validate_openssh_public_key(user_key)
            validate_openssh_public_key(host_key)
            if _fingerprint(user_key) != user_fingerprint or _fingerprint(host_key) != host_fingerprint:
                raise CertificateValidationError("SSH CA response fingerprint does not match its key")
            # Never persist a first-seen pin until both untrusted keys passed
            # independent local fingerprint verification.
            self.pins.verify_or_pin(
                self.team_slug, CaPins(user_fingerprint, host_fingerprint)
            )
        logins = response.get("my_logins_by_server") or {}
        if not isinstance(logins, Mapping):
            raise CertificateValidationError("SSH CA logins have an invalid shape")
        return CaStatus(
            enabled=enabled,
            user_ca_public_key=user_key,
            host_ca_public_key=host_key,
            user_ca_fingerprint=user_fingerprint,
            host_ca_fingerprint=host_fingerprint,
            policy=response.get("policy") or {},
            logins_by_server={str(key): tuple(map(str, value)) for key, value in logins.items()},
            krl_version=int(response["krl_version"]) if response.get("krl_version") is not None else None,
            raw=response,
        )

    async def enable(self, policy: Mapping[str, Any] | None = None) -> CaStatus:
        body = {"policy": dict(policy)} if policy is not None else None
        await self._signed("POST", self._base_path, body)
        return await self.get_status()

    async def update_policy(self, policy: Mapping[str, Any]) -> tuple[CaStatus, list[str]]:
        """Send the changed policy fields; return the new status and hosts to re-enrol.

        The endpoint takes the policy fields at the top level; omitted fields
        keep their value.
        """
        response = await self._signed("PUT", f"{self._base_path}/policy", dict(policy))
        refresh = response.get("hosts_needing_refresh") if isinstance(response, Mapping) else None
        hosts = [str(host) for host in refresh] if isinstance(refresh, list) else []
        return await self.get_status(), hosts

    async def revoke_certificate(self, serial: int, *, note: str | None = None) -> Mapping[str, Any]:
        """Revoke one issued certificate (owner/admin); hosts refuse it once the new KRL is delivered."""
        body = {"note": note} if note else {}
        return await self._signed("POST", f"{self._base_path}/certs/{int(serial)}/revoke", body)

    def ensure_device_ssh_key(self) -> DeviceSshKey:
        """Create once, then leave encryption and persistence to identity_store."""
        private_key = self.key_store.get_device_ssh_private_key()
        if private_key is None:
            generated = Ed25519PrivateKey.generate()
            private_key = generated.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
            self.key_store.store_device_ssh_private_key(private_key)
        try:
            private = load_ssh_private_key(private_key, password=None)
            if not isinstance(private, Ed25519PrivateKey):
                raise TypeError("not an Ed25519 private key")
            public_key = private.public_key().public_bytes(
                Encoding.OpenSSH, PublicFormat.OpenSSH
            ).decode("ascii")
        except Exception as exc:
            raise CertificateValidationError("Stored device SSH key is not a valid Ed25519 key") from exc
        if not public_key.startswith("ssh-ed25519 "):
            raise CertificateValidationError("Device SSH key must use Ed25519")
        return DeviceSshKey(private_key=private_key, public_key=public_key, fingerprint=_fingerprint(public_key))

    async def register_device_key(self) -> DeviceSshKey:
        key = self.ensure_device_ssh_key()
        await self._signed(
            "PUT",
            f"/api/v1/vault/devices/{self.device_id}/ssh-key",
            {"ssh_public_key": key.public_key},
        )
        return key

    async def issue_certificate(
        self,
        server_ids: Sequence[str],
        *,
        purpose: str = "interactive",
        requested_ttl_seconds: int | None = None,
    ) -> IssuedCertificate:
        """Issue, validate and persist a public user certificate."""
        if purpose not in {"interactive", "automation"} or not server_ids:
            raise ValueError("certificate purpose and at least one server are required")
        status = await self.get_status()
        if not status.enabled or status.user_ca_fingerprint is None:
            raise CertificateValidationError("SSH CA is not enabled for this team")
        body: dict[str, Any] = {"server_ids": list(server_ids), "purpose": purpose}
        if requested_ttl_seconds is not None:
            if requested_ttl_seconds <= 0:
                raise ValueError("requested_ttl_seconds must be positive")
            body["requested_ttl_seconds"] = requested_ttl_seconds
        response = await self._signed("POST", f"{self._base_path}/certs", body)
        return self._validate_and_store_certificate(response, status, server_ids, requested_ttl_seconds, purpose)

    async def renew_if_due(
        self, certificate: IssuedCertificate, server_ids: Sequence[str], *, purpose: str = "interactive"
    ) -> IssuedCertificate | None:
        if datetime.now(timezone.utc) < certificate.renew_after:
            return None
        return await self.issue_certificate(server_ids, purpose=purpose)

    def load_cached_certificate(
        self, server_ids: Sequence[str], *, purpose: str, status: CaStatus
    ) -> IssuedCertificate | None:
        """Return a locally persisted, fully revalidated certificate if available."""
        wanted_servers = tuple(server_ids)
        for serial, path in sorted(self._local_certificate_paths().items(), reverse=True):
            try:
                metadata = json.loads(self._metadata_path(path).read_text(encoding="utf-8"))
                if metadata.get("server_ids") != list(wanted_servers) or metadata.get("purpose") != purpose:
                    continue
                if status.krl_version is not None and metadata.get("krl_version") != status.krl_version:
                    # Members cannot read which serials were revoked, only that the
                    # KRL changed since this certificate was issued. A revoked
                    # certificate would be refused until it expires, so get a new one.
                    continue
                raw_certificate = path.read_text(encoding="ascii").rstrip("\r\n")
                response = {
                    "certificate": raw_certificate,
                    "serial": serial,
                    "principals": metadata["principals"],
                    "logins_by_server": metadata["logins_by_server"],
                    "valid_after": metadata["valid_after"],
                    "valid_before": metadata["valid_before"],
                    "renew_after": metadata["renew_after"],
                    "ca_fingerprint": metadata["ca_fingerprint"],
                }
                return self._validate_and_store_certificate(
                    response, status, wanted_servers, None, purpose, persist=False
                )
            except (OSError, ValueError, KeyError, TypeError, CertificateValidationError):
                continue
        return None

    async def audit_issuance(self, *, expected_head: str | None = None, team_id: str | None = None):
        """Audit the server chain and bind any locally held lease certificates."""
        from .ca_audit import CaIssuanceAuditor

        return await CaIssuanceAuditor(
            self.api_client, self.team_slug, team_id=team_id,
            local_certificates=self._local_certificate_paths(),
        ).audit(expected_head=expected_head)

    async def create_enrollment(
        self,
        server_id: str,
        kind: str,
        *,
        break_glass_item_id: str | None = None,
    ) -> Mapping[str, Any]:
        """Create a pull-based enrolment job; execution remains local to the CLI."""
        if kind not in {"enroll", "refresh", "unenroll"}:
            raise ValueError("invalid SSH CA enrolment kind")
        body: dict[str, Any] = {"server_id": server_id, "kind": kind}
        if break_glass_item_id is not None:
            body["break_glass_item_id"] = break_glass_item_id
        return await self._signed("POST", f"{self._base_path}/enrollments", body)

    async def get_enrollment(self, enrollment_id: str) -> Mapping[str, Any]:
        return await self._signed("GET", f"{self._base_path}/enrollments/{_path_id(enrollment_id)}", None)

    async def claim_enrollment(self, enrollment_id: str) -> Mapping[str, Any]:
        return await self._signed("POST", f"{self._base_path}/enrollments/{_path_id(enrollment_id)}/claim", None)

    async def request_host_certificate(self, enrollment_id: str, host_public_key: str) -> Mapping[str, Any]:
        if not host_public_key.startswith("ssh-ed25519 "):
            raise ValueError("host public key must be an Ed25519 OpenSSH key")
        return await self._signed(
            "POST",
            f"{self._base_path}/enrollments/{_path_id(enrollment_id)}/host-cert",
            {"host_public_key": host_public_key},
        )

    async def report_enrollment_result(
        self, enrollment_id: str, result: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        return await self._signed(
            "POST", f"{self._base_path}/enrollments/{_path_id(enrollment_id)}/result", dict(result)
        )

    async def _signed(self, method: str, path: str, body: dict[str, Any] | None) -> dict[str, Any]:
        result = self.api_client.request_signed(method, path, body, self.device_signer)
        return await result if inspect.isawaitable(result) else result

    def _validate_and_store_certificate(
        self,
        response: Mapping[str, Any],
        status: CaStatus,
        requested_server_ids: Sequence[str],
        requested_ttl_seconds: int | None,
        purpose: str,
        *,
        persist: bool = True,
    ) -> IssuedCertificate:
        raw_certificate = str(response.get("certificate", ""))
        try:
            certificate = load_ssh_public_identity(raw_certificate.encode("ascii"))
            certificate.verify_cert_signature()
            signature_key = certificate.signature_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
        except Exception as exc:
            raise CertificateValidationError("Server returned an invalid OpenSSH certificate") from exc
        if _fingerprint(signature_key) != status.user_ca_fingerprint:
            raise CertificateValidationError("Certificate was not signed by the pinned team user CA")
        if response.get("ca_fingerprint") != status.user_ca_fingerprint:
            raise CertificateValidationError("Certificate response names a different CA fingerprint")
        if certificate.type is not SSHCertificateType.USER or not raw_certificate.startswith("ssh-ed25519-cert-v01@openssh.com "):
            raise CertificateValidationError("Server returned a host certificate where a user certificate was required")
        device_key = self.ensure_device_ssh_key()
        subject = certificate.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
        if subject != device_key.public_key:
            raise CertificateValidationError("Certificate subject does not match this device SSH key")
        principals = tuple(principal.decode("utf-8") for principal in certificate.valid_principals)
        logins = {str(key): tuple(map(str, value)) for key, value in (response.get("logins_by_server") or {}).items()}
        expected = _expected_principals(status, requested_server_ids, logins)
        if set(principals) != expected:
            raise CertificateValidationError("Certificate principals differ from the requested server logins")
        valid_after = _timestamp(response.get("valid_after"))
        valid_before = _timestamp(response.get("valid_before"))
        if certificate.valid_after != int(valid_after.timestamp()) or certificate.valid_before != int(valid_before.timestamp()):
            raise CertificateValidationError("Certificate validity differs from the server response")
        if valid_before <= valid_after or valid_before <= datetime.now(timezone.utc):
            raise CertificateValidationError("Certificate has an invalid validity window")
        if requested_ttl_seconds is not None and (valid_before - valid_after).total_seconds() > requested_ttl_seconds + _CLOCK_SKEW_SECONDS:
            raise CertificateValidationError("Certificate validity exceeds the requested TTL")
        renew_after = _timestamp(response.get("renew_after"))
        if not valid_after <= renew_after < valid_before:
            raise CertificateValidationError("Certificate renewal time is outside its validity window")
        source_cidrs = status.policy.get("source_address_cidrs")
        if source_cidrs:
            actual_source = certificate.critical_options.get(b"source-address")
            expected_source = ",".join(map(str, source_cidrs)).encode("ascii")
            if actual_source != expected_source:
                raise CertificateValidationError("Certificate source-address constraint was relaxed")
        serial = int(response["serial"])
        path = self._write_public_certificate(raw_certificate, serial) if persist else self._certificate_path(serial, raw_certificate)
        issued = IssuedCertificate(
            certificate_path=path,
            certificate=raw_certificate,
            serial=serial,
            principals=principals,
            logins_by_server=logins,
            valid_after=valid_after,
            valid_before=valid_before,
            renew_after=renew_after,
            ca_fingerprint=str(response.get("ca_fingerprint", "")),
            server_ids=tuple(requested_server_ids),
            purpose=purpose,
        )
        if persist:
            self._write_certificate_metadata(issued, krl_version=status.krl_version)
        return issued

    def _write_public_certificate(self, certificate: str, serial: int) -> Path:
        """Persist an immutable certificate artifact for one issued lease."""
        if serial < 0:
            raise CertificateValidationError("Certificate serial is invalid")
        directory = self.certificate_dir / self.team_slug
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        target = self._certificate_path(serial, certificate)
        fd, temporary = tempfile.mkstemp(dir=directory, prefix=".certificate.", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(certificate.rstrip() + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            os.chmod(target, 0o600)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        return target

    def _certificate_path(self, serial: int, certificate: str) -> Path:
        digest = hashlib.sha256(certificate.encode("ascii")).hexdigest()[:24]
        return self.certificate_dir / self.team_slug / f"{self.device_id}-{serial}-{digest}.cert.pub"

    @staticmethod
    def _metadata_path(certificate_path: Path) -> Path:
        return certificate_path.with_suffix(".json")

    def _write_certificate_metadata(self, certificate: IssuedCertificate, *, krl_version: int | None) -> None:
        target = self._metadata_path(certificate.certificate_path)
        fd, temporary = tempfile.mkstemp(dir=target.parent, prefix=".certificate-meta.", suffix=".tmp")
        metadata = {
            "server_ids": list(certificate.server_ids),
            "purpose": certificate.purpose,
            "principals": list(certificate.principals),
            "logins_by_server": {key: list(value) for key, value in certificate.logins_by_server.items()},
            "valid_after": certificate.valid_after.isoformat(),
            "valid_before": certificate.valid_before.isoformat(),
            "renew_after": certificate.renew_after.isoformat(),
            "ca_fingerprint": certificate.ca_fingerprint,
            "krl_version": krl_version,
        }
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(metadata, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            os.chmod(target, 0o600)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def _local_certificate_paths(self) -> dict[int, Path]:
        directory = self.certificate_dir / self.team_slug
        if not directory.is_dir():
            return {}
        pattern = re.compile(
            rf"^{re.escape(self.device_id)}-(\d+)-[0-9a-f]{{24}}\.cert\.pub$"
        )
        paths: dict[int, Path] = {}
        for candidate in directory.iterdir():
            match = pattern.fullmatch(candidate.name)
            if match is not None and candidate.is_file():
                paths[int(match.group(1))] = candidate
        return paths


def _fingerprint(public_key: str) -> str:
    validate_openssh_public_key(public_key)
    try:
        blob = base64.b64decode(public_key.split()[1], validate=True)
    except (IndexError, ValueError, UnicodeError) as exc:
        raise CertificateValidationError("Invalid OpenSSH public key") from exc
    return openssh_fingerprint(blob)


def validate_openssh_public_key(value: str) -> str:
    """Accept exactly one canonical OpenSSH public-key line, optional comment."""
    if not isinstance(value, str) or not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise CertificateValidationError("OpenSSH public key must be one printable line")
    fields = value.split(" ", 2)
    if len(fields) < 2 or not fields[0] or not fields[1] or (len(fields) == 3 and not fields[2]):
        raise CertificateValidationError("OpenSSH public key has an invalid shape")
    if fields[0] not in {"ssh-ed25519", "ecdsa-sha2-nistp256"}:
        raise CertificateValidationError("OpenSSH public key uses an unsupported CA algorithm")
    try:
        blob = base64.b64decode(fields[1], validate=True)
        parsed = load_ssh_public_key((fields[0] + " " + fields[1]).encode("ascii"))
        canonical = parsed.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
    except Exception as exc:
        raise CertificateValidationError("OpenSSH public key is invalid") from exc
    if canonical != fields[0] + " " + fields[1] or not blob:
        raise CertificateValidationError("OpenSSH public key is not canonical")
    return value


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise CertificateValidationError("Certificate timestamp is missing")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        raise CertificateValidationError("Certificate timestamp is invalid") from exc


def _expected_principals(
    status: CaStatus, requested_server_ids: Sequence[str], response_logins: Mapping[str, tuple[str, ...]]
) -> set[str]:
    server_ids = tuple(status.logins_by_server) if tuple(requested_server_ids) == ("*",) else tuple(requested_server_ids)
    if not server_ids or any(server_id not in status.logins_by_server for server_id in server_ids):
        raise CertificateValidationError("Certificate response names an unrequested server")
    expected: set[str] = set()
    for server_id in server_ids:
        expected_logins = set(status.logins_by_server[server_id])
        actual_logins = set(response_logins.get(server_id, ()))
        if not actual_logins or actual_logins != expected_logins:
            raise CertificateValidationError("Certificate response logins differ from the requested server logins")
        expected.update(f"svn:{server_id}:{login}" for login in actual_logins)
    return expected


def _path_id(value: str) -> str:
    if not _DEVICE_ID_RE.fullmatch(value):
        raise ValueError("path identifier has an invalid shape")
    return value
