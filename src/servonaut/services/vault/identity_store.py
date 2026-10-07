"""Trusted local custody for a Team Vault identity and device keys."""
from __future__ import annotations

import base64
import json
import os
import stat
import tempfile
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Protocol

from servonaut.services.memory.crypto import secure_zero

from .crypto import (
    VaultCryptoError,
    decode_bundle,
    encode_bundle,
    identity_fingerprint,
    open_wrap,
    public_from_seed,
    seal_wrap,
    sign,
    wrap_aad,
    x25519_public,
)
from .errors import NO_LOCAL_IDENTITY, VaultUserError


class IdentityStoreError(VaultUserError):
    """Raised when local identity custody cannot be safely established."""


class DeviceSigner(Protocol):
    """Minimal signer accepted by :meth:`APIClient.request_signed`."""

    @property
    def device_id(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


@dataclass
class LocalDevice:
    """Private device material, held only after decrypting local storage."""

    device_id: str
    signing_seed: bytearray = field(repr=False)
    encryption_secret_key: bytearray = field(repr=False)

    def __post_init__(self) -> None:
        self.signing_seed = bytearray(self.signing_seed)
        self.encryption_secret_key = bytearray(self.encryption_secret_key)

    @property
    def signing_public_key(self) -> bytes:
        return public_from_seed(bytes(self.signing_seed))

    @property
    def encryption_public_key(self) -> bytes:
        return x25519_public(bytes(self.encryption_secret_key))

    def sign(self, message: bytes) -> bytes:
        return sign(bytes(self.signing_seed), message)


@dataclass
class LocalIdentity:
    """The decrypted identity bundle and its device private keys."""

    identity_id: str
    user_id: int
    signing_seed: bytearray = field(repr=False)
    encryption_secret_key: bytearray = field(repr=False)
    device: LocalDevice
    device_ssh_private_key: bytearray | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.signing_seed = bytearray(self.signing_seed)
        self.encryption_secret_key = bytearray(self.encryption_secret_key)
        if self.device_ssh_private_key is not None:
            self.device_ssh_private_key = bytearray(self.device_ssh_private_key)

    @property
    def signing_public_key(self) -> bytes:
        return public_from_seed(bytes(self.signing_seed))

    @property
    def encryption_public_key(self) -> bytes:
        return x25519_public(bytes(self.encryption_secret_key))

    @property
    def fingerprint_raw(self) -> bytes:
        return identity_fingerprint(self.signing_public_key, self.encryption_public_key)

    @property
    def fingerprint(self) -> str:
        return self.fingerprint_raw.hex()


class IdentityStore:
    """Store encrypted local identity material using an OS keyring KEK.

    File storage is deliberately opt-in.  The environment fallback exists for
    hermetic CI only and must be supplied explicitly by the caller, avoiding a
    surprising production dependency on a process environment secret.
    """

    _KEYRING_SERVICE = "servonaut-vault-device-kek-v1"

    def __init__(
        self,
        path: Path | None = None,
        *,
        allow_file_key_store: bool = False,
        environment_key: str | None = None,
    ) -> None:
        if path is None:
            custody_root = ensure_default_custody_root()
            self._path = custody_root / "vault" / "vault_keys.json"
        else:
            self._path = path
        self._allow_file_key_store = allow_file_key_store
        self._environment_key = environment_key
        self._identity: LocalIdentity | None = None

    @property
    def identity(self) -> LocalIdentity | None:
        return self._identity

    @property
    def path(self) -> Path:
        """The encrypted custody path, including caller-supplied test paths."""
        return self._path

    @property
    def allow_file_key_store(self) -> bool:
        return self._allow_file_key_store

    @allow_file_key_store.setter
    def allow_file_key_store(self, value: bool) -> None:
        self._allow_file_key_store = bool(value)

    def has_persisted_identity(self) -> bool:
        """Whether durable custody is present without unlocking or modifying it."""
        return self._path.exists()

    def signer(self) -> DeviceSigner:
        if self._identity is None:
            raise IdentityStoreError(NO_LOCAL_IDENTITY)
        return self._identity.device

    def get_device_ssh_private_key(self) -> bytes | None:
        """Return the unlocked device SSH private key, if one was enrolled."""
        if self._identity is None or self._identity.device_ssh_private_key is None:
            return None
        return bytes(self._identity.device_ssh_private_key)

    def store_device_ssh_private_key(self, private_key: bytes) -> None:
        """Persist device SSH material inside the existing encrypted bundle."""
        if not isinstance(private_key, bytes) or not private_key:
            raise IdentityStoreError("Device SSH private key must be non-empty bytes")
        identity = self._identity
        if identity is None:
            raise IdentityStoreError(NO_LOCAL_IDENTITY)
        replacement = replace(identity, device_ssh_private_key=bytearray(private_key))
        # ``save`` zeroes what the old bundle held but the replacement does not
        # share: here only the previous device SSH key, never the signing keys.
        self.save(replacement)

    def adopt(self, identity: LocalIdentity) -> None:
        """Make an already verified recovered/approved identity the current one."""
        self._identity = identity

    def create(self, *, identity_id: str, user_id: int, device_id: str | None = None) -> LocalIdentity:
        """Generate a new identity and first-device key set in memory."""
        identity = self.generate_identity(identity_id=identity_id, user_id=user_id, device_id=device_id)
        self._identity = identity
        return identity

    @staticmethod
    def generate_identity(
        *, identity_id: str, user_id: int, device_id: str | None = None
    ) -> LocalIdentity:
        """Generate an identity without changing the currently unlocked one."""
        return LocalIdentity(
            identity_id=_uuid(identity_id, "identity_id"),
            user_id=_positive_user_id(user_id),
            signing_seed=os.urandom(32),
            encryption_secret_key=os.urandom(32),
            device=LocalDevice(
                device_id=_uuid(device_id or str(uuid.uuid4()), "device_id"),
                signing_seed=os.urandom(32),
                encryption_secret_key=os.urandom(32),
            ),
        )

    def save(self, identity: LocalIdentity | None = None) -> None:
        """Encrypt and atomically persist identity and device secrets."""
        identity = identity or self._identity
        if identity is None:
            raise IdentityStoreError("Cannot save an empty Team Vault identity")
        kek, source = self._load_or_create_kek(identity.user_id, identity.device.device_id)
        aad = wrap_aad("device", identity.identity_id, identity.user_id, identity.fingerprint_raw)
        payload = encode_bundle(bytes(identity.signing_seed), bytes(identity.encryption_secret_key))
        ssh_key = identity.device_ssh_private_key or b""
        payload += identity.device.signing_seed + identity.device.encryption_secret_key
        payload += len(ssh_key).to_bytes(4, "big") + ssh_key
        blob = seal_wrap(kek, payload, aad)
        document = {
            "v": 1,
            "identity_id": identity.identity_id,
            "user_id": identity.user_id,
            "fingerprint": identity.fingerprint,
            "device": {
                "device_id": identity.device.device_id,
                "sig_public_key": _b64(identity.device.signing_public_key),
                "enc_public_key": _b64(identity.device.encryption_public_key),
            },
            "key_source": source,
            "blob": _b64(blob),
        }
        previous = self._identity
        _write_private_json(self._path, document)
        self._identity = identity
        if previous is not None and previous is not identity:
            self._zero_identity(previous, keep=identity)

    def load(self) -> LocalIdentity:
        """Unlock stored material and verify all public metadata before use."""
        document = _read_private_json(self._path)
        try:
            if document.get("v") != 1:
                raise ValueError("unsupported version")
            identity_id = _uuid(str(document["identity_id"]), "identity_id")
            user_id = _positive_user_id(document["user_id"])
            fingerprint = bytes.fromhex(str(document["fingerprint"]))
            if len(fingerprint) != 32:
                raise ValueError("fingerprint")
            device = document["device"]
            if not isinstance(device, dict):
                raise ValueError("device")
            device_id = _uuid(str(device["device_id"]), "device_id")
            blob = _b64_decode(str(document["blob"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise IdentityStoreError("Vault identity storage has an invalid shape") from exc
        kek, _source = self._load_or_create_kek(user_id, device_id, create=False)
        try:
            plain = open_wrap(kek, blob, wrap_aad("device", identity_id, user_id, fingerprint))
            signing_seed, encryption_secret_key = decode_bundle(plain[:69])
            if len(plain) < 137:
                raise VaultCryptoError("local device key payload has invalid length")
            ssh_length = int.from_bytes(plain[133:137], "big")
            if len(plain) != 137 + ssh_length:
                raise VaultCryptoError("local device SSH payload has invalid length")
            local = LocalIdentity(
                identity_id=identity_id,
                user_id=user_id,
                signing_seed=signing_seed,
                encryption_secret_key=encryption_secret_key,
                device=LocalDevice(device_id, plain[69:101], plain[101:133]),
                device_ssh_private_key=plain[137:] or None,
            )
        except VaultCryptoError as exc:
            raise IdentityStoreError("Vault identity storage failed authentication") from exc
        if local.fingerprint_raw != fingerprint:
            raise IdentityStoreError("Vault identity storage fingerprint mismatch")
        if _b64_decode(str(device["sig_public_key"])) != local.device.signing_public_key:
            raise IdentityStoreError("Vault device signing key metadata mismatch")
        if _b64_decode(str(device["enc_public_key"])) != local.device.encryption_public_key:
            raise IdentityStoreError("Vault device encryption key metadata mismatch")
        self._identity = local
        return local

    def wipe(self) -> None:
        """Remove local encrypted material and its keyring entry when possible."""
        device_id = self._identity.device.device_id if self._identity else None
        user_id = self._identity.user_id if self._identity else None
        if device_id is None and self._path.exists():
            try:
                document = _read_private_json(self._path)
                device_id = str(document.get("device", {}).get("device_id", ""))
                candidate_user_id = document.get("user_id")
                user_id = candidate_user_id if type(candidate_user_id) is int else None
            except IdentityStoreError:
                pass
        if self._path.exists():
            _require_private_file(self._path)
            self._path.unlink()
        if device_id and user_id:
            _delete_keyring_value(user_id, device_id)
        if self._identity is not None:
            self._zero_identity(self._identity)
        self._identity = None

    def wipe_memory(self) -> None:
        """Zero only the currently unlocked material, retaining durable custody."""
        if self._identity is not None:
            self._zero_identity(self._identity)
        self._identity = None

    def lock(self) -> None:
        """Lock this process's identity without deleting encrypted custody."""
        self.wipe_memory()

    @staticmethod
    def _zero_identity(identity: LocalIdentity, *, keep: LocalIdentity | None = None) -> None:
        """Zero *identity*'s secrets, except buffers still used by *keep*.

        A replacement made with ``dataclasses.replace`` shares the unchanged
        buffers (and the device) with the bundle it replaces; zeroing those
        would wipe the identity that stays current.
        """
        def buffers(value: LocalIdentity) -> list[Any]:
            return [value.signing_seed, value.encryption_secret_key, value.device.signing_seed,
                    value.device.encryption_secret_key, value.device_ssh_private_key]

        kept = [] if keep is None else buffers(keep)
        for buffer in buffers(identity):
            if buffer is not None and not any(buffer is other for other in kept):
                secure_zero(buffer)

    def _load_or_create_kek(self, user_id: int, device_id: str, *, create: bool = True) -> tuple[bytes, str]:
        env_key = self._environment_key
        if env_key is None:
            env_key = os.environ.get("SERVONAUT_VAULT_DEVICE_KEY")
        if env_key:
            return _decode_kek(env_key), "environment"
        stored = _get_keyring_value(user_id, device_id)
        if stored:
            return _decode_kek(stored), "keyring"
        if self._allow_file_key_store:
            key_path = self._path.with_name("device-kek")
            if key_path.exists():
                return self._load_or_create_file_kek(b"", create=False), "file"
        if not create:
            raise IdentityStoreError("The OS keyring does not contain this device key")
        key = os.urandom(32)
        if _set_keyring_value(user_id, device_id, _b64(key)):
            return key, "keyring"
        if self._allow_file_key_store:
            return self._load_or_create_file_kek(key, create=True), "file"
        raise IdentityStoreError(
            "no trusted OS keyring is available; turn on Settings > Team Vault > "
            "Allow encrypted file key storage (`vault.allow_file_key_store` in config.json), "
            "or provide SERVONAUT_VAULT_DEVICE_KEY"
        )

    def _load_or_create_file_kek(self, generated: bytes, *, create: bool) -> bytes:
        key_path = self._path.with_name("device-kek")
        if key_path.exists():
            _require_private_file(key_path)
            return _decode_kek(key_path.read_text(encoding="ascii").strip())
        if not create:
            raise IdentityStoreError("The explicit file device key is missing")
        _write_private_bytes(key_path, _b64(generated).encode("ascii"))
        return generated


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64_decode(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("invalid base64") from exc
    if _b64(decoded) != value:
        raise ValueError("non-canonical base64")
    return decoded


def _decode_kek(value: str) -> bytes:
    decoded = _b64_decode(value)
    if len(decoded) != 32:
        raise IdentityStoreError("Vault device key must be 32 bytes")
    return decoded


def _uuid(value: str, name: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{name} must be a UUID") from exc
    if str(parsed) != value or parsed.version != 4:
        raise ValueError(f"{name} must be a canonical UUIDv4")
    return value


def _positive_user_id(value: int) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("user_id must be positive")
    return value


def ensure_default_custody_root() -> Path:
    """Securely create or migrate the default ``~/.servonaut`` root.

    Earlier login/config paths created this shared directory with the process
    umask, commonly ``0755`` or ``0775``.  Team Vault custody needs a private
    root for the encrypted bundle and the process-scoped SSH-agent socket.
    Tighten only a directory opened through an ``O_NOFOLLOW`` descriptor after
    confirming it is owned by this user and is a real directory.
    """
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise IdentityStoreError("Vault custody root cannot be secured on this platform")

    home = Path.home()
    flags = os.O_RDONLY | directory | nofollow
    try:
        home_fd = os.open(home, flags)
    except OSError as exc:
        raise IdentityStoreError("Vault custody home directory cannot be inspected") from exc
    try:
        _require_owned_directory_fd(home_fd, "Vault custody home directory")
        try:
            os.mkdir(".servonaut", mode=0o700, dir_fd=home_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            raise IdentityStoreError("Vault custody root cannot be created") from exc
        try:
            root_fd = os.open(".servonaut", flags, dir_fd=home_fd)
        except OSError as exc:
            raise IdentityStoreError("Vault custody root is unsafe") from exc
    finally:
        os.close(home_fd)

    try:
        _require_owned_directory_fd(root_fd, "Vault custody root")
        info = os.fstat(root_fd)
        if info.st_mode & 0o077:
            try:
                os.fchmod(root_fd, 0o700)
            except OSError as exc:
                raise IdentityStoreError("Vault custody root permissions cannot be secured") from exc
        _require_owned_directory_fd(
            root_fd, "Vault custody root", require_private=True,
        )
    finally:
        os.close(root_fd)
    return home / ".servonaut"


def _require_owned_directory_fd(
    fd: int, label: str, *, require_private: bool = False,
) -> None:
    """Verify the directory currently held by *fd*, without path races."""
    try:
        info = os.fstat(fd)
    except OSError as exc:
        raise IdentityStoreError(f"{label} cannot be inspected") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise IdentityStoreError(f"{label} is unsafe")
    if info.st_uid != os.getuid():
        raise IdentityStoreError(f"{label} has unsafe ownership")
    if require_private and info.st_mode & 0o077:
        raise IdentityStoreError(f"{label} has unsafe permissions")


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise IdentityStoreError("Vault key directory is unsafe")
    if info.st_mode & 0o077:
        os.chmod(path, 0o700)


def _require_private_file(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise IdentityStoreError("Vault key path is unsafe")
    if info.st_mode & 0o077:
        raise IdentityStoreError("Vault key file permissions are too broad")


def _read_private_json(path: Path) -> dict[str, Any]:
    _require_private_file(path)
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise IdentityStoreError("Vault identity storage cannot be read") from exc
    if not isinstance(data, dict):
        raise IdentityStoreError("Vault identity storage is not an object")
    return data


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    _write_private_bytes(path, json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _write_private_bytes(path: Path, value: bytes) -> None:
    _ensure_private_directory(path.parent)
    if path.exists():
        _require_private_file(path)
    fd, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def _keyring_module() -> Any | None:
    try:
        import keyring
        backend = keyring.get_keyring()
    except Exception:
        return None
    module = type(backend).__module__ or ""
    allowed = (
        "keyring.backends.SecretService", "keyring.backends.secretservice", "keyring.backends.kwallet",
        "keyring.backends.macOS", "keyring.backends.Keyring", "keyring.backends.Windows",
        "keyring.backends.CredentialLocker", "keyring.backends.chainer",
    )
    return keyring if any(module.startswith(prefix) for prefix in allowed) else None


def _keyring_account(user_id: int, device_id: str) -> str:
    return f"{user_id}:{device_id}"


def _get_keyring_value(user_id: int, device_id: str) -> str | None:
    keyring = _keyring_module()
    if keyring is None:
        return None
    try:
        return keyring.get_password(IdentityStore._KEYRING_SERVICE, _keyring_account(user_id, device_id))
    except Exception:
        return None


def _set_keyring_value(user_id: int, device_id: str, value: str) -> bool:
    keyring = _keyring_module()
    if keyring is None:
        return False
    try:
        keyring.set_password(IdentityStore._KEYRING_SERVICE, _keyring_account(user_id, device_id), value)
    except Exception:
        return False
    return True


def _delete_keyring_value(user_id: int, device_id: str) -> None:
    keyring = _keyring_module()
    if keyring is None:
        return
    try:
        keyring.delete_password(IdentityStore._KEYRING_SERVICE, _keyring_account(user_id, device_id))
    except Exception:
        pass
