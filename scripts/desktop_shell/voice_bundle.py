"""Stage and verify the managed voice runtime inputs of a desktop payload.

The desktop payload never runs the voice engines in-process. It carries only
what the app needs to provision them on demand: a pinned ``uv`` executable,
the product wheel, the target's hash-locked requirements and a manifest that
binds their SHA-256 digests to the pinned Python release and time bounds.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from scripts.desktop_shell.model import (
    VOICE_MANIFEST_NAME,
    VOICE_REQUIREMENTS_NAME,
    DesktopPolicyValidationError,
    DesktopTargetSpec,
    VoiceRuntimePolicy,
    voice_lock_path,
)
from scripts.desktop_shell.native_headers import NativeHeaderError, read_native_identity
from scripts.standalone_cli.pinned_asset import (
    AssetRules,
    Opener,
    check_download_url,
    download_pinned_asset,
    extract_pinned_member,
)

_MANIFEST_SCHEMA_VERSION = 1
_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "target",
        "python_version",
        "uv",
        "wheel",
        "requirements",
        "timeouts",
    }
)
_FILE_KEYS = frozenset({"filename", "sha256"})
_TIMEOUT_KEYS = frozenset({"uv_command_seconds", "stall_seconds", "provision_seconds"})
_NATIVE_FORMATS = {"win32": "pe", "linux": "elf", "darwin": "macho"}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# Pins use canonical (PEP 503) names; every pin carries at least one hash.
_PIN_RE = re.compile(r"^([a-z0-9]+(?:-[a-z0-9]+)*)==([0-9][0-9A-Za-z.+!]*) \\$")
_HASH_RE = re.compile(r"^    --hash=sha256:([0-9a-f]{64})( \\)?$")
_CHUNK_BYTES = 1024 * 1024
# Locks and manifests are small text files; anything larger is not ours.
_MAX_TEXT_BYTES = 1024 * 1024


class VoiceBundleError(DesktopPolicyValidationError):
    """Raised when the managed voice runtime inputs are missing, unsafe or altered."""


def _unused_url_rule(url: str, is_redirect: bool) -> None:
    raise VoiceBundleError("uv download URL is invalid")


# The label and error type of uv URL checks; its own URL rule is never used.
_UV_ERRORS = AssetRules("uv", VoiceBundleError, _unused_url_rule)


@dataclass(frozen=True)
class VoiceLockPin:
    """One exact, hash-pinned distribution of a voice runtime lock."""

    name: str
    version: str
    sha256: tuple[str, ...]


@dataclass(frozen=True)
class BundledFile:
    """A file of the voice bundle and its SHA-256 digest."""

    filename: str
    sha256: str


@dataclass(frozen=True)
class VoiceBundleManifest:
    """The packaged manifest the app verifies before it provisions voice."""

    target: str
    python_version: str
    uv: BundledFile
    wheel: BundledFile
    requirements: BundledFile
    uv_command_seconds: int
    stall_seconds: int
    provision_seconds: int

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": _MANIFEST_SCHEMA_VERSION,
            "target": self.target,
            "python_version": self.python_version,
            "uv": _file_json(self.uv),
            "wheel": _file_json(self.wheel),
            "requirements": _file_json(self.requirements),
            "timeouts": {
                "uv_command_seconds": self.uv_command_seconds,
                "stall_seconds": self.stall_seconds,
                "provision_seconds": self.provision_seconds,
            },
        }


def expected_wheel_name(product_version: str) -> str:
    """Return the file name of the pure-Python product wheel for a version."""
    return f"servonaut-{product_version}-py3-none-any.whl"


def load_voice_lock(path: Path) -> tuple[VoiceLockPin, ...]:
    """Read and parse a voice lock file."""
    return parse_voice_lock(_read_bounded_text(path), path.name)


def parse_voice_lock(text: str, name: str) -> tuple[VoiceLockPin, ...]:
    """Parse a voice lock that holds only ``name==version`` pins with hashes."""
    if "\r" in text:
        # A checkout that converts line endings would change the reviewed bytes
        # the packaged manifest hashes, so only LF is accepted.
        raise VoiceBundleError(f"{name} must use LF line endings")
    pins: list[VoiceLockPin] = []
    pending: tuple[str, str] | None = None
    hashes: list[str] = []
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    for number, line in enumerate(lines, start=1):
        if pending is not None:
            match = _HASH_RE.fullmatch(line)
            if match is None:
                raise VoiceBundleError(f"{name}:{number}: expected a --hash line")
            hashes.append(match.group(1))
            if match.group(2) is None:
                pins.append(VoiceLockPin(*pending, tuple(hashes)))
                pending, hashes = None, []
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _PIN_RE.fullmatch(line)
        if match is None:
            raise VoiceBundleError(
                f"{name}:{number}: only name==version pins with hashes are allowed"
            )
        pending = (match.group(1), match.group(2))
    if pending is not None:
        raise VoiceBundleError(f"{name}: the last pin has no final hash line")
    names = [pin.name for pin in pins]
    if not pins or len(names) != len(set(names)):
        raise VoiceBundleError(f"{name}: pins must be present and unique")
    return tuple(pins)


def stage_voice_bundle(
    staging_root: Path,
    target: DesktopTargetSpec,
    wheel: Path,
    product_version: str,
    policy: VoiceRuntimePolicy,
    *,
    opener: Opener | None = None,
) -> Path:
    """Create ``<staging_root>/voice`` holding exactly the voice runtime inputs.

    The pinned uv archive is the only download: it is fetched over https within
    the policy's size and time bounds, its SHA-256 is verified, and only then is
    the single uv executable copied out of it.
    """
    wheel_name = expected_wheel_name(product_version)
    if wheel.name != wheel_name:
        raise VoiceBundleError(f"the product wheel must be named {wheel_name}")
    lock = voice_lock_path(target.name)
    load_voice_lock(lock)
    archive_spec = policy.uv_archives[target.name]
    voice_dir = staging_root / "voice"
    voice_dir.mkdir()
    uv_path = voice_dir / archive_spec.executable_name
    fetch_uv(policy, target, uv_path, opener=opener)
    shutil.copyfile(wheel, voice_dir / wheel_name)
    shutil.copyfile(lock, voice_dir / VOICE_REQUIREMENTS_NAME)
    manifest = _manifest_for(voice_dir, target, wheel_name, policy)
    (voice_dir / VOICE_MANIFEST_NAME).write_text(
        json.dumps(manifest.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return voice_dir


def verify_voice_bundle(
    voice_dir: Path,
    target: DesktopTargetSpec,
    product_version: str,
    policy: VoiceRuntimePolicy,
) -> VoiceBundleManifest:
    """Require exactly the voice runtime inputs, matching their manifest and policy."""
    status = _lstat(voice_dir, "voice bundle directory")
    if not stat.S_ISDIR(status.st_mode):
        raise VoiceBundleError("voice bundle directory must be a real directory")
    wheel_name = expected_wheel_name(product_version)
    uv_name = policy.uv_archives[target.name].executable_name
    expected = {uv_name, wheel_name, VOICE_REQUIREMENTS_NAME, VOICE_MANIFEST_NAME}
    actual = {entry.name for entry in voice_dir.iterdir()}
    if actual != expected:
        raise VoiceBundleError(
            "voice bundle files differ from policy: "
            f"missing {sorted(expected - actual)}, unexpected {sorted(actual - expected)}"
        )
    for name in expected:
        if not stat.S_ISREG(_lstat(voice_dir / name, name).st_mode):
            raise VoiceBundleError(f"voice bundle file must be a regular file: {name}")
    manifest = parse_voice_manifest(
        _loads_unique(_read_bounded_text(voice_dir / VOICE_MANIFEST_NAME))
    )
    if manifest != _manifest_for(voice_dir, target, wheel_name, policy):
        raise VoiceBundleError(
            "voice manifest does not match the bundled files or the voice runtime policy"
        )
    if manifest.requirements.sha256 != _sha256_file(voice_lock_path(target.name)):
        raise VoiceBundleError("voice requirements differ from the reviewed target lock")
    require_uv_identity(voice_dir / uv_name, target)
    return manifest


def parse_voice_manifest(raw: object) -> VoiceBundleManifest:
    """Strictly parse the packaged voice manifest."""
    if not isinstance(raw, dict) or set(raw) != _MANIFEST_KEYS:
        raise VoiceBundleError("voice manifest has unsupported or missing fields")
    if type(raw["schema_version"]) is not int or (
        raw["schema_version"] != _MANIFEST_SCHEMA_VERSION
    ):
        raise VoiceBundleError("voice manifest schema_version is unsupported")
    for field in ("target", "python_version"):
        if not isinstance(raw[field], str) or not raw[field]:
            raise VoiceBundleError(f"voice manifest {field} must be a string")
    timeouts = raw["timeouts"]
    if not isinstance(timeouts, dict) or set(timeouts) != _TIMEOUT_KEYS:
        raise VoiceBundleError("voice manifest timeouts are malformed")
    for field, value in timeouts.items():
        if type(value) is not int or value <= 0:
            raise VoiceBundleError(f"voice manifest timeout {field} is invalid")
    return VoiceBundleManifest(
        target=raw["target"],
        python_version=raw["python_version"],
        uv=_parse_file(raw["uv"], "uv"),
        wheel=_parse_file(raw["wheel"], "wheel"),
        requirements=_parse_file(raw["requirements"], "requirements"),
        uv_command_seconds=timeouts["uv_command_seconds"],
        stall_seconds=timeouts["stall_seconds"],
        provision_seconds=timeouts["provision_seconds"],
    )


def fetch_uv(
    policy: VoiceRuntimePolicy,
    target: DesktopTargetSpec,
    destination: Path,
    *,
    opener: Opener | None = None,
) -> None:
    """Fetch the target's pinned uv archive and extract its verified executable.

    The archive is the only download: it must come from the pinned origin over
    https, redirect only to the reviewed hosts, stay within the size and time
    bounds and match its pinned SHA-256 before anything is extracted from it.
    """
    spec = policy.uv_archives[target.name]
    rules = uv_asset_rules(policy)
    with tempfile.TemporaryDirectory(dir=destination.parent) as download_dir:
        archive = Path(download_dir) / "uv-archive"
        download_pinned_asset(
            rules,
            spec.url,
            archive,
            spec.sha256,
            max_bytes=policy.max_archive_bytes,
            deadline_seconds=policy.download_timeout_seconds,
            socket_timeout_seconds=policy.socket_timeout_seconds,
            opener=opener,
        )
        extract_pinned_member(
            rules,
            archive,
            spec.archive_format,
            str(spec.member),
            destination,
            policy.max_member_bytes,
        )
    if target.platform != "win32":
        destination.chmod(0o755)
    require_uv_identity(destination, target)


def uv_asset_rules(policy: VoiceRuntimePolicy) -> AssetRules:
    """uv archives start on the pinned origin and redirect only to reviewed hosts."""

    def validate(url: str, is_redirect: bool) -> None:
        hosts = policy.uv_redirect_hosts if is_redirect else {policy.uv_origin_host}
        _validate_download_url(url, frozenset(hosts), is_redirect=is_redirect)

    return AssetRules("uv", VoiceBundleError, validate)


def _validate_download_url(
    value: str, allowed_hosts: frozenset[str], *, is_redirect: bool
) -> None:
    check_download_url(_UV_ERRORS, value, allowed_hosts, is_redirect=is_redirect)


def require_uv_identity(path: Path, target: DesktopTargetSpec) -> None:
    """Require a uv executable built for the target's format and CPU."""
    try:
        identity = read_native_identity(path)
    except NativeHeaderError as error:
        raise VoiceBundleError(f"uv executable header is invalid: {error}") from error
    expected = _NATIVE_FORMATS[target.platform]
    if identity is None or identity.format != expected:
        raise VoiceBundleError(f"uv executable is not a {expected} binary")
    if identity.architecture != target.architecture:
        raise VoiceBundleError(
            f"uv executable architecture {identity.architecture!r} does not match "
            f"target {target.architecture!r}"
        )
    if target.platform != "win32" and not path.stat().st_mode & 0o111:
        raise VoiceBundleError("uv executable is not executable")


def _manifest_for(
    voice_dir: Path,
    target: DesktopTargetSpec,
    wheel_name: str,
    policy: VoiceRuntimePolicy,
) -> VoiceBundleManifest:
    uv_name = policy.uv_archives[target.name].executable_name
    return VoiceBundleManifest(
        target=target.name,
        python_version=policy.python_version,
        uv=_bundled(voice_dir, uv_name),
        wheel=_bundled(voice_dir, wheel_name),
        requirements=_bundled(voice_dir, VOICE_REQUIREMENTS_NAME),
        uv_command_seconds=policy.uv_command_timeout_seconds,
        stall_seconds=policy.stall_timeout_seconds,
        provision_seconds=policy.provision_timeout_seconds,
    )


def _bundled(voice_dir: Path, name: str) -> BundledFile:
    return BundledFile(filename=name, sha256=_sha256_file(voice_dir / name))


def _file_json(bundled: BundledFile) -> dict[str, str]:
    return {"filename": bundled.filename, "sha256": bundled.sha256}


def _parse_file(raw: object, label: str) -> BundledFile:
    if (
        not isinstance(raw, dict)
        or set(raw) != _FILE_KEYS
        or not isinstance(raw["filename"], str)
        or not isinstance(raw["sha256"], str)
        or not _SHA256_RE.fullmatch(raw["sha256"])
    ):
        raise VoiceBundleError(f"voice manifest {label} entry is malformed")
    return BundledFile(filename=raw["filename"], sha256=raw["sha256"])


def _loads_unique(text: str) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        keys = [key for key, _ in pairs]
        if len(keys) != len(set(keys)):
            raise VoiceBundleError("voice manifest repeats a key")
        return dict(pairs)

    try:
        return json.loads(text, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise VoiceBundleError("voice manifest is not valid JSON") from error


def _read_bounded_text(path: Path) -> str:
    status = _lstat(path, path.name)
    if not stat.S_ISREG(status.st_mode) or status.st_size > _MAX_TEXT_BYTES:
        raise VoiceBundleError(f"{path.name} must be a regular file within limits")
    try:
        return path.read_bytes().decode("ascii")
    except (OSError, UnicodeDecodeError) as error:
        raise VoiceBundleError(f"{path.name} could not be read as ASCII text") from error


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise VoiceBundleError(f"{label} is unavailable") from error


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()
