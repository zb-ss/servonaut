"""Typed JSON loading and fail-closed public evidence sanitisation."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import urllib.parse
from collections.abc import Mapping, Sequence
from pathlib import Path

from scripts.standalone_cli.artifact_types import ArtifactEvidenceError

_SAFE_DOCUMENT_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")
_SAFE_FIELD_NAME = re.compile(r"^[A-Za-z0-9$][A-Za-z0-9$_.:-]{0,127}$")
_WINDOWS_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_TOKEN_PREFIX = re.compile(r"\b(?:ghp_|github_pat_|sk-)[A-Za-z0-9_-]{12,}")
_JWT = re.compile(r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?:^|[?&;\s])(?:access[_-]?token|api[_-]?key|password|secret|signature)="
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_POSIX_PATH = re.compile(r"^/")


def load_bounded_json(path: Path, label: str, max_bytes: int) -> object:
    """Load one bounded regular UTF-8 JSON file with duplicate-key rejection."""
    raw = read_bounded_file(path, label, max_bytes)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
    ) as error:
        raise ArtifactEvidenceError(f"{label} is not valid JSON") from error


def read_bounded_file(path: Path, label: str, max_bytes: int) -> bytes:
    """Read a non-symlink regular file without exceeding its configured bound."""
    if not isinstance(path, Path) or not path.is_absolute():
        raise ArtifactEvidenceError(f"{label} path is invalid")
    if type(max_bytes) is not int or max_bytes < 1:
        raise ArtifactEvidenceError(f"{label} size limit is invalid")
    try:
        status = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} is unavailable") from error
    if not stat.S_ISREG(status.st_mode) or resolved != path:
        raise ArtifactEvidenceError(f"{label} is not a regular file")
    if status.st_size > max_bytes:
        raise ArtifactEvidenceError(f"{label} exceeds its size limit")
    try:
        with path.open("rb") as handle:
            raw = handle.read(max_bytes + 1)
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} could not be read") from error
    if len(raw) > max_bytes:
        raise ArtifactEvidenceError(f"{label} exceeds its size limit")
    return raw


def encode_public_json(
    document: object,
    document_name: str,
    *,
    forbidden_roots: Sequence[Path],
    max_bytes: int,
) -> bytes:
    """Validate a typed public document and return canonical JSON bytes."""
    if not _SAFE_DOCUMENT_NAME.fullmatch(document_name):
        raise ArtifactEvidenceError("public evidence document name is invalid")
    if type(max_bytes) is not int or max_bytes < 1:
        raise ArtifactEvidenceError("public evidence size limit is invalid")
    roots = _normalise_forbidden_roots(forbidden_roots)
    _validate_public_tree(document, document_name, roots, max_bytes)
    try:
        encoded = (
            json.dumps(
                document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as error:
        raise ArtifactEvidenceError(
            f"{document_name} is not serialisable public evidence"
        ) from error
    if len(encoded) > max_bytes:
        raise ArtifactEvidenceError(f"{document_name} exceeds its size limit")
    return encoded


def write_public_json(
    destination: Path,
    document: object,
    *,
    forbidden_roots: Sequence[Path],
    max_bytes: int,
    ownership_ledger: list[tuple[Path, tuple[int, int]]] | None = None,
) -> Path:
    """Atomically create one canonical public evidence document."""
    if not isinstance(destination, Path) or not destination.is_absolute():
        raise ArtifactEvidenceError("public evidence destination is invalid")
    document_name = destination.name
    encoded = encode_public_json(
        document,
        document_name,
        forbidden_roots=forbidden_roots,
        max_bytes=max_bytes,
    )
    _require_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise ArtifactEvidenceError(f"{document_name} already exists")
    descriptor = -1
    identity: tuple[int, int] | None = None
    completed = False
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o644,
        )
        status = os.fstat(descriptor)
        identity = (status.st_dev, status.st_ino)
        if ownership_ledger is not None:
            ownership_ledger.append((destination, identity))
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        completed = True
        return destination
    except ArtifactEvidenceError:
        raise
    except OSError as error:
        raise ArtifactEvidenceError(f"{document_name} could not be written") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if identity is not None and not completed:
            _remove_owned_file(destination, identity)


def _validate_public_tree(
    document: object,
    document_name: str,
    forbidden_roots: tuple[str, ...],
    max_bytes: int,
) -> None:
    stack: list[tuple[object, str]] = [(document, "$")]
    visited = 0
    while stack:
        value, field_path = stack.pop()
        visited += 1
        if visited > max_bytes:
            _reject(document_name, field_path, "structural-limit")
        if value is None or isinstance(value, (bool, int)):
            continue
        if isinstance(value, float):
            if not math.isfinite(value):
                _reject(document_name, field_path, "non-finite-number")
            continue
        if isinstance(value, str):
            _validate_public_string(
                value, document_name, field_path, forbidden_roots, max_bytes
            )
            continue
        if isinstance(value, Mapping):
            for key, child in value.items():
                if not isinstance(key, str):
                    _reject(document_name, field_path, "non-string-field")
                _validate_public_string(
                    key, document_name, field_path, forbidden_roots, max_bytes
                )
                safe_key = key if _SAFE_FIELD_NAME.fullmatch(key) else "<field>"
                stack.append((child, f"{field_path}.{safe_key}"))
            continue
        if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
            for index, child in enumerate(value):
                stack.append((child, f"{field_path}[{index}]"))
            continue
        _reject(document_name, field_path, "unsupported-value")


def _validate_public_string(
    value: str,
    document_name: str,
    field_path: str,
    forbidden_roots: tuple[str, ...],
    max_bytes: int,
) -> None:
    if len(value.encode("utf-8")) > max_bytes:
        _reject(document_name, field_path, "string-limit")
    decoded = urllib.parse.unquote(value)
    if _CONTROL.search(value) or _CONTROL.search(decoded):
        _reject(document_name, field_path, "control-character")
    if (
        _PRIVATE_KEY.search(value)
        or _PRIVATE_KEY.search(decoded)
        or _ACCESS_KEY.search(value)
        or _ACCESS_KEY.search(decoded)
        or _TOKEN_PREFIX.search(value)
        or _TOKEN_PREFIX.search(decoded)
        or _JWT.search(value)
        or _JWT.search(decoded)
        or _SECRET_ASSIGNMENT.search(value)
        or _SECRET_ASSIGNMENT.search(decoded)
    ):
        _reject(document_name, field_path, "credential-shape")
    lowered = value.casefold()
    folded = decoded.casefold()
    if any(root in lowered or root in folded for root in forbidden_roots):
        _reject(document_name, field_path, "discovered-local-root")
    if lowered.startswith("file:"):
        _reject(document_name, field_path, "local-uri")
    if lowered.startswith(("http://", "https://")):
        _validate_public_https(value, document_name, field_path)
        return
    if lowered.startswith("pkg:"):
        _validate_purl(value, document_name, field_path)
        return
    if (
        _WINDOWS_PATH.match(value)
        or _WINDOWS_PATH.match(decoded)
        or _POSIX_PATH.match(value)
        or _POSIX_PATH.match(decoded)
    ):
        _reject(document_name, field_path, "absolute-local-path")


def _validate_public_https(value: str, document_name: str, field_path: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        _reject(document_name, field_path, "unsafe-url")
        return
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
    ):
        _reject(document_name, field_path, "unsafe-url")


def _validate_purl(value: str, document_name: str, field_path: str) -> None:
    if (
        not value.startswith("pkg:")
        or any(character.isspace() for character in value)
        or "/" not in value[4:]
        or "@" not in value[4:]
    ):
        _reject(document_name, field_path, "unsafe-purl")


def _normalise_forbidden_roots(roots: Sequence[Path]) -> tuple[str, ...]:
    normalised: set[str] = set()
    for root in roots:
        if not isinstance(root, Path) or not root.is_absolute():
            raise ArtifactEvidenceError("forbidden evidence root is invalid")
        try:
            value = str(root.resolve(strict=True)).casefold()
        except OSError as error:
            raise ArtifactEvidenceError(
                "forbidden evidence root is unavailable"
            ) from error
        if value:
            normalised.add(value)
    return tuple(sorted(normalised))


def _require_directory(path: Path) -> Path:
    try:
        status = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ArtifactEvidenceError(
            "public evidence directory is unavailable"
        ) from error
    if not stat.S_ISDIR(status.st_mode) or resolved != path:
        raise ArtifactEvidenceError("public evidence directory is invalid")
    return resolved


def _remove_owned_file(path: Path, identity: tuple[int, int]) -> None:
    try:
        status = path.lstat()
        if stat.S_ISREG(status.st_mode) and (status.st_dev, status.st_ino) == identity:
            path.unlink()
    except OSError:
        return


def _reject(document_name: str, field_path: str, category: str) -> None:
    raise ArtifactEvidenceError(f"{document_name} rejected at {field_path}: {category}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactEvidenceError("JSON object contains a duplicate field")
        result[key] = value
    return result
