"""Confined raw-payload inspection for standalone artifact evidence."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType

from scripts.standalone_cli.artifact_types import (
    ArtifactDescriptor,
    ArtifactEvidenceError,
    PayloadEntry,
    PayloadSnapshot,
)
from scripts.standalone_cli.evidence_policy_types import EvidenceLimits
from scripts.standalone_cli.model import _wheel_product_version

_REQUIRED_METADATA = (
    PurePosixPath("pyinstaller/warn-servonaut.txt"),
    PurePosixPath("pyinstaller/Analysis-00.toc"),
    PurePosixPath("pyinstaller/PYZ-00.toc"),
    PurePosixPath("resolved/environment.json"),
    PurePosixPath("resolved/licenses.json"),
    PurePosixPath("resolved/sbom-python.cdx.json"),
    PurePosixPath("resolved/build-provenance.json"),
    PurePosixPath("resolved/build-toolchain.json"),
)
_MARKER_NAME = PurePosixPath("servonaut-runtime.json")
_PYTHON_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def snapshot_payload(
    artifact: ArtifactDescriptor, limits: EvidenceLimits
) -> PayloadSnapshot:
    """Return a complete lstat-only payload snapshot after bounded validation."""
    _validate_limits(limits)
    if artifact.archive is not None:
        raise ArtifactEvidenceError("raw payload must not already have an archive")
    root = _regular_directory(artifact.payload_root, "payload root")
    entries, expanded_bytes = _walk_payload(root, artifact.target.platform, limits)
    entry_by_path = {entry.relative_path: entry for entry in entries}
    SnapshotPathResolver(entries, limits.max_payload_entries).validate_links(
        artifact.target.platform
    )
    executable_relative = _relative_regular_file(
        artifact.executable, root, entry_by_path, "executable"
    )
    if PurePosixPath("_internal") not in entry_by_path:
        raise ArtifactEvidenceError("payload is missing the internal runtime directory")
    marker = _read_marker(root, entry_by_path, limits.max_metadata_file_bytes)
    product_version = _wheel_product_version(_regular_file(artifact.wheel, "wheel"))
    _validate_marker(marker, executable_relative, product_version)
    _validate_metadata(artifact, limits.max_metadata_file_bytes)
    provenance = _read_build_provenance(
        artifact, marker, product_version, limits.max_metadata_file_bytes
    )
    toolchain = _read_build_toolchain(artifact, limits.max_metadata_file_bytes)
    _validate_forbidden_paths(entries, artifact.target.forbidden_path_patterns)
    return PayloadSnapshot(
        root=root,
        entries=tuple(entries),
        expanded_regular_bytes=expanded_bytes,
        executable_relative_path=executable_relative,
        marker=MappingProxyType(marker),
        build_provenance=MappingProxyType(provenance),
        build_toolchain=MappingProxyType(toolchain),
    )


def validate_relative_links(
    entries: Iterable[PayloadEntry], platform_name: str, max_steps: int
) -> None:
    """Validate confined relative link targets without dereferencing links."""
    SnapshotPathResolver(entries, max_steps).validate_links(platform_name)


def _walk_payload(
    root: Path, platform_name: str, limits: EvidenceLimits
) -> tuple[list[PayloadEntry], int]:
    entries: list[PayloadEntry] = []
    expanded_bytes = 0
    pending: list[tuple[Path, PurePosixPath]] = [(root, PurePosixPath("."))]
    while pending:
        directory, relative_directory = pending.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            raise ArtifactEvidenceError(
                "payload directory could not be read"
            ) from error
        for child in children:
            relative = _child_relative(relative_directory, child.name)
            try:
                status = child.stat(follow_symlinks=False)
            except OSError as error:
                raise ArtifactEvidenceError(
                    "payload entry could not be read"
                ) from error
            if len(entries) >= limits.max_payload_entries:
                raise ArtifactEvidenceError("payload entry limit exceeded")
            mode = stat.S_IMODE(status.st_mode)
            child_path = Path(child.path)
            if stat.S_ISDIR(status.st_mode):
                entries.append(PayloadEntry(relative, "directory", mode, 0, None, None))
                pending.append((child_path, relative))
                continue
            if stat.S_ISREG(status.st_mode):
                if status.st_nlink != 1:
                    raise ArtifactEvidenceError("payload contains a hard-linked file")
                if status.st_size > limits.max_regular_file_bytes:
                    raise ArtifactEvidenceError("payload regular-file limit exceeded")
                expanded_bytes += status.st_size
                if expanded_bytes > limits.max_expanded_payload_bytes:
                    raise ArtifactEvidenceError("payload expanded-size limit exceeded")
                entries.append(
                    PayloadEntry(
                        relative,
                        "file",
                        mode,
                        status.st_size,
                        _sha256_file(child_path),
                        None,
                    )
                )
                continue
            if stat.S_ISLNK(status.st_mode):
                if platform_name == "win32":
                    raise ArtifactEvidenceError(
                        "Windows payloads cannot contain symbolic links"
                    )
                entries.append(
                    PayloadEntry(
                        relative,
                        "symlink",
                        mode,
                        status.st_size,
                        None,
                        _read_link_target(child_path),
                    )
                )
                continue
            raise ArtifactEvidenceError(
                "payload contains an unsupported filesystem entry"
            )
    entries.sort(key=lambda entry: entry.relative_path.as_posix())
    return entries, expanded_bytes


@dataclass(frozen=True)
class ResolvedPayloadEntry:
    """One manifest entry after confined symbolic-link resolution."""

    relative_path: PurePosixPath
    entry: PayloadEntry


class _TargetCursor:
    """Consume a raw POSIX link target without normalising its components."""

    def __init__(self, raw_target: str) -> None:
        if (
            not raw_target
            or "\x00" in raw_target
            or "\\" in raw_target
            or raw_target.startswith("/")
            or ":" in raw_target
        ):
            raise ArtifactEvidenceError("payload symbolic link target is unsafe")
        self._raw_target = raw_target
        self._offset = 0
        self._finished = False

    def next_component(self) -> str | None:
        """Return the next raw component, retaining terminal slash semantics."""
        if self._finished:
            return None
        start = self._offset
        length = len(self._raw_target)
        while self._offset < length and self._raw_target[self._offset] != "/":
            self._offset += 1
        component = self._raw_target[start : self._offset]
        if self._offset == length:
            self._finished = True
        else:
            self._offset += 1
        return component

    def has_component(self) -> bool:
        """Return whether a component remains without consuming it."""
        return not self._finished


@dataclass
class _LinkFrame:
    source: PurePosixPath
    cursor: _TargetCursor
    current: PurePosixPath | None
    consumed_component: bool = False
    waiting_on: PurePosixPath | None = None


class SnapshotPathResolver:
    """Resolve payload paths only through an already-validated manifest map."""

    def __init__(self, entries: Iterable[PayloadEntry], max_steps: int) -> None:
        if type(max_steps) is not int or max_steps <= 0:
            raise ArtifactEvidenceError("payload symbolic link limit is invalid")
        self._max_steps = max_steps
        self._remaining_steps = max_steps
        self._entries = self._index_entries(entries)
        self._resolved_links: dict[PurePosixPath, ResolvedPayloadEntry] = {}

    def validate_links(self, platform_name: str) -> None:
        """Validate every symbolic link for one target platform."""
        for path, entry in self._entries.items():
            if entry.kind != "symlink":
                continue
            if platform_name == "win32":
                raise ArtifactEvidenceError(
                    "Windows payloads cannot contain symbolic links"
                )
            if path in self._resolved_links:
                continue
            self._resolve_link(path, self._parent_entry_path(path))

    def resolve_entry(self, path: PurePosixPath) -> ResolvedPayloadEntry:
        """Resolve a manifest path without consulting the host filesystem."""
        if not isinstance(path, PurePosixPath):
            raise ArtifactEvidenceError("payload path is invalid")
        current: PurePosixPath | None = None
        consumed_component = False
        for component in path.parts:
            self._spend_step()
            if consumed_component:
                self._require_directory(current)
            if component in {"", "."}:
                consumed_component = True
                continue
            if component == ".." or not _safe_path_component(component):
                raise ArtifactEvidenceError("payload path is unsafe")
            parent = current
            current, _ = self._child_entry(parent, component)
            current = self._expand_if_link(current, parent)
            consumed_component = True
        if current is None:
            raise ArtifactEvidenceError("payload path is invalid")
        entry = self._entries.get(current)
        if entry is None:
            raise ArtifactEvidenceError("payload path is missing from the manifest")
        return ResolvedPayloadEntry(entry.relative_path, entry)

    def _index_entries(
        self, entries: Iterable[PayloadEntry]
    ) -> dict[PurePosixPath, PayloadEntry]:
        indexed: dict[PurePosixPath, PayloadEntry] = {}
        for entry in entries:
            if len(indexed) >= self._max_steps:
                raise ArtifactEvidenceError("payload entry limit exceeded")
            if not isinstance(entry, PayloadEntry) or not _safe_manifest_path(
                entry.relative_path
            ):
                raise ArtifactEvidenceError("payload entry path is unsafe")
            if entry.relative_path in indexed:
                raise ArtifactEvidenceError("payload contains duplicate entry paths")
            if entry.kind not in {"directory", "file", "symlink"}:
                raise ArtifactEvidenceError("payload entry kind is invalid")
            if entry.kind == "symlink" and not isinstance(entry.link_target, str):
                raise ArtifactEvidenceError("payload symbolic link is invalid")
            indexed[entry.relative_path] = entry
        return indexed

    def _resolve_link(
        self, source: PurePosixPath, parent: PurePosixPath | None
    ) -> ResolvedPayloadEntry:
        self._spend_step()
        cached = self._resolved_links.get(source)
        if cached is not None:
            return cached
        entry = self._entries[source]
        if entry.kind != "symlink" or entry.link_target is None:
            raise ArtifactEvidenceError("payload symbolic link is invalid")
        frames = [
            _LinkFrame(
                source,
                _TargetCursor(entry.link_target),
                parent,
            )
        ]
        active = {source}
        while frames:
            frame = frames[-1]
            if frame.waiting_on is not None:
                resolved = self._resolved_links.get(frame.waiting_on)
                if resolved is None:
                    raise ArtifactEvidenceError("payload symbolic link is invalid")
                frame.current = resolved.relative_path
                frame.waiting_on = None
                continue
            if not frame.cursor.has_component():
                if frame.current is None:
                    raise ArtifactEvidenceError(
                        "payload symbolic link escapes its root"
                    )
                target = self._entries.get(frame.current)
                if target is None:
                    raise ArtifactEvidenceError("payload symbolic link is dangling")
                resolved = ResolvedPayloadEntry(target.relative_path, target)
                self._resolved_links[frame.source] = resolved
                active.remove(frame.source)
                frames.pop()
                continue
            self._spend_step()
            component = frame.cursor.next_component()
            if component is None:
                raise ArtifactEvidenceError("payload symbolic link is invalid")
            if frame.consumed_component:
                self._require_directory(frame.current)
            if component in {"", "."}:
                frame.consumed_component = True
                continue
            if component == "..":
                if frame.current is None:
                    raise ArtifactEvidenceError(
                        "payload symbolic link escapes its root"
                    )
                frame.current = self._parent_entry_path(frame.current)
                frame.consumed_component = True
                continue
            if not _safe_path_component(component):
                raise ArtifactEvidenceError("payload symbolic link target is unsafe")
            parent = frame.current
            candidate, candidate_entry = self._child_entry(parent, component)
            frame.consumed_component = True
            if candidate_entry.kind != "symlink":
                frame.current = candidate
                continue
            self._spend_step()
            cached_target = self._resolved_links.get(candidate)
            if cached_target is not None:
                frame.current = cached_target.relative_path
                continue
            if candidate in active:
                raise ArtifactEvidenceError("payload symbolic link cycle detected")
            if candidate_entry.link_target is None:
                raise ArtifactEvidenceError("payload symbolic link is invalid")
            frame.waiting_on = candidate
            active.add(candidate)
            frames.append(
                _LinkFrame(
                    candidate,
                    _TargetCursor(candidate_entry.link_target),
                    parent,
                )
            )
        cached = self._resolved_links.get(source)
        if cached is None:
            raise ArtifactEvidenceError("payload symbolic link is invalid")
        return cached

    def _expand_if_link(
        self, path: PurePosixPath, parent: PurePosixPath | None
    ) -> PurePosixPath:
        entry = self._entries[path]
        if entry.kind != "symlink":
            return path
        return self._resolve_link(path, parent).relative_path

    def _child_entry(
        self, parent: PurePosixPath | None, component: str
    ) -> tuple[PurePosixPath, PayloadEntry]:
        if parent is not None:
            self._spend_steps(len(parent.parts))
        candidate = _append_path(parent, component)
        entry = self._entries.get(candidate)
        if entry is None:
            raise ArtifactEvidenceError("payload symbolic link is dangling")
        return entry.relative_path, entry

    def _parent_entry_path(self, path: PurePosixPath | None) -> PurePosixPath | None:
        if path is None:
            return None
        parent_components = len(path.parts) - 1
        if parent_components <= 0:
            return None
        self._spend_steps(parent_components)
        parent = path.parent
        entry = self._entries.get(parent)
        if entry is None or entry.kind != "directory":
            raise ArtifactEvidenceError("payload symbolic link parent is invalid")
        return entry.relative_path

    def _require_directory(self, path: PurePosixPath | None) -> None:
        if path is None:
            return
        entry = self._entries.get(path)
        if entry is None or entry.kind != "directory":
            raise ArtifactEvidenceError("payload path requires a directory")

    def _spend_step(self) -> None:
        self._spend_steps(1)

    def _spend_steps(self, count: int) -> None:
        if count > self._remaining_steps:
            raise ArtifactEvidenceError(
                "payload symbolic link resolution limit exceeded"
            )
        self._remaining_steps -= count


def _safe_manifest_path(path: object) -> bool:
    return (
        isinstance(path, PurePosixPath)
        and not path.is_absolute()
        and path != PurePosixPath(".")
        and bool(path.parts)
        and all(_safe_path_component(part) for part in path.parts)
    )


def _safe_path_component(component: str) -> bool:
    return (
        bool(component)
        and component not in {".", ".."}
        and "\x00" not in component
        and "/" not in component
        and "\\" not in component
        and ":" not in component
    )


def _append_path(parent: PurePosixPath | None, component: str) -> PurePosixPath:
    return PurePosixPath(component) if parent is None else parent / component


def _child_relative(parent: PurePosixPath, name: str) -> PurePosixPath:
    if not name or "\x00" in name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ArtifactEvidenceError("payload entry name is unsafe")
    return PurePosixPath(name) if parent == PurePosixPath(".") else parent / name


def _read_link_target(path: Path) -> str:
    try:
        target = os.readlink(path)
    except OSError as error:
        raise ArtifactEvidenceError(
            "payload symbolic link could not be read"
        ) from error
    if not isinstance(target, str):
        raise ArtifactEvidenceError("payload symbolic link target is invalid")
    return target


def _relative_regular_file(
    path: Path,
    root: Path,
    entries: Mapping[PurePosixPath, PayloadEntry],
    label: str,
) -> PurePosixPath:
    try:
        relative = PurePosixPath(path.absolute().relative_to(root).as_posix())
    except ValueError as error:
        raise ArtifactEvidenceError(f"{label} is outside the payload") from error
    entry = entries.get(relative)
    if entry is None or entry.kind != "file":
        raise ArtifactEvidenceError(f"{label} is not a regular payload file")
    return relative


def _read_marker(
    root: Path, entries: Mapping[PurePosixPath, PayloadEntry], limit: int
) -> dict[str, object]:
    marker_entry = entries.get(_MARKER_NAME)
    if marker_entry is None or marker_entry.kind != "file":
        raise ArtifactEvidenceError("payload runtime marker is missing")
    return _read_json_object(root / _MARKER_NAME, limit, "runtime marker")


def _validate_marker(
    marker: Mapping[str, object], executable: PurePosixPath, product_version: str
) -> None:
    expected = {
        "schema_version",
        "distribution",
        "product_version",
        "build_revision",
        "console_helper",
        "desktop_child",
    }
    if (
        set(marker) != expected
        or type(marker.get("schema_version")) is not int
        or marker.get("schema_version") != 1
    ):
        raise ArtifactEvidenceError("payload runtime marker has an invalid schema")
    if marker.get("distribution") != "frozen-cli":
        raise ArtifactEvidenceError(
            "payload runtime marker has an invalid distribution"
        )
    if marker.get("product_version") != product_version:
        raise ArtifactEvidenceError(
            "payload runtime marker version does not match wheel"
        )
    if not isinstance(marker.get("build_revision"), str):
        raise ArtifactEvidenceError("payload runtime marker has an invalid revision")
    if marker.get("desktop_child") is not None:
        raise ArtifactEvidenceError(
            "payload runtime marker has an invalid desktop helper"
        )
    if marker.get("console_helper") != executable.as_posix():
        raise ArtifactEvidenceError(
            "payload runtime marker helper does not match executable"
        )


def _read_build_provenance(
    artifact: ArtifactDescriptor,
    marker: Mapping[str, object],
    product_version: str,
    limit: int,
) -> dict[str, object]:
    provenance = _read_json_object(
        artifact.build_metadata_dir / "resolved" / "build-provenance.json",
        limit,
        "build provenance",
    )
    expected = {
        "schema_version",
        "source_commit",
        "target",
        "product_version",
        "build_revision",
        "wheel_sha256",
    }
    if (
        set(provenance) != expected
        or type(provenance.get("schema_version")) is not int
        or provenance.get("schema_version") != 1
    ):
        raise ArtifactEvidenceError("build provenance has an invalid schema")
    if provenance.get("target") != artifact.target.name:
        raise ArtifactEvidenceError("build provenance target does not match")
    if provenance.get("product_version") != product_version:
        raise ArtifactEvidenceError("build provenance product version does not match")
    if provenance.get("build_revision") != marker.get("build_revision"):
        raise ArtifactEvidenceError("build provenance revision does not match")
    if not isinstance(provenance.get("source_commit"), str) or not isinstance(
        provenance.get("wheel_sha256"), str
    ):
        raise ArtifactEvidenceError("build provenance has an invalid source commit")
    if provenance.get("wheel_sha256") != _sha256_file(
        _regular_file(artifact.wheel, "wheel")
    ):
        raise ArtifactEvidenceError("build provenance wheel hash does not match")
    return provenance


def _read_build_toolchain(
    artifact: ArtifactDescriptor, limit: int
) -> dict[str, object]:
    toolchain = _read_json_object(
        artifact.build_metadata_dir / "resolved" / "build-toolchain.json",
        limit,
        "build toolchain",
    )
    expected = {
        "schema_version",
        "python_implementation",
        "python_version",
        "spec_sha256",
        "hooks_sha256",
    }
    if (
        set(toolchain) != expected
        or type(toolchain.get("schema_version")) is not int
        or toolchain.get("schema_version") != 1
        or toolchain.get("python_implementation") != "CPython"
    ):
        raise ArtifactEvidenceError("build toolchain has an invalid schema")
    version = toolchain.get("python_version")
    if (
        not isinstance(version, str)
        or not _PYTHON_VERSION.fullmatch(version)
        or ".".join(version.split(".")[:2]) != artifact.target.python_version
    ):
        raise ArtifactEvidenceError("build toolchain Python version is invalid")
    if not all(
        isinstance(toolchain.get(name), str) and _SHA256.fullmatch(toolchain[name])
        for name in ("spec_sha256", "hooks_sha256")
    ):
        raise ArtifactEvidenceError("build toolchain has an invalid profile digest")
    return toolchain


def _validate_metadata(artifact: ArtifactDescriptor, limit: int) -> None:
    metadata_root = _regular_directory(artifact.build_metadata_dir, "build metadata")
    warning = _regular_file(artifact.pyinstaller_warning_file, "warning metadata")
    if warning != metadata_root / "pyinstaller" / "warn-servonaut.txt":
        raise ArtifactEvidenceError("warning metadata path is invalid")
    _read_bounded_bytes(warning, limit, "warning metadata")
    for relative in _REQUIRED_METADATA:
        metadata_file = _regular_file(metadata_root / relative, "build metadata")
        _read_bounded_bytes(metadata_file, limit, "build metadata")


def _validate_forbidden_paths(
    entries: Iterable[PayloadEntry], patterns: Iterable[str]
) -> None:
    for entry in entries:
        relative = entry.relative_path.as_posix()
        if any(fnmatch.fnmatchcase(relative, pattern) for pattern in patterns):
            raise ArtifactEvidenceError("payload contains a forbidden path")


def _regular_directory(path: Path, label: str) -> Path:
    try:
        status = path.lstat()
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} is unavailable") from error
    if not stat.S_ISDIR(status.st_mode):
        raise ArtifactEvidenceError(f"{label} is not a regular directory")
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} is unavailable") from error


def _regular_file(path: Path, label: str) -> Path:
    try:
        status = path.lstat()
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} is unavailable") from error
    if not stat.S_ISREG(status.st_mode):
        raise ArtifactEvidenceError(f"{label} is not a regular file")
    return path


def _read_json_object(path: Path, limit: int, label: str) -> dict[str, object]:
    raw = _read_bounded_bytes(_regular_file(path, label), limit, label)
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ArtifactEvidenceError,
    ) as error:
        raise ArtifactEvidenceError(f"{label} is not valid JSON") from error
    if not isinstance(payload, dict):
        raise ArtifactEvidenceError(f"{label} must be an object")
    return payload


def _read_bounded_bytes(path: Path, limit: int, label: str) -> bytes:
    try:
        if path.stat().st_size > limit:
            raise ArtifactEvidenceError(f"{label} exceeds its size limit")
        return path.read_bytes()
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} could not be read") from error


def _validate_limits(limits: EvidenceLimits) -> None:
    if not all(
        type(value) is int and value > 0
        for value in (
            limits.max_metadata_file_bytes,
            limits.max_payload_entries,
            limits.max_regular_file_bytes,
            limits.max_expanded_payload_bytes,
            limits.native_inspection_timeout_seconds,
            limits.native_inspection_max_output_bytes,
        )
    ):
        raise ArtifactEvidenceError("evidence limits are invalid")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ArtifactEvidenceError("artifact file could not be read") from error
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactEvidenceError("JSON object contains duplicate keys")
        result[key] = value
    return result
