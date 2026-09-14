"""Bounded native-binary inspection for standalone payload evidence."""

from __future__ import annotations

import os
import re
from pathlib import Path

from scripts.standalone_cli.artifact_types import ArtifactEvidenceError, PayloadSnapshot
from scripts.standalone_cli.bounded_command import run_bounded_command
from scripts.standalone_cli.evidence_policy_types import (
    EvidenceLimits,
    NativeConstraints,
)
from scripts.standalone_cli.model import TargetSpec

_GLIBC_PATTERN = re.compile(r"GLIBC_(\d+\.\d+)")
_GLIBCXX_PATTERN = re.compile(r"GLIBCXX_(\d+\.\d+(?:\.\d+)?)")
_CXXABI_PATTERN = re.compile(r"CXXABI_(\d+\.\d+(?:\.\d+)?)")
_MACHO_LOAD_COMMAND = re.compile(r"^Load command [0-9]+$")
_MACHO_FIELD = re.compile(r"^(?P<name>[a-z]+)\s+(?P<value>.+)$")
_MACHO_THIN_MAGICS = frozenset(
    {
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
    }
)
_MACHO_FAT_MAGICS = frozenset(
    {
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }
)


def inspect_native_payload(
    snapshot: PayloadSnapshot,
    target: TargetSpec,
    constraints: NativeConstraints,
    limits: EvidenceLimits,
    *,
    os_release_path: Path = Path("/etc/os-release"),
) -> list[dict[str, object]]:
    """Return public-safe facts after enforcing target-native constraints."""
    if target.platform == "linux":
        _require_linux_build_host(os_release_path, constraints)
    results: list[dict[str, object]] = []
    executable_found = False
    for entry in snapshot.entries:
        if entry.kind != "file":
            continue
        path = snapshot.root / entry.relative_path
        kind = _native_kind(path)
        is_executable = entry.relative_path == snapshot.executable_relative_path
        if kind is None:
            if is_executable:
                raise ArtifactEvidenceError("declared executable is not target-native")
            continue
        if kind == "macho-fat":
            raise ArtifactEvidenceError("fat Mach-O containers are unsupported")
        relative = entry.relative_path.as_posix()
        if kind == "pe":
            facts = _inspect_pe(path, relative, target, constraints)
        elif kind == "elf":
            facts = _inspect_elf(path, relative, target, constraints, limits)
        else:
            facts = _inspect_macho(path, relative, target, limits)
        results.append(facts)
        if is_executable:
            executable_found = True
    if not executable_found:
        raise ArtifactEvidenceError("declared executable is not target-native")
    return results


def _native_kind(path: Path) -> str | None:
    try:
        with path.open("rb") as handle:
            header = handle.read(4)
    except OSError as error:
        raise ArtifactEvidenceError("native payload file is unreadable") from error
    if header.startswith(b"MZ"):
        return "pe"
    if header == b"\x7fELF":
        return "elf"
    if header in _MACHO_THIN_MAGICS:
        return "macho"
    if header in _MACHO_FAT_MAGICS:
        return "macho-fat"
    return None


def _inspect_pe(
    path: Path, relative: str, target: TargetSpec, constraints: NativeConstraints
) -> dict[str, object]:
    if target.platform != "win32":
        raise ArtifactEvidenceError("unexpected PE binary for target")
    try:
        with path.open("rb") as handle:
            data = handle.read(512)
    except OSError as error:
        raise ArtifactEvidenceError("native payload file is unreadable") from error
    if len(data) < 0x40:
        raise ArtifactEvidenceError("truncated PE header")
    offset = int.from_bytes(data[0x3C:0x40], "little")
    if offset + 26 > len(data) or data[offset : offset + 4] != b"PE\0\0":
        raise ArtifactEvidenceError("invalid PE header")
    machine = int.from_bytes(data[offset + 4 : offset + 6], "little")
    optional_magic = int.from_bytes(data[offset + 24 : offset + 26], "little")
    expected = int(constraints.windows_machine, 0)
    if machine != expected or optional_magic != 0x20B:
        raise ArtifactEvidenceError("PE architecture does not match target")
    return {"path": relative, "kind": "pe", "machine": f"0x{machine:04x}"}


def _inspect_elf(
    path: Path,
    relative: str,
    target: TargetSpec,
    constraints: NativeConstraints,
    limits: EvidenceLimits,
) -> dict[str, object]:
    if target.platform != "linux":
        raise ArtifactEvidenceError("unexpected ELF binary for target")
    try:
        with path.open("rb") as handle:
            header = handle.read(64)
    except OSError as error:
        raise ArtifactEvidenceError("native payload file is unreadable") from error
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise ArtifactEvidenceError("truncated ELF header")
    machine = int.from_bytes(header[18:20], "little")
    if header[4] != 2 or header[5] != 1 or machine != int(constraints.linux_machine, 0):
        raise ArtifactEvidenceError("ELF architecture does not match target")
    versions = _elf_versions(path, limits)
    maximum_glibc = _maximum_version(versions["glibc"])
    if maximum_glibc is not None and _version_tuple(maximum_glibc) > _version_tuple(
        constraints.linux_max_glibc
    ):
        raise ArtifactEvidenceError("ELF GLIBC requirement exceeds target floor")
    return {
        "path": relative,
        "kind": "elf",
        "machine": machine,
        "max_glibc": maximum_glibc,
        "max_glibcxx": _maximum_version(versions["glibcxx"]),
        "max_cxxabi": _maximum_version(versions["cxxabi"]),
    }


def _elf_versions(path: Path, limits: EvidenceLimits) -> dict[str, list[str]]:
    output = _native_command_output(
        ["readelf", "--version-info", str(path)],
        path,
        limits,
        "ELF symbol inspection",
        "could not inspect ELF symbol requirements",
    )
    return {
        "glibc": _validated_versions(output, "GLIBC", _GLIBC_PATTERN),
        "glibcxx": _validated_versions(output, "GLIBCXX", _GLIBCXX_PATTERN),
        "cxxabi": _validated_versions(output, "CXXABI", _CXXABI_PATTERN),
    }


def _validated_versions(
    output: str, prefix: str, pattern: re.Pattern[str]
) -> list[str]:
    tokens = re.findall(rf"\b{prefix}_[^\s)\]]+", output)
    values = pattern.findall(output)
    if len(tokens) != len(values):
        raise ArtifactEvidenceError("ELF symbol-version output is malformed")
    return values


def _inspect_macho(
    path: Path, relative: str, target: TargetSpec, limits: EvidenceLimits
) -> dict[str, object]:
    if target.platform != "darwin" or target.macos_minimum_version is None:
        raise ArtifactEvidenceError("unexpected Mach-O binary for target")
    output = _native_command_output(
        ["otool", "-l", str(path)],
        path,
        limits,
        "Mach-O deployment inspection",
        "could not inspect Mach-O deployment target",
    )
    architecture = "arm64" if target.architecture == "arm64" else "x86_64"
    lipo_output = _native_command_output(
        ["lipo", "-archs", str(path)],
        path,
        limits,
        "Mach-O architecture inspection",
        "could not inspect Mach-O architecture",
    )
    if lipo_output.split() != [architecture]:
        raise ArtifactEvidenceError("Mach-O architecture does not match target")
    minimum = _macho_macos_minimum(output)
    if _version_tuple(minimum) > _version_tuple(target.macos_minimum_version):
        raise ArtifactEvidenceError("Mach-O deployment target exceeds policy")
    return {
        "path": relative,
        "kind": "macho",
        "architecture": architecture,
        "minimum": minimum,
    }


def _native_command_output(
    command: list[str],
    path: Path,
    limits: EvidenceLimits,
    label: str,
    error_message: str,
) -> str:
    try:
        output = run_bounded_command(
            command,
            dict(os.environ),
            path.parent,
            limits.native_inspection_timeout_seconds,
            limits.native_inspection_max_output_bytes,
            limits.native_inspection_max_output_bytes,
            label,
        )
        return output.decode("utf-8", errors="strict")
    except (ArtifactEvidenceError, UnicodeDecodeError) as error:
        raise ArtifactEvidenceError(error_message) from error


def _macho_macos_minimum(output: str) -> str:
    minimums: list[str] = []
    for block in _macho_load_command_blocks(output):
        fields = _macho_fields(block)
        command = fields.get("cmd")
        if command == "LC_BUILD_VERSION":
            if fields.get("platform", "").casefold() not in {"macos", "1"}:
                raise ArtifactEvidenceError("Mach-O deployment platform is invalid")
            minimums.append(_macho_version_field(fields, "minos"))
        elif command == "LC_VERSION_MIN_MACOSX":
            minimums.append(_macho_version_field(fields, "version"))
        elif isinstance(command, str) and command.startswith("LC_VERSION_MIN_"):
            raise ArtifactEvidenceError("Mach-O deployment platform is invalid")
    if not minimums or len(set(minimums)) != 1:
        raise ArtifactEvidenceError("Mach-O deployment target is invalid")
    return minimums[0]


def _macho_load_command_blocks(output: str) -> list[list[str]]:
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if _MACHO_LOAD_COMMAND.fullmatch(line):
            current = []
            blocks.append(current)
        elif current is not None and line:
            current.append(line)
    if not blocks:
        raise ArtifactEvidenceError("Mach-O load commands are invalid")
    return blocks


def _macho_fields(block: list[str]) -> dict[str, str]:
    command_values = [
        match.group("value")
        for line in block
        if (match := _MACHO_FIELD.fullmatch(line)) is not None
        and match.group("name") == "cmd"
    ]
    if len(command_values) != 1:
        raise ArtifactEvidenceError("Mach-O load commands are invalid")
    command = command_values[0]
    fields: dict[str, str] = {}
    for line in block:
        match = _MACHO_FIELD.fullmatch(line)
        if match is None:
            continue
        name = match.group("name")
        value = match.group("value")
        if name in fields:
            if command == "LC_BUILD_VERSION" and name in {"tool", "version"}:
                continue
            raise ArtifactEvidenceError("Mach-O load commands are invalid")
        fields[name] = value
    return fields


def _macho_version_field(fields: dict[str, str], name: str) -> str:
    value = fields.get(name)
    if value is None or re.fullmatch(r"\d+(?:\.\d+)*", value) is None:
        raise ArtifactEvidenceError("Mach-O deployment target is invalid")
    return value


def _require_linux_build_host(path: Path, constraints: NativeConstraints) -> None:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ArtifactEvidenceError(
            "Linux build host release data is unavailable"
        ) from error
    values: dict[str, str] = {}
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ArtifactEvidenceError("Linux build host release data is malformed")
        key, value = line.split("=", 1)
        if key not in {"ID", "VERSION_ID"}:
            continue
        if key in values:
            raise ArtifactEvidenceError("Linux build host release data is malformed")
        values[key] = value.strip().strip('"')
    if (
        values.get("ID") != constraints.linux_build_os_id
        or values.get("VERSION_ID") != constraints.linux_build_os_version
    ):
        raise ArtifactEvidenceError("Linux build host does not match target policy")


def _maximum_version(values: list[str]) -> str | None:
    return max(values, key=_version_tuple) if values else None


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))
