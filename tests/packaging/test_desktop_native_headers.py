"""Tests for bounded native header parsing used by desktop payload inspection."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from scripts.desktop_shell.native_headers import (
    NativeHeaderError,
    NativeIdentity,
    is_macho_file,
    macho_minimum_macos,
    read_native_identity,
)

_CPU_X86_64 = 0x01000007
_CPU_ARM64 = 0x0100000C


def _elf(machine: int, *, elf_class: int = 2) -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = elf_class
    header[5] = 1
    header[18:20] = machine.to_bytes(2, "little")
    return bytes(header)


def _pe(machine: int, *, optional_magic: int = 0x20B) -> bytes:
    header = bytearray(0x80 + 26)
    header[:2] = b"MZ"
    header[0x3C:0x40] = (0x80).to_bytes(4, "little")
    header[0x80:0x84] = b"PE\0\0"
    header[0x84:0x86] = machine.to_bytes(2, "little")
    header[0x98:0x9A] = optional_magic.to_bytes(2, "little")
    return bytes(header)


def _version(major: int, minor: int) -> int:
    return (major << 16) | (minor << 8)


def _macho(cpu_type: int, *commands: bytes) -> bytes:
    body = b"".join(commands)
    header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, cpu_type, 0, 2, len(commands), len(body), 0, 0
    )
    return header + body


def _build_version(major: int, minor: int, platform: int = 1) -> bytes:
    return struct.pack("<IIIIII", 0x32, 24, platform, _version(major, minor), 0, 0)


def _version_min(major: int, minor: int) -> bytes:
    return struct.pack("<IIII", 0x24, 16, _version(major, minor), 0)


def _write(tmp_path: Path, data: bytes, name: str = "binary") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


@pytest.mark.parametrize(
    ("data", "identity"),
    [
        (_elf(0x3E), NativeIdentity("elf", "x86_64")),
        (_elf(0xB7), NativeIdentity("elf", "arm64")),
        (_elf(0x3E, elf_class=1), NativeIdentity("elf", None)),
        (_pe(0x8664), NativeIdentity("pe", "x86_64")),
        (_pe(0xAA64), NativeIdentity("pe", "arm64")),
        (_pe(0x8664, optional_magic=0x10B), NativeIdentity("pe", None)),
        (_macho(_CPU_X86_64), NativeIdentity("macho", "x86_64")),
        (_macho(_CPU_ARM64), NativeIdentity("macho", "arm64")),
    ],
)
def test_read_native_identity_reports_format_and_architecture(
    tmp_path: Path, data: bytes, identity: NativeIdentity
) -> None:
    assert read_native_identity(_write(tmp_path, data)) == identity


def test_read_native_identity_ignores_non_native_files(tmp_path: Path) -> None:
    assert read_native_identity(_write(tmp_path, b"#!/bin/sh\n")) is None


def test_read_native_identity_rejects_universal_macho(tmp_path: Path) -> None:
    fat = _write(tmp_path, b"\xca\xfe\xba\xbe" + b"\0" * 28)

    assert is_macho_file(fat)
    with pytest.raises(NativeHeaderError, match="universal Mach-O"):
        read_native_identity(fat)


def test_read_native_identity_rejects_truncated_pe(tmp_path: Path) -> None:
    with pytest.raises(NativeHeaderError, match="truncated PE header"):
        read_native_identity(_write(tmp_path, b"MZ\0\0"))


@pytest.mark.parametrize(
    ("command", "expected"),
    [(_build_version(11, 0), (11, 0, 0)), (_version_min(10, 13), (10, 13, 0))],
)
def test_macho_minimum_macos_reads_deployment_target(
    tmp_path: Path, command: bytes, expected: tuple[int, int, int]
) -> None:
    binary = _write(tmp_path, _macho(_CPU_ARM64, command))

    assert macho_minimum_macos(binary, 4096) == expected


def test_macho_minimum_macos_requires_a_deployment_target(tmp_path: Path) -> None:
    binary = _write(tmp_path, _macho(_CPU_ARM64, struct.pack("<II", 0x19, 8)))

    with pytest.raises(NativeHeaderError, match="one macOS deployment target"):
        macho_minimum_macos(binary, 4096)


def test_macho_minimum_macos_rejects_other_platforms(tmp_path: Path) -> None:
    binary = _write(tmp_path, _macho(_CPU_ARM64, _build_version(17, 0, platform=2)))

    with pytest.raises(NativeHeaderError, match="non-macOS platform"):
        macho_minimum_macos(binary, 4096)


def test_macho_minimum_macos_bounds_load_commands(tmp_path: Path) -> None:
    binary = _write(tmp_path, _macho(_CPU_ARM64, _build_version(11, 0)))

    with pytest.raises(NativeHeaderError, match="exceed the limit"):
        macho_minimum_macos(binary, 8)


def test_macho_minimum_macos_rejects_malformed_commands(tmp_path: Path) -> None:
    command = struct.pack("<II", 0x32, 4)
    binary = _write(tmp_path, _macho(_CPU_ARM64, command))

    with pytest.raises(NativeHeaderError, match="malformed"):
        macho_minimum_macos(binary, 4096)
