"""Bounded native binary header parsing for desktop payload inspection."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

_ELF_MAGIC = b"\x7fELF"
_ELF_CLASS_64 = 2
_ELF_DATA_LITTLE_ENDIAN = 1
_ELF_MACHINES = {0x3E: "x86_64", 0xB7: "arm64"}
_PE_HEADER_READ_BYTES = 4096
_PE_SIGNATURE = b"PE\0\0"
_PE32_PLUS_MAGIC = 0x20B
_PE_MACHINES = {0x8664: "x86_64", 0xAA64: "arm64"}
# Thin Mach-O magic -> (struct byte order, header size).
_MACHO_THIN_MAGICS = {
    b"\xcf\xfa\xed\xfe": ("<", 32),
    b"\xce\xfa\xed\xfe": ("<", 28),
    b"\xfe\xed\xfa\xcf": (">", 32),
    b"\xfe\xed\xfa\xce": (">", 28),
}
_MACHO_FAT_MAGICS = frozenset(
    {
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }
)
_MACHO_CPU_TYPES = {0x01000007: "x86_64", 0x0100000C: "arm64"}
_LC_VERSION_MIN_MACOSX = 0x24
_LC_BUILD_VERSION = 0x32
_PLATFORM_MACOS = 1

NativeFormat = Literal["pe", "elf", "macho"]


class NativeHeaderError(ValueError):
    """Raised when a native binary header is truncated, unsupported or unsafe."""


@dataclass(frozen=True)
class NativeIdentity:
    """Container format and CPU architecture declared by a binary header."""

    format: NativeFormat
    architecture: str | None


def read_native_identity(path: Path) -> NativeIdentity | None:
    """Return the header identity of a native binary, or None for other files."""
    header = _read_prefix(path, _PE_HEADER_READ_BYTES)
    magic = header[:4]
    if header.startswith(b"MZ"):
        return NativeIdentity("pe", _pe_architecture(header))
    if magic == _ELF_MAGIC:
        return NativeIdentity("elf", _elf_architecture(header))
    if magic in _MACHO_FAT_MAGICS:
        raise NativeHeaderError(
            f"universal Mach-O binaries are not allowed: {path.name}"
        )
    if magic in _MACHO_THIN_MAGICS:
        byte_order, _ = _MACHO_THIN_MAGICS[magic]
        if len(header) < 8:
            raise NativeHeaderError(f"truncated Mach-O header: {path.name}")
        (cpu_type,) = struct.unpack_from(f"{byte_order}I", header, 4)
        return NativeIdentity("macho", _MACHO_CPU_TYPES.get(cpu_type))
    return None


def is_macho_file(path: Path) -> bool:
    """Return whether a file starts with a thin or universal Mach-O magic."""
    magic = _read_prefix(path, 4)
    return magic in _MACHO_THIN_MAGICS or magic in _MACHO_FAT_MAGICS


def macho_minimum_macos(path: Path, max_bytes: int) -> tuple[int, int, int]:
    """Return the single macOS deployment target declared by a thin Mach-O file."""
    header = _read_prefix(path, 32)
    layout = _MACHO_THIN_MAGICS.get(header[:4])
    if layout is None:
        raise NativeHeaderError(f"not a thin Mach-O binary: {path.name}")
    byte_order, header_size = layout
    if len(header) < header_size:
        raise NativeHeaderError(f"truncated Mach-O header: {path.name}")
    command_count, commands_size = struct.unpack_from(f"{byte_order}II", header, 16)
    if commands_size > max_bytes:
        raise NativeHeaderError(f"Mach-O load commands exceed the limit: {path.name}")
    commands = _read_prefix(path, header_size + commands_size)[header_size:]
    if len(commands) != commands_size:
        raise NativeHeaderError(f"truncated Mach-O load commands: {path.name}")
    minimums = set(_deployment_minimums(commands, command_count, byte_order, path))
    if len(minimums) != 1:
        raise NativeHeaderError(
            f"Mach-O binary must declare one macOS deployment target: {path.name}"
        )
    return minimums.pop()


def _deployment_minimums(
    commands: bytes, command_count: int, byte_order: str, path: Path
) -> list[tuple[int, int, int]]:
    minimums: list[tuple[int, int, int]] = []
    offset = 0
    for _ in range(command_count):
        if offset + 8 > len(commands):
            raise NativeHeaderError(f"malformed Mach-O load commands: {path.name}")
        command, size = struct.unpack_from(f"{byte_order}II", commands, offset)
        if size < 8 or offset + size > len(commands):
            raise NativeHeaderError(f"malformed Mach-O load commands: {path.name}")
        if command == _LC_BUILD_VERSION and size >= 16:
            platform, minimum = struct.unpack_from(
                f"{byte_order}II", commands, offset + 8
            )
            if platform != _PLATFORM_MACOS:
                raise NativeHeaderError(
                    f"Mach-O binary targets a non-macOS platform: {path.name}"
                )
            minimums.append(_decode_version(minimum))
        elif command == _LC_VERSION_MIN_MACOSX and size >= 12:
            (minimum,) = struct.unpack_from(f"{byte_order}I", commands, offset + 8)
            minimums.append(_decode_version(minimum))
        offset += size
    return minimums


def _decode_version(value: int) -> tuple[int, int, int]:
    return value >> 16, (value >> 8) & 0xFF, value & 0xFF


def _pe_architecture(header: bytes) -> str | None:
    if len(header) < 0x40:
        raise NativeHeaderError("truncated PE header")
    (offset,) = struct.unpack_from("<I", header, 0x3C)
    if offset + 26 > len(header) or header[offset : offset + 4] != _PE_SIGNATURE:
        raise NativeHeaderError("invalid PE header")
    (machine,) = struct.unpack_from("<H", header, offset + 4)
    (optional_magic,) = struct.unpack_from("<H", header, offset + 24)
    if optional_magic != _PE32_PLUS_MAGIC:
        return None
    return _PE_MACHINES.get(machine)


def _elf_architecture(header: bytes) -> str | None:
    if len(header) < 20:
        raise NativeHeaderError("truncated ELF header")
    if header[4] != _ELF_CLASS_64 or header[5] != _ELF_DATA_LITTLE_ENDIAN:
        return None
    (machine,) = struct.unpack_from("<H", header, 18)
    return _ELF_MACHINES.get(machine)


def _read_prefix(path: Path, size: int) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError as error:
        raise NativeHeaderError(f"could not read binary header: {path.name}") from error
