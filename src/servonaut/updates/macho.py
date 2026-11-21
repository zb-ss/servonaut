"""Read Mach-O CPU identities without invoking a developer tool."""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import BinaryIO

# Apple mach-o/loader.h and mach-o/fat.h magic and header layouts.
_THIN = {
    b"\xcf\xfa\xed\xfe": ("<", 32),
    b"\xce\xfa\xed\xfe": ("<", 28),
    b"\xfe\xed\xfa\xcf": (">", 32),
    b"\xfe\xed\xfa\xce": (">", 28),
}
_FAT = {
    b"\xca\xfe\xba\xbe": struct.Struct(">IIIII"),
    b"\xbe\xba\xfe\xca": struct.Struct("<IIIII"),
    b"\xca\xfe\xba\xbf": struct.Struct(">IIQQII"),
    b"\xbf\xba\xfe\xca": struct.Struct("<IIQQII"),
}
_CPU = {7: "i386", 12: "arm", 0x01000007: "x86_64", 0x0100000C: "arm64"}
_CPU_SUBTYPE_MASK = 0x00FFFFFF
_SPECIAL_SUBTYPES = {(0x01000007, 8): "x86_64h", (0x0100000C, 2): "arm64e"}
# Bound work even if an invalid universal header advertises billions of slices.
_MAX_ARCHITECTURES = 32


def _thin_cpu(header: bytes) -> tuple[int, int]:
    layout = _THIN.get(header[:4])
    if layout is None or len(header) < layout[1]:
        raise ValueError("Invalid Mach-O header")
    order, size = layout
    cpu, subtype = struct.unpack_from(f"{order}II", header, 4)
    if cpu not in _CPU or bool(cpu & 0x01000000) != (size == 32):
        raise ValueError("Unsupported Mach-O architecture")
    return cpu, subtype


def _architecture(cpu: int, subtype: int) -> str:
    return _SPECIAL_SUBTYPES.get((cpu, subtype & _CPU_SUBTYPE_MASK), _CPU[cpu])


def _fat_architectures(stream: BinaryIO, header: bytes, layout: struct.Struct) -> frozenset[str]:
    if len(header) < 8:
        raise ValueError("Truncated universal Mach-O header")
    (count,) = struct.unpack_from(f"{layout.format[0]}I", header, 4)
    if not 1 <= count <= _MAX_ARCHITECTURES:
        raise ValueError("Invalid universal Mach-O architecture count")
    table_end = 8 + count * layout.size
    stream.seek(8)
    table = stream.read(count * layout.size)
    if len(table) != count * layout.size:
        raise ValueError("Truncated universal Mach-O table")
    size = os.fstat(stream.fileno()).st_size
    slices = sorted(layout.iter_unpack(table), key=lambda record: record[2])
    architectures = set()
    previous_end = table_end
    for cpu, subtype, offset, length, *_ in slices:
        if offset < previous_end or offset + length > size:
            raise ValueError("Invalid universal Mach-O slice range")
        stream.seek(offset)
        if _thin_cpu(stream.read(min(length, 32))) != (cpu, subtype):
            raise ValueError("Mach-O slice does not match its table")
        arch = _architecture(cpu, subtype)
        if arch in architectures:
            raise ValueError("Duplicate universal Mach-O architecture")
        architectures.add(arch)
        previous_end = offset + length
    return frozenset(architectures)


def macho_architectures(executable: Path) -> frozenset[str]:
    """Read the declared thin or universal Mach-O architectures."""
    with executable.open("rb") as stream:
        header = stream.read(32)
        if (layout := _FAT.get(header[:4])) is not None:
            return _fat_architectures(stream, header, layout)
        return frozenset({_architecture(*_thin_cpu(header))})
