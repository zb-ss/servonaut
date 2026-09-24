"""Safe PyInstaller TOC inspection without importing generated payload code."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from scripts.standalone_cli.artifact_filesystem import matches_forbidden_path
from scripts.standalone_cli.artifact_types import (
    ArtifactDescriptor,
    ArtifactEvidenceError,
    PayloadSnapshot,
)

_TOC_NAMES = ("Analysis-00.toc", "PYZ-00.toc")
_MODULE_TYPECODES = frozenset({"PYMODULE", "PYSOURCE"})
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_STDLIB_DYNLOAD_ROOT = re.compile(r"^python[0-9]+\.[0-9]+$")


def validate_toc_policy(
    snapshot: PayloadSnapshot, artifact: ArtifactDescriptor, max_bytes: int
) -> None:
    """Reject forbidden payload paths and Python modules recorded by PyInstaller."""
    for entry in snapshot.entries:
        if matches_forbidden_path(
            entry.relative_path, artifact.target.forbidden_path_patterns
        ):
            raise ArtifactEvidenceError("payload contains a forbidden relative path")
        if entry.relative_path.as_posix().endswith(".dist-info/direct_url.json"):
            raise ArtifactEvidenceError(
                "payload contains forbidden wheel acquisition metadata"
            )
    for name in _TOC_NAMES:
        path = artifact.build_metadata_dir / "pyinstaller" / name
        for module in _modules_from_toc(path, max_bytes):
            if any(
                module == forbidden or module.startswith(f"{forbidden}.")
                for forbidden in artifact.target.forbidden_modules
            ):
                raise ArtifactEvidenceError(
                    "PyInstaller TOC contains a forbidden module"
                )


def _modules_from_toc(path: Path, max_bytes: int) -> set[str]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ArtifactEvidenceError("PyInstaller TOC is unavailable") from error
    if len(data) > max_bytes:
        raise ArtifactEvidenceError("PyInstaller TOC exceeds policy limit")
    try:
        parsed = ast.literal_eval(data.decode("utf-8"))
    except (
        SyntaxError,
        ValueError,
        UnicodeDecodeError,
        MemoryError,
        RecursionError,
    ) as error:
        raise ArtifactEvidenceError("PyInstaller TOC is invalid") from error
    modules: set[str] = set()
    _walk_toc(parsed, modules)
    return modules


def _walk_toc(value: object, modules: set[str]) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > 1000:
            raise ArtifactEvidenceError("PyInstaller TOC nesting exceeds policy limit")
        if (
            isinstance(current, tuple)
            and len(current) >= 3
            and isinstance(current[0], str)
        ):
            typecode = current[2]
            if typecode in _MODULE_TYPECODES:
                modules.add(current[0])
            elif typecode == "EXTENSION":
                modules.add(_extension_module_name(current[0]))
        if isinstance(current, (tuple, list)):
            stack.extend((child, depth + 1) for child in current)


def _extension_module_name(destination: str) -> str:
    """Recover the importable name PyInstaller used to place an extension.

    Extensions are collected at their package path with the platform suffix
    kept, and standard-library extensions under ``pythonX.Y/lib-dynload``.
    """
    parts = re.split(r"[\\/]", destination)
    if (
        len(parts) > 2
        and _STDLIB_DYNLOAD_ROOT.fullmatch(parts[0])
        and parts[1] == "lib-dynload"
    ):
        parts = parts[2:]
    names = [*parts[:-1], parts[-1].split(".", 1)[0]]
    if not all(_IDENTIFIER.fullmatch(name) for name in names):
        raise ArtifactEvidenceError("PyInstaller TOC has an invalid extension entry")
    return ".".join(names)
