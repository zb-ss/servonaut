"""Safe PyInstaller TOC inspection without importing generated payload code."""

from __future__ import annotations

import ast
from pathlib import Path

from scripts.standalone_cli.artifact_types import (
    ArtifactDescriptor,
    ArtifactEvidenceError,
    PayloadSnapshot,
)


def validate_toc_policy(
    snapshot: PayloadSnapshot, artifact: ArtifactDescriptor, max_bytes: int
) -> None:
    """Reject forbidden payload paths and Python modules recorded by PyInstaller."""
    for entry in snapshot.entries:
        relative = entry.relative_path.as_posix()
        if any(
            entry.relative_path.match(pattern)
            for pattern in artifact.target.forbidden_path_patterns
        ):
            raise ArtifactEvidenceError("payload contains a forbidden relative path")
        if relative.endswith(".dist-info/direct_url.json"):
            raise ArtifactEvidenceError(
                "payload contains forbidden wheel acquisition metadata"
            )
    for name in ("Analysis-00.toc", "PYZ-00.toc"):
        path = artifact.build_metadata_dir / "pyinstaller" / name
        if path.exists():
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
            if typecode in {"PYMODULE", "PYSOURCE"}:
                modules.add(current[0])
        if isinstance(current, (tuple, list)):
            stack.extend((child, depth + 1) for child in current)
