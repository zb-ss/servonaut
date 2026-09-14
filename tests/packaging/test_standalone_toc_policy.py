"""Unit coverage for bounded literal PyInstaller TOC policy checks."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from scripts.standalone_cli.artifact_types import (
    ArtifactDescriptor,
    ArtifactEvidenceError,
    PayloadSnapshot,
)
from scripts.standalone_cli.model import TargetSpec
from scripts.standalone_cli.toc_policy import validate_toc_policy


def test_toc_rejects_forbidden_module(tmp_path: Path) -> None:
    payload = tmp_path / "payload"
    payload.mkdir()
    metadata = tmp_path / "metadata" / "pyinstaller"
    metadata.mkdir(parents=True)
    (metadata / "Analysis-00.toc").write_text(
        "[('sounddevice', '/safe', 'PYMODULE')]", encoding="utf-8"
    )
    target = TargetSpec(
        "windows-x64",
        tmp_path / "policy",
        "win32",
        "x86_64",
        "3.12",
        tmp_path / "lock",
        "zip",
        "zip",
        "servonaut-{product_version}-{target}.{extension}",
        ("sounddevice",),
        (),
        tmp_path / "warnings",
        tmp_path / "sizes",
        "id",
        None,
    )
    artifact = ArtifactDescriptor(
        payload,
        payload / "servonaut.exe",
        None,
        target,
        tmp_path / "wheel",
        metadata / "warn-servonaut.txt",
        metadata.parent,
    )
    snapshot = PayloadSnapshot(
        payload, (), 0, PurePosixPath("servonaut.exe"), {}, {}, {}
    )

    with pytest.raises(ArtifactEvidenceError, match="forbidden module"):
        validate_toc_policy(snapshot, artifact, 1024)


def test_toc_ignores_forbidden_configuration_strings(tmp_path: Path) -> None:
    payload = tmp_path / "payload"
    payload.mkdir()
    metadata = tmp_path / "metadata" / "pyinstaller"
    metadata.mkdir(parents=True)
    (metadata / "Analysis-00.toc").write_text(
        "[('configuration', 'sounddevice', 'DATA')]", encoding="utf-8"
    )
    target = TargetSpec(
        "windows-x64",
        tmp_path / "policy",
        "win32",
        "x86_64",
        "3.12",
        tmp_path / "lock",
        "zip",
        "zip",
        "servonaut-{product_version}-{target}.{extension}",
        ("sounddevice",),
        (),
        tmp_path / "warnings",
        tmp_path / "sizes",
        "id",
        None,
    )
    artifact = ArtifactDescriptor(
        payload,
        payload / "servonaut.exe",
        None,
        target,
        tmp_path / "wheel",
        metadata / "warn-servonaut.txt",
        metadata.parent,
    )
    snapshot = PayloadSnapshot(
        payload, (), 0, PurePosixPath("servonaut.exe"), {}, {}, {}
    )

    validate_toc_policy(snapshot, artifact, 1024)


def test_toc_rejects_recursive_literal_input(tmp_path: Path) -> None:
    metadata = tmp_path / "metadata" / "pyinstaller"
    metadata.mkdir(parents=True)
    (metadata / "Analysis-00.toc").write_text("[" * 1001 + "]" * 1001, encoding="utf-8")

    from scripts.standalone_cli.toc_policy import _modules_from_toc

    with pytest.raises(ArtifactEvidenceError, match="TOC"):
        _modules_from_toc(metadata / "Analysis-00.toc", 4096)
