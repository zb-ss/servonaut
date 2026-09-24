"""Unit coverage for bounded literal PyInstaller TOC policy checks."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from scripts.standalone_cli.artifact_filesystem import _validate_forbidden_paths
from scripts.standalone_cli.artifact_types import (
    ArtifactDescriptor,
    ArtifactEvidenceError,
    PayloadEntry,
    PayloadSnapshot,
)
from scripts.standalone_cli.model import TargetSpec, load_target_spec
from scripts.standalone_cli.toc_policy import validate_toc_policy

_POLICY_PATH = (
    Path(__file__).parents[2] / "packaging" / "standalone_cli" / "target-policy.json"
)


def _toc_case(
    tmp_path: Path,
    target_name: str,
    analysis: str,
    *,
    entries: tuple[str, ...] = (),
    pyz: str | None = "[]",
) -> tuple[PayloadSnapshot, ArtifactDescriptor]:
    payload = tmp_path / "payload"
    payload.mkdir()
    metadata = tmp_path / "metadata" / "pyinstaller"
    metadata.mkdir(parents=True)
    (metadata / "Analysis-00.toc").write_text(analysis, encoding="utf-8")
    if pyz is not None:
        (metadata / "PYZ-00.toc").write_text(pyz, encoding="utf-8")
    target = load_target_spec(_POLICY_PATH, target_name)
    artifact = ArtifactDescriptor(
        payload,
        payload / "servonaut",
        None,
        target,
        tmp_path / "wheel",
        metadata / "warn-servonaut.txt",
        metadata.parent,
    )
    snapshot = PayloadSnapshot(
        payload,
        tuple(
            PayloadEntry(PurePosixPath(path), "file", 0o644, 1, "0" * 64, None)
            for path in entries
        ),
        0,
        PurePosixPath("servonaut"),
        {},
        {},
        {},
    )
    return snapshot, artifact


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
        1800,
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
    (metadata / "PYZ-00.toc").write_text("[]", encoding="utf-8")
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
        1800,
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


@pytest.mark.parametrize(
    "target_name,destination",
    (
        (
            "linux-x64-ubuntu-22.04",
            "python3.12/lib-dynload/readline.cpython-312-x86_64-linux-gnu.so",
        ),
        ("macos-arm64", "python3.12/lib-dynload/readline.cpython-312-darwin.so"),
        ("windows-x64", "sounddevice\\_backend.cp312-win_amd64.pyd"),
    ),
)
def test_toc_rejects_forbidden_extension_modules(
    tmp_path: Path, target_name: str, destination: str
) -> None:
    snapshot, artifact = _toc_case(
        tmp_path,
        target_name,
        f"[({destination!r}, '/build/source', 'EXTENSION')]",
    )

    with pytest.raises(ArtifactEvidenceError, match="forbidden module"):
        validate_toc_policy(snapshot, artifact, 1 << 20)


def test_toc_accepts_permitted_extension_modules(tmp_path: Path) -> None:
    snapshot, artifact = _toc_case(
        tmp_path,
        "linux-x64-ubuntu-22.04",
        "[('python3.12/lib-dynload/_ssl.cpython-312-x86_64-linux-gnu.so', 's', "
        "'EXTENSION'), ('cryptography/hazmat/bindings/_rust.abi3.so', 's', "
        "'EXTENSION'), ('libreadline.so.8', 's', 'BINARY')]",
    )

    validate_toc_policy(snapshot, artifact, 1 << 20)


def test_toc_rejects_an_unreadable_extension_destination(tmp_path: Path) -> None:
    snapshot, artifact = _toc_case(
        tmp_path,
        "linux-x64-ubuntu-22.04",
        "[('lib-dynload/_ssl.so', 's', 'EXTENSION')]",
    )

    with pytest.raises(ArtifactEvidenceError, match="invalid extension entry"):
        validate_toc_policy(snapshot, artifact, 1 << 20)


def test_toc_policy_requires_every_pyinstaller_toc(tmp_path: Path) -> None:
    snapshot, artifact = _toc_case(
        tmp_path, "linux-x64-ubuntu-22.04", "[]", pyz=None
    )

    with pytest.raises(ArtifactEvidenceError, match="TOC is unavailable"):
        validate_toc_policy(snapshot, artifact, 1 << 20)


@pytest.mark.parametrize(
    "path,forbidden",
    (
        ("_internal/servonaut/desktop/voice/engine.py", True),
        ("_internal/servonaut/renderer/assets/app.js", True),
        ("_internal/pkg/__pycache__/module.pyc", True),
        ("__pycache__/module.pyc", True),
        ("model.onnx", True),
        ("_internal/models/nested/model.onnx", True),
        ("tests/test_payload.py", True),
        (".hidden", True),
        (".hidden/child", True),
        ("_internal/pkg/tests/test_module.py", False),
        ("_internal/.hidden", False),
        ("_internal/servonaut/desktopish/module.py", False),
    ),
)
def test_every_payload_check_applies_one_forbidden_path_semantics(
    tmp_path: Path, path: str, forbidden: bool
) -> None:
    snapshot, artifact = _toc_case(
        tmp_path, "linux-x64-ubuntu-22.04", "[]", entries=(path,)
    )
    patterns = artifact.target.forbidden_path_patterns

    if forbidden:
        with pytest.raises(ArtifactEvidenceError, match="forbidden path"):
            _validate_forbidden_paths(snapshot.entries, patterns)
        with pytest.raises(ArtifactEvidenceError, match="forbidden relative path"):
            validate_toc_policy(snapshot, artifact, 1 << 20)
    else:
        _validate_forbidden_paths(snapshot.entries, patterns)
        validate_toc_policy(snapshot, artifact, 1 << 20)
