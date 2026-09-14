"""Unit coverage for bounded PE/ELF native evidence checks."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path, PurePosixPath

import pytest

from scripts.standalone_cli.artifact_types import (
    ArtifactEvidenceError,
    PayloadEntry,
    PayloadSnapshot,
)
from scripts.standalone_cli.evidence_policy_types import (
    EvidenceLimits,
    NativeConstraints,
)
from scripts.standalone_cli.model import TargetSpec
from scripts.standalone_cli.native_inspect import inspect_native_payload


def _target(tmp_path: Path, platform: str = "win32") -> TargetSpec:
    name = {
        "win32": "windows-x64",
        "linux": "linux-x64-ubuntu-22.04",
        "darwin": "macos-arm64",
    }[platform]
    archive = "zip" if platform == "win32" else "tar.gz"
    return TargetSpec(
        name=name,
        policy_path=tmp_path / "policy.json",
        platform=platform,
        architecture="x86_64",
        python_version="3.12",
        requirements_lock=tmp_path / "lock.txt",
        archive_format=archive,
        archive_extension=archive,
        artifact_name_template="servonaut-{product_version}-{target}.{extension}",
        forbidden_modules=(),
        forbidden_path_patterns=(),
        warning_allowlist=tmp_path / "warnings.json",
        size_baselines=tmp_path / "sizes.json",
        size_baseline_id="baseline",
        macos_minimum_version="13.0" if platform == "darwin" else None,
    )


def _snapshot(root: Path, name: str) -> PayloadSnapshot:
    path = root / name
    return PayloadSnapshot(
        root,
        (
            PayloadEntry(
                PurePosixPath(name), "file", 0o755, path.stat().st_size, None, None
            ),
        ),
        path.stat().st_size,
        PurePosixPath(name),
        {},
        {},
        {},
    )


def _limits() -> EvidenceLimits:
    return EvidenceLimits(1024, 100, 1024, 4096, 1, 4096)


def test_windows_pe_requires_pe32_plus_x64(tmp_path: Path) -> None:
    binary = tmp_path / "servonaut.exe"
    data = bytearray(512)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (128).to_bytes(4, "little")
    data[128:132] = b"PE\0\0"
    data[132:134] = (0x8664).to_bytes(2, "little")
    data[152:154] = (0x20B).to_bytes(2, "little")
    binary.write_bytes(data)
    constraints = NativeConstraints("0x8664", "62", "2.35", "ubuntu", "22.04")

    facts = inspect_native_payload(
        _snapshot(tmp_path, binary.name), _target(tmp_path), constraints, _limits()
    )

    assert facts == [{"path": binary.name, "kind": "pe", "machine": "0x8664"}]


@pytest.mark.parametrize(
    ("machine", "optional_magic", "message"),
    [(0x14C, 0x20B, "architecture"), (0x8664, 0x10B, "architecture")],
)
def test_windows_pe_rejects_wrong_native_shape(
    tmp_path: Path, machine: int, optional_magic: int, message: str
) -> None:
    binary = tmp_path / "servonaut.exe"
    data = bytearray(512)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (128).to_bytes(4, "little")
    data[128:132] = b"PE\0\0"
    data[132:134] = machine.to_bytes(2, "little")
    data[152:154] = optional_magic.to_bytes(2, "little")
    binary.write_bytes(data)

    with pytest.raises(ArtifactEvidenceError, match=message):
        inspect_native_payload(
            _snapshot(tmp_path, binary.name),
            _target(tmp_path),
            NativeConstraints("0x8664", "62", "2.35", "ubuntu", "22.04"),
            _limits(),
        )


def test_windows_pe_rejects_truncated_header(tmp_path: Path) -> None:
    binary = tmp_path / "servonaut.exe"
    binary.write_bytes(b"MZ")

    with pytest.raises(ArtifactEvidenceError, match="truncated PE"):
        inspect_native_payload(
            _snapshot(tmp_path, binary.name),
            _target(tmp_path),
            NativeConstraints("0x8664", "62", "2.35", "ubuntu", "22.04"),
            _limits(),
        )


@pytest.mark.parametrize(
    "magic",
    [
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    ],
)
def test_macho_rejects_fat_containers_even_with_one_slice(
    tmp_path: Path, magic: bytes
) -> None:
    binary = tmp_path / "servonaut"
    binary.write_bytes(magic + b"\0" * 16)

    with pytest.raises(ArtifactEvidenceError, match="fat Mach-O"):
        inspect_native_payload(
            _snapshot(tmp_path, binary.name),
            replace(
                _target(tmp_path, "darwin"), name="macos-x64", architecture="x86_64"
            ),
            NativeConstraints("0x8664", "62", "2.35", "ubuntu", "22.04"),
            _limits(),
        )


def test_native_inspection_requires_the_declared_executable(tmp_path: Path) -> None:
    executable = tmp_path / "servonaut"
    executable.write_text("resource", encoding="utf-8")

    with pytest.raises(ArtifactEvidenceError, match="declared executable"):
        inspect_native_payload(
            _snapshot(tmp_path, executable.name),
            _target(tmp_path),
            NativeConstraints("0x8664", "62", "2.35", "ubuntu", "22.04"),
            _limits(),
        )


def test_linux_host_and_elf_machine_are_required(tmp_path: Path) -> None:
    binary = tmp_path / "servonaut"
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4], data[5] = 2, 1
    data[18:20] = (62).to_bytes(2, "little")
    binary.write_bytes(data)
    release = tmp_path / "os-release"
    release.write_text("ID=ubuntu\nVERSION_ID=24.04\n", encoding="utf-8")
    constraints = NativeConstraints("0x8664", "62", "2.35", "ubuntu", "22.04")

    with pytest.raises(ArtifactEvidenceError, match="host does not match"):
        inspect_native_payload(
            _snapshot(tmp_path, binary.name),
            _target(tmp_path, "linux"),
            constraints,
            _limits(),
            os_release_path=release,
        )


def test_linux_host_rejects_duplicate_release_fields(tmp_path: Path) -> None:
    binary = tmp_path / "servonaut"
    binary.write_bytes(b"not native")
    release = tmp_path / "os-release"
    release.write_text("ID=ubuntu\nID=ubuntu\nVERSION_ID=22.04\n", encoding="utf-8")
    constraints = NativeConstraints("0x8664", "62", "2.35", "ubuntu", "22.04")

    with pytest.raises(ArtifactEvidenceError, match="release data is malformed"):
        inspect_native_payload(
            _snapshot(tmp_path, binary.name),
            _target(tmp_path, "linux"),
            constraints,
            _limits(),
            os_release_path=release,
        )


def test_linux_rejects_newer_or_malformed_glibc_requirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "servonaut"
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4], data[5] = 2, 1
    data[18:20] = (62).to_bytes(2, "little")
    binary.write_bytes(data)
    release = tmp_path / "os-release"
    release.write_text("ID=ubuntu\nVERSION_ID=22.04\n", encoding="utf-8")
    constraints = NativeConstraints("0x8664", "62", "2.35", "ubuntu", "22.04")
    target = _target(tmp_path, "linux")

    monkeypatch.setattr(
        "scripts.standalone_cli.native_inspect.run_bounded_command",
        lambda *_args: b"GLIBC_2.36",
    )
    with pytest.raises(ArtifactEvidenceError, match="exceeds target floor"):
        inspect_native_payload(
            _snapshot(tmp_path, binary.name),
            target,
            constraints,
            _limits(),
            os_release_path=release,
        )

    monkeypatch.setattr(
        "scripts.standalone_cli.native_inspect.run_bounded_command",
        lambda *_args: b"GLIBC_2.bad",
    )
    with pytest.raises(
        ArtifactEvidenceError, match="symbol-version output is malformed"
    ):
        inspect_native_payload(
            _snapshot(tmp_path, binary.name),
            target,
            constraints,
            _limits(),
            os_release_path=release,
        )


@pytest.mark.parametrize("outcome", ["timeout", "oversized"])
def test_native_subprocess_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    binary = tmp_path / "servonaut"
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4], data[5] = 2, 1
    data[18:20] = (62).to_bytes(2, "little")
    binary.write_bytes(data)
    release = tmp_path / "os-release"
    release.write_text("ID=ubuntu\nVERSION_ID=22.04\n", encoding="utf-8")
    if outcome == "timeout":
        monkeypatch.setattr(
            "scripts.standalone_cli.native_inspect.run_bounded_command",
            lambda *_args: (_ for _ in ()).throw(ArtifactEvidenceError("timed out")),
        )
    else:
        monkeypatch.setattr(
            "scripts.standalone_cli.native_inspect.run_bounded_command",
            lambda *_args: (_ for _ in ()).throw(
                ArtifactEvidenceError("exceeded its output limit")
            ),
        )

    with pytest.raises(ArtifactEvidenceError, match="could not inspect ELF"):
        inspect_native_payload(
            _snapshot(tmp_path, binary.name),
            _target(tmp_path, "linux"),
            NativeConstraints("0x8664", "62", "2.35", "ubuntu", "22.04"),
            _limits(),
            os_release_path=release,
        )


@pytest.mark.parametrize(("minimum", "message"), [("13.0", None), ("14.0", "exceeds")])
def test_macho_requires_thin_target_architecture_and_minimum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, minimum: str, message: str | None
) -> None:
    binary = tmp_path / "servonaut"
    binary.write_bytes(b"\xcf\xfa\xed\xfe")
    results = iter(
        [
            (
                "Load command 0\n"
                "      cmd LC_BUILD_VERSION\n"
                " platform 1\n"
                f"    minos {minimum}\n"
                "      tool LD\n"
                "   version 819.6\n"
                "Load command 1\n"
                "      cmd LC_LOAD_DYLIB\n"
                " current version 1351.0.0\n"
                "compatibility version 1.0.0\n"
            ).encode(),
            b"x86_64\n",
        ]
    )
    monkeypatch.setattr(
        "scripts.standalone_cli.native_inspect.run_bounded_command",
        lambda *_args: next(results),
    )
    target = _target(tmp_path, "darwin")
    target = replace(target, name="macos-x64", architecture="x86_64")

    def inspect() -> list[dict[str, object]]:
        return inspect_native_payload(
            _snapshot(tmp_path, binary.name),
            target,
            NativeConstraints("0x8664", "62", "2.35", "ubuntu", "22.04"),
            _limits(),
        )

    if message is None:
        assert inspect() == [
            {
                "path": binary.name,
                "kind": "macho",
                "architecture": "x86_64",
                "minimum": "13.0",
            }
        ]
    else:
        with pytest.raises(ArtifactEvidenceError, match=message):
            inspect()


@pytest.mark.parametrize(
    ("deployment", "message"),
    [
        ("platform 2\n    minos 13.0", "platform"),
        ("platform 1\n    minos not-a-version", "target is invalid"),
        (
            "platform 1\n    minos 12.0\nLoad command 1\n"
            + "cmd LC_VERSION_MIN_MACOSX\nversion 13.0",
            "target is invalid",
        ),
    ],
)
def test_macho_rejects_foreign_malformed_or_conflicting_deployment_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    deployment: str,
    message: str,
) -> None:
    binary = tmp_path / "servonaut"
    binary.write_bytes(b"\xcf\xfa\xed\xfe")
    output = f"Load command 0\ncmd LC_BUILD_VERSION\n{deployment}\n".encode()
    results = iter([output, b"x86_64\n"])
    monkeypatch.setattr(
        "scripts.standalone_cli.native_inspect.run_bounded_command",
        lambda *_args: next(results),
    )
    target = replace(
        _target(tmp_path, "darwin"), name="macos-x64", architecture="x86_64"
    )

    with pytest.raises(ArtifactEvidenceError, match=message):
        inspect_native_payload(
            _snapshot(tmp_path, binary.name),
            target,
            NativeConstraints("0x8664", "62", "2.35", "ubuntu", "22.04"),
            _limits(),
        )


def test_macho_accepts_legacy_macos_deployment_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "servonaut"
    binary.write_bytes(b"\xcf\xfa\xed\xfe")
    results = iter(
        [
            b"Load command 0\ncmd LC_VERSION_MIN_MACOSX\nversion 13.0\nsdk 14.0\n",
            b"x86_64\n",
        ]
    )
    monkeypatch.setattr(
        "scripts.standalone_cli.native_inspect.run_bounded_command",
        lambda *_args: next(results),
    )
    target = replace(
        _target(tmp_path, "darwin"), name="macos-x64", architecture="x86_64"
    )

    assert inspect_native_payload(
        _snapshot(tmp_path, binary.name),
        target,
        NativeConstraints("0x8664", "62", "2.35", "ubuntu", "22.04"),
        _limits(),
    ) == [
        {
            "path": binary.name,
            "kind": "macho",
            "architecture": "x86_64",
            "minimum": "13.0",
        }
    ]


def test_macho_accepts_multiple_build_tools_without_relaxing_deployment_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "servonaut"
    binary.write_bytes(b"\xcf\xfa\xed\xfe")
    results = iter(
        [
            (
                b"Load command 0\n"
                b"cmd LC_BUILD_VERSION\n"
                b"platform 1\n"
                b"minos 13.0\n"
                b"sdk 14.0\n"
                b"ntools 2\n"
                b"tool LD\n"
                b"version 819.6\n"
                b"tool LLD\n"
                b"version 1024.1\n"
            ),
            b"x86_64\n",
        ]
    )
    monkeypatch.setattr(
        "scripts.standalone_cli.native_inspect.run_bounded_command",
        lambda *_args: next(results),
    )
    target = replace(
        _target(tmp_path, "darwin"), name="macos-x64", architecture="x86_64"
    )

    assert (
        inspect_native_payload(
            _snapshot(tmp_path, binary.name),
            target,
            NativeConstraints("0x8664", "62", "2.35", "ubuntu", "22.04"),
            _limits(),
        )[0]["minimum"]
        == "13.0"
    )
