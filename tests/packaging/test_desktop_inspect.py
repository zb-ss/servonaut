"""Contract tests for desktop payload inspection engine."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import shutil
import struct
from pathlib import Path

import pytest

import scripts.desktop_shell.inspect as desktop_inspect
from scripts.desktop_shell.assets import find_upstream_static_dir, stage_frontend_assets
from scripts.desktop_shell.inspect import (
    DesktopInspectionError,
    DesktopInspectionReport,
    inspect_desktop_payload,
    main,
)

if find_upstream_static_dir() is None:
    pytest.skip(
        "Requires upstream textual-serve static assets directory",
        allow_module_level=True,
    )
from scripts.desktop_shell.model import (
    DesktopTargetSpec,
    load_desktop_target_spec,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POLICY_PATH = _REPO_ROOT / "packaging" / "desktop_shell" / "target-policy.json"
_TARGETS = ("windows-x64", "macos-x64", "macos-arm64", "linux-x64-ubuntu-22.04")
_NOTICE_DISTRIBUTIONS = ("aaa-one", "bbb-two", "ccc-three", "ddd-four", "eee-five")
_SAFE_TOC = [("servonaut", "/site/servonaut/__init__.py", "PYMODULE")]
_CPU_TYPES = {"x86_64": 0x01000007, "arm64": 0x0100000C}


def _elf(machine: int = 0x3E) -> bytes:
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = machine.to_bytes(2, "little")
    return bytes(header)


def _pe(machine: int = 0x8664) -> bytes:
    header = bytearray(0x80 + 26)
    header[:2] = b"MZ"
    header[0x3C:0x40] = (0x80).to_bytes(4, "little")
    header[0x80:0x86] = b"PE\0\0" + machine.to_bytes(2, "little")
    header[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    return bytes(header)


def _macho(architecture: str, minimum: tuple[int, int] = (11, 0)) -> bytes:
    version = (minimum[0] << 16) | (minimum[1] << 8)
    command = struct.pack("<IIIIII", 0x32, 24, 1, version, 0, 0)
    header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, _CPU_TYPES[architecture], 0, 2, 1, len(command), 0, 0
    )
    return header + command


def _native_executable(target: DesktopTargetSpec) -> bytes:
    if target.platform == "win32":
        return _pe()
    if target.platform == "darwin":
        return _macho(target.architecture)
    return _elf()


@pytest.fixture(autouse=True)
def notice_policy(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Replace the reviewed notice policy with synthetic notices of known bytes."""
    root = tmp_path_factory.mktemp("notice-policy")
    rows = []
    for distribution in _NOTICE_DISTRIBUTIONS:
        digest = hashlib.sha256(_notice_text(distribution)).hexdigest()
        rows.append(
            {
                "distribution": distribution,
                "version": "1.0.0",
                "source_relative_path": (
                    f"{distribution.replace('-', '_')}-1.0.0.dist-info/licenses/LICENSE"
                ),
                "payload_path": f"_internal/notices/{distribution}-LICENSE.txt",
                "sha256_by_target": {name: digest for name in _TARGETS},
            }
        )
    policy = root / "embedded-notices.json"
    policy.write_text(json.dumps({"schema_version": 1, "notices": rows}))
    monkeypatch.setattr(desktop_inspect, "EMBEDDED_NOTICE_POLICY_PATH", policy)
    return policy


def _notice_text(distribution: str) -> bytes:
    return f"{distribution} license text\n".encode()


@pytest.fixture
def target_spec() -> DesktopTargetSpec:
    return load_desktop_target_spec(_POLICY_PATH, "linux-x64-ubuntu-22.04")


def _create_mock_payload(
    root: Path,
    target: DesktopTargetSpec,
    version: str = "2.26.3",
    header: bytes | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    ext = ".exe" if target.platform == "win32" else ""
    content = _native_executable(target) if header is None else header
    for index, name in enumerate(
        (f"servonaut-desktop{ext}", f"servonaut-desktop-child{ext}", f"servonaut{ext}")
    ):
        path = root / name
        path.write_bytes(content + bytes([index]))
        path.chmod(0o755)

    marker = {
        "schema_version": 1,
        "distribution": "packaged-desktop",
        "product_version": version,
        "build_revision": "rev1",
        "console_helper": f"servonaut{ext}",
        "desktop_child": f"servonaut-desktop-child{ext}",
    }
    (root / "servonaut-runtime.json").write_text(json.dumps(marker))

    stage_frontend_assets(root / "frontend")
    shutil.copytree(root / "frontend", root / "_internal" / "frontend")

    notices = root / "_internal" / "notices"
    notices.mkdir(parents=True)
    (notices / "CPython-LICENSE.txt").write_text("Python license\n")
    for distribution in _NOTICE_DISTRIBUTIONS:
        (notices / f"{distribution}-LICENSE.txt").write_bytes(_notice_text(distribution))
    return root


def _create_build_metadata(
    root: Path,
    target: DesktopTargetSpec,
    version: str = "2.26.3",
    tocs: dict[str, list[tuple[str, str, str]]] | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "dependency-provenance.json").write_text(
        json.dumps({"target": target.name, "product_version": version})
    )
    for role in ("gui", "child", "console"):
        toc_dir = root / "executables" / role / "pyinstaller"
        toc_dir.mkdir(parents=True)
        entries = (tocs or {}).get(role, _SAFE_TOC)
        for name in ("Analysis-00.toc", "PYZ-00.toc"):
            (toc_dir / name).write_text(repr(entries))
    return root


@pytest.fixture
def build(tmp_path: Path, target_spec: DesktopTargetSpec) -> tuple[Path, Path]:
    return (
        _create_mock_payload(tmp_path / "payload", target_spec),
        _create_build_metadata(tmp_path / "build-metadata", target_spec),
    )


def _inspect(
    build: tuple[Path, Path], target: DesktopTargetSpec
) -> DesktopInspectionReport:
    payload, metadata = build
    return inspect_desktop_payload(payload, target, "2.26.3", metadata)


def test_inspect_desktop_payload_success(
    build: tuple[Path, Path], target_spec: DesktopTargetSpec
) -> None:
    report = _inspect(build, target_spec)

    assert isinstance(report, DesktopInspectionReport)
    assert report.target == "linux-x64-ubuntu-22.04"
    assert report.product_version == "2.26.3"
    assert report.marker_valid is True
    assert report.assets_verified_count > 0
    assert report.notices_verified_count == 6
    assert report.regular_file_count > 0
    assert report.binary_formats == {"gui": "elf", "child": "elf", "console": "elf"}


def test_inspect_rejects_missing_executable(
    build: tuple[Path, Path], target_spec: DesktopTargetSpec
) -> None:
    (build[0] / "servonaut-desktop-child").unlink()

    with pytest.raises(DesktopInspectionError, match="Child executable does not exist"):
        _inspect(build, target_spec)


def test_inspect_rejects_non_executable_permissions(
    build: tuple[Path, Path], target_spec: DesktopTargetSpec
) -> None:
    (build[0] / "servonaut").chmod(0o644)

    with pytest.raises(DesktopInspectionError, match="is not executable"):
        _inspect(build, target_spec)


def test_inspect_rejects_wrong_binary_format(
    tmp_path: Path, target_spec: DesktopTargetSpec
) -> None:
    payload = _create_mock_payload(tmp_path / "payload", target_spec, header=_pe())
    metadata = _create_build_metadata(tmp_path / "metadata", target_spec)

    with pytest.raises(DesktopInspectionError, match="does not match expected 'elf'"):
        _inspect((payload, metadata), target_spec)


def test_inspect_rejects_foreign_elf_architecture(
    tmp_path: Path, target_spec: DesktopTargetSpec
) -> None:
    payload = _create_mock_payload(
        tmp_path / "payload", target_spec, header=_elf(machine=0xB7)
    )
    metadata = _create_build_metadata(tmp_path / "metadata", target_spec)

    with pytest.raises(DesktopInspectionError, match="architecture 'arm64'"):
        _inspect((payload, metadata), target_spec)


def test_inspect_checks_pe_machine_for_windows(tmp_path: Path) -> None:
    target = load_desktop_target_spec(_POLICY_PATH, "windows-x64")
    metadata = _create_build_metadata(tmp_path / "metadata", target)
    native = _create_mock_payload(tmp_path / "native", target)
    foreign = _create_mock_payload(tmp_path / "foreign", target, header=_pe(0xAA64))

    assert _inspect((native, metadata), target).binary_formats["gui"] == "pe"
    with pytest.raises(DesktopInspectionError, match="architecture 'arm64'"):
        _inspect((foreign, metadata), target)


def test_inspect_rejects_aliased_executables(
    build: tuple[Path, Path], target_spec: DesktopTargetSpec
) -> None:
    child = build[0] / "servonaut-desktop-child"
    child.unlink()
    child.hardlink_to(build[0] / "servonaut")

    with pytest.raises(DesktopInspectionError, match="must be distinct files"):
        _inspect(build, target_spec)


def test_inspect_rejects_missing_marker(
    build: tuple[Path, Path], target_spec: DesktopTargetSpec
) -> None:
    (build[0] / "servonaut-runtime.json").unlink()

    with pytest.raises(
        DesktopInspectionError, match="servonaut-runtime.json marker missing"
    ):
        _inspect(build, target_spec)


def test_inspect_rejects_marker_version_mismatch(
    tmp_path: Path, target_spec: DesktopTargetSpec
) -> None:
    payload = _create_mock_payload(tmp_path / "payload", target_spec, version="2.26.2")
    metadata = _create_build_metadata(tmp_path / "metadata", target_spec)

    with pytest.raises(
        DesktopInspectionError, match="Product version mismatch in marker"
    ):
        _inspect((payload, metadata), target_spec)


def test_inspect_rejects_metadata_from_another_build(
    tmp_path: Path, target_spec: DesktopTargetSpec
) -> None:
    payload = _create_mock_payload(tmp_path / "payload", target_spec)
    metadata = _create_build_metadata(
        tmp_path / "metadata", target_spec, version="2.26.2"
    )

    with pytest.raises(DesktopInspectionError, match="does not belong"):
        _inspect((payload, metadata), target_spec)


@pytest.mark.parametrize(
    ("role", "module"),
    [
        ("gui", "faster_whisper"),
        ("child", "sounddevice.backend"),
        ("console", "_sounddevice"),
    ],
)
def test_inspect_rejects_forbidden_module_recorded_in_any_toc(
    tmp_path: Path, target_spec: DesktopTargetSpec, role: str, module: str
) -> None:
    payload = _create_mock_payload(tmp_path / "payload", target_spec)
    metadata = _create_build_metadata(
        tmp_path / "metadata",
        target_spec,
        tocs={role: [*_SAFE_TOC, (module, "/site/module.py", "PYMODULE")]},
    )

    with pytest.raises(DesktopInspectionError, match="forbidden module"):
        _inspect((payload, metadata), target_spec)


def test_inspect_requires_every_executable_toc(
    build: tuple[Path, Path], target_spec: DesktopTargetSpec
) -> None:
    (build[1] / "executables" / "console" / "pyinstaller" / "PYZ-00.toc").unlink()

    with pytest.raises(DesktopInspectionError, match="console executable PYZ-00.toc"):
        _inspect(build, target_spec)


@pytest.mark.parametrize(
    "relative",
    [
        "_internal/_sounddevice_data/portaudio-binaries/libportaudio.so",
        "_internal/tests/test_payload.py",
        "_internal/models/voice.onnx",
        "model.onnx",
        "_internal/python3.12/lib-dynload/readline.cpython-312-x86_64-linux-gnu.so",
    ],
)
def test_inspect_rejects_forbidden_payload_paths(
    build: tuple[Path, Path], target_spec: DesktopTargetSpec, relative: str
) -> None:
    path = build[0] / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"forbidden")

    with pytest.raises(DesktopInspectionError, match="forbidden relative path"):
        _inspect(build, target_spec)


@pytest.mark.parametrize("frontend", ["frontend", "_internal/frontend"])
def test_inspect_rejects_unlisted_frontend_file(
    build: tuple[Path, Path], target_spec: DesktopTargetSpec, frontend: str
) -> None:
    (build[0] / frontend / "injected.js").write_text("fetch('https://example.invalid')")

    with pytest.raises(DesktopInspectionError, match="Unlisted files"):
        _inspect(build, target_spec)


def test_inspect_requires_packaged_licenses_without_fallback(
    build: tuple[Path, Path], target_spec: DesktopTargetSpec
) -> None:
    (build[0] / "frontend" / "licenses.json").unlink()

    with pytest.raises(DesktopInspectionError, match="licenses.json"):
        _inspect(build, target_spec)


def test_inspect_rejects_altered_license_inventory(
    build: tuple[Path, Path], target_spec: DesktopTargetSpec
) -> None:
    licenses = build[0] / "_internal" / "frontend" / "licenses.json"
    licenses.write_text(licenses.read_text() + " ")

    with pytest.raises(DesktopInspectionError, match="licenses.json differs"):
        _inspect(build, target_spec)


def test_inspect_rejects_asset_tampering(
    build: tuple[Path, Path], target_spec: DesktopTargetSpec
) -> None:
    (build[0] / "frontend" / "index.html").write_text("tampered content")

    with pytest.raises(DesktopInspectionError, match="Staged hash mismatch"):
        _inspect(build, target_spec)


def test_inspect_requires_license_notices(
    build: tuple[Path, Path], target_spec: DesktopTargetSpec
) -> None:
    shutil.rmtree(build[0] / "_internal" / "notices")

    with pytest.raises(DesktopInspectionError, match="notices directory missing"):
        _inspect(build, target_spec)


@pytest.mark.parametrize(
    ("name", "content"),
    [("extra-LICENSE.txt", b"extra"), ("aaa-one-LICENSE.txt", b"altered")],
)
def test_inspect_rejects_notices_that_differ_from_policy(
    build: tuple[Path, Path], target_spec: DesktopTargetSpec, name: str, content: bytes
) -> None:
    (build[0] / "_internal" / "notices" / name).write_bytes(content)

    with pytest.raises(DesktopInspectionError, match="[Nn]otice"):
        _inspect(build, target_spec)


def test_inspect_rejects_empty_runtime_notice(
    build: tuple[Path, Path], target_spec: DesktopTargetSpec
) -> None:
    (build[0] / "_internal" / "notices" / "CPython-LICENSE.txt").write_bytes(b"")

    with pytest.raises(DesktopInspectionError, match="non-empty regular file"):
        _inspect(build, target_spec)


@pytest.mark.parametrize(
    ("max_bytes", "max_files", "message"),
    [(1024, 10_000, "Payload size"), (100 * 1024 * 1024, 5, "file count")],
)
def test_inspect_rejects_payload_above_size_baseline(
    build: tuple[Path, Path],
    target_spec: DesktopTargetSpec,
    tmp_path: Path,
    max_bytes: int,
    max_files: int,
    message: str,
) -> None:
    baselines = tmp_path / "size-baselines.json"
    baselines.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "baselines": {
                    target_spec.name: {
                        "target": target_spec.name,
                        "max_expanded_bytes": max_bytes,
                        "max_regular_file_count": max_files,
                        "rationale": "test ceiling",
                    }
                },
            }
        )
    )
    tight_target = dataclasses.replace(target_spec, size_baselines=baselines)

    with pytest.raises(DesktopInspectionError, match=message):
        _inspect(build, tight_target)


@pytest.mark.parametrize("target_name", ["macos-x64", "macos-arm64"])
def test_inspect_accepts_thin_macho_within_macos_floor(
    tmp_path: Path, target_name: str
) -> None:
    target = load_desktop_target_spec(_POLICY_PATH, target_name)
    payload = _create_mock_payload(tmp_path / "payload", target)
    (payload / "_internal" / "libexample.dylib").write_bytes(
        _macho(target.architecture, (10, 13))
    )
    metadata = _create_build_metadata(tmp_path / "metadata", target)

    assert _inspect((payload, metadata), target).binary_formats["gui"] == "macho"


def test_inspect_rejects_macho_for_the_other_architecture(tmp_path: Path) -> None:
    target = load_desktop_target_spec(_POLICY_PATH, "macos-x64")
    payload = _create_mock_payload(tmp_path / "payload", target, header=_macho("arm64"))
    metadata = _create_build_metadata(tmp_path / "metadata", target)

    with pytest.raises(DesktopInspectionError, match="architecture 'arm64'"):
        _inspect((payload, metadata), target)


@pytest.mark.parametrize(
    ("library", "message"),
    [
        (_macho("arm64", (14, 0)), "exceeds macOS 13.0"),
        (_macho("x86_64"), "architecture does not match"),
        (b"\xca\xfe\xba\xbe" + b"\0" * 28, "universal Mach-O"),
    ],
)
def test_inspect_rejects_payload_macho_outside_policy(
    tmp_path: Path, library: bytes, message: str
) -> None:
    target = load_desktop_target_spec(_POLICY_PATH, "macos-arm64")
    payload = _create_mock_payload(tmp_path / "payload", target)
    (payload / "_internal" / "libexample.dylib").write_bytes(library)
    metadata = _create_build_metadata(tmp_path / "metadata", target)

    with pytest.raises(DesktopInspectionError, match=message):
        _inspect((payload, metadata), target)


def test_inspect_main_cli(
    build: tuple[Path, Path], tmp_path: Path
) -> None:
    output_json = tmp_path / "report.json"
    argv = [
        "--payload",
        str(build[0]),
        "--build-metadata",
        str(build[1]),
        "--target",
        "linux-x64-ubuntu-22.04",
        "--product-version",
        "2.26.3",
        "--output",
        str(output_json),
    ]

    ret = main(argv)
    assert ret == 0
    assert output_json.is_file()
    data = json.loads(output_json.read_text(encoding="utf-8"))
    assert data["target"] == "linux-x64-ubuntu-22.04"
    assert data["marker_valid"] is True
