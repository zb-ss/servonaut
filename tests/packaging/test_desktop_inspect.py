"""Contract tests for desktop payload inspection engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.desktop_shell.assets import stage_frontend_assets
from scripts.desktop_shell.inspect import (
    DesktopInspectionError,
    DesktopInspectionReport,
    inspect_desktop_payload,
    main,
)
from scripts.desktop_shell.model import (
    DesktopTargetSpec,
    load_desktop_target_spec,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POLICY_PATH = _REPO_ROOT / "packaging" / "desktop_shell" / "target-policy.json"


@pytest.fixture
def target_spec() -> DesktopTargetSpec:
    return load_desktop_target_spec(_POLICY_PATH, "linux-x64-ubuntu-22.04")


def _create_mock_payload(
    root: Path,
    target: DesktopTargetSpec,
    version: str = "2.26.3",
    header: bytes = b"\x7fELF",
) -> Path:
    root.mkdir(parents=True, exist_ok=True)

    gui = root / "servonaut-desktop"
    child = root / "servonaut-desktop-child"
    console = root / "servonaut"

    for p, content in (
        (gui, header + b"1"),
        (child, header + b"2"),
        (console, header + b"3"),
    ):
        p.write_bytes(content)
        p.chmod(0o755)

    marker = {
        "schema_version": 1,
        "distribution": "packaged-desktop",
        "product_version": version,
        "build_revision": "rev1",
        "console_helper": "servonaut",
        "desktop_child": "servonaut-desktop-child",
    }
    (root / "servonaut-runtime.json").write_text(json.dumps(marker))

    frontend = root / "frontend"
    stage_frontend_assets(frontend)

    return root


def test_inspect_desktop_payload_success(
    tmp_path: Path, target_spec: DesktopTargetSpec
) -> None:
    payload = _create_mock_payload(tmp_path / "payload", target_spec)
    report = inspect_desktop_payload(payload, target_spec, "2.26.3")

    assert isinstance(report, DesktopInspectionReport)
    assert report.target == "linux-x64-ubuntu-22.04"
    assert report.product_version == "2.26.3"
    assert report.marker_valid is True
    assert report.assets_verified_count > 0
    assert report.binary_formats["gui"] == "elf"
    assert report.binary_formats["child"] == "elf"
    assert report.binary_formats["console"] == "elf"


def test_inspect_rejects_missing_executable(
    tmp_path: Path, target_spec: DesktopTargetSpec
) -> None:
    payload = _create_mock_payload(tmp_path / "payload", target_spec)
    (payload / "servonaut-desktop-child").unlink()

    with pytest.raises(DesktopInspectionError, match="Child executable does not exist"):
        inspect_desktop_payload(payload, target_spec, "2.26.3")


def test_inspect_rejects_non_executable_permissions(
    tmp_path: Path, target_spec: DesktopTargetSpec
) -> None:
    payload = _create_mock_payload(tmp_path / "payload", target_spec)
    (payload / "servonaut").chmod(0o644)

    with pytest.raises(DesktopInspectionError, match="is not executable"):
        inspect_desktop_payload(payload, target_spec, "2.26.3")


def test_inspect_rejects_wrong_binary_format(
    tmp_path: Path, target_spec: DesktopTargetSpec
) -> None:
    payload = _create_mock_payload(
        tmp_path / "payload", target_spec, header=b"MZ\x00\x00"
    )

    with pytest.raises(DesktopInspectionError, match="does not match expected 'elf'"):
        inspect_desktop_payload(payload, target_spec, "2.26.3")


def test_inspect_rejects_aliased_executables(
    tmp_path: Path, target_spec: DesktopTargetSpec
) -> None:
    payload = _create_mock_payload(tmp_path / "payload", target_spec)
    child = payload / "servonaut-desktop-child"
    child.unlink()
    # Hardlink console to child
    child.hardlink_to(payload / "servonaut")

    with pytest.raises(DesktopInspectionError, match="must be distinct files"):
        inspect_desktop_payload(payload, target_spec, "2.26.3")


def test_inspect_rejects_missing_marker(
    tmp_path: Path, target_spec: DesktopTargetSpec
) -> None:
    payload = _create_mock_payload(tmp_path / "payload", target_spec)
    (payload / "servonaut-runtime.json").unlink()

    with pytest.raises(
        DesktopInspectionError, match="servonaut-runtime.json marker missing"
    ):
        inspect_desktop_payload(payload, target_spec, "2.26.3")


def test_inspect_rejects_marker_version_mismatch(
    tmp_path: Path, target_spec: DesktopTargetSpec
) -> None:
    payload = _create_mock_payload(tmp_path / "payload", target_spec, version="2.26.2")

    with pytest.raises(
        DesktopInspectionError, match="Product version mismatch in marker"
    ):
        inspect_desktop_payload(payload, target_spec, "2.26.3")


def test_inspect_rejects_forbidden_voice_module(
    tmp_path: Path, target_spec: DesktopTargetSpec
) -> None:
    payload = _create_mock_payload(tmp_path / "payload", target_spec)
    (payload / "faster_whisper.py").write_text("forbidden")

    with pytest.raises(DesktopInspectionError, match="Forbidden module found"):
        inspect_desktop_payload(payload, target_spec, "2.26.3")


def test_inspect_rejects_asset_tampering(
    tmp_path: Path, target_spec: DesktopTargetSpec
) -> None:
    payload = _create_mock_payload(tmp_path / "payload", target_spec)
    index_html = payload / "frontend" / "index.html"
    index_html.write_text("tampered content")

    with pytest.raises(DesktopInspectionError, match="Asset hash mismatch"):
        inspect_desktop_payload(payload, target_spec, "2.26.3")


def test_inspect_main_cli(tmp_path: Path, target_spec: DesktopTargetSpec) -> None:
    payload = _create_mock_payload(tmp_path / "payload", target_spec)
    output_json = tmp_path / "report.json"

    argv = [
        "--payload",
        str(payload),
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
