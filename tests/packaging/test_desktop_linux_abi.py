"""Contract tests for Linux GI ABI feasibility, PyGObject GLib floor, and payload audits."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.desktop_shell.linux_abi import (
    GLIB_FLOOR,
    PINNED_PYGOBJECT_VERSION,
    REQUIRED_GTK_VERSION,
    REQUIRED_PYTHON_VERSION,
    REQUIRED_WEBKIT_API,
    UBUNTU_2204_BASELINE,
    UBUNTU_2404_FORWARD,
    LinuxAbiError,
    audit_linux_onedir_payload,
    get_split_runtime_fallback_spec,
    validate_pygobject_abi,
)
from scripts.desktop_shell.model import load_desktop_target_policy


def test_linux_target_policy_declares_exact_abi_spec() -> None:
    policy = load_desktop_target_policy()
    linux_target = policy.targets["linux-x64-ubuntu-22.04"]

    assert linux_target.linux_abi is not None
    abi = linux_target.linux_abi
    assert abi.python_version == REQUIRED_PYTHON_VERSION
    assert abi.pygobject_version == PINNED_PYGOBJECT_VERSION
    assert abi.glib_floor == GLIB_FLOOR
    assert abi.gtk_version == REQUIRED_GTK_VERSION
    assert abi.webkit_api == REQUIRED_WEBKIT_API
    assert abi.build_platform == UBUNTU_2204_BASELINE
    assert abi.qualification_platforms == (UBUNTU_2204_BASELINE, UBUNTU_2404_FORWARD)
    assert set(abi.prohibited_copied_distro_modules) >= {"gi", "_gi", "cairo"}
    assert set(abi.prohibited_bundled_closures) >= {
        "libgtk-3",
        "libglib-2.0",
        "libwebkit2gtk-4.1",
    }


def test_validate_pygobject_abi_contract() -> None:
    # Exact pinned version against supported GLib floor succeeds
    validate_pygobject_abi("3.48.2", "2.72")
    validate_pygobject_abi("3.48.2", "2.74")
    validate_pygobject_abi("3.48.2", "2.80")
    validate_pygobject_abi("3.48.2")

    # PyGObject 3.50+ is prohibited because of GLib >= 2.80 requirement
    with pytest.raises(LinuxAbiError, match="PyGObject >= 3.50 requires GLib >= 2.80"):
        validate_pygobject_abi("3.50.0")

    with pytest.raises(LinuxAbiError, match="PyGObject >= 3.50 requires GLib >= 2.80"):
        validate_pygobject_abi("3.52.1")

    # Other versions not pinned
    with pytest.raises(LinuxAbiError, match="must be exactly 3.48.2"):
        validate_pygobject_abi("3.48.1")

    # Host GLib below floor
    with pytest.raises(LinuxAbiError, match="below required floor 2.72"):
        validate_pygobject_abi("3.48.2", "2.70")

    # Malformed version
    with pytest.raises(LinuxAbiError, match="Malformed PyGObject version"):
        validate_pygobject_abi("invalid")


def test_audit_linux_onedir_payload_clean(tmp_path: Path) -> None:
    # Clean payload
    (tmp_path / "servonaut-desktop").touch()
    (tmp_path / "servonaut-desktop-child").touch()
    (tmp_path / "servonaut").touch()
    (tmp_path / "_internal").mkdir()
    (tmp_path / "_internal" / "python312.zip").touch()

    violations = audit_linux_onedir_payload(tmp_path)
    assert violations == []


def test_audit_linux_onedir_payload_detects_bundled_host_libraries(
    tmp_path: Path,
) -> None:
    internal = tmp_path / "_internal"
    internal.mkdir()

    (internal / "libgtk-3.so.0").touch()
    (internal / "libglib-2.0.so.0").touch()
    (internal / "libwebkit2gtk-4.1.so.0").touch()

    violations = audit_linux_onedir_payload(tmp_path)
    assert len(violations) == 3
    assert any("libgtk-3" in v for v in violations)
    assert any("libglib-2.0" in v for v in violations)
    assert any("libwebkit2gtk-4.1" in v for v in violations)


def test_audit_linux_onedir_payload_detects_foreign_abi_and_readline(
    tmp_path: Path,
) -> None:
    internal = tmp_path / "_internal"
    internal.mkdir()

    (internal / "cpython-310-x86_64-linux-gnu.so").touch()
    (internal / "libreadline.so.8").touch()

    violations = audit_linux_onedir_payload(tmp_path)
    assert len(violations) == 2
    assert any("Foreign Python ABI" in v for v in violations)
    assert any("libreadline" in v for v in violations)


def test_audit_linux_onedir_payload_detects_voice_contamination(tmp_path: Path) -> None:
    internal = tmp_path / "_internal"
    internal.mkdir()

    (internal / "libfaster_whisper.so").touch()
    (internal / "libctranslate2.so.4").touch()
    (internal / "model.onnx").touch()

    violations = audit_linux_onedir_payload(tmp_path)
    assert len(violations) == 3
    assert any("libfaster_whisper" in v for v in violations)
    assert any("libctranslate2" in v for v in violations)
    assert any("ONNX model" in v for v in violations)


def test_split_runtime_fallback_specification() -> None:
    spec = get_split_runtime_fallback_spec()
    assert spec["status"] == "reviewed_fallback"
    gui_rt = spec["gui_and_child_runtime"]
    assert gui_rt["python_version"] == "3.10"
    assert "python3-gi" in gui_rt["required_system_packages"]
    assert "gir1.2-webkit2-4.1" in gui_rt["required_system_packages"]

    console_rt = spec["console_helper_runtime"]
    assert console_rt["python_version"] == "3.12"
    assert console_rt["stack"] == "standalone-onedir"

    constraints = spec["shared_constraints"]
    assert constraints["same_product_version"] is True
    assert constraints["same_wheel_artifact"] is True
    assert constraints["no_abi_package_copy"] is True
