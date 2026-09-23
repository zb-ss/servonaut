"""Tests for inside-out Windows Authenticode code signing, argument masking, and verification."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.distribution.package_windows import (
    REQUIRED_PAYLOAD_FILES,
    package_windows,
)
from scripts.distribution.sign_windows import (
    WindowsSigningError,
    _mask_command_args,
    main,
    sign_msi,
    sign_payload_binaries,
    verify_signature,
)


@pytest.fixture
def mock_windows_payload(tmp_path: Path) -> Path:
    payload_dir = tmp_path / "mock-payload"
    payload_dir.mkdir(parents=True)

    for binary_name in REQUIRED_PAYLOAD_FILES:
        target = payload_dir / binary_name
        if binary_name.endswith(".json"):
            target.write_text('{"distribution": "packaged-desktop"}', encoding="utf-8")
        else:
            target.write_bytes(b"MZfakewindowspe")

    # Nested DLLs and PYDs
    internal_dir = payload_dir / "_internal" / "dlls"
    internal_dir.mkdir(parents=True)
    (internal_dir / "libcrypto.dll").write_bytes(b"MZfakecrypto")
    (internal_dir / "libssl.dll").write_bytes(b"MZfakessl")
    (internal_dir / "select.pyd").write_bytes(b"MZfakepyd")

    return payload_dir


class TestSignWindows:
    """Tests covering inside-out signing order and credential masking."""

    def test_inside_out_signing_order(self, mock_windows_payload: Path) -> None:
        signed = sign_payload_binaries(
            mock_windows_payload,
            cert_thumbprint="A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4",
            dry_run=True,
        )

        signed_names = [f.name for f in signed]

        # 1. Nested dynamic libraries must come first
        assert signed_names[:3] == ["libcrypto.dll", "libssl.dll", "select.pyd"]

        # 2. Helper executables must come before main GUI executable
        assert "servonaut.exe" in signed_names[3:5]
        assert "servonaut-desktop-child.exe" in signed_names[3:5]

        # 3. Main GUI launcher must be last
        assert signed_names[-1] == "servonaut-desktop.exe"

    def test_mask_command_args_passwords(self) -> None:
        cmd = ["signtool.exe", "sign", "/f", "cert.pfx", "/p", "SuperSecretPassword123!", "app.exe"]
        masked = _mask_command_args(cmd)
        assert "SuperSecretPassword123!" not in masked
        assert "***MASKED***" in masked

        cmd_colon = ["signtool.exe", "sign", "/p:SuperSecretPassword123!", "app.exe"]
        masked_colon = _mask_command_args(cmd_colon)
        assert "SuperSecretPassword123!" not in masked_colon
        assert "/p:***MASKED***" in masked_colon

    def test_sign_msi_dry_run(self, mock_windows_payload: Path, tmp_path: Path) -> None:
        out_dir = tmp_path / "dist"
        res = package_windows(
            payload_dir=mock_windows_payload,
            output_dir=out_dir,
            product_version="0.2.0",
            dry_run=True,
        )

        signed_msi = sign_msi(
            res.msi_path,
            cert_thumbprint="A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4",
            dry_run=True,
        )
        assert signed_msi == res.msi_path

    def test_verify_signature_dry_run(self, mock_windows_payload: Path) -> None:
        gui_exe = mock_windows_payload / "servonaut-desktop.exe"
        assert verify_signature(gui_exe, dry_run=True) is True

    def test_verify_signature_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            verify_signature(tmp_path / "nonexistent.exe", dry_run=True)

    def test_cli_sign_payload_and_msi(self, mock_windows_payload: Path, tmp_path: Path) -> None:
        out_dir = tmp_path / "dist"
        res = package_windows(
            payload_dir=mock_windows_payload,
            output_dir=out_dir,
            product_version="0.2.0",
            dry_run=True,
        )

        rc = main(
            [
                "--payload-dir",
                str(mock_windows_payload),
                "--msi",
                str(res.msi_path),
                "--thumbprint",
                "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4",
                "--dry-run",
            ]
        )
        assert rc == 0
