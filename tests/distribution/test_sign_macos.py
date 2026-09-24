"""Contract tests for macOS inside-out code signing and entitlements."""

from __future__ import annotations

from pathlib import Path
import plistlib

import pytest

from scripts.distribution.package_macos import (
    REQUIRED_PAYLOAD_FILES,
    assemble_app_bundle,
)
from scripts.distribution import sign_macos
from scripts.distribution.sign_macos import (
    MacosSigningError,
    main,
    sign_app_bundle,
    sign_dmg,
    verify_signature,
)


@pytest.fixture
def mock_payload(tmp_path: Path) -> Path:
    payload_dir = tmp_path / "mock-payload"
    payload_dir.mkdir(parents=True)

    for binary_name in REQUIRED_PAYLOAD_FILES:
        target = payload_dir / binary_name
        if binary_name.endswith(".json"):
            target.write_text('{"distribution": "packaged-desktop"}', encoding="utf-8")
        else:
            target.write_bytes(b"\xcf\xfa\xed\xfefakemacho")
            target.chmod(0o755)

    # Nested dylibs in _internal
    internal_dir = payload_dir / "_internal" / "dylibs"
    internal_dir.mkdir(parents=True)
    (internal_dir / "liba.dylib").write_bytes(b"dylib_a")
    (internal_dir / "libb.so").write_bytes(b"so_b")

    return payload_dir


class TestSignMacos:
    """Tests covering inside-out signing order and verification."""

    def test_inside_out_signing_order(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "out"
        app_path = assemble_app_bundle(
            payload_dir=mock_payload,
            output_dir=out_dir,
            product_version="2.26.3",
        )

        signed_items = sign_app_bundle(
            app_bundle_path=app_path,
            identity="Developer ID Application: Test Developer",
            dry_run=True,
        )

        # Assert signed items list is not empty
        assert len(signed_items) >= 5

        # Check order:
        # 1. Nested libs (.dylib, .so)
        # 2. Helpers (servonaut, servonaut-desktop-child)
        # 3. Main GUI (servonaut-desktop)
        # 4. App bundle (Servonaut.app)
        signed_names = [p.name for p in signed_items]

        # Nested libs must precede helpers
        idx_dylib = signed_names.index("liba.dylib")
        idx_so = signed_names.index("libb.so")
        idx_helper1 = signed_names.index("servonaut")
        idx_helper2 = signed_names.index("servonaut-desktop-child")
        idx_gui = signed_names.index("servonaut-desktop")
        idx_bundle = signed_names.index("Servonaut.app")

        assert idx_dylib < idx_helper1
        assert idx_so < idx_helper1
        assert idx_helper1 < idx_gui
        assert idx_helper2 < idx_gui
        assert idx_gui < idx_bundle
        assert idx_bundle == len(signed_items) - 1

    def test_entitlements_plist_declarations(self) -> None:
        entitlements_path = (
            Path(__file__).resolve().parents[2] / "packaging" / "macos" / "entitlements.plist"
        )
        assert entitlements_path.is_file()

        with open(entitlements_path, "rb") as fp:
            entitlements = plistlib.load(fp)

        # Hardened runtime essential keys
        assert entitlements.get("com.apple.security.cs.allow-jit") is True
        assert entitlements.get("com.apple.security.cs.allow-unsigned-executable-memory") is True
        assert entitlements.get("com.apple.security.cs.disable-library-validation") is True
        assert entitlements.get("com.apple.security.device.audio-input") is True
        assert entitlements.get("com.apple.security.network.client") is True
        assert entitlements.get("com.apple.security.network.server") is True

    def test_sign_dmg_dry_run(self, tmp_path: Path) -> None:
        dmg_path = tmp_path / "test.dmg"
        dmg_path.write_bytes(b"dummy_dmg_content")

        res = sign_dmg(dmg_path, identity="Developer ID Application: Test", dry_run=True)
        assert res == dmg_path

    def test_verify_signature_dry_run(self, tmp_path: Path) -> None:
        dmg_path = tmp_path / "test.dmg"
        dmg_path.write_bytes(b"dummy_dmg_content")

        valid, msg = verify_signature(dmg_path, dry_run=True)
        assert valid is True
        assert "verified" in msg

    def test_cli_sign_macos_success(
        self, mock_payload: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out_dir = tmp_path / "out"
        app_path = assemble_app_bundle(
            payload_dir=mock_payload,
            output_dir=out_dir,
            product_version="2.26.3",
        )

        ret = main([
            "--target",
            str(app_path),
            "--identity",
            "Developer ID Application: Test",
            "--dry-run",
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Successfully signed" in captured.out


def _codesign_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sign_macos.shutil, "which", lambda name: f"/usr/bin/{name}")


def _forbid_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_run(*args: object, **kwargs: object) -> None:
        raise AssertionError("no signing tool may run")

    monkeypatch.setattr(sign_macos.subprocess, "run", fail_run)


class TestSigningToolRequirements:
    """Dry runs never sign; real runs fail loudly when codesign is missing."""

    @pytest.fixture
    def app_path(self, mock_payload: Path, tmp_path: Path) -> Path:
        return assemble_app_bundle(
            payload_dir=mock_payload, output_dir=tmp_path / "out", product_version="2.26.3"
        )

    def test_dry_run_never_invokes_codesign(
        self, app_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _codesign_on_path(monkeypatch)
        _forbid_subprocess(monkeypatch)
        dmg_path = tmp_path / "test.dmg"
        dmg_path.write_bytes(b"dmg")

        signed = sign_app_bundle(app_path, "Developer ID Application: Test", dry_run=True)
        assert signed[-1] == app_path
        assert sign_dmg(dmg_path, "Developer ID Application: Test", dry_run=True) == dmg_path
        assert verify_signature(dmg_path, dry_run=True)[0] is True

    def test_missing_codesign_raises_outside_dry_run(
        self, app_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sign_macos.shutil, "which", lambda name: None)
        dmg_path = tmp_path / "test.dmg"
        dmg_path.write_bytes(b"dmg")

        with pytest.raises(MacosSigningError, match="codesign"):
            sign_app_bundle(app_path, "Developer ID Application: Test")
        with pytest.raises(MacosSigningError, match="codesign"):
            sign_dmg(dmg_path, "Developer ID Application: Test")
        with pytest.raises(MacosSigningError, match="codesign"):
            verify_signature(dmg_path)

    def test_missing_entitlements_raise_before_signing(
        self, app_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _codesign_on_path(monkeypatch)
        _forbid_subprocess(monkeypatch)

        with pytest.raises(FileNotFoundError, match="Entitlements"):
            sign_app_bundle(
                app_path,
                "Developer ID Application: Test",
                entitlements_file=tmp_path / "missing.plist",
            )
