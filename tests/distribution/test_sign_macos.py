"""Contract tests for macOS inside-out code signing and entitlements."""

from __future__ import annotations

import os
from pathlib import Path
import plistlib
import subprocess

import pytest

from scripts.distribution.package_macos import (
    REQUIRED_PAYLOAD_FILES,
    assemble_app_bundle,
)
from scripts.distribution import sign_macos
from scripts.distribution.sign_macos import (
    MacosSigningError,
    main,
    nested_code,
    sign_app_bundle,
    sign_dmg,
    verify_signature,
)

pytestmark = pytest.mark.skipif(os.name == "nt", reason="bundle links need POSIX symlinks")

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MACHO = b"\xcf\xfa\xed\xfe" + bytes(28)
_UV = b"\xcf\xfa\xed\xfe publisher-signed uv"
_DEVELOPER_ID = "Developer ID Application: Test Developer"


@pytest.fixture
def mock_payload(tmp_path: Path) -> Path:
    payload_dir = tmp_path / "mock-payload"
    payload_dir.mkdir(parents=True)

    for binary_name in REQUIRED_PAYLOAD_FILES:
        target = payload_dir / binary_name
        if binary_name.endswith(".json"):
            target.write_text('{"distribution": "packaged-desktop"}', encoding="utf-8")
        else:
            target.write_bytes(_MACHO)
            target.chmod(0o755)

    internal = payload_dir / "_internal"
    files = {
        "dylibs/liba.dylib": _MACHO,
        "dylibs/nested/libb.so": _MACHO,
        "dylibs/readme.txt": b"data",
        "Python.framework/Versions/3.12/Python": _MACHO,
        "Python.framework/Versions/3.12/Resources/Info.plist": b"<plist/>",
        "voice/uv": _UV,
        "voice/voice-runtime.json": b"{}",
        "base_library.zip": b"PK",
    }
    for relative, content in files.items():
        path = internal / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    os.symlink("3.12", internal / "Python.framework" / "Versions" / "Current")
    return payload_dir


@pytest.fixture
def app_path(mock_payload: Path, tmp_path: Path) -> Path:
    return assemble_app_bundle(
        payload_dir=mock_payload, output_dir=tmp_path / "out", product_version="2.26.3"
    )


def _codesign_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sign_macos.shutil, "which", lambda name: f"/usr/bin/{name}")


def _record_codesign(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Run a codesign stand-in that records every command and succeeds."""
    _codesign_on_path(monkeypatch)
    commands: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sign_macos.subprocess, "run", fake_run)
    return commands


def _forbid_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_run(*args: object, **kwargs: object) -> None:
        raise AssertionError("no signing tool may run")

    monkeypatch.setattr(sign_macos.subprocess, "run", fail_run)


def _target(command: list[str]) -> Path:
    return Path(command[-1])


def _entitlements(command: list[str]) -> str | None:
    if "--entitlements" not in command:
        return None
    return command[command.index("--entitlements") + 1]


class TestSigningOrder:
    def test_nested_code_is_found_by_magic_innermost_first(self, app_path: Path) -> None:
        frameworks = app_path / "Contents" / "Frameworks"

        found = nested_code(app_path)

        assert found == [
            frameworks / "Python.framework/Versions/3.12/Python",
            frameworks / "dylibs/nested/libb.so",
            frameworks / "dylibs/liba.dylib",
            frameworks / "Python.framework",
        ]

    def test_inside_out_signing_order(self, app_path: Path) -> None:
        signed_items = sign_app_bundle(app_path, _DEVELOPER_ID, dry_run=True)

        names = [path.name for path in signed_items]
        assert names == [
            "Python",
            "libb.so",
            "liba.dylib",
            "Python.framework",
            "servonaut-desktop-child",
            "servonaut",
            "Servonaut.app",
        ]

    def test_every_command_uses_the_hardened_runtime_and_never_deep(
        self, app_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        commands = _record_codesign(monkeypatch)

        sign_app_bundle(app_path, _DEVELOPER_ID)

        assert len(commands) == 7
        for command in commands:
            assert command[0] == "/usr/bin/codesign"
            assert command[1:6] == ["--force", "--options", "runtime", "--sign", _DEVELOPER_ID]
            assert "--deep" not in command
            assert "--timestamp" in command

    def test_entitlements_go_to_the_executables_only(
        self, app_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        commands = _record_codesign(monkeypatch)

        sign_app_bundle(app_path, _DEVELOPER_ID)

        by_target = {_target(command).name: _entitlements(command) for command in commands}
        gui = str(_REPO_ROOT / "packaging/macos/entitlements.plist")
        helper = str(_REPO_ROOT / "packaging/macos/helper-entitlements.plist")
        assert by_target == {
            "Python": None,
            "libb.so": None,
            "liba.dylib": None,
            "Python.framework": None,
            "servonaut-desktop-child": helper,
            "servonaut": helper,
            "Servonaut.app": gui,
        }

    def test_ad_hoc_signatures_carry_no_timestamp(
        self, app_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        commands = _record_codesign(monkeypatch)
        dmg_path = tmp_path / "test.dmg"
        dmg_path.write_bytes(b"dmg")

        sign_app_bundle(app_path, "-")
        sign_dmg(dmg_path, "-")

        for command in commands:
            assert "--timestamp=none" in command
            assert "--timestamp" not in command


class TestPreservedSignatures:
    def test_uv_is_never_signed(self, app_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        commands = _record_codesign(monkeypatch)
        uv = app_path / "Contents" / "Frameworks" / "voice" / "uv"

        sign_app_bundle(app_path, "-")

        assert all(_target(command) != uv for command in commands)
        assert uv not in nested_code(app_path)
        assert uv.read_bytes() == _UV

    def test_a_changed_uv_fails_the_signing(
        self, app_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _codesign_on_path(monkeypatch)
        uv = app_path / "Contents" / "Frameworks" / "voice" / "uv"

        def rewriting_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            if Path(cmd[-1]) == app_path:
                uv.write_bytes(_UV + b" re-signed")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(sign_macos.subprocess, "run", rewriting_run)

        with pytest.raises(MacosSigningError, match="keeps its own signature: uv"):
            sign_app_bundle(app_path, "-")


class TestEntitlements:
    """The hardened runtime's entitlements: only what the packaged app needs."""

    @staticmethod
    def _load(name: str) -> dict[str, object]:
        with open(_REPO_ROOT / "packaging" / "macos" / name, "rb") as fp:
            return plistlib.load(fp)

    def test_the_launcher_may_only_ask_for_the_microphone(self) -> None:
        assert self._load("entitlements.plist") == {
            "com.apple.security.device.audio-input": True,
        }

    def test_the_helpers_need_no_entitlement(self) -> None:
        assert self._load("helper-entitlements.plist") == {}

    @pytest.mark.parametrize("name", ["entitlements.plist", "helper-entitlements.plist"])
    def test_no_sandbox_only_or_code_injection_keys(self, name: str) -> None:
        keys = set(self._load(name))

        # App Sandbox keys do nothing without the sandbox.
        assert not {key for key in keys if key.startswith("com.apple.security.network.")}
        assert "com.apple.security.cs.allow-dyld-environment-variables" not in keys


class TestLayoutGate:
    def test_an_unsignable_layout_is_refused_before_signing(
        self, app_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _codesign_on_path(monkeypatch)
        _forbid_subprocess(monkeypatch)
        (app_path / "Contents" / "Frameworks" / "stray.json").write_text("{}")

        with pytest.raises(MacosSigningError, match="data file in a code location"):
            sign_app_bundle(app_path, "-")

    def test_a_missing_helper_is_refused(
        self, app_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _record_codesign(monkeypatch)
        (app_path / "Contents" / "MacOS" / "servonaut").unlink()

        with pytest.raises(MacosSigningError, match="Helper executable missing: servonaut"):
            sign_app_bundle(app_path, "-")


class TestSignMacos:
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

    def test_gatekeeper_assessment_is_optional(
        self, app_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        commands = _record_codesign(monkeypatch)

        assert verify_signature(app_path, gatekeeper=False)[0] is True
        assert [Path(command[0]).name for command in commands] == ["codesign"]
        assert commands[0][1:4] == ["--verify", "--deep", "--strict"]

        commands.clear()
        assert verify_signature(app_path)[0] is True
        assert [Path(command[0]).name for command in commands] == ["codesign", "spctl"]

    def test_cli_sign_macos_success(
        self, app_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
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

    def test_cli_ad_hoc_verification_skips_gatekeeper(
        self,
        app_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        commands = _record_codesign(monkeypatch)

        ret = main(["--target", str(app_path), "--identity", "-", "--verify"])

        assert ret == 0
        assert "spctl" not in {Path(command[0]).name for command in commands}
        assert "rejects ad-hoc signed apps by design" in capsys.readouterr().out


class TestSigningToolRequirements:
    """Dry runs never sign; real runs fail loudly when codesign is missing."""

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

    @pytest.mark.parametrize("argument", ["entitlements_file", "helper_entitlements_file"])
    def test_missing_entitlements_raise_before_signing(
        self, app_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argument: str
    ) -> None:
        _codesign_on_path(monkeypatch)
        _forbid_subprocess(monkeypatch)

        with pytest.raises(FileNotFoundError, match="Entitlements"):
            sign_app_bundle(
                app_path,
                "Developer ID Application: Test",
                **{argument: tmp_path / "missing.plist"},
            )
