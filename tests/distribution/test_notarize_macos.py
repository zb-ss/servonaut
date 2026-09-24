"""Contract tests for macOS notarization submission, ticket stapling, and secret masking."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from scripts.distribution import notarize_macos
from scripts.distribution.notarize_macos import (
    MacosNotarizationError,
    main,
    staple_ticket,
    submit_notarization,
    validate_staple,
)


class TestNotarizeMacos:
    """Tests covering notarytool execution, stapling, and secret protection."""

    def test_submit_notarization_dry_run(self, tmp_path: Path) -> None:
        dmg = tmp_path / "test.dmg"
        dmg.write_bytes(b"dummy")

        success, log, details = submit_notarization(
            artifact_path=dmg,
            keychain_profile="test-profile",
            dry_run=True,
        )

        assert success is True
        assert details.get("status") == "Accepted"
        assert "id" in details

    def test_staple_and_validate_ticket_dry_run(self, tmp_path: Path) -> None:
        dmg = tmp_path / "test.dmg"
        dmg.write_bytes(b"dummy")

        stapled, s_msg = staple_ticket(dmg, dry_run=True)
        assert stapled is True
        assert "stapled" in s_msg

        validated, v_msg = validate_staple(dmg, dry_run=True)
        assert validated is True
        assert "validated" in v_msg

    def test_cli_notarize_macos_dry_run(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        dmg = tmp_path / "test.dmg"
        dmg.write_bytes(b"dummy")

        ret = main([
            "--artifact",
            str(dmg),
            "--keychain-profile",
            "test-profile",
            "--staple",
            "--dry-run",
        ])

        assert ret == 0
        captured = capsys.readouterr()
        assert "Notarization succeeded" in captured.out
        assert "Stapling verified" in captured.out


@pytest.fixture
def dmg(tmp_path: Path) -> Path:
    artifact = tmp_path / "test.dmg"
    artifact.write_bytes(b"dummy")
    return artifact


def _record_xcrun(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Put xcrun on PATH and record every command instead of running it."""
    monkeypatch.setattr(notarize_macos.shutil, "which", lambda name: f"/usr/bin/{name}")
    commands: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, json.dumps({"id": "sub-1", "status": "Accepted"}), "")

    monkeypatch.setattr(notarize_macos.subprocess, "run", fake_run)
    return commands


class TestNotaryToolRequirements:
    """Dry runs never contact Apple; real runs fail loudly without the tools."""

    def test_dry_run_never_invokes_notary_tools(
        self, dmg: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        commands = _record_xcrun(monkeypatch)

        assert submit_notarization(dmg, keychain_profile="profile", dry_run=True)[0] is True
        assert staple_ticket(dmg, dry_run=True)[0] is True
        assert validate_staple(dmg, dry_run=True)[0] is True
        assert commands == []

    def test_missing_tools_raise_outside_dry_run(
        self, dmg: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(notarize_macos.shutil, "which", lambda name: None)

        with pytest.raises(MacosNotarizationError, match="notarytool"):
            submit_notarization(dmg, keychain_profile="profile")
        with pytest.raises(MacosNotarizationError, match="stapler"):
            staple_ticket(dmg)
        with pytest.raises(MacosNotarizationError, match="stapler"):
            validate_staple(dmg)


class TestNotaryCredentials:
    """Credentials come from a keychain profile or an API key file, never argv secrets."""

    def test_keychain_profile_submission(self, dmg: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        commands = _record_xcrun(monkeypatch)

        success, _, details = submit_notarization(dmg, keychain_profile="release-profile")

        assert success is True
        assert details["id"] == "sub-1"
        assert commands[0][:3] == ["/usr/bin/xcrun", "notarytool", "submit"]
        assert commands[0][commands[0].index("--keychain-profile") + 1] == "release-profile"

    def test_api_key_submission_keeps_key_material_off_argv(
        self, dmg: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        commands = _record_xcrun(monkeypatch)
        key_material = "PRIVATE-KEY-MATERIAL-FOR-TEST"
        key_file = tmp_path / "AuthKey_TEST.p8"
        key_file.write_text(key_material, encoding="utf-8")

        submit_notarization(dmg, api_key_file=key_file, api_key_id="KEYID", api_issuer="issuer-id")

        argv = commands[0]
        assert argv[argv.index("--key") + 1] == str(key_file.resolve())
        assert argv[argv.index("--key-id") + 1] == "KEYID"
        assert argv[argv.index("--issuer") + 1] == "issuer-id"
        assert "--password" not in argv
        assert not any(key_material in arg for arg in argv)

    def test_missing_credentials_raise(self, dmg: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _record_xcrun(monkeypatch)

        with pytest.raises(MacosNotarizationError, match="keychain_profile"):
            submit_notarization(dmg)
        with pytest.raises(MacosNotarizationError, match="api_key_id"):
            submit_notarization(dmg, api_key_file=dmg)

    def test_password_is_not_accepted(self, dmg: Path) -> None:
        with pytest.raises(TypeError):
            submit_notarization(  # type: ignore[call-arg]
                dmg, apple_id="dev", team_id="TEAM", app_password="not-on-argv"
            )
        with pytest.raises(SystemExit) as excinfo:
            main(["--artifact", str(dmg), "--password", "not-on-argv", "--dry-run"])
        assert excinfo.value.code == 2
