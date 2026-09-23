"""Contract tests for macOS notarization submission, ticket stapling, and secret masking."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.distribution.notarize_macos import (
    main,
    mask_sensitive_arguments,
    staple_ticket,
    submit_notarization,
    validate_staple,
)


class TestNotarizeMacos:
    """Tests covering notarytool execution, stapling, and secret protection."""

    def test_mask_sensitive_arguments(self) -> None:
        secret = "super-secret-app-password-123"
        args = [
            "xcrun",
            "notarytool",
            "submit",
            "Servonaut.dmg",
            "--apple-id",
            "test@example.com",
            "--password",
            secret,
        ]

        masked = mask_sensitive_arguments(args, secrets=[secret])
        assert secret not in masked
        assert "********" in masked
        assert masked[masked.index("--password") + 1] == "********"

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
