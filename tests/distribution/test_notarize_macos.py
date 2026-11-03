"""Contract tests for macOS notarization submission, ticket stapling, and secret masking."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from scripts.distribution import notarize_macos
from scripts.distribution.notarize_macos import (
    MacosNotarizationError,
    fetch_submission_log,
    main,
    rejected_submission_id,
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


_SUBMISSION = "2efe2717-52ef-43a5-96dc-0797e4ca1041"  # leak-guard:allow (synthetic id)
_ISSUES = {
    "status": "Invalid",
    "issues": [
        {
            "severity": "error",
            "path": "Servonaut.zip/Servonaut.app/Contents/MacOS/servonaut",
            "message": "The executable does not have the hardened runtime enabled.",
        }
    ],
}


def _notary_service(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status: str,
    submission_id: str = _SUBMISSION,
    log_returncode: int = 0,
) -> list[list[str]]:
    """Put xcrun on PATH and answer submit and log the way notarytool does."""
    monkeypatch.setattr(notarize_macos.shutil, "which", lambda name: f"/usr/bin/{name}")
    commands: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(cmd)
        if cmd[2] == "submit":
            body = {"id": submission_id, "status": status, "message": "Processing complete"}
            return subprocess.CompletedProcess(cmd, 0, json.dumps(body), "")
        if cmd[2] == "log":
            if log_returncode:
                return subprocess.CompletedProcess(cmd, log_returncode, "", "Error: HTTP 404")
            return subprocess.CompletedProcess(cmd, 0, json.dumps(_ISSUES, indent=2), "")
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr(notarize_macos.subprocess, "run", fake_run)
    return commands


def _api_key_argv(dmg: Path, key_file: Path) -> list[str]:
    return [
        "--artifact",
        str(dmg),
        "--api-key-file",
        str(key_file),
        "--api-key-id",
        "KEYID",
        "--api-issuer",
        "issuer-id",
        "--staple",
    ]


class TestRejectedSubmissionLog:
    """A refused submission's log is printed, so the CI output shows why."""

    @pytest.mark.parametrize("status", sorted(notarize_macos.REJECTED_STATUSES))
    def test_the_log_of_a_refused_submission_is_printed(
        self,
        dmg: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        status: str,
    ) -> None:
        commands = _notary_service(monkeypatch, status=status)
        key_file = tmp_path / "AuthKey_TEST.p8"
        key_file.write_text("PRIVATE-KEY-MATERIAL-FOR-TEST", encoding="utf-8")

        assert main(_api_key_argv(dmg, key_file)) == 1

        submit, log = commands
        assert log[:4] == ["/usr/bin/xcrun", "notarytool", "log", _SUBMISSION]
        # The log is fetched with the submission's own credentials.
        assert log[4:] == submit[submit.index("--key") : submit.index("--wait")]
        assert log[4:] == [
            "--key",
            str(key_file.resolve()),
            "--key-id",
            "KEYID",
            "--issuer",
            "issuer-id",
        ]
        stderr = capsys.readouterr().err
        assert f"Notarization log of submission {_SUBMISSION}:" in stderr
        assert "does not have the hardened runtime enabled" in stderr
        assert stderr.index("Notarization submission failed") < stderr.index("Notarization log")

    def test_a_keychain_profile_fetches_the_log_with_that_profile(
        self, dmg: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        commands = _notary_service(monkeypatch, status="Invalid")

        assert main(["--artifact", str(dmg), "--keychain-profile", "release-profile"]) == 1

        assert commands[1][2:] == ["log", _SUBMISSION, "--keychain-profile", "release-profile"]

    @pytest.mark.parametrize(
        ("status", "submission_id"),
        [
            ("Accepted", _SUBMISSION),
            # notarytool gave up waiting; Apple has not decided yet.
            ("In Progress", _SUBMISSION),
            ("Invalid", ""),
            ("Invalid", "--keychain-profile"),
        ],
    )
    def test_no_log_is_fetched_without_a_refused_submission(
        self,
        dmg: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        status: str,
        submission_id: str,
    ) -> None:
        commands = _notary_service(monkeypatch, status=status, submission_id=submission_id)

        main(["--artifact", str(dmg), "--keychain-profile", "release-profile"])

        assert [command[2] for command in commands] == ["submit"]
        assert "Notarization log" not in capsys.readouterr().err

    def test_a_log_that_cannot_be_fetched_still_fails_the_submission(
        self,
        dmg: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _notary_service(monkeypatch, status="Rejected", log_returncode=1)

        assert main(["--artifact", str(dmg), "--keychain-profile", "release-profile"]) == 1

        stderr = capsys.readouterr().err
        assert f"The notarization log of submission {_SUBMISSION} could not be fetched:" in stderr
        assert "Error: HTTP 404" in stderr

    def test_a_dry_run_never_fetches_a_log(
        self, dmg: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        commands = _notary_service(monkeypatch, status="Invalid")

        assert main(["--artifact", str(dmg), "--keychain-profile", "profile", "--dry-run"]) == 0
        assert commands == []

    def test_only_submission_ids_reach_notarytool(self, monkeypatch: pytest.MonkeyPatch) -> None:
        commands = _notary_service(monkeypatch, status="Invalid")

        with pytest.raises(MacosNotarizationError, match="submission id"):
            fetch_submission_log("--output-format", keychain_profile="profile")
        assert commands == []
        assert rejected_submission_id({"id": _SUBMISSION, "status": "Invalid"}) == _SUBMISSION
        assert rejected_submission_id({"id": _SUBMISSION.upper(), "status": "Rejected"})
        assert rejected_submission_id({"id": 7, "status": "Invalid"}) is None
        assert rejected_submission_id({"status": "Invalid"}) is None


# What stapler printed on a macOS runner when the connection to Apple dropped
# right after a successful notarization (exit code 68).
_CONNECTION_LOST = (
    "Processing: /tmp/servonaut.dmg\n"
    'error is Error Domain=NSURLErrorDomain Code=-1005 "The network connection was lost."\n'
    "CloudKit's response is inconsistent with expections: (null)\n"
    "The staple and validate action failed! Error 68."
)
_NOT_FOUND = (
    'CloudKit query for servonaut.dmg failed due to "Record not found".\n'
    "The validate action failed! Error 65."
)


def _stapler(
    monkeypatch: pytest.MonkeyPatch, *results: tuple[int, str]
) -> tuple[list[list[str]], list[float]]:
    """Answer stapler with the given (exit code, output) in order; record the pauses."""
    monkeypatch.setattr(notarize_macos.shutil, "which", lambda name: f"/usr/bin/{name}")
    answers = list(results)
    commands: list[list[str]] = []
    pauses: list[float] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(cmd)
        if cmd[1] == "notarytool":
            body = {"id": _SUBMISSION, "status": "Accepted"}
            return subprocess.CompletedProcess(cmd, 0, json.dumps(body), "")
        returncode, output = answers.pop(0)
        return subprocess.CompletedProcess(cmd, returncode, "", output)

    monkeypatch.setattr(notarize_macos.subprocess, "run", fake_run)
    monkeypatch.setattr(notarize_macos.time, "sleep", pauses.append)
    return commands, pauses


class TestStaplerRetry:
    """stapler is repeated only after the connection to Apple dropped."""

    @pytest.mark.parametrize(
        ("step", "action"), [(staple_ticket, "staple"), (validate_staple, "validate")]
    )
    def test_a_lost_connection_is_retried_until_it_works(
        self,
        dmg: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        step,
        action: str,
    ) -> None:
        commands, pauses = _stapler(monkeypatch, (68, _CONNECTION_LOST), (0, "worked"))

        assert step(dmg) == (True, "worked")

        assert commands == [["/usr/bin/xcrun", "stapler", action, str(dmg.resolve())]] * 2
        assert pauses == [15.0]
        assert f"stapler {action} lost its connection to Apple (attempt 1 of 4)" in (
            capsys.readouterr().err
        )

    def test_a_connection_lost_every_time_fails_with_the_last_output(
        self, dmg: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        commands, pauses = _stapler(
            monkeypatch, *((68, f"{_CONNECTION_LOST} ({attempt})") for attempt in range(1, 5))
        )

        stapled, output = staple_ticket(dmg)

        assert stapled is False
        assert output.endswith("Error 68. (4)")
        assert len(commands) == 4
        assert pauses == list(notarize_macos.STAPLER_RETRY_DELAYS_SECONDS)

    def test_any_other_failure_is_not_retried(
        self, dmg: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        commands, pauses = _stapler(monkeypatch, (65, _NOT_FOUND))

        assert validate_staple(dmg) == (False, _NOT_FOUND)
        assert len(commands) == 1
        assert pauses == []


class TestStapleCommandLine:
    """--staple and --staple-only staple the ticket and then validate it."""

    def test_staple_validates_the_ticket_after_a_lost_connection(
        self,
        dmg: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        commands, _ = _stapler(monkeypatch, (0, "stapled"), (68, _CONNECTION_LOST), (0, "valid"))

        assert main(["--artifact", str(dmg), "--keychain-profile", "profile", "--staple"]) == 0

        assert [command[2] for command in commands] == ["submit", "staple", "validate", "validate"]
        assert "Stapling verified for test.dmg" in capsys.readouterr().out

    def test_a_ticket_that_does_not_validate_fails(
        self,
        dmg: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _stapler(monkeypatch, (0, "stapled"), (65, _NOT_FOUND))

        assert main(["--artifact", str(dmg), "--keychain-profile", "profile", "--staple"]) == 1

        captured = capsys.readouterr()
        assert "The stapled ticket does not validate:" in captured.err
        assert "Record not found" in captured.err
        assert "Stapling verified" not in captured.out

    def test_staple_only_submits_nothing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        app = tmp_path / "Servonaut.app"
        app.mkdir()
        commands, _ = _stapler(monkeypatch, (68, _CONNECTION_LOST), (0, "stapled"), (0, "valid"))

        assert main(["--artifact", str(app), "--staple-only"]) == 0

        assert [command[1:3] for command in commands] == [["stapler", "staple"]] * 2 + [
            ["stapler", "validate"]
        ]
        assert "Stapling verified for Servonaut.app" in capsys.readouterr().out

    def test_a_dry_run_staple_only_contacts_nobody(
        self, dmg: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        commands, _ = _stapler(monkeypatch)

        assert main(["--artifact", str(dmg), "--staple-only", "--dry-run"]) == 0
        assert commands == []
