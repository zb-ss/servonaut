"""Tests for Microsoft Edge WebView2 Evergreen Runtime and OpenSSH detection tooling."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pytest

from scripts.distribution.webview2_detect import (
    WEBVIEW2_BOOTSTRAPPER_URL,
    WEBVIEW2_CLIENT_GUID,
    WEBVIEW2_STANDALONE_URL,
    detect_openssh,
    detect_webview2,
    main,
)


class TestWebView2Detection:
    """Test WebView2 Evergreen detection logic with registry mocks."""

    def test_detect_webview2_machine_64_success(self) -> None:
        def mock_reader(hive: str, subkey: str, value_name: str, is_64bit: bool) -> Optional[str]:
            if hive == "HKLM" and is_64bit and WEBVIEW2_CLIENT_GUID in subkey and value_name == "pv":
                return "118.0.2088.76"
            return None

        status = detect_webview2(registry_reader=mock_reader)
        assert status.available is True
        assert status.version == "118.0.2088.76"
        assert status.location == "machine_64"
        assert status.min_version_met is True
        assert "118.0.2088.76 is installed" in (status.guidance or "")

    def test_detect_webview2_machine_wow64_success(self) -> None:
        def mock_reader(hive: str, subkey: str, value_name: str, is_64bit: bool) -> Optional[str]:
            if hive == "HKLM" and not is_64bit and "WOW6432Node" in subkey and value_name == "pv":
                return "120.0.2210.91"
            return None

        status = detect_webview2(registry_reader=mock_reader)
        assert status.available is True
        assert status.version == "120.0.2210.91"
        assert status.location == "machine_wow64"
        assert status.min_version_met is True

    def test_detect_webview2_user_hive_success(self) -> None:
        def mock_reader(hive: str, subkey: str, value_name: str, is_64bit: bool) -> Optional[str]:
            if hive == "HKCU" and WEBVIEW2_CLIENT_GUID in subkey and value_name == "pv":
                return "86.0.616.0"
            return None

        status = detect_webview2(registry_reader=mock_reader)
        assert status.available is True
        assert status.version == "86.0.616.0"
        assert status.location == "user"
        assert status.min_version_met is True

    def test_detect_webview2_outdated_version(self) -> None:
        def mock_reader(hive: str, subkey: str, value_name: str, is_64bit: bool) -> Optional[str]:
            if hive == "HKLM" and is_64bit:
                return "85.0.564.70"
            return None

        status = detect_webview2(registry_reader=mock_reader)
        assert status.available is True
        assert status.version == "85.0.564.70"
        assert status.min_version_met is False
        assert "older than minimum required version" in (status.guidance or "")
        assert WEBVIEW2_BOOTSTRAPPER_URL in (status.guidance or "")
        assert WEBVIEW2_STANDALONE_URL in (status.guidance or "")

    def test_detect_webview2_missing(self) -> None:
        def mock_reader(hive: str, subkey: str, value_name: str, is_64bit: bool) -> Optional[str]:
            return None

        status = detect_webview2(registry_reader=mock_reader)
        assert status.available is False
        assert status.version is None
        assert status.min_version_met is False
        assert "is not installed on this system" in (status.guidance or "")
        assert WEBVIEW2_BOOTSTRAPPER_URL in (status.guidance or "")
        assert WEBVIEW2_STANDALONE_URL in (status.guidance or "")
        assert "Group Policy" in (status.guidance or "")


class TestOpenSSHDetection:
    """Test OpenSSH detection logic and optional feature guidance."""

    def test_detect_openssh_found_in_path(self) -> None:
        fake_ssh_path = "/usr/bin/ssh"
        status = detect_openssh(custom_which=lambda cmd: fake_ssh_path if "ssh" in cmd else None)
        assert status.available is True
        assert status.path == fake_ssh_path
        assert "available" in (status.guidance or "")

    def test_detect_openssh_found_in_system32(self, tmp_path: Path) -> None:
        sys32_openssh = tmp_path / "System32" / "OpenSSH"
        sys32_openssh.mkdir(parents=True)
        ssh_bin = sys32_openssh / "ssh.exe"
        ssh_bin.write_bytes(b"fake_ssh")

        status = detect_openssh(
            custom_which=lambda cmd: None,
            system_root=str(tmp_path),
        )
        assert status.available is True
        assert status.path == str(ssh_bin)

    def test_detect_openssh_missing_guidance(self) -> None:
        status = detect_openssh(
            custom_which=lambda cmd: None,
            system_root="/nonexistent/root",
        )
        assert status.available is False
        assert status.path is None
        guidance = status.guidance or ""
        assert "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0" in guidance
        assert "Optional features" in guidance


class TestCLIExecution:
    """Test CLI diagnostics output."""

    def test_cli_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["--json"])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "webview2" in data
        assert "openssh" in data
        assert "available" in data["webview2"]
        assert "available" in data["openssh"]


class TestWebView2NotInstalledMarker:
    """A pv value of 0.0.0.0 marks a location where the runtime is not installed."""

    def test_zero_version_is_skipped_for_the_next_location(self) -> None:
        values = {"machine": "0.0.0.0", "user": "120.0.2210.91"}

        def mock_reader(hive: str, subkey: str, value_name: str, is_64bit: bool) -> Optional[str]:
            return values["user"] if hive == "HKCU" else values["machine"]

        status = detect_webview2(registry_reader=mock_reader)
        assert status.available is True
        assert status.location == "user"

    def test_zero_version_everywhere_means_missing(self) -> None:
        status = detect_webview2(registry_reader=lambda *args: "0.0.0.0")
        assert status.available is False
        assert status.min_version_met is False
