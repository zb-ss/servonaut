"""Tests for platform utilities."""

import platform

import pytest

from servonaut.utils import platform_utils
from servonaut.utils.platform_utils import (
    describe_platform,
    get_os,
    command_exists,
    get_home_dir,
    get_ssh_dir,
)


class TestGetOs:

    def test_returns_known_value(self):
        result = get_os()
        assert result in ['linux', 'darwin', 'windows'] or isinstance(result, str)


class TestCommandExists:

    def test_python_exists(self):
        assert command_exists('python3') is True

    def test_nonexistent_command(self):
        assert command_exists('nonexistent_command_xyz_12345') is False


class TestGetHomeDir:

    def test_returns_existing_path(self):
        home = get_home_dir()
        assert home.exists()
        assert home.is_dir()


class TestGetSshDir:

    def test_returns_ssh_path(self):
        ssh_dir = get_ssh_dir()
        assert ssh_dir.name == '.ssh'
        assert ssh_dir.parent == get_home_dir()


class TestDescribePlatform:
    """A coarse OS name for the sign-in review page: major version only."""

    @pytest.fixture
    def on(self, monkeypatch):
        def set_os(os_name, **calls):
            monkeypatch.setattr(platform_utils, "get_os", lambda: os_name)
            for name, value in calls.items():
                monkeypatch.setattr(platform, name, value)
        return set_os

    def test_macos_major_version(self, on):
        on("darwin", mac_ver=lambda: ("15.1.2", ("", "", ""), "arm64"))
        assert describe_platform() == "macOS 15"

    def test_macos_without_a_version(self, on):
        on("darwin", mac_ver=lambda: ("", ("", "", ""), ""))
        assert describe_platform() == "macOS"

    @pytest.mark.parametrize(
        "release, version, expected",
        [
            ("10", "10.0.22631", "Windows 11"),  # Python < 3.12 calls Windows 11 "10"
            ("11", "10.0.26100", "Windows 11"),
            ("10", "10.0.19045", "Windows 10"),
            ("10", "", "Windows 10"),
            ("", "", "Windows"),
        ],
    )
    def test_windows_release(self, on, release, version, expected):
        on("windows", release=lambda: release, version=lambda: version)
        assert describe_platform() == expected

    def test_linux_distribution_and_version(self, on):
        on("linux", freedesktop_os_release=lambda: {"NAME": "Ubuntu", "VERSION_ID": "24.04", "PRETTY_NAME": "x"})
        assert describe_platform() == "Ubuntu 24.04"

    def test_linux_without_os_release(self, on):
        def missing():
            raise OSError("no os-release")
        on("linux", freedesktop_os_release=missing)
        assert describe_platform() == "Linux"

    def test_rolling_distribution_without_a_version(self, on):
        on("linux", freedesktop_os_release=lambda: {"NAME": "Arch Linux"})
        assert describe_platform() == "Arch Linux"

    def test_hostile_os_release_is_cleaned_and_capped(self, on):
        name = "Evil\x1b[31m<script>alert(1)</script>\n" + "A" * 80
        on("linux", freedesktop_os_release=lambda: {"NAME": name, "VERSION_ID": "1"})
        result = describe_platform()
        assert len(result) <= 40
        assert all(ch.isalnum() or ch in " ._()/+-" for ch in result)
        assert "<" not in result and "\x1b" not in result

    def test_nothing_left_reads_unknown(self, on):
        on("linux", freedesktop_os_release=lambda: {"NAME": "<<>>"})
        assert describe_platform() == "unknown"
