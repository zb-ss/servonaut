"""Tests for the resilient UpdateService upgrade path.

The key guarantee: run_upgrade NEVER reports success unless the installed
version actually advanced, and it refuses (with guidance) on source/local
installs that can't be release-upgraded in place.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.runtime import DistributionKind, RuntimeEvidence, resolve_runtime
from servonaut.services.update_service import (
    UpdateCheckResult,
    UpdateService,
    latest_index_version,
)


def _svc(current="2.16.3", latest="2.17.0", kind=DistributionKind.PIP):
    executable = Path(sys.executable)
    runtime = resolve_runtime(RuntimeEvidence(
        executable=executable,
        executable_root=executable.parent,
        resource_root=Path("/resources"),
        home=Path("/home/user"),
        is_frozen=kind in {DistributionKind.FROZEN_CLI, DistributionKind.PACKAGED_DESKTOP},
        package_version=current,
        package_is_installed=kind is not DistributionKind.SOURCE,
        source_install_path="file:///project" if kind is DistributionKind.SOURCE else None,
        path_console=None,
        pipx_executable=Path("/usr/bin/pipx") if kind is DistributionKind.PIPX else None,
        pipx_contains_servonaut=kind is DistributionKind.PIPX,
        marker=(
            {"schema_version": 1, "distribution": kind.value, "product_version": current,
             "channel": "stable", "packaging_revision": 1, "console_helper": "servonaut-cli"}
            if kind is DistributionKind.PACKAGED_DESKTOP else None
        ),
    ))
    service = UpdateService(runtime)
    service._latest = latest
    return service


def _fake_proc(returncode=0, out=b"ok"):
    p = MagicMock()
    p.returncode = returncode
    p.communicate = AsyncMock(return_value=(out, b""))
    return p


# --- version compare ---------------------------------------------------------

def test_is_newer():
    assert UpdateService._is_newer("2.17.0", "2.16.3")
    assert not UpdateService._is_newer("2.16.3", "2.17.0")
    assert not UpdateService._is_newer("2.17.0", "2.17.0")


# --- upgrade command targets the right environment ---------------------------

def test_get_upgrade_command_pip_uses_sys_executable(monkeypatch):
    s = _svc()
    assert s.get_upgrade_command() == [
        sys.executable, "-m", "pip", "install", "--upgrade", "servonaut"]


def test_get_upgrade_command_pipx_uses_full_path(monkeypatch):
    s = _svc(kind=DistributionKind.PIPX)
    assert s.get_upgrade_command() == [
        str(Path("/usr/bin/pipx")), "upgrade", "servonaut"
    ]


def test_source_missing_upgrade_command_has_no_side_effects():
    service = _svc(kind=DistributionKind.SOURCE)

    assert service.get_upgrade_command() is None
    assert service.update_status is None


def test_frozen_missing_upgrade_command_has_no_side_effects():
    service = _svc(kind=DistributionKind.FROZEN_CLI)

    assert service.get_upgrade_command() is None
    assert service.update_status is None
    assert service.check_for_update() is None
    assert "signed build" in service.update_status


# --- source/local installs are not silently "upgraded" -----------------------

def test_source_install_blocks_upgrade(monkeypatch):
    s = _svc(kind=DistributionKind.SOURCE)
    called = MagicMock()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", called)
    ok, msg = asyncio.run(s.run_upgrade())
    assert ok is False
    assert "source installation" in msg
    called.assert_not_called()  # never ran a subprocess


def test_source_install_path_detects_a_local_directory(monkeypatch):
    s = _svc()

    class _Dist:
        def read_text(self, name):
            return '{"dir_info": {}, "url": "file:///home/user/servonaut"}'

    monkeypatch.setattr("importlib.metadata.distribution", lambda name: _Dist())
    assert s.source_install_path() == "file:///home/user/servonaut"


def test_source_install_path_ignores_a_local_wheel_archive(monkeypatch):
    s = _svc()

    class _Dist:
        def read_text(self, name):
            return (
                '{"url": "file:///tmp/servonaut.whl", '
                '"archive_info": {"hash": "sha256=abc"}}'
            )

    monkeypatch.setattr("importlib.metadata.distribution", lambda name: _Dist())
    assert s.source_install_path() is None


def test_source_install_path_detects_editable(monkeypatch):
    s = _svc()

    class _Dist:
        def read_text(self, name):
            return '{"url": "file:///x", "dir_info": {"editable": true}}'

    monkeypatch.setattr("importlib.metadata.distribution", lambda name: _Dist())
    assert s.source_install_path() == "file:///x"


def test_source_install_path_none_for_pypi(monkeypatch):
    s = _svc()

    class _Dist:
        def read_text(self, name):
            return None  # PyPI wheels have no direct_url.json

    monkeypatch.setattr("importlib.metadata.distribution", lambda name: _Dist())
    assert s.source_install_path() is None


# --- run_upgrade verifies the version actually changed ------------------------

def _wire_pypi_upgrade(monkeypatch, s, before, after, returncode=0, out=b"ok"):
    monkeypatch.setattr(s, "source_install_path", lambda: None)
    monkeypatch.setattr(s, "detect_install_method", lambda: "pipx")
    monkeypatch.setattr(s, "get_upgrade_command",
                        lambda: ["pipx", "upgrade", "servonaut"])
    monkeypatch.setattr(s, "installed_version_external",
                        MagicMock(side_effect=[before, after]))
    monkeypatch.setattr(asyncio, "create_subprocess_exec",
                        AsyncMock(return_value=_fake_proc(returncode, out)))


def test_run_upgrade_success_when_version_advances(monkeypatch):
    s = _svc()
    _wire_pypi_upgrade(monkeypatch, s, "2.16.3", "2.17.0")
    ok, msg = asyncio.run(s.run_upgrade())
    assert ok is True and "2.16.3" in msg and "2.17.0" in msg


def test_run_upgrade_honest_when_version_unchanged(monkeypatch):
    # The original bug: exit 0 but nothing actually upgraded.
    s = _svc()
    _wire_pypi_upgrade(monkeypatch, s, "2.16.3", "2.16.3")
    ok, msg = asyncio.run(s.run_upgrade())
    assert ok is False
    assert "still v2.16.3" in msg and "expected v2.17.0" in msg


def test_run_upgrade_already_latest(monkeypatch):
    s = _svc(current="2.17.0", latest="2.17.0")
    _wire_pypi_upgrade(monkeypatch, s, "2.17.0", "2.17.0")
    ok, msg = asyncio.run(s.run_upgrade())
    assert ok is True and "latest" in msg.lower()


def test_run_upgrade_command_failure(monkeypatch):
    s = _svc()
    monkeypatch.setattr(s, "source_install_path", lambda: None)
    monkeypatch.setattr(s, "detect_install_method", lambda: "pipx")
    monkeypatch.setattr(s, "get_upgrade_command",
                        lambda: ["pipx", "upgrade", "servonaut"])
    monkeypatch.setattr(s, "installed_version_external", lambda: "2.16.3")
    monkeypatch.setattr(asyncio, "create_subprocess_exec",
                        AsyncMock(return_value=_fake_proc(1, b"boom")))
    ok, msg = asyncio.run(s.run_upgrade())
    assert ok is False and "failed" in msg.lower() and "boom" in msg


def test_run_upgrade_missing_command(monkeypatch):
    s = _svc()
    monkeypatch.setattr(s, "source_install_path", lambda: None)
    monkeypatch.setattr(s, "detect_install_method", lambda: "pipx")
    monkeypatch.setattr(s, "get_upgrade_command",
                        lambda: ["pipx", "upgrade", "servonaut"])
    monkeypatch.setattr(s, "installed_version_external", lambda: "2.16.3")
    monkeypatch.setattr(asyncio, "create_subprocess_exec",
                        AsyncMock(side_effect=OSError("no pipx")))
    ok, msg = asyncio.run(s.run_upgrade())
    assert ok is False and "Could not run" in msg


# --- pre-releases are never offered to a stable installation ----------------

def _file(yanked=False):
    return {"filename": "servonaut.whl", "yanked": yanked}


def _index(reported, releases=None):
    document = {"info": {"name": "servonaut", "version": reported}}
    if releases is not None:
        document["releases"] = releases
    return document


class _Response:
    def __init__(self, document):
        self._body = json.dumps(document).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None


class _Opener:
    def __init__(self, document):
        self._document = document

    def open(self, request, timeout):
        return _Response(self._document)


# PyPI's JSON API reports the newest non-yanked stable release as
# info.version even when a newer pre-release exists, and lists every
# version, pre-releases included, in the releases table.
_PRERELEASE_PUBLISHED = _index(
    "2.27.0",
    {
        "2.26.0": [_file()],
        "2.27.0": [_file()],
        "2.28.0rc1": [_file()],
        "2.28.0rc2": [_file()],
    },
)


def test_index_version_skips_a_newer_prerelease_for_stable_installs():
    assert latest_index_version(_PRERELEASE_PUBLISHED, include_prereleases=False) == "2.27.0"
    assert latest_index_version(_PRERELEASE_PUBLISHED, include_prereleases=True) == "2.28.0rc2"


def test_index_version_ignores_info_version_naming_a_prerelease():
    # With every stable release yanked, the index reports its newest
    # remaining release as info.version, even a pre-release.
    document = _index(
        "2.28.0rc1", {"2.27.0": [_file(yanked=True)], "2.28.0rc1": [_file()]}
    )
    assert latest_index_version(document, include_prereleases=False) is None
    assert latest_index_version(document, include_prereleases=True) == "2.28.0rc1"


def test_index_version_never_offers_yanked_or_empty_releases():
    document = _index(
        "2.27.2",
        {
            "2.27.0": [_file()],
            "2.27.1": [_file(yanked=True), _file(yanked=True)],
            "2.27.2": [],
        },
    )
    assert latest_index_version(document, include_prereleases=False) == "2.27.0"


def test_index_version_keeps_a_release_with_any_unyanked_file():
    document = _index("2.27.0", {"2.27.0": [_file()], "2.27.1": [_file(yanked=True), _file()]})
    assert latest_index_version(document, include_prereleases=False) == "2.27.1"


def test_index_version_without_a_releases_table_uses_info_version():
    # Some mirrors serve only info.version.
    for releases in (None, {}):
        stable = _index("2.27.0", releases)
        candidate = _index("2.28.0rc1", releases)
        assert latest_index_version(stable, include_prereleases=False) == "2.27.0"
        assert latest_index_version(candidate, include_prereleases=False) is None
        assert latest_index_version(candidate, include_prereleases=True) == "2.28.0rc1"


def test_index_version_skips_versions_it_cannot_order():
    document = _index("2.27.0", {"2.27.0": [_file()], "3.0.0-final": [_file()], "1!4.0": [_file()]})
    assert latest_index_version(document, include_prereleases=True) == "2.27.0"


def test_index_version_requires_info_version():
    for document in ({}, {"info": {}}, {"info": None}, []):
        with pytest.raises((KeyError, TypeError)):
            latest_index_version(document, include_prereleases=False)


@pytest.mark.parametrize(
    "current,offered",
    [
        ("2.27.0", None),  # stable: the newer pre-release is not an update
        ("2.26.0", "2.27.0"),  # stable: the newest stable release is
        ("2.28.0rc1", "2.28.0rc2"),  # pre-release: newer candidates are
        ("2.28.0rc2", None),
    ],
)
def test_update_check_offers_prereleases_only_to_prereleases(current, offered):
    service = _svc(current=current, latest=None)
    service._opener = _Opener(_PRERELEASE_PUBLISHED)

    assert service.check_for_update() == offered
    assert service.follows_prereleases is (current.find("rc") > 0)
    expected = UpdateCheckResult.UPDATE_AVAILABLE if offered else UpdateCheckResult.UP_TO_DATE
    assert service.last_check_result is expected


def test_update_check_moves_a_prerelease_to_the_final_release():
    document = _index("2.28.0", {"2.28.0rc2": [_file()], "2.28.0": [_file()]})
    service = _svc(current="2.28.0rc2", latest=None)
    service._opener = _Opener(document)
    assert service.check_for_update() == "2.28.0"


def test_is_newer_orders_prereleases():
    assert UpdateService._is_newer("2.28.0", "2.28.0rc2")
    assert UpdateService._is_newer("2.28.0rc2", "2.28.0rc1")
    assert UpdateService._is_newer("2.28.0rc1", "2.27.9")
    assert UpdateService._is_newer("2.28.1rc1", "2.28.0rc1")
    assert not UpdateService._is_newer("2.28.0rc1", "2.28.0")
    assert not UpdateService._is_newer("not-a-version", "2.27.0")
    assert not UpdateService._is_newer("2.28.0", "unknown")


@pytest.mark.parametrize("kind", [DistributionKind.PIP, DistributionKind.PIPX])
@pytest.mark.parametrize("latest", [None, "2.28.0", "2.28.0rc1"])
def test_stable_upgrade_commands_never_request_prereleases(kind, latest):
    command = _svc(current="2.27.0", latest=latest, kind=kind).get_upgrade_command()
    assert command is not None
    assert command[-1] == "servonaut"
    assert "--pre" not in command
    assert not any(argument.startswith("--pip-args") for argument in command)


def test_prerelease_upgrade_pins_the_version_found():
    # Pinning keeps dependencies on stable releases, and unlike pipx's
    # --pip-args=--pre it is not stored for later `pipx upgrade` runs.
    pip = _svc(current="2.28.0rc1", latest="2.28.0rc2").get_upgrade_command()
    pipx = _svc(
        current="2.28.0rc1", latest="2.28.0rc2", kind=DistributionKind.PIPX
    ).get_upgrade_command()
    assert pip == [sys.executable, "-m", "pip", "install", "--upgrade", "servonaut==2.28.0rc2"]
    assert pipx == [str(Path("/usr/bin/pipx")), "install", "--force", "servonaut==2.28.0rc2"]


def test_prerelease_upgrade_without_a_known_version_is_the_plain_upgrade():
    for latest in (None, "not a version"):
        command = _svc(current="2.28.0rc1", latest=latest).get_upgrade_command()
        assert command == [sys.executable, "-m", "pip", "install", "--upgrade", "servonaut"]


def test_run_upgrade_pins_the_prerelease_it_just_found(monkeypatch):
    service = _svc(current="2.28.0rc1", latest=None, kind=DistributionKind.PIPX)
    service._opener = _Opener(_PRERELEASE_PUBLISHED)
    monkeypatch.setattr(
        service, "installed_version_external", MagicMock(side_effect=["2.28.0rc1", "2.28.0rc2"])
    )
    spawn = AsyncMock(return_value=_fake_proc())
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    ok, message = asyncio.run(service.run_upgrade())
    assert ok is True, message
    assert spawn.call_args.args == (
        str(Path("/usr/bin/pipx")), "install", "--force", "servonaut==2.28.0rc2"
    )


# --- repackaged installations still see updates -----------------------------

@pytest.mark.parametrize(
    "current,offered",
    [
        ("2.27.0+deb1", "2.27.1"),
        ("2.27.1+deb1", None),
        ("2.27.0-1ubuntu1", "2.27.1"),
        ("v2.27.0", "2.27.1"),
        ("unknown", None),
    ],
)
def test_local_and_repackaged_versions_are_still_offered_updates(current, offered):
    service = _svc(current=current, latest=None)
    service._opener = _Opener(_index("2.27.1", {"2.27.1": [_file()], "2.28.0rc1": [_file()]}))
    assert service.check_for_update() == offered
    assert service.follows_prereleases is False


def test_a_local_prerelease_still_follows_prereleases():
    service = _svc(current="2.28.0rc1+local", latest=None)
    service._opener = _Opener(_PRERELEASE_PUBLISHED)
    assert service.follows_prereleases is True
    assert service.check_for_update() == "2.28.0rc2"
