"""Unit tests for APT-managed Linux packaged-desktop detection and update paths."""

from __future__ import annotations

import asyncio
import logging
import os
import stat
import subprocess
import sys
import threading
import time
from contextlib import asynccontextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Sequence
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)
from servonaut.services.api_client import ClientUpdateRequiredError
from servonaut.services.client_identity import (
    configure_client_identity,
    format_update_required_message,
    is_apt_managed_install,
    reset_client_identity_for_tests,
)
from servonaut.services.update_service import UpdateCheckResult, UpdateService
from servonaut.updates import apt as apt_mod
from servonaut.updates.apt import (
    APT_UPGRADE_COMMAND,
    AptDetectionConfig,
    AptInstallStatus,
    DpkgCommandResult,
    get_cached_apt_status,
    parse_deb822_sources,
    parse_oneline_sources,
    refresh_apt_status,
    reset_apt_status_cache_for_tests,
    scan_apt_sources,
)


@pytest.fixture(autouse=True)
def _reset_caches() -> Any:
    reset_client_identity_for_tests()
    reset_apt_status_cache_for_tests()
    yield
    reset_client_identity_for_tests()
    reset_apt_status_cache_for_tests()


def _make_runtime(
    tmp_path: Path,
    *,
    kind: DistributionKind = DistributionKind.PACKAGED_DESKTOP,
    is_frozen: bool = True,
    version: str = "2.34.0",
    create_files: bool = True,
    mode: int = 0o755,
    marker_mode: int = 0o644,
    dir_mode: int = 0o755,
) -> RuntimeLayout:
    root = tmp_path / "opt" / "servonaut"
    exe = root / "servonaut-desktop"
    marker = root / "servonaut-runtime.json"
    if create_files:
        root.mkdir(parents=True, exist_ok=True)
        exe.write_bytes(b"#!/bin/sh\n")
        marker.write_text('{"distribution_kind": "packaged-desktop"}\n', encoding="utf-8")
        os.chmod(exe, mode)
        os.chmod(marker, marker_mode)
        os.chmod(root, dir_mode)
    return RuntimeLayout(
        kind=kind,
        product_version=version,
        build_revision=None,
        resource_root=root,
        executable_root=root,
        data_root=tmp_path / "data",
        executable=exe,
        python_executable=None if is_frozen else tmp_path / "python",
        path_console=None,
        console_helper=None,
        desktop_child=None,
        package_management=PackageManagementCapability(PackageManagementKind.UNSUPPORTED, (), False),
        is_frozen=is_frozen,
    )


def _make_keyring(tmp_path: Path, name: str = "servonaut-archive-keyring.gpg", data: bytes = b"pgp-key-data") -> Path:
    keyrings = tmp_path / "keyrings"
    keyrings.mkdir(parents=True, exist_ok=True)
    path = keyrings / name
    path.write_bytes(data)
    return path


def _make_dpkg_runner(
    runtime: RuntimeLayout,
    *,
    status_stdout: str = "ii\tamd64\t2.34.0-1\n",
    status_rc: int = 0,
    search_stdout: str | None = None,
    search_rc: int = 0,
    calls: list[tuple[str, ...]] | None = None,
) -> Any:
    exe_resolved = runtime.executable.resolve()
    marker_resolved = (runtime.executable_root / "servonaut-runtime.json").resolve()
    default_search = (
        f"servonaut: {exe_resolved}\n"
        f"servonaut: {marker_resolved}\n"
    )

    def runner(argv: Sequence[str], _timeout: float) -> DpkgCommandResult:
        if calls is not None:
            calls.append(tuple(argv))
        if "-W" in argv:
            return DpkgCommandResult(returncode=status_rc, stdout=status_stdout)
        if "-S" in argv:
            return DpkgCommandResult(
                returncode=search_rc,
                stdout=default_search if search_stdout is None else search_stdout,
            )
        raise AssertionError(f"Unexpected dpkg-query args: {argv}")

    return runner


def _make_apt_env(
    tmp_path: Path,
    *,
    runtime: RuntimeLayout | None = None,
    suite: str = "stable",
    source_format: str = "deb822",
    dpkg_runner: Any = None,
    require_root_owned: bool = False,
) -> tuple[RuntimeLayout, AptDetectionConfig, Path, Path]:
    rt = runtime or _make_runtime(tmp_path)
    apt_dir = tmp_path / "etc" / "apt"
    sources_list = apt_dir / "sources.list"
    sources_d = apt_dir / "sources.list.d"
    sources_d.mkdir(parents=True, exist_ok=True)
    dpkg_status = tmp_path / "var" / "lib" / "dpkg" / "status"
    dpkg_status.parent.mkdir(parents=True, exist_ok=True)
    dpkg_status.write_text("Package: servonaut\nStatus: install ok installed\n", encoding="utf-8")
    keyring = _make_keyring(tmp_path)

    if source_format == "deb822":
        source_file = sources_d / "servonaut.sources"
        source_file.write_text(
            "Types: deb\n"
            "URIs: https://releases.servonaut.dev/apt/\n"
            f"Suites: {suite}\n"
            "Components: main\n"
            "Architectures: amd64\n"
            f"Signed-By: {keyring}\n",
            encoding="utf-8",
        )
    elif source_format == "oneline_d":
        source_file = sources_d / "servonaut.list"
        source_file.write_text(
            f"deb [arch=amd64 signed-by={keyring}] https://releases.servonaut.dev/apt/ {suite} main\n",
            encoding="utf-8",
        )
    elif source_format == "sources_list":
        source_file = sources_list
        source_file.write_text(
            f"deb [arch=amd64 signed-by={keyring}] https://releases.servonaut.dev/apt/ {suite} main\n",
            encoding="utf-8",
        )
    else:
        source_file = sources_d / "empty.sources"

    cfg = AptDetectionConfig(
        packaged_prefixes=(tmp_path,),
        sources_list_path=sources_list,
        sources_list_d_path=sources_d,
        dpkg_status_path=dpkg_status,
        require_root_owned=require_root_owned,
        dpkg_runner=dpkg_runner if dpkg_runner is not None else _make_dpkg_runner(rt),
    )
    return rt, cfg, source_file, keyring


# ---------------------------------------------------------------------------
# Deb822 .sources parser tests (valid, hostile, and malformed)
# ---------------------------------------------------------------------------


def test_parse_deb822_valid_variants(tmp_path: Path) -> None:
    keyring = _make_keyring(tmp_path)

    # Standard stable entry with trailing slash omitted, uppercase host, :443, and comments.
    text = (
        "# Official Servonaut APT repository\n"
        "Types: deb\n"
        "URIs: https://RELEASES.SERVONAUT.DEV:443/apt\n"
        "Suites: stable\n"
        "Components: main\n"
        "Architectures: amd64\n"
        f"Signed-By: {keyring}\n"
    )
    matches = parse_deb822_sources(text, source_path="/etc/apt/sources.list.d/servonaut.sources", host_arch="amd64")
    assert len(matches) == 1
    assert matches[0].suites == ("stable",)
    assert matches[0].keyring_paths == (str(keyring),)

    # Candidate + stable with multi-line continuations and omitted Architectures (defaults to host).
    multi = (
        "Enabled: yes\n"
        "Types: deb\n"
        "URIs:\n"
        " https://releases.servonaut.dev/apt/\n"
        "Suites:\n"
        " stable candidate\n"
        "Components: main\n"
        "Signed-By:\n"
        f" {keyring}\n"
    )
    matches_multi = parse_deb822_sources(multi, source_path="/etc/apt/sources.list.d/multi.sources", host_arch="amd64")
    assert len(matches_multi) == 1
    assert matches_multi[0].suites == ("stable", "candidate")

    # Valid inline ASCII-armored PGP public key block.
    inline_pgp = (
        "Types: deb\n"
        "URIs: https://releases.servonaut.dev/apt/\n"
        "Suites: candidate\n"
        "Components: main\n"
        "Signed-By:\n"
        " -----BEGIN PGP PUBLIC KEY BLOCK-----\n"
        " .\n"
        " mQENBF9exampleBase64KeyBodyLine0123456789+/==\n"
        " =abcd\n"
        " -----END PGP PUBLIC KEY BLOCK-----\n"
    )
    matches_pgp = parse_deb822_sources(inline_pgp, source_path="/etc/apt/sources.list.d/inline.sources", host_arch="amd64")
    assert len(matches_pgp) == 1
    assert matches_pgp[0].suites == ("candidate",)
    assert matches_pgp[0].keyring_paths == ()

    # One disabled stanza + one valid enabled stanza in the same file.
    two_stanzas = (
        "Enabled: no\n"
        "Types: deb\n"
        "URIs: https://releases.servonaut.dev/apt/\n"
        "Suites: candidate\n"
        "Components: main\n"
        f"Signed-By: {keyring}\n"
        "\n"
        "Types: deb\n"
        "URIs: https://releases.servonaut.dev/apt/\n"
        "Suites: stable\n"
        "Components: main\n"
        f"Signed-By: {keyring}\n"
    )
    matches_two = parse_deb822_sources(two_stanzas, source_path="/etc/apt/sources.list.d/two.sources", host_arch="amd64")
    assert len(matches_two) == 1
    assert matches_two[0].suites == ("stable",)


@pytest.mark.parametrize(
    "name, snippet_template",
    [
        ("disabled_no", "Enabled: no\nTypes: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("disabled_false", "Enabled: false\nTypes: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("disabled_0", "Enabled: 0\nTypes: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("disabled_ambiguous", "Enabled: maybe\nTypes: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("enabled_continuation_smuggle", "Enabled: yes\n no\nTypes: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("deb_src_only", "Types: deb-src\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("arch_mismatch", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nArchitectures: arm64\nSigned-By: {keyring}\n"),
        ("arch_negated", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nArchitectures: !amd64\nSigned-By: {keyring}\n"),
        ("arch_empty", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nArchitectures:\nSigned-By: {keyring}\n"),
        ("http_scheme", "Types: deb\nURIs: http://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("unrelated_uri", "Types: deb\nURIs: https://example.com/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("prefix_spoof_path", "Types: deb\nURIs: https://releases.servonaut.dev/apt-evil/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("prefix_spoof_host", "Types: deb\nURIs: https://releases.servonaut.dev.example.com/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("userinfo_uri", "Types: deb\nURIs: https://user@releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),  # leak-guard:allow
        ("query_uri", "Types: deb\nURIs: https://releases.servonaut.dev/apt/?x=1\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("nonstandard_port", "Types: deb\nURIs: https://releases.servonaut.dev:8443/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("mixed_official_and_foreign_uris", "Types: deb\nURIs: https://releases.servonaut.dev/apt/ https://example.com/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("unexpected_suite", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: bookworm\nComponents: main\nSigned-By: {keyring}\n"),
        ("flat_suite_slash", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: ./\nComponents: main\nSigned-By: {keyring}\n"),
        ("mixed_valid_and_unexpected_suite", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable unstable\nComponents: main\nSigned-By: {keyring}\n"),
        ("wrong_component", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: contrib\nSigned-By: {keyring}\n"),
        ("missing_signed_by", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\n"),
        ("empty_signed_by", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By:\n"),
        ("missing_keyring_file", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: {missing_keyring}\n"),
        ("empty_keyring_file", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: {empty_keyring}\n"),
        ("relative_keyring", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: keyrings/servonaut.gpg\n"),
        ("traversal_keyring", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: /usr/share/keyrings/../../etc/apt/trusted.gpg\n"),
        ("global_trusted_gpg", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: /etc/apt/trusted.gpg\n"),
        ("global_trusted_gpg_d", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: /etc/apt/trusted.gpg.d/servonaut.gpg\n"),
        ("global_trusted_gpg_backup", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: /etc/apt/trusted.gpg~\n"),
        ("inline_pgp_missing_end", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n mQENBF9exampleBase64KeyBodyLine0123456789+/==\n"),
        ("inline_pgp_empty_body", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n -----END PGP PUBLIC KEY BLOCK-----\n"),
        ("inline_pgp_header_only", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n Version: GnuPG v2\n .\n -----END PGP PUBLIC KEY BLOCK-----\n"),
        ("trusted_yes", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nTrusted: yes\nSigned-By: {keyring}\n"),
        ("allow_insecure_yes", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nAllow-Insecure: yes\nSigned-By: {keyring}\n"),
        ("allow_weak_true", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nAllow-Weak: true\nSigned-By: {keyring}\n"),
        ("allow_downgrade_1", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nAllow-Downgrade-To-Insecure: 1\nSigned-By: {keyring}\n"),
        ("check_valid_until_no", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nCheck-Valid-Until: no\nSigned-By: {keyring}\n"),
        ("check_date_false", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nCheck-Date: false\nSigned-By: {keyring}\n"),
        ("duplicate_field", "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nSuites: candidate\nComponents: main\nSigned-By: {keyring}\n"),
        ("orphan_continuation", " continuation-before-field\nTypes: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("missing_colon", "Types: deb\nBROKEN LINE WITHOUT COLON\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
        ("nul_byte", "Types: deb\x00\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\nComponents: main\nSigned-By: {keyring}\n"),
    ],
)
def test_parse_deb822_rejects_hostile_and_malformed_stanzas(
    tmp_path: Path, name: str, snippet_template: str,
) -> None:
    keyring = _make_keyring(tmp_path)
    empty_keyring = _make_keyring(tmp_path, name="empty.gpg", data=b"")
    missing_keyring = tmp_path / "keyrings" / "missing.gpg"
    snippet = snippet_template.format(
        keyring=keyring,
        empty_keyring=empty_keyring,
        missing_keyring=missing_keyring,
    )
    matches = parse_deb822_sources(
        snippet,
        source_path=f"/etc/apt/sources.list.d/{name}.sources",
        host_arch="amd64",
    )
    assert matches == [], f"Expected {name} to be rejected, got {matches}"


def test_symlink_keyring_into_global_trust_store_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_global = tmp_path / "global_trusted.d"
    fake_global.mkdir()
    target = fake_global / "global.gpg"
    target.write_bytes(b"global-key")
    scoped_link = tmp_path / "keyrings" / "servonaut.gpg"
    scoped_link.parent.mkdir(parents=True, exist_ok=True)
    scoped_link.symlink_to(target)

    monkeypatch.setattr(apt_mod, "_GLOBAL_TRUST_PATHS", (fake_global,))
    snippet = (
        "Types: deb\n"
        "URIs: https://releases.servonaut.dev/apt/\n"
        "Suites: stable\n"
        "Components: main\n"
        f"Signed-By: {scoped_link}\n"
    )
    assert parse_deb822_sources(
        snippet, source_path="/etc/apt/sources.list.d/servonaut.sources", host_arch="amd64",
    ) == []


# ---------------------------------------------------------------------------
# One-line .list parser tests (valid, hostile, and malformed)
# ---------------------------------------------------------------------------


def test_parse_oneline_valid_variants(tmp_path: Path) -> None:
    keyring = _make_keyring(tmp_path)
    text = (
        "# comment line\n"
        f"deb [arch=amd64 signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main # trailing comment\n"
        f"deb [arch=arm64 arch+=amd64 trusted=no check-valid-until=yes check-date=1 signed-by={keyring}] "
        "https://releases.servonaut.dev/apt candidate main\n"
        f"deb [arch-=arm64 signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main\n"
    )
    matches = parse_oneline_sources(
        text, source_path="/etc/apt/sources.list", host_arch="amd64",
    )
    assert [m.suites for m in matches] == [("stable",), ("candidate",), ("stable",)]


@pytest.mark.parametrize(
    "name, line_template",
    [
        ("deb_src", "deb-src [arch=amd64 signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main"),
        ("missing_options", "deb https://releases.servonaut.dev/apt/ stable main"),
        ("missing_signed_by", "deb [arch=amd64] https://releases.servonaut.dev/apt/ stable main"),
        ("unclosed_bracket", "deb [arch=amd64 signed-by={keyring} https://releases.servonaut.dev/apt/ stable main"),
        ("nested_bracket", "deb [arch=amd64 [signed-by={keyring}]] https://releases.servonaut.dev/apt/ stable main"),
        ("malformed_option_no_eq", "deb [arch=amd64 bogus signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main"),
        ("empty_option_val", "deb [arch=amd64 signed-by=] https://releases.servonaut.dev/apt/ stable main"),
        ("non_arch_plus_eq", "deb [trusted+=no signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main"),
        ("arch_mismatch", "deb [arch=arm64 signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main"),
        ("arch_removed_host", "deb [arch-=amd64 signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main"),
        ("trusted_yes", "deb [trusted=yes signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main"),
        ("trusted_masking", "deb [trusted=yes trusted=no signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main"),
        ("allow_insecure", "deb [allow-insecure=yes signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main"),
        ("allow_weak", "deb [allow-weak=true signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main"),
        ("allow_downgrade", "deb [allow-downgrade-to-insecure=1 signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main"),
        ("check_valid_until_no", "deb [check-valid-until=no signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main"),
        ("check_date_no", "deb [check-date=no signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main"),
        ("http_uri", "deb [signed-by={keyring}] http://releases.servonaut.dev/apt/ stable main"),
        ("foreign_uri", "deb [signed-by={keyring}] https://example.com/apt/ stable main"),
        ("wrong_suite", "deb [signed-by={keyring}] https://releases.servonaut.dev/apt/ testing main"),
        ("missing_component", "deb [signed-by={keyring}] https://releases.servonaut.dev/apt/ stable"),
        ("wrong_component", "deb [signed-by={keyring}] https://releases.servonaut.dev/apt/ stable non-free"),
        ("global_trusted_gpg", "deb [signed-by=/etc/apt/trusted.gpg.d/servonaut.gpg] https://releases.servonaut.dev/apt/ stable main"),
        ("traversal_keyring", "deb [signed-by=/etc/apt/keyrings/../trusted.gpg] https://releases.servonaut.dev/apt/ stable main"),
        ("nul_byte", "deb [signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main\x00"),
    ],
)
def test_parse_oneline_rejects_hostile_and_malformed_lines(
    tmp_path: Path, name: str, line_template: str,
) -> None:
    keyring = _make_keyring(tmp_path)
    line = line_template.format(keyring=keyring)
    matches = parse_oneline_sources(
        line + "\n", source_path=f"/etc/apt/sources.list.d/{name}.list", host_arch="amd64",
    )
    assert matches == [], f"Expected {name} to be rejected, got {matches}"


# ---------------------------------------------------------------------------
# Source-scanning bounds & filename hygiene
# ---------------------------------------------------------------------------


def test_scan_apt_sources_enforces_bounds_and_ignores_backups_and_non_utf8(tmp_path: Path) -> None:
    keyring = _make_keyring(tmp_path)
    sources_list = tmp_path / "sources.list"
    sources_d = tmp_path / "sources.list.d"
    sources_d.mkdir()

    # Ignored filenames per sources.list(5)
    valid_stanza = (
        "Types: deb\n"
        "URIs: https://releases.servonaut.dev/apt/\n"
        "Suites: stable\n"
        "Components: main\n"
        f"Signed-By: {keyring}\n"
    )
    (sources_d / ".hidden.sources").write_text(valid_stanza, encoding="utf-8")
    (sources_d / "servonaut.sources.save").write_text(valid_stanza, encoding="utf-8")
    (sources_d / "servonaut.list.bak").write_text(
        f"deb [signed-by={keyring}] https://releases.servonaut.dev/apt/ stable main\n",
        encoding="utf-8",
    )
    (sources_d / "dir.sources").mkdir()
    (sources_d / "bad-utf8.sources").write_bytes(b"\xff\xfeTypes: deb\n")

    # Oversized file (> max_source_file_bytes) is skipped without failing.
    (sources_d / "00-huge.sources").write_text("# " + ("x" * 2048) + "\n" + valid_stanza, encoding="utf-8")

    cfg = AptDetectionConfig(
        sources_list_path=sources_list,
        sources_list_d_path=sources_d,
        max_source_file_bytes=512,
        max_total_source_bytes=1024,
        max_source_files=10,
    )
    assert scan_apt_sources(cfg, host_arch="amd64") == []

    # A bounded valid file is picked up even after the oversized one is skipped.
    (sources_d / "99-good.sources").write_text(valid_stanza, encoding="utf-8")
    matches = scan_apt_sources(cfg, host_arch="amd64")
    assert len(matches) == 1
    assert matches[0].suites == ("stable",)

    # Total-bytes budget stops reading once exhausted.
    (sources_d / "01-pad.list").write_text("# " + ("a" * 400) + "\n", encoding="utf-8")
    (sources_d / "02-pad.list").write_text("# " + ("b" * 400) + "\n", encoding="utf-8")
    tight_cfg = AptDetectionConfig(
        sources_list_path=sources_list,
        sources_list_d_path=sources_d,
        max_source_file_bytes=512,
        max_total_source_bytes=700,
        max_source_files=10,
    )
    assert scan_apt_sources(tight_cfg, host_arch="amd64") == []

    # File-count cap limits how many sourceparts are scanned.
    cap_cfg = AptDetectionConfig(
        sources_list_path=sources_list,
        sources_list_d_path=sources_d,
        max_source_file_bytes=512,
        max_total_source_bytes=65536,
        max_source_files=2,
    )
    assert scan_apt_sources(cap_cfg, host_arch="amd64") == []


# ---------------------------------------------------------------------------
# dpkg-query ownership, bounded failures, and two-fact agreement
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source_format", ["deb822", "oneline_d", "sources_list"])
def test_refresh_apt_status_happy_path_all_source_formats(tmp_path: Path, source_format: str) -> None:
    rt, cfg, source_file, keyring = _make_apt_env(
        tmp_path, suite="candidate", source_format=source_format,
    )
    status = refresh_apt_status(rt, platform_name="linux", config=cfg)
    assert status.managed is True
    assert status.checked is True
    assert status.dpkg_owned is True
    assert status.suite == "candidate"
    assert status.suites == ("candidate",)
    assert status.suite_display == "candidate"
    assert status.architecture == "amd64"
    assert status.package_version == "2.34.0-1"
    assert status.source_paths == (str(source_file),)
    assert status.keyring_paths == (str(keyring),)


def test_dpkg_ownership_accepts_arch_qualified_owner_and_symlinked_executable(tmp_path: Path) -> None:
    rt = _make_runtime(tmp_path)
    # Simulate running via a symlink (/usr/bin/servonaut -> /opt/servonaut/servonaut-desktop).
    bin_dir = tmp_path / "usr" / "bin"
    bin_dir.mkdir(parents=True)
    symlink_exe = bin_dir / "servonaut"
    symlink_exe.symlink_to(rt.executable)
    symlink_rt = RuntimeLayout(
        kind=rt.kind,
        product_version=rt.product_version,
        build_revision=rt.build_revision,
        resource_root=rt.resource_root,
        executable_root=rt.executable_root,
        data_root=rt.data_root,
        executable=symlink_exe,
        python_executable=None,
        path_console=None,
        console_helper=None,
        desktop_child=None,
        package_management=rt.package_management,
        is_frozen=True,
    )
    exe_resolved = rt.executable.resolve()
    marker_resolved = (rt.executable_root / "servonaut-runtime.json").resolve()
    runner = _make_dpkg_runner(
        rt,
        search_stdout=(
            f"servonaut:amd64: {exe_resolved}\n"
            f"servonaut:amd64: {marker_resolved}\n"
        ),
    )
    _, cfg, _, _ = _make_apt_env(tmp_path, runtime=symlink_rt, dpkg_runner=runner)
    status = refresh_apt_status(symlink_rt, platform_name="linux", config=cfg)
    assert status.managed is True
    assert status.dpkg_owned is True


@pytest.mark.parametrize(
    "case, runner_kwargs",
    [
        ("rc_state", {"status_stdout": "rc\tamd64\t2.34.0-1\n"}),
        ("unpacked_state", {"status_stdout": "iU\tamd64\t2.34.0-1\n"}),
        ("half_configured", {"status_stdout": "iF\tamd64\t2.34.0-1\n"}),
        ("status_nonzero", {"status_rc": 1, "status_stdout": ""}),
        ("status_malformed_cols", {"status_stdout": "ii\tamd64\n"}),
        ("status_multiline", {"status_stdout": "ii\tamd64\t2.34.0-1\nii\tarm64\t2.34.0-1\n"}),
        ("status_bad_arch", {"status_stdout": "ii\tAMD64!\t2.34.0-1\n"}),
        ("status_control_char_ver", {"status_stdout": "ii\tamd64\t2.34.0\x1b[31m\n"}),
        ("search_nonzero", {"search_rc": 1, "search_stdout": ""}),
        ("search_empty", {"search_stdout": ""}),
        ("search_diversion", {"search_stdout": "diversion by other from: /opt/servonaut/servonaut-desktop\n"}),
        ("search_local_diversion", {"search_stdout": "local diversion from: /opt/servonaut/servonaut-desktop\n"}),
        ("search_malformed_line", {"search_stdout": "not-a-valid-dpkg-search-line\n"}),
    ],
)
def test_dpkg_bounded_failure_cases_fall_back_safely(
    tmp_path: Path, case: str, runner_kwargs: dict[str, Any],
) -> None:
    rt = _make_runtime(tmp_path)
    runner = _make_dpkg_runner(rt, **runner_kwargs)
    _, cfg, _, _ = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=runner)
    status = refresh_apt_status(rt, platform_name="linux", config=cfg)
    assert status.managed is False, f"Case {case} should not classify as managed"
    assert status.dpkg_owned is False


def test_dpkg_rejects_partial_or_shared_ownership_and_timeout_and_oversized_output(tmp_path: Path) -> None:
    rt = _make_runtime(tmp_path)
    exe_resolved = rt.executable.resolve()
    marker_resolved = (rt.executable_root / "servonaut-runtime.json").resolve()

    # Only executable owned (marker missing).
    only_exe = _make_dpkg_runner(rt, search_stdout=f"servonaut: {exe_resolved}\n")
    _, cfg1, _, _ = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=only_exe)
    assert refresh_apt_status(rt, platform_name="linux", config=cfg1).managed is False

    # Shared ownership with another package.
    shared = _make_dpkg_runner(
        rt,
        search_stdout=(
            f"otherpkg, servonaut: {exe_resolved}\n"
            f"servonaut: {marker_resolved}\n"
        ),
    )
    _, cfg2, _, _ = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=shared)
    assert refresh_apt_status(rt, platform_name="linux", config=cfg2).managed is False

    # Subprocess timeout.
    def timeout_runner(argv: Sequence[str], timeout: float) -> DpkgCommandResult:
        raise subprocess.TimeoutExpired(argv, timeout)

    _, cfg3, _, _ = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=timeout_runner)
    assert refresh_apt_status(rt, platform_name="linux", config=cfg3).managed is False

    # OSError from dpkg-query.
    def oserror_runner(_argv: Sequence[str], _timeout: float) -> DpkgCommandResult:
        raise OSError("permission denied")

    _, cfg4, _, _ = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=oserror_runner)
    assert refresh_apt_status(rt, platform_name="linux", config=cfg4).managed is False

    # Oversized stdout beyond max_dpkg_output_bytes.
    huge = _make_dpkg_runner(rt, search_stdout=("servonaut: " + ("x" * 2048) + "\n"))
    _, cfg5, _, _ = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=huge)
    cfg5_small = AptDetectionConfig(
        packaged_prefixes=(tmp_path,),
        sources_list_path=cfg5.sources_list_path,
        sources_list_d_path=cfg5.sources_list_d_path,
        dpkg_status_path=cfg5.dpkg_status_path,
        require_root_owned=False,
        max_dpkg_output_bytes=512,
        dpkg_runner=huge,
    )
    assert refresh_apt_status(rt, platform_name="linux", config=cfg5_small).managed is False

    # Missing dpkg-query binary in known system paths (never consults PATH).
    cfg_no_dpkg = AptDetectionConfig(
        packaged_prefixes=(tmp_path,),
        sources_list_path=cfg5.sources_list_path,
        sources_list_d_path=cfg5.sources_list_d_path,
        dpkg_status_path=cfg5.dpkg_status_path,
        dpkg_query_paths=(tmp_path / "no-such-dpkg-query",),
        require_root_owned=False,
        dpkg_runner=None,
    )
    assert refresh_apt_status(rt, platform_name="linux", config=cfg_no_dpkg).managed is False


def test_require_root_owned_checks_uid_and_modes_without_patching_os_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    rt = _make_runtime(tmp_path, mode=0o755, marker_mode=0o644, dir_mode=0o755)
    _, cfg, _, _ = _make_apt_env(tmp_path, runtime=rt, require_root_owned=True)
    real_stat = os.stat
    uid_override = {"uid": 1000}
    mode_overrides: dict[Path, int] = {}

    def fake_ownership_stat(path: Path) -> Any:
        st = real_stat(path)
        resolved = path.resolve()
        mode = mode_overrides.get(resolved, st.st_mode & ~0o022)
        return SimpleNamespace(st_uid=uid_override["uid"], st_mode=mode)

    monkeypatch.setattr(apt_mod, "_stat_for_ownership", fake_ownership_stat)

    # Tight modes (0o755/0o644) owned by a non-root user must be rejected.
    assert refresh_apt_status(rt, platform_name="linux", config=cfg, force=True).managed is False

    # Root-owned but group-writable executable (0o775) must be rejected.
    uid_override["uid"] = 0
    mode_overrides[rt.executable.resolve()] = stat.S_IFREG | 0o775
    assert refresh_apt_status(rt, platform_name="linux", config=cfg, force=True).managed is False

    # Root-owned with tight modes across the whole path chain passes.
    mode_overrides.clear()
    assert refresh_apt_status(rt, platform_name="linux", config=cfg, force=True).managed is True


def test_require_root_owned_rejects_writable_or_non_root_ancestor_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    rt = _make_runtime(tmp_path, mode=0o755, marker_mode=0o644, dir_mode=0o755)
    _, cfg, _, _ = _make_apt_env(tmp_path, runtime=rt, require_root_owned=True)
    real_stat = os.stat
    ancestor = (tmp_path / "opt").resolve()
    ancestor_override = {"uid": 0, "mode": stat.S_IFDIR | 0o777}

    def fake_ownership_stat(path: Path) -> Any:
        st = real_stat(path)
        if path.resolve() == ancestor:
            return SimpleNamespace(
                st_uid=ancestor_override["uid"],
                st_mode=ancestor_override["mode"],
            )
        return SimpleNamespace(st_uid=0, st_mode=st.st_mode & ~0o022)

    monkeypatch.setattr(apt_mod, "_stat_for_ownership", fake_ownership_stat)

    # World-writable ancestor directory (e.g. /opt 0777) must be rejected.
    assert refresh_apt_status(rt, platform_name="linux", config=cfg, force=True).managed is False

    # Non-root ancestor directory with tight mode (uid=1000, 0755) must be rejected.
    ancestor_override["uid"] = 1000
    ancestor_override["mode"] = stat.S_IFDIR | 0o755
    assert refresh_apt_status(rt, platform_name="linux", config=cfg, force=True).managed is False

    # Root-owned tight ancestor directory passes.
    ancestor_override["uid"] = 0
    assert refresh_apt_status(rt, platform_name="linux", config=cfg, force=True).managed is True


def test_configured_dpkg_timeout_env_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SERVONAUT_DPKG_QUERY_TIMEOUT_SECONDS", raising=False)
    assert AptDetectionConfig().effective_timeout() == 3.0
    monkeypatch.setenv("SERVONAUT_DPKG_QUERY_TIMEOUT_SECONDS", "7.5")
    assert AptDetectionConfig().effective_timeout() == 7.5
    # Lower clamp (0.5 s) prevents sub-millisecond timeouts from forcing permanent fallbacks.
    monkeypatch.setenv("SERVONAUT_DPKG_QUERY_TIMEOUT_SECONDS", "0.000001")
    assert AptDetectionConfig().effective_timeout() == 0.5
    monkeypatch.setenv("SERVONAUT_DPKG_QUERY_TIMEOUT_SECONDS", "0.1")
    assert AptDetectionConfig().effective_timeout() == 0.5
    assert AptDetectionConfig(dpkg_timeout_seconds=0.05).effective_timeout() == 0.5
    monkeypatch.setenv("SERVONAUT_DPKG_QUERY_TIMEOUT_SECONDS", "999")
    assert AptDetectionConfig().effective_timeout() == 30.0
    monkeypatch.setenv("SERVONAUT_DPKG_QUERY_TIMEOUT_SECONDS", "not-a-number")
    assert AptDetectionConfig().effective_timeout() == 3.0
    monkeypatch.setenv("SERVONAUT_DPKG_QUERY_TIMEOUT_SECONDS", "-2")
    assert AptDetectionConfig().effective_timeout() == 3.0
    monkeypatch.setenv("SERVONAUT_DPKG_QUERY_TIMEOUT_SECONDS", "nan")
    assert AptDetectionConfig().effective_timeout() == 3.0


# ---------------------------------------------------------------------------
# Isolation & incomplete-evidence fallback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind, is_frozen, platform_name",
    [
        (DistributionKind.PIPX, False, "linux"),
        (DistributionKind.PIP, False, "linux"),
        (DistributionKind.SOURCE, False, "linux"),
        (DistributionKind.FROZEN_CLI, True, "linux"),
        (DistributionKind.PACKAGED_DESKTOP, False, "linux"),
        (DistributionKind.PACKAGED_DESKTOP, True, "darwin"),
        (DistributionKind.PACKAGED_DESKTOP, True, "win32"),
    ],
)
def test_non_linux_or_non_packaged_desktop_never_classified_as_apt_even_with_valid_source(
    tmp_path: Path,
    kind: DistributionKind,
    is_frozen: bool,
    platform_name: str,
) -> None:
    calls: list[tuple[str, ...]] = []
    rt = _make_runtime(tmp_path, kind=kind, is_frozen=is_frozen)
    runner = _make_dpkg_runner(rt, calls=calls)
    _, cfg, _, _ = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=runner)

    status = refresh_apt_status(rt, platform_name=platform_name, config=cfg)
    assert status.managed is False
    assert calls == []
    assert is_apt_managed_install(runtime=rt, platform_name=platform_name, allow_probe=True, config=cfg) is False


def test_incomplete_evidence_falls_back_to_download_guidance(tmp_path: Path) -> None:
    # Fact 1 only: standalone .deb with no official APT source configured
    # skips dpkg-query entirely (cheap gate first) and falls back cleanly.
    calls: list[tuple[str, ...]] = []
    rt = _make_runtime(tmp_path)
    runner = _make_dpkg_runner(rt, calls=calls)
    rt, cfg_no_source, _, _ = _make_apt_env(
        tmp_path, runtime=rt, source_format="none", dpkg_runner=runner,
    )
    status_no_source = refresh_apt_status(rt, platform_name="linux", config=cfg_no_source)
    assert status_no_source.managed is False
    assert status_no_source.checked is True
    assert calls == []
    assert is_apt_managed_install(runtime=rt, platform_name="linux", config=cfg_no_source) is False

    # Fact 2 only: valid APT source configured, but binary is not owned by dpkg.
    reset_apt_status_cache_for_tests()
    runner_unowned = _make_dpkg_runner(rt, status_rc=1, status_stdout="")
    _, cfg_no_dpkg, _, _ = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=runner_unowned)
    status_no_dpkg = refresh_apt_status(rt, platform_name="linux", config=cfg_no_dpkg)
    assert status_no_dpkg.managed is False
    assert status_no_dpkg.dpkg_owned is False


# ---------------------------------------------------------------------------
# Cache behavior (zero I/O reads) and stat-based invalidation
# ---------------------------------------------------------------------------


def test_cached_reads_perform_zero_io_and_stat_changes_invalidate_cache(tmp_path: Path) -> None:
    calls: list[tuple[str, ...]] = []
    rt = _make_runtime(tmp_path)
    runner = _make_dpkg_runner(rt, calls=calls)
    _, cfg, source_file, keyring = _make_apt_env(
        tmp_path, runtime=rt, suite="stable", dpkg_runner=runner,
    )

    # Cold cache: zero I/O, never invokes dpkg_runner.
    assert get_cached_apt_status(rt, platform_name="linux", config=cfg) is None
    assert is_apt_managed_install(runtime=rt, platform_name="linux", config=cfg) is False
    assert calls == []

    # First refresh probes dpkg (-W and -S) and caches the result.
    first = refresh_apt_status(rt, platform_name="linux", config=cfg)
    assert first.managed is True
    assert first.suite == "stable"
    assert len(calls) == 2

    # Subsequent cached read hits memory with zero I/O.
    assert get_cached_apt_status(rt, platform_name="linux", config=cfg) == first
    assert is_apt_managed_install(runtime=rt, platform_name="linux", config=cfg) is True
    assert len(calls) == 2

    # Subsequent refresh with unchanged stats reuses cached status without re-running dpkg-query.
    second = refresh_apt_status(rt, platform_name="linux", config=cfg)
    assert second == first
    assert len(calls) == 2

    # Editing the .sources file invalidates cache and picks up the new suite.
    source_file.write_text(
        "Types: deb\n"
        "URIs: https://releases.servonaut.dev/apt/\n"
        "Suites: candidate\n"
        "Components: main\n"
        "Architectures: amd64\n"
        f"Signed-By: {keyring}\n",
        encoding="utf-8",
    )
    os.utime(source_file, ns=(source_file.stat().st_atime_ns, source_file.stat().st_mtime_ns + 1_000_000))
    third = refresh_apt_status(rt, platform_name="linux", config=cfg)
    assert third.managed is True
    assert third.suite == "candidate"
    assert len(calls) == 4

    # Updating /var/lib/dpkg/status invalidates cache.
    cfg.dpkg_status_path.write_text("Package: servonaut\nStatus: install ok installed\nVersion: 2.35.0-1\n", encoding="utf-8")
    os.utime(
        cfg.dpkg_status_path,
        ns=(cfg.dpkg_status_path.stat().st_atime_ns, cfg.dpkg_status_path.stat().st_mtime_ns + 1_000_000),
    )
    fourth = refresh_apt_status(rt, platform_name="linux", config=cfg)
    assert fourth.managed is True
    assert len(calls) == 6

    # Removing the referenced keyring invalidates cache and falls back to unmanaged
    # without needing to run dpkg-query (source pre-gate catches missing keyring).
    keyring.unlink()
    fifth = refresh_apt_status(rt, platform_name="linux", config=cfg)
    assert fifth.managed is False
    assert fifth.checked is True
    assert len(calls) == 6


# ---------------------------------------------------------------------------
# Explicit --update, UpdateService, ServonautApp, and CLI HTTP 426 paths
# ---------------------------------------------------------------------------


def test_cli_run_update_prints_apt_guidance_without_downloading_or_running_sudo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    import servonaut.main as main_mod
    import servonaut.runtime as runtime_mod
    import servonaut.services.update_service as update_svc_mod

    rt = _make_runtime(tmp_path, version="2.34.0")
    monkeypatch.setattr(main_mod.sys, "platform", "linux")
    monkeypatch.setattr(runtime_mod, "detect_runtime", lambda: rt)
    monkeypatch.setattr(
        apt_mod,
        "refresh_apt_status",
        lambda _rt: AptInstallStatus(
            managed=True,
            suite="stable",
            suites=("stable",),
            dpkg_owned=True,
            architecture="amd64",
            checked=True,
        ),
    )

    def _forbid(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("UpdateService or subprocess must not run for APT-managed installs")

    monkeypatch.setattr(update_svc_mod, "UpdateService", _forbid)
    monkeypatch.setattr(subprocess, "run", _forbid)

    main_mod._run_update()
    out = capsys.readouterr().out
    assert "Current version: 2.34.0" in out
    assert "Updates are managed by apt." in out
    assert "Release channel: stable (set in your APT source)" in out
    assert "To update now, run:" in out
    assert APT_UPGRADE_COMMAND in out
    assert f"`{APT_UPGRADE_COMMAND}`" not in out


@pytest.mark.asyncio
async def test_update_service_refuses_manifest_and_download_for_apt_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    rt = _make_runtime(tmp_path, version="2.34.0")
    monkeypatch.setattr(
        apt_mod,
        "refresh_apt_status",
        lambda _rt: AptInstallStatus(
            managed=True,
            suite="candidate",
            suites=("candidate",),
            dpkg_owned=True,
            architecture="amd64",
            checked=True,
        ),
    )
    svc = UpdateService(runtime=rt)
    monkeypatch.setattr(
        svc,
        "_check_frozen_update",
        MagicMock(side_effect=AssertionError("_check_frozen_update must not run for APT installs")),
    )
    monkeypatch.setattr(
        svc,
        "_run_frozen_upgrade",
        AsyncMock(side_effect=AssertionError("_run_frozen_upgrade must not run for APT installs")),
    )

    assert svc.check_for_update() is None
    assert svc.last_check_result is UpdateCheckResult.NOT_CONFIGURED
    assert "Updates are managed by apt." in (svc.update_status or "")
    assert APT_UPGRADE_COMMAND in (svc.update_status or "")

    ok, msg = await svc.run_upgrade()
    assert ok is False
    assert "Updates are managed by apt." in msg
    assert APT_UPGRADE_COMMAND in msg


@pytest.mark.asyncio
async def test_update_service_standalone_linux_deb_keeps_frozen_download_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    rt = _make_runtime(tmp_path, version="2.34.0")
    monkeypatch.setattr(
        apt_mod,
        "refresh_apt_status",
        lambda _rt: AptInstallStatus(managed=False, dpkg_owned=True, architecture="amd64", checked=True),
    )
    svc = UpdateService(runtime=rt)
    frozen_check = MagicMock(return_value="2.35.0")
    frozen_upgrade = AsyncMock(return_value=(True, "Downloaded verified installer."))
    monkeypatch.setattr(svc, "_check_frozen_update", frozen_check)
    monkeypatch.setattr(svc, "_run_frozen_upgrade", frozen_upgrade)

    assert svc.check_for_update() == "2.35.0"
    frozen_check.assert_called_once_with()
    assert await svc.run_upgrade() == (True, "Downloaded verified installer.")
    frozen_upgrade.assert_awaited_once_with()


def test_http_426_formatting_uses_warm_apt_cache_with_zero_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    rt = _make_runtime(tmp_path, version="2.34.0")
    runner = _make_dpkg_runner(rt, calls=calls)
    _, cfg, _, _ = _make_apt_env(tmp_path, runtime=rt, suite="stable", dpkg_runner=runner)

    # Warm the cache at startup (off the HTTP path).
    status = refresh_apt_status(rt, platform_name="linux", config=cfg)
    assert status.managed is True
    assert len(calls) == 2

    # Now simulate an HTTP 426 arriving on the CLI path: no I/O or dpkg calls allowed.
    configure_client_identity(kind="cli", version="2.34.0", runtime=rt)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(
        apt_mod,
        "refresh_apt_status",
        MagicMock(side_effect=AssertionError("HTTP 426 path must never call refresh_apt_status")),
    )
    err = ClientUpdateRequiredError(
        code="client_update_required",
        message="Upgrade required",
        status=426,
        details={"minimum_version": "2.35.0"},
    )
    assert "2.35.0" in err.message
    assert APT_UPGRADE_COMMAND in err.message
    assert len(calls) == 2

    # Standalone .deb (unmanaged in cache) keeps download guidance.
    apt_mod.seed_apt_status_cache_for_tests(
        AptInstallStatus(managed=False, dpkg_owned=True, checked=True),
        runtime=rt,
        platform_name="linux",
    )
    standalone_msg = format_update_required_message("2.35.0", runtime=rt, platform_name="linux")
    assert "https://servonaut.dev/download" in standalone_msg
    assert APT_UPGRADE_COMMAND not in standalone_msg


@pytest.mark.asyncio
async def test_servonaut_app_skips_background_and_requested_update_checks_for_apt_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from servonaut.app import ServonautApp

    rt = _make_runtime(tmp_path, version="2.34.0")
    probed: list[RuntimeLayout] = []

    def fake_refresh(runtime: RuntimeLayout, **_kwargs: Any) -> AptInstallStatus:
        probed.append(runtime)
        return AptInstallStatus(
            managed=True,
            suite="stable",
            suites=("stable",),
            dpkg_owned=True,
            architecture="amd64",
            checked=True,
        )

    monkeypatch.setattr(apt_mod, "refresh_apt_status", fake_refresh)
    app = ServonautApp()
    app.runtime_layout = rt
    legacy_check = MagicMock(side_effect=AssertionError("Legacy check must not run for APT installs"))
    app.update_service = type("StubSvc", (), {"check_for_update": legacy_check})()

    await app._check_for_update()
    outcome = await app.request_update_check()
    assert outcome == "skipped"
    assert probed == [rt, rt]
    legacy_check.assert_not_called()


# ---------------------------------------------------------------------------
# Edge cases: deb822 modifiers, bounded streaming, cache semantics & startup
# ---------------------------------------------------------------------------


def test_parse_deb822_honours_architectures_remove_and_add(tmp_path: Path) -> None:
    keyring = _make_keyring(tmp_path)

    # Architectures-Remove: amd64 excludes amd64 from matching.
    removed = (
        "Types: deb\n"
        "URIs: https://releases.servonaut.dev/apt/\n"
        "Suites: stable\n"
        "Components: main\n"
        "Architectures-Remove: amd64\n"
        f"Signed-By: {keyring}\n"
    )
    assert parse_deb822_sources(
        removed, source_path="/etc/apt/sources.list.d/rm.sources", host_arch="amd64",
    ) == []

    # Architectures-Remove: arm64 keeps amd64 eligible.
    removed_other = removed.replace("Architectures-Remove: amd64", "Architectures-Remove: arm64")
    assert len(
        parse_deb822_sources(
            removed_other, source_path="/etc/apt/sources.list.d/rm2.sources", host_arch="amd64",
        )
    ) == 1

    # Architectures: arm64 + Architectures-Add: amd64 allows amd64.
    added = (
        "Types: deb\n"
        "URIs: https://releases.servonaut.dev/apt/\n"
        "Suites: stable\n"
        "Components: main\n"
        "Architectures: arm64\n"
        "Architectures-Add: amd64\n"
        f"Signed-By: {keyring}\n"
    )
    assert len(
        parse_deb822_sources(
            added, source_path="/etc/apt/sources.list.d/add.sources", host_arch="amd64",
        )
    ) == 1

    # Explicit Architectures including amd64 still rejected when Architectures-Remove removes amd64.
    both = (
        "Types: deb\n"
        "URIs: https://releases.servonaut.dev/apt/\n"
        "Suites: stable\n"
        "Components: main\n"
        "Architectures: amd64 arm64\n"
        "Architectures-Remove: amd64\n"
        f"Signed-By: {keyring}\n"
    )
    assert parse_deb822_sources(
        both, source_path="/etc/apt/sources.list.d/both.sources", host_arch="amd64",
    ) == []


def test_parse_deb822_accepts_comma_separated_scoped_signed_by_and_rejects_mixed_global(
    tmp_path: Path,
) -> None:
    k1 = _make_keyring(tmp_path, name="k1.gpg")
    k2 = _make_keyring(tmp_path, name="k2.gpg")

    # Valid comma-separated scoped keyrings are accepted.
    valid = (
        "Types: deb\n"
        "URIs: https://releases.servonaut.dev/apt/\n"
        "Suites: stable\n"
        "Components: main\n"
        f"Signed-By: {k1},{k2}\n"
    )
    matches = parse_deb822_sources(
        valid, source_path="/etc/apt/sources.list.d/comma.sources", host_arch="amd64",
    )
    assert len(matches) == 1
    assert matches[0].keyring_paths == (str(k1), str(k2))

    # Any global-trust or missing entry in a comma-separated list rejects the stanza.
    mixed_global = valid.replace(f"{k1},{k2}", f"{k1},/etc/apt/trusted.gpg")
    assert parse_deb822_sources(
        mixed_global, source_path="/etc/apt/sources.list.d/bad1.sources", host_arch="amd64",
    ) == []
    mixed_missing = valid.replace(f"{k1},{k2}", f"{k1},{tmp_path / 'missing.gpg'}")
    assert parse_deb822_sources(
        mixed_missing, source_path="/etc/apt/sources.list.d/bad2.sources", host_arch="amd64",
    ) == []


def test_default_dpkg_runner_stops_reading_at_output_cap_and_kills_grandchild_on_timeout() -> None:
    # A runaway child attempting to stream 16 MiB is killed as soon as stdout crosses the cap.
    spam_cmd = (
        sys.executable,
        "-c",
        "import sys; chunk = b'x' * 65536\nfor _ in range(256): sys.stdout.buffer.write(chunk); sys.stdout.buffer.flush()",
    )
    with pytest.raises(ValueError, match="safety limit"):
        apt_mod._default_dpkg_runner(spam_cmd, timeout=5.0, max_output_bytes=8192)

    # A grandchild holding the stdout pipe open must be terminated within the timeout.
    grandchild_cmd = (
        sys.executable,
        "-c",
        "import subprocess, sys; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])",
    )
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        apt_mod._default_dpkg_runner(grandchild_cmd, timeout=0.5, max_output_bytes=8192)
    elapsed = time.monotonic() - started
    assert elapsed < 3.0


@pytest.mark.parametrize("failure_mode", ["timeout", "nonzero", "oserror", "unpacked_iU"])
def test_transient_dpkg_failures_are_not_cached_and_recover_on_next_refresh(
    tmp_path: Path, failure_mode: str,
) -> None:
    rt = _make_runtime(tmp_path)
    attempts = {"count": 0}
    healthy = _make_dpkg_runner(rt)

    def flaky_runner(argv: Sequence[str], timeout: float) -> DpkgCommandResult:
        if "-W" in argv:
            attempts["count"] += 1
            if attempts["count"] == 1:
                if failure_mode == "timeout":
                    raise subprocess.TimeoutExpired(argv, timeout)
                if failure_mode == "nonzero":
                    return DpkgCommandResult(returncode=1, stdout="")
                if failure_mode == "oserror":
                    raise OSError("temporary failure")
                if failure_mode == "unpacked_iU":
                    return DpkgCommandResult(returncode=0, stdout="iU\tamd64\t2.34.0-1\n")
        return healthy(argv, timeout)

    _, cfg, _, _ = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=flaky_runner)

    # First refresh hits the transient failure and falls back without caching.
    first = refresh_apt_status(rt, platform_name="linux", config=cfg)
    assert first.managed is False
    assert first.checked is False
    assert get_cached_apt_status(rt, platform_name="linux", config=cfg) is None

    # Second refresh (with zero filesystem changes) retries and recovers to managed=True.
    second = refresh_apt_status(rt, platform_name="linux", config=cfg)
    assert second.managed is True
    assert second.checked is True
    assert attempts["count"] == 2


def test_cache_invalidates_when_missing_keyring_for_official_uri_is_installed_later(
    tmp_path: Path,
) -> None:
    rt = _make_runtime(tmp_path)
    calls: list[tuple[str, ...]] = []
    runner = _make_dpkg_runner(rt, calls=calls)
    _, cfg, _source_file, keyring = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=runner)

    # Start with servonaut.sources present, but the referenced keyring not yet created.
    keyring.unlink()
    before = refresh_apt_status(rt, platform_name="linux", config=cfg)
    assert before.managed is False
    assert before.checked is True
    assert calls == []

    # Install the keyring afterwards without modifying servonaut.sources or dpkg/status.
    keyring.write_bytes(b"pgp-key-installed-later")
    after = refresh_apt_status(rt, platform_name="linux", config=cfg)
    assert after.managed is True
    assert after.suite == "stable"
    assert len(calls) == 2


def test_cache_discards_stale_result_when_dpkg_status_changes_mid_probe(tmp_path: Path) -> None:
    rt = _make_runtime(tmp_path)
    healthy = _make_dpkg_runner(rt)
    state = {"calls": 0}
    dpkg_status_holder: dict[str, Path] = {}

    def racing_runner(argv: Sequence[str], timeout: float) -> DpkgCommandResult:
        if "-W" in argv:
            state["calls"] += 1
            if state["calls"] == 1:
                # Simulate apt finishing an upgrade mid-probe after dpkg-query read `rc`.
                status_file = dpkg_status_holder["path"]
                status_file.write_text("Package: servonaut\nStatus: install ok installed\nVersion: 2.35.0-1\n", encoding="utf-8")
                os.utime(
                    status_file,
                    ns=(status_file.stat().st_atime_ns, status_file.stat().st_mtime_ns + 1_000_000),
                )
                return DpkgCommandResult(returncode=0, stdout="rc\tamd64\t2.34.0-1\n")
        return healthy(argv, timeout)

    _, cfg, _, _ = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=racing_runner)
    dpkg_status_holder["path"] = cfg.dpkg_status_path

    # Pre-probe vs post-probe fingerprint mismatch discards the stale `rc` result and re-probes.
    status = refresh_apt_status(rt, platform_name="linux", config=cfg)
    assert status.managed is True
    assert state["calls"] == 2
    # Subsequent refresh with no further disk change serves the fresh managed=True cache.
    assert refresh_apt_status(rt, platform_name="linux", config=cfg).managed is True
    assert state["calls"] == 2


def test_concurrent_refreshes_share_single_flight_probe(tmp_path: Path) -> None:
    rt = _make_runtime(tmp_path)
    calls: list[tuple[str, ...]] = []
    healthy = _make_dpkg_runner(rt, calls=calls)
    entered = threading.Event()
    release = threading.Event()

    def slow_runner(argv: Sequence[str], timeout: float) -> DpkgCommandResult:
        if "-W" in argv:
            entered.set()
            release.wait(timeout=5.0)
        return healthy(argv, timeout)

    _, cfg, _, _ = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=slow_runner)

    results: list[AptInstallStatus] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            results.append(refresh_apt_status(rt, platform_name="linux", config=cfg))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t1 = threading.Thread(target=worker)
    t1.start()
    assert entered.wait(timeout=5.0)

    others = [threading.Thread(target=worker) for _ in range(3)]
    for t in others:
        t.start()
    # Give joining threads a moment to park on the single-flight event.
    time.sleep(0.05)
    release.set()

    t1.join(timeout=5.0)
    for t in others:
        t.join(timeout=5.0)

    assert errors == []
    assert len(results) == 4
    assert all(r.managed is True and r.suite == "stable" for r in results)
    # Single-flight guard: only one (-W, -S) pair ran for all 4 concurrent callers.
    assert len(calls) == 2


def test_cheap_gates_skip_dpkg_outside_packaged_prefix_or_without_official_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    rt = _make_runtime(tmp_path)
    calls: list[tuple[str, ...]] = []
    runner = _make_dpkg_runner(rt, calls=calls)
    _, cfg, source_file, keyring = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=runner)

    # 1. Default packaged_prefixes (/opt/servonaut) rejects a binary in tmp_path without
    #    reading /etc/apt or spawning dpkg-query.
    scan_spy = MagicMock(side_effect=AssertionError("Must not scan sources outside packaged prefix"))
    monkeypatch.setattr(apt_mod, "_iter_readable_source_files", scan_spy)
    default_prefix_cfg = AptDetectionConfig(
        sources_list_path=cfg.sources_list_path,
        sources_list_d_path=cfg.sources_list_d_path,
        dpkg_status_path=cfg.dpkg_status_path,
        require_root_owned=False,
        dpkg_runner=runner,
    )
    outside = refresh_apt_status(rt, platform_name="linux", config=default_prefix_cfg)
    assert outside.managed is False
    assert calls == []
    scan_spy.assert_not_called()

    # Restore source reader for gates 2 and 3.
    monkeypatch.undo()

    # 2. Under the packaged prefix, an arch-mismatched source runs -W only and skips -S.
    source_file.write_text(
        "Types: deb\n"
        "URIs: https://releases.servonaut.dev/apt/\n"
        "Suites: stable\n"
        "Components: main\n"
        "Architectures: arm64\n"
        f"Signed-By: {keyring}\n",
        encoding="utf-8",
    )
    arch_mismatch = refresh_apt_status(rt, platform_name="linux", config=cfg, force=True)
    assert arch_mismatch.managed is False
    assert len(calls) == 1
    assert "-W" in calls[0]


def test_relay_foreground_startup_does_not_crash_and_warms_apt_in_background(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import servonaut.main as main_mod
    import servonaut.runtime as runtime_mod

    rt = _make_runtime(tmp_path, version="2.34.0")
    started = threading.Event()
    release = threading.Event()
    warmed_threads: list[threading.Thread] = []
    real_warm = apt_mod.warm_apt_status_in_background

    def blocking_refresh(runtime: RuntimeLayout, **_kwargs: Any) -> AptInstallStatus:
        started.set()
        release.wait(timeout=5.0)
        status = AptInstallStatus(
            managed=True,
            suite="stable",
            suites=("stable",),
            dpkg_owned=True,
            architecture="amd64",
            checked=True,
        )
        apt_mod.seed_apt_status_cache_for_tests(status, runtime=runtime, platform_name="linux")
        return status

    def spy_warm(*args: Any, **kwargs: Any) -> threading.Thread | None:
        thread = real_warm(*args, **kwargs)
        if thread is not None:
            warmed_threads.append(thread)
        return thread

    class _StopAfterWarm(RuntimeError):
        pass

    # Stop immediately after warm_apt_status_in_background runs (when ConfigManager is constructed).
    monkeypatch.setattr(main_mod.sys, "platform", "linux")
    monkeypatch.setattr(runtime_mod, "detect_runtime", lambda: rt)
    monkeypatch.setattr(apt_mod, "refresh_apt_status", blocking_refresh)
    monkeypatch.setattr(apt_mod, "warm_apt_status_in_background", spy_warm)
    monkeypatch.setattr(
        "servonaut.config.manager.ConfigManager",
        MagicMock(side_effect=_StopAfterWarm("reached ConfigManager without blocking")),
    )

    try:
        # Relay startup must not crash or block on APT probing before taking the relay lock.
        with pytest.raises(_StopAfterWarm):
            main_mod._relay_run_foreground()
        assert len(warmed_threads) == 1
        assert started.wait(timeout=5.0)
        release.set()
        warmed_threads[0].join(timeout=5.0)
        cached = get_cached_apt_status(rt, platform_name="linux")
        assert cached is not None and cached.managed is True
    finally:
        release.set()


@pytest.mark.asyncio
async def test_mcp_run_server_warms_apt_cache_in_background_without_blocking_stdio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    from servonaut.mcp import server as mcp_server
    import servonaut.runtime as runtime_mod

    assert "asyncio" in vars(mcp_server)

    rt = _make_runtime(tmp_path, version="2.34.0")
    started = threading.Event()
    release = threading.Event()
    stdio_entered = threading.Event()
    warmed_threads: list[threading.Thread] = []
    real_warm = apt_mod.warm_apt_status_in_background

    def blocking_refresh(runtime: RuntimeLayout, **_kwargs: Any) -> AptInstallStatus:
        started.set()
        release.wait(timeout=5.0)
        status = AptInstallStatus(
            managed=True,
            suite="stable",
            suites=("stable",),
            dpkg_owned=True,
            architecture="amd64",
            checked=True,
        )
        apt_mod.seed_apt_status_cache_for_tests(status, runtime=runtime, platform_name="linux")
        return status

    def spy_warm(*args: Any, **kwargs: Any) -> threading.Thread | None:
        thread = real_warm(*args, **kwargs)
        if thread is not None:
            warmed_threads.append(thread)
        return thread

    @asynccontextmanager
    async def fake_kept_fresh(_policy: Any):
        yield

    check_unblocked = {"enabled": True}

    @asynccontextmanager
    async def fake_stdio_server(**_kwargs: Any):
        # Proves stdio_server starts before blocking_refresh finishes (no handshake delay).
        stdio_entered.set()
        if check_unblocked["enabled"]:
            assert not release.is_set()
        yield (MagicMock(), MagicMock())

    fake_server = SimpleNamespace(
        servonaut_tools=SimpleNamespace(team_policy=None),
        run=AsyncMock(return_value=None),
        create_initialization_options=MagicMock(return_value={}),
    )

    monkeypatch.setattr(mcp_server.sys, "platform", "linux")
    monkeypatch.setattr(runtime_mod, "detect_runtime", lambda: rt)
    monkeypatch.setattr(apt_mod, "refresh_apt_status", blocking_refresh)
    monkeypatch.setattr(apt_mod, "warm_apt_status_in_background", spy_warm)
    monkeypatch.setattr(mcp_server, "create_mcp_server", lambda: fake_server)
    monkeypatch.setattr("servonaut.services.team_policy_refresh.kept_fresh", fake_kept_fresh)
    monkeypatch.setattr("mcp.server.stdio.stdio_server", fake_stdio_server)

    try:
        await mcp_server.run_server()
        assert stdio_entered.is_set()
        assert len(warmed_threads) == 1
        assert started.wait(timeout=5.0)
        release.set()
        warmed_threads[0].join(timeout=5.0)
        cached = get_cached_apt_status(rt, platform_name="linux")
        assert cached is not None and cached.managed is True
    finally:
        release.set()

    # Verify errors from warm_apt_status_in_background are logged at debug level instead of swallowed.
    check_unblocked["enabled"] = False
    monkeypatch.setattr(
        apt_mod,
        "warm_apt_status_in_background",
        MagicMock(side_effect=RuntimeError("simulated warm error")),
    )
    with caplog.at_level(logging.DEBUG, logger="servonaut.mcp.server"):
        await mcp_server.run_server()
    assert any("simulated warm error" in rec.getMessage() for rec in caplog.records)


def test_definitive_dpkg_missing_or_unowned_is_cached_with_ttl_while_transients_stay_uncached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Default TTL is 5 minutes and configurable via environment variable.
    monkeypatch.delenv("SERVONAUT_APT_NEGATIVE_TTL_SECONDS", raising=False)
    assert AptDetectionConfig().effective_negative_ttl() == 300.0
    monkeypatch.setenv("SERVONAUT_APT_NEGATIVE_TTL_SECONDS", "45")
    assert AptDetectionConfig().effective_negative_ttl() == 45.0
    monkeypatch.setenv("SERVONAUT_APT_NEGATIVE_TTL_SECONDS", "99999")
    assert AptDetectionConfig().effective_negative_ttl() == 3600.0
    monkeypatch.setenv("SERVONAUT_APT_NEGATIVE_TTL_SECONDS", "bad")
    assert AptDetectionConfig().effective_negative_ttl() == 300.0

    rt = _make_runtime(tmp_path)
    clock = {"now": 1000.0}
    monkeypatch.setattr(apt_mod.time, "monotonic", lambda: clock["now"])

    # 1. Exit 1 with "no packages found matching servonaut" is cached for the configured TTL.
    calls_pkg: list[tuple[str, ...]] = []

    def not_installed_runner(argv: Sequence[str], _timeout: float) -> DpkgCommandResult:
        calls_pkg.append(tuple(argv))
        return DpkgCommandResult(
            returncode=1,
            stdout="",
            stderr="dpkg-query: no packages found matching servonaut\n",
        )

    _, base_cfg, _, _ = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=not_installed_runner)
    cfg_pkg = AptDetectionConfig(
        packaged_prefixes=base_cfg.packaged_prefixes,
        sources_list_path=base_cfg.sources_list_path,
        sources_list_d_path=base_cfg.sources_list_d_path,
        dpkg_status_path=base_cfg.dpkg_status_path,
        require_root_owned=False,
        negative_cache_ttl_seconds=60.0,
        dpkg_runner=not_installed_runner,
    )
    first = refresh_apt_status(rt, platform_name="linux", config=cfg_pkg)
    assert first.managed is False and first.checked is True
    assert len(calls_pkg) == 1

    # Within TTL: cache hit, zero extra dpkg-query invocations.
    clock["now"] = 1030.0
    second = refresh_apt_status(rt, platform_name="linux", config=cfg_pkg)
    assert second == first
    assert get_cached_apt_status(rt, platform_name="linux", config=cfg_pkg) == first
    assert len(calls_pkg) == 1

    # Past TTL: cached negative expires and triggers a fresh probe.
    clock["now"] = 1061.0
    assert get_cached_apt_status(rt, platform_name="linux", config=cfg_pkg) is None
    third = refresh_apt_status(rt, platform_name="linux", config=cfg_pkg)
    assert third.managed is False and third.checked is True
    assert len(calls_pkg) == 2

    # 2. Exit 1 with "no path found matching pattern" on -S is also cached for the TTL.
    reset_apt_status_cache_for_tests()
    calls_path: list[tuple[str, ...]] = []

    def unowned_path_runner(argv: Sequence[str], _timeout: float) -> DpkgCommandResult:
        calls_path.append(tuple(argv))
        if "-W" in argv:
            return DpkgCommandResult(returncode=0, stdout="ii\tamd64\t2.34.0-1\n")
        return DpkgCommandResult(
            returncode=1,
            stdout="",
            stderr="dpkg-query: no path found matching pattern /opt/servonaut/servonaut-desktop\n",
        )

    cfg_path = AptDetectionConfig(
        packaged_prefixes=base_cfg.packaged_prefixes,
        sources_list_path=base_cfg.sources_list_path,
        sources_list_d_path=base_cfg.sources_list_d_path,
        dpkg_status_path=base_cfg.dpkg_status_path,
        require_root_owned=False,
        negative_cache_ttl_seconds=60.0,
        dpkg_runner=unowned_path_runner,
    )
    clock["now"] = 2000.0
    p1 = refresh_apt_status(rt, platform_name="linux", config=cfg_path)
    assert p1.managed is False and p1.checked is True
    assert len(calls_path) == 2
    clock["now"] = 2010.0
    assert refresh_apt_status(rt, platform_name="linux", config=cfg_path) == p1
    assert len(calls_path) == 2
    clock["now"] = 2061.0
    assert refresh_apt_status(rt, platform_name="linux", config=cfg_path).checked is True
    assert len(calls_path) == 4

    # 3. Non-zero exit without a definitive message (e.g. rc=2 lock error) remains uncached.
    reset_apt_status_cache_for_tests()
    calls_err: list[tuple[str, ...]] = []

    def lock_error_runner(argv: Sequence[str], _timeout: float) -> DpkgCommandResult:
        calls_err.append(tuple(argv))
        return DpkgCommandResult(returncode=2, stdout="", stderr="dpkg-query: error: database locked\n")

    cfg_err = AptDetectionConfig(
        packaged_prefixes=base_cfg.packaged_prefixes,
        sources_list_path=base_cfg.sources_list_path,
        sources_list_d_path=base_cfg.sources_list_d_path,
        dpkg_status_path=base_cfg.dpkg_status_path,
        require_root_owned=False,
        negative_cache_ttl_seconds=60.0,
        dpkg_runner=lock_error_runner,
    )
    e1 = refresh_apt_status(rt, platform_name="linux", config=cfg_err)
    assert e1.managed is False and e1.checked is False
    e2 = refresh_apt_status(rt, platform_name="linux", config=cfg_err)
    assert e2.managed is False and e2.checked is False
    assert len(calls_err) == 2


def test_single_flight_join_shares_probe_independently_of_key_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    rt = _make_runtime(tmp_path)
    calls: list[tuple[str, ...]] = []
    healthy = _make_dpkg_runner(rt, calls=calls)
    entered = threading.Event()
    release = threading.Event()

    def slow_runner(argv: Sequence[str], timeout: float) -> DpkgCommandResult:
        if "-W" in argv:
            entered.set()
            release.wait(timeout=5.0)
        return healthy(argv, timeout)

    _, cfg, _, _ = _make_apt_env(tmp_path, runtime=rt, dpkg_runner=slow_runner)
    # Bypass the per-key lock so only the single-flight event join prevents duplicate probes.
    monkeypatch.setattr(apt_mod, "_lock_for_key", lambda _key: nullcontext())

    results: list[AptInstallStatus] = []

    def worker() -> None:
        results.append(refresh_apt_status(rt, platform_name="linux", config=cfg))

    owner = threading.Thread(target=worker)
    owner.start()
    assert entered.wait(timeout=5.0)

    joiners = [threading.Thread(target=worker) for _ in range(3)]
    for t in joiners:
        t.start()
    time.sleep(0.05)
    release.set()

    owner.join(timeout=5.0)
    for t in joiners:
        t.join(timeout=5.0)

    assert len(results) == 4
    assert all(r.managed is True for r in results)
    assert len(calls) == 2


def test_atexit_terminates_in_flight_dpkg_query_process_group(tmp_path: Path) -> None:
    pid_file = tmp_path / "sleeper.pid"
    sleeper_script = (
        "import os, pathlib, time\n"
        f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
        "time.sleep(30)\n"
    )
    parent_script = (
        "import sys, threading, time\n"
        "from pathlib import Path\n"
        "from servonaut.updates import apt\n"
        f"cmd = [sys.executable, '-c', {sleeper_script!r}]\n"
        "t = threading.Thread(target=lambda: apt._default_dpkg_runner(cmd, timeout=30.0), daemon=True)\n"
        "t.start()\n"
        f"pid_file = Path({str(pid_file)!r})\n"
        "deadline = time.monotonic() + 5.0\n"
        "while not pid_file.exists() and time.monotonic() < deadline:\n"
        "    time.sleep(0.02)\n"
        "assert pid_file.exists(), 'child did not start'\n"
    )
    env = dict(os.environ)
    src_root = str(Path(apt_mod.__file__).resolve().parents[2])
    env["PYTHONPATH"] = src_root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

    completed = subprocess.run(
        [sys.executable, "-c", parent_script],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    child_pid = int(pid_file.read_text(encoding="utf-8").strip())

    # After parent interpreter exit, the atexit handler must have killed the child process group.
    deadline = time.monotonic() + 2.0
    alive = True
    while time.monotonic() < deadline:
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            alive = False
            break
        except PermissionError:
            break
        time.sleep(0.05)
    if alive:
        try:
            os.kill(child_pid, 9)
        except OSError:
            pass
    assert not alive, f"In-flight child process {child_pid} survived parent interpreter exit"


def test_importing_client_identity_does_not_load_distribution_or_cryptography() -> None:
    src_root = str(Path(apt_mod.__file__).resolve().parents[2])
    env = dict(os.environ)
    env["PYTHONPATH"] = src_root
    check_client_identity = (
        "import sys, servonaut.services.client_identity\n"
        "for mod in ('cryptography', 'servonaut.distribution', 'servonaut.updates.apt'):\n"
        "    assert mod not in sys.modules, f'unexpected startup import: {mod}'\n"
    )
    res1 = subprocess.run(
        [sys.executable, "-c", check_client_identity],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert res1.returncode == 0, res1.stderr

    check_apt_module = (
        "import sys, servonaut.updates.apt\n"
        "for mod in ('cryptography', 'servonaut.distribution'):\n"
        "    assert mod not in sys.modules, f'unexpected apt import: {mod}'\n"
    )
    res2 = subprocess.run(
        [sys.executable, "-c", check_apt_module],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert res2.returncode == 0, res2.stderr
