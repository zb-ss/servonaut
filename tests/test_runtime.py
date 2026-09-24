"""Contract tests for the pure, distribution-aware runtime layout."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from servonaut import __version__, runtime
from servonaut.runtime import (
    DesktopLaunchRoles,
    DesktopProcessRole,
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeCapabilityError,
    RuntimeEvidence,
    RuntimeMarkerError,
    collect_runtime_evidence,
    resolve_runtime,
    validate_desktop_child_argv,
    validate_desktop_process_role,
    validate_launch_argv,
)

_RUNTIME_FIXTURE_ROOT = Path.cwd() / "runtime fixture"


def _evidence(**overrides: object) -> RuntimeEvidence:
    executable = _RUNTIME_FIXTURE_ROOT / "Servonaut" / "servonaut"
    defaults: dict[str, object] = {
        "executable": executable,
        "executable_root": executable.parent,
        "resource_root": executable.parent / "_internal",
        "home": Path("/home/user"),
        "is_frozen": False,
        "package_version": "2.27.0",
        "package_is_installed": True,
        "source_install_path": None,
        "path_console": _RUNTIME_FIXTURE_ROOT / "bin" / "servonaut",
        "pipx_executable": _RUNTIME_FIXTURE_ROOT / "bin" / "pipx",
        "pipx_contains_servonaut": False,
        "marker": None,
    }
    defaults.update(overrides)
    return RuntimeEvidence(**defaults)  # type: ignore[arg-type]


def _desktop_marker(**overrides: object) -> dict[str, object]:
    marker: dict[str, object] = {
        "schema_version": 1,
        "distribution": "packaged-desktop",
        "product_version": "2.27.0",
        "console_helper": "bin/servonaut-cli.exe",
        "desktop_child": "bin/desktop-child.exe",
    }
    marker.update(overrides)
    return marker


@pytest.mark.parametrize(
    ("evidence", "expected_kind", "expected_management"),
    [
        (
            _evidence(source_install_path="file:///workspace/servonaut"),
            DistributionKind.SOURCE,
            PackageManagementKind.PIP,
        ),
        (
            _evidence(),
            DistributionKind.PIP,
            PackageManagementKind.PIP,
        ),
        (
            _evidence(pipx_contains_servonaut=True),
            DistributionKind.PIPX,
            PackageManagementKind.PIPX,
        ),
        (
            _evidence(is_frozen=True),
            DistributionKind.FROZEN_CLI,
            PackageManagementKind.UNSUPPORTED,
        ),
        (
            _evidence(is_frozen=True, marker=_desktop_marker()),
            DistributionKind.PACKAGED_DESKTOP,
            PackageManagementKind.UNSUPPORTED,
        ),
    ],
)
def test_resolves_each_supported_distribution(
    evidence: RuntimeEvidence,
    expected_kind: DistributionKind,
    expected_management: PackageManagementKind,
) -> None:
    layout = resolve_runtime(evidence)

    assert layout.kind is expected_kind
    assert layout.package_management.kind is expected_management
    assert layout.data_root == evidence.home / ".servonaut"


def test_source_precedes_an_unrelated_pipx_installation() -> None:
    layout = resolve_runtime(
        _evidence(
            source_install_path="file:///workspace/servonaut",
            pipx_contains_servonaut=True,
        )
    )

    assert layout.kind is DistributionKind.SOURCE
    assert not layout.package_management.allows_automatic_mutation


def test_no_installed_metadata_resolves_to_source() -> None:
    layout = resolve_runtime(_evidence(package_is_installed=False))

    assert layout.kind is DistributionKind.SOURCE


def test_missing_distribution_metadata_uses_the_source_package_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def metadata_missing(name: str) -> None:
        raise runtime.importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(runtime.importlib.metadata, "distribution", metadata_missing)

    assert runtime._package_evidence() == (__version__, False, None)


@pytest.mark.parametrize(
    ("direct_url", "expected_source"),
    [
        (
            {
                "url": "file:///builds/servonaut-2.27.0-py3-none-any.whl",
                "archive_info": {"hash": "sha256=fixture"},
            },
            None,
        ),
        (
            {
                "url": "file:///workspace/servonaut",
                "dir_info": {"editable": True},
            },
            "file:///workspace/servonaut",
        ),
        (
            {
                "url": "file:///workspace/servonaut",
                "dir_info": {},
            },
            "file:///workspace/servonaut",
        ),
    ],
)
def test_direct_url_distinguishes_local_archives_from_source_directories(
    direct_url: dict[str, object], expected_source: str | None
) -> None:
    class _Distribution:
        version = "2.27.0"

        @staticmethod
        def read_text(name: str) -> str:
            assert name == "direct_url.json"
            return runtime.json.dumps(direct_url)

    assert runtime._source_install_path(_Distribution()) == expected_source  # type: ignore[arg-type]


def test_invalid_utf8_direct_url_is_best_effort_non_source() -> None:
    class _Distribution:
        @staticmethod
        def read_text(name: str) -> str:
            assert name == "direct_url.json"
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    assert runtime._source_install_path(_Distribution()) is None  # type: ignore[arg-type]


def test_evidence_marker_and_capability_prefix_are_immutable() -> None:
    evidence = _evidence(marker=_desktop_marker())
    capability = PackageManagementCapability(
        PackageManagementKind.PIP,
        ["python", "-m", "pip"],  # type: ignore[arg-type]
        True,
    )

    assert isinstance(evidence.marker, type({}.keys().mapping))
    with pytest.raises(TypeError):
        assert evidence.marker is not None
        evidence.marker["product_version"] = "mutated"  # type: ignore[index]
    assert capability.argv_prefix == ("python", "-m", "pip")


def test_marker_precedes_unmarked_frozen_evidence() -> None:
    layout = resolve_runtime(
        _evidence(
            marker=_desktop_marker(product_version="2.27.1"),
            is_frozen=False,
            package_is_installed=False,
        )
    )

    assert layout.kind is DistributionKind.PACKAGED_DESKTOP
    assert layout.is_frozen
    assert layout.product_version == "2.27.1"


def test_marker_uses_executable_root_not_pyinstaller_resource_root() -> None:
    executable = (
        _RUNTIME_FIXTURE_ROOT / "Servonaut.app" / "Contents" / "MacOS" / "Servonaut"
    )
    resource_root = (
        _RUNTIME_FIXTURE_ROOT / "Servonaut.app" / "Contents" / "Resources" / "_internal"
    )
    layout = resolve_runtime(
        _evidence(
            executable=executable,
            executable_root=executable.parent,
            resource_root=resource_root,
            is_frozen=True,
            marker=_desktop_marker(
                console_helper="helpers/servonaut-cli",
                desktop_child="children/桌面-helper",
            ),
        )
    )

    assert layout.resource_root == resource_root
    assert layout.console_helper == executable.parent / "helpers" / "servonaut-cli"
    assert layout.desktop_child == executable.parent / "children" / "桌面-helper"
    assert layout.console_helper != resource_root / "helpers" / "servonaut-cli"


def test_unmarked_frozen_cli_never_exposes_python_or_pip() -> None:
    layout = resolve_runtime(_evidence(is_frozen=True, package_is_installed=False))

    assert layout.python_executable is None
    assert layout.current_app_argv("connect") == [
        str(layout.executable),
        "connect",
    ]
    assert layout.mcp_argv() == [str(layout.executable), "--mcp"]
    with pytest.raises(RuntimeCapabilityError):
        layout.package_management.dependency_install_argv(["hcloud"])
    with pytest.raises(RuntimeCapabilityError):
        layout.package_management.self_update_argv()


def test_marked_frozen_cli_defaults_its_console_helper_to_the_executable() -> None:
    layout = resolve_runtime(
        _evidence(
            is_frozen=True,
            marker={
                "schema_version": 1,
                "distribution": "frozen-cli",
                "product_version": "2.27.0",
            },
        )
    )

    assert layout.console_helper == layout.executable
    assert layout.mcp_argv() == [str(layout.executable), "--mcp"]


def test_package_capabilities_keep_pip_pipx_and_source_semantics() -> None:
    pip = resolve_runtime(_evidence())
    pipx = resolve_runtime(_evidence(pipx_contains_servonaut=True))
    source = resolve_runtime(_evidence(source_install_path="file:///workspace"))

    assert pip.package_management.dependency_install_argv(["hcloud"]) == [
        str(pip.executable),
        "-m",
        "pip",
        "install",
        "hcloud",
    ]
    assert pip.package_management.self_update_argv() == [
        str(pip.executable),
        "-m",
        "pip",
        "install",
        "--upgrade",
        "servonaut",
    ]
    assert pipx.package_management.dependency_install_argv(["ovh"]) == [
        str(pipx.package_management.argv_prefix[0]),
        "inject",
        "servonaut",
        "ovh",
    ]
    assert pipx.package_management.self_update_argv("servonaut") == [
        str(pipx.package_management.argv_prefix[0]),
        "upgrade",
        "servonaut",
    ]
    assert source.package_management.dependency_install_argv(["hcloud"]) == [
        str(source.executable),
        "-m",
        "pip",
        "install",
        "hcloud",
    ]
    with pytest.raises(RuntimeCapabilityError, match="self-update"):
        source.package_management.self_update_argv()


def test_argv_builders_preserve_spaced_unicode_arguments_and_return_fresh_lists() -> (
    None
):
    layout = resolve_runtime(_evidence())
    first = layout.current_app_argv("secrets", "café server")
    second = layout.current_app_argv("secrets", "café server")

    assert first == [
        str(layout.executable),
        "-m",
        "servonaut.main",
        "secrets",
        "café server",
    ]
    assert first is not second
    first.append("mutated")
    assert second[-1] == "café server"

    mcp_first = layout.mcp_argv()
    mcp_second = layout.mcp_argv()
    assert mcp_first == [str(layout.path_console), "--mcp"]
    assert mcp_first is not mcp_second


def test_every_runtime_argv_builder_returns_a_fresh_list() -> None:
    pip = resolve_runtime(_evidence())
    frozen = resolve_runtime(_evidence(is_frozen=True))
    desktop = resolve_runtime(_evidence(is_frozen=True, marker=_desktop_marker()))
    builders = [
        lambda: pip.current_app_argv("connect"),
        pip.mcp_argv,
        lambda: frozen.current_app_argv("connect"),
        frozen.mcp_argv,
        lambda: desktop.current_app_argv("connect"),
        desktop.mcp_argv,
        lambda: desktop.desktop_child_argv("--worker"),
        lambda: pip.package_management.dependency_install_argv(["hcloud"]),
        pip.package_management.self_update_argv,
    ]

    for build in builders:
        first = build()
        second = build()
        first.append("mutated")
        assert first is not second
        assert "mutated" not in second


def test_desktop_builders_never_select_gui_or_child_for_mcp() -> None:
    layout = resolve_runtime(_evidence(is_frozen=True, marker=_desktop_marker()))

    assert layout.current_app_argv("connect") == [
        str(layout.console_helper),
        "connect",
    ]
    assert layout.mcp_argv() == [
        str(layout.console_helper),
        "--mcp",
    ]
    assert layout.desktop_child_argv("--worker") == [
        str(layout.desktop_child),
        "--worker",
    ]


def test_desktop_marker_rejects_private_child_as_console_helper() -> None:
    with pytest.raises(RuntimeMarkerError, match="desktop child"):
        resolve_runtime(
            _evidence(
                marker=_desktop_marker(
                    console_helper="bin/helper", desktop_child="bin/helper"
                )
            )
        )


def test_desktop_marker_accepts_console_helper_as_current_executable() -> None:
    executable = _RUNTIME_FIXTURE_ROOT / "bundle" / "Servonaut"
    layout = resolve_runtime(
        _evidence(
            executable=executable,
            executable_root=executable.parent,
            marker=_desktop_marker(console_helper="Servonaut"),
            is_frozen=True,
        )
    )
    assert layout.console_helper == executable


def test_desktop_child_requires_marker_metadata() -> None:
    layout = resolve_runtime(
        _evidence(
            marker=_desktop_marker(desktop_child=None),
            is_frozen=True,
        )
    )

    with pytest.raises(RuntimeCapabilityError, match="no desktop child"):
        layout.desktop_child_argv()


@pytest.mark.parametrize(
    "marker",
    [
        {},
        {"schema_version": True, "distribution": "frozen-cli", "product_version": "2"},
        {"schema_version": 2, "distribution": "frozen-cli", "product_version": "2"},
        {"schema_version": 1, "distribution": "pip", "product_version": "2"},
        {"schema_version": 1, "distribution": "frozen-cli", "product_version": ""},
        {
            "schema_version": 1,
            "distribution": "frozen-cli",
            "product_version": "2",
            "endpoint": "https://example.invalid",
        },
    ],
)
def test_marker_schema_is_strict(marker: dict[str, object]) -> None:
    with pytest.raises(RuntimeMarkerError):
        resolve_runtime(_evidence(marker=marker))


@pytest.mark.parametrize(
    "helper",
    [
        "",
        "/usr/bin/servonaut-cli",
        "../servonaut-cli",
        "helpers/../servonaut-cli",
        "helpers//servonaut-cli",
        r"..\servonaut-cli.exe",
        r"C:\servonaut-cli.exe",
        r"C:servonaut-cli.exe",
        r"\\server\share\servonaut-cli.exe",
        r"\servonaut-cli.exe",
        "helpers/./servonaut-cli",
        "helpers/worker:alternate",
        "helpers/console. ",
        "helpers/console ",
        "CON",
        "aux.exe",
        "CONIN$",
        "conout$.exe",
        "drivers/LPT9",
        "drivers/com1.log",
        "drivers/COM¹.exe",
        "drivers/lpt²",
        "drivers/Com³.log",
    ],
)
def test_marker_helper_rejects_posix_and_windows_escape_forms(helper: str) -> None:
    with pytest.raises(RuntimeMarkerError):
        resolve_runtime(_evidence(marker=_desktop_marker(console_helper=helper)))


def test_pure_resolution_performs_no_filesystem_or_environment_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("pure resolver attempted I/O")

    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr(Path, "exists", forbidden)
    monkeypatch.setattr(Path, "is_file", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(runtime.shutil, "which", forbidden)
    monkeypatch.setattr(runtime.subprocess, "run", forbidden)
    monkeypatch.setattr(runtime.importlib.metadata, "distribution", forbidden)

    layout = resolve_runtime(_evidence(marker=_desktop_marker()))

    assert layout.kind is DistributionKind.PACKAGED_DESKTOP


def test_collection_distinguishes_absent_and_malformed_markers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "servonaut"
    monkeypatch.setattr(runtime.sys, "executable", str(executable))
    monkeypatch.setattr(runtime.sys, "frozen", True, raising=False)
    monkeypatch.setattr(runtime, "_package_evidence", lambda: ("2.27.0", False, None))
    monkeypatch.setattr(runtime, "_path_command", lambda name: None)
    monkeypatch.setattr(runtime, "_pipx_owns_current_runtime", lambda pipx, exe: False)

    assert collect_runtime_evidence().marker is None
    (tmp_path / "servonaut-runtime.json").write_text("not-json", encoding="utf-8")
    with pytest.raises(RuntimeMarkerError, match="invalid JSON"):
        collect_runtime_evidence()
    (tmp_path / "servonaut-runtime.json").write_bytes(b"\xff")
    with pytest.raises(RuntimeMarkerError, match="could not be read"):
        collect_runtime_evidence()


def test_collection_rejects_oversized_and_deeply_nested_markers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "servonaut"
    marker_path = tmp_path / "servonaut-runtime.json"
    monkeypatch.setattr(runtime.sys, "executable", str(executable))
    monkeypatch.setattr(runtime.sys, "frozen", True, raising=False)
    monkeypatch.setattr(runtime, "_package_evidence", lambda: ("2.27.0", False, None))
    monkeypatch.setattr(runtime, "_path_command", lambda name: None)
    monkeypatch.setattr(runtime, "_pipx_owns_current_runtime", lambda pipx, exe: False)

    marker_path.write_bytes(b"x" * (runtime._MAX_MARKER_BYTES + 1))
    with pytest.raises(RuntimeMarkerError, match="supported size"):
        collect_runtime_evidence()

    marker_path.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    with pytest.raises(RuntimeMarkerError, match="invalid JSON"):
        collect_runtime_evidence()


def test_collection_keeps_meipass_resource_root_distinct_from_executable_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "App Folder" / "Servonaut.exe"
    resource_root = tmp_path / "App Folder" / "_internal resources"
    monkeypatch.setattr(runtime.sys, "executable", str(executable))
    monkeypatch.setattr(runtime.sys, "frozen", True, raising=False)
    monkeypatch.setattr(runtime.sys, "_MEIPASS", str(resource_root), raising=False)
    monkeypatch.setattr(runtime, "_package_evidence", lambda: ("2.27.0", True, None))
    monkeypatch.setattr(runtime, "_path_command", lambda name: None)
    monkeypatch.setattr(runtime, "_pipx_owns_current_runtime", lambda pipx, exe: False)

    evidence = collect_runtime_evidence()

    assert evidence.executable_root == executable.parent
    assert evidence.resource_root == resource_root


@pytest.mark.parametrize(
    ("is_frozen", "package_is_installed", "source_install_path", "marker"),
    [
        (False, False, None, None),
        (False, True, "file:///workspace/servonaut", None),
        (True, True, None, None),
        (False, True, None, _desktop_marker()),
    ],
)
def test_collection_skips_pipx_for_known_source_and_packaged_layouts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    is_frozen: bool,
    package_is_installed: bool,
    source_install_path: str | None,
    marker: dict[str, object] | None,
) -> None:
    executable = tmp_path / "servonaut"
    monkeypatch.setattr(runtime.sys, "executable", str(executable))
    monkeypatch.setattr(runtime.sys, "frozen", is_frozen, raising=False)
    monkeypatch.setattr(
        runtime,
        "_package_evidence",
        lambda: ("2.27.0", package_is_installed, source_install_path),
    )
    monkeypatch.setattr(runtime, "_read_build_marker", lambda root: marker)
    monkeypatch.setattr(runtime, "_path_command", lambda name: None)
    monkeypatch.setattr(
        runtime,
        "_pipx_owns_current_runtime",
        lambda pipx, python: pytest.fail("known layout inspected pipx"),
    )

    evidence = collect_runtime_evidence()

    assert not evidence.pipx_contains_servonaut
    assert evidence.pipx_executable is None


@pytest.mark.parametrize(
    ("pipx_owned", "expected_kind"),
    [(False, DistributionKind.PIP), (True, DistributionKind.PIPX)],
)
def test_collection_still_probes_pipx_for_mutable_installed_runtimes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipx_owned: bool,
    expected_kind: DistributionKind,
) -> None:
    executable = tmp_path / "environment" / "bin" / "python"
    pipx = tmp_path / "tools" / "pipx"
    calls: list[tuple[Path | None, Path]] = []
    monkeypatch.setattr(runtime.sys, "executable", str(executable))
    monkeypatch.setattr(runtime.sys, "frozen", False, raising=False)
    monkeypatch.setattr(runtime, "_package_evidence", lambda: ("2.27.0", True, None))
    monkeypatch.setattr(runtime, "_read_build_marker", lambda root: None)
    monkeypatch.setattr(
        runtime,
        "_path_command",
        lambda name: pipx if name == "pipx" else None,
    )

    def pipx_ownership(candidate: Path | None, python: Path) -> bool:
        calls.append((candidate, python))
        return pipx_owned

    monkeypatch.setattr(runtime, "_pipx_owns_current_runtime", pipx_ownership)

    evidence = collect_runtime_evidence()

    assert calls == [(pipx, executable)]
    assert evidence.pipx_contains_servonaut is pipx_owned
    assert resolve_runtime(evidence).kind is expected_kind


def test_pipx_detection_requires_the_current_python_to_be_in_the_pipx_venv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipx = _RUNTIME_FIXTURE_ROOT / "tools" / "pipx"
    source_python = _RUNTIME_FIXTURE_ROOT / "workspace" / ".venv" / "bin" / "python"
    pipx_venvs = _RUNTIME_FIXTURE_ROOT / "pipx" / "venvs"
    pipx_python = pipx_venvs / "servonaut" / "bin" / "python"

    assert not runtime._pipx_owns_current_runtime(pipx, source_python)

    class _Result:
        returncode = 0
        stdout = ""

    def run(argv: list[str], *args: object, **kwargs: object) -> _Result:
        result = _Result()
        result.stdout = (
            str(pipx_venvs)
            if argv[1:3] == ["environment", "--value"]
            else '{"venvs": {"servonaut": {}}}'
        )
        return result

    monkeypatch.setattr(runtime.subprocess, "run", run)
    assert runtime._pipx_owns_current_runtime(pipx, pipx_python)


def test_pipx_inspection_timeout_is_bounded_and_configurable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipx = _RUNTIME_FIXTURE_ROOT / "tools" / "pipx"
    pipx_venvs = _RUNTIME_FIXTURE_ROOT / "pipx" / "venvs"
    pipx_python = pipx_venvs / "servonaut" / "bin" / "python"
    captured: dict[str, object] = {}

    class _Result:
        returncode = 0
        stdout = ""

    def run(argv: list[str], *args: object, **kwargs: object) -> _Result:
        captured.update(kwargs)
        result = _Result()
        result.stdout = (
            str(pipx_venvs)
            if argv[1:3] == ["environment", "--value"]
            else '{"venvs": {"servonaut": {}}}'
        )
        return result

    monkeypatch.setenv("SERVONAUT_PIPX_INSPECTION_TIMEOUT_SECONDS", "2.5")
    monkeypatch.setattr(runtime.subprocess, "run", run)

    assert runtime._pipx_owns_current_runtime(pipx, pipx_python)
    assert captured["timeout"] == 2.5


def test_pipx_detection_uses_the_reported_custom_venvs_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipx = tmp_path / "tools" / "pipx"
    local_venvs = tmp_path / "custom pipx home" / "venvs"
    python = local_venvs / "servonaut" / "bin" / "python"
    calls: list[list[str]] = []

    class _Result:
        returncode = 0
        stdout = ""

    def run(argv: list[str], *args: object, **kwargs: object) -> _Result:
        calls.append(argv)
        result = _Result()
        result.stdout = (
            str(local_venvs)
            if argv[1:3] == ["environment", "--value"]
            else '{"venvs": {"servonaut": {}}}'
        )
        return result

    monkeypatch.setattr(runtime.subprocess, "run", run)

    assert runtime._pipx_owns_current_runtime(pipx, python)
    assert calls == [
        [str(pipx), "environment", "--value", "PIPX_LOCAL_VENVS"],
        [str(pipx), "list", "--json"],
    ]


@pytest.mark.parametrize(
    ("listing", "expected"),
    [
        ('{"venvs": {"servonaut": {}}}', True),
        ('{"venvs": {"other-tool": {}}}', False),
        ("package other-tool has invalid interpreter", False),
    ],
)
def test_pipx_detection_reads_the_listing_when_a_sibling_venv_is_broken(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, listing: str, expected: bool
) -> None:
    """pipx exits non-zero when any other venv is broken but still lists the healthy ones."""
    pipx = tmp_path / "tools" / "pipx"
    local_venvs = tmp_path / "pipx home" / "venvs"
    python = local_venvs / "servonaut" / "bin" / "python"

    def run(argv: list[str], *args: object, **kwargs: object) -> subprocess.CompletedProcess:
        if argv[1:3] == ["environment", "--value"]:
            return subprocess.CompletedProcess(argv, 0, stdout=str(local_venvs), stderr="")
        return subprocess.CompletedProcess(argv, 1, stdout=listing, stderr="")

    monkeypatch.setattr(runtime.subprocess, "run", run)

    assert runtime._pipx_owns_current_runtime(pipx, python) is expected


def test_pipx_detection_rejects_an_unrelated_similarly_named_venv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipx = tmp_path / "tools" / "pipx"
    local_venvs = tmp_path / "pipx home" / "venvs"
    unrelated_python = tmp_path / "project" / "venvs" / "servonaut" / "bin" / "python"

    class _Result:
        returncode = 0
        stdout = str(local_venvs)

    monkeypatch.setattr(runtime.subprocess, "run", lambda *args, **kwargs: _Result())

    assert not runtime._pipx_owns_current_runtime(pipx, unrelated_python)


def test_pipx_detection_does_not_resolve_the_venv_python_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipx = tmp_path / "tools" / "pipx"
    local_venvs = tmp_path / "pipx home" / "venvs"
    venv_bin = local_venvs / "servonaut" / "bin"
    venv_bin.mkdir(parents=True)
    base_python = tmp_path / "base-python"
    base_python.write_text("fixture", encoding="utf-8")
    python = venv_bin / ("python.exe" if os.name == "nt" else "python")
    try:
        python.symlink_to(base_python)
    except OSError:
        pytest.skip("symlinks are unavailable on this test host")

    class _Result:
        returncode = 0
        stdout = ""

    def run(argv: list[str], *args: object, **kwargs: object) -> _Result:
        result = _Result()
        result.stdout = (
            str(local_venvs)
            if argv[1:3] == ["environment", "--value"]
            else '{"venvs": {"servonaut": {}}}'
        )
        return result

    monkeypatch.setattr(runtime.subprocess, "run", run)

    assert runtime._pipx_owns_current_runtime(pipx, python)


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "0", "-1", "invalid"])
def test_pipx_inspection_timeout_rejects_non_finite_and_invalid_values(
    value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SERVONAUT_PIPX_INSPECTION_TIMEOUT_SECONDS", value)

    assert runtime._pipx_inspection_timeout_seconds() == 5.0


def test_validate_launch_argv_checks_at_the_operation_boundary(tmp_path: Path) -> None:
    command = tmp_path / "launch helper.exe"
    command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    command.chmod(command.stat().st_mode | stat.S_IXUSR)

    validated = validate_launch_argv([str(command), "café server"])

    assert command.is_absolute()
    assert validated == [str(command), "café server"]
    assert validated is not validate_launch_argv([str(command), "café server"])
    with pytest.raises(RuntimeCapabilityError, match="absolute"):
        validate_launch_argv(["relative-command"])
    with pytest.raises(RuntimeCapabilityError, match="regular file"):
        validate_launch_argv([str(tmp_path / "missing")])


def test_validate_launch_argv_confines_packaged_helper_targets(tmp_path: Path) -> None:
    root = tmp_path / "bundle root"
    helper = root / "helpers" / "console helper.exe"
    helper.parent.mkdir(parents=True)
    helper.write_text("fixture", encoding="utf-8")
    helper.chmod(helper.stat().st_mode | stat.S_IXUSR)

    assert validate_launch_argv([str(helper)], executable_root=root) == [str(helper)]


def _packaged_layout(
    root: Path, *, desktop_child: bool = False
) -> runtime.RuntimeLayout:
    executable = root / "Servonaut.exe"
    console_helper = root / "helpers" / "console helper.exe"
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_text("fixture", encoding="utf-8")
    console_helper.parent.mkdir(parents=True, exist_ok=True)
    console_helper.write_text("fixture", encoding="utf-8")
    marker = _desktop_marker(
        console_helper="helpers/console helper.exe",
        desktop_child="helpers/desktop child.exe" if desktop_child else None,
    )
    if desktop_child:
        child = root / "helpers" / "desktop child.exe"
        child.write_text("fixture", encoding="utf-8")
    return resolve_runtime(
        _evidence(
            executable=executable,
            executable_root=root,
            resource_root=root / "_internal",
            is_frozen=True,
            marker=marker,
        )
    )


def test_runtime_aware_validation_derives_the_packaged_root(tmp_path: Path) -> None:
    root = tmp_path / "bundle root"
    layout = _packaged_layout(root)
    assert layout.console_helper is not None
    layout.console_helper.chmod(layout.console_helper.stat().st_mode | stat.S_IXUSR)

    assert validate_launch_argv([str(layout.console_helper)], runtime=layout) == [
        str(layout.console_helper)
    ]


@pytest.mark.parametrize("source_install_path", (None, "file:///workspace/servonaut"))
def test_runtime_aware_validation_does_not_confine_managed_python_symlinks(
    tmp_path: Path, source_install_path: str | None
) -> None:
    root = tmp_path / "managed environment"
    interpreter = root / "bin" / ("python.exe" if os.name == "nt" else "python")
    interpreter.parent.mkdir(parents=True)
    base_python = tmp_path / "base interpreter"
    base_python.write_text("fixture", encoding="utf-8")
    base_python.chmod(base_python.stat().st_mode | stat.S_IXUSR)
    try:
        interpreter.symlink_to(base_python)
    except OSError:
        pytest.skip("symlinks are unavailable on this test host")
    managed = resolve_runtime(
        _evidence(
            executable=interpreter,
            executable_root=interpreter.parent,
            resource_root=root / "resources",
            source_install_path=source_install_path,
            is_frozen=False,
        )
    )
    frozen = resolve_runtime(
        _evidence(
            executable=interpreter,
            executable_root=interpreter.parent,
            resource_root=root / "resources",
            is_frozen=True,
        )
    )

    assert validate_launch_argv([str(interpreter)], runtime=managed) == [
        str(interpreter)
    ]
    with pytest.raises(RuntimeCapabilityError, match="inside the executable root"):
        validate_launch_argv([str(interpreter)], runtime=frozen)


def test_validate_launch_argv_allows_an_in_root_helper_symlink(tmp_path: Path) -> None:
    root = tmp_path / "bundle root"
    target = root / "helpers" / "console helper.exe"
    target.parent.mkdir(parents=True)
    target.write_text("fixture", encoding="utf-8")
    target.chmod(target.stat().st_mode | stat.S_IXUSR)
    helper = root / "console helper.exe"
    try:
        helper.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable on this test host")

    assert validate_launch_argv([str(helper)], executable_root=root) == [str(helper)]


def test_validate_launch_argv_rejects_an_escaped_helper_symlink(tmp_path: Path) -> None:
    root = tmp_path / "bundle root"
    root.mkdir()
    outside = tmp_path / "outside helper.exe"
    outside.write_text("fixture", encoding="utf-8")
    outside.chmod(outside.stat().st_mode | stat.S_IXUSR)
    helper = root / "console helper.exe"
    try:
        helper.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable on this test host")

    with pytest.raises(RuntimeCapabilityError, match="inside the executable root"):
        validate_launch_argv([str(helper)], executable_root=root)


def test_runtime_aware_validation_rejects_an_escaped_helper_symlink(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle root"
    layout = _packaged_layout(root)
    outside = tmp_path / "outside helper.exe"
    outside.write_text("fixture", encoding="utf-8")
    outside.chmod(outside.stat().st_mode | stat.S_IXUSR)
    helper = root / "escaped helper.exe"
    try:
        helper.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable on this test host")

    with pytest.raises(RuntimeCapabilityError, match="inside the executable root"):
        validate_launch_argv([str(helper)], runtime=layout)


@pytest.mark.parametrize(
    ("forbidden", "alias_kind", "message"),
    [
        ("gui", "symlink", "GUI executable"),
        ("gui", "hardlink", "GUI executable"),
        ("child", "symlink", "desktop child helper"),
        ("child", "hardlink", "desktop child helper"),
    ],
)
def test_runtime_aware_validation_rejects_gui_and_child_samefile_aliases(
    tmp_path: Path, forbidden: str, alias_kind: str, message: str
) -> None:
    root = tmp_path / "bundle root"
    layout = _packaged_layout(root, desktop_child=True)
    target = layout.executable if forbidden == "gui" else layout.desktop_child
    assert target is not None
    target.chmod(target.stat().st_mode | stat.S_IXUSR)
    alias = root / f"{forbidden} alias.exe"
    try:
        if alias_kind == "hardlink":
            alias.hardlink_to(target)
        else:
            alias.symlink_to(target)
    except OSError:
        pytest.skip(f"{alias_kind}s are unavailable on this test host")

    with pytest.raises(RuntimeCapabilityError, match=message):
        validate_launch_argv([str(alias)], platform_name="nt", runtime=layout)


def test_windows_executable_suffix_validation_is_explicit_and_deterministic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "console.exe"
    executable.write_text("fixture", encoding="utf-8")
    script = tmp_path / "console.sh"
    script.write_text("fixture", encoding="utf-8")

    def forbidden_posix_permission_check(*args: object, **kwargs: object) -> bool:
        raise AssertionError(
            "Windows launch validation must not inspect POSIX execute bits"
        )

    monkeypatch.setattr(runtime.os, "access", forbidden_posix_permission_check)

    assert validate_launch_argv([str(executable)], platform_name="nt") == [
        str(executable)
    ]
    with pytest.raises(RuntimeCapabilityError, match="Windows file extension"):
        validate_launch_argv([str(script)], platform_name="nt")


def test_frozen_windows_commands_require_native_executables_not_pathext_scripts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "bundle root"
    root.mkdir()
    executable = root / "Servonaut.exe"
    executable.write_text("fixture", encoding="utf-8")
    script = root / "console helper.ps1"
    script.write_text("fixture", encoding="utf-8")
    layout = resolve_runtime(
        _evidence(
            executable=executable,
            executable_root=root,
            resource_root=root / "_internal",
            is_frozen=True,
        )
    )
    monkeypatch.setenv("PATHEXT", ".PS1;.EXE")

    assert validate_launch_argv([str(script)], platform_name="nt") == [str(script)]
    with pytest.raises(RuntimeCapabilityError, match="native Windows .exe"):
        validate_launch_argv([str(script)], platform_name="nt", runtime=layout)
    assert validate_launch_argv(
        [str(executable)], platform_name="nt", runtime=layout
    ) == [str(executable)]


def test_collection_keeps_only_the_current_interpreter_console_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment_bin = tmp_path / "environment with spaces" / "bin"
    environment_bin.mkdir(parents=True)
    executable = environment_bin / ("python.exe" if os.name == "nt" else "python")
    executable.write_text("fixture", encoding="utf-8")
    entrypoint = environment_bin / ("servonaut.exe" if os.name == "nt" else "servonaut")
    entrypoint.write_text("fixture", encoding="utf-8")
    decoy = tmp_path / "other environment" / "servonaut"
    decoy.parent.mkdir()
    decoy.write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(runtime.sys, "executable", str(executable))
    monkeypatch.setattr(runtime, "_package_evidence", lambda: ("2.27.0", True, None))
    monkeypatch.setattr(runtime, "_pipx_owns_current_runtime", lambda pipx, exe: False)
    monkeypatch.setattr(
        runtime,
        "_path_command",
        lambda name: decoy if name == "servonaut" else None,
    )

    assert collect_runtime_evidence().path_console is None

    candidate = (
        tmp_path / "path entry" / ("servonaut.exe" if os.name == "nt" else "servonaut")
    )
    candidate.parent.mkdir()
    try:
        candidate.symlink_to(entrypoint)
    except OSError:
        pytest.skip("symlinks are unavailable on this test host")
    monkeypatch.setattr(
        runtime,
        "_path_command",
        lambda name: candidate if name == "servonaut" else None,
    )

    assert collect_runtime_evidence().path_console == entrypoint.resolve()


def test_invalid_argument_and_package_inputs_fail_before_command_construction() -> None:
    layout = resolve_runtime(_evidence())

    with pytest.raises(TypeError, match="arguments"):
        layout.current_app_argv("valid", 1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="packages"):
        layout.package_management.dependency_install_argv([])


def _setup_desktop_bundle_fixture(
    root: Path,
    *,
    ext: str | None = None,
    current_role: DesktopProcessRole = DesktopProcessRole.GUI,
) -> tuple[Path, Path, Path, runtime.RuntimeLayout]:
    # The shipped desktop bundle is flat: all three executables and the
    # runtime marker share one directory, and the console helper is plain
    # ``servonaut``.
    if ext is None:
        ext = ".exe" if os.name == "nt" else ""
    gui = root / f"servonaut-desktop{ext}"
    child = root / f"servonaut-desktop-child{ext}"
    console = root / f"servonaut{ext}"

    root.mkdir(parents=True, exist_ok=True)
    for executable, content in (
        (gui, "gui-fixture"),
        (child, "child-fixture"),
        (console, "console-fixture"),
    ):
        executable.write_text(content, encoding="utf-8")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)

    marker = _desktop_marker(
        console_helper=f"servonaut{ext}",
        desktop_child=f"servonaut-desktop-child{ext}",
    )

    if current_role is DesktopProcessRole.GUI:
        current_exe = gui
    elif current_role is DesktopProcessRole.CHILD:
        current_exe = child
    else:
        current_exe = console

    layout = resolve_runtime(
        _evidence(
            executable=current_exe,
            executable_root=current_exe.parent,
            resource_root=root / "_internal",
            is_frozen=True,
            marker=marker,
        )
    )
    return gui, child, console, layout


def test_desktop_process_roles_validates_in_matching_contexts(tmp_path: Path) -> None:
    for role in (
        DesktopProcessRole.GUI,
        DesktopProcessRole.CHILD,
        DesktopProcessRole.CONSOLE,
    ):
        role_dir = tmp_path / f"context_{role.value}"
        gui, child, console, layout = _setup_desktop_bundle_fixture(
            role_dir, current_role=role
        )
        current = (
            gui
            if role is DesktopProcessRole.GUI
            else (child if role is DesktopProcessRole.CHILD else console)
        )
        roles = validate_desktop_process_role(layout, role, current_executable=current)
        assert isinstance(roles, DesktopLaunchRoles)
        assert roles.current == current
        assert roles.child == child
        assert roles.console == console


def test_desktop_process_roles_deterministic_windows_mode(tmp_path: Path) -> None:
    root = tmp_path / "win_bundle"
    gui, child, console, layout = _setup_desktop_bundle_fixture(
        root, ext=".exe", current_role=DesktopProcessRole.GUI
    )
    roles = validate_desktop_process_role(
        layout,
        DesktopProcessRole.GUI,
        current_executable=gui,
        platform_name="nt",
    )
    assert roles.current == gui
    assert roles.child == child
    assert roles.console == console


def test_desktop_process_roles_spaces_and_unicode_paths(tmp_path: Path) -> None:
    root = tmp_path / "servonaut desktop bundle åäö 🚀"
    gui, _child, _console, layout = _setup_desktop_bundle_fixture(
        root, current_role=DesktopProcessRole.GUI
    )
    roles = validate_desktop_process_role(
        layout, DesktopProcessRole.GUI, current_executable=gui
    )
    assert roles.current == gui


def test_desktop_process_roles_rejects_non_desktop_or_unfrozen_distributions(
    tmp_path: Path,
) -> None:
    ext = ".exe" if os.name == "nt" else ""
    exe = tmp_path / f"servonaut{ext}"
    exe.write_text("fixture", encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)

    for kind in (
        DistributionKind.SOURCE,
        DistributionKind.PIP,
        DistributionKind.PIPX,
        DistributionKind.FROZEN_CLI,
    ):
        evidence_dict: dict[str, object] = {
            "executable": exe,
            "executable_root": tmp_path,
        }
        if kind is DistributionKind.SOURCE:
            evidence_dict["source_install_path"] = "file:///workspace"
        elif kind is DistributionKind.PIPX:
            evidence_dict["pipx_contains_servonaut"] = True
        elif kind is DistributionKind.FROZEN_CLI:
            evidence_dict["is_frozen"] = True
        layout = resolve_runtime(_evidence(**evidence_dict))
        with pytest.raises(
            RuntimeCapabilityError, match="require a packaged desktop distribution"
        ):
            validate_desktop_process_role(
                layout, DesktopProcessRole.GUI, current_executable=exe
            )

    # Packaged desktop but is_frozen = False
    from dataclasses import replace

    gui, _, _, layout_frozen = _setup_desktop_bundle_fixture(
        tmp_path / "unfrozen", current_role=DesktopProcessRole.GUI
    )
    unfrozen = replace(layout_frozen, is_frozen=False)
    with pytest.raises(RuntimeCapabilityError, match="require a frozen distribution"):
        validate_desktop_process_role(
            unfrozen, DesktopProcessRole.GUI, current_executable=gui
        )


def test_desktop_process_roles_rejects_mismatched_current_executable(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    _gui, _child, _console, layout = _setup_desktop_bundle_fixture(
        root, current_role=DesktopProcessRole.GUI
    )
    ext = ".exe" if os.name == "nt" else ""
    other = root / f"other-exe{ext}"
    other.write_text("other", encoding="utf-8")
    other.chmod(other.stat().st_mode | stat.S_IXUSR)

    with pytest.raises(
        RuntimeCapabilityError, match="Current executable does not match"
    ):
        validate_desktop_process_role(
            layout, DesktopProcessRole.GUI, current_executable=other
        )


def test_desktop_process_roles_rejects_role_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    gui, _child, _console, layout = _setup_desktop_bundle_fixture(
        root, current_role=DesktopProcessRole.GUI
    )

    with pytest.raises(RuntimeCapabilityError, match="does not match expected role"):
        validate_desktop_process_role(
            layout, DesktopProcessRole.CHILD, current_executable=gui
        )
    with pytest.raises(RuntimeCapabilityError, match="does not match expected role"):
        validate_desktop_process_role(
            layout, DesktopProcessRole.CONSOLE, current_executable=gui
        )

    _, _, _, child_layout = _setup_desktop_bundle_fixture(
        tmp_path / "child_b", current_role=DesktopProcessRole.CHILD
    )
    with pytest.raises(RuntimeCapabilityError, match="does not match expected role"):
        validate_desktop_process_role(
            child_layout,
            DesktopProcessRole.GUI,
            current_executable=child_layout.executable,
        )


def test_desktop_process_roles_rejects_invalid_file_properties(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    gui, child, _console, layout = _setup_desktop_bundle_fixture(
        root, current_role=DesktopProcessRole.GUI
    )
    ext = ".exe" if os.name == "nt" else ""

    # Missing file
    gui.unlink()
    with pytest.raises(RuntimeCapabilityError, match="existing regular file"):
        validate_desktop_process_role(
            layout, DesktopProcessRole.GUI, current_executable=gui
        )
    gui.write_text("fixture", encoding="utf-8")
    gui.chmod(gui.stat().st_mode | stat.S_IXUSR)

    # Directory instead of regular file
    dir_exe = root / f"dir_helper{ext}"
    dir_exe.mkdir()
    layout_dir = resolve_runtime(
        _evidence(
            executable=gui,
            executable_root=root,
            is_frozen=True,
            marker=_desktop_marker(
                console_helper=f"servonaut{ext}",
                desktop_child=f"dir_helper{ext}",
            ),
        )
    )
    with pytest.raises(RuntimeCapabilityError, match="directory|regular file"):
        validate_desktop_process_role(
            layout_dir, DesktopProcessRole.GUI, current_executable=gui
        )

    # Final-component symlink
    link_child = root / f"link-child{ext}"
    try:
        link_child.symlink_to(child)
    except OSError:
        pytest.skip("symlinks unavailable")

    layout_link = resolve_runtime(
        _evidence(
            executable=gui,
            executable_root=root,
            is_frozen=True,
            marker=_desktop_marker(
                console_helper=f"servonaut{ext}",
                desktop_child=f"link-child{ext}",
            ),
        )
    )
    with pytest.raises(RuntimeCapabilityError, match="symlink"):
        validate_desktop_process_role(
            layout_link, DesktopProcessRole.GUI, current_executable=gui
        )

    # Intermediate symlink escape
    outside = tmp_path / "outside"
    outside.mkdir()
    escaping_child = outside / f"desktop-child{ext}"
    escaping_child.write_text("outside", encoding="utf-8")
    escaping_child.chmod(escaping_child.stat().st_mode | stat.S_IXUSR)

    esc_link = root / f"escape-link{ext}"
    try:
        esc_link.symlink_to(escaping_child)
    except OSError:
        pytest.skip("symlinks unavailable")

    layout_esc = resolve_runtime(
        _evidence(
            executable=gui,
            executable_root=root,
            is_frozen=True,
            marker=_desktop_marker(
                console_helper=f"servonaut{ext}",
                desktop_child=f"escape-link{ext}",
            ),
        )
    )
    with pytest.raises(RuntimeCapabilityError, match="symlink|executable root"):
        validate_desktop_process_role(
            layout_esc, DesktopProcessRole.GUI, current_executable=gui
        )

    # Non-executable on POSIX
    if os.name != "nt":
        gui.chmod(gui.stat().st_mode & ~stat.S_IXUSR)
        with pytest.raises(RuntimeCapabilityError, match="not executable"):
            validate_desktop_process_role(
                layout, DesktopProcessRole.GUI, current_executable=gui
            )
        gui.chmod(gui.stat().st_mode | stat.S_IXUSR)

    # Suffix not .exe on Windows
    no_ext_root = tmp_path / "bundle_no_ext"
    no_ext_gui = no_ext_root / "servonaut-desktop"
    no_ext_gui.parent.mkdir(parents=True, exist_ok=True)
    no_ext_gui.write_text("no-ext", encoding="utf-8")
    no_ext_gui.chmod(no_ext_gui.stat().st_mode | stat.S_IXUSR)
    layout_no_ext = resolve_runtime(
        _evidence(
            executable=no_ext_gui,
            executable_root=no_ext_root,
            resource_root=no_ext_root / "_internal",
            is_frozen=True,
            marker=_desktop_marker(
                console_helper="servonaut",
                desktop_child="servonaut-desktop-child",
            ),
        )
    )
    with pytest.raises(RuntimeCapabilityError, match="native Windows .exe"):
        validate_desktop_process_role(
            layout_no_ext,
            DesktopProcessRole.GUI,
            current_executable=no_ext_gui,
            platform_name="nt",
        )


def test_desktop_process_roles_rejects_pairwise_hardlinks(tmp_path: Path) -> None:
    root = tmp_path / "hardlink_bundle"
    gui, child, _console, _ = _setup_desktop_bundle_fixture(
        root, current_role=DesktopProcessRole.GUI
    )

    ext = ".exe" if os.name == "nt" else ""
    hl_console = root / f"servonaut{ext}"
    hl_console.unlink()
    try:
        hl_console.hardlink_to(child)
    except OSError:
        pytest.skip("hardlinks unavailable")

    layout_same = resolve_runtime(
        _evidence(
            executable=gui,
            executable_root=root,
            is_frozen=True,
            marker=_desktop_marker(
                console_helper=f"servonaut{ext}",
                desktop_child=f"servonaut-desktop-child{ext}",
            ),
        )
    )
    with pytest.raises(RuntimeCapabilityError, match="distinct files"):
        validate_desktop_process_role(
            layout_same, DesktopProcessRole.GUI, current_executable=gui
        )


def test_desktop_role_errors_are_path_free(tmp_path: Path) -> None:
    root = tmp_path / "bundle_path_free"
    gui, _child, _console, layout = _setup_desktop_bundle_fixture(
        root, current_role=DesktopProcessRole.GUI
    )
    gui.unlink()

    with pytest.raises(RuntimeCapabilityError) as exc_info:
        validate_desktop_process_role(
            layout, DesktopProcessRole.GUI, current_executable=gui
        )
    assert str(root) not in str(exc_info.value)
    assert str(gui) not in str(exc_info.value)


def test_desktop_child_argv_composition_and_validation(tmp_path: Path) -> None:
    root = tmp_path / "child_argv_bundle"
    gui, child, _console, layout = _setup_desktop_bundle_fixture(
        root, current_role=DesktopProcessRole.GUI
    )

    # Pure composition
    argv = layout.desktop_child_argv("--flag", "with space", "unicode-å")
    validated = validate_desktop_child_argv(
        argv, runtime=layout, launcher_executable=gui
    )
    assert validated == (str(child), "--flag", "with space", "unicode-å")

    # Rejection if launcher does not match runtime executable
    with pytest.raises(
        RuntimeCapabilityError, match="Current executable does not match"
    ):
        validate_desktop_child_argv(argv, runtime=layout, launcher_executable=child)

    # Rejection if runtime layout is child process (role mismatch)
    _, child_exe, _, child_layout = _setup_desktop_bundle_fixture(
        tmp_path / "child_layout_dir", current_role=DesktopProcessRole.CHILD
    )
    with pytest.raises(RuntimeCapabilityError, match="does not match expected role"):
        validate_desktop_child_argv(
            argv, runtime=child_layout, launcher_executable=child_exe
        )

    # Empty argv
    with pytest.raises(RuntimeCapabilityError, match="empty"):
        validate_desktop_child_argv([], runtime=layout, launcher_executable=gui)

    # Rejection of relative or alternate spelling
    ext = ".exe" if os.name == "nt" else ""
    rel_argv = [f"servonaut-desktop-child{ext}", "--flag"]
    with pytest.raises(RuntimeCapabilityError, match="marked child path"):
        validate_desktop_child_argv(rel_argv, runtime=layout, launcher_executable=gui)


def test_packaged_desktop_console_process_validates_own_argv(tmp_path: Path) -> None:
    root = tmp_path / "console_validates_bundle"
    gui, child, console, layout = _setup_desktop_bundle_fixture(
        root, current_role=DesktopProcessRole.CONSOLE
    )

    app_argv = layout.current_app_argv()
    assert app_argv == [str(console)]
    validated_app = validate_launch_argv(app_argv, runtime=layout)
    assert validated_app == [str(console)]

    mcp_argv = layout.mcp_argv()
    assert mcp_argv == [str(console), "--mcp"]
    validated_mcp = validate_launch_argv(mcp_argv, runtime=layout)
    assert validated_mcp == [str(console), "--mcp"]

    # Passing GUI or child as console command is rejected
    with pytest.raises(RuntimeCapabilityError, match="identify the console helper"):
        validate_launch_argv([str(gui)], runtime=layout)
    with pytest.raises(RuntimeCapabilityError, match="desktop child helper"):
        validate_launch_argv([str(child)], runtime=layout)

    # Arbitrary in-bundle binary is rejected
    ext = ".exe" if os.name == "nt" else ""
    arbitrary = root / f"arbitrary{ext}"
    arbitrary.write_text("bin", encoding="utf-8")
    arbitrary.chmod(arbitrary.stat().st_mode | stat.S_IXUSR)
    with pytest.raises(RuntimeCapabilityError, match="identify the console helper"):
        validate_launch_argv([str(arbitrary)], runtime=layout)
