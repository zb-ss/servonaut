"""Contract tests for desktop payload build request, spec, and build engine."""

from __future__ import annotations

import ast
import importlib
import importlib.metadata
import json
import runpy
import sys
from pathlib import Path
from typing import ClassVar

import pytest

from scripts.desktop_shell.model import (
    DesktopBuildRequest,
    DesktopPolicyValidationError,
    DesktopTargetSpec,
    load_desktop_target_spec,
    validate_desktop_build_request,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POLICY_PATH = _REPO_ROOT / "packaging" / "desktop_shell" / "target-policy.json"
_SPEC_PATH = _REPO_ROOT / "packaging" / "desktop_shell" / "servonaut_desktop.spec"
_ENTRIES_DIR = _REPO_ROOT / "packaging" / "desktop_shell" / "entries"


@pytest.fixture
def sample_target_spec() -> DesktopTargetSpec:
    return load_desktop_target_spec(_POLICY_PATH, "linux-x64-ubuntu-22.04")


def test_desktop_build_request_fields(
    sample_target_spec: DesktopTargetSpec, tmp_path: Path
) -> None:
    wheel = tmp_path / "servonaut-2.26.3-py3-none-any.whl"
    wheel.write_bytes(b"dummy")

    req = DesktopBuildRequest(
        wheel=wheel,
        target=sample_target_spec,
        product_version="2.26.3",
        build_revision="rev1",
        source_commit="commit1",
        output_dir=tmp_path / "out",
        require_artifact_selftest=True,
    )
    assert req.wheel == wheel
    assert req.target == sample_target_spec
    assert req.product_version == "2.26.3"
    assert req.build_revision == "rev1"
    assert req.source_commit == "commit1"
    assert req.output_dir == tmp_path / "out"
    assert req.require_artifact_selftest is True


def test_validate_desktop_build_request_rejects_non_file(
    sample_target_spec: DesktopTargetSpec, tmp_path: Path
) -> None:
    req = DesktopBuildRequest(
        wheel=tmp_path / "nonexistent.whl",
        target=sample_target_spec,
        product_version="2.26.3",
        build_revision="rev1",
        source_commit="commit1",
        output_dir=tmp_path / "out",
    )
    with pytest.raises(DesktopPolicyValidationError, match="wheel file not found"):
        validate_desktop_build_request(req)


def test_validate_desktop_build_request_rejects_non_absolute_output(
    sample_target_spec: DesktopTargetSpec, tmp_path: Path
) -> None:
    wheel = tmp_path / "servonaut-2.26.3-py3-none-any.whl"
    # Create valid zip with METADATA
    import zipfile

    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(
            "servonaut-2.26.3.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: servonaut\nVersion: 2.26.3\n",
        )

    req = DesktopBuildRequest(
        wheel=wheel,
        target=sample_target_spec,
        product_version="2.26.3",
        build_revision="rev1",
        source_commit="commit1",
        output_dir=Path("relative/out"),
    )
    with pytest.raises(
        DesktopPolicyValidationError, match="output_dir must be an absolute path"
    ):
        validate_desktop_build_request(req)


def test_validate_desktop_build_request_rejects_version_mismatch(
    sample_target_spec: DesktopTargetSpec, tmp_path: Path
) -> None:
    wheel = tmp_path / "servonaut-2.26.3-py3-none-any.whl"
    import zipfile

    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(
            "servonaut-2.26.3.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: servonaut\nVersion: 2.26.3\n",
        )

    req = DesktopBuildRequest(
        wheel=wheel,
        target=sample_target_spec,
        product_version="2.26.4",  # Mismatch
        build_revision="rev1",
        source_commit="commit1",
        output_dir=tmp_path / "out",
    )
    with pytest.raises(
        DesktopPolicyValidationError, match="does not match product version"
    ):
        validate_desktop_build_request(req)


def test_desktop_entries_exist_and_are_valid_python() -> None:
    gui_entry = _ENTRIES_DIR / "servonaut_desktop.py"
    child_entry = _ENTRIES_DIR / "servonaut_desktop_child.py"

    assert gui_entry.is_file()
    assert child_entry.is_file()

    # Verify syntax parses cleanly
    ast.parse(gui_entry.read_text(encoding="utf-8"))
    ast.parse(child_entry.read_text(encoding="utf-8"))


def test_servonaut_desktop_spec_parses_cleanly() -> None:
    assert _SPEC_PATH.is_file()
    source = _SPEC_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert tree is not None




class _MockAnalysis:
    instances: ClassVar[list[_MockAnalysis]] = []

    def __init__(self, scripts: list[str], **kwargs: object) -> None:
        self.scripts = scripts
        self.kwargs = kwargs
        self.pure: list[object] = []
        self.binaries: list[object] = []
        self.datas: list[object] = [
            ("servonaut-2.26.3.dist-info/METADATA", "/wheel/METADATA", "DATA"),
            (
                "servonaut-2.26.3.dist-info/direct_url.json",
                "/wheel/direct_url.json",
                "DATA",
            ),
        ]
        self.__class__.instances.append(self)


class _MockPYZ:
    def __init__(self, pure: list[object]) -> None:
        self.pure = pure


class _MockEXE:
    instances: ClassVar[list[_MockEXE]] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.args = args
        self.kwargs = kwargs
        self.__class__.instances.append(self)


class _MockCOLLECT:
    instances: ClassVar[list[_MockCOLLECT]] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.args = args
        self.kwargs = kwargs
        self.__class__.instances.append(self)


@pytest.fixture
def spec_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """Stage a minimal, valid spec environment with builder-staged notices."""
    hooks = pytest.importorskip("PyInstaller.utils.hooks")
    monkeypatch.setattr(hooks, "copy_metadata", lambda name: [])
    for mock in (_MockAnalysis, _MockEXE, _MockCOLLECT):
        mock.instances.clear()

    site_packages = tmp_path / "site-packages"
    servonaut_pkg = site_packages / "servonaut"
    servonaut_pkg.mkdir(parents=True)
    (servonaut_pkg / "__init__.py").write_text("__version__ = '2.26.3'\n")
    dist_info = site_packages / "servonaut-2.26.3.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: servonaut\nVersion: 2.26.3\n"
    )

    frontend_dir = tmp_path / "frontend"
    frontend_dir.mkdir()
    (frontend_dir / "index.html").write_text("<html></html>")

    metadata_dir = tmp_path / "build-metadata"
    runtime_notice = metadata_dir / "runtime-notice" / "CPython-LICENSE.txt"
    runtime_notice.parent.mkdir(parents=True)
    runtime_notice.write_text("Python license\n")
    notices_root = metadata_dir / "third-party-notices"
    notices_root.mkdir()
    (notices_root / "example-LICENSE.txt").write_text("Example license\n")

    output_dir = tmp_path / "dist"
    output_dir.mkdir()

    profile_path = tmp_path / "profile.json"
    profile_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target_name": "linux-x64-ubuntu-22.04",
                "target_platform": "linux",
                "target_architecture": "x86_64",
                "python_version": "3.12",
                "payload_name": "servonaut-desktop",
                "product_version": "2.26.3",
                "excluded_modules": ["readline"],
                "hook_directory": str(
                    (_REPO_ROOT / "packaging" / "desktop_shell" / "hooks").resolve()
                ),
                "require_artifact_selftest": False,
            }
        )
    )
    cli_entry = tmp_path / "cli.py"
    cli_entry.write_text("print('cli')")

    paths = {
        "SERVONAUT_DESKTOP_GUI_ENTRY_SCRIPT": _ENTRIES_DIR / "servonaut_desktop.py",
        "SERVONAUT_DESKTOP_CHILD_ENTRY_SCRIPT": _ENTRIES_DIR
        / "servonaut_desktop_child.py",
        "SERVONAUT_DESKTOP_CLI_ENTRY_SCRIPT": cli_entry,
        "SERVONAUT_DESKTOP_ISOLATED_SITE_PACKAGES": site_packages,
        "SERVONAUT_DESKTOP_PROFILE_PATH": profile_path,
        "SERVONAUT_DESKTOP_OUTPUT_DIR": output_dir,
        "SERVONAUT_DESKTOP_BUILD_METADATA_DIR": metadata_dir,
        "SERVONAUT_DESKTOP_FRONTEND_DIR": frontend_dir,
        "SERVONAUT_DESKTOP_RUNTIME_NOTICE_SOURCE": runtime_notice,
        "SERVONAUT_DESKTOP_THIRD_PARTY_NOTICES_ROOT": notices_root,
    }
    for key, value in paths.items():
        monkeypatch.setenv(key, str(value.resolve()))
    monkeypatch.setenv("SERVONAUT_DESKTOP_REQUIRE_ARTIFACT_SELFTEST", "0")

    monkeypatch.syspath_prepend(str(site_packages))
    monkeypatch.delitem(sys.modules, "servonaut", raising=False)
    importlib.invalidate_caches()
    return {key: value.resolve() for key, value in paths.items()}


def _run_spec() -> dict[str, object]:
    return runpy.run_path(
        str(_SPEC_PATH),
        init_globals={
            "Analysis": _MockAnalysis,
            "PYZ": _MockPYZ,
            "EXE": _MockEXE,
            "COLLECT": _MockCOLLECT,
            "SPECPATH": str(_SPEC_PATH.parent),
        },
    )


def test_desktop_spec_execution_builds_three_executables(
    spec_environment: dict[str, Path],
) -> None:
    _run_spec()

    # Analyses are created in the executable-role order the builder relies on
    # when it persists each Analysis/PYZ TOC.
    assert [Path(a.scripts[0]).name for a in _MockAnalysis.instances] == [
        "servonaut_desktop.py",
        "servonaut_desktop_child.py",
        "cli.py",
    ]
    exe_names = {exe.kwargs.get("name") for exe in _MockEXE.instances}
    assert exe_names == {"servonaut-desktop", "servonaut-desktop-child", "servonaut"}
    gui_exe = next(
        e for e in _MockEXE.instances if e.kwargs.get("name") == "servonaut-desktop"
    )
    assert gui_exe.kwargs.get("console") is False
    assert len(_MockCOLLECT.instances) == 1
    assert _MockCOLLECT.instances[0].kwargs.get("name") == "servonaut-desktop"


def test_desktop_spec_collects_staged_notices(
    spec_environment: dict[str, Path],
) -> None:
    _run_spec()

    datas = _MockAnalysis.instances[0].kwargs["datas"]
    notices = {Path(source).name for source, destination in datas if destination == "notices"}
    assert notices == {"CPython-LICENSE.txt", "example-LICENSE.txt"}


@pytest.mark.parametrize(
    "missing",
    [
        "SERVONAUT_DESKTOP_RUNTIME_NOTICE_SOURCE",
        "SERVONAUT_DESKTOP_THIRD_PARTY_NOTICES_ROOT",
    ],
)
def test_desktop_spec_requires_notice_environment(
    spec_environment: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    missing: str,
) -> None:
    monkeypatch.delenv(missing)

    with pytest.raises(SystemExit) as raised:
        _run_spec()

    assert raised.value.code == 64
    assert missing in capsys.readouterr().err


def test_desktop_spec_rejects_notice_outside_build_metadata(
    spec_environment: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    stray = tmp_path / "stray-LICENSE.txt"
    stray.write_text("not staged\n")
    monkeypatch.setenv("SERVONAUT_DESKTOP_RUNTIME_NOTICE_SOURCE", str(stray))

    with pytest.raises(SystemExit) as raised:
        _run_spec()

    assert raised.value.code == 64
    assert "staged notice location" in capsys.readouterr().err


def test_desktop_spec_reports_missing_runtime_metadata(
    spec_environment: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import PyInstaller.utils.hooks as hooks

    def missing_distribution(name: str) -> list[object]:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(hooks, "copy_metadata", missing_distribution)

    with pytest.raises(SystemExit) as raised:
        _run_spec()

    assert raised.value.code == 64 + 16
    assert "runtime metadata for servonaut is not installed" in capsys.readouterr().err


def test_desktop_spec_diagnostics_leave_interrupts_alone(
    spec_environment: dict[str, Path],
) -> None:
    spec_globals = _run_spec()
    run_phase = spec_globals["_run_diagnostic_phase"]

    def interrupted() -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        run_phase(0, interrupted)


def _spec_hidden_imports() -> list[str]:
    tree = ast.parse(_SPEC_PATH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "hidden_imports"
                for target in node.targets
            )
            and isinstance(node.value, ast.List)
        ):
            return [element.value for element in node.value.elts]
    raise AssertionError("spec declares no hidden_imports list")


def test_desktop_spec_hidden_imports_name_existing_servonaut_modules() -> None:
    """A removed application module must not linger as a hidden import."""
    source_root = _REPO_ROOT / "src"
    for module in _spec_hidden_imports():
        if not module.startswith("servonaut."):
            continue
        relative = Path(*module.split("."))
        assert (source_root / relative.with_suffix(".py")).is_file() or (
            source_root / relative / "__init__.py"
        ).is_file(), module
    assert "servonaut.desktop.dialogs" not in _spec_hidden_imports()
