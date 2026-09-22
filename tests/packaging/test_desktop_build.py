"""Contract tests for desktop payload build request, spec, and build engine."""

from __future__ import annotations

import ast
import importlib
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


def test_desktop_spec_execution_builds_three_executables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("PyInstaller")
    _MockAnalysis.instances.clear()
    _MockEXE.instances.clear()
    _MockCOLLECT.instances.clear()

    # Create dummy environment
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    servonaut_pkg = site_packages / "servonaut"
    servonaut_pkg.mkdir()
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
    metadata_dir.mkdir()

    output_dir = tmp_path / "dist"
    output_dir.mkdir()

    profile_path = tmp_path / "profile.json"
    profile_data = {
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
    profile_path.write_text(json.dumps(profile_data))

    gui_entry = _ENTRIES_DIR / "servonaut_desktop.py"
    child_entry = _ENTRIES_DIR / "servonaut_desktop_child.py"
    cli_entry = tmp_path / "cli.py"
    cli_entry.write_text("print('cli')")

    env = {
        "SERVONAUT_DESKTOP_GUI_ENTRY_SCRIPT": str(gui_entry.resolve()),
        "SERVONAUT_DESKTOP_CHILD_ENTRY_SCRIPT": str(child_entry.resolve()),
        "SERVONAUT_DESKTOP_CLI_ENTRY_SCRIPT": str(cli_entry.resolve()),
        "SERVONAUT_DESKTOP_ISOLATED_SITE_PACKAGES": str(site_packages.resolve()),
        "SERVONAUT_DESKTOP_PROFILE_PATH": str(profile_path.resolve()),
        "SERVONAUT_DESKTOP_OUTPUT_DIR": str(output_dir.resolve()),
        "SERVONAUT_DESKTOP_BUILD_METADATA_DIR": str(metadata_dir.resolve()),
        "SERVONAUT_DESKTOP_FRONTEND_DIR": str(frontend_dir.resolve()),
        "SERVONAUT_DESKTOP_REQUIRE_ARTIFACT_SELFTEST": "0",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    monkeypatch.syspath_prepend(str(site_packages))
    monkeypatch.delitem(sys.modules, "servonaut", raising=False)
    importlib.invalidate_caches()

    globals_dict = {
        "Analysis": _MockAnalysis,
        "PYZ": _MockPYZ,
        "EXE": _MockEXE,
        "COLLECT": _MockCOLLECT,
        "SPECPATH": str(_SPEC_PATH.parent),
    }

    # Execute spec file in mocked context
    runpy.run_path(str(_SPEC_PATH), init_globals=globals_dict)

    # Assert 3 analysis calls
    assert len(_MockAnalysis.instances) == 3
    # Assert 3 executables
    assert len(_MockEXE.instances) == 3
    exe_names = {exe.kwargs.get("name") for exe in _MockEXE.instances}
    assert exe_names == {"servonaut-desktop", "servonaut-desktop-child", "servonaut"}

    # Assert console=False on GUI exe
    gui_exe = next(
        e for e in _MockEXE.instances if e.kwargs.get("name") == "servonaut-desktop"
    )
    assert gui_exe.kwargs.get("console") is False

    # Assert 1 COLLECT with name "servonaut-desktop"
    assert len(_MockCOLLECT.instances) == 1
    assert _MockCOLLECT.instances[0].kwargs.get("name") == "servonaut-desktop"
