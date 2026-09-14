"""Contract tests for the wheel-only standalone PyInstaller specification."""

from __future__ import annotations

import importlib
import json
import os
import runpy
import sys
from pathlib import Path
from types import ModuleType
from typing import ClassVar

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_SPEC_PATH = _REPOSITORY_ROOT / "packaging" / "standalone_cli" / "servonaut_cli.spec"
_HOOK_DIRECTORY = _SPEC_PATH.parent / "hooks"


class _Analysis:
    instances: ClassVar[list[_Analysis]] = []

    def __init__(self, scripts: list[str], **kwargs: object) -> None:
        self.scripts = scripts
        self.kwargs = kwargs
        self.pure: list[object] = []
        self.binaries: list[object] = []
        self.datas: list[object] = [
            ("servonaut-2.26.2.dist-info/METADATA", "/wheel/METADATA", "DATA"),
            ("servonaut-2.26.2.dist-info/RECORD", "/wheel/RECORD", "DATA"),
            (
                "servonaut-2.26.2.dist-info/licenses/LICENSE",
                "/wheel/LICENSE",
                "DATA",
            ),
            (
                "servonaut-2.26.2.dist-info/direct_url.json",
                "/wheel/direct_url.json",
                "DATA",
            ),
        ]
        self.__class__.instances.append(self)


class _PYZ:
    def __init__(self, pure: list[object]) -> None:
        self.pure = pure


class _EXE:
    instances: ClassVar[list[_EXE]] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.args = args
        self.kwargs = kwargs
        self.__class__.instances.append(self)


class _COLLECT:
    instances: ClassVar[list[_COLLECT]] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.args = args
        self.kwargs = kwargs
        self.__class__.instances.append(self)


def _reset_fake_pyinstaller() -> None:
    _Analysis.instances.clear()
    _EXE.instances.clear()
    _COLLECT.instances.clear()


def _write_isolated_wheel_site(
    tmp_path: Path, *, selftest: bool = False
) -> tuple[Path, Path]:
    venv_root = tmp_path / "venv"
    site_packages = venv_root / "lib" / "python3.12" / "site-packages"
    package = site_packages / "servonaut"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("__version__ = '2.26.2'\n", encoding="utf-8")
    if selftest:
        (package / "_artifact_selftest.py").write_text(
            "def main(argv): return 0\n", encoding="utf-8"
        )
    metadata = site_packages / "servonaut-2.26.2.dist-info"
    metadata.mkdir()
    (metadata / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: servonaut\nVersion: 2.26.2\n",
        encoding="utf-8",
    )
    shim = venv_root / "bin" / "servonaut_shim.py"
    shim.parent.mkdir()
    shim.write_text("from servonaut.main import main\nmain()\n", encoding="utf-8")
    return site_packages, shim


def _configure_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    selftest: bool = False,
) -> tuple[Path, Path]:
    for name in tuple(os.environ):
        if name.startswith("SERVONAUT_STANDALONE_"):
            monkeypatch.delenv(name)
    site_packages, shim = _write_isolated_wheel_site(tmp_path, selftest=selftest)
    output_dir = tmp_path / "output" / "dist"
    metadata_dir = tmp_path / "output" / "build-metadata"
    output_dir.mkdir(parents=True)
    metadata_dir.mkdir()
    profile = {
        "schema_version": 1,
        "target_name": "linux-x64-ubuntu-22.04",
        "target_platform": "linux",
        "target_architecture": "x86_64",
        "python_version": "3.12",
        "payload_name": "servonaut",
        "product_version": "2.26.2",
        "excluded_modules": ["readline", "sounddevice"],
        "hook_directory": str(_HOOK_DIRECTORY.resolve()),
        "require_artifact_selftest": selftest,
    }
    profile_path = tmp_path / "resolved-profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    monkeypatch.setenv("SERVONAUT_STANDALONE_ENTRY_SCRIPT", str(shim.resolve()))
    monkeypatch.setenv(
        "SERVONAUT_STANDALONE_ISOLATED_SITE_PACKAGES", str(site_packages.resolve())
    )
    monkeypatch.setenv("SERVONAUT_STANDALONE_PROFILE_PATH", str(profile_path.resolve()))
    monkeypatch.setenv("SERVONAUT_STANDALONE_OUTPUT_DIR", str(output_dir.resolve()))
    monkeypatch.setenv(
        "SERVONAUT_STANDALONE_BUILD_METADATA_DIR", str(metadata_dir.resolve())
    )
    monkeypatch.setenv(
        "SERVONAUT_STANDALONE_REQUIRE_ARTIFACT_SELFTEST", "1" if selftest else "0"
    )
    monkeypatch.syspath_prepend(str(site_packages))
    monkeypatch.setattr(sys, "version_info", (3, 12, 0, "final", 0))
    monkeypatch.delitem(sys.modules, "servonaut", raising=False)
    importlib.invalidate_caches()
    return output_dir, site_packages


def _execute_spec(output_dir: Path) -> dict[str, object]:
    _reset_fake_pyinstaller()
    pyinstaller = ModuleType("PyInstaller")
    utils = ModuleType("PyInstaller.utils")
    hooks = ModuleType("PyInstaller.utils.hooks")
    hooks.copy_metadata = lambda name: [
        (f"/wheel/{name}-1.0.dist-info", f"{name}-1.0.dist-info")
    ]
    pyinstaller.utils = utils
    utils.hooks = hooks
    modules = {
        "PyInstaller": pyinstaller,
        "PyInstaller.utils": utils,
        "PyInstaller.utils.hooks": hooks,
    }
    previous = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    try:
        return runpy.run_path(
            str(_SPEC_PATH),
            init_globals={
                "Analysis": _Analysis,
                "PYZ": _PYZ,
                "EXE": _EXE,
                "COLLECT": _COLLECT,
                "DISTPATH": str(output_dir),
                "SPECPATH": str(_SPEC_PATH.parent),
            },
        )
    finally:
        for name, module in previous.items():
            if module is None:
                del sys.modules[name]
            else:
                sys.modules[name] = module


def _execute_mcp_hook() -> tuple[dict[str, object], list[tuple[str, object]]]:
    calls: list[tuple[str, object]] = []
    pyinstaller = ModuleType("PyInstaller")
    utils = ModuleType("PyInstaller.utils")
    hooks = ModuleType("PyInstaller.utils.hooks")

    def collect_submodules(package: str) -> list[str]:
        calls.append(("submodules", package))
        return ["mcp.server.stdio"]

    def collect_data_files(
        package: str, *, includes: list[str]
    ) -> list[tuple[str, str]]:
        calls.append(("data", (package, includes)))
        return [("/wheel/syntax_rfc3987.lark", "rfc3987_syntax")]

    hooks.collect_submodules = collect_submodules
    hooks.collect_data_files = collect_data_files
    pyinstaller.utils = utils
    utils.hooks = hooks
    modules = {
        "PyInstaller": pyinstaller,
        "PyInstaller.utils": utils,
        "PyInstaller.utils.hooks": hooks,
    }
    previous = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    try:
        namespace = runpy.run_path(str(_HOOK_DIRECTORY / "hook-mcp.py"))
    finally:
        for name, module in previous.items():
            if module is None:
                del sys.modules[name]
            else:
                sys.modules[name] = module
    return namespace, calls


def _execute_servonaut_hook() -> tuple[dict[str, object], list[tuple[str, object]]]:
    calls: list[tuple[str, object]] = []
    pyinstaller = ModuleType("PyInstaller")
    utils = ModuleType("PyInstaller.utils")
    hooks = ModuleType("PyInstaller.utils.hooks")

    def collect_submodules(package: str) -> list[str]:
        calls.append(("submodules", package))
        return [
            "servonaut.screens.settings.panels.general",
            "servonaut.screens.settings.panels.voice",
        ]

    def collect_data_files(
        package: str, *, includes: list[str]
    ) -> list[tuple[str, str]]:
        calls.append(("data", (package, includes)))
        return [("/wheel/memory_screen.tcss", "servonaut")]

    hooks.collect_submodules = collect_submodules
    hooks.collect_data_files = collect_data_files
    pyinstaller.utils = utils
    utils.hooks = hooks
    modules = {
        "PyInstaller": pyinstaller,
        "PyInstaller.utils": utils,
        "PyInstaller.utils.hooks": hooks,
    }
    previous = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    try:
        namespace = runpy.run_path(str(_HOOK_DIRECTORY / "hook-servonaut.py"))
    finally:
        for name, module in previous.items():
            if module is None:
                del sys.modules[name]
            else:
                sys.modules[name] = module
    return namespace, calls


def test_spec_executes_against_an_installed_wheel_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir, site_packages = _configure_environment(monkeypatch, tmp_path)

    namespace = _execute_spec(output_dir)

    assert namespace["PRODUCT_VERSION"] == "2.26.2"
    analysis = _Analysis.instances.pop()
    assert analysis.scripts[0].endswith("venv/bin/servonaut_shim.py")
    assert analysis.kwargs["pathex"] == []
    assert "readline" in analysis.kwargs["excludes"]
    assert "servonaut._artifact_selftest" not in analysis.kwargs["hiddenimports"]
    assert str(_REPOSITORY_ROOT / "src") not in analysis.kwargs["pathex"]
    assert (site_packages / "servonaut").is_dir()
    assert set(namespace["_RUNTIME_METADATA_DISTRIBUTIONS"]) == {
        "servonaut",
        "mcp",
        "ovh",
        "hcloud",
        "boto3",
        "botocore",
        "cryptography",
        "PyNaCl",
        "bcrypt",
        "keyring",
        "certifi",
    }
    assert len(analysis.kwargs["datas"]) >= len(
        namespace["_RUNTIME_METADATA_DISTRIBUTIONS"]
    )
    collected_data = _COLLECT.instances[-1].args[2]
    destinations = {entry[0] for entry in collected_data}
    assert "servonaut-2.26.2.dist-info/direct_url.json" not in destinations
    assert {
        "servonaut-2.26.2.dist-info/METADATA",
        "servonaut-2.26.2.dist-info/RECORD",
        "servonaut-2.26.2.dist-info/licenses/LICENSE",
    } <= destinations
    assert _EXE.instances.pop().kwargs["name"] == "servonaut"
    assert _COLLECT.instances.pop().kwargs["name"] == "servonaut"


def test_spec_requires_the_conditional_selftest_from_the_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir, _site_packages = _configure_environment(
        monkeypatch, tmp_path, selftest=False
    )
    monkeypatch.setenv("SERVONAUT_STANDALONE_REQUIRE_ARTIFACT_SELFTEST", "1")
    profile_path = Path(os.environ["SERVONAUT_STANDALONE_PROFILE_PATH"])
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    profile["require_artifact_selftest"] = True
    profile_path.write_text(json.dumps(profile), encoding="utf-8")

    with pytest.raises(RuntimeError, match="_artifact_selftest"):
        _execute_spec(output_dir)


def test_spec_adds_the_conditional_selftest_only_when_requested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir, _site_packages = _configure_environment(
        monkeypatch, tmp_path, selftest=True
    )

    _execute_spec(output_dir)

    assert (
        "servonaut._artifact_selftest"
        in _Analysis.instances.pop().kwargs["hiddenimports"]
    )


def test_spec_rejects_an_unknown_standalone_environment_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir, _site_packages = _configure_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("SERVONAUT_STANDALONE_UNTRUSTED", "value")

    with pytest.raises(RuntimeError, match="unexpected standalone environment"):
        _execute_spec(output_dir)


def test_spec_and_hooks_are_narrow_and_console_onedir_only() -> None:
    spec = _SPEC_PATH.read_text(encoding="utf-8")

    assert "collect_all(" not in spec
    assert 'name="servonaut"' in spec
    assert "console=True" in spec
    assert "pathex=[]" in spec
    assert "readline" in spec
    assert "SERVONAUT_STANDALONE_REQUIRE_ARTIFACT_SELFTEST" in spec
    assert "*.pyc" not in spec

    hooks = {
        path.name: path.read_text(encoding="utf-8")
        for path in _HOOK_DIRECTORY.glob("*.py")
    }
    assert (
        "hook-textual.py" in hooks and "collect_data_files" in hooks["hook-textual.py"]
    )
    assert "hook-boto3.py" in hooks and "botocore.session" in hooks["hook-boto3.py"]
    assert "hook-botocore.py" in hooks and "botocore.data" in hooks["hook-botocore.py"]
    assert "hook-certifi.py" in hooks and "*.pem" in hooks["hook-certifi.py"]
    assert {"hook-nacl.py"} <= hooks.keys()
    assert {"hook-mcp.py", "hook-ovh.py", "hook-hcloud.py"} <= hooks.keys()
    assert "*.css" in hooks["hook-servonaut.py"]
    assert "*.tcss" in hooks["hook-servonaut.py"]
    assert "data/*.txt" in hooks["hook-servonaut.py"]
    assert (_REPOSITORY_ROOT / "src" / "servonaut" / "memory_screen.tcss").is_file()
    assert (
        _REPOSITORY_ROOT / "src" / "servonaut" / "data" / "chat_system_prompt.txt"
    ).is_file()


def test_mcp_hook_collects_only_the_installed_fallback_grammar() -> None:
    namespace, calls = _execute_mcp_hook()

    assert namespace["hiddenimports"] == ["mcp.server.stdio", "rfc3987_syntax"]
    assert namespace["datas"] == [("/wheel/syntax_rfc3987.lark", "rfc3987_syntax")]
    assert calls == [
        ("submodules", "mcp.server"),
        ("data", ("rfc3987_syntax", ["syntax_rfc3987.lark"])),
    ]
    assert "rfc3987" not in namespace["hiddenimports"]


def test_servonaut_hook_collects_only_dynamic_settings_panels() -> None:
    namespace, calls = _execute_servonaut_hook()

    assert namespace["datas"] == [("/wheel/memory_screen.tcss", "servonaut")]
    assert namespace["hiddenimports"] == [
        "servonaut.screens.settings.panels.general",
        "servonaut.screens.settings.panels.voice",
    ]
    assert calls == [
        (
            "data",
            ("servonaut", ["*.css", "*.tcss", "styles/**/*.tcss", "data/*.txt"]),
        ),
        ("submodules", "servonaut.screens.settings.panels"),
    ]
    assert all(
        not module.startswith("servonaut.services.voice")
        for module in namespace["hiddenimports"]
    )
