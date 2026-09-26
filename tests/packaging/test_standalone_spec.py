"""Contract tests for the wheel-only standalone PyInstaller specification."""

from __future__ import annotations

import errno
import importlib
import json
import os
import runpy
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import ClassVar

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_SPEC_PATH = _REPOSITORY_ROOT / "packaging" / "standalone_cli" / "servonaut_cli.spec"
_HOOK_DIRECTORY = _SPEC_PATH.parent / "hooks"


def _write_embedded_notice_staging(
    metadata_dir: Path, config_root: Path = _SPEC_PATH.parent
) -> Path:
    raw = json.loads(
        (config_root / "embedded-notices.json").read_text(encoding="utf-8")
    )
    root = metadata_dir / "third-party-notices"
    root.mkdir()
    for index, row in enumerate(raw["notices"]):
        filename = Path(row["payload_path"]).name
        (root / filename).write_bytes(f"notice {index}\n".encode())
    return root


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
    excluded_modules: tuple[str, ...] = ("readline", "sounddevice"),
) -> tuple[Path, Path]:
    for name in tuple(os.environ):
        if name.startswith("SERVONAUT_STANDALONE_"):
            monkeypatch.delenv(name)
    site_packages, shim = _write_isolated_wheel_site(tmp_path, selftest=selftest)
    output_dir = tmp_path / "output" / "dist"
    metadata_dir = tmp_path / "output" / "build-metadata"
    output_dir.mkdir(parents=True)
    metadata_dir.mkdir()
    runtime_notice = metadata_dir / "runtime-notice" / "CPython-LICENSE.txt"
    runtime_notice.parent.mkdir()
    runtime_notice.write_bytes(b"CPython notice fixture\n")
    embedded_notices = _write_embedded_notice_staging(metadata_dir)
    profile = {
        "schema_version": 1,
        "target_name": "linux-x64-ubuntu-22.04",
        "target_platform": "linux",
        "target_architecture": "x86_64",
        "python_version": "3.12",
        "payload_name": "servonaut",
        "product_version": "2.26.2",
        "excluded_modules": list(excluded_modules),
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
        "SERVONAUT_STANDALONE_RUNTIME_NOTICE_SOURCE", str(runtime_notice.resolve())
    )
    monkeypatch.setenv(
        "SERVONAUT_STANDALONE_THIRD_PARTY_NOTICES_ROOT",
        str(embedded_notices.resolve()),
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
    assert (str(namespace["RUNTIME_NOTICE_SOURCE"]), "notices") in analysis.kwargs[
        "datas"
    ]
    assert {
        (str(source), "notices") for source in namespace["EMBEDDED_NOTICE_SOURCES"]
    } <= set(analysis.kwargs["datas"])
    assert len(namespace["EMBEDDED_NOTICE_SOURCES"]) == 5
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


def test_spec_excludes_every_module_the_resolved_profile_forbids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forbidden = ("readline", "sounddevice", "servonaut.desktop")
    output_dir, _ = _configure_environment(
        monkeypatch, tmp_path, excluded_modules=forbidden
    )

    _execute_spec(output_dir)

    analysis = _Analysis.instances.pop()
    assert set(forbidden) <= set(analysis.kwargs["excludes"])


def test_spec_rejects_a_substituted_runtime_notice_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir, _site_packages = _configure_environment(monkeypatch, tmp_path)
    substitute = tmp_path / "substitute.txt"
    substitute.write_bytes(b"substitute\n")
    monkeypatch.setenv("SERVONAUT_STANDALONE_RUNTIME_NOTICE_SOURCE", str(substitute))

    with pytest.raises(SystemExit) as result:
        _execute_spec(output_dir)

    assert result.value.code == 64


def test_spec_rejects_a_runtime_notice_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir, _site_packages = _configure_environment(monkeypatch, tmp_path)
    source = Path(os.environ["SERVONAUT_STANDALONE_RUNTIME_NOTICE_SOURCE"])
    replacement = tmp_path / "replacement.txt"
    replacement.write_bytes(b"replacement\n")
    try:
        source.unlink()
        source.symlink_to(replacement)
    except OSError:
        pytest.skip("symlinks are unavailable on this test host")

    with pytest.raises(SystemExit) as result:
        _execute_spec(output_dir)

    assert result.value.code == 64


def test_spec_rejects_a_foreign_runtime_notice_through_expected_parent_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir, _site_packages = _configure_environment(monkeypatch, tmp_path)
    source = Path(os.environ["SERVONAUT_STANDALONE_RUNTIME_NOTICE_SOURCE"])
    expected_parent = source.parent
    foreign_parent = tmp_path / "foreign-runtime-notice"
    expected_parent.rename(foreign_parent)
    try:
        expected_parent.symlink_to(foreign_parent, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable on this test host")
    monkeypatch.setenv(
        "SERVONAUT_STANDALONE_RUNTIME_NOTICE_SOURCE",
        str((foreign_parent / source.name).resolve()),
    )

    with pytest.raises(SystemExit) as result:
        _execute_spec(output_dir)

    assert result.value.code == 64


@pytest.mark.parametrize(
    "kind",
    ("foreign", "sibling-alias", "missing", "extra", "directory", "symlink"),
)
def test_spec_rejects_substituted_or_incomplete_embedded_notices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    output_dir, _site_packages = _configure_environment(monkeypatch, tmp_path)
    root = Path(os.environ["SERVONAUT_STANDALONE_THIRD_PARTY_NOTICES_ROOT"])
    first = min(root.iterdir())
    if kind == "foreign":
        foreign = tmp_path / "foreign-notices"
        foreign.mkdir()
        for source in root.iterdir():
            (foreign / source.name).write_bytes(source.read_bytes())
        monkeypatch.setenv(
            "SERVONAUT_STANDALONE_THIRD_PARTY_NOTICES_ROOT", str(foreign)
        )
    elif kind == "sibling-alias":
        foreign = tmp_path / "foreign-notices"
        root.rename(foreign)
        try:
            root.symlink_to(foreign, target_is_directory=True)
        except OSError:
            pytest.skip("symlinks are unavailable on this test host")
        monkeypatch.setenv(
            "SERVONAUT_STANDALONE_THIRD_PARTY_NOTICES_ROOT",
            str(foreign.resolve()),
        )
    elif kind == "missing":
        first.unlink()
    elif kind == "extra":
        (root / "extra-LICENSE.txt").write_bytes(b"extra\n")
    elif kind == "directory":
        first.unlink()
        first.mkdir()
    elif kind == "symlink":
        replacement = tmp_path / "replacement-notice"
        replacement.write_bytes(first.read_bytes())
        first.unlink()
        try:
            first.symlink_to(replacement)
        except OSError:
            pytest.skip("symlinks are unavailable on this test host")

    with pytest.raises(SystemExit) as result:
        _execute_spec(output_dir)

    assert result.value.code == 64


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

    with pytest.raises(SystemExit) as error:
        _execute_spec(output_dir)
    assert error.value.code == 64


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

    with pytest.raises(SystemExit) as error:
        _execute_spec(output_dir)
    assert error.value.code == 64


@pytest.mark.parametrize(
    ("phase_name", "phase", "expected"),
    (
        ("preflight", 0, 64),
        ("runtime metadata", 1, 80),
        ("analysis", 2, 96),
        ("data filtering", 3, 112),
        ("PYZ", 4, 128),
        ("EXE", 5, 144),
        ("COLLECT", 6, 160),
    ),
)
def test_spec_phase_wrapper_preserves_all_other_phase_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase_name: str,
    phase: int,
    expected: int,
) -> None:
    output_dir, _site_packages = _configure_environment(monkeypatch, tmp_path)
    namespace = _execute_spec(output_dir)
    wrapper = namespace["_run_diagnostic_phase"]

    def fail() -> None:
        raise RuntimeError(phase_name)

    with pytest.raises(SystemExit) as error:
        wrapper(phase, fail)

    assert error.value.code == expected


@pytest.mark.parametrize(
    ("error", "expected"),
    (
        (FileNotFoundError(), 4),
        (PermissionError(), 5),
        (OSError(errno.EACCES, "access"), 5),
        (OSError(errno.ENOSPC, "capacity"), 6),
        (RecursionError(), 7),
        (MemoryError(), 8),
    ),
)
def test_spec_phase_wrapper_uses_closed_builtin_categories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
    expected: int,
) -> None:
    output_dir, _site_packages = _configure_environment(monkeypatch, tmp_path)
    namespace = _execute_spec(output_dir)
    wrapper = namespace["_run_diagnostic_phase"]

    def fail() -> None:
        raise error

    with pytest.raises(SystemExit) as result:
        wrapper(2, fail)

    assert result.value.code == 96 + expected


@pytest.mark.parametrize("platform_name", ("linux", "darwin"))
def test_spec_phase_wrapper_rejects_posix_einval_as_access_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform_name: str
) -> None:
    output_dir, _site_packages = _configure_environment(monkeypatch, tmp_path)
    namespace = _execute_spec(output_dir)
    wrapper = namespace["_run_diagnostic_phase"]
    monkeypatch.setattr(sys, "platform", platform_name)

    def fail() -> None:
        raise OSError(errno.EINVAL, "invalid")

    with pytest.raises(SystemExit) as result:
        wrapper(2, fail)

    assert result.value.code == 96


def test_spec_phase_wrapper_accepts_windows_einval_as_access_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir, _site_packages = _configure_environment(monkeypatch, tmp_path)
    namespace = _execute_spec(output_dir)
    wrapper = namespace["_run_diagnostic_phase"]
    monkeypatch.setattr(sys, "platform", "win32")

    def fail() -> None:
        raise OSError(errno.EINVAL, "invalid")

    with pytest.raises(SystemExit) as result:
        wrapper(2, fail)

    assert result.value.code == 101


def test_spec_phase_wrapper_rejects_invalid_explicit_cause_chains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir, _site_packages = _configure_environment(monkeypatch, tmp_path)
    namespace = _execute_spec(output_dir)
    wrapper = namespace["_run_diagnostic_phase"]
    first = RuntimeError()
    second = PermissionError()
    first.__cause__ = second
    second.__cause__ = first

    def fail() -> None:
        raise first

    with pytest.raises(SystemExit) as result:
        wrapper(2, fail)

    assert result.value.code == 96


def test_spec_phase_wrapper_rejects_explicit_cause_depth_overflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir, _site_packages = _configure_environment(monkeypatch, tmp_path)
    namespace = _execute_spec(output_dir)
    wrapper = namespace["_run_diagnostic_phase"]
    first = RuntimeError()
    second = PermissionError()
    third = RuntimeError()
    fourth = RuntimeError()
    fifth = RuntimeError()
    first.__cause__ = second
    second.__cause__ = third
    third.__cause__ = fourth
    fourth.__cause__ = fifth

    def fail() -> None:
        raise first

    with pytest.raises(SystemExit) as result:
        wrapper(2, fail)

    assert result.value.code == 96


def _copied_spec_child(tmp_path: Path, *, phase: int, kind: str) -> int:
    spec_directory = tmp_path / "spec"
    spec_directory.mkdir()
    spec = spec_directory / "servonaut_cli.spec"
    spec.write_text(_SPEC_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    (spec_directory / "embedded-notices.json").write_bytes(
        (_SPEC_PATH.parent / "embedded-notices.json").read_bytes()
    )
    (spec_directory / "hooks").mkdir()
    venv_root = tmp_path / "venv"
    site_packages = venv_root / "lib" / "python3.12" / "site-packages"
    package = site_packages / "servonaut"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("__version__ = '2.26.2'\n", encoding="utf-8")
    metadata = site_packages / "servonaut-2.26.2.dist-info"
    metadata.mkdir()
    (metadata / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: servonaut\nVersion: 2.26.2\n",
        encoding="utf-8",
    )
    shim = venv_root / "bin" / "servonaut-shim.py"
    shim.parent.mkdir()
    shim.write_text("from servonaut.main import main\nmain()\n", encoding="utf-8")
    output_dir = tmp_path / "output" / "dist"
    metadata_dir = tmp_path / "output" / "build-metadata"
    output_dir.mkdir(parents=True)
    metadata_dir.mkdir()
    runtime_notice = metadata_dir / "runtime-notice" / "CPython-LICENSE.txt"
    runtime_notice.parent.mkdir()
    runtime_notice.write_bytes(b"CPython notice fixture\n")
    _write_embedded_notice_staging(metadata_dir, spec_directory)
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target_name": "linux-x64-ubuntu-22.04",
                "target_platform": "linux",
                "target_architecture": "x86_64",
                "python_version": "3.12",
                "payload_name": "servonaut",
                "product_version": "2.26.2",
                "excluded_modules": ["readline"],
                "hook_directory": str((spec_directory / "hooks").resolve()),
                "require_artifact_selftest": False,
            }
        ),
        encoding="utf-8",
    )
    child = tmp_path / "run.py"
    child.write_text(
        """
import errno
import hashlib
import os
import runpy
import sys
from pathlib import Path
from types import ModuleType

root = Path(os.environ["SPEC_CHILD_ROOT"])
phase = int(os.environ["SPEC_CHILD_PHASE"])
kind = os.environ["SPEC_CHILD_KIND"]
sys.version_info = (3, 12, 0, "final", 0)
sys.path.insert(0, str(root / "venv" / "lib" / "python3.12" / "site-packages"))

def fail():
    errors = {
        "other": RuntimeError(),
        "missing": FileNotFoundError(),
        "access": PermissionError(),
        "capacity": OSError(errno.ENOSPC, "capacity"),
        "recursion": RecursionError(),
        "memory": MemoryError(),
    }
    raise errors[kind]

class Analysis:
    def __init__(self, *args, **kwargs):
        if phase == 2:
            fail()
        notice = root / "output" / "build-metadata" / "runtime-notice" / "CPython-LICENSE.txt"
        notice_root = root / "output" / "build-metadata" / "third-party-notices"
        expected = [(str(notice), "notices"), *[
            (str(path), "notices") for path in sorted(notice_root.iterdir())
        ]]
        if kwargs["datas"] != expected:
            raise RuntimeError("runtime notice data is not exact")
        if hashlib.sha256(notice.read_bytes()).hexdigest() != hashlib.sha256(b"CPython notice fixture\\n").hexdigest():
            raise RuntimeError("runtime notice data bytes changed")
        self.scripts = []
        self.binaries = []
        self.pure = []
        self.datas = Data()

class Data(list):
    def __iter__(self):
        if phase == 3:
            fail()
        return super().__iter__()

class PYZ:
    def __init__(self, *args, **kwargs):
        if phase == 4:
            fail()

class EXE:
    def __init__(self, *args, **kwargs):
        if phase == 5:
            fail()

class COLLECT:
    def __init__(self, *args, **kwargs):
        if phase == 6:
            fail()

pyinstaller = ModuleType("PyInstaller")
utils = ModuleType("PyInstaller.utils")
hooks = ModuleType("PyInstaller.utils.hooks")
def copy_metadata(_name):
    if phase == 1:
        fail()
    return []
hooks.copy_metadata = copy_metadata
pyinstaller.utils = utils
utils.hooks = hooks
sys.modules.update({
    "PyInstaller": pyinstaller,
    "PyInstaller.utils": utils,
    "PyInstaller.utils.hooks": hooks,
})
if phase == 0:
    os.environ["SERVONAUT_STANDALONE_UNTRUSTED"] = "1"
else:
    os.environ.update({
        "SERVONAUT_STANDALONE_ENTRY_SCRIPT": str(root / "venv" / "bin" / "servonaut-shim.py"),
        "SERVONAUT_STANDALONE_ISOLATED_SITE_PACKAGES": str(root / "venv" / "lib" / "python3.12" / "site-packages"),
        "SERVONAUT_STANDALONE_PROFILE_PATH": str(root / "profile.json"),
        "SERVONAUT_STANDALONE_OUTPUT_DIR": str(root / "output" / "dist"),
        "SERVONAUT_STANDALONE_BUILD_METADATA_DIR": str(root / "output" / "build-metadata"),
        "SERVONAUT_STANDALONE_RUNTIME_NOTICE_SOURCE": str(root / "output" / "build-metadata" / "runtime-notice" / "CPython-LICENSE.txt"),
        "SERVONAUT_STANDALONE_THIRD_PARTY_NOTICES_ROOT": str(root / "output" / "build-metadata" / "third-party-notices"),
        "SERVONAUT_STANDALONE_REQUIRE_ARTIFACT_SELFTEST": "0",
    })
runpy.run_path(str(root / "spec" / "servonaut_cli.spec"), init_globals={
    "Analysis": Analysis, "PYZ": PYZ, "EXE": EXE, "COLLECT": COLLECT,
    "DISTPATH": str(root / "output" / "dist"), "SPECPATH": str(root / "spec"),
})
""".lstrip(),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, str(child)],
        cwd=tmp_path,
        env={
            "PATH": os.defpath,
            "SPEC_CHILD_ROOT": str(tmp_path),
            "SPEC_CHILD_PHASE": str(phase),
            "SPEC_CHILD_KIND": kind,
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.returncode


@pytest.mark.parametrize("phase", range(7))
def test_copied_spec_child_emits_each_other_phase_code(
    tmp_path: Path, phase: int
) -> None:
    assert _copied_spec_child(tmp_path, phase=phase, kind="other") == 64 + (phase * 16)


@pytest.mark.parametrize(
    ("kind", "category"),
    (
        ("missing", 4),
        ("access", 5),
        ("capacity", 6),
        ("recursion", 7),
        ("memory", 8),
    ),
)
def test_copied_spec_child_emits_closed_builtin_categories(
    tmp_path: Path, kind: str, category: int
) -> None:
    assert _copied_spec_child(tmp_path, phase=2, kind=kind) == 96 + category


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
