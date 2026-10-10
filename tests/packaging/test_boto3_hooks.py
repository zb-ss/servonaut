"""Frozen builds carry what boto3 loads at run time: resource definitions and helpers imported by name."""
from __future__ import annotations

import inspect
import re
import runpy
import sys
from pathlib import Path
from types import ModuleType

import pytest

_REPO = Path(__file__).resolve().parents[2]
_HOOKS = [
    _REPO / "packaging" / "desktop_shell" / "hooks" / "hook-boto3.py",
    _REPO / "packaging" / "standalone_cli" / "hooks" / "hook-boto3.py",
]


_COLLECTED_PACKAGES = {"boto3.dynamodb", "boto3.ec2", "boto3.s3"}


def _run_hook(path: Path) -> tuple[dict[str, object], list[tuple[str, list[str]]], list[str]]:
    collected: list[tuple[str, list[str]]] = []
    submodule_packages: list[str] = []
    pyinstaller = ModuleType("PyInstaller")
    utils = ModuleType("PyInstaller.utils")
    hooks = ModuleType("PyInstaller.utils.hooks")

    def collect_data_files(package: str, *, includes: list[str]) -> list[tuple[str, str]]:
        collected.append((package, includes))
        return [("/wheel/boto3/data/ec2/2016-11-15/resources-1.json", "boto3/data/ec2/2016-11-15")]

    def collect_submodules(package: str) -> list[str]:
        submodule_packages.append(package)
        return [package, f"{package}.helpers"]

    hooks.collect_data_files = collect_data_files
    hooks.collect_submodules = collect_submodules
    pyinstaller.utils = utils
    utils.hooks = hooks
    modules = {"PyInstaller": pyinstaller, "PyInstaller.utils": utils, "PyInstaller.utils.hooks": hooks}
    previous = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    try:
        return runpy.run_path(str(path)), collected, submodule_packages
    finally:
        for name, module in previous.items():
            if module is None:
                del sys.modules[name]
            else:
                sys.modules[name] = module


@pytest.mark.parametrize("hook", _HOOKS, ids=["desktop", "standalone"])
def test_the_boto3_hook_bundles_its_resource_definitions(hook: Path) -> None:
    namespace, collected, submodule_packages = _run_hook(hook)

    assert collected == [("boto3", ["data/**/*.json"])]
    assert namespace["datas"]
    assert set(submodule_packages) == _COLLECTED_PACKAGES
    hidden = set(namespace["hiddenimports"])
    assert {"botocore.credentials", "botocore.session", "boto3.ec2.helpers", "boto3.s3.helpers"} <= hidden


def test_every_helper_boto3_imports_by_name_is_in_a_collected_package() -> None:
    """boto3 registers these as dotted names; the import scan cannot follow them."""
    import boto3.session

    source = inspect.getsource(boto3.session.Session._register_default_handlers)
    lazy_targets = re.findall(r"lazy_call\(\s*['\"]([\w.]+)['\"]", source)

    assert lazy_targets, "boto3 no longer registers helpers by name; revisit the hook"
    for target in lazy_targets:
        module = target.rsplit(".", 1)[0]
        assert any(module == package or module.startswith(f"{package}.") for package in _COLLECTED_PACKAGES), target


def test_the_include_pattern_matches_the_ec2_resource_definition() -> None:
    import boto3

    root = Path(boto3.__file__).parent
    matched = {path.relative_to(root).as_posix() for path in root.glob("data/**/*.json")}

    assert any(path.startswith("data/ec2/") and path.endswith("/resources-1.json") for path in matched)
