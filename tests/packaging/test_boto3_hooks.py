"""Frozen builds carry boto3's resource definitions, which boto3.resource() reads at run time."""
from __future__ import annotations

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


def _run_hook(path: Path) -> tuple[dict[str, object], list[tuple[str, list[str]]]]:
    collected: list[tuple[str, list[str]]] = []
    pyinstaller = ModuleType("PyInstaller")
    utils = ModuleType("PyInstaller.utils")
    hooks = ModuleType("PyInstaller.utils.hooks")

    def collect_data_files(package: str, *, includes: list[str]) -> list[tuple[str, str]]:
        collected.append((package, includes))
        return [("/wheel/boto3/data/ec2/2016-11-15/resources-1.json", "boto3/data/ec2/2016-11-15")]

    hooks.collect_data_files = collect_data_files
    pyinstaller.utils = utils
    utils.hooks = hooks
    modules = {"PyInstaller": pyinstaller, "PyInstaller.utils": utils, "PyInstaller.utils.hooks": hooks}
    previous = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    try:
        return runpy.run_path(str(path)), collected
    finally:
        for name, module in previous.items():
            if module is None:
                del sys.modules[name]
            else:
                sys.modules[name] = module


@pytest.mark.parametrize("hook", _HOOKS, ids=["desktop", "standalone"])
def test_the_boto3_hook_bundles_its_resource_definitions(hook: Path) -> None:
    namespace, collected = _run_hook(hook)

    assert collected == [("boto3", ["data/**/*.json"])]
    assert namespace["datas"]
    assert {"botocore.credentials", "botocore.session"} <= set(namespace["hiddenimports"])


def test_the_include_pattern_matches_the_ec2_resource_definition() -> None:
    import boto3

    root = Path(boto3.__file__).parent
    matched = {path.relative_to(root).as_posix() for path in root.glob("data/**/*.json")}

    assert any(path.startswith("data/ec2/") and path.endswith("/resources-1.json") for path in matched)
