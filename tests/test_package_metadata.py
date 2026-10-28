"""Regression checks for package metadata used by release builds."""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
PACKAGE_INIT = ROOT / "src" / "servonaut" / "__init__.py"
PUBLIC_REPOSITORY = "https://github.com/zb-ss/servonaut"
DESKTOP_ONLY_DEPENDENCIES = {
    "aiohttp",
    "aiohttp-jinja2",
    "pyinstaller",
    "pywebview",
    "textual-serve",
}


def _project_section() -> str:
    """Return the project table without requiring Python 3.11's tomllib."""
    document = PYPROJECT.read_text(encoding="utf-8")
    return document.split("[project]", maxsplit=1)[1].split("\n[", maxsplit=1)[0]


def _optional_dependencies_section() -> str:
    """Return the text from the optional-dependencies table onwards."""
    document = PYPROJECT.read_text(encoding="utf-8")
    return document.split("[project.optional-dependencies]", maxsplit=1)[1]


def _requirements(table: str, key: str) -> list[str]:
    """Extract the raw requirement strings from a simple dependency array."""
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*\[(?P<requirements>.*?)^\]",
        table,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"Missing {key!r} dependency list"
    return re.findall(r'"([^"]+)"', match.group("requirements"))


def _requirement_names(table: str, key: str) -> set[str]:
    """Extract normalized package names from a simple dependency array."""
    return {
        re.split(r"[\s<>=!~\[;]", requirement, maxsplit=1)[0].lower()
        for requirement in _requirements(table, key)
    }


def _names_installed_on(requirements: list[str], python_version: str) -> set[str]:
    """Names whose environment marker admits *python_version*."""
    from packaging.requirements import Requirement

    installed = set()
    for requirement in map(Requirement, requirements):
        marker = requirement.marker
        if marker is None or marker.evaluate({"python_version": python_version}):
            installed.add(requirement.name.lower())
    return installed


def _source_version() -> str:
    """Read the sole ``__version__`` assignment without importing the package."""
    module = ast.parse(PACKAGE_INIT.read_text(encoding="utf-8"))
    versions = [
        node.value.value
        for node in module.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
        and target.id == "__version__"
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    assert len(versions) == 1
    return versions[0]


def test_distribution_version_matches_source_identity() -> None:
    project = _project_section()
    match = re.search(r'^version\s*=\s*"([^"]+)"$', project, flags=re.MULTILINE)

    assert match is not None
    assert match.group(1) == _source_version()


def test_desktop_build_dependencies_stay_out_of_base_and_all_extras() -> None:
    base_dependencies = _requirement_names(_project_section(), "dependencies")
    all_dependencies = _requirement_names(_optional_dependencies_section(), "all")

    assert not base_dependencies & DESKTOP_ONLY_DEPENDENCIES
    assert not all_dependencies & DESKTOP_ONLY_DEPENDENCIES


def test_all_extra_skips_batch_voice_engine_where_onnxruntime_has_no_build() -> None:
    # Regression: `pipx install 'servonaut[all]'` failed to resolve on
    # Python 3.15 because faster-whisper needs onnxruntime, which publishes
    # no cp315 build. The version strings are pinned on purpose.
    extras = _optional_dependencies_section()
    all_requirements = _requirements(extras, "all")

    assert "faster-whisper" in _names_installed_on(all_requirements, "3.14")
    assert "faster-whisper" not in _names_installed_on(all_requirements, "3.15")
    assert {"mcp", "sherpa-onnx"} <= _names_installed_on(all_requirements, "3.15")
    # Asking for the batch engine by name must still fail loudly on 3.15
    # instead of installing an extra that cannot work.
    assert "faster-whisper" in _names_installed_on(_requirements(extras, "voice"), "3.15")


def test_public_project_urls_reference_servonaut_repository() -> None:
    urls = PYPROJECT.read_text(encoding="utf-8").split("[project.urls]", maxsplit=1)[1]

    assert f'Homepage = "{PUBLIC_REPOSITORY}"' in urls
    assert f'Repository = "{PUBLIC_REPOSITORY}"' in urls
    assert f'Issues = "{PUBLIC_REPOSITORY}/issues"' in urls
