"""Fixtures for journeys that install Servonaut as a package.

The checkout is built once per run (see ``installs.session_wheels``); the
release cache supplies published wheels. Each journey gets an :class:`Installs`
whose venvs and pipx home live in its own directory, and whose programs the
guard lets the journey start.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

from e2e.harness import installs as installs_module
from e2e.harness.bootstrap import E2EContext, load_guard
from e2e.harness.releases import ReleaseCache
from e2e.tools import fetch_previous_release as fetcher

GUARD = load_guard()


def _require_modules(*names: str, why: str) -> None:
    missing = [name for name in names if importlib.util.find_spec(name) is None]
    if missing:
        pytest.skip(f"{why} needs {', '.join(missing)}: pip install -e '.[e2e]'")


@pytest.fixture(scope="session")
def packaging_dir(e2e_ctx: E2EContext) -> Path:
    path = e2e_ctx.root / "packaged"
    path.mkdir(exist_ok=True)
    return path


@pytest.fixture(scope="session")
def built_wheels(e2e_ctx: E2EContext, packaging_dir: Path) -> dict[str, Path]:
    """The checkout built as :func:`installs.wheel_versions` names them."""
    _require_modules(*installs_module.BUILD_MODULES, why="building the wheel")
    try:
        return installs_module.session_wheels(e2e_ctx, packaging_dir / "wheels")
    except RuntimeError as exc:
        pytest.fail(str(exc))


@pytest.fixture(scope="session")
def build_version() -> str:
    """The version the checkout is built as: above every published release."""
    return installs_module.wheel_versions(fetcher.checkout_version())[0]


@pytest.fixture(scope="session")
def newer_version() -> str:
    """The version after :func:`build_version`, for the update journeys."""
    return installs_module.wheel_versions(fetcher.checkout_version())[1]


@pytest.fixture(scope="session")
def current_wheel(built_wheels: dict[str, Path]) -> Path:
    """The checkout, built from its sdist as the publish workflow does."""
    return built_wheels["current"]


@pytest.fixture(scope="session")
def newer_wheel(built_wheels: dict[str, Path]) -> Path:
    return built_wheels["newer"]


@pytest.fixture(scope="session")
def overlay(packaging_dir: Path) -> Path:
    return installs_module.build_overlay(packaging_dir / "overlay")


@pytest.fixture(scope="session")
def release_cache() -> ReleaseCache:
    return ReleaseCache.from_environment()


@pytest.fixture
def installs(
    journey: Any, fake_cloud: Any, e2e_ctx: E2EContext, overlay: Path
) -> installs_module.Installs:
    """This journey's installs, and permission for the journey to start them."""
    result = installs_module.Installs(
        root=journey.directory / "installs",
        overlay=overlay,
        fake_cloud=fake_cloud,
        base_env=lambda sandbox, overrides: journey.child_env(sandbox, **overrides),
        shim_dir=journey.shims.directory,
        allowed_dirs=e2e_ctx.allowed_dirs,
        armed_log=journey.armed_log,
        log=journey.children,
    )
    result.root.mkdir()
    GUARD.set_spawn_dirs(result.spawn_dirs)
    return result


@pytest.fixture
def pipx_available() -> None:
    _require_modules("pipx", why="installing with pipx")
