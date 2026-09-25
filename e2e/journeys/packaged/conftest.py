"""Fixtures for journeys that install Servonaut as a package.

The wheel is built once per test process from the checkout; the release
cache supplies published wheels. Each journey gets an :class:`Installs`
whose venvs and pipx home live in its own directory, and whose programs the
guard lets the journey start.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

from e2e.harness import installs as installs_module
from e2e.harness.bootstrap import (
    CHILD_SITE_DIR,
    REPO_ROOT,
    E2EContext,
    Sandbox,
    build_env,
    load_guard,
)
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


def _session_runner(
    e2e_ctx: E2EContext, directory: Path
) -> tuple[installs_module.ToolRunner, Sandbox, Path]:
    """A runner for session-level builds, outside any journey."""
    sandbox = Sandbox(directory / "sandbox").create()
    guard_log = directory / "guard.jsonl"

    def env_for(box: Sandbox) -> dict[str, str]:
        return build_env(
            box,
            shim_dir=e2e_ctx.default_shims,
            guard_log=guard_log,
            armed_log=directory / "armed.jsonl",
            extra={"PYTHONPATH": str(CHILD_SITE_DIR)},
        )

    return installs_module.ToolRunner(env_for, directory / "armed.jsonl"), sandbox, guard_log


def _build(e2e_ctx: E2EContext, directory: Path, source: Path, *, sdist: bool) -> Path:
    _require_modules("build", "hatchling", why="building the wheel")
    runner, sandbox, guard_log = _session_runner(e2e_ctx, directory)
    wheel = installs_module.build_wheel(runner, sandbox, source, directory / "dist", sdist=sdist)
    escapes = GUARD.read_log(guard_log)
    if escapes:
        pytest.fail(f"building the wheel tried to leave the sandbox: {escapes}")
    return wheel


@pytest.fixture(scope="session")
def current_wheel(e2e_ctx: E2EContext, packaging_dir: Path) -> Path:
    """The checkout built as the publish workflow builds it (sdist, then wheel)."""
    return _build(e2e_ctx, packaging_dir / "current", REPO_ROOT, sdist=True)


@pytest.fixture(scope="session")
def newer_version() -> str:
    """A version one patch above the checkout's."""
    from servonaut import __version__

    major, minor, micro = fetcher.version_key(__version__)[:3]
    return f"{major}.{minor}.{micro + 1}"


@pytest.fixture(scope="session")
def newer_wheel(e2e_ctx: E2EContext, packaging_dir: Path, newer_version: str) -> Path:
    """The checkout built as if it were the next patch release."""
    directory = packaging_dir / "newer"
    source = installs_module.copy_sources(directory / "src", version=newer_version)
    return _build(e2e_ctx, directory, source, sdist=False)


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
