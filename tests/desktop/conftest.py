"""Shared configuration and fixtures for the desktop test suite."""

from __future__ import annotations

import importlib
import logging
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)

# Set by the CI job that installs servonaut[desktop-test]. There, a missing
# host dependency must fail the run: otherwise the host, authentication and
# Origin tests would silently skip and the job would still pass.
REQUIRE_DESKTOP_TESTS_ENV = "SERVONAUT_REQUIRE_DESKTOP_TESTS"
REQUIRED_DESKTOP_MODULES = ("aiohttp", "textual_serve")

_NOISY_LOGGERS = ("botocore", "boto3", "urllib3", "textual")


def require_desktop_dependencies() -> None:
    """Import the desktop host dependencies when the run requires them."""
    if os.environ.get(REQUIRE_DESKTOP_TESTS_ENV) != "1":
        return
    for name in REQUIRED_DESKTOP_MODULES:
        try:
            importlib.import_module(name)
        except ImportError as error:
            raise pytest.UsageError(
                f"{REQUIRE_DESKTOP_TESTS_ENV}=1 but {name} cannot be imported; "
                "install servonaut[desktop-test]."
            ) from error


require_desktop_dependencies()


@pytest.fixture
def source_runtime(tmp_path: Path) -> RuntimeLayout:
    """A source-checkout runtime whose data directory lives under tmp_path."""
    return RuntimeLayout(
        kind=DistributionKind.SOURCE,
        product_version="3.0.0",
        build_revision=None,
        resource_root=tmp_path,
        executable_root=tmp_path,
        data_root=tmp_path / "data",
        executable=Path(sys.executable),
        python_executable=Path(sys.executable),
        path_console=None,
        console_helper=None,
        desktop_child=None,
        package_management=PackageManagementCapability(
            PackageManagementKind.UNSUPPORTED, (), False
        ),
        is_frozen=False,
    )


@pytest.fixture
def restore_root_logging() -> Iterator[None]:
    """Undo process-wide logging configuration made by an entry point under test."""
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    saved_noisy = {name: logging.getLogger(name).level for name in _NOISY_LOGGERS}
    try:
        yield
    finally:
        for handler in root.handlers[:]:
            if handler not in saved_handlers:
                handler.close()
                root.removeHandler(handler)
        for handler in saved_handlers:
            if handler not in root.handlers:
                root.addHandler(handler)
        root.setLevel(saved_level)
        for name, level in saved_noisy.items():
            logging.getLogger(name).setLevel(level)
