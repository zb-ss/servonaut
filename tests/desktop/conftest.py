"""Shared configuration for the desktop test suite."""

from __future__ import annotations

import importlib
import os

import pytest

# Set by the CI job that installs servonaut[desktop-test]. There, a missing
# host dependency must fail the run: otherwise the host, authentication and
# Origin tests would silently skip and the job would still pass.
REQUIRE_DESKTOP_TESTS_ENV = "SERVONAUT_REQUIRE_DESKTOP_TESTS"
REQUIRED_DESKTOP_MODULES = ("aiohttp", "textual_serve")


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
