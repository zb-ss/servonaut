"""Published releases for the upgrade journeys, read from the local cache.

``e2e/tools/fetch_previous_release.py`` downloads them before the suite runs
(the suite itself never reaches the network). A journey asks for a release by
role ("previous", "schema-5" ...); the wheel's digest is checked against the
manifest and the file is copied into the journey before anything installs it.

A missing cache or role skips the journey, with the fetch command as the
reason. When ``SERVONAUT_E2E_RELEASE_CACHE`` is set explicitly (as CI does),
the cache is required and a missing release fails instead.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, Optional

import pytest

from e2e.harness.bootstrap import ENV_RELEASE_CACHE, load_guard
from e2e.tools import fetch_previous_release as fetcher

PREVIOUS = fetcher.PREVIOUS_ROLE
# Every role the upgrade journeys know about, whether or not it is cached.
ROLES = (PREVIOUS, *fetcher.boundary_roles())
FETCH_COMMAND = "python e2e/tools/fetch_previous_release.py"


@dataclass(frozen=True)
class Release:
    """A cached published release, copied into a journey."""

    role: str
    version: str
    config_schema: int
    wheel: Path


@dataclass(frozen=True)
class ReleaseCache:
    directory: Path
    required: bool

    @classmethod
    def from_environment(cls) -> "ReleaseCache":
        explicit = os.environ.get(ENV_RELEASE_CACHE)
        return cls(fetcher.cache_dir(explicit), required=bool(explicit))

    def _unavailable(self, reason: str) -> NoReturn:
        if self.required:
            pytest.fail(f"{reason} ({ENV_RELEASE_CACHE} is set, so the cache is required)")
        pytest.skip(f"{reason}; run `{FETCH_COMMAND}` first")

    def _check_readable(self) -> None:
        # The guard refuses reads below the real home unless they are inside
        # the checkout; say so plainly instead of failing on the first open.
        if load_guard().is_protected(os.path.realpath(self.directory)):
            pytest.fail(
                f"the release cache {self.directory} is below your home directory, which "
                "the suite may not read: keep it inside the checkout (the default) or "
                f"point {ENV_RELEASE_CACHE} outside your home"
            )

    def release(self, role: str, destination: Path) -> Release:
        """The cached release for *role*, verified and copied into *destination*."""
        from servonaut import __version__ as current

        self._check_readable()
        try:
            manifest = fetcher.read_manifest(self.directory)
        except (OSError, ValueError, TypeError, KeyError, fetcher.FetchError) as exc:
            self._unavailable(f"the release cache {self.directory} is unreadable: {exc}")
        if manifest is None:
            self._unavailable(f"there is no release cache in {self.directory}")
        if manifest.checkout_version != current:
            self._unavailable(
                f"the release cache was prepared for {manifest.checkout_version}, not {current}"
            )
        if role in manifest.not_applicable:
            pytest.skip(f"no release before {current} wrote the config schema of {role!r}")
        entry: Optional[fetcher.CachedRelease] = manifest.release(role)
        if entry is None:
            self._unavailable(f"no {role!r} release in the cache {self.directory}")
        source = self.directory / entry.file
        if not source.is_file() or fetcher.sha256_of(source) != entry.sha256:
            pytest.fail(f"{source} is missing or does not match its recorded SHA-256")
        destination.mkdir(parents=True, exist_ok=True)
        copy = destination / entry.file
        shutil.copyfile(source, copy)
        return Release(role, entry.version, entry.config_schema, copy)
