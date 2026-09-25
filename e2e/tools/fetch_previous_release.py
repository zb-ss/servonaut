#!/usr/bin/env python3
"""Download published Servonaut wheels for the upgrade journeys.

The end-to-end suite never reaches the network, so the published releases
that the upgrade journeys install are downloaded beforehand, by this script,
into a cache directory::

    python e2e/tools/fetch_previous_release.py [--cache DIR]

It fetches the newest release at or below the checkout's version (the
"previous" role; the journeys build the checkout as a later version) and the
newest release of each earlier config schema (the "schema-N" roles). The
previous release is checked against the SHA-256 digest the index publishes;
the schema releases are pinned to their digests below, since a published file
never changes. Downloads come from files.pythonhosted.org only. Name, digest
and config schema are recorded in ``manifest.json`` beside the wheels. The
journeys check each digest again before installing a wheel and skip, with the
command above as the reason, when the cache is missing. If the index cannot
be reached, an intact cache made for this checkout is kept.

The cache directory is ``SERVONAUT_E2E_RELEASE_CACHE`` when set, otherwise
``.e2e-cache/releases`` in the checkout. It must not lie below your home
directory unless it is inside the checkout: the suite cannot read there.

Standard library only, so it runs before the test dependencies are installed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT = "servonaut"
ENV_CACHE = "SERVONAUT_E2E_RELEASE_CACHE"
DEFAULT_CACHE = REPO_ROOT / ".e2e-cache" / "releases"
MANIFEST_NAME = "manifest.json"
MANIFEST_FORMAT = 1
DEFAULT_INDEX_URL = "https://pypi.org"
DOWNLOAD_HOST = "files.pythonhosted.org"
PREVIOUS_ROLE = "previous"


@dataclass(frozen=True)
class PinnedRelease:
    """A published release and the SHA-256 of its pure-Python wheel."""

    version: str
    sha256: str


# The newest published release that wrote each earlier config schema: a
# user still on it upgrades through every migration step from there. This is
# history, so the entries never change. A change that raises CONFIG_VERSION
# adds the latest release here, the last to write the old schema, with the
# digest PyPI lists for its wheel; the release-cache journey
# (e2e/journeys/packaged) fails until it does.
SCHEMA_BOUNDARY_RELEASES: dict[int, PinnedRelease] = {
    2: PinnedRelease("2.6.0", "00ebfc8e2e8a62c19ceb9069f20cbecbd79bda51a659a5479e95253f9e0dc749"),
    5: PinnedRelease("2.25.4", "dbc8f1cb81439f2daf857ded1279b10362e6b4eaa92f79d5e689b9edecef5304"),
}

_FINAL_VERSION = re.compile(r"^\d+(\.\d+)*$")
_SCHEMA_LINE = re.compile(r"^CONFIG_VERSION\s*=\s*(\d+)\s*$", re.MULTILINE)
_SCHEMA_MEMBER = f"{PROJECT}/config/schema.py"
_WHEEL_NAME = re.compile(rf"{PROJECT}-[0-9][0-9A-Za-z.]*-py3-none-any\.whl")
_TIMEOUT_SECONDS = 60
_CHUNK = 64 * 1024


class FetchError(RuntimeError):
    """The cache could not be prepared."""


class IndexUnavailable(FetchError):
    """The package index could not be reached."""


@dataclass(frozen=True)
class CachedRelease:
    """One wheel in the cache, as ``manifest.json`` records it."""

    role: str
    version: str
    file: str
    sha256: str
    config_schema: int


def version_key(version: str) -> tuple[int, ...]:
    """The numeric release part of *version* ("2.27.0rc1" sorts as 2.27.0)."""
    match = re.match(r"\d+(\.\d+)*", version)
    if not match:
        raise FetchError(f"not a release version: {version}")
    return tuple(int(part) for part in match.group().split("."))


def is_final(version: str) -> bool:
    return bool(_FINAL_VERSION.match(version))


def cache_dir(explicit: Optional[str] = None) -> Path:
    """The cache directory: *explicit*, else the environment, else the default."""
    chosen = explicit or os.environ.get(ENV_CACHE)
    return Path(chosen).resolve() if chosen else DEFAULT_CACHE


def checkout_version(root: Path = REPO_ROOT) -> str:
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
    if not match:
        raise FetchError("no version in pyproject.toml")
    return match.group(1)


def schema_from_source(text: str) -> int:
    match = _SCHEMA_LINE.search(text)
    if not match:
        raise FetchError("no CONFIG_VERSION in the config schema module")
    return int(match.group(1))


def checkout_schema(root: Path = REPO_ROOT) -> int:
    source = root / "src" / PROJECT / "config" / "schema.py"
    return schema_from_source(source.read_text(encoding="utf-8"))


def wheel_schema(path: Path) -> int:
    with zipfile.ZipFile(path) as archive:
        return schema_from_source(archive.read(_SCHEMA_MEMBER).decode("utf-8"))


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class Manifest:
    """What ``manifest.json`` records: the checkout it was made for, and the wheels."""

    checkout_version: str
    releases: tuple[CachedRelease, ...]
    # Boundary roles with nothing to upgrade from for this checkout.
    not_applicable: tuple[str, ...] = ()

    def release(self, role: str) -> Optional[CachedRelease]:
        return next((entry for entry in self.releases if entry.role == role), None)


def read_manifest(directory: Path) -> Optional[Manifest]:
    """*directory*'s manifest, or None when there is none."""
    try:
        data = json.loads((directory / MANIFEST_NAME).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if data.get("format") != MANIFEST_FORMAT:
        raise FetchError(f"{directory / MANIFEST_NAME} has an unknown format")
    releases = tuple(CachedRelease(**entry) for entry in data.get("releases", []))
    for release in releases:
        # Only bare wheel names: the manifest never names a file elsewhere.
        if not _WHEEL_NAME.fullmatch(release.file):
            raise FetchError(f"{directory / MANIFEST_NAME} lists an unexpected file")
    return Manifest(data["checkout_version"], releases, tuple(data.get("not_applicable", [])))


# ---------------------------------------------------------------------------
# Choosing the releases
# ---------------------------------------------------------------------------


def _git_tag_versions(root: Path) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "tag", "--list", "v*"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    versions = [line.strip()[1:] for line in result.stdout.splitlines()]
    return [version for version in versions if is_final(version)]


def previous_version(
    current: str, tag_versions: Iterable[str], index_versions: Iterable[str]
) -> str:
    """The newest release at or below *current*: from Git tags, else the index.

    Between releases the checkout carries the latest release's version, and
    that release is the one most users upgrade from.
    """
    for source in (list(tag_versions), list(index_versions)):
        known = [v for v in source if is_final(v) and version_key(v) <= version_key(current)]
        if known:
            return max(known, key=version_key)
    raise FetchError(f"no published release is at or below {current}")


def choose_roles(
    current: str, current_schema: int, previous: str, previous_schema: int
) -> dict[str, str]:
    """Role → version for everything the upgrade journeys install.

    A boundary release newer than the checkout, or whose schema is not older
    than the checkout's, has nothing to upgrade from here and gets no role
    (see :func:`boundary_roles` for the full list).
    """
    # Only the newest older schema can lack an entry: schemas are raised one
    # at a time now (3 and 4 were never released on their own).
    missing = current_schema - 1
    if previous_schema == current_schema and missing > max(SCHEMA_BOUNDARY_RELEASES):
        raise FetchError(
            f"config schema {missing} has no boundary release: add the newest release "
            f"that wrote schema {missing} to SCHEMA_BOUNDARY_RELEASES in {Path(__file__).name}"
        )
    roles = {PREVIOUS_ROLE: previous}
    for schema, pinned in sorted(SCHEMA_BOUNDARY_RELEASES.items()):
        if schema >= current_schema or version_key(pinned.version) > version_key(current):
            continue
        roles[boundary_role(schema)] = pinned.version
    return roles


def boundary_role(schema: int) -> str:
    return f"schema-{schema}"


def boundary_roles() -> list[str]:
    """Every boundary role, applicable to this checkout or not."""
    return [boundary_role(schema) for schema in sorted(SCHEMA_BOUNDARY_RELEASES)]


def pinned_sha256(role: str) -> Optional[str]:
    """The digest a boundary role is pinned to (None for the previous release)."""
    for schema, pinned in SCHEMA_BOUNDARY_RELEASES.items():
        if boundary_role(schema) == role:
            return pinned.sha256
    return None


# ---------------------------------------------------------------------------
# The package index
# ---------------------------------------------------------------------------


class Index:
    """Read-only access to the package index's JSON API."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def _get_json(self, path: str) -> dict:
        url = f"{self.base_url}{path}"
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
                return json.loads(response.read())
        except OSError as exc:
            raise IndexUnavailable(f"could not read {url}: {exc}") from exc
        except ValueError as exc:
            raise FetchError(f"{url} is not a JSON document: {exc}") from exc

    def versions(self) -> list[str]:
        releases = self._get_json(f"/pypi/{PROJECT}/json").get("releases", {})
        return [
            version
            for version, files in releases.items()
            if files and not all(f.get("yanked") for f in files)
        ]

    def wheel(self, version: str) -> tuple[str, str, str]:
        """(file name, download URL, SHA-256) of *version*'s pure-Python wheel."""
        files = self._get_json(f"/pypi/{PROJECT}/{version}/json").get("urls", [])
        for entry in files:
            name = entry.get("filename", "")
            if entry.get("packagetype") != "bdist_wheel" or not name.endswith("-py3-none-any.whl"):
                continue
            if entry.get("yanked"):
                raise FetchError(f"{PROJECT} {version} is yanked")
            digest = entry.get("digests", {}).get("sha256", "")
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise FetchError(f"{name} has no SHA-256 digest in the index")
            return name, entry["url"], digest
        raise FetchError(f"{PROJECT} {version} has no pure-Python wheel")


def _download(url: str, destination: Path, expected_sha256: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname != DOWNLOAD_HOST:
        raise FetchError(f"refusing a download from anywhere but https://{DOWNLOAD_HOST}: {url}")
    partial = destination.with_name(f".{destination.name}.part")
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT_SECONDS) as response:
            with partial.open("wb") as handle:
                for chunk in iter(lambda: response.read(_CHUNK), b""):
                    handle.write(chunk)
                    digest.update(chunk)
        if digest.hexdigest() != expected_sha256:
            raise FetchError(f"{destination.name}: SHA-256 does not match the index")
        partial.replace(destination)
    except OSError as exc:
        raise IndexUnavailable(f"could not download {url}: {exc}") from exc
    finally:
        partial.unlink(missing_ok=True)


def fetch_wheel(
    index: Index, version: str, directory: Path, pinned: Optional[str] = None
) -> tuple[Path, str]:
    """Make sure *version*'s wheel is in *directory*, with the *pinned* digest
    when there is one, else the one the index publishes."""
    name, url, expected = index.wheel(version)
    if pinned is not None and expected != pinned:
        raise FetchError(f"{name}: the index lists another SHA-256 than the pinned one")
    path = directory / name
    if path.is_file() and sha256_of(path) == expected:
        print(f"  {name}: cached")
        return path, expected
    print(f"  {name}: downloading")
    _download(url, path, expected)
    return path, expected


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def verified_cache(directory: Path) -> Optional[Manifest]:
    """The manifest in *directory* if it was made for this checkout and every
    wheel still matches its recorded digest; otherwise None."""
    try:
        manifest = read_manifest(directory)
    except (OSError, ValueError, TypeError, KeyError, FetchError):
        return None
    if manifest is None or manifest.checkout_version != checkout_version():
        return None
    for release in manifest.releases:
        path = directory / release.file
        if not path.is_file() or sha256_of(path) != release.sha256:
            return None
    return manifest


def _write_manifest(
    directory: Path, current: str, releases: list[CachedRelease], not_applicable: list[str]
) -> None:
    payload = {
        "format": MANIFEST_FORMAT,
        "checkout_version": current,
        "releases": [asdict(release) for release in releases],
        "not_applicable": not_applicable,
    }
    partial = directory / f".{MANIFEST_NAME}.part"
    partial.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    partial.replace(directory / MANIFEST_NAME)


def _prune(directory: Path, earlier: Optional[Manifest], keep: set[str]) -> None:
    """Delete the wheels only the earlier manifest listed; nothing else is ours."""
    if earlier is None:
        return
    for release in earlier.releases:
        if release.file not in keep:
            (directory / release.file).unlink(missing_ok=True)


def prepare(
    directory: Path, index: Index, previous_override: Optional[str] = None
) -> list[CachedRelease]:
    current = checkout_version()
    current_schema = checkout_schema()
    directory.mkdir(parents=True, exist_ok=True)
    try:
        earlier = read_manifest(directory)
    except (ValueError, TypeError, KeyError, FetchError):
        earlier = None
    if previous_override:
        previous = previous_override
    else:
        tags = _git_tag_versions(REPO_ROOT)
        previous = previous_version(current, tags, [] if tags else index.versions())
    print(f"checkout {current} (config schema {current_schema}); previous release {previous}")

    previous_path, previous_digest = fetch_wheel(index, previous, directory)
    previous_schema = wheel_schema(previous_path)
    releases = [
        CachedRelease(PREVIOUS_ROLE, previous, previous_path.name, previous_digest, previous_schema)
    ]
    roles = choose_roles(current, current_schema, previous, previous_schema)
    for role, version in roles.items():
        if role == PREVIOUS_ROLE:
            continue
        path, digest = fetch_wheel(index, version, directory, pinned_sha256(role))
        releases.append(CachedRelease(role, version, path.name, digest, wheel_schema(path)))
    not_applicable = [role for role in boundary_roles() if role not in roles]
    _write_manifest(directory, current, releases, not_applicable)
    _prune(directory, earlier, {release.file for release in releases})
    return releases


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--cache", help=f"cache directory (default: ${ENV_CACHE}, else {DEFAULT_CACHE})"
    )
    parser.add_argument("--previous", help="use this version as the previous release")
    parser.add_argument("--index-url", default=DEFAULT_INDEX_URL, help="package index base URL")
    args = parser.parse_args(argv)
    directory = cache_dir(args.cache)
    try:
        releases = list(prepare(directory, Index(args.index_url), args.previous))
    except IndexUnavailable as exc:
        # A cache already made for this checkout, and still intact, will do.
        cached = verified_cache(directory)
        if cached is None:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"warning: {exc}; keeping the cache made earlier for this checkout")
        releases = list(cached.releases)
    except FetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for release in releases:
        print(f"{release.role}: {release.version} (config schema {release.config_schema})")
    print(f"cache: {directory}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
