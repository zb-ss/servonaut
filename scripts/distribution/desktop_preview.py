"""Versions and asset names of the Linux desktop preview attached to each release.

Every published release (``vX.Y.Z``) and release candidate (``vX.Y.ZrcN``)
carries a preview ``.deb`` of the desktop app. The release tag decides the
product version, the Debian package version and the asset names, and a
checkout whose package version declarations disagree with the tag is refused
before anything is built from it.

``plan`` prints the values as ``key=value`` lines for ``$GITHUB_OUTPUT``.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import sys
from typing import Optional, Sequence

from scripts.distribution.package_deb import debian_version

# Stable releases and release candidates, as the Release workflow tags them.
RELEASE_TAG = re.compile(
    r"v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))(?:rc([1-9][0-9]*))?"
)
ASSET_PREFIX = "servonaut-desktop-preview"
ARCHITECTURE = "amd64"
PACKAGE_NAME = "servonaut"

# The two declarations the Release workflow sets, read the way it reads them.
_VERSION_DECLARATIONS = (
    (Path("pyproject.toml"), re.compile(r'^version = "([^"\n]*)"$', re.MULTILINE)),
    (
        Path("src/servonaut/__init__.py"),
        re.compile(r"^__version__ = ['\"]([^'\"\n]*)['\"]$", re.MULTILINE),
    ),
)


class DesktopPreviewError(ValueError):
    """A release tag or checkout that cannot carry a desktop preview."""


@dataclass(frozen=True)
class DesktopPreview:
    """The desktop preview of one release tag."""

    tag: str
    product_version: str
    debian_version: str
    prerelease: bool

    @property
    def deb_asset(self) -> str:
        # Asset names keep the tag's spelling: GitHub renames release assets
        # whose names contain characters such as the "~" of a Debian version.
        return f"{ASSET_PREFIX}_{self.product_version}_{ARCHITECTURE}.deb"

    @property
    def sums_asset(self) -> str:
        return f"{ASSET_PREFIX}_{self.product_version}_SHA256SUMS"

    def outputs(self) -> dict[str, str]:
        return {
            "tag": self.tag,
            "product-version": self.product_version,
            "debian-version": self.debian_version,
            "package-name": PACKAGE_NAME,
            "architecture": ARCHITECTURE,
            "deb-asset": self.deb_asset,
            "sums-asset": self.sums_asset,
            "prerelease": "true" if self.prerelease else "false",
        }


def preview_for_tag(tag: str) -> DesktopPreview:
    """Return the desktop preview of a vX.Y.Z or vX.Y.ZrcN release tag."""
    match = RELEASE_TAG.fullmatch(tag) if isinstance(tag, str) else None
    if match is None:
        raise DesktopPreviewError(
            "The release tag must be a release vX.Y.Z or a release candidate vX.Y.ZrcN."
        )
    product_version = tag[1:]
    return DesktopPreview(
        tag=tag,
        product_version=product_version,
        debian_version=debian_version(product_version),
        prerelease=match.group(2) is not None,
    )


def declared_versions(checkout: Path) -> tuple[str, ...]:
    """The versions in pyproject.toml and servonaut.__version__ of a checkout."""
    versions = []
    for path, pattern in _VERSION_DECLARATIONS:
        try:
            text = (checkout / path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            raise DesktopPreviewError(f"{path.as_posix()} could not be read.") from None
        matches = pattern.findall(text)
        if len(matches) != 1:
            raise DesktopPreviewError(
                f"Expected one static version in {path.as_posix()}."
            )
        versions.append(matches[0])
    return tuple(versions)


def require_matching_checkout(preview: DesktopPreview, checkout: Path) -> None:
    """Refuse a checkout whose package versions are not the tag's version."""
    for declared in declared_versions(checkout):
        if declared != preview.product_version:
            raise DesktopPreviewError(
                f"{preview.tag} does not match the package version {declared!r} "
                "declared in its checkout."
            )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser(
        "plan", help="Print the preview's versions and asset names for a release tag"
    )
    plan.add_argument("--tag", required=True)
    plan.add_argument(
        "--checkout",
        type=Path,
        default=Path.cwd(),
        help="Checkout whose package versions must match the tag (default: cwd)",
    )
    args = parser.parse_args(argv)
    try:
        preview = preview_for_tag(args.tag)
        require_matching_checkout(preview, args.checkout)
    except DesktopPreviewError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    for key, value in preview.outputs().items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
