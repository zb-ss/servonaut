"""Versions and asset names of the desktop previews attached to each release.

Every published release (``vX.Y.Z``) and release candidate (``vX.Y.ZrcN``)
carries a preview ``.deb`` of the Linux desktop app and can carry signed
preview disk images of the macOS app. The release tag decides the product
version, the Debian package version, the release identity the builds stamp
into their runtime marker and the asset names, and a checkout whose package
version declarations disagree with the tag is refused before anything is
built from it.

``plan`` prints the values as ``key=value`` lines for ``$GITHUB_OUTPUT``;
``check-marker`` refuses a packaged build whose runtime marker does not carry
the release identity the tag decides.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
from typing import Optional, Sequence

from scripts.distribution.package_deb import debian_version
from scripts.standalone_cli.release_identity import (
    ReleaseIdentity,
    ReleaseIdentityError,
    identity_for_release_tag,
    validate_marker_identity,
)

# Stable releases and release candidates, as the Release workflow tags them.
RELEASE_TAG = re.compile(
    r"v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))(?:rc([1-9][0-9]*))?"
)
ASSET_PREFIX = "servonaut-desktop-preview"
ARCHITECTURE = "amd64"
PACKAGE_NAME = "servonaut"
# A release's preview builds are the first packaging of its version; the tag
# decides their channel, stable for a release and preview for a candidate.
PACKAGING_REVISION = 1
# The macOS preview's disk images, one per desktop target, in plan order.
MACOS_TARGETS: tuple[str, ...] = ("macos-arm64", "macos-x64")
# What the desktop builder writes into every packaged build's runtime marker.
PACKAGED_DISTRIBUTION = "packaged-desktop"

# The two declarations the Release workflow sets, read the way it reads them.
_VERSION_DECLARATIONS = (
    (Path("pyproject.toml"), re.compile(r'^version = "([^"\n]*)"$', re.MULTILINE)),
    (
        Path("src/servonaut/__init__.py"),
        re.compile(r"^__version__ = ['\"]([^'\"\n]*)['\"]$", re.MULTILINE),
    ),
)


class DesktopPreviewError(ValueError):
    """A release tag, checkout or packaged build that cannot carry a desktop preview."""


@dataclass(frozen=True)
class DesktopPreview:
    """The desktop preview of one release tag."""

    tag: str
    product_version: str
    debian_version: str
    prerelease: bool
    identity: ReleaseIdentity

    @property
    def deb_asset(self) -> str:
        # Asset names keep the tag's spelling: GitHub renames release assets
        # whose names contain characters such as the "~" of a Debian version.
        return f"{ASSET_PREFIX}_{self.product_version}_{ARCHITECTURE}.deb"

    @property
    def sums_asset(self) -> str:
        return f"{ASSET_PREFIX}_{self.product_version}_SHA256SUMS"

    def macos_dmg_asset(self, target: str) -> str:
        """The disk image of one macOS desktop target."""
        if target not in MACOS_TARGETS:
            raise DesktopPreviewError(
                f"The macOS preview targets are {', '.join(MACOS_TARGETS)}, not {target!r}."
            )
        return f"{ASSET_PREFIX}_{self.product_version}_{target}.dmg"

    @property
    def macos_sums_asset(self) -> str:
        # The release also carries the Linux preview's SHA256SUMS, so the
        # macOS one has a name of its own.
        return f"{ASSET_PREFIX}_{self.product_version}_macos_SHA256SUMS"

    def _identity_outputs(self) -> dict[str, str]:
        return {
            "channel": self.identity.channel,
            "packaging-revision": str(self.identity.packaging_revision),
        }

    def outputs(self) -> dict[str, str]:
        """The Linux preview's values."""
        return {
            "tag": self.tag,
            "product-version": self.product_version,
            "debian-version": self.debian_version,
            "package-name": PACKAGE_NAME,
            "architecture": ARCHITECTURE,
            "deb-asset": self.deb_asset,
            "sums-asset": self.sums_asset,
            "prerelease": "true" if self.prerelease else "false",
            **self._identity_outputs(),
        }

    def macos_outputs(self) -> dict[str, str]:
        """The macOS preview's values, the same for every target.

        Each disk image has its own key, so the jobs of every target can
        publish all of them without one overwriting another's.
        """
        return {
            "tag": self.tag,
            "product-version": self.product_version,
            **{f"dmg-asset-{target}": self.macos_dmg_asset(target) for target in MACOS_TARGETS},
            "sums-asset": self.macos_sums_asset,
            "prerelease": "true" if self.prerelease else "false",
            **self._identity_outputs(),
        }


def preview_for_tag(tag: str) -> DesktopPreview:
    """Return the desktop preview of a vX.Y.Z or vX.Y.ZrcN release tag."""
    match = RELEASE_TAG.fullmatch(tag) if isinstance(tag, str) else None
    if match is None:
        raise DesktopPreviewError(
            "The release tag must be a release vX.Y.Z or a release candidate vX.Y.ZrcN."
        )
    product_version = tag[1:]
    try:
        identity = identity_for_release_tag(
            tag,
            product_version=product_version,
            channel=None,
            packaging_revision=str(PACKAGING_REVISION),
        )
    except ReleaseIdentityError as error:
        raise DesktopPreviewError(f"{tag} has no release identity: {error}.") from None
    return DesktopPreview(
        tag=tag,
        product_version=product_version,
        debian_version=debian_version(product_version),
        prerelease=match.group(2) is not None,
        identity=identity,
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


def require_marker_identity(preview: DesktopPreview, marker_path: Path) -> ReleaseIdentity:
    """Refuse a packaged build whose runtime marker is not the tag's release build.

    The marker must name the tag's product version and the release identity
    the tag decides: the update check follows its channel and orders builds
    by its packaging revision.
    """
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise DesktopPreviewError(
            f"The packaged runtime marker {marker_path.name} could not be read."
        ) from None
    if not isinstance(marker, dict):
        raise DesktopPreviewError("The packaged runtime marker is not a JSON object.")
    if marker.get("distribution") != PACKAGED_DISTRIBUTION:
        raise DesktopPreviewError(
            f"The packaged runtime marker does not describe a {PACKAGED_DISTRIBUTION} build."
        )
    if marker.get("product_version") != preview.product_version:
        raise DesktopPreviewError(
            f"The packaged build is version {marker.get('product_version')!r}, "
            f"but {preview.tag} needs {preview.product_version}."
        )
    try:
        identity = validate_marker_identity(marker)
    except ReleaseIdentityError as error:
        raise DesktopPreviewError(f"The packaged {error}.") from None
    if identity != preview.identity:
        raise DesktopPreviewError(
            f"The packaged build follows the {identity.channel} channel at packaging "
            f"revision {identity.packaging_revision}, but {preview.tag} needs the "
            f"{preview.identity.channel} channel at packaging revision "
            f"{preview.identity.packaging_revision}."
        )
    return identity


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
    plan.add_argument(
        "--platform",
        choices=("linux", "macos"),
        default="linux",
        help="The preview to plan: the Linux .deb (default) or the macOS disk images",
    )
    check = commands.add_parser(
        "check-marker",
        help="Require a packaged build's runtime marker to carry the tag's release identity",
    )
    check.add_argument("--tag", required=True)
    check.add_argument("--marker", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        preview = preview_for_tag(args.tag)
        if args.command == "check-marker":
            identity = require_marker_identity(preview, args.marker)
        else:
            require_matching_checkout(preview, args.checkout)
    except DesktopPreviewError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    if args.command == "check-marker":
        print(
            f"The packaged build is {preview.product_version} on the {identity.channel} "
            f"channel at packaging revision {identity.packaging_revision}."
        )
        return 0
    outputs = preview.macos_outputs() if args.platform == "macos" else preview.outputs()
    for key, value in outputs.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
