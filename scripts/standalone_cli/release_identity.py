"""Release channel and packaging revision stamped into a build's runtime marker.

The update check orders two builds of the same product version by their integer
packaging revision, and it follows the release channel the build was cut for.
Both values therefore come from explicit build inputs. They are never derived
from a free-form revision label such as a CI run identifier.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

# The release channels a packaged build can follow; the runtime marker parser
# accepts exactly these.
RELEASE_CHANNELS: Final = ("stable", "preview")
# A build cut without release inputs is a development or qualification build.
# It follows the stable channel as the first packaging of its version, so a
# signed release of that same version is never offered to it as an update.
DEVELOPMENT_CHANNEL: Final = "stable"
DEVELOPMENT_PACKAGING_REVISION: Final = 1
# Windows Installer versions carry the packaging revision in a 16-bit field.
MAX_PACKAGING_REVISION: Final = 65535
_PACKAGING_REVISION_RE: Final = re.compile(r"^[1-9][0-9]{0,4}$")
# Release tags: stable vX.Y.Z, or preview vX.Y.Z-preview.N for the same X.Y.Z.
STABLE_TAG: Final = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
PREVIEW_TAG: Final = re.compile(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-preview\.[1-9][0-9]*"
)


class ReleaseIdentityError(ValueError):
    """Raised when a build's release channel or packaging revision is invalid."""


@dataclass(frozen=True)
class ReleaseIdentity:
    """The release channel and packaging revision one build is cut for."""

    channel: str
    packaging_revision: int

    def __post_init__(self) -> None:
        if not isinstance(self.channel, str) or self.channel not in RELEASE_CHANNELS:
            raise ReleaseIdentityError(
                f"release channel must be one of {', '.join(RELEASE_CHANNELS)}"
            )
        if (
            type(self.packaging_revision) is not int
            or not 1 <= self.packaging_revision <= MAX_PACKAGING_REVISION
        ):
            raise ReleaseIdentityError(
                f"packaging revision must be an integer from 1 to {MAX_PACKAGING_REVISION}"
            )

    def marker_fields(self) -> dict[str, object]:
        """Return the runtime marker fields that carry this identity."""
        return {"channel": self.channel, "packaging_revision": self.packaging_revision}


DEVELOPMENT_IDENTITY: Final = ReleaseIdentity(
    DEVELOPMENT_CHANNEL, DEVELOPMENT_PACKAGING_REVISION
)


def parse_packaging_revision(value: str) -> int:
    """Parse a canonical decimal packaging revision without sign or padding."""
    if (
        not isinstance(value, str)
        or not _PACKAGING_REVISION_RE.fullmatch(value)
        or int(value) > MAX_PACKAGING_REVISION
    ):
        raise ReleaseIdentityError(
            f"packaging revision must be an integer from 1 to {MAX_PACKAGING_REVISION}"
        )
    return int(value)


def add_release_identity_arguments(
    parser: argparse.ArgumentParser, *, required: bool
) -> None:
    """Add the release-channel and packaging-revision options to a builder CLI.

    A builder whose inputs are all explicit requires both. A builder with a
    separate release mode leaves them optional; its development builds then
    use the development identity and its release builds must state both.
    """
    parser.add_argument(
        "--channel",
        choices=RELEASE_CHANNELS,
        required=required,
        default=None,
        help="Release channel the build follows for updates."
        + _optional_note(required, DEVELOPMENT_CHANNEL),
    )
    parser.add_argument(
        "--packaging-revision",
        required=required,
        default=None,
        help="Integer packaging revision of this product version."
        + _optional_note(required, DEVELOPMENT_PACKAGING_REVISION),
    )


def _optional_note(required: bool, development_default: object) -> str:
    if required:
        return ""
    return (
        " Required for release builds; development builds use "
        f"{development_default}."
    )


def resolve_release_identity(
    channel: str | None,
    packaging_revision: str | None,
    *,
    required: bool,
) -> ReleaseIdentity:
    """Return the build's identity; when required, both values must be stated."""
    if required and (channel is None or packaging_revision is None):
        raise ReleaseIdentityError(
            "release builds require explicit --channel and --packaging-revision"
        )
    return ReleaseIdentity(
        channel=DEVELOPMENT_CHANNEL if channel is None else channel,
        packaging_revision=(
            DEVELOPMENT_PACKAGING_REVISION
            if packaging_revision is None
            else parse_packaging_revision(packaging_revision)
        ),
    )


def channel_for_release_tag(tag: str) -> str:
    """Return the release channel a stable or preview release tag belongs to."""
    if isinstance(tag, str):
        if STABLE_TAG.fullmatch(tag) is not None:
            return "stable"
        if PREVIEW_TAG.fullmatch(tag) is not None:
            return "preview"
    raise ReleaseIdentityError(
        "release tag must be a stable vX.Y.Z or preview vX.Y.Z-preview.N tag"
    )


def release_tag_product_version(tag: str) -> str:
    """Return the product version a release tag targets, without a preview suffix."""
    channel_for_release_tag(tag)
    return tag[1:].split("-", 1)[0]


def identity_for_release_tag(
    tag: str,
    *,
    product_version: str,
    channel: str | None,
    packaging_revision: str | None,
) -> ReleaseIdentity:
    """Return a release build's identity, taking the channel from its tag.

    The tag decides the channel, so an explicit channel may only repeat it; the
    packaging revision has no default for a release build.
    """
    if release_tag_product_version(tag) != product_version:
        raise ReleaseIdentityError("release tag does not match the product version")
    tag_channel = channel_for_release_tag(tag)
    if channel is not None and channel != tag_channel:
        raise ReleaseIdentityError(
            f"--channel {channel} contradicts the {tag_channel} release tag"
        )
    if packaging_revision is None:
        raise ReleaseIdentityError("release builds require an explicit --packaging-revision")
    return ReleaseIdentity(tag_channel, parse_packaging_revision(packaging_revision))


def validate_marker_identity(marker: Mapping[str, object]) -> ReleaseIdentity:
    """Read and validate the identity fields of a generated runtime marker."""
    try:
        return ReleaseIdentity(
            channel=marker.get("channel"),  # type: ignore[arg-type]
            packaging_revision=marker.get("packaging_revision"),  # type: ignore[arg-type]
        )
    except ReleaseIdentityError as error:
        raise ReleaseIdentityError(f"runtime marker {error}") from None
