"""The release channel and packaging revision a build writes into its marker."""

from __future__ import annotations

import argparse

import pytest

from scripts.standalone_cli.release_identity import (
    DEVELOPMENT_IDENTITY,
    MAX_PACKAGING_REVISION,
    PREVIEW_TAG,
    STABLE_TAG,
    ReleaseIdentity,
    ReleaseIdentityError,
    add_release_identity_arguments,
    channel_for_release_tag,
    identity_for_release_tag,
    parse_packaging_revision,
    release_tag_product_version,
    resolve_release_identity,
    validate_marker_identity,
)
from servonaut import runtime


def test_marker_channels_match_the_runtime_parser() -> None:
    from scripts.standalone_cli.release_identity import RELEASE_CHANNELS

    assert frozenset(RELEASE_CHANNELS) == runtime._MARKER_CHANNELS


def test_revision_bound_matches_the_runtime_and_manifest() -> None:
    """The build scripts do not import the app, so the shared bound is pinned here."""
    assert MAX_PACKAGING_REVISION == runtime.MAX_PACKAGING_REVISION
    assert DEVELOPMENT_IDENTITY.packaging_revision == runtime.MIN_PACKAGING_REVISION


def test_development_builds_default_to_the_first_stable_packaging() -> None:
    identity = resolve_release_identity(None, None, required=False)

    assert identity == DEVELOPMENT_IDENTITY
    assert identity.marker_fields() == {"channel": "stable", "packaging_revision": 1}


def test_explicit_inputs_are_used_for_development_builds() -> None:
    identity = resolve_release_identity("preview", "3", required=False)

    assert identity == ReleaseIdentity("preview", 3)


@pytest.mark.parametrize(
    ("channel", "revision"), [(None, None), ("stable", None), (None, "2")]
)
def test_release_builds_require_both_inputs(
    channel: str | None, revision: str | None
) -> None:
    with pytest.raises(ReleaseIdentityError, match="release builds require"):
        resolve_release_identity(channel, revision, required=True)


def test_release_builds_keep_their_explicit_inputs() -> None:
    assert resolve_release_identity(
        "stable", "2", required=True
    ) == ReleaseIdentity("stable", 2)


@pytest.mark.parametrize(
    "value",
    ["0", "-1", "+1", " 1", "1 ", "01", "1_0", "1.0", "ci-r1", "", "65536", "٣"],
)
def test_packaging_revision_text_must_be_a_canonical_integer(value: str) -> None:
    with pytest.raises(ReleaseIdentityError, match="packaging revision"):
        parse_packaging_revision(value)


def test_packaging_revision_accepts_the_windows_installer_bound() -> None:
    assert parse_packaging_revision(str(MAX_PACKAGING_REVISION)) == MAX_PACKAGING_REVISION


@pytest.mark.parametrize(
    ("channel", "revision"),
    [("nightly", 1), ("Stable", 1), (None, 1), ("stable", 0), ("stable", True), ("stable", "1")],
)
def test_identity_rejects_values_the_runtime_would_refuse(
    channel: object, revision: object
) -> None:
    with pytest.raises(ReleaseIdentityError):
        ReleaseIdentity(channel, revision)  # type: ignore[arg-type]


def test_marker_identity_is_read_back_from_generated_fields() -> None:
    marker = {"schema_version": 1, **ReleaseIdentity("preview", 4).marker_fields()}

    assert validate_marker_identity(marker) == ReleaseIdentity("preview", 4)
    with pytest.raises(ReleaseIdentityError, match="runtime marker"):
        validate_marker_identity({"schema_version": 1, "channel": "stable"})


def test_cli_options_default_to_unset_so_release_builds_can_require_them() -> None:
    parser = argparse.ArgumentParser()
    add_release_identity_arguments(parser, required=False)

    unset = parser.parse_args([])
    given = parser.parse_args(["--channel", "preview", "--packaging-revision", "2"])

    assert (unset.channel, unset.packaging_revision) == (None, None)
    assert (given.channel, given.packaging_revision) == ("preview", "2")
    with pytest.raises(SystemExit):
        parser.parse_args(["--channel", "nightly"])


def test_cli_options_can_be_required_for_builders_with_only_explicit_inputs() -> None:
    parser = argparse.ArgumentParser()
    add_release_identity_arguments(parser, required=True)

    with pytest.raises(SystemExit):
        parser.parse_args(["--channel", "stable"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--packaging-revision", "1"])
    given = parser.parse_args(["--channel", "stable", "--packaging-revision", "1"])
    assert (given.channel, given.packaging_revision) == ("stable", "1")


@pytest.mark.parametrize(
    ("tag", "channel", "version"),
    [("v2.27.0", "stable", "2.27.0"), ("v2.27.0-preview.2", "preview", "2.27.0")],
)
def test_release_tags_decide_the_channel(tag: str, channel: str, version: str) -> None:
    assert channel_for_release_tag(tag) == channel
    assert release_tag_product_version(tag) == version


@pytest.mark.parametrize(
    "tag", ["2.27.0", "v2.27", "v2.27.0-rc.1", "v2.27.0-preview.0", "v02.27.0", ""]
)
def test_other_tags_are_refused(tag: str) -> None:
    with pytest.raises(ReleaseIdentityError, match="release tag"):
        channel_for_release_tag(tag)


def test_tag_patterns_match_the_release_candidate_policy() -> None:
    """The build scripts cannot import the candidate policy, so the patterns are pinned."""
    from scripts.distribution import release_candidate

    assert STABLE_TAG.pattern == release_candidate.STABLE_TAG.pattern
    assert PREVIEW_TAG.pattern == release_candidate.PREVIEW_TAG.pattern


def test_release_tag_identity_takes_the_channel_from_the_tag() -> None:
    assert identity_for_release_tag(
        "v2.27.0-preview.1", product_version="2.27.0", channel=None, packaging_revision="2"
    ) == ReleaseIdentity("preview", 2)
    with pytest.raises(ReleaseIdentityError, match="contradicts"):
        identity_for_release_tag(
            "v2.27.0", product_version="2.27.0", channel="preview", packaging_revision="1"
        )
    with pytest.raises(ReleaseIdentityError, match="packaging-revision"):
        identity_for_release_tag(
            "v2.27.0", product_version="2.27.0", channel="stable", packaging_revision=None
        )
