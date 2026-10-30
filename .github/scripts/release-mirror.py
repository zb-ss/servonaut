#!/usr/bin/env python3
"""Copy a GitHub release's verified files to the release mirror.

The mirror only carries files; it is never trusted. GitHub's SHA256SUMS
assets, and the build-provenance attestations the workflow checks on the
desktop packages, stay the source of truth: a file is uploaded only when a
SUMS asset of the same release lists it with a matching digest.

Subcommands, in the order the workflow runs them:

  verify        check the downloaded release files against their SUMS assets
                and write the plan of files to mirror
  upload        put each planned file under <tag>/ in the bucket, never
                replacing an object that holds something else
  check-public  download each file again through its public URL
  channels      point latest.json (newest stable release) and
                channels/pre.json (newest release, candidates included) at
                the release, never at an older one
  manifests     sign the update manifests the packaged desktop app reads,
                manifest/stable.json and manifest/preview.json, for the
                release's desktop files; each must pass the app's own trust
                policy before it is uploaded, and neither moves to an older
                release
  notes         add or refresh the mirror links in the release notes
  refresh       re-sign the update manifests with a fresh expiry before they
                expire, while GitHub still lists every file they name
  audit         re-check the channel files, every file they list and the
                update manifests against GitHub

The bucket is reached with the standard AWS_ACCESS_KEY_ID and
AWS_SECRET_ACCESS_KEY variables plus MIRROR_ENDPOINT and MIRROR_BUCKET; the
update manifests are signed with RELEASE_MANIFEST_SIGNING_KEY (an Ed25519
private key in PEM form) under RELEASE_MANIFEST_KEY_ID, both read from the
environment and skipped with a notice while either is unset. The manifest
code is the app's own servonaut.distribution, imported from the checkout.
Error messages name object keys and error codes only, never the endpoint,
the bucket or the key, because CI logs are public.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

SCHEMA = 1
TAG_PATTERN = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:rc([1-9][0-9]*))?$"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SUMS_LINE = re.compile(r"([0-9a-f]{64}) [ *](\S+)")
# Rehearsals write under a prefix that can never be a release tag or a
# channel file, so they never touch what users download.
REHEARSAL_PREFIX = re.compile(r"^_[a-z0-9-]+/$")

IMMUTABLE = "public, max-age=31536000, immutable"
SHORT_LIVED = "public, max-age=300"
TEXT = "text/plain; charset=utf-8"
JSON_TYPE = "application/json"
LATEST_KEY = "latest.json"
PRE_KEY = "channels/pre.json"
USER_AGENT = "servonaut-release-mirror"
NOTES_START = "<!-- release-mirror:start -->"
NOTES_END = "<!-- release-mirror:end -->"
# Statuses of a conditional write that lost to an existing or concurrent one.
CONFLICT_STATUSES = (409, 412)
CHUNK = 1024 * 1024

DESKTOP_PREFIX = "servonaut-desktop-preview"
# The macOS disk images: asset suffix, and the architecture as the app's
# servonaut.distribution.trust.normalize_arch spells it.
MACOS_TARGETS = (("macos-arm64", "arm64"), ("macos-x64", "x86_64"))
# Update manifests the packaged desktop app reads. Each follows one channel
# file and must pass the trust policy of app builds on one release channel.
STABLE_MANIFEST_KEY = "manifest/stable.json"
PREVIEW_MANIFEST_KEY = "manifest/preview.json"
UPDATE_MANIFESTS = {
    LATEST_KEY: (STABLE_MANIFEST_KEY, "stable"),
    PRE_KEY: (PREVIEW_MANIFEST_KEY, "preview"),
}
# The release files an update manifest lists: their manifest kind, and the
# oldest operating system they run on (the app bundle's LSMinimumSystemVersion;
# Linux has no comparable version).
DESKTOP_KINDS = {"desktop-deb": ("ubuntu_deb", None), "desktop-dmg": ("macos_dmg", "13.0")}
# The packaging revision the desktop preview workflows stamp into the runtime
# marker of every release build.
PACKAGING_REVISION = 1
# Defaults of the repository variables RELEASE_MANIFEST_VALIDITY_DAYS and
# RELEASE_MANIFEST_REFRESH_DAYS. A manifest's expiry bounds how long a stale
# copy can hold an app back, so the validity also has a ceiling.
DEFAULT_VALIDITY_DAYS = 14
DEFAULT_REFRESH_DAYS = 7
MAX_VALIDITY_DAYS = 90
# An update manifest's product version: X.Y.Z, or X.Y.Z-rc.N for a candidate.
MANIFEST_VERSION = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.([1-9][0-9]*))?"
)
KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class MirrorError(Exception):
    """A release cannot be mirrored as it is; the message says why."""


@dataclass(frozen=True, order=True)
class Version:
    """A release version; a final release sorts after its candidates."""

    major: int
    minor: int
    patch: int
    final: int
    candidate: int


def parse_tag(tag: str) -> Version:
    match = TAG_PATTERN.match(tag)
    if not match:
        raise MirrorError(f"{tag!r} is not a release tag vX.Y.Z or vX.Y.ZrcN")
    major, minor, patch, candidate = match.groups()
    if candidate is None:
        return Version(int(major), int(minor), int(patch), 1, 0)
    return Version(int(major), int(minor), int(patch), 0, int(candidate))


@dataclass(frozen=True)
class Asset:
    """A verified release file and how the mirror serves it."""

    name: str
    kind: str
    size: int
    sha256: str
    md5: str
    content_type: str
    checksums_name: str | None = None
    platform: str | None = None
    arch: str | None = None


def desktop_checksums_names(version: str) -> tuple[str, str]:
    """The SHA256SUMS assets that list a release's Linux and macOS desktop files."""
    return f"{DESKTOP_PREFIX}_{version}_SHA256SUMS", f"{DESKTOP_PREFIX}_{version}_macos_SHA256SUMS"


def describe(name: str, version: str) -> dict[str, str] | None:
    """How the mirror serves a release file, or None for a file it skips."""
    if name == f"{DESKTOP_PREFIX}_{version}_amd64.deb":
        return {
            "kind": "desktop-deb",
            "content_type": "application/vnd.debian.binary-package",
            "platform": "linux",
            "arch": "x86_64",
        }
    for target, arch in MACOS_TARGETS:
        if name == f"{DESKTOP_PREFIX}_{version}_{target}.dmg":
            return {
                "kind": "desktop-dmg",
                "content_type": "application/x-apple-diskimage",
                "platform": "darwin",
                "arch": arch,
            }
    if name in ("install.sh", "install.ps1"):
        return {"kind": "install-script", "content_type": TEXT}
    if name in (*desktop_checksums_names(version), "install-scripts_SHA256SUMS"):
        return {"kind": "checksums", "content_type": TEXT}
    return None


def parse_sums(text: str, sums_name: str) -> dict[str, str]:
    """The digests a SHA256SUMS file lists, by file name."""
    entries: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        match = SUMS_LINE.fullmatch(line)
        if not match:
            raise MirrorError(f"{sums_name} line {number} is not '<sha256>  <file name>'")
        digest, name = match.groups()
        if "/" in name or "\\" in name or name in (".", ".."):
            raise MirrorError(f"{sums_name} lists {name!r}, which is not a plain file name")
        if name in entries:
            raise MirrorError(f"{sums_name} lists {name} twice")
        entries[name] = digest
    if not entries:
        raise MirrorError(f"{sums_name} lists no files")
    return entries


def digests(path: Path) -> tuple[str, str, int]:
    """SHA-256 and MD5 hex digests of a file, and its size."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            sha256.update(chunk)
            md5.update(chunk)
            size += len(chunk)
    return sha256.hexdigest(), md5.hexdigest(), size


def downloaded_files(directory: Path, github_sizes: dict[str, int]) -> list[str]:
    """The downloaded files, each the size GitHub says its asset is."""
    names = sorted(entry.name for entry in directory.iterdir())
    for name in names:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise MirrorError(f"{name} is not a regular file")
        if name not in github_sizes:
            raise MirrorError(f"{name} is not an asset of the release")
        if path.stat().st_size != github_sizes[name]:
            raise MirrorError(f"{name} did not download completely")
    return names


def listed_digests(directory: Path, names: Iterable[str]) -> dict[str, tuple[str, str]]:
    """Each file a SUMS asset lists: its expected digest and that SUMS asset."""
    present = set(names)
    listed: dict[str, tuple[str, str]] = {}
    for sums_name in sorted(name for name in present if name.endswith("SHA256SUMS")):
        text = (directory / sums_name).read_text(encoding="utf-8")
        for name, digest in parse_sums(text, sums_name).items():
            if name not in present:
                raise MirrorError(f"{sums_name} lists {name}, which the release lacks")
            if name in listed and listed[name][0] != digest:
                raise MirrorError(f"Two SHA256SUMS assets disagree about {name}")
            listed.setdefault(name, (digest, sums_name))
    return listed


def verify(directory: Path, tag: str, github_sizes: dict[str, int]) -> tuple[list[Asset], list[str]]:
    """The release files that may be mirrored, and notices about the rest.

    A file is mirrored only when a SUMS asset lists it with the digest it
    has; a mismatch stops everything. A SUMS asset itself is mirrored as
    downloaded from GitHub.
    """
    version = tag[1:]
    names = downloaded_files(directory, github_sizes)
    listed = listed_digests(directory, names)
    assets: list[Asset] = []
    notices: list[str] = []
    for name in names:
        sha256, md5, size = digests(directory / name)
        is_sums = name.endswith("SHA256SUMS")
        if not is_sums and name not in listed:
            notices.append(f"{name}: skipped, no SHA256SUMS asset lists it")
            continue
        if not is_sums and listed[name][0] != sha256:
            raise MirrorError(f"{name} does not match its digest in {listed[name][1]}")
        served = describe(name, version)
        if served is None:
            notices.append(f"{name}: skipped, not a file the mirror serves")
            continue
        checksums = None if is_sums else listed[name][1]
        assets.append(Asset(name=name, size=size, sha256=sha256, md5=md5, checksums_name=checksums, **served))
    order = {"desktop-deb": 0, "desktop-dmg": 1, "install-script": 2, "checksums": 3}
    assets.sort(key=lambda asset: (order[asset.kind], asset.name))
    return assets, notices


def object_key(prefix: str, tag: str, name: str) -> str:
    return f"{prefix}{tag}/{name}"


def public_url(base: str, prefix: str, tag: str, name: str) -> str:
    return f"{base.rstrip('/')}/{object_key(prefix, tag, name)}"


def github_url(repo: str, tag: str, name: str) -> str:
    return f"https://github.com/{repo}/releases/download/{tag}/{name}"


def check_prefix(prefix: str) -> str:
    if prefix and not REHEARSAL_PREFIX.match(prefix):
        raise MirrorError("A rehearsal prefix looks like _name/; it must never be a release tag")
    return prefix


# --- the bucket -------------------------------------------------------------


def bucket_client() -> tuple[Any, str]:
    """An S3 client for the mirror bucket, and the bucket's name."""
    import boto3
    from botocore.config import Config

    endpoint = os.environ.get("MIRROR_ENDPOINT", "")
    bucket = os.environ.get("MIRROR_BUCKET", "")
    if not endpoint or not bucket:
        raise MirrorError("MIRROR_ENDPOINT and MIRROR_BUCKET must be set")
    config = Config(
        # Newer botocore adds checksum headers that S3-compatible stores may
        # reject; Content-MD5 is sent explicitly instead.
        request_checksum_calculation="when_required",
        response_checksum_validation="when_required",
        retries={"max_attempts": 5, "mode": "standard"},
    )
    client = boto3.client("s3", endpoint_url=endpoint, region_name="auto", config=config)
    return client, bucket


def error_status(error: Exception) -> int | None:
    response = getattr(error, "response", None) or {}
    return response.get("ResponseMetadata", {}).get("HTTPStatusCode")


def error_code(error: Exception) -> str:
    response = getattr(error, "response", None) or {}
    return response.get("Error", {}).get("Code") or type(error).__name__


def is_bucket_error(error: Exception) -> bool:
    """Whether an exception came from botocore (its text may name the endpoint)."""
    return type(error).__module__.startswith(("botocore", "boto3"))


def put_release_file(client: Any, bucket: str, key: str, path: Path, asset: Asset) -> str:
    """Upload one file unless the key exists; an existing key must match."""
    for attempt in range(3):
        try:
            with path.open("rb") as body:
                client.put_object(
                    Bucket=bucket,
                    Key=key,
                    Body=body,
                    ContentType=asset.content_type,
                    CacheControl=IMMUTABLE,
                    ContentMD5=base64.b64encode(bytes.fromhex(asset.md5)).decode("ascii"),
                    Metadata={"sha256": asset.sha256},
                    IfNoneMatch="*",
                )
            return "uploaded"
        except Exception as error:
            if not is_bucket_error(error) or error_status(error) not in CONFLICT_STATUSES:
                raise
        existing = head(client, bucket, key)
        if existing is not None:
            if existing.get("Metadata", {}).get("sha256") != asset.sha256 or existing.get("ContentLength") != asset.size:
                raise MirrorError(f"{key} already holds a different file; the mirror never replaces one")
            return "already mirrored"
        time.sleep(2 * (attempt + 1))  # a concurrent upload of the same key
    raise MirrorError(f"{key} kept changing while it was uploaded")


def head(client: Any, bucket: str, key: str) -> dict[str, Any] | None:
    try:
        return client.head_object(Bucket=bucket, Key=key)
    except Exception as error:
        if is_bucket_error(error) and error_status(error) == 404:
            return None
        raise


def upload(client: Any, bucket: str, directory: Path, tag: str, assets: list[Asset], prefix: str) -> list[tuple[str, str]]:
    outcomes = []
    for asset in assets:
        key = object_key(prefix, tag, asset.name)
        outcomes.append((key, put_release_file(client, bucket, key, directory / asset.name, asset)))
    return outcomes


def read_channel(client: Any, bucket: str, key: str) -> tuple[dict[str, Any] | None, str | None]:
    """A channel file's manifest and ETag, or (None, None) when it is missing."""
    try:
        response = client.get_object(Bucket=bucket, Key=key)
    except Exception as error:
        if is_bucket_error(error) and error_status(error) == 404:
            return None, None
        raise
    try:
        manifest = json.loads(response["Body"].read())
    except ValueError:
        manifest = {}
    return manifest, response.get("ETag")


def replaces(current: dict[str, Any] | None, manifest: dict[str, Any]) -> bool:
    """Whether a channel file may point at manifest's release instead."""
    if current is None:
        return True
    try:
        return parse_tag(str(current.get("tag", ""))) <= parse_tag(manifest["tag"])
    except MirrorError:
        return True  # an unreadable channel file is repaired, not kept


def put_short_lived(client: Any, bucket: str, key: str, body: bytes, etag: str | None) -> bool:
    """Write a short-lived JSON file over the version read, or as a new key.

    False when another write got there first, so the caller reads again.
    """
    condition = {"IfMatch": etag} if etag else {"IfNoneMatch": "*"}
    try:
        client.put_object(
            Bucket=bucket, Key=key, Body=body, ContentType=JSON_TYPE, CacheControl=SHORT_LIVED, **condition
        )
    except Exception as error:
        if not is_bucket_error(error) or error_status(error) not in CONFLICT_STATUSES:
            raise
        return False
    return True


def write_channel(client: Any, bucket: str, key: str, manifest: dict[str, Any]) -> str:
    """Point a channel file at manifest's release unless it names a newer one.

    The write is conditional on what was read, so two runs for different
    releases cannot both win.
    """
    body = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    for _ in range(5):
        current, etag = read_channel(client, bucket, key)
        if current == manifest:
            return "unchanged"
        if not replaces(current, manifest):
            return f"kept, it names the newer {current.get('tag')}"
        if put_short_lived(client, bucket, key, body, etag):
            return "written"
    raise MirrorError(f"{key} kept changing while it was written")


# --- channel manifests -----------------------------------------------------


def manifest_for(plan: dict[str, Any], base: str, repo: str, prefix: str) -> dict[str, Any]:
    """The schema-1 channel manifest for a planned release."""
    tag = plan["tag"]
    entries = []
    for raw in plan["assets"]:
        asset = Asset(**raw)
        entry: dict[str, Any] = {"name": asset.name, "kind": asset.kind}
        if asset.platform:
            entry["platform"] = asset.platform
        if asset.arch:
            entry["arch"] = asset.arch
        entry.update(
            size=asset.size,
            sha256=asset.sha256,
            url=public_url(base, prefix, tag, asset.name),
            github_url=github_url(repo, tag, asset.name),
        )
        if asset.checksums_name:
            entry["checksums_name"] = asset.checksums_name
        entries.append(entry)
    return {
        "schema": SCHEMA,
        "version": tag[1:],
        "tag": tag,
        "published_at": plan["published_at"],
        "release_url": plan["release_url"],
        "assets": entries,
    }


def channel_keys(plan: dict[str, Any], github_latest_tag: str, prefix: str) -> list[str]:
    """The channel files a release may update.

    latest.json carries only GitHub's latest stable release; pre.json the
    newest release of any kind, for those who take release candidates.
    """
    keys = [PRE_KEY]
    if not plan["prerelease"] and plan["tag"] == github_latest_tag:
        keys.insert(0, LATEST_KEY)
    return [prefix + key for key in keys]


# --- update manifests ------------------------------------------------------
#
# The packaged desktop app learns of updates from a signed release manifest
# (servonaut.distribution). These are built, signed and checked with that
# same code, imported from the checkout only by the subcommands that need it.

Signer = tuple[Any, str]
PolicyFor = Callable[[str], Any]


def timestamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def manifest_version(tag: str) -> str:
    """The Semantic Version an update manifest gives a release.

    A candidate vX.Y.ZrcN becomes X.Y.Z-rc.N, which sorts after the
    candidates before it and before the release X.Y.Z.
    """
    version = parse_tag(tag)
    release = f"{version.major}.{version.minor}.{version.patch}"
    return release if version.final else f"{release}-rc.{version.candidate}"


def manifest_tag(product_version: object) -> str:
    """The release tag an update manifest's product version names."""
    match = MANIFEST_VERSION.fullmatch(product_version) if isinstance(product_version, str) else None
    if not match:
        # Manifest content is untrusted, so only a short excerpt is echoed.
        raise MirrorError(f"{str(product_version)[:40]!r} is not the version of a release")
    major, minor, patch, candidate = match.groups()
    return f"v{major}.{minor}.{patch}" + (f"rc{candidate}" if candidate else "")


def manifest_order(data: Any) -> tuple[Version, int] | None:
    """Where a stored update manifest's release sorts, or None when it names none."""
    if not isinstance(data, dict):
        return None
    try:
        version = parse_tag(manifest_tag(data.get("product_version")))
    except MirrorError:
        return None
    revision = data.get("packaging_revision")
    return version, revision if type(revision) is int else 0


def parse_days(name: str, value: str, default: int) -> int:
    """A whole number of days from a repository variable, or its default when unset."""
    value = value.strip()
    if not value:
        return default
    if not re.fullmatch(r"[1-9][0-9]{0,2}", value):
        raise MirrorError(f"The repository variable {name} must be a whole number of days, not {value[:20]!r}")
    return int(value)


def manifest_days(validity: str, refresh: str) -> tuple[int, int]:
    """How long a signed manifest is valid, and how close to its expiry it is re-signed."""
    validity_days = parse_days("RELEASE_MANIFEST_VALIDITY_DAYS", validity, DEFAULT_VALIDITY_DAYS)
    refresh_days = parse_days("RELEASE_MANIFEST_REFRESH_DAYS", refresh, DEFAULT_REFRESH_DAYS)
    if validity_days > MAX_VALIDITY_DAYS:
        raise MirrorError(f"RELEASE_MANIFEST_VALIDITY_DAYS may be at most {MAX_VALIDITY_DAYS}")
    if refresh_days >= validity_days:
        raise MirrorError("RELEASE_MANIFEST_REFRESH_DAYS must be fewer than RELEASE_MANIFEST_VALIDITY_DAYS")
    return validity_days, refresh_days


def signing_configured() -> bool:
    return bool(os.environ.get("RELEASE_MANIFEST_SIGNING_KEY", "").strip()) and bool(
        os.environ.get("RELEASE_MANIFEST_KEY_ID", "").strip()
    )


def manifest_signer() -> Signer | None:
    """The manifest signing key and its id, or None while either is unset.

    Both come from the environment, never the command line, and the key is
    only ever held in memory.
    """
    if not signing_configured():
        return None
    key_id = os.environ["RELEASE_MANIFEST_KEY_ID"].strip()
    if not KEY_ID_PATTERN.fullmatch(key_id):
        raise MirrorError("RELEASE_MANIFEST_KEY_ID must be a short id of letters, digits, '.', '_' and '-'")
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pem = os.environ["RELEASE_MANIFEST_SIGNING_KEY"].strip().encode("utf-8")
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        key = None
    if not isinstance(key, Ed25519PrivateKey):
        # What was found is a secret, so it is never described.
        raise MirrorError("RELEASE_MANIFEST_SIGNING_KEY is not an unencrypted Ed25519 private key in PEM form")
    return key, key_id


def app_trust_policy(build_channel: str) -> Any:
    """The trust policy app builds on build_channel check update manifests with.

    It is the app's own, built from the keys and download origins the app
    pins; None while the app pins no key.
    """
    from servonaut.distribution import ReleaseChannel, release_trust_policy

    return release_trust_policy(ReleaseChannel(build_channel))


def trust_policy(build_channel: str, policy_for: PolicyFor | None) -> Any:
    policy = (policy_for or app_trust_policy)(build_channel)
    if policy is None:
        raise MirrorError("The app pins no release key, so it would refuse every update manifest")
    return policy


def signed_manifest(
    product_version: str,
    *,
    channel: Any,
    packaging_revision: int | None,
    artifacts: Iterable[Any],
    signer: Signer,
    now: datetime,
    validity_days: int,
) -> Any:
    """A manifest of a release's artifacts, published now and signed for validity_days."""
    from servonaut.distribution import ManifestBuilder, ManifestError

    try:
        builder = ManifestBuilder(
            product_version,
            channel=channel,
            packaging_revision=packaging_revision,
            published_at=timestamp(now),
            expires_at=timestamp(now + timedelta(days=validity_days)),
        )
        for artifact in artifacts:
            builder.add_artifact(artifact)
        return builder.build_signed(*signer)
    except ManifestError as error:
        raise MirrorError(f"The update manifest of {product_version} cannot be built: {error}") from None


def update_manifest(
    plan: dict[str, Any], base: str, prefix: str, signer: Signer, now: datetime, validity_days: int
) -> Any | None:
    """The signed update manifest of a release's mirrored desktop files, or None without any."""
    from servonaut.distribution import (
        ArtifactKind,
        ManifestError,
        ReleaseArtifact,
        ReleaseChannel,
        normalize_arch,
        normalize_platform,
    )
    from servonaut.runtime import DistributionKind

    tag = plan["tag"]
    desktop = [Asset(**raw) for raw in plan["assets"] if raw["kind"] in DESKTOP_KINDS]
    if not desktop:
        return None
    artifacts = []
    try:
        for asset in desktop:
            kind, min_os = DESKTOP_KINDS[asset.kind]
            platform, arch = normalize_platform(asset.platform), normalize_arch(asset.arch)
            artifacts.append(
                ReleaseArtifact(
                    artifact_id=f"{kind}-{platform}-{arch}",
                    kind=ArtifactKind(kind),
                    distribution=DistributionKind.PACKAGED_DESKTOP,
                    platform=platform,
                    arch=arch,
                    filename=asset.name,
                    download_url=public_url(base, prefix, tag, asset.name),
                    byte_size=asset.size,
                    sha256=asset.sha256,
                    min_os=min_os,
                )
            )
    except ManifestError as error:
        raise MirrorError(f"The update manifest of {tag} cannot list its files: {error}") from None
    # The tag decides the channel, as it does for the release builds.
    channel = ReleaseChannel.STABLE if parse_tag(tag).final else ReleaseChannel.PREVIEW
    return signed_manifest(
        manifest_version(tag),
        channel=channel,
        packaging_revision=PACKAGING_REVISION,
        artifacts=artifacts,
        signer=signer,
        now=now,
        validity_days=validity_days,
    )


def published_manifest(manifest: Any, build_channel: str, now: datetime, policy_for: PolicyFor | None = None) -> bytes:
    """The bytes to upload, once the app's own trust policy accepts them.

    They are read back the way the app reads them, so a manifest the app
    would refuse, or one in which a host would find no single update, is
    never published.
    """
    from servonaut.distribution import (
        ManifestError,
        ReleaseManifest,
        canonicalize_json,
        resolve_target_artifact,
        verify_manifest,
    )

    policy = trust_policy(build_channel, policy_for)
    body = canonicalize_json(manifest.to_dict()) + b"\n"
    try:
        published = ReleaseManifest.from_json(body)
        verify_manifest(published, policy, now=now)
        for artifact in published.artifacts:
            resolve_target_artifact(
                published,
                artifact.distribution,
                platform_name=artifact.platform,
                machine_arch=artifact.arch,
                os_version=artifact.min_os,
            )
    except ManifestError as error:
        raise MirrorError(
            f"App builds on the {build_channel} channel would refuse the update manifest of "
            f"{manifest.product_version}: {error}"
        ) from None
    return body


def manifest_keys(plan: dict[str, Any], github_latest_tag: str, prefix: str) -> list[tuple[str, str]]:
    """The update manifests a release may update, each with the build channel that reads it.

    They follow the channel files: stable.json names the release latest.json
    names, preview.json the one channels/pre.json names.
    """
    return [
        (prefix + UPDATE_MANIFESTS[key][0], UPDATE_MANIFESTS[key][1])
        for key in channel_keys(plan, github_latest_tag, "")
    ]


def write_manifest(client: Any, bucket: str, key: str, body: bytes, order: tuple[Version, int]) -> str:
    """Upload an update manifest unless the stored one names a newer release.

    The same release is replaced, which renews its expiry; the write is
    conditional on what was read, like a channel file's.
    """
    for _ in range(5):
        current, etag = read_channel(client, bucket, key)
        current_order = manifest_order(current)
        if current_order is not None and current_order > order:
            return f"kept, it names the newer {manifest_tag(current['product_version'])}"
        if put_short_lived(client, bucket, key, body, etag):
            return "written"
    raise MirrorError(f"{key} kept changing while it was written")


def github_desktop_digests(repo: str, tag: str, fetcher: Fetcher | None = None) -> dict[str, str]:
    """The digests GitHub's desktop SHA256SUMS assets of a release list, by file name."""
    listed: dict[str, str] = {}
    for name in desktop_checksums_names(tag[1:]):
        status, _, chunks = (fetcher or fetch)(github_url(repo, tag, name))
        if status == 404:
            continue  # a release without that platform's files
        if status != 200:
            raise MirrorError(f"GitHub answered {status} for {name} of {tag}")
        listed.update(parse_sums(b"".join(chunks).decode("utf-8"), name))
    return listed


def unlisted_artifacts(manifest: Any, listed: dict[str, str]) -> list[str]:
    """The files of a manifest whose digest GitHub's SHA256SUMS do not list."""
    return [
        f"{artifact.filename}: GitHub's SHA256SUMS do not list its digest"
        for artifact in manifest.artifacts
        if listed.get(artifact.filename) != artifact.sha256
    ]


def authentic_manifest(data: Any, build_channel: str, policy_for: PolicyFor | None) -> Any:
    """A stored update manifest, once a key the app pins is found to have signed it.

    Its expiry is not checked: an expired manifest of ours is still renewed.
    """
    from servonaut.distribution import ManifestError, ReleaseManifest, verify_manifest

    policy = dataclasses.replace(trust_policy(build_channel, policy_for), require_freshness=False)
    try:
        manifest = ReleaseManifest.from_dict(data)
        verify_manifest(manifest, policy)
    except ManifestError as error:
        raise MirrorError(
            f"it is not an update manifest a pinned key signed ({error}); mirror its release again to replace it"
        ) from None
    return manifest


def refresh_manifest(
    client: Any,
    bucket: str,
    key: str,
    build_channel: str,
    signer: Signer,
    now: datetime,
    days: tuple[int, int],
    repo: str,
    fetcher: Fetcher | None = None,
    policy_for: PolicyFor | None = None,
) -> str:
    """Re-sign an update manifest with a fresh expiry once fewer than the refresh days remain.

    Only a manifest a pinned key signed is renewed, with its release and
    files unchanged, and only while GitHub's SHA256SUMS still list them.
    """
    from servonaut.distribution.manifest import parse_timestamp

    validity_days, refresh_days = days
    for _ in range(5):
        current, etag = read_channel(client, bucket, key)
        if current is None:
            return "missing; mirroring the newest release again writes it"
        manifest = authentic_manifest(current, build_channel, policy_for)
        if manifest.expires_at and parse_timestamp(manifest.expires_at) - now >= timedelta(days=refresh_days):
            return f"valid until {manifest.expires_at}, not due"
        tag = manifest_tag(manifest.product_version)
        unlisted = unlisted_artifacts(manifest, github_desktop_digests(repo, tag, fetcher))
        if unlisted:
            raise MirrorError(f"{unlisted[0]}, so it is not re-signed")
        renewed = signed_manifest(
            manifest.product_version,
            channel=manifest.channel,
            packaging_revision=manifest.packaging_revision,
            artifacts=manifest.artifacts,
            signer=signer,
            now=now,
            validity_days=validity_days,
        )
        if put_short_lived(client, bucket, key, published_manifest(renewed, build_channel, now, policy_for), etag):
            return f"re-signed, valid until {renewed.expires_at}"
    raise MirrorError(f"{key} kept changing while it was re-signed")


# --- release notes ---------------------------------------------------------


def desktop_label(asset: Asset) -> str:
    if asset.kind == "desktop-deb":
        return "Linux (.deb)"
    return "macOS on Apple silicon" if asset.arch == "arm64" else "macOS on Intel"


def notes_block(plan: dict[str, Any], base: str, prefix: str, download_page: str) -> str | None:
    """The release-notes paragraph that links the mirrored desktop packages."""
    desktop = [Asset(**raw) for raw in plan["assets"] if raw["kind"] in DESKTOP_KINDS]
    if not desktop:
        return None
    lines = [
        NOTES_START,
        "### Faster download",
        "",
        "The desktop preview is also served from the release mirror, which stays fast on slow or "
        "lossy connections. These are the same files as the assets below; check each against the "
        "SHA256SUMS asset named next to it.",
        "",
    ]
    for asset in desktop:
        url = public_url(base, prefix, plan["tag"], asset.name)
        lines.append(f"- {desktop_label(asset)}: [{asset.name}]({url}), listed in `{asset.checksums_name}`")
    if not plan["prerelease"] and download_page:
        lines += ["", f"Every way to install Servonaut: {download_page}"]
    lines.append(NOTES_END)
    return "\n".join(lines)


def notes_block_span(body: str) -> tuple[int, int] | None:
    """Where the mirror block sits in the release notes, if it is there."""
    start, end = body.find(NOTES_START), body.find(NOTES_END)
    if start == -1 and end == -1:
        return None
    if start == -1 or end < start:
        raise MirrorError("The release notes hold half a mirror block; fix them by hand")
    return start, end + len(NOTES_END)


def with_notes_block(body: str | None, block: str) -> str:
    """The release notes with the mirror block added, or replaced in place."""
    body = body or ""
    span = notes_block_span(body)
    if span is not None:
        return body[: span[0]] + block + body[span[1]:]
    stripped = body.rstrip()
    return f"{stripped}\n\n{block}\n" if stripped else f"{block}\n"


def without_notes_block(body: str | None) -> str:
    """The release notes without the mirror block, for a package that was withdrawn."""
    body = body or ""
    span = notes_block_span(body)
    if span is None:
        return body
    parts = [part for part in (body[: span[0]].rstrip(), body[span[1]:].strip("\n")) if part]
    return "\n\n".join(parts) + "\n" if parts else ""


# --- public downloads ------------------------------------------------------


def fetch(url: str, timeout: float = 120) -> tuple[int, dict[str, str], Iterable[bytes]]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        response = urllib.request.urlopen(request, timeout=timeout)  # noqa: S310 (https only)
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), iter(())
    headers = {key.lower(): value for key, value in response.headers.items()}

    def chunks() -> Iterable[bytes]:
        with response:
            while chunk := response.read(CHUNK):
                yield chunk

    return response.status, headers, chunks()


Fetcher = Callable[[str], tuple[int, dict[str, str], Iterable[bytes]]]


def measure(url: str, fetcher: Fetcher) -> tuple[int, dict[str, str], str, int]:
    """Status, headers, SHA-256 and size of what a URL serves."""
    status, headers, chunks = fetcher(url)
    sha256 = hashlib.sha256()
    size = 0
    for chunk in chunks:
        sha256.update(chunk)
        size += len(chunk)
    return status, headers, sha256.hexdigest(), size


def check_public(plan: dict[str, Any], base: str, prefix: str, fetcher: Fetcher = fetch) -> list[str]:
    """Download every mirrored file through its public URL and compare it."""
    report = []
    for raw in plan["assets"]:
        asset = Asset(**raw)
        url = public_url(base, prefix, plan["tag"], asset.name)
        status, headers, sha256, size = measure(url, fetcher)
        if status != 200:
            raise MirrorError(f"{url} answered {status}")
        if (sha256, size) != (asset.sha256, asset.size):
            raise MirrorError(f"{url} does not serve the verified file")
        served_type = headers.get("content-type", "").split(";")[0].strip()
        if served_type != asset.content_type.split(";")[0]:
            raise MirrorError(f"{url} is served as {served_type or 'nothing'}, not {asset.content_type}")
        # The CDN may rewrite Cache-Control (its browser TTL setting does).
        if headers.get("cache-control") != IMMUTABLE:
            raise MirrorError(f"{url} is served with Cache-Control {headers.get('cache-control')!r}, not {IMMUTABLE!r}")
        report.append(f"{url} ({headers.get('cf-cache-status', 'no cache status')})")
    return report


# --- audit -----------------------------------------------------------------


def fetch_channel(url: str, fetcher: Fetcher) -> dict[str, Any]:
    """A channel file as served: short-lived JSON, so a new release shows within minutes."""
    status, headers, chunks = fetcher(url)
    if status != 200:
        raise MirrorError(f"{url} answered {status}")
    if headers.get("cache-control") != SHORT_LIVED:
        raise MirrorError(f"{url} is served with Cache-Control {headers.get('cache-control')!r}, not {SHORT_LIVED!r}")
    try:
        data = json.loads(b"".join(chunks))
    except ValueError as error:
        raise MirrorError(f"{url} is not JSON") from error
    if not isinstance(data, dict):
        raise MirrorError(f"{url} is not a JSON object")
    return data


def manifest_problems(manifest: dict[str, Any], base: str, repo: str) -> list[str]:
    """Where a channel manifest breaks the schema-1 contract."""
    problems = []
    tag = str(manifest.get("tag", ""))
    if manifest.get("schema") != SCHEMA:
        problems.append("schema is not 1")
    if not TAG_PATTERN.match(tag) or manifest.get("version") != tag[1:]:
        problems.append("tag and version do not name one release")
    assets = manifest.get("assets")
    if not isinstance(assets, list):
        return problems + ["assets is not a list"]
    for entry in assets:
        name = str(entry.get("name", ""))
        if entry.get("url") != f"{base.rstrip('/')}/{tag}/{name}":
            problems.append(f"{name}: url is not the mirror's address for it")
        if entry.get("github_url") != github_url(repo, tag, name):
            problems.append(f"{name}: github_url is not GitHub's address for it")
        if not SHA256_PATTERN.match(str(entry.get("sha256", ""))) or not isinstance(entry.get("size"), int):
            problems.append(f"{name}: sha256 or size is malformed")
    return problems


def asset_problems(entry: dict[str, Any], github_sums: dict[str, dict[str, str]], fetcher: Fetcher) -> list[str]:
    """Where a listed file differs between the manifest, the mirror and GitHub."""
    name = entry["name"]
    status, _, sha256, size = measure(entry["url"], fetcher)
    if status != 200:
        return [f"{name}: the mirror answered {status}"]
    if (sha256, size) != (entry["sha256"], entry["size"]):
        return [f"{name}: the mirror serves a file other than the manifest names"]
    checksums = entry.get("checksums_name")
    if checksums:
        listed = github_sums.get(checksums, {}).get(name)
        if listed != sha256:
            return [f"{name}: GitHub's {checksums} lists a different digest"]
    elif entry.get("kind") == "checksums":
        _, _, github_sha256, _ = measure(entry["github_url"], fetcher)
        if github_sha256 != sha256:
            return [f"{name}: differs from GitHub's copy"]
    return []


def github_sums_for(manifest: dict[str, Any], fetcher: Fetcher) -> dict[str, dict[str, str]]:
    sums: dict[str, dict[str, str]] = {}
    for entry in manifest.get("assets", []):
        if entry.get("kind") == "checksums":
            status, _, chunks = fetcher(entry["github_url"])
            if status == 200:
                sums[entry["name"]] = parse_sums(b"".join(chunks).decode("utf-8"), entry["name"])
    return sums


def release_mismatch(manifest: Any, tag: str, channel: dict[str, Any], channel_key: str) -> list[str]:
    """Where an update manifest names other desktop files than its channel file.

    A release without desktop files leaves the update manifest at the newest
    release that had them, so only a newer one is wrong then.
    """
    desktop = {
        entry["name"]: (entry["sha256"], entry["size"])
        for entry in channel["assets"]
        if entry.get("kind") in DESKTOP_KINDS
    }
    if not desktop:
        if parse_tag(tag) > parse_tag(channel["tag"]):
            return [f"names {tag}, which is newer than {channel['tag']} in {channel_key}"]
        return []
    if tag != channel["tag"]:
        return [f"names {tag}, but {channel_key} names {channel['tag']}"]
    if {artifact.filename: (artifact.sha256, artifact.byte_size) for artifact in manifest.artifacts} != desktop:
        return [f"lists other desktop files than {channel_key}"]
    return []


def update_manifest_problems(
    base: str,
    repo: str,
    key: str,
    build_channel: str,
    channel: tuple[str, dict[str, Any] | None],
    now: datetime,
    refresh_days: int,
    fetcher: Fetcher,
    policy_for: PolicyFor | None = None,
) -> list[str]:
    """Where a published update manifest breaks what the app and GitHub expect.

    channel is the channel file it follows and that file's manifest, or
    None when the file itself failed the audit.
    """
    from servonaut.distribution import ManifestError, ReleaseManifest, verify_manifest
    from servonaut.distribution.manifest import parse_timestamp

    try:
        data = fetch_channel(f"{base.rstrip('/')}/{key}", fetcher)
        policy = trust_policy(build_channel, policy_for)
    except MirrorError as error:
        return [str(error)]
    try:
        manifest = ReleaseManifest.from_dict(data)
        verify_manifest(manifest, policy, now=now)
    except ManifestError as error:
        return [f"app builds on the {build_channel} channel refuse it: {error}"]
    try:
        tag = manifest_tag(manifest.product_version)
        listed = github_desktop_digests(repo, tag, fetcher)
    except MirrorError as error:
        return [str(error)]
    problems = []
    # The refresh re-signs a manifest once fewer than refresh_days remain; a
    # day of slack keeps the audit from racing it.
    if manifest.expires_at and parse_timestamp(manifest.expires_at) - now < timedelta(days=refresh_days - 1):
        problems.append(f"expires at {manifest.expires_at} and was not re-signed in time")
    for artifact in manifest.artifacts:
        if artifact.download_url != public_url(base, "", tag, artifact.filename):
            problems.append(f"{artifact.filename}: download_url is not the mirror's address for it")
    problems += unlisted_artifacts(manifest, listed)
    channel_key, channel_manifest = channel
    if channel_manifest is not None:
        problems += release_mismatch(manifest, tag, channel_manifest, channel_key)
    return problems


def audit(
    base: str,
    repo: str,
    github_latest_tag: str,
    github_latest_published_at: str,
    now: datetime,
    fetcher: Fetcher = fetch,
    grace: timedelta = timedelta(hours=6),
    manifests: bool = False,
    refresh_days: int = DEFAULT_REFRESH_DAYS,
    policy_for: PolicyFor | None = None,
) -> list[str]:
    """Every way the published channel files, and the update manifests when signed, disagree with GitHub."""
    problems: list[str] = []
    channels: dict[str, dict[str, Any] | None] = {}
    for key in (LATEST_KEY, PRE_KEY):
        url = f"{base.rstrip('/')}/{key}"
        channels[key] = None
        try:
            manifest = fetch_channel(url, fetcher)
        except MirrorError as error:
            problems.append(f"{key}: {error}")
            continue
        found = manifest_problems(manifest, base, repo)
        if not found:
            sums = github_sums_for(manifest, fetcher)
            for entry in manifest["assets"]:
                found += asset_problems(entry, sums, fetcher)
        problems += [f"{key}: {problem}" for problem in found]
        if not found:
            channels[key] = manifest
        if key == LATEST_KEY and not found and github_latest_tag and manifest.get("tag") != github_latest_tag:
            published = datetime.fromisoformat(github_latest_published_at.replace("Z", "+00:00"))
            if now - published > grace:
                problems.append(f"{key}: names {manifest.get('tag')}, but GitHub's latest release is {github_latest_tag}")
    if manifests:
        for channel_key, (key, build_channel) in UPDATE_MANIFESTS.items():
            found = update_manifest_problems(
                base, repo, key, build_channel, (channel_key, channels[channel_key]), now, refresh_days, fetcher, policy_for
            )
            problems += [f"{key}: {problem}" for problem in found]
    return problems


# --- command line ----------------------------------------------------------


def write_summary(lines: Iterable[str]) -> None:
    text = "\n".join(lines) + "\n"
    print(text, end="")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(text)


def set_output(name: str, value: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


NO_SIGNING_KEY = (
    "RELEASE_MANIFEST_SIGNING_KEY or RELEASE_MANIFEST_KEY_ID is not set in the release-mirror "
    "environment, so the update manifests are not signed."
)


def notice(message: str) -> None:
    print(f"::notice::{message}")


def load_plan(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def command_verify(args: argparse.Namespace) -> None:
    release = json.loads(Path(args.release_json).read_text(encoding="utf-8"))
    tag = release.get("tag_name", "")
    parse_tag(tag)
    if release.get("draft"):
        raise MirrorError(f"{tag} is a draft; only published releases are mirrored")
    sizes = {asset["name"]: asset["size"] for asset in release.get("assets", [])}
    assets, notices = verify(Path(args.dir), tag, sizes)
    plan = {
        "tag": tag,
        "prerelease": bool(release.get("prerelease")),
        "published_at": release.get("published_at"),
        "release_url": release.get("html_url"),
        "assets": [asdict(asset) for asset in assets],
    }
    Path(args.out).write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    deb = next((asset.name for asset in assets if asset.kind == "desktop-deb"), "")
    set_output("desktop-deb", deb)
    set_output("desktop-dmgs", " ".join(asset.name for asset in assets if asset.kind == "desktop-dmg"))
    set_output("asset-count", str(len(assets)))
    lines = [f"### Verified files of {tag}", ""]
    lines += [f"- `{asset.name}` ({asset.kind}, {asset.size} bytes, sha256 `{asset.sha256}`)" for asset in assets]
    lines += [f"- {notice}" for notice in notices]
    if not assets:
        lines.append("- nothing to mirror")
    write_summary(lines)


def command_upload(args: argparse.Namespace) -> None:
    plan = load_plan(args.plan)
    prefix = check_prefix(args.prefix)
    client, bucket = bucket_client()
    assets = [Asset(**raw) for raw in plan["assets"]]
    outcomes = upload(client, bucket, Path(args.dir), plan["tag"], assets, prefix)
    write_summary(["### Uploads", ""] + [f"- `{key}`: {outcome}" for key, outcome in outcomes])


def command_check_public(args: argparse.Namespace) -> None:
    plan = load_plan(args.plan)
    report = check_public(plan, args.base, check_prefix(args.prefix))
    write_summary(["### Public downloads", ""] + [f"- {line}" for line in report])


def command_channels(args: argparse.Namespace) -> None:
    plan = load_plan(args.plan)
    prefix = check_prefix(args.prefix)
    if not plan["assets"]:
        write_summary(["### Channels", "", "- nothing was mirrored, so no channel changes"])
        return
    manifest = manifest_for(plan, args.base, args.repo, prefix)
    keys = channel_keys(plan, args.github_latest_tag, prefix)
    if args.dry_run:
        write_summary(["### Channels (dry run)", ""] + [f"- `{key}` would name {plan['tag']}" for key in keys])
        return
    client, bucket = bucket_client()
    outcomes = [(key, write_channel(client, bucket, key, manifest)) for key in keys]
    write_summary(["### Channels", ""] + [f"- `{key}`: {outcome}" for key, outcome in outcomes])


def command_manifests(args: argparse.Namespace) -> None:
    plan = load_plan(args.plan)
    prefix = check_prefix(args.prefix)
    title = "### Update manifests" + (" (dry run)" if args.dry_run else "")
    signer = manifest_signer()
    if signer is None:
        notice(NO_SIGNING_KEY)
        write_summary([title, "", "- skipped: no signing key is configured"])
        return
    validity_days, _ = manifest_days(args.validity_days, args.refresh_days)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    manifest = update_manifest(plan, args.base, prefix, signer, now, validity_days)
    if manifest is None:
        write_summary([title, "", "- no desktop files were mirrored, so the update manifests stay as they are"])
        return
    # Each is checked before anything is written, so a refusal changes nothing.
    bodies = [
        (key, published_manifest(manifest, build_channel, now))
        for key, build_channel in manifest_keys(plan, args.github_latest_tag, prefix)
    ]
    if args.dry_run:
        write_summary(
            [title, ""]
            + [f"- `{key}` would name {plan['tag']}, valid until {manifest.expires_at}" for key, _ in bodies]
        )
        return
    order = (parse_tag(plan["tag"]), PACKAGING_REVISION)
    client, bucket = bucket_client()
    outcomes = [(key, write_manifest(client, bucket, key, body, order)) for key, body in bodies]
    write_summary([title, ""] + [f"- `{key}`: {outcome}" for key, outcome in outcomes])


def command_refresh(args: argparse.Namespace) -> None:
    # The audit checks the update manifests only once they are signed.
    set_output("signing", "true" if signing_configured() else "false")
    title = "### Update manifest refresh"
    signer = manifest_signer()
    if signer is None:
        notice(NO_SIGNING_KEY)
        write_summary([title, "", "- skipped: no signing key is configured"])
        return
    days = manifest_days(args.validity_days, args.refresh_days)
    prefix = check_prefix(args.prefix)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    client, bucket = bucket_client()
    lines, failures = [title, ""], []
    for manifest_key, build_channel in UPDATE_MANIFESTS.values():
        key = prefix + manifest_key
        try:
            outcome = refresh_manifest(client, bucket, key, build_channel, signer, now, days, args.repo, fetch)
        except MirrorError as error:
            failures.append(f"{key}: {error}")
            outcome = f"failed: {error}"
        lines.append(f"- `{key}`: {outcome}")
    write_summary(lines)
    if failures:
        raise MirrorError("; ".join(failures))


def command_notes(args: argparse.Namespace) -> None:
    plan = load_plan(args.plan)
    block = notes_block(plan, args.base, check_prefix(args.prefix), args.download_page)
    body = Path(args.body_file).read_text(encoding="utf-8")
    # Without a mirrored package, an earlier link to one must go.
    updated = without_notes_block(body) if block is None else with_notes_block(body, block)
    Path(args.out).write_text(updated, encoding="utf-8")
    set_output("changed", "true" if updated != body else "false")
    print("release notes " + ("changed" if updated != body else "unchanged"))


def command_audit(args: argparse.Namespace) -> None:
    refresh_days = parse_days("RELEASE_MANIFEST_REFRESH_DAYS", args.refresh_days, DEFAULT_REFRESH_DAYS)
    problems = audit(
        args.base,
        args.repo,
        args.github_latest_tag,
        args.github_latest_published_at,
        datetime.now(timezone.utc),
        fetch,
        manifests=args.manifests,
        refresh_days=refresh_days,
    )
    if args.refresh_result and args.refresh_result != "success":
        problems.append(f"the update manifest refresh ended with {args.refresh_result}, see its log")
    checked = "the channel files and every file they list"
    if args.manifests:
        checked += ", and the update manifests,"
    lines = ["### Release mirror audit", ""]
    lines += [f"- {problem}" for problem in problems] or [f"- {checked} match GitHub"]
    write_summary(lines)
    if args.report:
        Path(args.report).write_text("\n".join(lines) + "\n", encoding="utf-8")
    if problems:
        raise MirrorError(f"The mirror disagrees with GitHub in {len(problems)} place(s)")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = root.add_subparsers(dest="command", required=True)
    verify_cmd = commands.add_parser("verify")
    verify_cmd.add_argument("--dir", required=True)
    verify_cmd.add_argument("--release-json", required=True)
    verify_cmd.add_argument("--out", required=True)
    for name in ("upload", "check-public", "channels", "manifests", "notes"):
        sub = commands.add_parser(name)
        sub.add_argument("--plan", required=True)
        sub.add_argument("--prefix", default="")
        if name == "upload":
            sub.add_argument("--dir", required=True)
        else:
            sub.add_argument("--base", required=True)
    channels_cmd = commands.choices["channels"]
    channels_cmd.add_argument("--repo", required=True)
    channels_cmd.add_argument("--github-latest-tag", required=True)
    channels_cmd.add_argument("--dry-run", action="store_true")
    manifests_cmd = commands.choices["manifests"]
    manifests_cmd.add_argument("--github-latest-tag", required=True)
    manifests_cmd.add_argument("--dry-run", action="store_true")
    refresh_cmd = commands.add_parser("refresh")
    refresh_cmd.add_argument("--repo", required=True)
    refresh_cmd.add_argument("--prefix", default="")
    # Empty values, from unset repository variables, mean the defaults.
    for sub in (manifests_cmd, refresh_cmd):
        sub.add_argument("--validity-days", default="")
        sub.add_argument("--refresh-days", default="")
    notes_cmd = commands.choices["notes"]
    notes_cmd.add_argument("--body-file", required=True)
    notes_cmd.add_argument("--out", required=True)
    notes_cmd.add_argument("--download-page", default="")
    audit_cmd = commands.add_parser("audit")
    audit_cmd.add_argument("--base", required=True)
    audit_cmd.add_argument("--repo", required=True)
    audit_cmd.add_argument("--github-latest-tag", required=True)
    audit_cmd.add_argument("--github-latest-published-at", required=True)
    audit_cmd.add_argument("--report", default="")
    audit_cmd.add_argument("--manifests", action="store_true")
    audit_cmd.add_argument("--refresh-days", default="")
    audit_cmd.add_argument("--refresh-result", default="")
    return root


COMMANDS = {
    "verify": command_verify,
    "upload": command_upload,
    "check-public": command_check_public,
    "channels": command_channels,
    "manifests": command_manifests,
    "notes": command_notes,
    "refresh": command_refresh,
    "audit": command_audit,
}


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        COMMANDS[args.command](args)
    except MirrorError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    except Exception as error:
        if not is_bucket_error(error):
            raise
        # botocore's own text can name the endpoint; report the code only.
        print(f"::error::The bucket refused the request ({error_code(error)})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
