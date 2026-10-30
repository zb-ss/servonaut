"""The release mirror: its script against an in-memory bucket, and its workflow's contract.

The bucket stand-in enforces the conditional writes the real store honours
(If-None-Match, If-Match, Content-MD5), so the "never replace a published
file" and "never move a channel backwards" rules are exercised, not mocked.
Update manifests are signed with a key generated for the test and checked
with a trust policy that pins it, the way the app pins its release keys.
The workflow's resolve step runs for real under bash.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from servonaut.distribution import (
    OperatingSystemTooOldError,
    ReleaseChannel,
    ReleaseManifest,
    TrustPolicy,
    canonicalize_json,
    channels_accepted_by,
    parse_semver,
    release_trust_policy,
    resolve_target_artifact,
    trust_root,
    verify_manifest,
)
from servonaut.distribution.manifest import parse_timestamp
from servonaut.runtime import DistributionKind

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github/scripts/release-mirror.py"
WORKFLOWS = ROOT / ".github/workflows"
WORKFLOW = WORKFLOWS / "release-mirror.yml"
REQUIREMENTS = ROOT / ".github/requirements/release-mirror.txt"
REPO = "example-org/example-app"
BASE = "https://mirror.example.org"


def _load():
    spec = importlib.util.spec_from_file_location("release_mirror", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # Dataclasses resolve their annotations through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


mirror = _load()


# ---------------------------------------------------------------------------
# Fixtures: a release on disk and a bucket that enforces conditional writes
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _subdir(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.mkdir()
    return path


def _release(
    tmp_path: Path, version: str = "1.2.3", extra: dict[str, bytes] | None = None, macos: bool = False
) -> tuple[Path, dict[str, int]]:
    """A downloaded release: desktop package, install scripts and their SUMS files.

    With macos, also the two macOS disk images and the SUMS file that lists them.
    """
    files = {
        f"servonaut-desktop-preview_{version}_amd64.deb": b"deb payload " * 100,
        "install.sh": b"#!/bin/sh\necho install\n",
        "install.ps1": b"Write-Output install\n",
    }
    deb = f"servonaut-desktop-preview_{version}_amd64.deb"
    files[f"servonaut-desktop-preview_{version}_SHA256SUMS"] = f"{_sha256(files[deb])}  {deb}\n".encode()
    files["install-scripts_SHA256SUMS"] = (
        f"{_sha256(files['install.sh'])}  install.sh\n{_sha256(files['install.ps1'])}  install.ps1\n".encode()
    )
    if macos:
        dmgs = {
            f"servonaut-desktop-preview_{version}_{target}.dmg": f"{target} image ".encode() * 50
            for target in ("macos-arm64", "macos-x64")
        }
        files.update(dmgs)
        files[f"servonaut-desktop-preview_{version}_macos_SHA256SUMS"] = "".join(
            f"{_sha256(data)}  {name}\n" for name, data in dmgs.items()
        ).encode()
    files.update(extra or {})
    directory = tmp_path / "files"
    directory.mkdir(exist_ok=True)
    for name, data in files.items():
        (directory / name).write_bytes(data)
    return directory, {name: len(data) for name, data in files.items()}


def _plan(tmp_path: Path, tag: str = "v1.2.3", prerelease: bool = False, macos: bool = False) -> tuple[Path, dict[str, Any]]:
    directory, sizes = _release(tmp_path, tag[1:], macos=macos)
    assets, _ = mirror.verify(directory, tag, sizes)
    plan = {
        "tag": tag,
        "prerelease": prerelease,
        "published_at": "2026-01-02T03:04:05Z",
        "release_url": f"https://github.com/{REPO}/releases/tag/{tag}",
        "assets": [mirror.asdict(asset) for asset in assets],
    }
    return directory, plan


def _error(status: int, code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "refused"}, "ResponseMetadata": {"HTTPStatusCode": status}}, "Op")


class FakeBucket:
    """An object store with the conditional writes R2 honours."""

    def __init__(self) -> None:
        self.objects: dict[str, dict[str, Any]] = {}
        self.puts: list[dict[str, Any]] = []
        self.fail_puts: list[ClientError] = []

    def put_object(self, *, Bucket: str, Key: str, Body: Any, ContentType: str, CacheControl: str,
                   Metadata: dict[str, str] | None = None, ContentMD5: str | None = None,
                   IfNoneMatch: str | None = None, IfMatch: str | None = None) -> dict[str, str]:
        data = Body.read() if hasattr(Body, "read") else Body
        self.puts.append({"Key": Key, "IfNoneMatch": IfNoneMatch, "IfMatch": IfMatch, "ContentMD5": ContentMD5})
        if self.fail_puts:
            raise self.fail_puts.pop(0)
        if ContentMD5 is not None and ContentMD5 != base64.b64encode(hashlib.md5(data).digest()).decode():
            raise _error(400, "BadDigest")
        existing = self.objects.get(Key)
        if IfNoneMatch == "*" and existing is not None:
            raise _error(412, "PreconditionFailed")
        if IfMatch is not None and (existing is None or existing["etag"] != IfMatch):
            raise _error(412, "PreconditionFailed")
        etag = f'"{hashlib.md5(data).hexdigest()}"'
        self.objects[Key] = {"data": data, "etag": etag, "type": ContentType, "cache": CacheControl, "meta": Metadata or {}}
        return {"ETag": etag}

    def head_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        if Key not in self.objects:
            raise _error(404, "404")
        stored = self.objects[Key]
        return {"Metadata": stored["meta"], "ContentLength": len(stored["data"]), "ETag": stored["etag"]}

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        if Key not in self.objects:
            raise _error(404, "NoSuchKey")
        stored = self.objects[Key]
        return {"Body": io.BytesIO(stored["data"]), "ETag": stored["etag"]}


# ---------------------------------------------------------------------------
# Tags and SUMS files
# ---------------------------------------------------------------------------


def test_a_final_release_sorts_after_its_candidates() -> None:
    assert mirror.parse_tag("v2.30.0rc7") < mirror.parse_tag("v2.30.0")
    assert mirror.parse_tag("v2.30.0rc2") < mirror.parse_tag("v2.30.0rc10")
    assert mirror.parse_tag("v2.29.9") < mirror.parse_tag("v2.30.0rc1")


@pytest.mark.parametrize("tag", ["2.30.0", "v2.30", "v2.30.0-rc1", "v02.30.0", "v2.30.0rc0", "master"])
def test_only_release_tags_are_accepted(tag: str) -> None:
    with pytest.raises(mirror.MirrorError):
        mirror.parse_tag(tag)


def test_sums_files_in_text_and_binary_mode_parse() -> None:
    digest = "a" * 64
    assert mirror.parse_sums(f"{digest}  one.deb\n\n{digest} *two.sh\n", "SUMS") == {"one.deb": digest, "two.sh": digest}


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not a digest  file\n",
        f"{'A' * 64}  upper.deb\n",
        f"{'a' * 64}  ../escape.deb\n",
        f"{'a' * 64}  dir/file.deb\n",
        f"{'a' * 64}  same.deb\n{'b' * 64}  same.deb\n",
    ],
)
def test_malformed_sums_files_are_refused(text: str) -> None:
    with pytest.raises(mirror.MirrorError):
        mirror.parse_sums(text, "SUMS")


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def test_verified_files_carry_their_kind_type_and_checksums(tmp_path: Path) -> None:
    directory, sizes = _release(tmp_path)
    assets, notices = mirror.verify(directory, "v1.2.3", sizes)

    assert notices == []
    assert [(asset.name, asset.kind, asset.checksums_name) for asset in assets] == [
        ("servonaut-desktop-preview_1.2.3_amd64.deb", "desktop-deb", "servonaut-desktop-preview_1.2.3_SHA256SUMS"),
        ("install.ps1", "install-script", "install-scripts_SHA256SUMS"),
        ("install.sh", "install-script", "install-scripts_SHA256SUMS"),
        ("install-scripts_SHA256SUMS", "checksums", None),
        ("servonaut-desktop-preview_1.2.3_SHA256SUMS", "checksums", None),
    ]
    deb = assets[0]
    assert (deb.content_type, deb.platform, deb.arch) == ("application/vnd.debian.binary-package", "linux", "x86_64")
    assert {asset.content_type for asset in assets[1:]} == {"text/plain; charset=utf-8"}
    assert deb.sha256 == _sha256((directory / deb.name).read_bytes())


def test_a_file_that_differs_from_its_sums_entry_stops_everything(tmp_path: Path) -> None:
    directory, sizes = _release(tmp_path)
    (directory / "install.sh").write_bytes(b"#!/bin/sh\necho evil\n")
    sizes["install.sh"] = (directory / "install.sh").stat().st_size

    with pytest.raises(mirror.MirrorError, match="install.sh does not match"):
        mirror.verify(directory, "v1.2.3", sizes)


def test_files_no_sums_lists_and_unknown_files_are_skipped_with_a_notice(tmp_path: Path) -> None:
    directory, sizes = _release(tmp_path, extra={"notes.txt": b"hello\n"})
    unknown = b"other\n"
    (directory / "other.bin").write_bytes(unknown)
    sizes["other.bin"] = len(unknown)
    sums = directory / "install-scripts_SHA256SUMS"
    sums.write_bytes(sums.read_bytes() + f"{_sha256(unknown)}  other.bin\n".encode())
    sizes[sums.name] = sums.stat().st_size

    assets, notices = mirror.verify(directory, "v1.2.3", sizes)

    assert "notes.txt" not in {asset.name for asset in assets}
    assert "other.bin" not in {asset.name for asset in assets}
    assert notices == [
        "notes.txt: skipped, no SHA256SUMS asset lists it",
        "other.bin: skipped, not a file the mirror serves",
    ]


def test_an_incomplete_download_is_refused(tmp_path: Path) -> None:
    directory, sizes = _release(tmp_path)
    sizes["install.sh"] += 1

    with pytest.raises(mirror.MirrorError, match="did not download completely"):
        mirror.verify(directory, "v1.2.3", sizes)


def test_a_sums_file_listing_a_missing_file_is_refused(tmp_path: Path) -> None:
    directory, sizes = _release(tmp_path)
    (directory / "install.ps1").unlink()
    del sizes["install.ps1"]

    with pytest.raises(mirror.MirrorError, match="lists install.ps1, which the release lacks"):
        mirror.verify(directory, "v1.2.3", sizes)


def test_a_file_that_is_no_release_asset_is_refused(tmp_path: Path) -> None:
    directory, sizes = _release(tmp_path)
    (directory / "stray").write_bytes(b"x")

    with pytest.raises(mirror.MirrorError, match="not an asset of the release"):
        mirror.verify(directory, "v1.2.3", sizes)


def test_a_symlink_is_never_followed(tmp_path: Path) -> None:
    directory, sizes = _release(tmp_path)
    (directory / "link.sh").symlink_to(directory / "install.sh")
    sizes["link.sh"] = 1

    with pytest.raises(mirror.MirrorError, match="not a regular file"):
        mirror.verify(directory, "v1.2.3", sizes)


MAC_SUMS = "servonaut-desktop-preview_1.2.3_macos_SHA256SUMS"
ARM_DMG = "servonaut-desktop-preview_1.2.3_macos-arm64.dmg"
X64_DMG = "servonaut-desktop-preview_1.2.3_macos-x64.dmg"


def test_macos_disk_images_are_mirrored_against_their_own_sums(tmp_path: Path) -> None:
    directory, sizes = _release(tmp_path, macos=True)

    assets, notices = mirror.verify(directory, "v1.2.3", sizes)

    assert notices == []
    desktop = [(a.name, a.kind, a.platform, a.arch, a.checksums_name) for a in assets if a.kind.startswith("desktop-")]
    assert desktop == [
        ("servonaut-desktop-preview_1.2.3_amd64.deb", "desktop-deb", "linux", "x86_64", "servonaut-desktop-preview_1.2.3_SHA256SUMS"),
        (ARM_DMG, "desktop-dmg", "darwin", "arm64", MAC_SUMS),
        (X64_DMG, "desktop-dmg", "darwin", "x86_64", MAC_SUMS),
    ]
    assert {a.content_type for a in assets if a.kind == "desktop-dmg"} == {"application/x-apple-diskimage"}
    # The macOS SUMS never collides with the Linux one, and is mirrored as well.
    assert [a.name for a in assets if a.kind == "checksums"] == [
        "install-scripts_SHA256SUMS",
        "servonaut-desktop-preview_1.2.3_SHA256SUMS",
        MAC_SUMS,
    ]


def test_a_disk_image_that_differs_from_the_macos_sums_stops_everything(tmp_path: Path) -> None:
    directory, sizes = _release(tmp_path, macos=True)
    (directory / X64_DMG).write_bytes(b"tampered image " * 50)
    sizes[X64_DMG] = (directory / X64_DMG).stat().st_size

    with pytest.raises(mirror.MirrorError, match=f"{X64_DMG} does not match its digest in {MAC_SUMS}"):
        mirror.verify(directory, "v1.2.3", sizes)


def test_mirrored_disk_images_are_downloaded_again_and_compared(tmp_path: Path) -> None:
    directory, plan = _plan(tmp_path, macos=True)

    report = mirror.check_public(plan, BASE, "", _fetcher(_served(directory, plan)))

    assert len(report) == 8
    assert any(line.startswith(f"{BASE}/v1.2.3/{ARM_DMG} ") for line in report)


# ---------------------------------------------------------------------------
# Uploads
# ---------------------------------------------------------------------------


def test_files_are_uploaded_once_with_their_digest_and_headers(tmp_path: Path) -> None:
    directory, plan = _plan(tmp_path)
    assets = [mirror.Asset(**raw) for raw in plan["assets"]]
    bucket = FakeBucket()

    outcomes = mirror.upload(bucket, "b", directory, "v1.2.3", assets, "")

    assert [outcome for _, outcome in outcomes] == ["uploaded"] * 5
    deb = bucket.objects["v1.2.3/servonaut-desktop-preview_1.2.3_amd64.deb"]
    assert deb["type"] == "application/vnd.debian.binary-package"
    assert deb["cache"] == "public, max-age=31536000, immutable"
    assert deb["meta"] == {"sha256": assets[0].sha256}
    assert all(put["IfNoneMatch"] == "*" and put["ContentMD5"] for put in bucket.puts)


def test_a_re_run_keeps_the_files_already_mirrored(tmp_path: Path) -> None:
    directory, plan = _plan(tmp_path)
    assets = [mirror.Asset(**raw) for raw in plan["assets"]]
    bucket = FakeBucket()
    mirror.upload(bucket, "b", directory, "v1.2.3", assets, "")
    before = {key: stored["data"] for key, stored in bucket.objects.items()}

    outcomes = mirror.upload(bucket, "b", directory, "v1.2.3", assets, "")

    assert [outcome for _, outcome in outcomes] == ["already mirrored"] * 5
    assert {key: stored["data"] for key, stored in bucket.objects.items()} == before


def test_a_different_file_under_a_published_key_is_refused(tmp_path: Path) -> None:
    directory, plan = _plan(tmp_path)
    assets = [mirror.Asset(**raw) for raw in plan["assets"]]
    bucket = FakeBucket()
    bucket.objects["v1.2.3/install.sh"] = {"data": b"other", "etag": '"x"', "type": "t", "cache": "c", "meta": {"sha256": "0" * 64}}

    with pytest.raises(mirror.MirrorError, match="already holds a different file"):
        mirror.upload(bucket, "b", directory, "v1.2.3", assets, "")
    assert bucket.objects["v1.2.3/install.sh"]["data"] == b"other"


def test_a_concurrent_upload_of_the_same_key_is_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mirror.time, "sleep", lambda _: None)
    directory, plan = _plan(tmp_path)
    deb = mirror.Asset(**plan["assets"][0])
    bucket = FakeBucket()
    bucket.fail_puts.append(_error(409, "ConditionalRequestConflict"))

    assert mirror.upload(bucket, "b", directory, "v1.2.3", [deb], "") == [(f"v1.2.3/{deb.name}", "uploaded")]


def test_other_storage_errors_are_not_mistaken_for_an_existing_file(tmp_path: Path) -> None:
    directory, plan = _plan(tmp_path)
    deb = mirror.Asset(**plan["assets"][0])
    bucket = FakeBucket()
    bucket.fail_puts.append(_error(403, "AccessDenied"))

    with pytest.raises(ClientError):
        mirror.upload(bucket, "b", directory, "v1.2.3", [deb], "")


@pytest.mark.parametrize("prefix", ["v1/", "latest.json", "../x/", "_Upper/", "_rehearsal"])
def test_a_rehearsal_prefix_can_never_reach_released_files(prefix: str) -> None:
    with pytest.raises(mirror.MirrorError):
        mirror.check_prefix(prefix)
    assert mirror.check_prefix("_rehearsal/") == "_rehearsal/"


# ---------------------------------------------------------------------------
# Channel files
# ---------------------------------------------------------------------------


def test_the_manifest_follows_schema_1(tmp_path: Path) -> None:
    _, plan = _plan(tmp_path)

    manifest = mirror.manifest_for(plan, BASE, REPO, "")

    assert list(manifest) == ["schema", "version", "tag", "published_at", "release_url", "assets"]
    assert manifest["schema"] == 1 and manifest["version"] == "1.2.3"
    deb = manifest["assets"][0]
    assert list(deb) == ["name", "kind", "platform", "arch", "size", "sha256", "url", "github_url", "checksums_name"]
    assert deb["url"] == f"{BASE}/v1.2.3/servonaut-desktop-preview_1.2.3_amd64.deb"
    assert deb["github_url"] == f"https://github.com/{REPO}/releases/download/v1.2.3/servonaut-desktop-preview_1.2.3_amd64.deb"
    assert isinstance(deb["size"], int)
    script = manifest["assets"][1]
    assert "platform" not in script and script["checksums_name"] == "install-scripts_SHA256SUMS"
    assert "checksums_name" not in manifest["assets"][-1]
    assert "md5" not in json.dumps(manifest)


@pytest.mark.parametrize(
    "tag,prerelease,latest,expected",
    [
        ("v1.2.3", False, "v1.2.3", ["latest.json", "channels/pre.json"]),
        ("v1.2.2", False, "v1.2.3", ["channels/pre.json"]),
        ("v1.3.0rc1", True, "v1.2.3", ["channels/pre.json"]),
    ],
)
def test_only_githubs_latest_stable_release_may_become_latest_json(tag: str, prerelease: bool, latest: str, expected: list[str]) -> None:
    plan = {"tag": tag, "prerelease": prerelease}

    assert mirror.channel_keys(plan, latest, "") == expected
    assert mirror.channel_keys(plan, latest, "_rehearsal/") == [f"_rehearsal/{key}" for key in expected]


def _manifest(tag: str) -> dict[str, Any]:
    return {"schema": 1, "version": tag[1:], "tag": tag, "published_at": "", "release_url": "", "assets": []}


def test_a_channel_file_is_created_and_then_left_alone() -> None:
    bucket = FakeBucket()

    assert mirror.write_channel(bucket, "b", "latest.json", _manifest("v1.2.3")) == "written"
    assert bucket.puts[-1]["IfNoneMatch"] == "*"
    assert mirror.write_channel(bucket, "b", "latest.json", _manifest("v1.2.3")) == "unchanged"
    stored = bucket.objects["latest.json"]
    assert (stored["type"], stored["cache"]) == ("application/json", "public, max-age=300")
    assert json.loads(stored["data"]) == _manifest("v1.2.3")


@pytest.mark.parametrize(
    "current,new,outcome",
    [
        ("v1.2.3", "v1.2.4", "written"),
        ("v1.3.0rc2", "v1.3.0", "written"),
        ("v1.2.4", "v1.2.3", "kept, it names the newer v1.2.4"),
        ("v1.3.0", "v1.3.0rc2", "kept, it names the newer v1.3.0"),
    ],
)
def test_a_channel_file_never_moves_to_an_older_release(current: str, new: str, outcome: str) -> None:
    bucket = FakeBucket()
    mirror.write_channel(bucket, "b", "channels/pre.json", _manifest(current))

    etag_before = bucket.objects["channels/pre.json"]["etag"]

    assert mirror.write_channel(bucket, "b", "channels/pre.json", _manifest(new)) == outcome
    if outcome == "written":
        # Conditional on the version this run read.
        assert bucket.puts[-1]["IfMatch"] == etag_before
    assert json.loads(bucket.objects["channels/pre.json"]["data"])["tag"] == max(current, new, key=mirror.parse_tag)


def test_a_newer_release_with_more_files_replaces_the_same_releases_manifest() -> None:
    bucket = FakeBucket()
    mirror.write_channel(bucket, "b", "latest.json", _manifest("v1.2.3"))
    fuller = {**_manifest("v1.2.3"), "assets": [{"name": "install.sh"}]}

    assert mirror.write_channel(bucket, "b", "latest.json", fuller) == "written"


def test_a_channel_write_that_loses_a_race_re_reads_and_decides_again() -> None:
    bucket = FakeBucket()
    mirror.write_channel(bucket, "b", "latest.json", _manifest("v1.2.3"))
    # Another run writes a newer release between this run's read and write.
    real_put = bucket.put_object

    def racing_put(**kwargs: Any) -> dict[str, str]:
        if kwargs.get("IfMatch") and not getattr(racing_put, "raced", False):
            racing_put.raced = True
            real_put(Bucket="b", Key="latest.json", Body=json.dumps(_manifest("v1.2.5")).encode(),
                     ContentType="application/json", CacheControl="c")
        return real_put(**kwargs)

    bucket.put_object = racing_put  # type: ignore[method-assign]

    assert mirror.write_channel(bucket, "b", "latest.json", _manifest("v1.2.4")) == "kept, it names the newer v1.2.5"


def test_an_unreadable_channel_file_is_repaired() -> None:
    bucket = FakeBucket()
    bucket.objects["latest.json"] = {"data": b"not json", "etag": '"e"', "type": "t", "cache": "c", "meta": {}}

    assert mirror.write_channel(bucket, "b", "latest.json", _manifest("v1.2.3")) == "written"


# ---------------------------------------------------------------------------
# Update manifests
# ---------------------------------------------------------------------------

KEY = Ed25519PrivateKey.generate()
KEY_ID = "test-release-key"
SIGNER = (KEY, KEY_ID)
SIGNED_AT = datetime(2026, 1, 3, tzinfo=timezone.utc)
STABLE_JSON = "manifest/stable.json"
PREVIEW_JSON = "manifest/preview.json"


def _policy_for(key: Ed25519PrivateKey = KEY, origin: str = BASE + "/"):
    """Trust policies built like the app's, pinning only the test key."""
    def policy(build_channel: str) -> TrustPolicy:
        return TrustPolicy(
            trusted_public_keys={KEY_ID: key.public_key()},
            allowed_origin_prefixes=(origin,),
            allowed_channels=channels_accepted_by(ReleaseChannel(build_channel)),
        )
    return policy


POLICY_FOR = _policy_for()


def _pem(key: Any, encryption: Any = None) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption or serialization.NoEncryption()
    ).decode()


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _update_manifest(
    tmp_path: Path, tag: str = "v1.2.3", signed_at: datetime = SIGNED_AT, signer: tuple[Any, str] = SIGNER,
    base: str = BASE, prefix: str = "",
) -> tuple[Path, dict[str, Any], Any]:
    """A release with Linux and macOS desktop files, and its signed update manifest."""
    root = tmp_path / tag
    root.mkdir(exist_ok=True)
    directory, plan = _plan(root, tag, prerelease="rc" in tag, macos=True)
    return directory, plan, mirror.update_manifest(plan, base, prefix, signer, signed_at, 14)


def _body(manifest: Any) -> bytes:
    """A manifest's bytes as stored, without the publish-time check."""
    return canonicalize_json(manifest.to_dict()) + b"\n"


def test_the_update_manifest_lists_each_desktop_file_of_the_release(tmp_path: Path) -> None:
    _, plan, manifest = _update_manifest(tmp_path)

    assert (manifest.product_version, manifest.channel, manifest.packaging_revision) == ("1.2.3", ReleaseChannel.STABLE, 1)
    assert (manifest.published_at, manifest.expires_at) == ("2026-01-03T00:00:00Z", "2026-01-17T00:00:00Z")
    assert [
        (a.artifact_id, a.kind.value, a.distribution, a.platform, a.arch, a.min_os, a.filename) for a in manifest.artifacts
    ] == [
        ("ubuntu_deb-linux-x86_64", "ubuntu_deb", DistributionKind.PACKAGED_DESKTOP, "linux", "x86_64", None,
         "servonaut-desktop-preview_1.2.3_amd64.deb"),
        ("macos_dmg-darwin-arm64", "macos_dmg", DistributionKind.PACKAGED_DESKTOP, "darwin", "arm64", "13.0", ARM_DMG),
        ("macos_dmg-darwin-x86_64", "macos_dmg", DistributionKind.PACKAGED_DESKTOP, "darwin", "x86_64", "13.0", X64_DMG),
    ]
    planned = {raw["name"]: raw for raw in plan["assets"]}
    for artifact in manifest.artifacts:
        assert artifact.download_url == f"{BASE}/v1.2.3/{artifact.filename}"
        assert (artifact.sha256, artifact.byte_size) == (planned[artifact.filename]["sha256"], planned[artifact.filename]["size"])
    assert [signature.key_id for signature in manifest.signatures] == [KEY_ID]
    verify_manifest(manifest, POLICY_FOR("stable"), now=SIGNED_AT)


@pytest.mark.parametrize(
    "host,machine,os_version,expected",
    [
        ("linux", "x86_64", None, "servonaut-desktop-preview_1.2.3_amd64.deb"),
        ("darwin", "arm64", "14.2", ARM_DMG),
        ("darwin", "x86_64", "13.0", X64_DMG),
    ],
)
def test_an_app_on_each_host_finds_exactly_its_own_file(
    tmp_path: Path, host: str, machine: str, os_version: str | None, expected: str
) -> None:
    _, _, manifest = _update_manifest(tmp_path)

    found = resolve_target_artifact(
        manifest, DistributionKind.PACKAGED_DESKTOP, platform_name=host, machine_arch=machine, os_version=os_version
    )

    assert found.filename == expected


def test_the_disk_images_need_macos_13(tmp_path: Path) -> None:
    _, _, manifest = _update_manifest(tmp_path)

    with pytest.raises(OperatingSystemTooOldError):
        resolve_target_artifact(
            manifest, DistributionKind.PACKAGED_DESKTOP, platform_name="darwin", machine_arch="arm64", os_version="12.7"
        )


def test_a_candidate_gets_a_preview_manifest_that_sorts_between_its_neighbours(tmp_path: Path) -> None:
    _, _, manifest = _update_manifest(tmp_path, "v1.3.0rc2")

    assert (manifest.product_version, manifest.channel) == ("1.3.0-rc.2", ReleaseChannel.PREVIEW)
    versions = ["1.2.9"] + [mirror.manifest_version(tag) for tag in ("v1.3.0rc2", "v1.3.0rc10", "v1.3.0")]
    precedence = [parse_semver(version).precedence for version in versions]
    assert precedence == sorted(precedence) and len(set(map(str, precedence))) == 4
    for tag in ("v1.3.0rc2", "v1.3.0", "v0.0.1rc1"):
        assert mirror.manifest_tag(mirror.manifest_version(tag)) == tag


@pytest.mark.parametrize("version", ["1.3.0rc2", "1.3.0-rc2", "1.3.0-rc.0", "v1.3.0", "1.3", "1.3.0-beta.1", 7, None])
def test_only_release_versions_name_a_release(version: object) -> None:
    with pytest.raises(mirror.MirrorError, match="is not the version of a release"):
        mirror.manifest_tag(version)


def test_a_release_without_desktop_files_gets_no_update_manifest(tmp_path: Path) -> None:
    _, plan = _plan(tmp_path)
    plan["assets"] = [raw for raw in plan["assets"] if raw["kind"] != "desktop-deb"]

    assert mirror.update_manifest(plan, BASE, "", SIGNER, SIGNED_AT, 14) is None


def test_the_manifest_is_checked_with_the_apps_own_pinned_trust_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(trust_root, "PINNED_RELEASE_KEYS", MappingProxyType({KEY_ID: _raw_public(KEY).hex()}))
    mirror_origin = next(o for o in trust_root.ALLOWED_ARTIFACT_ORIGINS if not o.startswith("https://github.com/"))
    _, _, manifest = _update_manifest(tmp_path, base=mirror_origin)

    body = mirror.published_manifest(manifest, "stable", SIGNED_AT)

    verify_manifest(ReleaseManifest.from_json(body), release_trust_policy(ReleaseChannel.STABLE), now=SIGNED_AT)
    assert mirror.app_trust_policy("preview").allowed_channels == channels_accepted_by(ReleaseChannel.PREVIEW)
    # Files anywhere but an origin the app pins are refused.
    _, _, elsewhere = _update_manifest(tmp_path, base="https://downloads.example.net")
    with pytest.raises(mirror.MirrorError, match="stable channel would refuse .* not in allowed origins"):
        mirror.published_manifest(elsewhere, "stable", SIGNED_AT)


def test_while_the_app_pins_no_key_no_manifest_is_published(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(trust_root, "PINNED_RELEASE_KEYS", MappingProxyType({}))
    _, _, manifest = _update_manifest(tmp_path)

    with pytest.raises(mirror.MirrorError, match="pins no release key"):
        mirror.published_manifest(manifest, "stable", SIGNED_AT)


@pytest.mark.parametrize("signer", [(Ed25519PrivateKey.generate(), KEY_ID), (KEY, "another-key")], ids=["other-key", "other-id"])
def test_a_manifest_the_app_does_not_trust_is_never_published(tmp_path: Path, signer: tuple[Any, str]) -> None:
    _, _, manifest = _update_manifest(tmp_path, signer=signer)

    with pytest.raises(mirror.MirrorError, match="stable channel would refuse"):
        mirror.published_manifest(manifest, "stable", SIGNED_AT, POLICY_FOR)


def test_stable_builds_are_never_offered_a_candidate(tmp_path: Path) -> None:
    _, _, candidate = _update_manifest(tmp_path, "v1.3.0rc1")
    _, _, stable = _update_manifest(tmp_path, "v1.2.3")

    with pytest.raises(mirror.MirrorError, match="stable channel would refuse .* not permitted"):
        mirror.published_manifest(candidate, "stable", SIGNED_AT, POLICY_FOR)
    # Preview builds take candidates, and move on to a stable release.
    assert mirror.published_manifest(candidate, "preview", SIGNED_AT, POLICY_FOR)
    assert mirror.published_manifest(stable, "preview", SIGNED_AT, POLICY_FOR)


def test_the_published_bytes_are_the_signed_manifest(tmp_path: Path) -> None:
    _, _, manifest = _update_manifest(tmp_path)

    body = mirror.published_manifest(manifest, "stable", SIGNED_AT, POLICY_FOR)

    assert ReleaseManifest.from_json(body) == manifest
    assert body.endswith(b"\n") and b"\n" not in body[:-1]


@pytest.mark.parametrize(
    "tag,prerelease,latest,expected",
    [
        ("v1.2.3", False, "v1.2.3", [(STABLE_JSON, "stable"), (PREVIEW_JSON, "preview")]),
        ("v1.2.2", False, "v1.2.3", [(PREVIEW_JSON, "preview")]),
        ("v1.3.0rc1", True, "v1.2.3", [(PREVIEW_JSON, "preview")]),
    ],
)
def test_stable_json_follows_latest_json_and_preview_json_follows_pre_json(
    tag: str, prerelease: bool, latest: str, expected: list[tuple[str, str]]
) -> None:
    plan = {"tag": tag, "prerelease": prerelease}

    assert mirror.manifest_keys(plan, latest, "") == expected
    assert mirror.manifest_keys(plan, latest, "_rehearsal/") == [(f"_rehearsal/{key}", channel) for key, channel in expected]


def test_an_update_manifest_is_written_short_lived(tmp_path: Path) -> None:
    _, _, manifest = _update_manifest(tmp_path)
    body = mirror.published_manifest(manifest, "preview", SIGNED_AT, POLICY_FOR)
    bucket = FakeBucket()

    assert mirror.write_manifest(bucket, "b", PREVIEW_JSON, body, (mirror.parse_tag("v1.2.3"), 1)) == "written"

    stored = bucket.objects[PREVIEW_JSON]
    assert (stored["type"], stored["cache"], stored["data"]) == ("application/json", "public, max-age=300", body)
    assert bucket.puts[-1]["IfNoneMatch"] == "*"


@pytest.mark.parametrize(
    "current,new,outcome",
    [
        ("v1.2.3", "v1.2.4", "written"),
        ("v1.3.0rc2", "v1.3.0", "written"),
        ("v1.3.0rc9", "v1.3.0rc10", "written"),
        # The same release again renews its expiry.
        ("v1.2.3", "v1.2.3", "written"),
        ("v1.2.4", "v1.2.3", "kept, it names the newer v1.2.4"),
        ("v1.3.0", "v1.3.0rc2", "kept, it names the newer v1.3.0"),
        ("v1.3.0rc10", "v1.3.0rc9", "kept, it names the newer v1.3.0rc10"),
    ],
)
def test_an_update_manifest_never_moves_to_an_older_release(tmp_path: Path, current: str, new: str, outcome: str) -> None:
    bodies = {tag: _body(_update_manifest(tmp_path, tag)[2]) for tag in (current, new)}
    bucket = FakeBucket()
    mirror.write_manifest(bucket, "b", PREVIEW_JSON, bodies[current], (mirror.parse_tag(current), 1))
    etag_before = bucket.objects[PREVIEW_JSON]["etag"]

    assert mirror.write_manifest(bucket, "b", PREVIEW_JSON, bodies[new], (mirror.parse_tag(new), 1)) == outcome
    if outcome == "written":
        assert bucket.puts[-1]["IfMatch"] == etag_before
    stored = ReleaseManifest.from_json(bucket.objects[PREVIEW_JSON]["data"])
    assert stored.product_version == mirror.manifest_version(max(current, new, key=mirror.parse_tag))


def test_a_newer_packaging_of_the_same_release_is_kept(tmp_path: Path) -> None:
    bucket = FakeBucket()
    newer = json.dumps({"product_version": "1.2.3", "packaging_revision": 2}).encode()
    bucket.objects[STABLE_JSON] = {"data": newer, "etag": '"e"', "type": "t", "cache": "c", "meta": {}}

    assert mirror.write_manifest(bucket, "b", STABLE_JSON, b"{}", (mirror.parse_tag("v1.2.3"), 1)) == "kept, it names the newer v1.2.3"


def test_an_unreadable_update_manifest_is_repaired() -> None:
    bucket = FakeBucket()
    bucket.objects[STABLE_JSON] = {"data": b"not json", "etag": '"e"', "type": "t", "cache": "c", "meta": {}}

    assert mirror.write_manifest(bucket, "b", STABLE_JSON, b"{}", (mirror.parse_tag("v1.2.3"), 1)) == "written"
    assert bucket.puts[-1]["IfMatch"] == '"e"'


def test_a_manifest_write_that_loses_a_race_re_reads_and_decides_again(tmp_path: Path) -> None:
    bodies = {tag: _body(_update_manifest(tmp_path, tag)[2]) for tag in ("v1.2.3", "v1.2.4", "v1.2.5")}
    bucket = FakeBucket()
    mirror.write_manifest(bucket, "b", STABLE_JSON, bodies["v1.2.3"], (mirror.parse_tag("v1.2.3"), 1))
    real_put = bucket.put_object

    def racing_put(**kwargs: Any) -> dict[str, str]:
        if kwargs.get("IfMatch") and not getattr(racing_put, "raced", False):
            racing_put.raced = True
            real_put(Bucket="b", Key=STABLE_JSON, Body=bodies["v1.2.5"], ContentType="application/json", CacheControl="c")
        return real_put(**kwargs)

    bucket.put_object = racing_put  # type: ignore[method-assign]

    outcome = mirror.write_manifest(bucket, "b", STABLE_JSON, bodies["v1.2.4"], (mirror.parse_tag("v1.2.4"), 1))

    assert outcome == "kept, it names the newer v1.2.5"


def test_the_manifest_periods_default_to_two_weeks_and_one_week() -> None:
    assert mirror.manifest_days("", "") == (14, 7)
    assert mirror.manifest_days("30", " 10 ") == (30, 10)


@pytest.mark.parametrize(
    "validity,refresh",
    [("0", ""), ("14.5", ""), ("-3", ""), ("two", ""), ("91", ""), ("", "14"), ("7", "10"), ("", "0")],
)
def test_unusable_manifest_periods_are_refused(validity: str, refresh: str) -> None:
    with pytest.raises(mirror.MirrorError, match="RELEASE_MANIFEST_"):
        mirror.manifest_days(validity, refresh)


@pytest.mark.parametrize("key,key_id", [("", ""), ("key", ""), ("", KEY_ID), ("  ", KEY_ID)])
def test_without_both_signing_settings_there_is_no_signer(monkeypatch: pytest.MonkeyPatch, key: str, key_id: str) -> None:
    monkeypatch.setenv("RELEASE_MANIFEST_SIGNING_KEY", key)
    monkeypatch.setenv("RELEASE_MANIFEST_KEY_ID", key_id)

    assert mirror.manifest_signer() is None


def test_the_signer_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RELEASE_MANIFEST_SIGNING_KEY", _pem(KEY))
    monkeypatch.setenv("RELEASE_MANIFEST_KEY_ID", f" {KEY_ID}\n")

    key, key_id = mirror.manifest_signer()

    assert key_id == KEY_ID
    assert _raw_public(key) == _raw_public(KEY)


@pytest.mark.parametrize(
    "secret",
    [
        "not a key at all",
        _pem(ec.generate_private_key(ec.SECP256R1())),
        _pem(KEY, serialization.BestAvailableEncryption(b"passphrase")),
    ],
    ids=["garbage", "not-ed25519", "encrypted"],
)
def test_an_unusable_signing_key_is_refused_without_being_echoed(monkeypatch: pytest.MonkeyPatch, secret: str) -> None:
    monkeypatch.setenv("RELEASE_MANIFEST_SIGNING_KEY", secret)
    monkeypatch.setenv("RELEASE_MANIFEST_KEY_ID", KEY_ID)

    with pytest.raises(mirror.MirrorError, match="not an unencrypted Ed25519 private key") as raised:
        mirror.manifest_signer()

    assert not any(line in str(raised.value) for line in secret.splitlines() if len(line) > 8)


def test_a_key_id_that_is_not_a_short_id_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RELEASE_MANIFEST_SIGNING_KEY", _pem(KEY))
    monkeypatch.setenv("RELEASE_MANIFEST_KEY_ID", "two words")

    with pytest.raises(mirror.MirrorError, match="RELEASE_MANIFEST_KEY_ID"):
        mirror.manifest_signer()


# ---------------------------------------------------------------------------
# Refreshing the update manifests
# ---------------------------------------------------------------------------


def _github_sums(directory: Path, plan: dict[str, Any]) -> dict[str, tuple[int, str, bytes]]:
    """GitHub's copies of a release's SHA256SUMS assets, by download URL."""
    return {
        mirror.github_url(REPO, plan["tag"], raw["name"]): (200, "application/octet-stream", (directory / raw["name"]).read_bytes())
        for raw in plan["assets"]
        if raw["kind"] == "checksums"
    }


def _stored(tmp_path: Path, signed_at: datetime = SIGNED_AT, signer: tuple[Any, str] = SIGNER, key: str = PREVIEW_JSON):
    """A bucket holding one release's update manifest, and GitHub's SUMS for it."""
    directory, plan, manifest = _update_manifest(tmp_path, signed_at=signed_at, signer=signer)
    bucket = FakeBucket()
    bucket.put_object(Bucket="b", Key=key, Body=_body(manifest), ContentType="application/json", CacheControl=mirror.SHORT_LIVED)
    return bucket, _fetcher(_github_sums(directory, plan)), manifest


def _refresh(bucket: FakeBucket, now: datetime, fetcher: Any, key: str = PREVIEW_JSON, channel: str = "preview") -> str:
    return mirror.refresh_manifest(bucket, "b", key, channel, SIGNER, now, (14, 7), REPO, fetcher, POLICY_FOR)


def test_a_manifest_with_enough_time_left_is_not_re_signed(tmp_path: Path) -> None:
    bucket, github, _ = _stored(tmp_path)
    before = bucket.objects[PREVIEW_JSON]["data"]

    assert _refresh(bucket, SIGNED_AT + timedelta(days=7), github) == "valid until 2026-01-17T00:00:00Z, not due"
    assert bucket.objects[PREVIEW_JSON]["data"] == before


def test_a_manifest_close_to_its_expiry_is_re_signed_and_otherwise_unchanged(tmp_path: Path) -> None:
    bucket, github, manifest = _stored(tmp_path)
    etag = bucket.objects[PREVIEW_JSON]["etag"]
    now = SIGNED_AT + timedelta(days=8)

    assert _refresh(bucket, now, github) == "re-signed, valid until 2026-01-25T00:00:00Z"

    assert bucket.puts[-1]["IfMatch"] == etag
    stored = bucket.objects[PREVIEW_JSON]
    assert (stored["type"], stored["cache"]) == ("application/json", "public, max-age=300")
    renewed = ReleaseManifest.from_json(stored["data"])
    verify_manifest(renewed, POLICY_FOR("preview"), now=now)
    assert renewed.published_at == "2026-01-11T00:00:00Z"
    same = ("product_version", "channel", "packaging_revision", "artifacts")
    assert [getattr(renewed, field) for field in same] == [getattr(manifest, field) for field in same]


def test_an_expired_manifest_of_ours_is_still_renewed(tmp_path: Path) -> None:
    bucket, github, _ = _stored(tmp_path)

    assert _refresh(bucket, SIGNED_AT + timedelta(days=40), github) == "re-signed, valid until 2026-02-26T00:00:00Z"


def test_a_manifest_whose_files_github_no_longer_lists_is_not_renewed(tmp_path: Path) -> None:
    bucket, _, _ = _stored(tmp_path)
    before = bucket.objects[PREVIEW_JSON]["data"]

    with pytest.raises(mirror.MirrorError, match="GitHub's SHA256SUMS do not list its digest, so it is not re-signed"):
        _refresh(bucket, SIGNED_AT + timedelta(days=8), _fetcher({}))
    assert bucket.objects[PREVIEW_JSON]["data"] == before


def test_a_manifest_no_pinned_key_signed_is_not_renewed(tmp_path: Path) -> None:
    bucket, github, _ = _stored(tmp_path, signer=(Ed25519PrivateKey.generate(), KEY_ID))

    with pytest.raises(mirror.MirrorError, match="not an update manifest a pinned key signed"):
        _refresh(bucket, SIGNED_AT + timedelta(days=8), github)


def test_a_missing_manifest_is_left_to_the_next_mirror_run() -> None:
    assert _refresh(FakeBucket(), SIGNED_AT, _fetcher({})) == "missing; mirroring the newest release again writes it"


def test_a_refresh_that_loses_to_a_newer_release_leaves_it_alone(tmp_path: Path) -> None:
    bucket, github, _ = _stored(tmp_path)
    now = SIGNED_AT + timedelta(days=8)
    newer = _body(_update_manifest(tmp_path, "v1.2.4", signed_at=now)[2])
    real_put = bucket.put_object

    def racing_put(**kwargs: Any) -> dict[str, str]:
        if kwargs.get("IfMatch") and not getattr(racing_put, "raced", False):
            racing_put.raced = True
            real_put(Bucket="b", Key=PREVIEW_JSON, Body=newer, ContentType="application/json", CacheControl="c")
        return real_put(**kwargs)

    bucket.put_object = racing_put  # type: ignore[method-assign]

    assert _refresh(bucket, now, github) == "valid until 2026-01-25T00:00:00Z, not due"
    assert bucket.objects[PREVIEW_JSON]["data"] == newer


# ---------------------------------------------------------------------------
# Public downloads
# ---------------------------------------------------------------------------


def _fetcher(files: dict[str, tuple[int, str, bytes]], cache_control: dict[str, str] | None = None):
    """A CDN stand-in: channel JSON is short-lived, every other file immutable."""
    def fetch(url: str):
        status, content_type, data = files.get(url, (404, "", b""))
        default = mirror.SHORT_LIVED if content_type == "application/json" else mirror.IMMUTABLE
        headers = {
            "content-type": content_type,
            "cache-control": (cache_control or {}).get(url, default),
            "cf-cache-status": "MISS",
        }
        return status, headers, iter([data])
    return fetch


def _served(directory: Path, plan: dict[str, Any], prefix: str = "") -> dict[str, tuple[int, str, bytes]]:
    return {
        mirror.public_url(BASE, prefix, plan["tag"], raw["name"]): (200, raw["content_type"], (directory / raw["name"]).read_bytes())
        for raw in plan["assets"]
    }


def test_every_mirrored_file_is_downloaded_again_and_compared(tmp_path: Path) -> None:
    directory, plan = _plan(tmp_path)

    report = mirror.check_public(plan, BASE, "", _fetcher(_served(directory, plan)))

    assert len(report) == 5 and all(line.endswith("(MISS)") for line in report)


def test_a_public_copy_that_differs_fails_the_check(tmp_path: Path) -> None:
    directory, plan = _plan(tmp_path)
    served = _served(directory, plan)
    url = mirror.public_url(BASE, "", "v1.2.3", "install.sh")
    served[url] = (200, "text/plain; charset=utf-8", b"tampered")

    with pytest.raises(mirror.MirrorError, match="does not serve the verified file"):
        mirror.check_public(plan, BASE, "", _fetcher(served))


def test_a_file_served_with_the_wrong_type_fails_the_check(tmp_path: Path) -> None:
    directory, plan = _plan(tmp_path)
    served = _served(directory, plan)
    url = mirror.public_url(BASE, "", "v1.2.3", "servonaut-desktop-preview_1.2.3_amd64.deb")
    served[url] = (200, "application/octet-stream", served[url][2])

    with pytest.raises(mirror.MirrorError, match="is served as application/octet-stream"):
        mirror.check_public(plan, BASE, "", _fetcher(served))


def test_a_file_whose_cache_header_the_cdn_rewrote_fails_the_check(tmp_path: Path) -> None:
    directory, plan = _plan(tmp_path)
    url = mirror.public_url(BASE, "", "v1.2.3", "install.sh")

    with pytest.raises(mirror.MirrorError, match="Cache-Control 'public, max-age=14400'"):
        mirror.check_public(plan, BASE, "", _fetcher(_served(directory, plan), {url: "public, max-age=14400"}))


def test_a_missing_public_copy_fails_the_check(tmp_path: Path) -> None:
    _, plan = _plan(tmp_path)

    with pytest.raises(mirror.MirrorError, match="answered 404"):
        mirror.check_public(plan, BASE, "", _fetcher({}))


# ---------------------------------------------------------------------------
# Release notes
# ---------------------------------------------------------------------------


def test_the_notes_block_is_added_once_and_replaced_in_place(tmp_path: Path) -> None:
    _, plan = _plan(tmp_path)
    block = mirror.notes_block(plan, BASE, "", "https://example.org/download")
    body = "## What's Changed\n* a fix\n"

    once = mirror.with_notes_block(body, block)
    twice = mirror.with_notes_block(once, block)

    assert once == twice
    assert once.startswith(body.rstrip()) and once.count(mirror.NOTES_START) == 1
    assert f"{BASE}/v1.2.3/servonaut-desktop-preview_1.2.3_amd64.deb" in block
    assert "servonaut-desktop-preview_1.2.3_SHA256SUMS" in block
    assert "https://example.org/download" in block
    updated = mirror.with_notes_block(once, block.replace("Faster download", "Quicker download"))
    assert "Quicker download" in updated and "Faster download" not in updated
    assert updated.startswith(body.rstrip())


def test_a_candidate_links_its_own_package_but_not_the_stable_download_page(tmp_path: Path) -> None:
    _, plan = _plan(tmp_path, "v1.3.0rc1", prerelease=True)

    block = mirror.notes_block(plan, BASE, "", "https://example.org/download")

    assert "/v1.3.0rc1/servonaut-desktop-preview_1.3.0rc1_amd64.deb" in block
    assert "https://example.org/download" not in block


def test_a_release_without_a_desktop_package_gets_no_block(tmp_path: Path) -> None:
    _, plan = _plan(tmp_path)
    plan["assets"] = [raw for raw in plan["assets"] if raw["kind"] != "desktop-deb"]

    assert mirror.notes_block(plan, BASE, "", "") is None


@pytest.mark.parametrize("body", [f"text\n{mirror.NOTES_START}\nhalf", f"text\n{mirror.NOTES_END}\n"])
def test_half_a_block_is_left_for_a_person_to_fix(body: str) -> None:
    with pytest.raises(mirror.MirrorError):
        mirror.with_notes_block(body, f"{mirror.NOTES_START}\nnew\n{mirror.NOTES_END}")
    with pytest.raises(mirror.MirrorError):
        mirror.without_notes_block(body)


def test_a_withdrawn_package_loses_its_link_and_the_notes_are_restored(tmp_path: Path) -> None:
    _, plan = _plan(tmp_path)
    block = mirror.notes_block(plan, BASE, "", "")
    body = "## What's Changed\n* a fix"

    assert mirror.without_notes_block(mirror.with_notes_block(body, block)) == body + "\n"
    assert mirror.without_notes_block(body) == body
    assert mirror.without_notes_block(mirror.with_notes_block("", block)) == ""
    # Text a person added after the block is kept.
    edited = mirror.with_notes_block(body, block) + "\nThanks to everyone who tested.\n"
    assert mirror.without_notes_block(edited) == body + "\n\nThanks to everyone who tested.\n"


def test_the_notes_command_removes_the_link_when_the_package_is_gone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _, plan = _plan(tmp_path)
    block = mirror.notes_block(plan, BASE, "", "")
    plan["assets"] = [raw for raw in plan["assets"] if raw["kind"] != "desktop-deb"]
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    (tmp_path / "body.md").write_text(mirror.with_notes_block("notes", block))
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)

    code = mirror.main(["notes", "--plan", str(tmp_path / "plan.json"), "--base", BASE, "--body-file", str(tmp_path / "body.md"), "--out", str(tmp_path / "new.md")])

    assert code == 0
    assert capsys.readouterr().out == "release notes changed\n"
    assert (tmp_path / "new.md").read_text() == "notes\n"


def test_empty_notes_get_just_the_block() -> None:
    block = f"{mirror.NOTES_START}\nnew\n{mirror.NOTES_END}"

    assert mirror.with_notes_block("", block) == block + "\n"
    assert mirror.with_notes_block(None, block) == block + "\n"


def test_the_notes_block_links_every_mirrored_desktop_file(tmp_path: Path) -> None:
    _, plan = _plan(tmp_path, macos=True)

    block = mirror.notes_block(plan, BASE, "", "")

    deb = "servonaut-desktop-preview_1.2.3_amd64.deb"
    assert [line for line in block.splitlines() if line.startswith("- ")] == [
        f"- Linux (.deb): [{deb}]({BASE}/v1.2.3/{deb}), listed in `servonaut-desktop-preview_1.2.3_SHA256SUMS`",
        f"- macOS on Apple silicon: [{ARM_DMG}]({BASE}/v1.2.3/{ARM_DMG}), listed in `{MAC_SUMS}`",
        f"- macOS on Intel: [{X64_DMG}]({BASE}/v1.2.3/{X64_DMG}), listed in `{MAC_SUMS}`",
    ]


def test_a_release_with_only_disk_images_still_links_them(tmp_path: Path) -> None:
    _, plan = _plan(tmp_path, macos=True)
    plan["assets"] = [raw for raw in plan["assets"] if raw["kind"] != "desktop-deb"]

    block = mirror.notes_block(plan, BASE, "", "")

    assert f"{BASE}/v1.2.3/{ARM_DMG}" in block and f"{BASE}/v1.2.3/{X64_DMG}" in block
    assert ".deb" not in block


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def _published(tmp_path: Path, macos: bool = False) -> tuple[dict[str, tuple[int, str, bytes]], dict[str, Any]]:
    """A mirror and GitHub that agree: channel files, mirrored files and GitHub's SUMS."""
    directory, plan = _plan(tmp_path, macos=macos)
    manifest = mirror.manifest_for(plan, BASE, REPO, "")
    served = _served(directory, plan)
    for key in ("latest.json", "channels/pre.json"):
        served[f"{BASE}/{key}"] = (200, "application/json", json.dumps(manifest).encode())
    for entry in manifest["assets"]:
        if entry["kind"] == "checksums":
            served[entry["github_url"]] = (200, "application/octet-stream", (directory / entry["name"]).read_bytes())
    return served, manifest


NOW = datetime(2026, 1, 3, tzinfo=timezone.utc)


def test_an_agreeing_mirror_passes_the_audit(tmp_path: Path) -> None:
    served, _ = _published(tmp_path)

    assert mirror.audit(BASE, REPO, "v1.2.3", "2026-01-02T03:04:05Z", NOW, _fetcher(served)) == []


def test_a_channel_file_pointing_elsewhere_fails_the_audit(tmp_path: Path) -> None:
    served, manifest = _published(tmp_path)
    manifest["assets"][0]["url"] = "https://elsewhere.example.net/evil.deb"
    served[f"{BASE}/latest.json"] = (200, "application/json", json.dumps(manifest).encode())

    problems = mirror.audit(BASE, REPO, "v1.2.3", "2026-01-02T03:04:05Z", NOW, _fetcher(served))

    assert problems == ["latest.json: servonaut-desktop-preview_1.2.3_amd64.deb: url is not the mirror's address for it"]


def test_a_mirrored_file_github_disagrees_with_fails_the_audit(tmp_path: Path) -> None:
    served, manifest = _published(tmp_path)
    evil = b"evil payload"
    deb = manifest["assets"][0]
    deb.update(sha256=_sha256(evil), size=len(evil))
    served[deb["url"]] = (200, "application/vnd.debian.binary-package", evil)
    served[f"{BASE}/latest.json"] = (200, "application/json", json.dumps(manifest).encode())

    problems = mirror.audit(BASE, REPO, "v1.2.3", "2026-01-02T03:04:05Z", NOW, _fetcher(served))

    assert any("GitHub's servonaut-desktop-preview_1.2.3_SHA256SUMS lists a different digest" in p for p in problems)


def test_a_missing_channel_file_fails_the_audit(tmp_path: Path) -> None:
    served, _ = _published(tmp_path)
    del served[f"{BASE}/channels/pre.json"]

    assert mirror.audit(BASE, REPO, "v1.2.3", "2026-01-02T03:04:05Z", NOW, _fetcher(served)) == [
        f"channels/pre.json: {BASE}/channels/pre.json answered 404"
    ]


def test_a_channel_file_cached_longer_than_five_minutes_fails_the_audit(tmp_path: Path) -> None:
    served, _ = _published(tmp_path)
    slow = {f"{BASE}/latest.json": "public, max-age=14400"}

    problems = mirror.audit(BASE, REPO, "v1.2.3", "2026-01-02T03:04:05Z", NOW, _fetcher(served, slow))

    assert problems == [
        f"latest.json: {BASE}/latest.json is served with Cache-Control 'public, max-age=14400', not 'public, max-age=300'"
    ]


def test_latest_json_behind_github_fails_only_after_the_grace_period(tmp_path: Path) -> None:
    served, _ = _published(tmp_path)

    fresh = mirror.audit(BASE, REPO, "v1.2.4", (NOW - timedelta(hours=1)).isoformat(), NOW, _fetcher(served))
    stale = mirror.audit(BASE, REPO, "v1.2.4", (NOW - timedelta(days=1)).isoformat(), NOW, _fetcher(served))

    assert fresh == []
    assert stale == ["latest.json: names v1.2.3, but GitHub's latest release is v1.2.4"]


def _with_manifests(
    tmp_path: Path, signed_at: datetime = NOW - timedelta(days=1)
) -> tuple[dict[str, tuple[int, str, bytes]], dict[str, Any]]:
    """An agreeing mirror and GitHub, with both update manifests signed at signed_at."""
    _, plan, manifest = _update_manifest(tmp_path, signed_at=signed_at)
    served, _ = _published(tmp_path / plan["tag"], macos=True)
    for key, channel in ((STABLE_JSON, "stable"), (PREVIEW_JSON, "preview")):
        served[f"{BASE}/{key}"] = (200, "application/json", mirror.published_manifest(manifest, channel, signed_at, POLICY_FOR))
    return served, plan


def _audit(served: dict[str, tuple[int, str, bytes]], latest: str = "v1.2.3") -> list[str]:
    return mirror.audit(
        BASE, REPO, latest, "2026-01-02T03:04:05Z", NOW, _fetcher(served), manifests=True, policy_for=POLICY_FOR
    )


def test_agreeing_update_manifests_pass_the_audit(tmp_path: Path) -> None:
    served, _ = _with_manifests(tmp_path)

    assert _audit(served) == []


def test_the_update_manifests_are_audited_only_once_they_are_signed(tmp_path: Path) -> None:
    served, _ = _published(tmp_path)

    assert mirror.audit(BASE, REPO, "v1.2.3", "2026-01-02T03:04:05Z", NOW, _fetcher(served)) == []
    assert _audit(served) == [
        f"manifest/stable.json: {BASE}/manifest/stable.json answered 404",
        f"manifest/preview.json: {BASE}/manifest/preview.json answered 404",
    ]


def test_an_update_manifest_no_pinned_key_signed_fails_the_audit(tmp_path: Path) -> None:
    served, plan = _with_manifests(tmp_path)
    forged = mirror.update_manifest(plan, BASE, "", (Ed25519PrivateKey.generate(), KEY_ID), NOW, 14)
    served[f"{BASE}/{STABLE_JSON}"] = (200, "application/json", _body(forged))

    problems = _audit(served)

    assert len(problems) == 1
    assert problems[0].startswith("manifest/stable.json: app builds on the stable channel refuse it: Cryptographic signature")


def test_an_update_manifest_cached_longer_than_five_minutes_fails_the_audit(tmp_path: Path) -> None:
    served, _ = _with_manifests(tmp_path)

    problems = mirror.audit(
        BASE, REPO, "v1.2.3", "2026-01-02T03:04:05Z", NOW,
        _fetcher(served, {f"{BASE}/{PREVIEW_JSON}": "public, max-age=14400"}), manifests=True, policy_for=POLICY_FOR,
    )

    assert problems == [
        f"manifest/preview.json: {BASE}/manifest/preview.json is served with Cache-Control 'public, max-age=14400', "
        "not 'public, max-age=300'"
    ]


def test_an_update_manifest_the_refresh_left_behind_fails_the_audit(tmp_path: Path) -> None:
    # 7 days left: the refresh, at 7 days, is not yet due.
    fine, _ = _with_manifests(_subdir(tmp_path, "fine"), NOW - timedelta(days=7))
    # 5 days left: the refresh should have re-signed it.
    late, _ = _with_manifests(_subdir(tmp_path, "late"), NOW - timedelta(days=9))

    assert _audit(fine) == []
    assert _audit(late) == [
        "manifest/stable.json: expires at 2026-01-08T00:00:00Z and was not re-signed in time",
        "manifest/preview.json: expires at 2026-01-08T00:00:00Z and was not re-signed in time",
    ]


def test_an_expired_update_manifest_fails_the_audit(tmp_path: Path) -> None:
    served, _ = _with_manifests(tmp_path, NOW - timedelta(days=15))

    problems = _audit(served)

    assert [problem.split(": ", 2)[:2] for problem in problems] == [
        ["manifest/stable.json", "app builds on the stable channel refuse it"],
        ["manifest/preview.json", "app builds on the preview channel refuse it"],
    ]
    assert all("expired" in problem for problem in problems)


def test_an_update_manifest_naming_another_release_fails_the_audit(tmp_path: Path) -> None:
    served, _ = _with_manifests(tmp_path)
    directory, plan, older = _update_manifest(tmp_path, "v1.2.2", signed_at=NOW)
    served.update(_github_sums(directory, plan))
    served[f"{BASE}/{STABLE_JSON}"] = (200, "application/json", _body(older))

    assert _audit(served) == ["manifest/stable.json: names v1.2.2, but latest.json names v1.2.3"]


def test_an_update_manifest_listing_other_files_than_its_channel_fails_the_audit(tmp_path: Path) -> None:
    served, plan = _with_manifests(tmp_path)
    fewer = {**plan, "assets": [raw for raw in plan["assets"] if raw["name"] != X64_DMG]}
    manifest = mirror.update_manifest(fewer, BASE, "", SIGNER, NOW, 14)
    served[f"{BASE}/{PREVIEW_JSON}"] = (200, "application/json", _body(manifest))

    assert _audit(served) == ["manifest/preview.json: lists other desktop files than channels/pre.json"]


def test_an_update_manifest_pointing_away_from_the_mirror_fails_the_audit(tmp_path: Path) -> None:
    served, plan = _with_manifests(tmp_path)
    rehearsal = mirror.update_manifest(plan, BASE, "_rehearsal/", SIGNER, NOW, 14)
    served[f"{BASE}/{STABLE_JSON}"] = (200, "application/json", _body(rehearsal))

    assert _audit(served) == [
        f"manifest/stable.json: {name}: download_url is not the mirror's address for it"
        for name in ("servonaut-desktop-preview_1.2.3_amd64.deb", ARM_DMG, X64_DMG)
    ]


def test_an_update_manifest_file_github_does_not_list_fails_the_audit(tmp_path: Path) -> None:
    served, _ = _with_manifests(tmp_path)
    del served[mirror.github_url(REPO, "v1.2.3", MAC_SUMS)]

    problems = _audit(served)

    for key in ("manifest/stable.json", "manifest/preview.json"):
        for name in (ARM_DMG, X64_DMG):
            assert f"{key}: {name}: GitHub's SHA256SUMS do not list its digest" in problems


def test_a_release_without_desktop_files_leaves_the_last_manifest_in_place(tmp_path: Path) -> None:
    # latest.json moved on to a release that has only the install scripts.
    directory, plan = _plan(_subdir(tmp_path, "scripts"), "v1.2.4")
    plan["assets"] = [raw for raw in plan["assets"] if not raw["name"].startswith("servonaut-desktop-preview")]
    channel = mirror.manifest_for(plan, BASE, REPO, "")
    served = _served(directory, plan)
    served.update(_github_sums(directory, plan))
    for key in ("latest.json", "channels/pre.json"):
        served[f"{BASE}/{key}"] = (200, "application/json", json.dumps(channel).encode())
    manifests = {}
    for tag in ("v1.2.3", "v1.2.5"):
        desktop_dir, desktop_plan, manifest = _update_manifest(tmp_path, tag, signed_at=NOW)
        served.update(_github_sums(desktop_dir, desktop_plan))
        manifests[tag] = (200, "application/json", _body(manifest))

    served[f"{BASE}/{STABLE_JSON}"] = served[f"{BASE}/{PREVIEW_JSON}"] = manifests["v1.2.3"]
    assert _audit(served, latest="v1.2.4") == []
    served[f"{BASE}/{PREVIEW_JSON}"] = manifests["v1.2.5"]
    assert _audit(served, latest="v1.2.4") == [
        "manifest/preview.json: names v1.2.5, which is newer than v1.2.4 in channels/pre.json"
    ]


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def test_verify_writes_the_plan_and_the_step_outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory, sizes = _release(tmp_path)
    release = {
        "tag_name": "v1.2.3",
        "draft": False,
        "prerelease": False,
        "published_at": "2026-01-02T03:04:05Z",
        "html_url": "https://github.com/example/releases/tag/v1.2.3",
        "assets": [{"name": name, "size": size} for name, size in sizes.items()],
    }
    (tmp_path / "release.json").write_text(json.dumps(release))
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "output"))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    code = mirror.main(["verify", "--dir", str(directory), "--release-json", str(tmp_path / "release.json"), "--out", str(tmp_path / "plan.json")])

    assert code == 0
    plan = json.loads((tmp_path / "plan.json").read_text())
    assert plan["tag"] == "v1.2.3" and len(plan["assets"]) == 5
    assert (tmp_path / "output").read_text() == (
        "desktop-deb=servonaut-desktop-preview_1.2.3_amd64.deb\ndesktop-dmgs=\nasset-count=5\n"
    )


def test_a_draft_is_never_mirrored(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    directory, _ = _release(tmp_path)
    (tmp_path / "release.json").write_text(json.dumps({"tag_name": "v1.2.3", "draft": True, "assets": []}))

    code = mirror.main(["verify", "--dir", str(directory), "--release-json", str(tmp_path / "release.json"), "--out", str(tmp_path / "plan.json")])

    assert code == 1
    assert "is a draft" in capsys.readouterr().err


def test_storage_errors_report_their_code_but_never_the_endpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _, plan = _plan(tmp_path)
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    endpoint = "https://0123456789abcdef.storage.example.net"

    class Refusing(FakeBucket):
        def put_object(self, **kwargs: Any) -> dict[str, str]:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": f"no access at {endpoint}"}}, "PutObject")

    monkeypatch.setattr(mirror, "bucket_client", lambda: (Refusing(), "secret-bucket-name"))

    code = mirror.main(["upload", "--dir", str(tmp_path / "files"), "--plan", str(tmp_path / "plan.json")])

    output = capsys.readouterr()
    assert code == 1
    assert "AccessDenied" in output.err
    assert endpoint not in output.err + output.out and "secret-bucket-name" not in output.err + output.out


def test_the_notes_command_reports_whether_the_body_changed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _, plan = _plan(tmp_path)
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    (tmp_path / "body.md").write_text("notes\n")
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    args = ["notes", "--plan", str(tmp_path / "plan.json"), "--base", BASE, "--body-file", str(tmp_path / "body.md"), "--out", str(tmp_path / "new.md")]

    assert mirror.main(args) == 0
    assert capsys.readouterr().out == "release notes changed\n"
    (tmp_path / "body.md").write_text((tmp_path / "new.md").read_text())
    assert mirror.main(args) == 0
    assert capsys.readouterr().out == "release notes unchanged\n"


def test_verify_names_the_disk_images_for_their_provenance_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory, sizes = _release(tmp_path, macos=True)
    release = {"tag_name": "v1.2.3", "draft": False, "assets": [{"name": name, "size": size} for name, size in sizes.items()]}
    (tmp_path / "release.json").write_text(json.dumps(release))
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "output"))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    code = mirror.main(["verify", "--dir", str(directory), "--release-json", str(tmp_path / "release.json"), "--out", str(tmp_path / "plan.json")])

    assert code == 0
    assert f"desktop-dmgs={ARM_DMG} {X64_DMG}\n" in (tmp_path / "output").read_text()


def _no_bucket() -> tuple[Any, str]:
    raise AssertionError("the bucket must not be touched")


def _without_signing(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("RELEASE_MANIFEST_SIGNING_KEY", "RELEASE_MANIFEST_KEY_ID", "GITHUB_STEP_SUMMARY"):
        monkeypatch.delenv(name, raising=False)


def _with_signing(monkeypatch: pytest.MonkeyPatch, policy_for: Any = POLICY_FOR) -> None:
    _without_signing(monkeypatch)
    monkeypatch.setenv("RELEASE_MANIFEST_SIGNING_KEY", _pem(KEY))
    monkeypatch.setenv("RELEASE_MANIFEST_KEY_ID", KEY_ID)
    monkeypatch.setattr(mirror, "app_trust_policy", policy_for)


def _manifests_args(tmp_path: Path, plan: dict[str, Any], latest: str = "v1.2.3", *extra: str) -> list[str]:
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    return ["manifests", "--plan", str(tmp_path / "plan.json"), "--base", BASE, "--github-latest-tag", latest, *extra]


def test_without_a_signing_key_the_manifests_are_skipped_with_a_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _without_signing(monkeypatch)
    monkeypatch.setattr(mirror, "bucket_client", _no_bucket)
    _, plan = _plan(tmp_path, macos=True)

    # Not even a broken period setting fails the run while signing is off.
    code = mirror.main(_manifests_args(tmp_path, plan, "v1.2.3", "--validity-days", "soon"))

    assert code == 0
    assert "::notice::RELEASE_MANIFEST_SIGNING_KEY or RELEASE_MANIFEST_KEY_ID is not set" in capsys.readouterr().out


def test_the_manifests_command_signs_checks_and_writes_both_manifests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _with_signing(monkeypatch)
    bucket = FakeBucket()
    monkeypatch.setattr(mirror, "bucket_client", lambda: (bucket, "b"))
    _, plan = _plan(tmp_path, macos=True)

    code = mirror.main(_manifests_args(tmp_path, plan, "v1.2.3", "--validity-days", "10", "--refresh-days", "3"))

    assert code == 0
    assert sorted(bucket.objects) == [PREVIEW_JSON, STABLE_JSON]
    for key, channel in ((STABLE_JSON, "stable"), (PREVIEW_JSON, "preview")):
        stored = ReleaseManifest.from_json(bucket.objects[key]["data"])
        verify_manifest(stored, POLICY_FOR(channel))
        assert parse_timestamp(stored.expires_at) - parse_timestamp(stored.published_at) == timedelta(days=10)
    out = capsys.readouterr().out
    assert f"- `{STABLE_JSON}`: written" in out and f"- `{PREVIEW_JSON}`: written" in out
    assert not any(line in out for line in _pem(KEY).splitlines()[1:-1])


def test_a_candidate_updates_only_the_preview_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _with_signing(monkeypatch)
    bucket = FakeBucket()
    monkeypatch.setattr(mirror, "bucket_client", lambda: (bucket, "b"))
    _, plan = _plan(tmp_path, "v1.3.0rc1", prerelease=True, macos=True)

    assert mirror.main(_manifests_args(tmp_path, plan, "v1.2.3")) == 0

    assert list(bucket.objects) == [PREVIEW_JSON]
    assert ReleaseManifest.from_json(bucket.objects[PREVIEW_JSON]["data"]).channel == ReleaseChannel.PREVIEW


def test_a_dry_run_signs_and_checks_but_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _with_signing(monkeypatch)
    monkeypatch.setattr(mirror, "bucket_client", _no_bucket)
    _, plan = _plan(tmp_path, macos=True)

    assert mirror.main(_manifests_args(tmp_path, plan, "v1.2.3", "--dry-run")) == 0

    out = capsys.readouterr().out
    assert "### Update manifests (dry run)" in out and f"- `{STABLE_JSON}` would name v1.2.3, valid until " in out


def test_a_manifest_the_app_would_refuse_leaves_both_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The app pins some other key than the one the mirror signs with.
    _with_signing(monkeypatch, _policy_for(Ed25519PrivateKey.generate()))
    monkeypatch.setattr(mirror, "bucket_client", _no_bucket)
    _, plan = _plan(tmp_path, macos=True)

    assert mirror.main(_manifests_args(tmp_path, plan)) == 1
    assert "stable channel would refuse the update manifest of 1.2.3" in capsys.readouterr().err


def test_without_desktop_files_the_manifests_stay_as_they_are(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _with_signing(monkeypatch)
    monkeypatch.setattr(mirror, "bucket_client", _no_bucket)
    _, plan = _plan(tmp_path)
    plan["assets"] = [raw for raw in plan["assets"] if raw["kind"] != "desktop-deb"]

    assert mirror.main(_manifests_args(tmp_path, plan)) == 0
    assert "no desktop files were mirrored" in capsys.readouterr().out


def test_the_refresh_tells_the_audit_whether_manifests_are_signed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _without_signing(monkeypatch)
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "output"))
    monkeypatch.setattr(mirror, "bucket_client", _no_bucket)

    assert mirror.main(["refresh", "--repo", REPO]) == 0

    assert (tmp_path / "output").read_text() == "signing=false\n"
    assert "::notice::" in capsys.readouterr().out


def test_the_refresh_command_renews_each_manifest_and_reports_the_one_it_cannot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _with_signing(monkeypatch)
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "output"))
    # Signed long ago, so both are due today.
    bucket, github, _ = _stored(tmp_path, key=PREVIEW_JSON)
    forged = _update_manifest(tmp_path, signer=(Ed25519PrivateKey.generate(), KEY_ID))[2]
    bucket.objects[STABLE_JSON] = {"data": _body(forged), "etag": '"s"', "type": "application/json", "cache": "c", "meta": {}}
    monkeypatch.setattr(mirror, "bucket_client", lambda: (bucket, "b"))
    monkeypatch.setattr(mirror, "fetch", github)

    code = mirror.main(["refresh", "--repo", REPO])

    output = capsys.readouterr()
    assert code == 1
    assert (tmp_path / "output").read_text() == "signing=true\n"
    assert f"- `{PREVIEW_JSON}`: re-signed, valid until " in output.out
    assert f"{STABLE_JSON}: it is not an update manifest a pinned key signed" in output.err
    verify_manifest(ReleaseManifest.from_json(bucket.objects[PREVIEW_JSON]["data"]), POLICY_FOR("preview"))
    assert bucket.objects[STABLE_JSON]["data"] == _body(forged)


def test_a_failed_refresh_fails_the_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    served, _ = _published(tmp_path)
    monkeypatch.setattr(mirror, "fetch", _fetcher(served))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    args = ["audit", "--base", BASE, "--repo", REPO, "--github-latest-tag", "v1.2.3",
            "--github-latest-published-at", "2026-01-02T03:04:05Z", "--report", str(tmp_path / "audit.md")]

    assert mirror.main([*args, "--refresh-result", "success"]) == 0
    assert mirror.main([*args, "--refresh-result", "failure"]) == 1
    assert "the update manifest refresh ended with failure" in (tmp_path / "audit.md").read_text()


def test_the_audit_command_checks_the_manifests_when_asked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    served, _ = _with_manifests(tmp_path, datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=1))
    monkeypatch.setattr(mirror, "fetch", _fetcher(served))
    monkeypatch.setattr(mirror, "app_trust_policy", POLICY_FOR)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    args = ["audit", "--base", BASE, "--repo", REPO, "--github-latest-tag", "v1.2.3",
            "--github-latest-published-at", "2026-01-02T03:04:05Z", "--report", str(tmp_path / "audit.md"), "--manifests"]

    assert mirror.main(args) == 0
    assert "and the update manifests, match GitHub" in (tmp_path / "audit.md").read_text()
    del served[f"{BASE}/{STABLE_JSON}"]
    assert mirror.main(args) == 1


# ---------------------------------------------------------------------------
# The workflow's contract
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _job(workflow: str, name: str) -> str:
    jobs = workflow.split("\njobs:\n", 1)[1]
    blocks = re.split(r"\n  (?=[a-z][a-z-]*:\n)", "\n" + jobs)
    return next(block for block in blocks if block.startswith(f"{name}:\n"))


def _step(workflow: str, name: str) -> str:
    start = workflow.index(f"      - name: {name}\n")
    step = workflow[start:]
    following = re.search(r"\n      - ", step)
    return step[: following.start()] if following else step


def _script(workflow: str, name: str) -> str:
    block = _step(workflow, name).split("        run: |\n", 1)[1]
    lines = []
    for line in block.splitlines():
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line)
    return textwrap.dedent("\n".join(lines))


def _granted(job: str) -> list[tuple[str, str]]:
    """The scopes a job's permissions block grants, in order."""
    block = job.split("    permissions:", 1)[1]
    if block.startswith(" {}"):
        return []
    block = re.split(r"\n    (?! )", block, maxsplit=1)[0]
    return re.findall(r"^      ([a-z-]+): (\w+)$", block, re.MULTILINE)


# The workflows that attach release files, by file and by the name the
# workflow_run trigger must use.
UPSTREAM_WORKFLOWS = {
    "desktop-preview-deb.yml": "Desktop preview .deb",
    "desktop-preview-macos.yml": "Desktop preview macOS",
    "release-install-scripts.yml": "Release install scripts",
}


def _upstream_files() -> list[Path]:
    return [WORKFLOWS / file for file in UPSTREAM_WORKFLOWS if (WORKFLOWS / file).exists()]


def test_it_runs_after_the_workflows_that_attach_release_files(workflow: str) -> None:
    triggers = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    for path in _upstream_files():
        declared = re.search(r"^name: (.+)$", path.read_text(encoding="utf-8"), re.MULTILINE).group(1)
        assert declared == UPSTREAM_WORKFLOWS[path.name]
    names = list(UPSTREAM_WORKFLOWS.values())

    assert f"    workflows: [{', '.join(json.dumps(name) for name in names)}]\n    types: [completed]\n" in triggers
    for trigger in ("push:", "pull_request", "release:", "workflow_call:"):
        assert trigger not in triggers
    for name in ("tag:", "dry_run:", "audit:"):
        assert f"      {name}\n" in triggers
    assert re.search(r'  schedule:\n    - cron: "\d+ \d+ \* \* \*"\n', triggers)


def test_each_job_has_the_least_privilege_it_needs(workflow: str) -> None:
    assert "\npermissions:\n  contents: read\n" in workflow
    assert "    permissions: {}\n" in _job(workflow, "resolve")
    assert _granted(_job(workflow, "mirror")) == [("contents", "read"), ("attestations", "read")]
    assert _granted(_job(workflow, "notes")) == [("contents", "write")]
    assert _granted(_job(workflow, "refresh")) == [("contents", "read")]
    assert _granted(_job(workflow, "audit")) == [("contents", "read"), ("issues", "write")]


def test_the_upload_credentials_reach_only_the_jobs_that_write_to_the_mirror(workflow: str) -> None:
    for name in ("resolve", "notes", "audit"):
        assert "secrets." not in _job(workflow, name)
    for name in ("mirror", "refresh"):
        job = _job(workflow, name)
        assert "    environment: release-mirror\n" in job
        # Secrets go to steps, never to every step of a job.
        assert "secrets." not in job.split("    steps:\n", 1)[0]
    assert workflow.count("environment:") == 2
    for step in ("Download the release", "Verify the files against their checksums", "Install the uploader"):
        assert "secrets." not in _step(workflow, step)


def test_only_the_signing_steps_receive_the_manifest_signing_key(workflow: str) -> None:
    signing_steps = ("Sign the update manifests", "Re-sign the update manifests before they expire")
    assert workflow.count("secrets.RELEASE_MANIFEST_SIGNING_KEY") == len(signing_steps)
    for name in signing_steps:
        step = _step(workflow, name)
        assert "          RELEASE_MANIFEST_SIGNING_KEY: ${{ secrets.RELEASE_MANIFEST_SIGNING_KEY }}\n" in step
        assert "          RELEASE_MANIFEST_KEY_ID: ${{ vars.RELEASE_MANIFEST_KEY_ID }}\n" in step
        assert "          MANIFEST_VALIDITY_DAYS: ${{ vars.RELEASE_MANIFEST_VALIDITY_DAYS }}\n" in step
        assert "          MANIFEST_REFRESH_DAYS: ${{ vars.RELEASE_MANIFEST_REFRESH_DAYS }}\n" in step
        script = _script(workflow, name)
        assert '--validity-days "${MANIFEST_VALIDITY_DAYS}"' in script
        assert '--refresh-days "${MANIFEST_REFRESH_DAYS}"' in script
        # Never on a command line, where a process listing could show it.
        assert "SIGNING_KEY" not in script


def test_the_manifest_code_is_the_apps_own_from_the_checkout(workflow: str) -> None:
    commands = re.findall(r"^(.*)python \.github/scripts/release-mirror\.py (manifests|refresh|audit)\b", workflow, re.MULTILINE)
    assert sorted(command for _, command in commands) == ["audit", "manifests", "refresh"]
    for prefix, _ in commands:
        assert prefix.strip() == 'PYTHONPATH="${GITHUB_WORKSPACE}/src"'
    # Each of those jobs installs the signature library from the locked file.
    for name in ("mirror", "refresh", "audit"):
        assert "-r .github/requirements/release-mirror.txt" in _job(workflow, name)


def test_no_job_checks_out_a_tag_or_keeps_credentials(workflow: str) -> None:
    checkouts = re.findall(r"      - uses: actions/checkout@\S+ # v[\d.]+\n((?:        .+\n)+)", workflow)
    assert len(checkouts) == 4
    for options in checkouts:
        assert "persist-credentials: false" in options
        assert "ref:" not in options


def test_inputs_reach_scripts_only_through_the_environment(workflow: str) -> None:
    for script in re.findall(r"        run: \|\n((?:          .*\n|\n)+)", workflow):
        assert "${{" not in script


def test_every_job_has_a_timeout_and_runs_queue_per_tag(workflow: str) -> None:
    for name in ("resolve", "mirror", "notes", "refresh", "audit"):
        assert re.search(r"^    timeout-minutes: \d+$", _job(workflow, name), re.MULTILINE), name
    assert (
        "concurrency:\n  group: release-mirror-${{ github.event.workflow_run.head_branch || inputs.tag || 'audit' }}\n"
        "  cancel-in-progress: false\n"
    ) in workflow


def test_the_uploader_is_installed_from_hash_locked_requirements(workflow: str) -> None:
    install = _script(workflow, "Install the uploader")
    assert "--require-hashes" in install and "--only-binary=:all:" in install
    assert "-r .github/requirements/release-mirror.txt" in install
    requirements = REQUIREMENTS.read_text(encoding="utf-8")
    pinned = re.findall(
        r"^([a-z0-9-]+)==\S+(?: ;[^\\\n]+)? \\\n((?:    --hash=sha256:[0-9a-f]{64}(?: \\)?\n)+)", requirements, re.MULTILINE
    )
    # The uploader, and the signature library the update manifests need.
    assert {"boto3", "cryptography"} <= {name for name, _ in pinned}
    assert len(pinned) == len(re.findall(r"^[a-z0-9-]+==", requirements, re.MULTILINE))


def test_files_are_verified_before_anything_is_uploaded(workflow: str) -> None:
    mirror_job = _job(workflow, "mirror")
    order = [
        "- name: Download the release",
        "- name: Verify the files against their checksums",
        "- name: Verify the desktop package's build provenance",
        "- name: Verify the macOS disk images' build provenance",
        "- name: Upload the files",
        "- name: Download the files again through the mirror",
        "- name: Point the channel files at the release",
        "- name: Sign the update manifests",
        "- name: Hand the plan to the notes job",
    ]
    positions = [mirror_job.index(marker) for marker in order]
    assert positions == sorted(positions)
    for step in ("Mask the bucket's address", "Upload the files", "Download the files again through the mirror"):
        assert "        if: env.DRY_RUN != 'true' && steps.verify.outputs.asset-count != '0'\n" in _step(workflow, step)


def test_the_update_manifests_follow_the_channel_files(workflow: str) -> None:
    channels = _step(workflow, "Point the channel files at the release")
    assert "        id: channels\n" in channels
    assert 'echo "github-latest-tag=${latest}" >> "${GITHUB_OUTPUT}"' in channels
    step = _step(workflow, "Sign the update manifests")
    # Always runs: the script skips with a notice when there is no key.
    assert "        if:" not in step
    assert "          LATEST_TAG: ${{ steps.channels.outputs.github-latest-tag }}\n" in step
    script = _script(workflow, "Sign the update manifests")
    assert '--github-latest-tag "${LATEST_TAG}"' in script
    assert 'if [ "${DRY_RUN}" = "true" ]; then dry_run_flag=(--dry-run); fi' in script


def test_the_desktop_package_must_come_from_its_own_workflow_and_tag(workflow: str) -> None:
    script = _script(workflow, "Verify the desktop package's build provenance")
    assert 'gh attestation verify "${RUNNER_TEMP}/mirror/files/${DEB}"' in script
    assert '--signer-workflow "${GH_REPO}/.github/workflows/desktop-preview-deb.yml"' in script
    assert '--source-ref "refs/tags/${TAG}"' in script


def test_each_disk_image_must_come_from_the_macos_workflow_and_tag(workflow: str) -> None:
    step = _step(workflow, "Verify the macOS disk images' build provenance")
    assert "        if: steps.verify.outputs.desktop-dmgs != ''\n" in step
    script = _script(workflow, "Verify the macOS disk images' build provenance")
    assert 'for dmg in "${images[@]}"; do' in script
    assert 'gh attestation verify "${RUNNER_TEMP}/mirror/files/${dmg}"' in script
    assert '--signer-workflow "${GH_REPO}/.github/workflows/desktop-preview-macos.yml"' in script
    assert '--source-ref "refs/tags/${TAG}"' in script


def test_the_provenance_loop_checks_every_disk_image(workflow: str, tmp_path: Path) -> None:
    calls = tmp_path / "calls"
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "gh").write_text(f'#!/bin/sh\necho "$@" >> "{calls}"\n')
    (fake / "gh").chmod(0o755)
    names = "servonaut-desktop-preview_1.2.3_macos-arm64.dmg servonaut-desktop-preview_1.2.3_macos-x64.dmg"

    result = subprocess.run(
        ["bash", "-c", _script(workflow, "Verify the macOS disk images' build provenance")],
        text=True,
        capture_output=True,
        check=False,
        env={"PATH": f"{fake}:{os.environ['PATH']}", "DMGS": names, "RUNNER_TEMP": "/runner", "GH_REPO": REPO, "TAG": "v1.2.3"},
    )

    assert result.returncode == 0, result.stderr
    verified = [line.split()[2] for line in calls.read_text().splitlines()]
    assert verified == [f"/runner/mirror/files/{name}" for name in names.split()]


def test_the_notes_job_edits_only_after_a_real_mirror_run(workflow: str) -> None:
    notes = _job(workflow, "notes")
    # Every real run, so a withdrawn package's link is removed again.
    assert "    if: needs.mirror.result == 'success' && needs.resolve.outputs.dry-run != 'true'\n" in notes
    assert 'gh api -X PATCH "repos/${GH_REPO}/releases/${release_id}"' in notes


def test_the_audit_runs_daily_only_while_the_mirror_is_on(workflow: str) -> None:
    audit = _job(workflow, "audit")
    assert "vars.RELEASE_MIRROR == 'on'" in audit
    assert "(github.event_name == 'schedule' || inputs.audit == true)" in audit
    assert "if: failure() && steps.audit.outcome == 'failure'" in audit


def test_the_manifests_are_re_signed_daily_before_the_audit(workflow: str) -> None:
    refresh = _job(workflow, "refresh")
    audit = _job(workflow, "audit")
    condition = (
        "github.repository == 'zb-ss/servonaut' && vars.RELEASE_MIRROR == 'on' &&\n"
        "      (github.event_name == 'schedule' || inputs.audit == true)\n"
    )
    assert f"    if: >-\n      {condition}" in refresh
    # The audit also runs after a failed refresh, to report what users get.
    assert "    needs: refresh\n" in audit
    assert f"    if: >-\n      !cancelled() && {condition}" in audit
    assert "      signing: ${{ steps.refresh.outputs.signing }}\n" in refresh
    step = _step(workflow, "Compare the mirror with GitHub")
    assert "          MANIFESTS_SIGNED: ${{ needs.refresh.outputs.signing }}\n" in step
    assert "          REFRESH_RESULT: ${{ needs.refresh.result }}\n" in step
    script = _script(workflow, "Compare the mirror with GitHub")
    assert 'if [ "${MANIFESTS_SIGNED}" = "true" ]; then manifests_flag=(--manifests); fi' in script
    assert '--refresh-result "${REFRESH_RESULT}"' in script


def _resolve(workflow: str, tmp_path: Path, **env: str) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    output = tmp_path / "output"
    output.write_text("", encoding="utf-8")
    defaults = {
        "GITHUB_EVENT_NAME": "workflow_run",
        "GITHUB_REPOSITORY": REPO,
        "RUN_TAG": "v1.2.3",
        "RUN_CONCLUSION": "success",
        "RUN_EVENT": "release",
        "RUN_REPOSITORY": REPO,
        "INPUT_TAG": "",
        "INPUT_DRY_RUN": "false",
        "MIRROR_SWITCH": "on",
    }
    result = subprocess.run(
        ["bash", "-c", _script(workflow, "Decide what to mirror")],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
        env={
            "PATH": os.environ["PATH"],
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
            **defaults,
            **env,
        },
    )
    values = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    return result, values


@pytest.mark.parametrize("tag", ["v1.2.3", "v1.3.0rc4"])
def test_a_finished_release_workflow_mirrors_its_tag(workflow: str, tmp_path: Path, tag: str) -> None:
    result, values = _resolve(workflow, tmp_path, RUN_TAG=tag)

    assert result.returncode == 0, result.stderr
    assert values == {"mirror": "true", "tag": tag, "dry-run": "false"}


@pytest.mark.parametrize(
    "env",
    [
        {"RUN_CONCLUSION": "failure"},
        {"RUN_EVENT": "push"},
        {"RUN_REPOSITORY": "someone/fork"},
        {"RUN_TAG": "master"},
        {"MIRROR_SWITCH": "off"},
        {"MIRROR_SWITCH": ""},
    ],
    ids=["failed", "push", "fork", "branch", "switched-off", "switch-unset"],
)
def test_other_runs_are_skipped_without_failing(workflow: str, tmp_path: Path, env: dict[str, str]) -> None:
    result, values = _resolve(workflow, tmp_path, **env)

    assert result.returncode == 0, result.stderr
    assert values == {"mirror": "false"}
    assert "::notice::" in result.stdout


def test_a_dry_run_works_while_the_mirror_is_off(workflow: str, tmp_path: Path) -> None:
    result, values = _resolve(
        workflow, tmp_path, GITHUB_EVENT_NAME="workflow_dispatch", INPUT_TAG="v1.2.3", INPUT_DRY_RUN="true", MIRROR_SWITCH="off"
    )

    assert result.returncode == 0, result.stderr
    assert values == {"mirror": "true", "tag": "v1.2.3", "dry-run": "true"}


def test_a_manual_run_mirrors_only_while_the_mirror_is_on(workflow: str, tmp_path: Path) -> None:
    on, on_values = _resolve(workflow, tmp_path, GITHUB_EVENT_NAME="workflow_dispatch", INPUT_TAG="v1.2.3")
    off, off_values = _resolve(workflow, tmp_path, GITHUB_EVENT_NAME="workflow_dispatch", INPUT_TAG="v1.2.3", MIRROR_SWITCH="off")

    assert on_values == {"mirror": "true", "tag": "v1.2.3", "dry-run": "false"}
    assert off.returncode == 0 and off_values == {"mirror": "false"}


@pytest.mark.parametrize(
    "env",
    [
        {"GITHUB_EVENT_NAME": "workflow_dispatch", "INPUT_TAG": "1.2.3"},
        {"GITHUB_EVENT_NAME": "workflow_dispatch", "INPUT_TAG": ""},
        {"MIRROR_SWITCH": "maybe"},
        {"GITHUB_EVENT_NAME": "push"},
    ],
    ids=["bad-tag", "no-tag", "bad-switch", "other-event"],
)
def test_invalid_requests_fail_instead_of_guessing(workflow: str, tmp_path: Path, env: dict[str, str]) -> None:
    result, values = _resolve(workflow, tmp_path, **env)

    assert result.returncode == 1
    assert "::error::" in result.stdout
    assert values.get("mirror") != "true"


def test_it_accepts_the_same_tags_as_the_workflows_it_follows(workflow: str) -> None:
    pattern = re.compile(r"^          version='(.+)'$", re.MULTILINE)
    ours = pattern.search(workflow).group(1)
    for path in _upstream_files():
        assert pattern.search(path.read_text(encoding="utf-8")).group(1) == ours
    assert mirror.TAG_PATTERN.pattern == rf"^v{ours.replace('(rc[1-9][0-9]*)?', '(?:rc([1-9][0-9]*))?')}$"
