"""The release mirror: its script against an in-memory bucket, and its workflow's contract.

The bucket stand-in enforces the conditional writes the real store honours
(If-None-Match, If-Match, Content-MD5), so the "never replace a published
file" and "never move a channel backwards" rules are exercised, not mocked.
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
from typing import Any

import pytest
from botocore.exceptions import ClientError

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


def _release(tmp_path: Path, version: str = "1.2.3", extra: dict[str, bytes] | None = None) -> tuple[Path, dict[str, int]]:
    """A downloaded release: desktop package, install scripts and both SUMS files."""
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
    files.update(extra or {})
    directory = tmp_path / "files"
    directory.mkdir(exist_ok=True)
    for name, data in files.items():
        (directory / name).write_bytes(data)
    return directory, {name: len(data) for name, data in files.items()}


def _plan(tmp_path: Path, tag: str = "v1.2.3", prerelease: bool = False) -> tuple[Path, dict[str, Any]]:
    directory, sizes = _release(tmp_path, tag[1:])
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


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def _published(tmp_path: Path) -> tuple[dict[str, tuple[int, str, bytes]], dict[str, Any]]:
    """A mirror and GitHub that agree: channel files, mirrored files and GitHub's SUMS."""
    directory, plan = _plan(tmp_path)
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
    assert (tmp_path / "output").read_text() == "desktop-deb=servonaut-desktop-preview_1.2.3_amd64.deb\nasset-count=5\n"


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


def test_it_runs_after_the_workflows_that_attach_release_files(workflow: str) -> None:
    triggers = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    names = [
        re.search(r"^name: (.+)$", (WORKFLOWS / file).read_text(encoding="utf-8"), re.MULTILINE).group(1)
        for file in ("desktop-preview-deb.yml", "release-install-scripts.yml")
    ]

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
    assert _granted(_job(workflow, "audit")) == [("contents", "read"), ("issues", "write")]


def test_the_upload_credentials_reach_only_the_mirror_job(workflow: str) -> None:
    for name in ("resolve", "notes", "audit"):
        assert "secrets." not in _job(workflow, name)
    mirror_job = _job(workflow, "mirror")
    assert "    environment: release-mirror\n" in mirror_job
    assert workflow.count("environment:") == 1
    for step in ("Download the release", "Verify the files against their checksums", "Install the uploader"):
        assert "secrets." not in _step(workflow, step)


def test_no_job_checks_out_a_tag_or_keeps_credentials(workflow: str) -> None:
    checkouts = re.findall(r"      - uses: actions/checkout@\S+ # v[\d.]+\n((?:        .+\n)+)", workflow)
    assert len(checkouts) == 3
    for options in checkouts:
        assert "persist-credentials: false" in options
        assert "ref:" not in options


def test_inputs_reach_scripts_only_through_the_environment(workflow: str) -> None:
    for script in re.findall(r"        run: \|\n((?:          .*\n|\n)+)", workflow):
        assert "${{" not in script


def test_every_job_has_a_timeout_and_runs_queue_per_tag(workflow: str) -> None:
    for name in ("resolve", "mirror", "notes", "audit"):
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
    pinned = re.findall(r"^([a-z0-9-]+)==\S+ \\\n((?:    --hash=sha256:[0-9a-f]{64}(?: \\)?\n)+)", requirements, re.MULTILINE)
    assert "boto3" in {name for name, _ in pinned}
    assert len(pinned) == len(re.findall(r"^[a-z0-9-]+==", requirements, re.MULTILINE))


def test_files_are_verified_before_anything_is_uploaded(workflow: str) -> None:
    mirror_job = _job(workflow, "mirror")
    order = [
        "- name: Download the release",
        "- name: Verify the files against their checksums",
        "- name: Verify the desktop package's build provenance",
        "- name: Upload the files",
        "- name: Download the files again through the mirror",
        "- name: Point the channel files at the release",
    ]
    positions = [mirror_job.index(marker) for marker in order]
    assert positions == sorted(positions)
    for step in ("Mask the bucket's address", "Upload the files", "Download the files again through the mirror"):
        assert "        if: env.DRY_RUN != 'true' && steps.verify.outputs.asset-count != '0'\n" in _step(workflow, step)


def test_the_desktop_package_must_come_from_its_own_workflow_and_tag(workflow: str) -> None:
    script = _script(workflow, "Verify the desktop package's build provenance")
    assert 'gh attestation verify "${RUNNER_TEMP}/mirror/files/${DEB}"' in script
    assert '--signer-workflow "${GH_REPO}/.github/workflows/desktop-preview-deb.yml"' in script
    assert '--source-ref "refs/tags/${TAG}"' in script


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
    for file in ("desktop-preview-deb.yml", "release-install-scripts.yml"):
        assert pattern.search((WORKFLOWS / file).read_text(encoding="utf-8")).group(1) == ours
    assert mirror.TAG_PATTERN.pattern == rf"^v{ours.replace('(rc[1-9][0-9]*)?', '(?:rc([1-9][0-9]*))?')}$"
