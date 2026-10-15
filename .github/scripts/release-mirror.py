#!/usr/bin/env python3
"""Copy a GitHub release's verified files to the release mirror.

The mirror only carries files; it is never trusted. GitHub's SHA256SUMS
assets, and the build-provenance attestation the workflow checks on the
desktop package, stay the source of truth: a file is uploaded only when a
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
  notes         add or refresh the mirror link in the release notes
  audit         re-check the channel files, and every file they list,
                against GitHub

The bucket is reached with the standard AWS_ACCESS_KEY_ID and
AWS_SECRET_ACCESS_KEY variables plus MIRROR_ENDPOINT and MIRROR_BUCKET.
Error messages name object keys and error codes only, never the endpoint or
the bucket, because CI logs are public.
"""

from __future__ import annotations

import argparse
import base64
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


def describe(name: str, version: str) -> dict[str, str] | None:
    """How the mirror serves a release file, or None for a file it skips."""
    if name == f"servonaut-desktop-preview_{version}_amd64.deb":
        return {
            "kind": "desktop-deb",
            "content_type": "application/vnd.debian.binary-package",
            "platform": "linux",
            "arch": "x86_64",
        }
    if name in ("install.sh", "install.ps1"):
        return {"kind": "install-script", "content_type": TEXT}
    if name in (f"servonaut-desktop-preview_{version}_SHA256SUMS", "install-scripts_SHA256SUMS"):
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
    order = {"desktop-deb": 0, "install-script": 1, "checksums": 2}
    assets.sort(key=lambda asset: (order[asset.kind], asset.name))
    return assets, notices


def object_key(prefix: str, tag: str, name: str) -> str:
    return f"{prefix}{tag}/{name}"


def public_url(base: str, prefix: str, tag: str, name: str) -> str:
    return f"{base.rstrip('/')}/{object_key(prefix, tag, name)}"


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
        condition = {"IfMatch": etag} if etag else {"IfNoneMatch": "*"}
        try:
            client.put_object(
                Bucket=bucket, Key=key, Body=body, ContentType=JSON_TYPE, CacheControl=SHORT_LIVED, **condition
            )
            return "written"
        except Exception as error:
            if not is_bucket_error(error) or error_status(error) not in CONFLICT_STATUSES:
                raise
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
            github_url=f"https://github.com/{repo}/releases/download/{tag}/{asset.name}",
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


# --- release notes ---------------------------------------------------------


def notes_block(plan: dict[str, Any], base: str, prefix: str, download_page: str) -> str | None:
    """The release-notes paragraph that links the mirrored desktop package."""
    deb = next((Asset(**raw) for raw in plan["assets"] if raw["kind"] == "desktop-deb"), None)
    if deb is None:
        return None
    url = public_url(base, prefix, plan["tag"], deb.name)
    lines = [
        NOTES_START,
        "### Faster download",
        "",
        "The desktop preview package is also served from the release mirror, which stays fast "
        f"on slow or lossy connections: [{deb.name}]({url}). It is the same file; check it "
        f"against `{deb.checksums_name}` among the assets below.",
    ]
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
        if entry.get("github_url") != f"https://github.com/{repo}/releases/download/{tag}/{name}":
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


def audit(
    base: str,
    repo: str,
    github_latest_tag: str,
    github_latest_published_at: str,
    now: datetime,
    fetcher: Fetcher = fetch,
    grace: timedelta = timedelta(hours=6),
) -> list[str]:
    """Every way the published channel files disagree with GitHub."""
    problems: list[str] = []
    for key in (LATEST_KEY, PRE_KEY):
        url = f"{base.rstrip('/')}/{key}"
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
        if key == LATEST_KEY and not found and github_latest_tag and manifest.get("tag") != github_latest_tag:
            published = datetime.fromisoformat(github_latest_published_at.replace("Z", "+00:00"))
            if now - published > grace:
                problems.append(f"{key}: names {manifest.get('tag')}, but GitHub's latest release is {github_latest_tag}")
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
    problems = audit(
        args.base,
        args.repo,
        args.github_latest_tag,
        args.github_latest_published_at,
        datetime.now(timezone.utc),
    )
    lines = ["### Release mirror audit", ""]
    lines += [f"- {problem}" for problem in problems] or ["- the channel files and every file they list match GitHub"]
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
    for name in ("upload", "check-public", "channels", "notes"):
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
    return root


COMMANDS = {
    "verify": command_verify,
    "upload": command_upload,
    "check-public": command_check_public,
    "channels": command_channels,
    "notes": command_notes,
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
