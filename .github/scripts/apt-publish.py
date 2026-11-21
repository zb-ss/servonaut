#!/usr/bin/env python3
"""Reconcile the APT archive from the verified release mirror."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib
import json
import os
import re
import sys
import tempfile
from collections.abc import Callable, Iterable
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from functools import cache
from pathlib import Path
from urllib.parse import quote, urlsplit

from apt_archive import (
    APPROVED_HASH, FINGERPRINT, INVENTORY, KEYRING, TAG, ArchiveError, Change, Conflict, Input,
    Inventory, MissingObject, Object, Package, PublicArchive, Publisher, Settings, Signer, audit, build_indexes,
    run, validate_debian_fields, version_order,
)
from scripts.distribution.package_deb import debian_version

mirror = importlib.import_module("release-mirror")
REHEARSAL_PREFIX = re.compile(r"apt-rehearsal/[0-9]+-[0-9]+")


def bounded_bytes(chunks: Iterable[bytes], maximum: int) -> bytes:
    body = bytearray()
    for chunk in chunks:
        if len(body) + len(chunk) > maximum:
            raise ArchiveError("Public archive object exceeded its size budget")
        body.extend(chunk)
    return bytes(body)


class HttpArchive:
    def __init__(self, base: str, prefix: str, timeout: float, maximum: int) -> None:
        url = urlsplit(base)
        if url.scheme != "https" or not url.hostname or url.username or url.query or url.fragment:
            raise ArchiveError("The public mirror must be an HTTPS URL without credentials")
        self.base = base.rstrip("/") + ("/" + prefix if prefix else "")
        self.timeout = timeout
        self.maximum = maximum

    def fetch(self, key: str) -> tuple[int, bytes]:
        status, _, chunks = mirror.fetch(f"{self.base}/{quote(key, safe='/~')}", timeout=self.timeout)
        return status, bounded_bytes(chunks, self.maximum)

    def read(self, key: str) -> bytes:
        status, body = self.fetch(key)
        if status == 404:
            raise MissingObject(f"Public archive object is missing: {key}")
        if status != 200:
            raise ArchiveError(f"Public archive returned HTTP {status} for {key}")
        return body

    def denied(self, key: str) -> bool:
        status, _ = self.fetch(key)
        return status in (403, 404)


class R2Store:
    """Translate the archive store's atomic operations to the mirror API."""

    def __init__(self, client, bucket: str, prefix: str, maximum: int) -> None:
        self.client = client
        self.bucket = bucket
        self.prefix = prefix
        self.maximum = maximum

    def get(self, key: str) -> Object | None:
        try:
            obj = self.client.get_object(Bucket=self.bucket, Key=f"{self.prefix}/{key}")
        except Exception as error:
            if not mirror.is_bucket_error(error):
                raise
            if mirror.error_status(error) == 404:
                return None
            raise ArchiveError(f"Archive read failed: {mirror.error_code(error)}") from None
        stream = obj["Body"]
        try:
            if obj["ContentLength"] > self.maximum:
                raise ArchiveError("Mirror object exceeded its size budget")
            body = stream.read(self.maximum + 1)
        finally:
            stream.close()
        if len(body) != obj["ContentLength"] or len(body) > self.maximum:
            raise ArchiveError("Mirror object length mismatch")
        return Object(body, obj["ETag"])

    def put(self, key: str, body: bytes, *, etag: str | None, immutable: bool = False) -> None:
        if len(body) > self.maximum:
            raise ArchiveError("Archive write exceeded its size budget")
        content_type = (
            "application/vnd.debian.binary-package" if key.endswith(".deb") else
            "application/json" if key.endswith(".json") else
            "application/pgp-keys" if key.endswith(".gpg") else
            "application/pgp-signature" if key.endswith("/InRelease") else
            "application/octet-stream"
        )
        condition = {"IfMatch": etag} if etag is not None else {"IfNoneMatch": "*"}
        try:
            self.client.put_object(
                Bucket=self.bucket, Key=f"{self.prefix}/{key}", Body=body,
                ContentType=content_type, CacheControl=mirror.IMMUTABLE if immutable else "no-store",
                ContentMD5=base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode(),
                **condition,
            )
        except Exception as error:
            if not mirror.is_bucket_error(error):
                raise
            if mirror.error_status(error) in mirror.CONFLICT_STATUSES:
                raise Conflict("A conditional archive write was rejected") from None
            raise ArchiveError(f"Archive write failed: {mirror.error_code(error)}") from None

    def delete(self, key: str) -> None:
        try:
            self.client.delete_object(Bucket=self.bucket, Key=f"{self.prefix}/{key}")
        except Exception as error:
            if not mirror.is_bucket_error(error):
                raise
            raise ArchiveError(f"Archive deletion failed: {mirror.error_code(error)}") from None


def clear_rehearsals(
    client, bucket: str, *, prefix: str | None = None, older_than: datetime | None = None,
) -> None:
    """Delete only complete rehearsal prefixes, never production archive objects."""
    if prefix is not None and not REHEARSAL_PREFIX.fullmatch(prefix):
        raise ArchiveError("Invalid rehearsal cleanup prefix")
    if prefix is None and older_than is None:
        raise ArchiveError("Rehearsal sweep requires an age threshold")
    search = f"{prefix}/" if prefix else "apt-rehearsal/"
    runs: dict[str, list[dict]] = {}
    try:
        pages = client.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=search)
        for page in pages:
            for obj in page.get("Contents", ()):
                key = obj["Key"]
                parts = key.split("/", 2)
                if len(parts) != 3 or not parts[2] or not key.startswith(search):
                    continue
                run_prefix = "/".join(parts[:2])
                if REHEARSAL_PREFIX.fullmatch(run_prefix):
                    runs.setdefault(run_prefix, []).append(obj)
        for objects in runs.values():
            if older_than is None or max(obj["LastModified"] for obj in objects) < older_than:
                for obj in objects:
                    client.delete_object(Bucket=bucket, Key=obj["Key"])
    except Exception as error:
        if not mirror.is_bucket_error(error):
            raise
        raise ArchiveError(f"Rehearsal cleanup failed: {mirror.error_code(error)}") from None


class VerifiedReleases:
    """Fresh GitHub listing, checksum, public mirror bytes and tagged provenance."""

    def __init__(
        self, repo: str, published: HttpArchive, scratch: Path, settings: Settings, *,
        pool: PublicArchive, checksum_budget: int, notice: Callable[[str, str | None], None],
        unqualified_delay: timedelta, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.repo = repo
        self.published = published
        self.scratch = scratch
        self.settings = settings
        self.pool = pool
        self.checksum_budget = checksum_budget
        self.notice = notice
        self.unqualified_delay = unqualified_delay
        self.clock = clock

    def releases(self) -> list[dict]:
        pages = json.loads(run([
            "gh", "api", "--paginate", "--slurp", f"repos/{self.repo}/releases?per_page=100",
        ], timeout=self.settings.timeout))
        if not isinstance(pages, list) or not pages or any(not isinstance(page, list) for page in pages):
            raise ArchiveError("Invalid release list")
        return [release for page in pages for release in page]

    @staticmethod
    def expected_assets(tag: str) -> tuple[str, str]:
        name = f"{mirror.DESKTOP_PREFIX}_{tag[1:]}_amd64.deb"
        sums, _ = mirror.desktop_checksums_names(tag[1:])
        return name, sums

    @staticmethod
    def eligible(release: dict, *, final: bool) -> bool:
        return (release.get("draft") is False and bool(release.get("published_at"))
                and release.get("prerelease") is (not final))

    def github_checksum(self, tag: str, sums: str) -> bytes:
        status, _, chunks = mirror.fetch(mirror.github_url(self.repo, tag, sums), timeout=self.settings.timeout)
        if status != 200:
            raise ArchiveError(f"GitHub checksum is unavailable for {tag}")
        return bounded_bytes(chunks, self.checksum_budget)

    def verify(self, package: Package, name: str, body: bytes) -> Input:
        package.check(body)
        path = self.scratch / name
        path.write_bytes(body)
        validate_debian_fields(path, package, self.settings.timeout)
        run([
            "gh", "attestation", "verify", str(path), "--repo", self.repo,
            "--signer-workflow", f"{self.repo}/.github/workflows/desktop-preview-deb.yml",
            "--source-ref", f"refs/tags/{package.tag}",
        ], timeout=self.settings.timeout)
        return Input(package, path)

    def knows_withdrawal(self, change: Change) -> bool:
        name, sums = self.expected_assets(change.tag)
        for release in self.releases():
            if release.get("tag_name") != change.tag or not self.eligible(
                release, final=bool(version_order(change.tag)[3]),
            ):
                continue
            assets = {asset["name"]: asset for asset in release.get("assets", ())}
            if name not in assets:
                return False
            digest = assets[name].get("digest")
            if digest is not None:
                return digest == f"sha256:{change.digest}"
            if sums in assets:
                raw = self.github_checksum(change.tag, sums).decode()
                return mirror.parse_sums(raw, sums).get(name) == change.digest
        return False

    def checked_input(
        self, release: dict, tag: str, inventory: Inventory, recorded: Package | None,
    ) -> Input | None:
        name, sums = self.expected_assets(tag)
        assets = {asset["name"]: asset for asset in release.get("assets", ())}
        if name not in assets or sums not in assets:
            raise ArchiveError(f"Release package or checksum is not listed for {tag}")
        listed = assets[name].get("digest")
        if recorded is not None and listed not in (None, f"sha256:{recorded.sha256}"):
            raise ReplacedInput
        tagged = self.github_checksum(tag, sums)
        digest = mirror.parse_sums(tagged.decode(), sums).get(name, "")
        if not APPROVED_HASH.fullmatch(digest):
            raise ArchiveError(f"Checksum asset does not list the package for {tag}")
        if recorded is not None and digest != recorded.sha256:
            raise ReplacedInput
        if digest in inventory.raw["withdrawn"].get(tag, ()):
            return None
        if listed not in (None, f"sha256:{digest}"):
            raise ArchiveError(f"GitHub asset digest differs from the checksum for {tag}")
        mirrored = self.published.read(mirror.object_key("", tag, sums))
        if mirrored != tagged:
            raise ArchiveError(f"GitHub and mirror checksum assets differ for {tag}")
        package = Package(tag, debian_version(tag[1:]), digest, assets[name].get("size"))
        if recorded is not None and package != recorded:
            raise ReplacedInput
        body = self.published.read(mirror.object_key("", tag, name))
        try:
            package.check(body)
        except ArchiveError:
            if recorded is not None:
                raise ReplacedInput from None
            raise
        return self.verify(package, name, body)

    def recover_pool(self, package: Package) -> Input:
        name, _ = self.expected_assets(package.tag)
        return self.verify(package, name, self.pool.read(package.key))

    def current_releases(self, admitted: dict[str, Package]) -> dict[str, dict | None]:
        current: dict[str, dict | None] = {}
        for release in self.releases():
            tag = release.get("tag_name")
            if not isinstance(tag, str) or not TAG.fullmatch(tag):
                continue
            if not self.eligible(release, final=bool(version_order(tag)[3])):
                continue
            if tag in current:
                raise ArchiveError(f"Duplicate published release {tag}")
            current[tag] = release
        for tag in admitted:
            current.setdefault(tag, None)
        return current

    def qualify(
        self, release: dict | None, tag: str, inventory: Inventory, recorded: Package | None,
        admitted: set[str],
    ) -> Input | None:
        try:
            if release is None:
                raise ArchiveError(f"Release no longer listed for {tag}")
            result = self.checked_input(release, tag, inventory, recorded)
        except ReplacedInput:
            self.notice(f"Refused replacement bytes for admitted release {tag}", "upstream")
            if recorded is not None and recorded.key in admitted and not inventory.blocked(recorded):
                return self.recover_pool(recorded)
            return None
        except (ArchiveError, mirror.MirrorError, OSError, UnicodeError):
            if recorded is not None and recorded.key in admitted and not inventory.blocked(recorded):
                self.notice(f"Upstream package evidence is unavailable for {tag}", "upstream")
                return self.recover_pool(recorded)
            if recorded is None:
                now = int(self.clock().timestamp())
                first_skip = inventory.raw["unqualified_since"].setdefault(tag, now)
                over_delay = now - first_skip >= self.unqualified_delay.total_seconds()
                self.notice(f"Skipped package qualification for {tag}", "unqualified" if over_delay else None)
            return None
        inventory.raw["unqualified_since"].pop(tag, None)
        return result

    def select(self, inventory: Inventory) -> dict[str, list[Input]]:
        choices: dict[bool, list[Input]] = {True: [], False: []}
        recorded = {package.tag: package for package in inventory.packages.values()}
        admitted = {key for keys in inventory.raw["desired"].values() for key in keys}
        admitted_by_tag = {tag: package for tag, package in recorded.items() if package.key in admitted}
        current = self.current_releases(admitted_by_tag)
        history = inventory.raw["unqualified_since"]
        for tag in history.keys() - current.keys():
            del history[tag]
        for tag in sorted(current, key=version_order, reverse=True):
            final = bool(version_order(tag)[3])
            limit = self.settings.finals if final else self.settings.candidates
            if len(choices[final]) >= limit:
                history.pop(tag, None)
                continue
            item = self.qualify(current[tag], tag, inventory, recorded.get(tag), admitted)
            if item is not None:
                choices[final].append(item)
        stable = choices[True]
        return {"stable": stable, "candidate": stable + choices[False]}


class ReplacedInput(ArchiveError):
    """A newly listed object does not match its previously admitted identity."""


def fixture_signing(home: Path, passphrase: bytes, timeout: float, *, validity_days: int = 1) -> str:
    """A fresh rehearsal key, confined to that run's distinct archive prefix."""
    options = ["gpg", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0"]
    stdin = passphrase + b"\n"
    expiry = f"{validity_days}d"
    run([*options, "--quick-generate-key", "APT rehearsal", "rsa2048", "cert", expiry],
        input_bytes=stdin, timeout=timeout)
    primary = run([
        "gpg", "--homedir", str(home), "--batch", "--with-colons", "--list-keys",
    ], timeout=timeout).decode().splitlines()
    fingerprint, = [row.split(":")[9] for row in primary if row.startswith("fpr:")]
    run([*options, "--quick-add-key", fingerprint, "rsa2048", "sign", expiry],
        input_bytes=stdin, timeout=timeout)
    rows = run([
        "gpg", "--homedir", str(home), "--batch", "--with-colons", "--with-subkey-fingerprint",
        "--list-keys", fingerprint,
    ], timeout=timeout).decode().splitlines()
    _, subkey = [row.split(":")[9] for row in rows if row.startswith("fpr:")]
    return subkey


def public_inventory(public: HttpArchive) -> Inventory:
    try:
        return Inventory(public.read(INVENTORY))
    except MissingObject:
        return Inventory()


def import_signing_subkey(home: Path, secret: bytes, fingerprint: str, timeout: float) -> None:
    gpg = ["gpg", "--homedir", str(home), "--batch"]
    run([*gpg, "--import"], input_bytes=secret, timeout=timeout)
    rows = run([
        *gpg, "--with-colons", "--with-subkey-fingerprint", "--list-secret-keys",
    ], timeout=timeout).decode().splitlines()
    records = [row.split(":") for row in rows]
    primary = [row for row in records if row[0] == "sec"]
    if len(primary) != 1 or primary[0][14] != "#":
        raise ArchiveError("Signing input must contain one stub primary and no private primary key")
    for record, following in zip(records, records[1:]):
        if (record[0] == "ssb" and "s" in record[11] and record[14] == "+"
                and following[0] == "fpr" and following[9] == fingerprint):
            return
    raise ArchiveError("Configured fingerprint does not identify an available signing subkey")


def signing(
    args: argparse.Namespace, home: Path, store: R2Store, public: HttpArchive,
) -> tuple[Signer, bytes]:
    configured = os.environ.get("APT_REPO_SIGNING_SUBKEY_FINGERPRINT", "")
    secret = os.environ.get("APT_REPO_SIGNING_SUBKEY", "")
    passphrase = os.environ.get("APT_REPO_SIGNING_PASSPHRASE", "").encode()
    configured_public = os.environ.get("APT_REPO_PUBLIC_KEYRING", "")
    if args.rehearsal:
        if secret or passphrase or configured:
            raise ArchiveError("Rehearsal must use only fixture signing keys")
        passphrase = os.urandom(24).hex().encode()
        configured = fixture_signing(home, passphrase, args.timeout, validity_days=args.valid_hours // 24 + 2)
    else:
        if not secret or not passphrase or b"\n" in passphrase or not FINGERPRINT.fullmatch(configured):
            raise ArchiveError("APT signing subkey, passphrase and full fingerprint are required")
        import_signing_subkey(home, secret.encode(), configured, args.timeout)
    current = store.get(KEYRING)
    if configured_public:
        try:
            exported = base64.b64decode(configured_public, validate=True)
        except binascii.Error as error:
            raise ArchiveError("Public archive keyring is not valid base64") from error
    else:
        exported = run([
            "gpg", "--homedir", str(home), "--batch", "--export-options", "export-minimal",
            "--export", configured,
        ], timeout=args.timeout)
        if current is not None and current.body != exported:
            raise ArchiveError("An established archive keyring requires the owner-approved keyring for rotation")
    if not exported:
        raise ArchiveError("No public archive keyring was found")
    keyring = home / "archive.gpg"
    keyring.write_bytes(exported)
    signer = Signer(home, keyring, configured, args.timeout)
    now = datetime.now(timezone.utc)
    expires = signer.expires_at()
    if expires <= now + timedelta(hours=args.valid_hours):
        raise ArchiveError("Signing subkey expires before the next archive snapshot")
    if not args.rehearsal:
        warn_key_rotation(expires, now, args.key_alert_days)
    signer.sign(b"Servonaut APT signing check\n", passphrase)
    if current is None or current.body != exported:
        store.put(KEYRING, exported, etag=current.etag if current is not None else None)
    if public.read(KEYRING) != exported:
        raise ArchiveError("Public archive keyring failed readback")
    if args.rehearsal:
        print(f"Rehearsal signing fingerprint: {configured}")
    return signer, passphrase


def parser() -> argparse.ArgumentParser:
    arguments = argparse.ArgumentParser(description=__doc__)
    arguments.add_argument(
        "--action", choices=("publish", "withdraw", "restore", "pause", "resume", "audit",
                             "cleanup-rehearsal", "sweep-rehearsals"), default="publish",
    )
    arguments.add_argument("--tag", default="")
    arguments.add_argument("--digest", default="")
    arguments.add_argument("--repo", required=True)
    arguments.add_argument("--base", required=True)
    arguments.add_argument("--prefix", required=True)
    arguments.add_argument("--rehearsal", action="store_true")
    arguments.add_argument("--dry-run", action="store_true")
    for name in ("finals", "candidates", "valid-hours", "pool-days", "index-days", "alert-hours",
                 "split-minutes", "attempts", "timeout", "max-bytes", "checksum-max-bytes",
                 "key-alert-days", "rehearsal-retention-hours", "unqualified-alert-hours"):
        default = os.environ.get("APT_" + name.replace("-", "_").upper())
        arguments.add_argument(f"--{name}", type=int, default=default, required=default is None)
    return arguments


def notice(message: str, alert: str | None = None) -> None:
    """Send safe diagnostics and signal an operational issue to the workflow."""
    print(f"::warning::{message}")
    if alert and (output := os.environ.get("GITHUB_OUTPUT")):
        with open(output, "a", encoding="utf-8") as stream:
            stream.write(f"{alert}=true\n")


def warn_key_rotation(expires: datetime, now: datetime, lead_days: int) -> None:
    if expires <= now + timedelta(days=lead_days):
        notice("APT signing subkey is inside its rotation window", "rotation")


def execute(args: argparse.Namespace, scratch: Path) -> None:
    if args.rehearsal:
        if not REHEARSAL_PREFIX.fullmatch(args.prefix) or args.action in ("audit", "sweep-rehearsals"):
            raise ArchiveError("Rehearsal requires a fresh, separate run prefix")
    elif args.prefix != "apt":
        raise ArchiveError("Use the production archive prefix or an explicit rehearsal")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        raise ArchiveError("Invalid GitHub repository")
    settings = Settings(
        args.finals, args.candidates, timedelta(hours=args.valid_hours), timedelta(days=args.pool_days),
        timedelta(days=args.index_days), timedelta(hours=args.alert_hours), timedelta(minutes=args.split_minutes),
        args.attempts, args.timeout,
    )
    if min(args.rehearsal_retention_hours, args.unqualified_alert_hours) <= 0:
        raise ArchiveError("Rehearsal retention and qualification delays must be positive")
    if args.key_alert_days <= 0:
        raise ArchiveError("Signing rotation lead time must be positive")
    if not 0 < args.checksum_max_bytes <= args.max_bytes:
        raise ArchiveError("Object size budget must be positive")
    public = HttpArchive(args.base, args.prefix, args.timeout, args.max_bytes)
    if args.action in ("cleanup-rehearsal", "sweep-rehearsals"):
        if args.dry_run or args.tag or args.digest or (args.action == "cleanup-rehearsal" and not args.rehearsal):
            raise ArchiveError("Invalid rehearsal cleanup request")
        client, bucket = mirror.bucket_client()
        if args.action == "cleanup-rehearsal":
            clear_rehearsals(client, bucket, prefix=args.prefix)
        else:
            deadline = datetime.now(timezone.utc) - timedelta(hours=args.rehearsal_retention_hours)
            clear_rehearsals(client, bucket, older_than=deadline)
        return
    source = VerifiedReleases(
        args.repo, HttpArchive(args.base, "", args.timeout, args.max_bytes), scratch, settings,
        pool=public, checksum_budget=args.checksum_max_bytes, notice=notice,
        unqualified_delay=timedelta(hours=args.unqualified_alert_hours),
    )
    home = scratch / "gnupg"
    home.mkdir(mode=0o700)
    if args.action == "audit":
        path = home / "archive.gpg"
        path.write_bytes(public.read(KEYRING))
        signer = Signer(home, path, os.environ.get("APT_REPO_SIGNING_SUBKEY_FINGERPRINT", ""), args.timeout)
        now = datetime.now(timezone.utc)
        expires = signer.expires_at()
        warn_key_rotation(expires, now, args.key_alert_days)
        audit(public, Inventory(public.read(INVENTORY)), signer.verify, settings=settings, now=now,
              key_expires=expires)
        print("Public APT archive signatures, expiry, inventory and bytes verified.")
        return

    change = Change(args.action, args.tag, args.digest)
    if args.dry_run:
        inventory = public_inventory(public)
        inventory.change(change, source.knows_withdrawal)
        inputs = {"stable": [], "candidate": []} if inventory.raw["paused"] else source.select(inventory)
        if change.action == "withdraw":
            print(f"Would withdraw APT package {change.tag} with SHA-256 {change.digest}")
        for suite, artifacts in inputs.items():
            build_indexes(artifacts, scratch, settings.timeout)
            print(f"{suite}: " + (", ".join(item.package.tag for item in artifacts) or "(empty)"))
        return

    client, bucket = mirror.bucket_client()
    store = R2Store(client, bucket, args.prefix, args.max_bytes)

    @cache
    def get_signing() -> tuple[Signer, bytes]:
        return signing(args, home, store, public)

    def sign(plain: bytes) -> bytes:
        signer, phrase = get_signing()
        return signer.sign(plain, phrase)

    try:
        publisher = Publisher(
            store, public, settings, scratch, source.select, build_indexes,
            sign, lambda signed: get_signing()[0].verify(signed), knows_release=source.knows_withdrawal,
        )
        if args.rehearsal and change.action != "publish":
            publisher.publish()
        publisher.publish(change)
    finally:
        with suppress(ArchiveError):
            run(["gpgconf", "--homedir", str(home), "--kill", "all"], timeout=args.timeout)
    print(f"APT {change.action} completed for {args.prefix}.")


def main() -> int:
    args = parser().parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix="servonaut-apt-") as directory:
            execute(args, Path(directory))
    except (ArchiveError, mirror.MirrorError) as error:
        print(f"APT publication failed: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"APT publication failed ({type(error).__name__}).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
