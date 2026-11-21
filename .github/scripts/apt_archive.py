"""Build, publish, and audit the signed Servonaut APT archive."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime
from pathlib import Path
from typing import Callable, Protocol

from scripts.distribution.package_deb import debian_version

SUITES = ("stable", "candidate")
COMPONENT = "main"
ARCH = "amd64"
PACKAGE = "servonaut"
POOL = "pool/main/s/servonaut/"
INVENTORY = "inventory.json"
KEYRING = "servonaut-archive-keyring.gpg"
INDEX_NAMES = ("Packages", "Packages.gz")
ALGORITHMS = ("SHA256", "SHA512")
APPROVED_HASH = re.compile(r"[0-9a-f]{64}")
FINGERPRINT = re.compile(r"[0-9A-F]{40}")
TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:rc([1-9][0-9]*))?")
POOL_KEY = re.compile(r"pool/main/s/servonaut/servonaut_[0-9.]+(?:~rc[0-9]+)?_amd64\.deb")
INDEX_KEY = re.compile(
    r"dists/(?:stable|candidate)/main/binary-amd64/by-hash/(?:SHA256/[a-f0-9]{64}|SHA512/[a-f0-9]{128})"
)


class ArchiveError(Exception):
    """Unsafe or incomplete publication evidence."""


class Conflict(ArchiveError):
    """A conditional object write lost to another attempt."""


class MissingObject(ArchiveError):
    """A required public object was absent."""


@dataclass(frozen=True)
class Object:
    body: bytes
    etag: str


class Store(Protocol):
    """The workflow serializes writers. Conditional writes fence stale plans."""

    def get(self, key: str) -> Object | None: ...
    def put(self, key: str, body: bytes, *, etag: str | None, immutable: bool = False) -> None: ...
    def delete(self, key: str) -> None: ...


class PublicArchive(Protocol):
    def read(self, key: str) -> bytes: ...
    def denied(self, key: str) -> bool: ...


@dataclass(frozen=True)
class Settings:
    finals: int
    candidates: int
    valid_for: timedelta
    pool_grace: timedelta
    index_grace: timedelta
    alert_before: timedelta
    split_grace: timedelta
    attempts: int
    timeout: float

    def __post_init__(self) -> None:
        if (
            min(self.finals, self.candidates, self.attempts, self.timeout) <= 0
            or not timedelta(0) < self.alert_before < self.valid_for
            or self.pool_grace < timedelta(days=30)
            or self.index_grace < timedelta(days=7)
            or self.split_grace < timedelta(0)
        ):
            raise ArchiveError("Invalid APT archive retention or timing configuration")


def version_order(tag: str) -> tuple[int, ...]:
    match = TAG.fullmatch(tag)
    if match is None:
        raise ArchiveError("Not a supported release tag")
    major, minor, patch, rc = match.groups()
    return int(major), int(minor), int(patch), int(rc is None), int(rc or 0)


@dataclass(frozen=True)
class Package:
    tag: str
    version: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        version_order(self.tag)
        if self.version != debian_version(self.tag[1:]):
            raise ArchiveError("Debian version does not match the release tag")
        if not APPROVED_HASH.fullmatch(self.sha256) or type(self.size) is not int or self.size <= 0:
            raise ArchiveError("Invalid package checksum or size")

    @property
    def key(self) -> str:
        return f"{POOL}{PACKAGE}_{self.version}_{ARCH}.deb"

    def check(self, body: bytes) -> None:
        if len(body) != self.size or sha256(body) != self.sha256:
            raise ArchiveError(f"Package bytes do not match {self.tag}")


@dataclass(frozen=True)
class Input:
    package: Package
    path: Path


@dataclass(frozen=True)
class Change:
    action: str = "publish"
    tag: str = ""
    digest: str = ""

    def __post_init__(self) -> None:
        if self.action in ("withdraw", "restore"):
            version_order(self.tag)
            if not APPROVED_HASH.fullmatch(self.digest):
                raise ArchiveError("Withdrawal requires an exact SHA-256 digest")
        elif self.action not in ("publish", "pause", "resume") or self.tag or self.digest:
            raise ArchiveError("Invalid APT policy action")


class Inventory:
    """Durable evidence and references, including a partly published snapshot."""

    def __init__(self, raw: bytes | None = None) -> None:
        document = json.loads(raw) if raw is not None else {
            "schema": 1, "paused": False, "withdrawn": {}, "packages": {},
            "retained": {}, "active": [], "desired": {}, "started": 0, "serial": "",
            "unqualified_since": {},
        }
        if isinstance(document, dict):
            document.setdefault("unqualified_since", {})
        if (
            not isinstance(document, dict)
            or set(document) != {
                "schema", "paused", "withdrawn", "packages", "retained", "active", "desired", "started", "serial",
                "unqualified_since",
            }
            or document["schema"] != 1
            or type(document["paused"]) is not bool
            or type(document["started"]) is not int
            or not isinstance(document["serial"], str)
            or document["serial"] and not re.fullmatch(r"[0-9a-f]{32}", document["serial"])
            or not all(isinstance(document[name], dict) for name in ("withdrawn", "packages", "retained", "desired"))
        ):
            raise ArchiveError("Invalid archive inventory")
        since = document["unqualified_since"]
        if not isinstance(since, dict) or any(
            not TAG.fullmatch(tag) or type(timestamp) is not int or timestamp < 0 for tag, timestamp in since.items()
        ):
            raise ArchiveError("Invalid package qualification history")
        self.raw = document
        self.packages = {key: Package(**row) for key, row in document["packages"].items()}
        if any(key != package.key for key, package in self.packages.items()):
            raise ArchiveError("Invalid package path in archive inventory")
        for tag, digests in document["withdrawn"].items():
            version_order(tag)
            if not isinstance(digests, list) or not all(APPROVED_HASH.fullmatch(value) for value in digests):
                raise ArchiveError("Invalid withdrawal policy")
        for key, expiry in document["retained"].items():
            if not (key in self.packages or INDEX_KEY.fullmatch(key)) or type(expiry) is not int:
                raise ArchiveError("Invalid retained archive reference")
        if not isinstance(document["active"], list) or set(document["active"]) - document["retained"].keys():
            raise ArchiveError("Untracked live archive reference")
        if (
            document["desired"].keys() - set(SUITES)
            or any(not isinstance(keys, list) or set(keys) - self.packages.keys()
                   for keys in document["desired"].values())
        ):
            raise ArchiveError("Invalid suite membership")

    def encode(self) -> bytes:
        return (json.dumps(self.raw, sort_keys=True, separators=(",", ":")) + "\n").encode()

    def blocked(self, package: Package) -> bool:
        return self.raw["paused"] or package.sha256 in self.raw["withdrawn"].get(package.tag, ())

    def change(
        self, change: Change, knows_release: Callable[[Change], bool] = lambda change: False,
    ) -> None:
        if change.action in ("pause", "resume"):
            self.raw["paused"] = change.action == "pause"
        if change.action == "withdraw" and not (
            any(package.tag == change.tag and package.sha256 == change.digest
                for package in self.packages.values())
            or change.digest in self.raw["withdrawn"].get(change.tag, ())
            or knows_release(change)
        ):
            raise ArchiveError("No known APT package matches the withdrawal tag and SHA-256")
        if change.action in ("withdraw", "restore"):
            digests = set(self.raw["withdrawn"].get(change.tag, ()))
            if change.action == "withdraw":
                digests.add(change.digest)
            else:
                digests.discard(change.digest)
            self.raw["withdrawn"][change.tag] = sorted(digests)

    def reserve(
        self, inputs: dict[str, list[Input]], hashed: set[str],
        now: datetime, settings: Settings, serial: str,
    ) -> None:
        selected = {item.package.key: item.package for rows in inputs.values() for item in rows}
        for key, package in selected.items():
            if self.packages.setdefault(key, package) != package:
                raise ArchiveError(f"Different bytes already belong to {package.tag}")
            self.raw["packages"][key] = asdict(package)
        self.raw["started"] = int(now.timestamp())
        self.raw["serial"] = serial
        self.raw["desired"] = {suite: sorted(item.package.key for item in rows) for suite, rows in inputs.items()}
        live = set(self.raw["active"]) | set(selected) | hashed
        for key in live:
            grace = settings.pool_grace if POOL_KEY.fullmatch(key) else settings.index_grace
            deadline = int((now + settings.valid_for + grace).timestamp())
            retained = self.raw["retained"]
            retained[key] = max(retained.get(key, 0), deadline)
        self.raw["active"] = sorted(live)


def sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def paths(suite: str, indexes: dict[str, bytes]) -> dict[str, bytes]:
    root = f"dists/{suite}/{COMPONENT}/binary-{ARCH}/"
    objects = {}
    for name, body in indexes.items():
        for algorithm in ALGORITHMS:
            digest = hashlib.new(algorithm.lower(), body).hexdigest()
            objects[f"{root}by-hash/{algorithm}/{digest}"] = body
        objects[root + name] = body
    return objects


def deb_fields(path: Path, timeout: float) -> dict[str, str]:
    raw = run(["dpkg-deb", "-f", str(path)], timeout=timeout).decode("utf-8")
    return paragraphs(raw)[0]


def paragraphs(document: str) -> list[dict[str, str]]:
    """Parse Debian control paragraphs, including folded fields."""
    output = []
    for paragraph in document.rstrip().split("\n\n"):
        if not paragraph:
            continue
        fields: dict[str, str] = {}
        name = ""
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")) and name:
                fields[name] += "\n" + line.strip()
                continue
            name, colon, value = line.partition(":")
            if not colon or not name or name in fields:
                raise ArchiveError("Malformed Debian control data")
            fields[name] = value.strip()
        output.append(fields)
    return output


def run(
    argv: list[str], *, timeout: float, input_bytes: bytes | None = None, cwd: Path | None = None,
) -> bytes:
    """Run a packaging or signing tool without reporting its private input."""
    excluded = {
        "APT_REPO_SIGNING_SUBKEY", "APT_REPO_SIGNING_PASSPHRASE",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "MIRROR_ENDPOINT", "MIRROR_BUCKET",
    }
    if argv[0] != "gh":
        excluded.update(("GH_TOKEN", "GITHUB_TOKEN"))
    env = {key: value for key, value in os.environ.items() if key not in excluded}
    try:
        result = subprocess.run(argv, input=input_bytes, capture_output=True, cwd=cwd, timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ArchiveError(f"{argv[0]} failed ({type(error).__name__})") from None
    if result.returncode:
        raise ArchiveError(f"{argv[0]} failed (exit {result.returncode})")
    return result.stdout


def validate_debian_fields(path: Path, package: Package, timeout: float) -> None:
    fields = deb_fields(path, timeout)
    expected = {"Package": PACKAGE, "Version": package.version, "Architecture": ARCH}
    if any(fields.get(field) != value for field, value in expected.items()):
        raise ArchiveError(f"Debian control fields do not match {package.tag}")


def build_indexes(inputs: list[Input], scratch: Path, timeout: float) -> dict[str, bytes]:
    """Index only checked packages, in relative-path order and without gzip time."""
    with tempfile.TemporaryDirectory(dir=scratch) as directory:
        root = Path(directory)
        (root / POOL).mkdir(parents=True)
        for item in inputs:
            item.package.check(item.path.read_bytes())
            validate_debian_fields(item.path, item.package, timeout)
            # The supplied file can belong to a different filesystem.
            shutil.copyfile(item.path, root / item.package.key)
        raw = run(["apt-ftparchive", "packages", "pool"], cwd=root, timeout=timeout)
        entries = raw.rstrip().split(b"\n\n") if raw.strip() else []
        plain = b"".join(entry + b"\n\n" for entry in sorted(entries))
        if index_packages(plain) != {item.package.key: item.package.sha256 for item in inputs}:
            raise ArchiveError("Generated package index did not match verified inputs")
        return {"Packages": plain, "Packages.gz": gzip.compress(plain, mtime=0)}


def index_packages(index: bytes) -> dict[str, str]:
    rows = {}
    for fields in paragraphs(index.decode("utf-8")):
        key, digest = fields.get("Filename", ""), fields.get("SHA256", "")
        expected = f"{POOL}{PACKAGE}_{fields.get('Version')}_{ARCH}.deb"
        if (
            not POOL_KEY.fullmatch(key) or key != expected
            or fields.get("Package") != PACKAGE or fields.get("Architecture") != ARCH
            or not APPROVED_HASH.fullmatch(digest) or key in rows
        ):
            raise ArchiveError("Invalid package record in APT index")
        rows[key] = digest
    return rows


def release(suite: str, indexes: dict[str, bytes], now: datetime, validity: timedelta, serial: str) -> bytes:
    fields = [
        "Origin: Servonaut", "Label: Servonaut", f"Suite: {suite}", f"Codename: {suite}",
        f"Date: {format_datetime(now, usegmt=True)}",
        f"Valid-Until: {format_datetime(now + validity, usegmt=True)}",
        f"Architectures: {ARCH}", f"Components: {COMPONENT}", "Acquire-By-Hash: yes",
        f"X-Servonaut-Snapshot: {serial}",
    ]
    for algorithm in ALGORITHMS:
        fields.append(f"{algorithm}:")
        for name, body in indexes.items():
            digest = hashlib.new(algorithm.lower(), body).hexdigest()
            fields.append(f" {digest} {len(body)} {COMPONENT}/binary-{ARCH}/{name}")
    return ("\n".join(fields) + "\n").encode()


class Signer:
    """Use an isolated home and independently verify plaintext and signing identity."""

    def __init__(self, home: Path, keyring: Path, fingerprint: str, timeout: float) -> None:
        if not FINGERPRINT.fullmatch(fingerprint):
            raise ArchiveError("Expected a full signing subkey fingerprint")
        self.home = home
        self.keyring = keyring.resolve()
        self.fingerprint = fingerprint
        self.timeout = timeout

    def verify(self, signed: bytes) -> bytes:
        with tempfile.TemporaryDirectory(dir=self.home) as directory:
            path = Path(directory) / "InRelease"
            path.write_bytes(signed)
            plain = Path(directory) / "Release"
            status = run([
                "gpgv", "--homedir", str(self.home), "--keyring", str(self.keyring),
                "--status-fd", "1", "--output", str(plain), str(path),
            ], timeout=self.timeout)
            records = [line.split(maxsplit=3) for line in status.splitlines()
                       if line.startswith(b"[GNUPG:] ")]
            rejected = {b"EXPKEYSIG", b"EXPSIG", b"REVKEYSIG", b"KEYEXPIRED", b"KEYREVOKED"}
            if any(row[1] in rejected for row in records):
                raise ArchiveError("InRelease signing key or signature is expired or revoked")
            fingerprint = self.fingerprint.encode("ascii")
            valid = [row[2] for row in records if row[1] == b"VALIDSIG"]
            good = [row[2] for row in records if row[1] == b"GOODSIG"]
            if valid != [fingerprint] or len(good) != 1 or good[0] not in (fingerprint, fingerprint[-16:]):
                raise ArchiveError("InRelease was not signed by the configured valid signing subkey")
            return plain.read_bytes()

    def expires_at(self) -> datetime:
        records = run([
            "gpg", "--homedir", str(self.home), "--batch", "--with-colons",
            "--with-subkey-fingerprint", "--show-keys", str(self.keyring),
        ], timeout=self.timeout).decode().splitlines()
        rows = [record.split(":") for record in records]
        primary_expiry = 0
        for key, fingerprint in zip(rows, rows[1:]):
            if key[0] == "pub":
                primary_expiry = int(key[6] or "0")
            if (key[0] == "sub" and "s" in key[11] and fingerprint[0] == "fpr"
                    and fingerprint[9] == self.fingerprint):
                deadlines = [expiry for expiry in (primary_expiry, int(key[6] or "0")) if expiry]
                if deadlines:
                    return datetime.fromtimestamp(min(deadlines), tz=timezone.utc)
                raise ArchiveError("The configured signing subkey needs a finite expiry")
        raise ArchiveError("The public keyring does not contain the configured signing subkey")

    def sign(self, plain: bytes, passphrase: bytes) -> bytes:
        with tempfile.TemporaryDirectory(dir=self.home) as directory:
            path = Path(directory) / "Release"
            path.write_bytes(plain)
            signed = run([
                "gpg", "--homedir", str(self.home), "--batch", "--pinentry-mode", "loopback",
                "--passphrase-fd", "0", "--local-user", self.fingerprint + "!", "--digest-algo",
                "SHA256", "--output", "-", "--clearsign", str(path),
            ], input_bytes=passphrase + b"\n", timeout=self.timeout)
            if self.verify(signed) != plain:
                raise ArchiveError("InRelease does not attest the intended Release bytes")
            return signed


def immutable(store: Store, key: str, body: bytes, *, cached: bool = False) -> None:
    prior = store.get(key)
    if prior is None:
        store.put(key, body, etag=None, immutable=cached)
    elif len(prior.body) != len(body) or sha256(prior.body) != sha256(body):
        raise ArchiveError(f"Immutable archive object differs: {key}")


def inrelease(suite: str) -> str:
    return f"dists/{suite}/InRelease"


def load_inventory(store: Store) -> tuple[Inventory, str | None]:
    current = store.get(INVENTORY)
    if current is None and any(store.get(inrelease(suite)) for suite in SUITES):
        # Never reconstruct away a withdrawal tombstone or a reader retention window.
        raise ArchiveError("Archive inventory missing; restore it before renewing signed metadata")
    return Inventory(current.body if current else None), current.etag if current else None


class Publisher:
    """Reconcile fresh inputs in the one protected workflow writer group."""

    def __init__(
        self, store: Store, public: PublicArchive, settings: Settings, scratch: Path,
        select: Callable[[Inventory], dict[str, list[Input]]],
        build: Callable[[list[Input], Path, float], dict[str, bytes]],
        sign: Callable[[bytes], bytes], verify: Callable[[bytes], bytes],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        *, knows_release: Callable[[Change], bool] = lambda change: False,
    ) -> None:
        self.store = store
        self.public = public
        self.settings = settings
        self.scratch = scratch
        self.select = select
        self.build = build
        self.sign = sign
        self.verify = verify
        self.clock = clock
        self.knows_release = knows_release

    def publish(self, change: Change = Change()) -> None:
        for _ in range(self.settings.attempts):
            try:
                self.reconcile(change)
                return
            except Conflict:
                # Re-read policy, release eligibility, and each suite ETag.
                continue
        raise ArchiveError("Concurrent archive change did not settle")

    def require_inventory(self, expected: str) -> None:
        current = self.store.get(INVENTORY)
        if current is None or current.etag != expected:
            raise Conflict("Archive policy or publication changed")

    def block_packages(self, inventory: Inventory) -> None:
        for package in inventory.packages.values():
            if not inventory.blocked(package):
                continue
            if self.store.get(package.key) is not None:
                self.store.delete(package.key)
            if not self.public.denied(package.key):
                raise ArchiveError(f"Withdrawn pool object is still public: {package.key}")

    def reconcile(self, change: Change) -> None:
        inventory, etag = load_inventory(self.store)
        if change.action != "publish":
            inventory.change(change, self.knows_release)
            self.store.put(INVENTORY, inventory.encode(), etag=etag)
            inventory, etag = load_inventory(self.store)
        # Block withdrawn bytes even if checking upstream or signing later fails.
        self.block_packages(inventory)
        now = self.clock()
        inputs = {suite: [] for suite in SUITES} if inventory.raw["paused"] else self.select(inventory)
        if set(inputs) != set(SUITES) or any(inventory.blocked(item.package) for rows in inputs.values() for item in rows):
            raise ArchiveError("Selected package conflicts with archive policy")
        indexes = {suite: self.build(inputs[suite], self.scratch, self.settings.timeout) for suite in SUITES}
        serial = os.urandom(16).hex()
        signed = {suite: self.sign(release(suite, indexes[suite], now, self.settings.valid_for, serial))
                  for suite in SUITES}
        objects = {suite: paths(suite, indexes[suite]) for suite in SUITES}
        hashed = {key for rows in objects.values() for key in rows if "/by-hash/" in key}
        previous = {suite: self.store.get(inrelease(suite)) for suite in SUITES}
        inventory.reserve(inputs, hashed, now, self.settings, serial)
        # Persist eligibility and retention before a client can see any of these objects.
        self.store.put(INVENTORY, inventory.encode(), etag=etag)
        recorded = self.store.get(INVENTORY)
        if recorded is None or recorded.body != inventory.encode():
            raise Conflict("Archive policy changed after reservation")
        active = set(hashed)
        for item in {item.package.key: item for rows in inputs.values() for item in rows}.values():
            self.require_inventory(recorded.etag)
            body = item.path.read_bytes()
            item.package.check(body)
            immutable(self.store, item.package.key, body)
            item.package.check(self.public.read(item.package.key))
            active.add(item.package.key)
        for suite, rows in objects.items():
            for key, body in rows.items():
                if "/by-hash/" in key:
                    self.require_inventory(recorded.etag)
                    immutable(self.store, key, body, cached=True)
                    if sha256(self.public.read(key)) != sha256(body):
                        raise ArchiveError(f"Public by-hash verification failed: {key}")
        for suite, rows in objects.items():
            for key, body in rows.items():
                if "/by-hash/" not in key:
                    self.require_inventory(recorded.etag)
                    current = self.store.get(key)
                    self.store.put(key, body, etag=current.etag if current else None)
        for suite in SUITES:
            self.require_inventory(recorded.etag)
            current = previous[suite]
            self.store.put(inrelease(suite), signed[suite], etag=current.etag if current else None)
        audit(self.public, inventory, self.verify, settings=self.settings, now=now, require_current=True)
        for key, until in list(inventory.raw["retained"].items()):
            if key not in active and until < int(now.timestamp()):
                self.require_inventory(recorded.etag)
                self.store.delete(key)
                del inventory.raw["retained"][key]
        inventory.raw["active"] = sorted(active)
        self.store.put(INVENTORY, inventory.encode(), etag=recorded.etag)


def audit(
    public: PublicArchive, inventory: Inventory, verify: Callable[[bytes], bytes], *,
    settings: Settings, now: datetime, require_current: bool = False,
    key_expires: datetime | None = None,
) -> None:
    snapshots = []
    for suite in SUITES:
        fields, = paragraphs(verify(public.read(inrelease(suite))).decode("utf-8"))
        required = {
            "Origin": "Servonaut", "Label": "Servonaut", "Suite": suite, "Codename": suite,
            "Architectures": ARCH, "Components": COMPONENT, "Acquire-By-Hash": "yes",
        }
        if any(fields.get(key) != value for key, value in required.items()):
            raise ArchiveError(f"Unexpected Release fields in {suite}")
        issued, expires = (parsedate_to_datetime(fields[key]) for key in ("Date", "Valid-Until"))
        if key_expires is not None and key_expires <= expires:
            raise ArchiveError(f"Signing subkey expires before the {suite} snapshot")
        if not issued <= now or expires - now <= settings.alert_before or expires - issued > settings.valid_for:
            raise ArchiveError(f"Signed {suite} snapshot is outside its renewal window")
        indexes: dict[str, bytes] = {}
        for algorithm in ALGORITHMS:
            entries = fields[algorithm].strip().splitlines()
            if len(entries) != len(INDEX_NAMES):
                raise ArchiveError(f"Unexpected index digests in {suite}")
            for name, entry in zip(INDEX_NAMES, entries):
                digest, size, path = entry.split()
                if path != f"{COMPONENT}/binary-{ARCH}/{name}" or not re.fullmatch(
                    "[0-9a-f]{" + str(int(algorithm[3:]) // 4) + "}", digest,
                ):
                    raise ArchiveError(f"Invalid index path or digest in {suite}")
                by_hash = f"dists/{suite}/{COMPONENT}/binary-{ARCH}/by-hash/{algorithm}/{digest}"
                body = public.read(by_hash)
                if hashlib.new(algorithm.lower(), body).hexdigest() != digest or len(body) != int(size):
                    raise ArchiveError(f"Corrupt by-hash data in {suite}")
                if name in indexes and indexes[name] != body:
                    raise ArchiveError(f"Signed digests identify different indexes in {suite}")
                indexes[name] = body
        if gzip.decompress(indexes["Packages.gz"]) != indexes["Packages"]:
            raise ArchiveError(f"Compressed and plain indexes differ in {suite}")
        keys = index_packages(indexes["Packages"])
        for key, digest in keys.items():
            package = inventory.packages.get(key)
            if package is None or inventory.blocked(package) or package.sha256 != digest:
                raise ArchiveError(f"Index includes an unverified or blocked package in {suite}")
            if suite == "stable" and not version_order(package.tag)[3]:
                raise ArchiveError("Stable suite advertises a release candidate")
            package.check(public.read(key))
        snapshots.append((suite, fields["X-Servonaut-Snapshot"], issued, sorted(keys), indexes))
    if {row[1] for row in snapshots} != {inventory.raw["serial"]}:
        started = datetime.fromtimestamp(inventory.raw["started"], tz=timezone.utc)
        if require_current or now - started >= settings.split_grace:
            raise ArchiveError("The signed suites differ from the current archive snapshot")
        return
    for suite, _, _, keys, indexes in snapshots:
        if keys != inventory.raw["desired"].get(suite):
            raise ArchiveError(f"Signed {suite} membership differs from verified inventory")
        for name, body in indexes.items():
            if public.read(f"dists/{suite}/{COMPONENT}/binary-{ARCH}/{name}") != body:
                raise ArchiveError(f"Canonical {suite} index differs from its signed snapshot")
    for package in inventory.packages.values():
        if inventory.blocked(package) and not public.denied(package.key):
            raise ArchiveError(f"Blocked pool object is still public: {package.key}")
