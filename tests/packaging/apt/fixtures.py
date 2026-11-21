"""Shared fixtures for the local APT archive tests."""

from __future__ import annotations

import gzip
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / ".github" / "scripts"))

from apt_archive import (  # noqa: E402
    Conflict, Input, MissingObject, Object, Package, Settings, sha256,
)
from scripts.distribution.package_deb import debian_version  # noqa: E402

SETTINGS = Settings(2, 2, timedelta(hours=48), timedelta(days=30),
                    timedelta(days=7), timedelta(hours=24), timedelta(minutes=30), 3, 30)
NOW = datetime(2030, 1, 4, tzinfo=timezone.utc)


class FixtureStore:
    """In-process conditional object store, with optional file:// projection."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root
        self.objects: dict[str, Object] = {}
        self.events: list[tuple[str, str]] = []
        self.before_put: Callable[[str, bytes], None] | None = None

    def get(self, key: str) -> Object | None:
        return self.objects.get(key)

    def put(self, key: str, body: bytes, *, etag: str | None, immutable: bool = False) -> None:
        if self.before_put is not None:
            self.before_put(key, body)
        existing = self.objects.get(key)
        if etag != (existing.etag if existing else None):
            raise Conflict(key)
        self.objects[key] = Object(body, sha256(body))
        self.events.append(("put", key))
        if self.root is not None:
            path = self.root / key
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            path.chmod(0o644)

    def delete(self, key: str) -> None:
        self.objects.pop(key, None)
        self.events.append(("delete", key))
        if self.root is not None:
            (self.root / key).unlink(missing_ok=True)

    def read(self, key: str) -> bytes:
        obj = self.get(key)
        if obj is None:
            raise MissingObject(key)
        return obj.body

    def denied(self, key: str) -> bool:
        return self.get(key) is None


def sample(root: Path, tag: str, body: bytes | None = None) -> Input:
    content = body if body is not None else tag.encode()
    version = debian_version(tag[1:])
    path = root / f"fixture_{version}.deb"
    path.write_bytes(content)
    return Input(Package(tag, version, sha256(content), len(content)), path)


def plain_fixture_indexes(inputs: list[Input], scratch: Path, timeout: float) -> dict[str, bytes]:
    del scratch, timeout
    rows = []
    for row in sorted((item.package for item in inputs), key=lambda package: package.key):
        rows.append(
            f"Package: servonaut\nVersion: {row.version}\nArchitecture: amd64\n"
            f"Filename: {row.key}\nSize: {row.size}\nSHA256: {row.sha256}\n\n"
        )
    plain = "".join(rows).encode()
    return {"Packages": plain, "Packages.gz": gzip.compress(plain, mtime=0)}
