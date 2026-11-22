"""Read package releases and bind pip to a checked distribution file."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from servonaut.updates.status import public_version
from servonaut.utils.endpoints import endpoint_override
from servonaut.utils.package_version import PackageVersion
from servonaut.utils.tls import build_opener

DEFAULT_PROJECT_URL = "https://pypi.org/pypi/servonaut/json"
DEFAULT_INDEX_URL = "https://pypi.org/simple/"
_READ_CHUNK = 64 * 1024
_MAX_JSON_BYTES = 8 * 1024 * 1024
_LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}


class UpdateUnavailable(ValueError):
    """The update could not be selected or verified safely."""


class ManualUpdateRequired(UpdateUnavailable):
    """This installation must use its existing package-management workflow."""


def _origin(url: str) -> tuple[str, str | None, int | None]:
    parts = urllib.parse.urlsplit(url)
    if parts.username is not None or parts.password is not None:
        raise UpdateUnavailable("Update URLs cannot contain credentials")
    return parts.scheme, parts.hostname, parts.port


class _RestrictedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _origin(req.full_url) != _origin(newurl):
            raise UpdateUnavailable("Update download changed origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url: str, timeout: float, headers: Mapping[str, str] | None = None):
    request = urllib.request.Request(url, headers=dict(headers or {}))
    return build_opener(_RestrictedRedirects()).open(request, timeout=timeout)


def read_document(url: str, timeout: float, headers: Mapping[str, str] | None = None) -> dict:
    with _open(url, timeout, headers) as response:
        data = response.read(_MAX_JSON_BYTES + 1)
    if len(data) > _MAX_JSON_BYTES:
        raise UpdateUnavailable("Update metadata is too large")
    document = json.loads(data)
    if not isinstance(document, dict):
        raise UpdateUnavailable("Update metadata is invalid")
    return document


def _same_loopback(left: str, right: str) -> bool:
    scheme, host, port = _origin(left)
    other_scheme, other_host, other_port = _origin(right)
    return (
        host in _LOOPBACK_NAMES and other_host in _LOOPBACK_NAMES
        and scheme == other_scheme and port == other_port
    )


@dataclass(frozen=True)
class Wheel:
    filename: str
    url: str
    digest: str
    size: int


class PackageIndex:
    def __init__(self) -> None:
        self.url = endpoint_override("SERVONAUT_PYPI_URL") or DEFAULT_PROJECT_URL
        self.index_url = os.environ.get("PIP_INDEX_URL") or DEFAULT_INDEX_URL
        if self.url == DEFAULT_PROJECT_URL:
            if self.index_url.rstrip("/") != DEFAULT_INDEX_URL.rstrip("/"):
                raise ManualUpdateRequired("Update uses a custom package index")
        elif not _same_loopback(self.url, self.index_url):
            raise ManualUpdateRequired("Update uses a custom package index")
        if any(os.environ.get(key) for key in (
            "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_NO_INDEX", "PIPX_GLOBAL",
            "PIP_CONSTRAINT", "PIP_TARGET", "PIP_PREFIX", "PIP_ROOT", "PIP_USER",
            "PIP_REQUIREMENT", "PIP_EDITABLE", "PIP_TRUSTED_HOST",
        )):
            raise ManualUpdateRequired("Update uses custom package settings")

    def document(self, timeout: float) -> dict[str, Any]:
        return read_document(self.url, timeout, {"Accept": "application/json"})

    def wheel(self, document: dict, version: str) -> Wheel | None:
        releases = document.get("releases")
        files = releases.get(version) if isinstance(releases, dict) else None
        if not isinstance(files, list):
            return None
        filename = f"servonaut-{version}-py3-none-any.whl"
        matching = [record for record in files if isinstance(record, dict)
                    and record.get("filename") == filename]
        if len(matching) != 1:
            return None
        record = matching[0]
        if record.get("yanked") is not False:
            return None
        url = record.get("url")
        digests = record.get("digests")
        digest = digests.get("sha256") if isinstance(digests, dict) else None
        size = record.get("size")
        if (not isinstance(url, str) or not isinstance(digest, str)
                or re.fullmatch(r"[a-f0-9]{64}", digest) is None
                or type(size) is not int or size <= 0):
            return None
        if self.url == DEFAULT_PROJECT_URL:
            if _origin(url) != ("https", "files.pythonhosted.org", None):
                return None
        elif not _same_loopback(url, self.url):
            return None
        return Wheel(filename, url, digest, size)

    def target(self, document: dict, current: str, channel: str) -> str | None:
        version = public_version(current)
        releases = document.get("releases")
        if version is None or not isinstance(releases, dict):
            return None
        candidates = []
        for label in releases:
            candidate = PackageVersion.parse(label)
            if not candidate or candidate <= version or candidate.dev is not None:
                continue
            if candidate.pre is not None and (channel != "rc" or candidate.pre[0] != 2):
                continue
            if self.wheel(document, label) is not None:
                candidates.append(candidate)
        newest = max(candidates, default=None)
        return newest.text if newest else None


def _copy_wheel(wheel: Wheel, path: Path, timeout: float) -> None:
    size = 0
    digest = hashlib.sha256()
    deadline = time.monotonic() + timeout
    with _open(wheel.url, timeout) as response, path.open("wb") as output:
        while chunk := response.read(_READ_CHUNK):
            size += len(chunk)
            if size > wheel.size or time.monotonic() > deadline:
                raise UpdateUnavailable("Update download exceeded its limits")
            digest.update(chunk)
            output.write(chunk)
    if size != wheel.size or digest.hexdigest() != wheel.digest:
        raise UpdateUnavailable("Update wheel failed its integrity check")


@contextmanager
def pinned_wheel(index: PackageIndex, version: str, wheel: Wheel, directory: Path,
                 timeout: Callable[[], float]) -> Iterator[tuple[str, dict[str, str]]]:
    """Bind the install subprocess to the selected wheel and exact version."""
    if index.wheel(index.document(timeout()), version) != wheel:
        raise UpdateUnavailable("The selected file changed or was withdrawn")
    with tempfile.TemporaryDirectory(prefix="wheel-", dir=directory) as scratch:
        root = Path(scratch)
        path = root / wheel.filename
        _copy_wheel(wheel, path, timeout())
        # Decide again after the download, immediately before pip can install it.
        if index.wheel(index.document(timeout()), version) != wheel:
            raise UpdateUnavailable("The selected file changed or was withdrawn")
        constraint = root / "constraints.txt"
        constraint.write_text(f"servonaut=={version}\n", encoding="utf-8")
        environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("PIP_")}
        yield f"{path.as_uri()}#sha256={wheel.digest}", {
            **environment,
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_INDEX_URL": index.index_url,
            "PIP_CONSTRAINT": constraint.as_uri(),
            "PIP_NO_INPUT": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        }
