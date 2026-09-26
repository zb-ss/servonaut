"""Bounded download and single-member extraction of checksum-pinned assets.

Build tooling uses this to fetch a reviewed third-party executable from its
release page. The request URL and every redirect must pass the caller's URL
rule; the declared length, the streamed size and a wall-clock deadline bound
the transfer (``read1`` returns whatever has arrived, so a server that trickles
bytes cannot hold a read past the deadline); the digest must match the pin; and
extraction copies one regular file out of an archive whose every member is
safe. Callers supply their own error type and message label.
"""

from __future__ import annotations

import hashlib
import http.client
import stat
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Literal

_CHUNK_BYTES = 1024 * 1024
_ZIP_ENCRYPTED_FLAG = 0x1


@dataclass(frozen=True)
class AssetRules:
    """One caller's error type, message label and URL rule.

    ``validate_url(url, is_redirect)`` raises ``error`` for a URL the caller
    does not accept: the request URL (``is_redirect=False``) and every
    redirect target and final URL (``is_redirect=True``).
    """

    label: str
    error: type[Exception]
    validate_url: Callable[[str, bool], None]

    def fail(self, message: str) -> Exception:
        return self.error(f"{self.label} {message}")


class _ValidatingRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only when the caller's URL rule accepts its target."""

    def __init__(self, rules: AssetRules) -> None:
        super().__init__()
        self._rules = rules

    def redirect_request(  # type: ignore[override]
        self,
        request: urllib.request.Request,
        file_pointer: BinaryIO,
        code: int,
        message: str,
        headers: http.client.HTTPMessage,
        new_url: str,
    ) -> urllib.request.Request | None:
        self._rules.validate_url(new_url, True)
        return super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )


Opener = Callable[[urllib.request.Request, float], http.client.HTTPResponse]


def check_download_url(
    rules: AssetRules, value: str, allowed_hosts: frozenset[str], *, is_redirect: bool
) -> None:
    """Accept a plain https URL on an allowed host; only redirects carry a query.

    Callers pin the request URL to their origin host and pass their reviewed
    redirect hosts for redirects and the final URL.
    """
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise rules.fail("download URL is invalid") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed_hosts
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
        or (not is_redirect and parsed.query)
    ):
        raise rules.fail("download URL is invalid")


def validating_opener(rules: AssetRules) -> Opener:
    """Return an opener whose redirects must satisfy ``rules``."""
    opener = urllib.request.build_opener(_ValidatingRedirects(rules))
    return lambda request, timeout: opener.open(request, timeout=timeout)


def download_pinned_asset(
    rules: AssetRules,
    url: str,
    destination: Path,
    expected_sha256: str,
    *,
    max_bytes: int,
    deadline_seconds: float,
    socket_timeout_seconds: float,
    opener: Opener | None = None,
) -> None:
    """Fetch one pinned asset into a new file within size and time limits.

    A blocked read is bounded by ``socket_timeout_seconds``, so the whole
    transfer ends within the deadline plus one socket timeout.
    """
    rules.validate_url(url, False)
    request = urllib.request.Request(
        url, headers={"Accept": "application/octet-stream"}
    )
    open_url = opener or validating_opener(rules)
    deadline = time.monotonic() + deadline_seconds
    digest = hashlib.sha256()
    total = 0
    created = False
    try:
        with open_url(request, socket_timeout_seconds) as response:
            rules.validate_url(response.geturl(), True)
            _require_declared_length(rules, response, max_bytes)
            with destination.open("xb") as handle:
                created = True
                while chunk := response.read1(_CHUNK_BYTES):
                    if time.monotonic() > deadline:
                        raise rules.fail("download timed out")
                    total += len(chunk)
                    if total > max_bytes:
                        raise rules.fail("download exceeds its size limit")
                    digest.update(chunk)
                    handle.write(chunk)
    except rules.error:
        _discard(destination, created)
        raise
    except (OSError, urllib.error.URLError, http.client.HTTPException) as error:
        _discard(destination, created)
        raise rules.fail("download failed") from error
    if digest.hexdigest() != expected_sha256:
        _discard(destination, created)
        raise rules.fail("download checksum does not match policy")


def extract_pinned_member(
    rules: AssetRules,
    archive_path: Path,
    archive_format: Literal["zip", "tar.gz"],
    member_name: str,
    destination: Path,
    max_bytes: int,
) -> None:
    """Copy one regular-file member into a new file; every member must be safe."""
    extract = _extract_zip_member if archive_format == "zip" else _extract_tar_member
    try:
        with _new_file(destination) as output:
            extract(rules, archive_path, member_name, output, max_bytes)
    except rules.error:
        raise
    except (
        OSError,
        EOFError,
        RuntimeError,
        zlib.error,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:
        raise rules.fail("archive is invalid") from error


def _require_declared_length(
    rules: AssetRules, response: http.client.HTTPResponse, maximum: int
) -> None:
    content_length = response.headers.get("Content-Length")
    if content_length is None:
        return
    try:
        declared_length = int(content_length)
    except ValueError as error:
        raise rules.fail("download length is invalid") from error
    if declared_length < 0 or declared_length > maximum:
        raise rules.fail("download exceeds its size limit")


def _discard(destination: Path, created: bool) -> None:
    """Remove only a partial file this download created itself."""
    if created:
        destination.unlink(missing_ok=True)


@contextmanager
def _new_file(destination: Path) -> Iterator[BinaryIO]:
    """Create ``destination`` and remove it again if filling it fails.

    An existing file is never opened, so a failure never deletes one.
    """
    handle = destination.open("xb")
    try:
        with handle:
            yield handle
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def _extract_zip_member(
    rules: AssetRules, archive_path: Path, member_name: str, output: BinaryIO, max_bytes: int
) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        members: dict[str, zipfile.ZipInfo] = {}
        total = 0
        for info in archive.infolist():
            name = _normalise_member(rules, info.filename)
            if name in members:
                raise rules.fail("archive has duplicate members")
            # Archives written on Windows record no file type; others must
            # declare a regular file. Encrypted members are never read.
            file_type = stat.S_IFMT(info.external_attr >> 16)
            if not info.is_dir() and (
                file_type not in {0, stat.S_IFREG} or info.flag_bits & _ZIP_ENCRYPTED_FLAG
            ):
                raise rules.fail("archive contains an unsafe member")
            total += info.file_size
            if info.file_size < 0 or total > max_bytes:
                raise rules.fail("archive exceeds its size limit")
            members[name] = info
        selected = members.get(member_name)
        if selected is None or selected.is_dir():
            raise rules.fail("executable member is missing")
        with archive.open(selected) as source:
            _copy_bounded(rules, source, output, max_bytes)


def _extract_tar_member(
    rules: AssetRules, archive_path: Path, member_name: str, output: BinaryIO, max_bytes: int
) -> None:
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members: dict[str, tarfile.TarInfo] = {}
        total = 0
        for info in archive.getmembers():
            name = _normalise_member(rules, info.name)
            if name in members:
                raise rules.fail("archive has duplicate members")
            if not (info.isfile() or info.isdir()):
                raise rules.fail("archive contains an unsafe member")
            total += info.size
            if info.size < 0 or total > max_bytes:
                raise rules.fail("archive exceeds its size limit")
            members[name] = info
        selected = members.get(member_name)
        if selected is None or not selected.isfile():
            raise rules.fail("executable member is missing")
        source = archive.extractfile(selected)
        if source is None:
            raise rules.fail("executable member is missing")
        with source:
            _copy_bounded(rules, source, output, max_bytes)


def _normalise_member(rules: AssetRules, value: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise rules.fail("archive member is invalid")
    stripped = value.removesuffix("/")
    path = PurePosixPath(stripped)
    if (
        not stripped
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in stripped.split("/"))
    ):
        raise rules.fail("archive member is invalid")
    return path.as_posix()


def _copy_bounded(
    rules: AssetRules, source: BinaryIO, output: BinaryIO, max_bytes: int
) -> None:
    total = 0
    while chunk := source.read(_CHUNK_BYTES):
        total += len(chunk)
        if total > max_bytes:
            raise rules.fail("executable exceeds its size limit")
        output.write(chunk)
