"""Offline stand-ins for the pinned voice model downloads.

The downloader talks to the network through a ``urllib`` opener, so tests
hand it :class:`FakeOpener` instead: canned responses keyed by URL, with
every request recorded. Specs are built with pins computed from the bytes
the test serves, so a test controls exactly which verification passes.
"""

from __future__ import annotations

import dataclasses
import hashlib
import io
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
import urllib.request

from servonaut.services.voice_models import (
    VoiceModelAsset,
    VoiceModelDownloader,
    VoiceModelDownloadPolicy,
    VoiceModelSpec,
)

#: No pause between resume attempts, so failure paths stay fast.
FAST_RETRY = VoiceModelDownloadPolicy(retry_delay_seconds=0.0)


class FakeResponse:
    """File-like HTTP response over fixed bytes.

    ``fail_after`` raises that exception once the bytes are served, like a
    connection dropping mid-body. ``gate`` blocks every read after the
    first until the test sets it.
    """

    def __init__(
        self,
        data: bytes = b"",
        *,
        status: int = 200,
        content_length: Optional[int] = None,
        content_range: Optional[str] = None,
        fail_after: Optional[Exception] = None,
        chunk_limit: Optional[int] = None,
        gate: Optional[threading.Event] = None,
    ) -> None:
        self._data = io.BytesIO(data)
        self._fail_after = fail_after
        self._chunk_limit = chunk_limit
        self._gate = gate
        self.status = status
        self.reads = 0
        self.headers: Dict[str, str] = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)
        if content_range is not None:
            self.headers["Content-Range"] = content_range

    def read(self, amt: int = -1) -> bytes:
        self.reads += 1
        if self._gate is not None and self.reads > 1:
            self._gate.wait(5)
        if self._chunk_limit is not None:
            amt = self._chunk_limit if amt < 0 else min(amt, self._chunk_limit)
        chunk = self._data.read(amt)
        if not chunk and self._fail_after is not None:
            raise self._fail_after
        return chunk

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: Any) -> None:
        pass


Canned = Union[FakeResponse, Exception, Callable[[], FakeResponse]]


class FakeOpener:
    """Serves canned responses keyed by URL and records every request.

    A list is served one entry per request, in order; a single entry
    answers every request for that URL. A callable builds a fresh response
    per request, so a body can be served more than once.
    """

    def __init__(self, responses: Dict[str, Union[Canned, List[Canned]]]) -> None:
        self._responses = responses
        self.requested: List[str] = []
        self.ranges: List[Optional[str]] = []
        self.timeouts: List[Optional[float]] = []

    def open(self, request: urllib.request.Request, timeout: Optional[float] = None) -> FakeResponse:
        self.requested.append(request.full_url)
        self.ranges.append(request.get_header("Range"))
        self.timeouts.append(timeout)
        canned = self._responses[request.full_url]
        response = canned.pop(0) if isinstance(canned, list) else canned
        if isinstance(response, Exception):
            raise response
        if callable(response):
            return response()
        return response


def pinned_asset(filename: str, data: bytes, **overrides: Any) -> VoiceModelAsset:
    """An asset served from ``https://models.example`` and pinned to *data*."""
    return VoiceModelAsset(
        filename=filename,
        url=overrides.pop("url", f"https://models.example/{filename}"),
        expected_size=overrides.pop("expected_size", len(data)),
        expected_sha256=overrides.pop("expected_sha256", hashlib.sha256(data).hexdigest()),
        **overrides,
    )


def with_assets(spec: VoiceModelSpec, *assets: VoiceModelAsset) -> VoiceModelSpec:
    """*spec* with its assets replaced; identity, paths and required files kept."""
    return dataclasses.replace(spec, assets=assets)


def serving(files: Dict[str, bytes]) -> FakeOpener:
    """An opener that serves each asset of :func:`pinned_asset` by filename."""
    return FakeOpener({
        f"https://models.example/{name}": (lambda data=data: FakeResponse(data))
        for name, data in files.items()
    })


def downloader(opener: FakeOpener) -> VoiceModelDownloader:
    """A downloader over *opener* that retries without pausing."""
    return VoiceModelDownloader(opener=opener, policy=FAST_RETRY)  # type: ignore[arg-type]


def staging_leftovers(root: Path) -> List[str]:
    """Names of the terminal app's staging entries under *root*."""
    return sorted(entry.name for entry in root.glob(".partial.*"))
