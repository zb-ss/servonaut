"""Pinned voice model registry and verified downloader.

Every speech model Servonaut manages itself — streaming speech
recognition, speech synthesis and voice-activity detection — is described
here by exact source URL, byte size and SHA-256. The terminal app's voice
setup and the desktop model cache both download through
:class:`VoiceModelDownloader`, so the two can never disagree on what a
model is or accept different bytes for it.

Every asset is pinned by its exact byte size and SHA-256; those pins, not
the URL, are what make a download trustworthy. Hugging Face assets are
addressed by commit revision, so their URL is immutable too. Release
assets are addressed by their release tag, and a publisher can replace an
asset under an existing tag: such a replacement fails the download (the
pins no longer match) rather than installing different bytes. A download
that grows past the pinned size is aborted mid-stream, redirects may never
leave HTTPS, and nothing reaches the model directory until every byte
verified.

Standard library only: the standalone command-line build, which ships
without the desktop package, downloads through this module as well.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import partial
import hashlib
import http.client
import logging
import os
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
import threading
import time
from typing import Any, Callable, Dict, Final, Mapping, Optional, Tuple
import urllib.error
import urllib.request

from servonaut.services.voice_engines import (
    KOKORO_ARCHIVE_URL,
    KOKORO_MODEL_ID,
    KOKORO_REQUIRED_FILES,
    NEMOTRON_DEFAULT_LATENCY_MS,
    NEMOTRON_FILES,
    NEMOTRON_LATENCY_OPTIONS,
    SILERO_VAD_FILE,
    SILERO_VAD_MODEL_ID,
    SILERO_VAD_URL,
    kokoro_model_dir,
    nemotron_model_dir,
    nemotron_repo,
    normalise_nemotron_latency,
    silero_vad_model_dir,
)
from servonaut.utils.archive_safety import UnsafeArchiveError, extract_tar_safely
from servonaut.utils.credential_scrub import scrub_credentials

logger = logging.getLogger(__name__)

_DOWNLOAD_CHUNK_SIZE: Final[int] = 1024 * 1024  # 1 MiB
_USER_AGENT: Final[str] = "Servonaut-VoiceModelCache/1.0"
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_CONTENT_RANGE = re.compile(r"bytes (\d+)-(\d+)/(\d+|\*)")
_HTTP_PARTIAL_CONTENT: Final[int] = 206


class VoiceModelError(Exception):
    """Base exception for voice model cache and download errors."""


class VoiceModelIntegrityError(VoiceModelError):
    """Raised when downloaded model weights fail cryptographic or size verification."""


class VoiceModelExtractionError(VoiceModelError):
    """Raised when an archive extraction violates safety invariants (e.g. path traversal)."""


class VoiceModelCancelledError(VoiceModelError):
    """Raised when the caller cancels a download; nothing reaches the cache."""


class _TransferInterrupted(ConnectionError):
    """The body ended before the pinned size arrived; resumable."""


#: What a model download can raise once the downloader has retried what it
#: could: network, disk, protocol and archive failures.
MODEL_DOWNLOAD_ERRORS: Final[Tuple[type, ...]] = (
    OSError,
    VoiceModelError,
    tarfile.TarError,
    http.client.HTTPException,
)


@dataclass(frozen=True)
class VoiceModelDownloadPolicy:
    """Timing limits for model downloads.

    There is deliberately no total deadline: a large model on a slow link
    legitimately takes long. What is bounded is silence.

    Attributes:
        stall_timeout_seconds: A transfer that delivers no bytes for this
            long is abandoned, then resumed.
        max_resume_attempts: Interruptions tolerated per asset; each attempt
            continues where the last stopped (an HTTP Range request).
        retry_delay_seconds: Pause before each resume attempt.
        lock_timeout_seconds: Wait for another download into the same cache.
    """

    stall_timeout_seconds: float = 60.0
    max_resume_attempts: int = 5
    retry_delay_seconds: float = 2.0
    lock_timeout_seconds: float = 15.0


@dataclass(frozen=True, slots=True)
class VoiceModelAsset:
    """One pinned file or archive belonging to a model package.

    The URL must be HTTPS, and the exact size and SHA-256 are mandatory:
    an asset without them cannot be verified, so it cannot be constructed.
    """

    filename: str
    url: str
    expected_size: int
    expected_sha256: str
    is_archive: bool = False

    def __post_init__(self) -> None:
        if not self.url.startswith("https://"):
            raise ValueError(f"Model asset '{self.filename}' must use an https:// URL")
        if self.expected_size <= 0:
            raise ValueError(f"Model asset '{self.filename}' needs its exact size")
        if not _SHA256_HEX.fullmatch(self.expected_sha256):
            raise ValueError(
                f"Model asset '{self.filename}' needs a lowercase hex SHA-256"
            )


@dataclass(frozen=True, slots=True)
class VoiceModelSpec:
    """Complete specification of a downloadable voice model package.

    ``model_dir`` maps a models root to the directory the engine loads this
    model from — one of the :mod:`~servonaut.services.voice_engines` path
    helpers, so the downloader and the engines can never disagree on where
    a model lives.
    """

    model_id: str
    display_name: str
    description: str
    engine: str  # "vad", "tts", "stt"
    assets: Tuple[VoiceModelAsset, ...]
    required_files: Tuple[str, ...]
    model_dir: Callable[[Path], Path]
    total_disk_bytes: int

    @property
    def total_download_bytes(self) -> int:
        """Exact number of bytes the download transfers."""
        return sum(asset.expected_size for asset in self.assets)


# ---------------------------------------------------------------------------
# Pinned registry
# ---------------------------------------------------------------------------
# The speech-synthesis archive and the voice-activity model are published
# only as release assets (no commit-addressed copy of the same bytes exists
# from the publisher), so their URLs are tag-addressed; see the module
# docstring for what the pins guarantee when a tag's asset is replaced.

SILERO_VAD_SPEC: Final[VoiceModelSpec] = VoiceModelSpec(
    model_id=SILERO_VAD_MODEL_ID,
    display_name="Silero VAD (Voice Activity Detection)",
    description="Low-latency neural voice activity detector (16 kHz onnx)",
    engine="vad",
    assets=(
        VoiceModelAsset(
            filename=SILERO_VAD_FILE,
            url=SILERO_VAD_URL,
            expected_size=643_854,
            expected_sha256="9e2449e1087496d8d4caba907f23e0bd3f78d91fa552479bb9c23ac09cbb1fd6",
        ),
    ),
    required_files=(SILERO_VAD_FILE,),
    model_dir=silero_vad_model_dir,
    total_disk_bytes=643_854,
)

KOKORO_TTS_SPEC: Final[VoiceModelSpec] = VoiceModelSpec(
    model_id=KOKORO_MODEL_ID,
    display_name="Kokoro TTS (Speech Synthesis)",
    description="Multilingual 82M-parameter int8 text-to-speech engine",
    engine="tts",
    assets=(
        VoiceModelAsset(
            filename=f"{KOKORO_MODEL_ID}.tar.bz2",
            url=KOKORO_ARCHIVE_URL,
            expected_size=132_303_094,
            expected_sha256="4c3052abaa60943a341f193888cf6abd68787dae6ab8ae5c925a706caa247e4e",
            is_archive=True,
        ),
    ),
    required_files=KOKORO_REQUIRED_FILES,
    model_dir=kokoro_model_dir,
    # Measured size of the extracted tree.
    total_disk_bytes=189_455_587,
)

# Streaming ASR: one repository per latency variant, each pinned to a
# commit. The decoder, joiner and token table are byte-identical across
# variants; only the encoder differs.
_HF_RESOLVE_URL: Final[str] = "https://huggingface.co/{repo}/resolve/{revision}/{filename}"
_NEMOTRON_SHARED_FILES: Final[Mapping[str, Tuple[int, str]]] = {
    "decoder.int8.onnx": (
        14_978_075, "19f9c98fc6d0a2c33a65a43b36fdb2e914c26c0aa9764be3aebc502a1e982fb0",
    ),
    "joiner.int8.onnx": (
        9_504_438, "4101c7c679a0bc30483794b27a059e34e79232aa2068d78d51231a22c8b0d7ce",
    ),
    "tokens.txt": (
        131_440, "729cc103155bafa785f9cd45746cd41cabe97eab7182fc04d594129587958f8a",
    ),
}
# latency_ms -> (commit revision, encoder size, encoder SHA-256)
_NEMOTRON_VARIANTS: Final[Mapping[int, Tuple[str, int, str]]] = {
    80: (
        "2ac5952ae18a2cc010c25e3fd96ad20cf254bd09", 657_601_516,
        "411e1222810f4a4cf0a3704c7609597a12def5b4ad2c7347a24ccd40d895484d",
    ),
    160: (
        "b3a4dbde84fba1a13cb4270e6730b525ac6a2db6", 657_601_518,
        "e1b39e5e16bef578a54ed2fba5f031438e000cc36c3ea2ca49d55699d5baebd4",
    ),
    320: (
        "424ce58898995b713f84341f2e1492f9207a26aa", 657_601_518,
        "f79c3fcc149f268b54b7d5754bdc2ba5c47c16b1fc70d15728a56f6efbf60ca5",
    ),
    560: (
        "ab43d895f5985b1bbab8b6eac8607fcdc05343f3", 657_601_403,
        "012e9321373af99021415e0b0eb3ec827b4be3153be6f30d9b448fe65e896e68",
    ),
    1120: (
        "cba1c96ca5ef0e8393b50584ae153a79145dc492", 657_601_521,
        "2fff2166acaa535bd969fb223c1f0783d71029f143cb298bc54c2afe85abf772",
    ),
}


def nemotron_model_id(latency_ms: int) -> str:
    """Registry id of the streaming ASR variant for *latency_ms*."""
    latency = normalise_nemotron_latency(latency_ms)
    return f"nemotron-3.5-asr-streaming-0.6b-{latency}ms-int8"


def _nemotron_spec(latency_ms: int) -> VoiceModelSpec:
    revision, encoder_size, encoder_sha256 = _NEMOTRON_VARIANTS[latency_ms]
    pins = {"encoder.int8.onnx": (encoder_size, encoder_sha256), **_NEMOTRON_SHARED_FILES}
    repo = nemotron_repo(latency_ms)
    assets = tuple(
        VoiceModelAsset(
            filename=local_name,
            url=_HF_RESOLVE_URL.format(repo=repo, revision=revision, filename=remote_name),
            expected_size=pins[remote_name][0],
            expected_sha256=pins[remote_name][1],
        )
        for remote_name, local_name in NEMOTRON_FILES.items()
    )
    return VoiceModelSpec(
        model_id=nemotron_model_id(latency_ms),
        display_name=f"Nemotron Streaming ASR ({latency_ms} ms)",
        description="Quantized 0.6B transducer streaming speech recognition engine",
        engine="stt",
        assets=assets,
        required_files=tuple(NEMOTRON_FILES.values()),
        model_dir=partial(nemotron_model_dir, latency_ms),
        total_disk_bytes=sum(asset.expected_size for asset in assets),
    )


_NEMOTRON_SPECS: Final[Mapping[int, VoiceModelSpec]] = {
    latency: _nemotron_spec(latency) for latency in NEMOTRON_LATENCY_OPTIONS
}
NEMOTRON_ASR_SPEC: Final[VoiceModelSpec] = _NEMOTRON_SPECS[NEMOTRON_DEFAULT_LATENCY_MS]


def nemotron_spec(latency_ms: int) -> VoiceModelSpec:
    """Streaming ASR spec for *latency_ms*, snapped to a published variant."""
    return _NEMOTRON_SPECS[normalise_nemotron_latency(latency_ms)]


MODEL_REGISTRY: Final[Dict[str, VoiceModelSpec]] = {
    spec.model_id: spec
    for spec in (SILERO_VAD_SPEC, KOKORO_TTS_SPEC, *_NEMOTRON_SPECS.values())
}


# ---------------------------------------------------------------------------
# Verification helpers
# ---------------------------------------------------------------------------


def compute_file_sha256(path: Path) -> str:
    """Compute the hex-encoded SHA-256 digest of a file in chunks."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(_DOWNLOAD_CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def safe_extract_tar(tar: tarfile.TarFile, destination: Path) -> None:
    """Extract *tar* into *destination*, refusing any unsafe member.

    Raises:
        VoiceModelExtractionError: If any member is a link, a special file,
            or a path that could escape *destination*. Nothing is extracted.
    """
    try:
        extract_tar_safely(tar, destination)
    except UnsafeArchiveError as e:
        raise VoiceModelExtractionError(str(e)) from e


class HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only while they stay on HTTPS.

    A plain-HTTP hop would let anyone on the path substitute the payload
    before the hash check ever sees it (and leak the request), so the
    download fails instead.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        if not newurl.lower().startswith("https://"):
            raise VoiceModelError(f"Refusing a non-HTTPS redirect to '{newurl}'")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_https_only_opener() -> urllib.request.OpenerDirector:
    """URL opener whose redirects can never downgrade to plain HTTP."""
    return urllib.request.build_opener(HttpsOnlyRedirectHandler)


def _header(response: Any, name: str) -> Optional[str]:
    headers = getattr(response, "headers", None)
    return headers.get(name) if headers is not None else None


def _reject_wrong_length(asset: VoiceModelAsset, response: Any, start: int) -> None:
    """Fail before transferring anything when the advertised length is wrong."""
    advertised = _header(response, "Content-Length")
    if advertised is None or not str(advertised).isdigit():
        return
    if start + int(advertised) != asset.expected_size:
        raise VoiceModelIntegrityError(
            f"Server offers '{asset.filename}' as {advertised} bytes from offset "
            f"{start}; expected {asset.expected_size} in total"
        )


def _resume_offset(asset: VoiceModelAsset, response: Any, requested: int) -> int:
    """Where the response body starts: *requested*, or 0 if the server restarted.

    A server may ignore a Range header and send the whole file again;
    that restarts the transfer. A partial response for a range that was
    not asked for is refused.
    """
    status = getattr(response, "status", 200)
    if status != _HTTP_PARTIAL_CONTENT:
        return 0
    match = _CONTENT_RANGE.fullmatch(str(_header(response, "Content-Range") or "").strip())
    if (
        requested == 0
        or match is None
        or int(match.group(1)) != requested
        or match.group(3) not in ("*", str(asset.expected_size))
    ):
        raise VoiceModelIntegrityError(
            f"Server sent an unexpected range of '{asset.filename}' "
            f"({_header(response, 'Content-Range')!r} for offset {requested})"
        )
    return requested


def _check_cancelled(cancel: Optional[threading.Event], asset: VoiceModelAsset) -> None:
    if cancel is not None and cancel.is_set():
        raise VoiceModelCancelledError(f"Download of '{asset.filename}' was cancelled")


def _pause(seconds: float, cancel: Optional[threading.Event]) -> None:
    """Sleep before a retry, waking early when the download is cancelled."""
    if cancel is None:
        time.sleep(seconds)
    else:
        cancel.wait(seconds)


def _is_transient(error: BaseException) -> bool:
    """Whether a failed transfer is worth resuming (network, not content)."""
    if isinstance(error, urllib.error.HTTPError):
        return error.code >= 500 or error.code == 429
    return isinstance(
        error, (TimeoutError, ConnectionError, http.client.IncompleteRead, urllib.error.URLError),
    )


class _ProgressTracker:
    """Reports overall progress across every asset of one download."""

    def __init__(self, total: int, callback: Optional[Callable[[float, int, int], None]]) -> None:
        self._total = max(1, total)
        self._callback = callback
        self.received = 0

    def advance(self, count: int) -> None:
        self.received += count
        self.report(min(0.95, self.received / self._total))

    def report(self, fraction: float) -> None:
        if self._callback is None:
            return
        try:
            self._callback(fraction, self.received, self._total)
        except Exception:  # noqa: BLE001 — a progress consumer must not break the download
            logger.debug("Model download progress callback failed", exc_info=True)


# ---------------------------------------------------------------------------
# Downloader
# ---------------------------------------------------------------------------


class VoiceModelDownloader:
    """Downloads a pinned model and moves it into place once every byte verified."""

    def __init__(
        self,
        *,
        opener: Optional[urllib.request.OpenerDirector] = None,
        policy: Optional[VoiceModelDownloadPolicy] = None,
    ) -> None:
        """Build a downloader.

        Args:
            opener: URL opener for downloads; defaults to one whose
                redirects must stay on HTTPS.
            policy: Stall and resume limits for downloads.
        """
        self._opener = opener or build_https_only_opener()
        self._policy = policy or VoiceModelDownloadPolicy()

    @property
    def opener(self) -> urllib.request.OpenerDirector:
        """URL opener the downloads go through."""
        return self._opener

    @property
    def policy(self) -> VoiceModelDownloadPolicy:
        """Stall and resume limits."""
        return self._policy

    def install(
        self,
        spec: VoiceModelSpec,
        root_dir: Path,
        *,
        staging_prefix: str,
        progress_callback: Optional[Callable[[float, int, int], None]] = None,
        cancel: Optional[threading.Event] = None,
    ) -> Path:
        """Download, verify and unpack *spec*, then swap it into its directory.

        Everything is staged in a fresh ``<staging_prefix><model_id>.*``
        directory under *root_dir* and only renamed into the model
        directory once every asset matched its pinned size and SHA-256; a
        failure at any point leaves the previous model directory untouched.
        The replaced tree is set aside under the same prefix until the new
        one is in place, so one glob finds everything a killed install left.

        Args:
            spec: Model to install.
            root_dir: Models root the model directory is resolved under.
            staging_prefix: Name prefix of the staging directory, so the
                caller can recognise (and sweep) its own leftovers.
            progress_callback: Callable receiving (fraction, downloaded_bytes,
                total_bytes), called on the downloading thread.
            cancel: Set it to stop the download at the next chunk or retry.

        Returns:
            The model directory the files now live in.

        Raises:
            VoiceModelCancelledError: If ``cancel`` is set.
            VoiceModelIntegrityError: If an asset does not match its pins.
            VoiceModelError: If download or extraction fails.
            OSError: If the models root cannot be written.
        """
        root_dir.mkdir(parents=True, exist_ok=True)
        target_path = spec.model_dir(root_dir)
        progress = _ProgressTracker(spec.total_download_bytes, progress_callback)
        own_prefix = f"{staging_prefix}{spec.model_id}."
        staging_dir = Path(tempfile.mkdtemp(prefix=own_prefix, dir=root_dir))
        try:
            self._stage_assets(spec, staging_dir, progress, cancel)
            progress.report(0.98)
            _commit(staging_dir, target_path, retired_prefix=f"{own_prefix}retired.")
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)
        progress.report(1.0)
        return target_path

    def _stage_assets(
        self,
        spec: VoiceModelSpec,
        staging_dir: Path,
        progress: _ProgressTracker,
        cancel: Optional[threading.Event] = None,
    ) -> None:
        """Download, verify and unpack every asset of *spec* into *staging_dir*."""
        for asset in spec.assets:
            dest_file = staging_dir / asset.filename
            self._download_asset(asset, dest_file, progress, cancel)
            if asset.is_archive:
                progress.report(0.90)
                _unpack_archive(spec, dest_file, staging_dir)

        for name in spec.required_files:
            path = staging_dir / name
            if not path.is_file() or path.stat().st_size == 0:
                raise VoiceModelIntegrityError(
                    f"Model archive did not contain required file '{name}'"
                )

    def _download_asset(
        self,
        asset: VoiceModelAsset,
        destination: Path,
        progress: _ProgressTracker,
        cancel: Optional[threading.Event] = None,
    ) -> None:
        """Fetch one asset into *destination*, resuming after interruptions."""
        failures = 0
        while True:
            _check_cancelled(cancel, asset)
            try:
                self._transfer(asset, destination, progress, cancel)
                break
            except Exception as e:
                if not _is_transient(e):
                    raise
                failures += 1
                if failures > self._policy.max_resume_attempts:
                    raise VoiceModelError(
                        f"Download of '{asset.filename}' kept failing "
                        f"({failures} attempts): {e}"
                    ) from e
                logger.warning(
                    "Download of %s interrupted (%s); resuming",
                    asset.filename, scrub_credentials(str(e)),
                )
                _pause(self._policy.retry_delay_seconds, cancel)
        _check_cancelled(cancel, asset)
        _verify_downloaded(asset, destination)

    def _transfer(
        self,
        asset: VoiceModelAsset,
        destination: Path,
        progress: _ProgressTracker,
        cancel: Optional[threading.Event] = None,
    ) -> None:
        """One attempt: continue *destination* from its current length.

        The stall timeout is the socket timeout, so it bounds each wait for
        more bytes, never the transfer as a whole.
        """
        offset = destination.stat().st_size if destination.exists() else 0
        headers = {"User-Agent": _USER_AGENT}
        if offset:
            headers["Range"] = f"bytes={offset}-"
        request = urllib.request.Request(asset.url, headers=headers)
        with self._opener.open(request, timeout=self._policy.stall_timeout_seconds) as response:
            start = _resume_offset(asset, response, offset)
            _reject_wrong_length(asset, response, start)
            progress.advance(start - offset)  # a restart gives back what was counted
            received = start
            with destination.open("r+b" if start else "wb") as out:
                out.seek(start)
                out.truncate()
                while chunk := response.read(_DOWNLOAD_CHUNK_SIZE):
                    _check_cancelled(cancel, asset)
                    received += len(chunk)
                    if received > asset.expected_size:
                        raise VoiceModelIntegrityError(
                            f"Download of '{asset.filename}' exceeded its expected "
                            f"{asset.expected_size} bytes; aborted"
                        )
                    out.write(chunk)
                    progress.advance(len(chunk))
        if received < asset.expected_size:
            raise _TransferInterrupted(
                f"transfer ended after {received} of {asset.expected_size} bytes"
            )


def _verify_downloaded(asset: VoiceModelAsset, destination: Path) -> None:
    """Check the whole file — including resumed parts — against its pins."""
    size = destination.stat().st_size
    if size != asset.expected_size:
        raise VoiceModelIntegrityError(
            f"Downloaded '{asset.filename}' size mismatch: expected "
            f"{asset.expected_size} bytes, got {size}"
        )
    digest = compute_file_sha256(destination)
    if digest != asset.expected_sha256:
        raise VoiceModelIntegrityError(
            f"Cryptographic hash mismatch for '{asset.filename}': "
            f"expected {asset.expected_sha256}, got {digest}"
        )


def _unpack_archive(spec: VoiceModelSpec, archive_path: Path, staging_dir: Path) -> None:
    """Extract *archive_path* and lift its content root into *staging_dir*."""
    extract_dir = staging_dir / "extracted"
    with tarfile.open(archive_path, "r:*") as tar:
        safe_extract_tar(tar, extract_dir)
    archive_path.unlink()

    # Archives ship either flat or wrapped in one top-level directory.
    content_dir = extract_dir
    marker = spec.required_files[0]
    if not (content_dir / marker).is_file():
        content_dir = next(
            (sub for sub in extract_dir.iterdir() if sub.is_dir() and (sub / marker).is_file()),
            extract_dir,
        )
    for item in list(content_dir.iterdir()):
        shutil.move(str(item), str(staging_dir / item.name))
    shutil.rmtree(extract_dir, ignore_errors=True)


def _commit(staging_dir: Path, target_path: Path, *, retired_prefix: str) -> None:
    """Swap the verified staging tree into place.

    Any previous (incomplete or corrupt) tree is renamed aside first, into
    a ``retired_prefix`` directory beside the staging tree, and removed
    only after the new one is in place.
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)
    retired: Optional[Path] = None
    if target_path.exists():
        retired = Path(tempfile.mkdtemp(prefix=retired_prefix, dir=staging_dir.parent))
        target_path.rename(retired / target_path.name)
    os.replace(staging_dir, target_path)
    if retired is not None:
        shutil.rmtree(retired, ignore_errors=True)
