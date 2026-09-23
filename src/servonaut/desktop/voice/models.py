"""Voice model asset cache, verification, and integrity store for Servonaut Desktop.

Manages download, cryptographic verification, safe archive extraction, status
inspection, and eviction of voice model weights under the companion runtime
models directory (~/.servonaut/runtimes/voice/models/).
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import io
import logging
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import time
from typing import Any, Callable, Dict, Final, List, Mapping, Optional, Sequence, Tuple
import urllib.request

from servonaut.desktop.voice.runtime import DEFAULT_RUNTIME_ROOT, VoiceRuntimeLock

logger = logging.getLogger(__name__)

DEFAULT_MODELS_ROOT: Final[Path] = DEFAULT_RUNTIME_ROOT / "models"
_LOCK_FILENAME: Final[str] = ".models.lock"
_DOWNLOAD_CHUNK_SIZE: Final[int] = 1024 * 1024  # 1 MiB


class VoiceModelError(Exception):
    """Base exception for voice model cache and download errors."""


class VoiceModelIntegrityError(VoiceModelError):
    """Raised when downloaded model weights fail cryptographic or size verification."""


class VoiceModelExtractionError(VoiceModelError):
    """Raised when an archive extraction violates safety invariants (e.g. path traversal)."""


class VoiceModelCacheState(str, Enum):
    """State of an on-disk model asset."""

    NOT_DOWNLOADED = "not_downloaded"
    DOWNLOADING = "downloading"
    VERIFIED = "verified"
    CORRUPTED = "corrupted"


@dataclass(frozen=True, slots=True)
class VoiceModelAsset:
    """Individual file or archive belonging to a model package."""

    filename: str
    url: str
    expected_size: Optional[int] = None
    expected_sha256: Optional[str] = None
    is_archive: bool = False
    archive_format: Optional[str] = None


@dataclass(frozen=True, slots=True)
class VoiceModelSpec:
    """Complete specification of a downloadable voice model package."""

    model_id: str
    display_name: str
    description: str
    engine: str  # "vad", "tts", "stt"
    assets: Tuple[VoiceModelAsset, ...]
    local_dir_name: str
    required_files: Tuple[str, ...]
    total_download_bytes: int
    total_disk_bytes: int


# Standard model registry
SILERO_VAD_SPEC: Final[VoiceModelSpec] = VoiceModelSpec(
    model_id="silero-vad-v4-16k",
    display_name="Silero VAD (Voice Activity Detection)",
    description="Low-latency neural voice activity detector (16 kHz onnx)",
    engine="vad",
    assets=(
        VoiceModelAsset(
            filename="silero_vad.onnx",
            url="https://github.com/k2-fsa/sherpa-onnx/releases/download/asr-models/silero_vad.onnx",
            expected_size=643_854,
            is_archive=False,
        ),
    ),
    local_dir_name="",  # Lives directly as silero_vad.onnx or under silero-vad-v4-16k
    required_files=("silero_vad.onnx",),
    total_download_bytes=643_854,
    total_disk_bytes=643_854,
)

KOKORO_TTS_SPEC: Final[VoiceModelSpec] = VoiceModelSpec(
    model_id="kokoro-int8-multi-lang-v1_0",
    display_name="Kokoro TTS (Speech Synthesis)",
    description="Multilingual 82M-parameter int8 text-to-speech engine",
    engine="tts",
    assets=(
        VoiceModelAsset(
            filename="kokoro-int8-multi-lang-v1_0.tar.bz2",
            url="https://github.com/k2-fsa/sherpa-onnx/releases/download/tts-models/kokoro-int8-multi-lang-v1_0.tar.bz2",
            expected_size=131_839_838,
            is_archive=True,
            archive_format="tar.bz2",
        ),
    ),
    local_dir_name="kokoro-int8-multi-lang-v1_0",
    required_files=(
        "model.int8.onnx",
        "voices.bin",
        "tokens.txt",
        "lexicon-us-en.txt",
        "lexicon-gb-en.txt",
        "espeak-ng-data/phontab",
        "espeak-ng-data/phonindex",
        "espeak-ng-data/phondata",
        "espeak-ng-data/intonations",
    ),
    total_download_bytes=131_839_838,
    total_disk_bytes=189_455_587,
)

NEMOTRON_ASR_SPEC: Final[VoiceModelSpec] = VoiceModelSpec(
    model_id="nemotron-3.5-asr-streaming-0.6b-320ms-int8",
    display_name="Nemotron Streaming ASR",
    description="Quantized 0.6B transducer streaming speech recognition engine",
    engine="stt",
    assets=(
        VoiceModelAsset(
            filename="encoder.int8.onnx",
            url="https://huggingface.co/csukuangfj2/sherpa-onnx-nemotron-3.5-asr-streaming-0.6b-320ms-int8-2026-06-11/resolve/main/encoder.int8.onnx",
            expected_size=638_000_000,
        ),
        VoiceModelAsset(
            filename="decoder.int8.onnx",
            url="https://huggingface.co/csukuangfj2/sherpa-onnx-nemotron-3.5-asr-streaming-0.6b-320ms-int8-2026-06-11/resolve/main/decoder.int8.onnx",
            expected_size=15_000_000,
        ),
        VoiceModelAsset(
            filename="joiner.int8.onnx",
            url="https://huggingface.co/csukuangfj2/sherpa-onnx-nemotron-3.5-asr-streaming-0.6b-320ms-int8-2026-06-11/resolve/main/joiner.int8.onnx",
            expected_size=63_000_000,
        ),
        VoiceModelAsset(
            filename="tokens.txt",
            url="https://huggingface.co/csukuangfj2/sherpa-onnx-nemotron-3.5-asr-streaming-0.6b-320ms-int8-2026-06-11/resolve/main/tokens.txt",
            expected_size=120_000,
        ),
    ),
    local_dir_name="nemotron",
    required_files=(
        "encoder.int8.onnx",
        "decoder.int8.onnx",
        "joiner.int8.onnx",
        "tokens.txt",
    ),
    total_download_bytes=716_120_000,
    total_disk_bytes=716_120_000,
)

MODEL_REGISTRY: Final[Dict[str, VoiceModelSpec]] = {
    SILERO_VAD_SPEC.model_id: SILERO_VAD_SPEC,
    KOKORO_TTS_SPEC.model_id: KOKORO_TTS_SPEC,
    NEMOTRON_ASR_SPEC.model_id: NEMOTRON_ASR_SPEC,
}


@dataclass(frozen=True, slots=True)
class VoiceModelStatus:
    """Inspection record for a voice model asset."""

    model_id: str
    state: VoiceModelCacheState
    model_dir: Path
    size_bytes: int = 0
    missing_files: Tuple[str, ...] = ()
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_verified(self) -> bool:
        """Whether the model is verified and ready for inference."""
        return self.state is VoiceModelCacheState.VERIFIED


def compute_file_sha256(path: Path) -> str:
    """Compute the hex-encoded SHA-256 digest of a file in chunks."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(_DOWNLOAD_CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def safe_extract_tar(tar: tarfile.TarFile, destination: Path) -> None:
    """Safely extract tar members, strictly preventing directory traversal / zip-slip.

    Args:
        tar: Open TarFile instance.
        destination: Absolute resolved destination directory.

    Raises:
        VoiceModelExtractionError: If any archive member attempts directory traversal.
    """
    dest_path = destination.resolve()
    for member in tar.getmembers():
        member_name = member.name.replace("\\", "/")
        target_path = (dest_path / member_name).resolve()

        try:
            target_path.relative_to(dest_path)
        except ValueError:
            raise VoiceModelExtractionError(
                f"Path traversal detected in archive member: '{member.name}' escapes '{dest_path}'"
            )

        if member.islnk() or member.issym():
            link_target = (target_path.parent / member.linkname).resolve()
            try:
                link_target.relative_to(dest_path)
            except ValueError:
                raise VoiceModelExtractionError(
                    f"Symlink traversal detected in member: '{member.name}' -> '{member.linkname}'"
                )

    # All members validated; safe to extract
    if hasattr(tarfile, "data_filter"):
        tar.extractall(path=dest_path, filter="data")
    else:
        tar.extractall(path=dest_path)


class VoiceModelCache:
    """Manages downloading, verification, caching, and eviction of voice model weights."""

    def __init__(self, root_dir: Optional[Path] = None) -> None:
        self._root_dir = (root_dir or DEFAULT_MODELS_ROOT).resolve()

    @property
    def root_dir(self) -> Path:
        """Root directory where model weights are stored."""
        return self._root_dir

    @property
    def lock_path(self) -> Path:
        """Advisory concurrency lock path."""
        return self._root_dir / _LOCK_FILENAME

    def _get_target_path(self, spec: VoiceModelSpec) -> Path:
        """Return the target directory or file path for a model."""
        if spec.local_dir_name:
            return self._root_dir / spec.local_dir_name
        # Models with empty local_dir_name live directly under root_dir
        return self._root_dir

    def _check_files(
        self, spec: VoiceModelSpec, target_path: Path, deep_verify: bool = False
    ) -> VoiceModelStatus:
        """Internal inspection of model files on disk."""
        missing: list[str] = []
        total_size = 0
        for req in spec.required_files:
            file_path = target_path / req
            if not file_path.is_file():
                missing.append(req)
                continue
            try:
                sz = file_path.stat().st_size
                if sz == 0:
                    missing.append(f"{req} (0 bytes)")
                else:
                    total_size += sz
            except OSError:
                missing.append(req)

        if missing:
            # If nothing exists, it's NOT_DOWNLOADED; if partial files exist, it's CORRUPTED
            if len(missing) == len(spec.required_files) and not target_path.exists():
                return VoiceModelStatus(
                    model_id=spec.model_id,
                    state=VoiceModelCacheState.NOT_DOWNLOADED,
                    model_dir=target_path,
                    size_bytes=0,
                    missing_files=tuple(missing),
                    message="Model is not downloaded",
                )
            return VoiceModelStatus(
                model_id=spec.model_id,
                state=VoiceModelCacheState.CORRUPTED,
                model_dir=target_path,
                size_bytes=total_size,
                missing_files=tuple(missing),
                message=f"Model files are missing or incomplete: {', '.join(missing)}",
            )

        if deep_verify:
            corrupted: list[str] = []
            for asset in spec.assets:
                if not asset.is_archive and asset.expected_sha256:
                    asset_path = target_path / asset.filename
                    if asset_path.is_file():
                        digest = compute_file_sha256(asset_path)
                        if digest.lower() != asset.expected_sha256.lower():
                            corrupted.append(f"{asset.filename} checksum mismatch")

            if corrupted:
                return VoiceModelStatus(
                    model_id=spec.model_id,
                    state=VoiceModelCacheState.CORRUPTED,
                    model_dir=target_path,
                    size_bytes=total_size,
                    message=f"Deep verification failed: {', '.join(corrupted)}",
                )

        return VoiceModelStatus(
            model_id=spec.model_id,
            state=VoiceModelCacheState.VERIFIED,
            model_dir=target_path,
            size_bytes=total_size,
            message="Model weights are verified and ready",
        )

    def status(self, model_id: str, *, deep_verify: bool = False) -> VoiceModelStatus:
        """Inspect the presence and integrity of a model on disk without mutating state."""
        spec = MODEL_REGISTRY.get(model_id)
        if spec is None:
            return VoiceModelStatus(
                model_id=model_id,
                state=VoiceModelCacheState.NOT_DOWNLOADED,
                model_dir=self._root_dir / model_id,
                message=f"Unknown model identifier: '{model_id}'",
            )

        target_path = self._get_target_path(spec)

        # Check for concurrency lock
        lock = VoiceRuntimeLock(self.lock_path)
        if lock.is_locked():
            return VoiceModelStatus(
                model_id=model_id,
                state=VoiceModelCacheState.DOWNLOADING,
                model_dir=target_path,
                message="Model download or maintenance is currently in progress",
            )

        return self._check_files(spec, target_path, deep_verify=deep_verify)

    def download(
        self,
        model_id: str,
        *,
        progress_callback: Optional[Callable[[float, int, int], None]] = None,
        timeout: float = 600.0,
    ) -> VoiceModelStatus:
        """Atomically download, verify, and unpack model assets into the cache directory.

        Args:
            model_id: Identifier of the model to download.
            progress_callback: Callable receiving (percentage: float, downloaded_bytes: int, total_bytes: int).
            timeout: Maximum download timeout in seconds.

        Returns:
            VoiceModelStatus after provisioning.

        Raises:
            VoiceModelError: If download, checksum, or extraction fails.
        """
        spec = MODEL_REGISTRY.get(model_id)
        if spec is None:
            raise VoiceModelError(f"Cannot download unknown model: '{model_id}'")

        self._root_dir.mkdir(parents=True, exist_ok=True)
        target_path = self._get_target_path(spec)

        def report(pct: float, cur: int, total: int) -> None:
            if progress_callback:
                try:
                    progress_callback(pct, cur, total)
                except Exception:
                    pass

        with VoiceRuntimeLock(self.lock_path, timeout=15.0):
            # Check if already installed and verified
            current = self._check_files(spec, target_path, deep_verify=False)
            if current.is_verified:
                return current

            staging_dir = self._root_dir / f".staging.{spec.model_id}.{os.getpid()}"
            if staging_dir.exists():
                shutil.rmtree(staging_dir, ignore_errors=True)
            staging_dir.mkdir(parents=True, exist_ok=True)

            try:
                total_expected = spec.total_download_bytes or 1
                bytes_accumulated = 0

                for asset in spec.assets:
                    dest_file = staging_dir / asset.filename
                    bytes_accumulated = self._download_single_asset(
                        asset=asset,
                        destination=dest_file,
                        bytes_accumulated=bytes_accumulated,
                        total_expected=total_expected,
                        progress_callback=report,
                        timeout=timeout,
                    )

                    if asset.is_archive:
                        report(0.90, bytes_accumulated, total_expected)
                        extract_dir = staging_dir / "extracted"
                        extract_dir.mkdir(parents=True, exist_ok=True)
                        with tarfile.open(dest_file, "r:*") as tar:
                            safe_extract_tar(tar, extract_dir)

                        # Clean up archive tarball after extraction
                        with contextlib.suppress(OSError):
                            dest_file.unlink()

                        # Detect content root (support flat or nested archive layouts)
                        source_content_dir = extract_dir
                        if spec.required_files and not (source_content_dir / spec.required_files[0]).is_file():
                            for sub in extract_dir.iterdir():
                                if sub.is_dir() and (sub / spec.required_files[0]).is_file():
                                    source_content_dir = sub
                                    break

                        # Move extracted content to staging_dir
                        for item in list(source_content_dir.iterdir()):
                            dest_item = staging_dir / item.name
                            if dest_item.exists():
                                if dest_item.is_dir():
                                    shutil.rmtree(dest_item, ignore_errors=True)
                                else:
                                    dest_item.unlink()
                            shutil.move(str(item), str(dest_item))

                        shutil.rmtree(extract_dir, ignore_errors=True)

                # Verify all required files are present in staging_dir
                for req in spec.required_files:
                    req_path = staging_dir / req
                    if not req_path.is_file() or req_path.stat().st_size == 0:
                        raise VoiceModelIntegrityError(
                            f"Model archive did not contain required file '{req}'"
                        )

                # Atomic commit to target_path
                report(0.98, total_expected, total_expected)
                if spec.local_dir_name:
                    if target_path.exists():
                        shutil.rmtree(target_path, ignore_errors=True)
                    staging_dir.rename(target_path)
                else:
                    # Target is directly under root_dir (single file model)
                    for item in staging_dir.iterdir():
                        final_dest = self._root_dir / item.name
                        if final_dest.exists():
                            if final_dest.is_dir():
                                shutil.rmtree(final_dest, ignore_errors=True)
                            else:
                                final_dest.unlink()
                        shutil.move(str(item), str(final_dest))
                    shutil.rmtree(staging_dir, ignore_errors=True)

                report(1.0, total_expected, total_expected)

            except Exception:
                shutil.rmtree(staging_dir, ignore_errors=True)
                raise

        return self.status(model_id)

    def _download_single_asset(
        self,
        asset: VoiceModelAsset,
        destination: Path,
        bytes_accumulated: int,
        total_expected: int,
        progress_callback: Callable[[float, int, int], None],
        timeout: float,
    ) -> int:
        """Download one asset to a destination path with progress and hash checking."""
        temp_dest = destination.with_suffix(f"{destination.suffix}.partial.{os.getpid()}")
        hasher = hashlib.sha256() if asset.expected_sha256 else None
        current_bytes = bytes_accumulated
        start_time = time.time()

        try:
            req = urllib.request.Request(
                asset.url,
                headers={"User-Agent": "Servonaut-VoiceModelCache/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                with temp_dest.open("wb") as out_f:
                    while True:
                        if time.time() - start_time > timeout:
                            raise VoiceModelError(
                                f"Download of '{asset.filename}' timed out after {timeout}s"
                            )
                        chunk = resp.read(_DOWNLOAD_CHUNK_SIZE)
                        if not chunk:
                            break
                        out_f.write(chunk)
                        if hasher:
                            hasher.update(chunk)
                        current_bytes += len(chunk)
                        pct = min(0.95, current_bytes / max(1, total_expected))
                        progress_callback(pct, current_bytes, total_expected)

            # Check size
            file_size = temp_dest.stat().st_size
            if asset.expected_size is not None and file_size != asset.expected_size:
                raise VoiceModelIntegrityError(
                    f"Downloaded '{asset.filename}' size mismatch: expected {asset.expected_size} bytes, got {file_size}"
                )

            # Check SHA-256
            if hasher and asset.expected_sha256:
                digest = hasher.hexdigest()
                if digest.lower() != asset.expected_sha256.lower():
                    raise VoiceModelIntegrityError(
                        f"Cryptographic hash mismatch for '{asset.filename}': "
                        f"expected {asset.expected_sha256}, got {digest}"
                    )

            temp_dest.replace(destination)
            return current_bytes

        except Exception:
            with contextlib.suppress(OSError):
                temp_dest.unlink()
            raise

    def evict(self, model_id: str) -> None:
        """Evict model files from disk."""
        spec = MODEL_REGISTRY.get(model_id)
        if spec is None:
            return

        with VoiceRuntimeLock(self.lock_path, timeout=5.0):
            target_path = self._get_target_path(spec)
            if spec.local_dir_name:
                if target_path.exists():
                    shutil.rmtree(target_path, ignore_errors=True)
            else:
                for req in spec.required_files:
                    f = self._root_dir / req
                    with contextlib.suppress(OSError):
                        f.unlink()

    def inventory(self) -> List[VoiceModelStatus]:
        """Return the status and disk footprint of all registered models."""
        return [self.status(mid) for mid in MODEL_REGISTRY]
