"""Voice model cache and integrity store for Servonaut Desktop.

Inspects, downloads, verifies and evicts voice model weights under one
models root, serialising every change behind an inter-process lock. Every
model lands in the directory the speech engines load it from (see
:mod:`servonaut.services.voice_engines`), so a model fetched here is used by
the voice worker and by the terminal app alike, and a model the terminal app
already downloaded is reused rather than fetched again.

The pinned registry and the verified downloader live in
:mod:`servonaut.services.voice_models`, shared with the terminal app's
voice setup; their names are re-exported here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path
import shutil
import threading
from typing import Any, Callable, Dict, Final, List, Optional, Tuple
import urllib.request

from servonaut.desktop.voice.runtime import VoiceRuntimeLock
from servonaut.services.voice_engines import directory_bytes, voice_models_root
from servonaut.services.voice_models import (  # noqa: F401 — re-exported
    KOKORO_TTS_SPEC,
    MODEL_DOWNLOAD_ERRORS,
    MODEL_REGISTRY,
    NEMOTRON_ASR_SPEC,
    SILERO_VAD_SPEC,
    HttpsOnlyRedirectHandler,
    VoiceModelAsset,
    VoiceModelCancelledError,
    VoiceModelDownloader,
    VoiceModelDownloadPolicy,
    VoiceModelError,
    VoiceModelExtractionError,
    VoiceModelIntegrityError,
    VoiceModelSpec,
    build_https_only_opener,
    compute_file_sha256,
    nemotron_model_id,
    nemotron_spec,
    safe_extract_tar,
)

logger = logging.getLogger(__name__)

#: The models root at import time. :class:`VoiceModelCache` resolves the
#: live root on construction instead, so prefer that.
DEFAULT_MODELS_ROOT: Final[Path] = voice_models_root()

_LOCK_FILENAME: Final[str] = ".models.lock"
_STAGING_PREFIX: Final[str] = ".staging."


class VoiceModelCacheState(str, Enum):
    """State of an on-disk model asset."""

    NOT_DOWNLOADED = "not_downloaded"
    DOWNLOADING = "downloading"
    VERIFIED = "verified"
    CORRUPTED = "corrupted"


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


class VoiceModelCache:
    """Manages downloading, verification, caching, and eviction of voice model weights."""

    def __init__(
        self,
        root_dir: Optional[Path] = None,
        *,
        opener: Optional[urllib.request.OpenerDirector] = None,
        policy: Optional[VoiceModelDownloadPolicy] = None,
    ) -> None:
        """Build a cache over *root_dir* (the engines' models root by default).

        Args:
            root_dir: Models root; ``None`` uses
                :func:`~servonaut.services.voice_engines.voice_models_root`.
            opener: URL opener for downloads; defaults to one whose
                redirects must stay on HTTPS.
            policy: Stall, resume and lock limits for downloads.
        """
        self._root_dir = Path(root_dir if root_dir is not None else voice_models_root()).resolve()
        self._opener = opener or build_https_only_opener()
        self._policy = policy or VoiceModelDownloadPolicy()
        self._downloader = VoiceModelDownloader(opener=self._opener, policy=self._policy)

    @property
    def root_dir(self) -> Path:
        """Root directory where model weights are stored."""
        return self._root_dir

    @property
    def lock_path(self) -> Path:
        """Advisory concurrency lock path."""
        return self._root_dir / _LOCK_FILENAME

    def model_dir(self, spec: VoiceModelSpec) -> Path:
        """Directory *spec* lives in under this cache's root."""
        return spec.model_dir(self._root_dir)

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def status(
        self, model_id: str, *, deep_verify: bool = False, check_lock: bool = True
    ) -> VoiceModelStatus:
        """Inspect the presence and integrity of a model on disk without mutating state.

        With ``check_lock`` (the default), any download or eviction in
        progress reports DOWNLOADING. Without it the files alone decide:
        downloads are staged and committed by rename, so a model other than
        the one being fetched reads correctly while the cache is locked.
        """
        spec = MODEL_REGISTRY.get(model_id)
        if spec is None:
            return VoiceModelStatus(
                model_id=model_id,
                state=VoiceModelCacheState.NOT_DOWNLOADED,
                model_dir=self._root_dir / model_id,
                message=f"Unknown model identifier: '{model_id}'",
            )

        target_path = self.model_dir(spec)
        if check_lock and VoiceRuntimeLock(self.lock_path).is_locked():
            return VoiceModelStatus(
                model_id=model_id,
                state=VoiceModelCacheState.DOWNLOADING,
                model_dir=target_path,
                message="Model download or maintenance is currently in progress",
            )
        return self._check_files(spec, target_path, deep_verify=deep_verify)

    def inventory(self, *, check_lock: bool = True) -> List[VoiceModelStatus]:
        """Return the status and disk footprint of all registered models."""
        return [self.status(mid, check_lock=check_lock) for mid in MODEL_REGISTRY]

    def _check_files(
        self, spec: VoiceModelSpec, target_path: Path, *, deep_verify: bool = False
    ) -> VoiceModelStatus:
        """Classify the on-disk state of *spec* at *target_path*."""
        present = [name for name in spec.required_files if (target_path / name).is_file()]
        if not present:
            return self._status(
                spec, target_path, VoiceModelCacheState.NOT_DOWNLOADED,
                "Model is not downloaded", missing=spec.required_files,
            )

        problems = self._missing_or_empty(spec, target_path)
        if problems:
            return self._status(
                spec, target_path, VoiceModelCacheState.CORRUPTED,
                f"Model files are missing or incomplete: {', '.join(problems)}",
                missing=tuple(problems),
            )

        mismatched = self._mismatched_assets(spec, target_path, deep_verify=deep_verify)
        if mismatched:
            return self._status(
                spec, target_path, VoiceModelCacheState.CORRUPTED,
                f"Model files failed verification: {', '.join(mismatched)}",
            )

        return self._status(
            spec, target_path, VoiceModelCacheState.VERIFIED,
            "Model weights are verified and ready",
        )

    @staticmethod
    def _missing_or_empty(spec: VoiceModelSpec, target_path: Path) -> List[str]:
        problems: List[str] = []
        for name in spec.required_files:
            path = target_path / name
            try:
                if path.stat().st_size == 0:
                    problems.append(f"{name} (0 bytes)")
            except OSError:
                problems.append(name)
        return problems

    @staticmethod
    def _mismatched_assets(
        spec: VoiceModelSpec, target_path: Path, *, deep_verify: bool
    ) -> List[str]:
        """Loose assets whose size (always) or digest (deep) is wrong."""
        mismatched: List[str] = []
        for asset in spec.assets:
            if asset.is_archive:
                continue
            path = target_path / asset.filename
            try:
                size = path.stat().st_size
            except OSError:
                mismatched.append(f"{asset.filename} missing")
                continue
            if size != asset.expected_size:
                mismatched.append(f"{asset.filename} size mismatch")
            elif deep_verify and compute_file_sha256(path) != asset.expected_sha256:
                mismatched.append(f"{asset.filename} checksum mismatch")
        return mismatched

    @staticmethod
    def _status(
        spec: VoiceModelSpec,
        target_path: Path,
        state: VoiceModelCacheState,
        message: str,
        *,
        missing: Tuple[str, ...] = (),
    ) -> VoiceModelStatus:
        size = 0 if state is VoiceModelCacheState.NOT_DOWNLOADED else directory_bytes(target_path)
        return VoiceModelStatus(
            model_id=spec.model_id,
            state=state,
            model_dir=target_path,
            size_bytes=size,
            missing_files=tuple(missing),
            message=message,
        )

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    def download(
        self,
        model_id: str,
        *,
        progress_callback: Optional[Callable[[float, int, int], None]] = None,
        cancel: Optional[threading.Event] = None,
    ) -> VoiceModelStatus:
        """Atomically download, verify, and unpack model assets into the cache directory.

        Interrupted or stalled transfers resume where they stopped (see
        :class:`VoiceModelDownloadPolicy`); nothing reaches the model
        directory until every asset matched its pinned size and SHA-256.

        Args:
            model_id: Identifier of the model to download.
            progress_callback: Callable receiving (fraction, downloaded_bytes, total_bytes).
            cancel: Set it to stop the download at the next chunk or retry;
                the staging directory is removed and the lock released.

        Returns:
            VoiceModelStatus after provisioning.

        Raises:
            VoiceModelCancelledError: If ``cancel`` is set.
            VoiceModelError: If download, checksum, or extraction fails.
        """
        spec = MODEL_REGISTRY.get(model_id)
        if spec is None:
            raise VoiceModelError(f"Cannot download unknown model: '{model_id}'")

        self._root_dir.mkdir(parents=True, exist_ok=True)
        target_path = self.model_dir(spec)

        with VoiceRuntimeLock(self.lock_path, timeout=self._policy.lock_timeout_seconds):
            self._sweep_stale_staging()
            current = self._check_files(spec, target_path)
            if current.is_verified:
                return current

            self._downloader.install(
                spec,
                self._root_dir,
                staging_prefix=_STAGING_PREFIX,
                progress_callback=progress_callback,
                cancel=cancel,
            )
            return self._check_files(spec, target_path)

    def _sweep_stale_staging(self) -> None:
        """Remove staging leftovers from downloads that were killed mid-way.

        Runs under the cache lock, so no live download can own any of them.
        """
        for entry in self._root_dir.glob(f"{_STAGING_PREFIX}*"):
            logger.info("Removing stale model staging entry %s", entry.name)
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Eviction
    # ------------------------------------------------------------------

    def evict(self, model_id: str) -> None:
        """Evict model files from disk."""
        spec = MODEL_REGISTRY.get(model_id)
        if spec is None:
            return
        with VoiceRuntimeLock(self.lock_path, timeout=self._policy.lock_timeout_seconds):
            shutil.rmtree(self.model_dir(spec), ignore_errors=True)
