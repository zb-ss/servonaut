"""Unit tests for VoiceModelCache, asset verification, and integrity store.

Tests:
- Model registry definitions and asset specifications
- Cryptographic SHA-256 checksum computation
- Safe archive extraction (path traversal / zip-slip prevention)
- Model cache status transitions (NOT_DOWNLOADED, DOWNLOADING, VERIFIED, CORRUPTED)
- Atomic download workflow with simulated network responses
- Progress reporting across download and extraction phases
- Failure handling (size mismatch, hash mismatch, missing required files, cleanup)
- Model eviction and cache inventory reporting
"""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import tarfile
from typing import Any
from unittest.mock import MagicMock, patch
import urllib.error

import pytest

from servonaut.desktop.voice.models import (
    KOKORO_TTS_SPEC,
    MODEL_REGISTRY,
    NEMOTRON_ASR_SPEC,
    SILERO_VAD_SPEC,
    VoiceModelAsset,
    VoiceModelCache,
    VoiceModelCacheState,
    VoiceModelError,
    VoiceModelExtractionError,
    VoiceModelIntegrityError,
    VoiceModelSpec,
    VoiceModelStatus,
    compute_file_sha256,
    safe_extract_tar,
)
from servonaut.desktop.voice.runtime import VoiceRuntimeLock


class TestVoiceModelRegistry:
    def test_standard_models_registered(self) -> None:
        assert SILERO_VAD_SPEC.model_id in MODEL_REGISTRY
        assert KOKORO_TTS_SPEC.model_id in MODEL_REGISTRY
        assert NEMOTRON_ASR_SPEC.model_id in MODEL_REGISTRY

    def test_spec_invariants(self) -> None:
        for mid, spec in MODEL_REGISTRY.items():
            assert spec.model_id == mid
            assert spec.display_name
            assert spec.description
            assert spec.engine in ("vad", "tts", "stt")
            assert len(spec.assets) > 0
            assert len(spec.required_files) > 0
            assert spec.total_download_bytes > 0
            assert spec.total_disk_bytes > 0


class TestVoiceModelVerification:
    def test_compute_file_sha256(self, tmp_path: Path) -> None:
        test_file = tmp_path / "sample.bin"
        content = b"Servonaut secure voice model test payload"
        test_file.write_bytes(content)

        expected = hashlib.sha256(content).hexdigest()
        assert compute_file_sha256(test_file) == expected

    def test_safe_extract_tar_valid(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "valid.tar"
        dest_path = tmp_path / "extracted"
        dest_path.mkdir(parents=True, exist_ok=True)

        with tarfile.open(archive_path, "w") as tar:
            data = b"model binary payload"
            ti = tarfile.TarInfo(name="model.int8.onnx")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

            subdir_data = b"sub payload"
            ti2 = tarfile.TarInfo(name="sub/file.txt")
            ti2.size = len(subdir_data)
            tar.addfile(ti2, io.BytesIO(subdir_data))

        with tarfile.open(archive_path, "r") as tar:
            safe_extract_tar(tar, dest_path)

        assert (dest_path / "model.int8.onnx").read_bytes() == b"model binary payload"
        assert (dest_path / "sub" / "file.txt").read_bytes() == b"sub payload"

    def test_safe_extract_tar_rejects_parent_traversal(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "traversal.tar"
        dest_path = tmp_path / "dest"
        dest_path.mkdir(parents=True, exist_ok=True)

        with tarfile.open(archive_path, "w") as tar:
            data = b"evil payload"
            ti = tarfile.TarInfo(name="../escape.txt")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

        with tarfile.open(archive_path, "r") as tar:
            with pytest.raises(VoiceModelExtractionError, match="Path traversal detected"):
                safe_extract_tar(tar, dest_path)

    def test_safe_extract_tar_rejects_symlink_traversal(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "symlink_traversal.tar"
        dest_path = tmp_path / "dest"
        dest_path.mkdir(parents=True, exist_ok=True)

        with tarfile.open(archive_path, "w") as tar:
            ti = tarfile.TarInfo(name="evil_link")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "../../etc/shadow"
            tar.addfile(ti)

        with tarfile.open(archive_path, "r") as tar:
            with pytest.raises(VoiceModelExtractionError, match="Symlink traversal detected"):
                safe_extract_tar(tar, dest_path)


class TestVoiceModelCacheStatus:
    def test_status_unknown_model(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        st = cache.status("nonexistent-model")
        assert st.state is VoiceModelCacheState.NOT_DOWNLOADED
        assert not st.is_verified
        assert "Unknown model identifier" in st.message

    def test_status_not_downloaded(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        st = cache.status(KOKORO_TTS_SPEC.model_id)
        assert st.state is VoiceModelCacheState.NOT_DOWNLOADED
        assert not st.is_verified
        assert "not downloaded" in st.message

    def test_status_downloading_when_locked(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        lock = VoiceRuntimeLock(cache.lock_path, timeout=1.0)
        lock.acquire()
        try:
            st = cache.status(KOKORO_TTS_SPEC.model_id)
            assert st.state is VoiceModelCacheState.DOWNLOADING
            assert not st.is_verified
            assert "in progress" in st.message
        finally:
            lock.release()

    def test_status_corrupted_missing_required_files(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        kokoro_dir = tmp_path / KOKORO_TTS_SPEC.local_dir_name
        kokoro_dir.mkdir(parents=True, exist_ok=True)
        # Create only 1 of the required files
        (kokoro_dir / "model.int8.onnx").write_bytes(b"dummy")

        st = cache.status(KOKORO_TTS_SPEC.model_id)
        assert st.state is VoiceModelCacheState.CORRUPTED
        assert not st.is_verified
        assert "voices.bin" in st.missing_files

    def test_status_corrupted_zero_byte_file(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        kokoro_dir = tmp_path / KOKORO_TTS_SPEC.local_dir_name
        kokoro_dir.mkdir(parents=True, exist_ok=True)
        for req in KOKORO_TTS_SPEC.required_files:
            p = kokoro_dir / req
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"content")

        # Make one file 0 bytes
        (kokoro_dir / "voices.bin").write_bytes(b"")

        st = cache.status(KOKORO_TTS_SPEC.model_id)
        assert st.state is VoiceModelCacheState.CORRUPTED
        assert any("voices.bin (0 bytes)" in m for m in st.missing_files)

    def test_status_verified_success(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        kokoro_dir = tmp_path / KOKORO_TTS_SPEC.local_dir_name
        kokoro_dir.mkdir(parents=True, exist_ok=True)
        for req in KOKORO_TTS_SPEC.required_files:
            p = kokoro_dir / req
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"model data content")

        st = cache.status(KOKORO_TTS_SPEC.model_id)
        assert st.state is VoiceModelCacheState.VERIFIED
        assert st.is_verified
        assert st.size_bytes > 0


class TestVoiceModelCacheDownload:
    def test_download_unknown_model_raises(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        with pytest.raises(VoiceModelError, match="Cannot download unknown model"):
            cache.download("unknown-id")

    def test_download_idempotent_when_already_verified(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        # Create silero model file
        silero_file = tmp_path / "silero_vad.onnx"
        silero_file.write_bytes(b"silero onnx weights")

        with patch("urllib.request.urlopen") as mock_urlopen:
            st = cache.download(SILERO_VAD_SPEC.model_id)
            assert st.is_verified
            # No network call should be made
            mock_urlopen.assert_not_called()

    def test_download_single_file_success(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        content = b"fake silero onnx payload for unit tests"

        custom_spec = VoiceModelSpec(
            model_id="test-vad",
            display_name="Test VAD",
            description="Test single file",
            engine="vad",
            assets=(
                VoiceModelAsset(
                    filename="test_vad.onnx",
                    url="https://example.invalid/test_vad.onnx",
                    expected_size=len(content),
                    expected_sha256=hashlib.sha256(content).hexdigest(),
                    is_archive=False,
                ),
            ),
            local_dir_name="",
            required_files=("test_vad.onnx",),
            total_download_bytes=len(content),
            total_disk_bytes=len(content),
        )

        progress_reports: list[tuple[float, int, int]] = []

        def on_progress(pct: float, cur: int, total: int) -> None:
            progress_reports.append((pct, cur, total))

        class MockResponse:
            def __init__(self, data: bytes) -> None:
                self._data = io.BytesIO(data)

            def read(self, amt: int = -1) -> bytes:
                return self._data.read(amt)

            def __enter__(self) -> MockResponse:
                return self

            def __exit__(self, *args: Any) -> None:
                pass

        with (
            patch.dict(MODEL_REGISTRY, {"test-vad": custom_spec}),
            patch("urllib.request.urlopen", return_value=MockResponse(content)),
        ):
            st = cache.download("test-vad", progress_callback=on_progress)
            assert st.state is VoiceModelCacheState.VERIFIED
            assert (tmp_path / "test_vad.onnx").read_bytes() == content
            assert len(progress_reports) > 0
            assert progress_reports[-1][0] == 1.0

    def test_download_archive_success(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)

        # Build in-memory tar.bz2 archive with the required Kokoro files
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:bz2") as tar:
            for req in KOKORO_TTS_SPEC.required_files:
                data = b"simulated kokoro weight bytes"
                ti = tarfile.TarInfo(name=f"{KOKORO_TTS_SPEC.model_id}/{req}")
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))

        archive_bytes = buf.getvalue()

        # Custom spec matching archive bytes
        spec = VoiceModelSpec(
            model_id="test-tts",
            display_name="Test TTS",
            description="Test archive extraction",
            engine="tts",
            assets=(
                VoiceModelAsset(
                    filename="test-tts.tar.bz2",
                    url="https://example.invalid/test-tts.tar.bz2",
                    expected_size=len(archive_bytes),
                    is_archive=True,
                    archive_format="tar.bz2",
                ),
            ),
            local_dir_name="test-tts",
            required_files=KOKORO_TTS_SPEC.required_files,
            total_download_bytes=len(archive_bytes),
            total_disk_bytes=1000,
        )

        class MockResponse:
            def __init__(self, data: bytes) -> None:
                self._data = io.BytesIO(data)

            def read(self, amt: int = -1) -> bytes:
                return self._data.read(amt)

            def __enter__(self) -> MockResponse:
                return self

            def __exit__(self, *args: Any) -> None:
                pass

        with (
            patch.dict(MODEL_REGISTRY, {"test-tts": spec}),
            patch("urllib.request.urlopen", return_value=MockResponse(archive_bytes)),
        ):
            st = cache.download("test-tts")
            assert st.state is VoiceModelCacheState.VERIFIED
            dest_dir = tmp_path / "test-tts"
            assert dest_dir.is_dir()
            assert (dest_dir / "model.int8.onnx").is_file()
            assert (dest_dir / "espeak-ng-data" / "phontab").is_file()

    def test_download_size_mismatch_fails_and_cleans_up(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        content = b"short"

        spec = VoiceModelSpec(
            model_id="test-size",
            display_name="Test Size",
            description="Test size mismatch",
            engine="vad",
            assets=(
                VoiceModelAsset(
                    filename="file.bin",
                    url="https://example.invalid/file.bin",
                    expected_size=99999,  # Mismatch
                ),
            ),
            local_dir_name="",
            required_files=("file.bin",),
            total_download_bytes=99999,
            total_disk_bytes=99999,
        )

        class MockResponse:
            def __init__(self, data: bytes) -> None:
                self._data = io.BytesIO(data)

            def read(self, amt: int = -1) -> bytes:
                return self._data.read(amt)

            def __enter__(self) -> MockResponse:
                return self

            def __exit__(self, *args: Any) -> None:
                pass

        with (
            patch.dict(MODEL_REGISTRY, {"test-size": spec}),
            patch("urllib.request.urlopen", return_value=MockResponse(content)),
        ):
            with pytest.raises(VoiceModelIntegrityError, match="size mismatch"):
                cache.download("test-size")

            # Verify no partial or corrupt file committed
            assert not (tmp_path / "file.bin").exists()
            assert len(list(tmp_path.glob(".staging*"))) == 0

    def test_download_hash_mismatch_fails(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        content = b"data"

        spec = VoiceModelSpec(
            model_id="test-hash",
            display_name="Test Hash",
            description="Test hash mismatch",
            engine="vad",
            assets=(
                VoiceModelAsset(
                    filename="file.bin",
                    url="https://example.invalid/file.bin",
                    expected_size=len(content),
                    expected_sha256="0000000000000000000000000000000000000000000000000000000000000000",
                ),
            ),
            local_dir_name="",
            required_files=("file.bin",),
            total_download_bytes=len(content),
            total_disk_bytes=len(content),
        )

        class MockResponse:
            def __init__(self, data: bytes) -> None:
                self._data = io.BytesIO(data)

            def read(self, amt: int = -1) -> bytes:
                return self._data.read(amt)

            def __enter__(self) -> MockResponse:
                return self

            def __exit__(self, *args: Any) -> None:
                pass

        with (
            patch.dict(MODEL_REGISTRY, {"test-hash": spec}),
            patch("urllib.request.urlopen", return_value=MockResponse(content)),
        ):
            with pytest.raises(VoiceModelIntegrityError, match="Cryptographic hash mismatch"):
                cache.download("test-hash")

            assert not (tmp_path / "file.bin").exists()

    def test_download_http_error_fails(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            with pytest.raises(urllib.error.URLError):
                cache.download(SILERO_VAD_SPEC.model_id)


class TestVoiceModelCacheEvictionAndInventory:
    def test_evict_directory_model(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        kokoro_dir = tmp_path / KOKORO_TTS_SPEC.local_dir_name
        kokoro_dir.mkdir(parents=True, exist_ok=True)
        (kokoro_dir / "model.int8.onnx").write_bytes(b"dummy")

        assert kokoro_dir.exists()
        cache.evict(KOKORO_TTS_SPEC.model_id)
        assert not kokoro_dir.exists()

    def test_evict_single_file_model(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        silero_file = tmp_path / "silero_vad.onnx"
        silero_file.write_bytes(b"dummy")

        assert silero_file.exists()
        cache.evict(SILERO_VAD_SPEC.model_id)
        assert not silero_file.exists()

    def test_inventory(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        inv = cache.inventory()
        assert len(inv) == len(MODEL_REGISTRY)
        ids = [st.model_id for st in inv]
        assert SILERO_VAD_SPEC.model_id in ids
        assert KOKORO_TTS_SPEC.model_id in ids
        assert NEMOTRON_ASR_SPEC.model_id in ids
