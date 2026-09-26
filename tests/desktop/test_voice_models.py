"""Unit tests for VoiceModelCache, the pinned model registry, and integrity checks.

Covers:
- Registry pins: HTTPS URLs (commit-addressed where the host allows), exact sizes and SHA-256
- One models root shared with the speech engines' own path helpers
- Status classification (NOT_DOWNLOADED, DOWNLOADING, VERIFIED, CORRUPTED)
- Download: size cap mid-stream, advertised length, digest, HTTPS-only redirects
- Staging hygiene: stale staging sweep under the lock, atomic replacement
- Safe archive extraction, eviction and inventory
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
import re
import tarfile
import time
from typing import Any, Dict, List, Optional, Union
import urllib.error
import urllib.request
from unittest.mock import patch

import pytest

from servonaut.desktop.voice.models import (
    KOKORO_TTS_SPEC,
    MODEL_REGISTRY,
    NEMOTRON_ASR_SPEC,
    SILERO_VAD_SPEC,
    HttpsOnlyRedirectHandler,
    VoiceModelAsset,
    VoiceModelCache,
    VoiceModelCacheState,
    VoiceModelDownloadPolicy,
    VoiceModelError,
    VoiceModelExtractionError,
    VoiceModelIntegrityError,
    VoiceModelSpec,
    compute_file_sha256,
    nemotron_model_id,
    nemotron_spec,
    safe_extract_tar,
)
from servonaut.desktop.voice.runtime import VoiceRuntimeLock
from servonaut.services import voice_engines
from servonaut.services.voice_engines import (
    KOKORO_ARCHIVE_BYTES,
    NEMOTRON_LATENCY_OPTIONS,
    SILERO_VAD_BYTES,
    is_kokoro_model_present,
    is_nemotron_model_present,
    is_silero_vad_model_present,
    kokoro_model_dir,
    nemotron_model_dir,
    silero_vad_model_dir,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeResponse:
    """File-like HTTP response over fixed bytes or an endless byte stream.

    ``fail_after`` raises that exception once the given bytes are served,
    like a connection dropping mid-body; ``read_delay`` paces every read.
    """

    def __init__(
        self,
        data: bytes = b"",
        *,
        endless: bool = False,
        content_length: Optional[int] = None,
        status: int = 200,
        content_range: Optional[str] = None,
        fail_after: Optional[Exception] = None,
        read_delay: float = 0.0,
    ) -> None:
        self._data = io.BytesIO(data)
        self._endless = endless
        self._fail_after = fail_after
        self._read_delay = read_delay
        self.status = status
        self.reads = 0
        self.headers: Dict[str, str] = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)
        if content_range is not None:
            self.headers["Content-Range"] = content_range

    def read(self, amt: int = -1) -> bytes:
        self.reads += 1
        time.sleep(self._read_delay)
        if self._endless:
            return b"x" * amt
        chunk = self._data.read(amt)
        if not chunk and self._fail_after is not None:
            raise self._fail_after
        return chunk

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: Any) -> None:
        pass


Canned = Union[FakeResponse, Exception]


class FakeOpener:
    """Serves canned responses keyed by URL and records every request.

    A list of responses is served one per request, in order; a single
    response (or exception) answers every request for that URL.
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
        return response


FAST_RETRY = VoiceModelDownloadPolicy(retry_delay_seconds=0.0)


def _asset(filename: str, data: bytes, **kwargs: Any) -> VoiceModelAsset:
    return VoiceModelAsset(
        filename=filename,
        url=f"https://models.example/{filename}",
        expected_size=kwargs.pop("expected_size", len(data)),
        expected_sha256=kwargs.pop("expected_sha256", hashlib.sha256(data).hexdigest()),
        **kwargs,
    )


def _spec(model_id: str, *assets: VoiceModelAsset, required: tuple[str, ...]) -> VoiceModelSpec:
    return VoiceModelSpec(
        model_id=model_id,
        display_name=model_id,
        description="test model",
        engine="vad",
        assets=assets,
        required_files=required,
        model_dir=lambda root: root / model_id,
        total_disk_bytes=1,
    )


def _write_required(spec: VoiceModelSpec, model_dir: Path) -> None:
    """Lay down files matching *spec*'s pinned sizes (content is irrelevant)."""
    sizes = {a.filename: a.expected_size for a in spec.assets if not a.is_archive}
    for name in spec.required_files:
        path = model_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as f:
            f.truncate(sizes.get(name, 4))


# ---------------------------------------------------------------------------
# Registry pins
# ---------------------------------------------------------------------------


class TestRegistryPins:
    def test_every_asset_is_pinned(self) -> None:
        for spec in MODEL_REGISTRY.values():
            for asset in spec.assets:
                assert asset.url.startswith("https://")
                assert asset.expected_size > 0
                assert re.fullmatch(r"[0-9a-f]{64}", asset.expected_sha256)

    def test_urls_are_revision_or_release_addressed(self) -> None:
        for spec in MODEL_REGISTRY.values():
            for asset in spec.assets:
                if "huggingface.co" in asset.url:
                    revision = asset.url.split("/resolve/")[1].split("/")[0]
                    assert re.fullmatch(r"[0-9a-f]{40}", revision), asset.url
                else:
                    assert "/releases/download/" in asset.url, asset.url

    def test_one_spec_per_published_latency(self) -> None:
        for latency in NEMOTRON_LATENCY_OPTIONS:
            spec = nemotron_spec(latency)
            assert spec.model_id == nemotron_model_id(latency)
            assert spec.model_id in MODEL_REGISTRY
            assert f"{latency}ms" in spec.assets[0].url
        assert nemotron_spec(300) is nemotron_spec(320)
        assert NEMOTRON_ASR_SPEC is nemotron_spec(320)

    def test_confirmation_copy_matches_pins(self) -> None:
        assert SILERO_VAD_SPEC.total_download_bytes == SILERO_VAD_BYTES
        assert KOKORO_TTS_SPEC.total_download_bytes == KOKORO_ARCHIVE_BYTES

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"url": "http://models.example/a"},
            {"expected_size": 0},
            {"expected_sha256": ""},
            {"expected_sha256": "ABC"},
        ],
    )
    def test_asset_without_pins_is_rejected(self, kwargs: Dict[str, Any]) -> None:
        values: Dict[str, Any] = {
            "filename": "a",
            "url": "https://models.example/a",
            "expected_size": 1,
            "expected_sha256": "0" * 64,
        }
        values.update(kwargs)
        with pytest.raises(ValueError):
            VoiceModelAsset(**values)


# ---------------------------------------------------------------------------
# One models root, shared with the engines
# ---------------------------------------------------------------------------


class TestSharedModelsRoot:
    def test_targets_come_from_engine_helpers(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        root = cache.root_dir
        assert cache.model_dir(SILERO_VAD_SPEC) == silero_vad_model_dir(root)
        assert cache.model_dir(KOKORO_TTS_SPEC) == kokoro_model_dir(root)
        for latency in NEMOTRON_LATENCY_OPTIONS:
            assert cache.model_dir(nemotron_spec(latency)) == nemotron_model_dir(latency, root)

    def test_models_the_cache_verifies_are_what_the_engines_load(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        root = cache.root_dir
        for spec in (SILERO_VAD_SPEC, KOKORO_TTS_SPEC, nemotron_spec(160)):
            _write_required(spec, cache.model_dir(spec))
            assert cache.status(spec.model_id).is_verified

        assert is_silero_vad_model_present(root)
        assert is_kokoro_model_present(root)
        assert is_nemotron_model_present(160, root)
        assert not is_nemotron_model_present(320, root)

    def test_default_root_is_the_engines_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(voice_engines, "VOICE_MODEL_ROOT", tmp_path)
        assert VoiceModelCache().root_dir == tmp_path.resolve()


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


class TestStatus:
    def test_unknown_model(self, tmp_path: Path) -> None:
        st = VoiceModelCache(root_dir=tmp_path).status("unknown-model")
        assert st.state is VoiceModelCacheState.NOT_DOWNLOADED
        assert "Unknown model" in st.message

    def test_never_downloaded_single_file_model_is_not_corrupted(self, tmp_path: Path) -> None:
        # The models root itself exists; the VAD was simply never fetched.
        st = VoiceModelCache(root_dir=tmp_path).status(SILERO_VAD_SPEC.model_id)
        assert st.state is VoiceModelCacheState.NOT_DOWNLOADED

    def test_empty_model_directory_is_not_downloaded(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        cache.model_dir(KOKORO_TTS_SPEC).mkdir(parents=True)
        assert cache.status(KOKORO_TTS_SPEC.model_id).state is VoiceModelCacheState.NOT_DOWNLOADED

    def test_downloading_when_locked(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        with VoiceRuntimeLock(cache.lock_path):
            st = cache.status(KOKORO_TTS_SPEC.model_id)
        assert st.state is VoiceModelCacheState.DOWNLOADING

    def test_partial_model_is_corrupted(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        model_dir = cache.model_dir(KOKORO_TTS_SPEC)
        _write_required(KOKORO_TTS_SPEC, model_dir)
        (model_dir / "voices.bin").unlink()
        st = cache.status(KOKORO_TTS_SPEC.model_id)
        assert st.state is VoiceModelCacheState.CORRUPTED
        assert "voices.bin" in st.missing_files

    def test_zero_byte_required_file_is_corrupted(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        model_dir = cache.model_dir(KOKORO_TTS_SPEC)
        _write_required(KOKORO_TTS_SPEC, model_dir)
        (model_dir / "tokens.txt").write_bytes(b"")
        assert cache.status(KOKORO_TTS_SPEC.model_id).state is VoiceModelCacheState.CORRUPTED

    def test_truncated_loose_asset_is_corrupted(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        model_dir = cache.model_dir(SILERO_VAD_SPEC)
        model_dir.mkdir(parents=True)
        (model_dir / "silero_vad.onnx").write_bytes(b"truncated")
        st = cache.status(SILERO_VAD_SPEC.model_id)
        assert st.state is VoiceModelCacheState.CORRUPTED
        assert "size mismatch" in st.message

    def test_deep_verify_detects_wrong_digest(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        _write_required(SILERO_VAD_SPEC, cache.model_dir(SILERO_VAD_SPEC))
        assert cache.status(SILERO_VAD_SPEC.model_id).is_verified
        st = cache.status(SILERO_VAD_SPEC.model_id, deep_verify=True)
        assert st.state is VoiceModelCacheState.CORRUPTED
        assert "checksum mismatch" in st.message

    def test_verified_reports_disk_footprint(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        _write_required(SILERO_VAD_SPEC, cache.model_dir(SILERO_VAD_SPEC))
        st = cache.status(SILERO_VAD_SPEC.model_id)
        assert st.is_verified
        assert st.size_bytes == SILERO_VAD_SPEC.assets[0].expected_size


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


class TestDownload:
    def test_unknown_model_raises(self, tmp_path: Path) -> None:
        with pytest.raises(VoiceModelError, match="Cannot download unknown model"):
            VoiceModelCache(root_dir=tmp_path).download("unknown-id")

    def test_already_verified_makes_no_request(self, tmp_path: Path) -> None:
        opener = FakeOpener({})
        cache = VoiceModelCache(root_dir=tmp_path, opener=opener)
        _write_required(SILERO_VAD_SPEC, cache.model_dir(SILERO_VAD_SPEC))
        assert cache.download(SILERO_VAD_SPEC.model_id).is_verified
        assert opener.requested == []

    def test_single_file_success(self, tmp_path: Path) -> None:
        content = b"fake onnx payload"
        asset = _asset("test_vad.onnx", content)
        spec = _spec("test-vad", asset, required=("test_vad.onnx",))
        opener = FakeOpener({asset.url: FakeResponse(content, content_length=len(content))})
        cache = VoiceModelCache(root_dir=tmp_path, opener=opener)
        reports: List[tuple[float, int, int]] = []

        with patch.dict(MODEL_REGISTRY, {spec.model_id: spec}):
            st = cache.download(spec.model_id, progress_callback=lambda *a: reports.append(a))

        assert st.is_verified
        assert (cache.root_dir / "test-vad" / "test_vad.onnx").read_bytes() == content
        assert reports[-1][0] == 1.0

    def test_archive_success(self, tmp_path: Path) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:bz2") as tar:
            for name in KOKORO_TTS_SPEC.required_files:
                data = b"simulated kokoro bytes"
                info = tarfile.TarInfo(name=f"{KOKORO_TTS_SPEC.model_id}/{name}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        archive = buf.getvalue()
        asset = _asset("test-tts.tar.bz2", archive, is_archive=True)
        spec = _spec("test-tts", asset, required=KOKORO_TTS_SPEC.required_files)
        cache = VoiceModelCache(root_dir=tmp_path, opener=FakeOpener({asset.url: FakeResponse(archive)}))

        with patch.dict(MODEL_REGISTRY, {spec.model_id: spec}):
            assert cache.download(spec.model_id).is_verified

        model_dir = cache.root_dir / "test-tts"
        assert (model_dir / "espeak-ng-data" / "phontab").is_file()
        assert not (model_dir / "test-tts.tar.bz2").exists()
        assert not (model_dir / "extracted").exists()

    def test_stream_aborts_once_it_exceeds_the_pinned_size(self, tmp_path: Path) -> None:
        asset = _asset("big.bin", b"", expected_size=3 * 1024 * 1024, expected_sha256="0" * 64)
        spec = _spec("test-cap", asset, required=("big.bin",))
        response = FakeResponse(endless=True)
        cache = VoiceModelCache(root_dir=tmp_path, opener=FakeOpener({asset.url: response}))

        with patch.dict(MODEL_REGISTRY, {spec.model_id: spec}):
            with pytest.raises(VoiceModelIntegrityError, match="exceeded"):
                cache.download(spec.model_id)

        assert response.reads <= 4  # three pinned MiB, then one over the cap
        assert list(cache.root_dir.glob(".staging*")) == []

    def test_wrong_advertised_length_fails_before_transfer(self, tmp_path: Path) -> None:
        content = b"payload"
        asset = _asset("file.bin", content)
        spec = _spec("test-length", asset, required=("file.bin",))
        response = FakeResponse(content, content_length=len(content) + 1)
        cache = VoiceModelCache(root_dir=tmp_path, opener=FakeOpener({asset.url: response}))

        with patch.dict(MODEL_REGISTRY, {spec.model_id: spec}):
            with pytest.raises(VoiceModelIntegrityError, match="expected"):
                cache.download(spec.model_id)
        assert response.reads == 0

    def test_short_download_fails_and_cleans_up(self, tmp_path: Path) -> None:
        asset = _asset("file.bin", b"short", expected_size=99_999)
        spec = _spec("test-size", asset, required=("file.bin",))
        cache = VoiceModelCache(
            root_dir=tmp_path,
            opener=FakeOpener({asset.url: FakeResponse(b"short")}),
            policy=VoiceModelDownloadPolicy(max_resume_attempts=0),
        )

        with patch.dict(MODEL_REGISTRY, {spec.model_id: spec}):
            with pytest.raises(VoiceModelError, match="ended after 5 of 99999 bytes"):
                cache.download(spec.model_id)

        assert not (cache.root_dir / "test-size").exists()
        assert list(cache.root_dir.glob(".staging*")) == []

    def test_hash_mismatch_fails(self, tmp_path: Path) -> None:
        asset = _asset("file.bin", b"data", expected_sha256="0" * 64)
        spec = _spec("test-hash", asset, required=("file.bin",))
        cache = VoiceModelCache(root_dir=tmp_path, opener=FakeOpener({asset.url: FakeResponse(b"data")}))

        with patch.dict(MODEL_REGISTRY, {spec.model_id: spec}):
            with pytest.raises(VoiceModelIntegrityError, match="Cryptographic hash mismatch"):
                cache.download(spec.model_id)
        assert not (cache.root_dir / "test-hash").exists()

    def test_persistent_network_error_fails_after_the_retries(self, tmp_path: Path) -> None:
        url = SILERO_VAD_SPEC.assets[0].url
        opener = FakeOpener({url: urllib.error.URLError("Connection refused")})
        cache = VoiceModelCache(
            root_dir=tmp_path,
            opener=opener,
            policy=VoiceModelDownloadPolicy(max_resume_attempts=2, retry_delay_seconds=0.0),
        )
        with pytest.raises(VoiceModelError, match="kept failing"):
            cache.download(SILERO_VAD_SPEC.model_id)
        assert len(opener.requested) == 3

    def test_http_client_error_is_not_retried(self, tmp_path: Path) -> None:
        url = SILERO_VAD_SPEC.assets[0].url
        opener = FakeOpener({url: urllib.error.HTTPError(url, 404, "Not Found", {}, None)})  # type: ignore[arg-type]
        cache = VoiceModelCache(root_dir=tmp_path, opener=opener, policy=FAST_RETRY)
        with pytest.raises(urllib.error.HTTPError):
            cache.download(SILERO_VAD_SPEC.model_id)
        assert len(opener.requested) == 1


class TestStallAndResume:
    """No total deadline: slow is fine, silence is not, and drops resume."""

    def test_slow_but_steady_download_completes(self, tmp_path: Path) -> None:
        data = bytes(range(256)) * 4096 * 3  # three 1 MiB-ish reads
        asset = _asset("weights.bin", data)
        spec = _spec("test-slow", asset, required=("weights.bin",))
        opener = FakeOpener({asset.url: FakeResponse(data, read_delay=0.15)})
        policy = VoiceModelDownloadPolicy(stall_timeout_seconds=0.2, retry_delay_seconds=0.0)
        cache = VoiceModelCache(root_dir=tmp_path, opener=opener, policy=policy)

        started = time.monotonic()
        with patch.dict(MODEL_REGISTRY, {spec.model_id: spec}):
            assert cache.download(spec.model_id).is_verified
        assert time.monotonic() - started > policy.stall_timeout_seconds  # longer than any one wait
        assert opener.timeouts == [policy.stall_timeout_seconds]

    def test_stalled_transfer_fails(self, tmp_path: Path) -> None:
        data = b"weights" * 100
        asset = _asset("weights.bin", data)
        spec = _spec("test-stall", asset, required=("weights.bin",))
        stall = TimeoutError("The read operation timed out")  # what the socket raises
        opener = FakeOpener({asset.url: [FakeResponse(b"", fail_after=stall) for _ in range(3)]})
        cache = VoiceModelCache(
            root_dir=tmp_path, opener=opener,
            policy=VoiceModelDownloadPolicy(max_resume_attempts=2, retry_delay_seconds=0.0),
        )
        with patch.dict(MODEL_REGISTRY, {spec.model_id: spec}):
            with pytest.raises(VoiceModelError, match="kept failing"):
                cache.download(spec.model_id)
        assert len(opener.requested) == 3
        assert not (cache.root_dir / "test-stall").exists()

    def test_interrupted_transfer_resumes_where_it_stopped(self, tmp_path: Path) -> None:
        data = bytes(range(256)) * 1000
        half = len(data) // 2
        asset = _asset("weights.bin", data)
        spec = _spec("test-resume", asset, required=("weights.bin",))
        opener = FakeOpener({asset.url: [
            FakeResponse(data[:half], content_length=len(data), fail_after=ConnectionResetError()),
            FakeResponse(
                data[half:], status=206, content_length=len(data) - half,
                content_range=f"bytes {half}-{len(data) - 1}/{len(data)}",
            ),
        ]})
        reports: List[tuple[float, int, int]] = []
        cache = VoiceModelCache(root_dir=tmp_path, opener=opener, policy=FAST_RETRY)

        with patch.dict(MODEL_REGISTRY, {spec.model_id: spec}):
            assert cache.download(spec.model_id, progress_callback=lambda *a: reports.append(a)).is_verified

        assert opener.ranges == [None, f"bytes={half}-"]
        assert (cache.root_dir / "test-resume" / "weights.bin").read_bytes() == data
        assert max(r[1] for r in reports) == len(data)  # resumed bytes were not counted twice

    def test_server_ignoring_the_range_restarts_the_transfer(self, tmp_path: Path) -> None:
        data = b"0123456789" * 1000
        asset = _asset("weights.bin", data)
        spec = _spec("test-restart", asset, required=("weights.bin",))
        opener = FakeOpener({asset.url: [
            FakeResponse(data[:3000], fail_after=ConnectionResetError()),
            FakeResponse(data, status=200, content_length=len(data)),
        ]})
        cache = VoiceModelCache(root_dir=tmp_path, opener=opener, policy=FAST_RETRY)
        with patch.dict(MODEL_REGISTRY, {spec.model_id: spec}):
            assert cache.download(spec.model_id).is_verified
        assert (cache.root_dir / "test-restart" / "weights.bin").read_bytes() == data

    def test_unexpected_range_is_refused(self, tmp_path: Path) -> None:
        data = b"0123456789" * 1000
        asset = _asset("weights.bin", data)
        spec = _spec("test-bad-range", asset, required=("weights.bin",))
        opener = FakeOpener({asset.url: [
            FakeResponse(data[:3000], fail_after=ConnectionResetError()),
            FakeResponse(data[1000:], status=206, content_range=f"bytes 1000-9999/{len(data)}"),
        ]})
        cache = VoiceModelCache(root_dir=tmp_path, opener=opener, policy=FAST_RETRY)
        with patch.dict(MODEL_REGISTRY, {spec.model_id: spec}):
            with pytest.raises(VoiceModelIntegrityError, match="unexpected range"):
                cache.download(spec.model_id)

    def test_resumed_bytes_are_verified_with_the_rest(self, tmp_path: Path) -> None:
        data = b"0123456789" * 1000
        asset = _asset("weights.bin", data)
        spec = _spec("test-tampered", asset, required=("weights.bin",))
        tail = b"X" * (len(data) - 3000)  # a different file behind the same URL
        opener = FakeOpener({asset.url: [
            FakeResponse(data[:3000], fail_after=ConnectionResetError()),
            FakeResponse(tail, status=206, content_range=f"bytes 3000-{len(data) - 1}/{len(data)}"),
        ]})
        cache = VoiceModelCache(root_dir=tmp_path, opener=opener, policy=FAST_RETRY)
        with patch.dict(MODEL_REGISTRY, {spec.model_id: spec}):
            with pytest.raises(VoiceModelIntegrityError, match="hash mismatch"):
                cache.download(spec.model_id)
        assert not (cache.root_dir / "test-tampered").exists()

    def test_corrupted_model_is_replaced(self, tmp_path: Path) -> None:
        content = b"fresh weights"
        asset = _asset("file.bin", content)
        spec = _spec("test-replace", asset, required=("file.bin",))
        cache = VoiceModelCache(root_dir=tmp_path, opener=FakeOpener({asset.url: FakeResponse(content)}))
        old_dir = cache.root_dir / "test-replace"
        old_dir.mkdir()
        (old_dir / "file.bin").write_bytes(b"old")
        (old_dir / "leftover").write_bytes(b"stale")

        with patch.dict(MODEL_REGISTRY, {spec.model_id: spec}):
            assert cache.download(spec.model_id).is_verified

        assert (old_dir / "file.bin").read_bytes() == content
        assert not (old_dir / "leftover").exists()
        assert list(cache.root_dir.glob(".staging*")) == []

    def test_stale_staging_is_swept_under_the_lock(self, tmp_path: Path) -> None:
        content = b"weights"
        asset = _asset("file.bin", content)
        spec = _spec("test-sweep", asset, required=("file.bin",))
        cache = VoiceModelCache(root_dir=tmp_path, opener=FakeOpener({asset.url: FakeResponse(content)}))
        stale_dir = cache.root_dir / ".staging.test-sweep.killed"
        (stale_dir / "sub").mkdir(parents=True)
        (stale_dir / "sub" / "encoder.partial").write_bytes(b"x" * 64)
        stale_file = cache.root_dir / ".staging.orphan"
        stale_file.write_bytes(b"x")

        with patch.dict(MODEL_REGISTRY, {spec.model_id: spec}):
            cache.download(spec.model_id)

        assert not stale_dir.exists()
        assert not stale_file.exists()


class TestHttpsOnlyRedirects:
    def _redirect(self, new_url: str) -> Any:
        request = urllib.request.Request("https://models.example/a")
        return HttpsOnlyRedirectHandler().redirect_request(
            request, io.BytesIO(), 302, "Found", {}, new_url,
        )

    def test_plain_http_redirect_is_refused(self) -> None:
        with pytest.raises(VoiceModelError, match="non-HTTPS redirect"):
            self._redirect("http://mirror.example/a")

    def test_https_redirect_is_followed(self) -> None:
        followed = self._redirect("https://cdn.example/a")
        assert followed.full_url == "https://cdn.example/a"

    def test_default_opener_uses_the_https_only_handler(self, tmp_path: Path) -> None:
        opener = VoiceModelCache(root_dir=tmp_path)._opener
        assert any(isinstance(h, HttpsOnlyRedirectHandler) for h in opener.handlers)


# ---------------------------------------------------------------------------
# Archive safety, eviction, inventory
# ---------------------------------------------------------------------------


class TestSafeExtract:
    def test_valid_archive(self, tmp_path: Path) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo("dir/file.txt")
            info.size = 2
            tar.addfile(info, io.BytesIO(b"ok"))
        buf.seek(0)
        with tarfile.open(fileobj=buf) as tar:
            safe_extract_tar(tar, tmp_path / "dest")
        assert (tmp_path / "dest" / "dir" / "file.txt").read_bytes() == b"ok"

    def test_parent_traversal_rejected(self, tmp_path: Path) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo("../escape.txt")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        buf.seek(0)
        with tarfile.open(fileobj=buf) as tar:
            with pytest.raises(VoiceModelExtractionError, match="traversal"):
                safe_extract_tar(tar, tmp_path / "dest")

    def test_symlink_chain_rejected_without_the_data_filter(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Interpreters before the PEP 706 backports lack tarfile.data_filter;
        # a chain of in-tree-looking links must still never escape.
        monkeypatch.delattr(tarfile, "data_filter", raising=False)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            first = tarfile.TarInfo("s")
            first.type = tarfile.SYMTYPE
            first.linkname = "."
            tar.addfile(first)
            second = tarfile.TarInfo("s/t")
            second.type = tarfile.SYMTYPE
            second.linkname = ".."
            tar.addfile(second)
            payload = tarfile.TarInfo("t/escaped.txt")
            payload.size = 5
            tar.addfile(payload, io.BytesIO(b"pwned"))
        buf.seek(0)
        dest = tmp_path / "base" / "dest"
        with tarfile.open(fileobj=buf) as tar:
            with pytest.raises(VoiceModelExtractionError, match="link member"):
                safe_extract_tar(tar, dest)
        assert not (tmp_path / "base" / "escaped.txt").exists()
        assert not dest.exists() or list(dest.iterdir()) == []


class TestEvictionAndInventory:
    def test_evict_removes_the_model_directory(self, tmp_path: Path) -> None:
        cache = VoiceModelCache(root_dir=tmp_path)
        for spec in (KOKORO_TTS_SPEC, SILERO_VAD_SPEC):
            _write_required(spec, cache.model_dir(spec))
            cache.evict(spec.model_id)
            assert not cache.model_dir(spec).exists()

    def test_inventory_lists_every_registered_model(self, tmp_path: Path) -> None:
        inventory = VoiceModelCache(root_dir=tmp_path).inventory()
        assert [st.model_id for st in inventory] == list(MODEL_REGISTRY)
        assert all(st.state is VoiceModelCacheState.NOT_DOWNLOADED for st in inventory)

    def test_compute_file_sha256(self, tmp_path: Path) -> None:
        path = tmp_path / "sample.bin"
        path.write_bytes(b"payload")
        assert compute_file_sha256(path) == hashlib.sha256(b"payload").hexdigest()
