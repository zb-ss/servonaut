"""Registry of the speech-to-text engines voice input can run on.

Two engines, with genuinely different shapes rather than two names for the
same thing:

``whisper``
    Batch. Records first, then decodes the whole utterance. Accurate and
    the lighter download, but the text only appears once you stop talking.

``nemotron``
    Streaming. A cache-aware transducer that decodes as the audio arrives,
    so words appear while you speak and the output only ever grows —
    unlike re-running a batch model over a widening buffer, which revises
    text that has already been shown. Costs a larger download.

Everything engine-specific lives here — pip requirements, model identity,
where the weights land, how big they are — so the setup service and the
settings panel can stay engine-agnostic and a third engine means adding
one entry rather than editing branches in five files.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.config.schema import VoiceConfig

# Shared by both engines: capture and buffer handling.
_AUDIO_PACKAGES: Tuple[str, ...] = ("sounddevice>=0.4", "numpy>=1.24")

# Root for weights we manage ourselves. Whisper's are handled by the
# transcription backend's own Hugging Face cache instead, so only the
# streaming engine keeps files here.
VOICE_MODEL_ROOT = Path("~/.servonaut/voice_models").expanduser()

# Streaming latency variants published for the transducer model. Smaller
# chunks show words sooner and cost slightly more accuracy; every variant
# is the same download size, so this is a free choice.
NEMOTRON_LATENCY_OPTIONS: Tuple[int, ...] = (80, 160, 320, 560, 1120)
NEMOTRON_DEFAULT_LATENCY_MS = 320

# Repository template for the int8 streaming exports. int8 rather than the
# float build on purpose: the float encoder alone is ~2.4 GB against
# ~660 MB quantised, for no benefit at dictation quality.
_NEMOTRON_REPO_TEMPLATE = (
    "csukuangfj2/sherpa-onnx-nemotron-3.5-asr-streaming-0.6b-{latency}ms-int8-2026-06-11"
)

# The four files the recognizer needs, mapped to the local names it is
# handed. Keeping the local names stable means a repository reshuffle only
# touches the left-hand side.
NEMOTRON_FILES: Dict[str, str] = {
    "encoder.int8.onnx": "encoder.int8.onnx",
    "decoder.int8.onnx": "decoder.int8.onnx",
    "joiner.int8.onnx": "joiner.int8.onnx",
    "tokens.txt": "tokens.txt",
}

# Measured total of the int8 files, for the confirmation copy.
NEMOTRON_DOWNLOAD_BYTES = 683 * 1024 * 1024


@dataclass(frozen=True)
class VoiceEngineSpec:
    """Static description of one speech-to-text engine.

    Attributes:
        id: Stable identifier stored in config.
        label: Human-readable name for the settings dropdown.
        streaming: Whether it emits partial text while the user speaks.
        packages: pip requirements this engine needs on top of the audio ones.
        import_names: Modules that must import for the engine to be usable.
        summary: One-line description shown under the dropdown.
    """

    id: str
    label: str
    streaming: bool
    packages: Tuple[str, ...]
    import_names: Tuple[str, ...]
    summary: str


ENGINES: Dict[str, VoiceEngineSpec] = {
    "whisper": VoiceEngineSpec(
        id="whisper",
        label="Whisper (batch, smaller download)",
        streaming=False,
        packages=("faster-whisper>=1.0", *_AUDIO_PACKAGES),
        import_names=("numpy", "faster_whisper"),
        summary=(
            "Transcribes after you stop speaking. Smaller download and very "
            "accurate; the wait is visible on longer dictations."
        ),
    ),
    "nemotron": VoiceEngineSpec(
        id="nemotron",
        label="Nemotron streaming (live text, larger download)",
        streaming=True,
        packages=("sherpa-onnx>=1.13.3", *_AUDIO_PACKAGES),
        import_names=("numpy", "sherpa_onnx"),
        summary=(
            "Words appear as you speak and are never rewritten. Needs a "
            "larger model download and more memory while running."
        ),
    ),
}

DEFAULT_ENGINE = "whisper"


def engine_spec(engine_id: str) -> VoiceEngineSpec:
    """Look up an engine, falling back to the default for unknown ids.

    Falls back rather than raising so a config written by a newer release
    (or edited by hand) degrades to a working engine instead of breaking
    the settings panel and the chat dock together.
    """
    return ENGINES.get(engine_id) or ENGINES[DEFAULT_ENGINE]


def nemotron_repo(latency_ms: int) -> str:
    """Repository id holding the streaming weights for *latency_ms*."""
    return _NEMOTRON_REPO_TEMPLATE.format(latency=_normalise_latency(latency_ms))


def nemotron_model_dir(latency_ms: int) -> Path:
    """Local directory the streaming weights for *latency_ms* live in."""
    latency = _normalise_latency(latency_ms)
    return VOICE_MODEL_ROOT / f"nemotron-3.5-{latency}ms-int8"


def _normalise_latency(latency_ms: int) -> int:
    """Snap *latency_ms* to a published variant.

    An unpublished value would resolve to a repository that does not exist
    and fail at download time, so it is snapped to the nearest offered
    chunk size instead.
    """
    try:
        value = int(latency_ms)
    except (TypeError, ValueError):
        return NEMOTRON_DEFAULT_LATENCY_MS
    if value in NEMOTRON_LATENCY_OPTIONS:
        return value
    return min(NEMOTRON_LATENCY_OPTIONS, key=lambda option: abs(option - value))


def model_label(engine_id: str, *, model_size: str, latency_ms: int) -> str:
    """Human-readable name for the model an engine is configured to use."""
    if engine_spec(engine_id).streaming:
        return f"Nemotron streaming {_normalise_latency(latency_ms)}ms"
    return f"Whisper {model_size}"


def directory_bytes(path: Path) -> int:
    """Total size of the files under *path*, or 0 when it does not exist.

    Symlinks are skipped so a cache that hard-links or symlinks blobs is
    not counted twice.
    """
    if not path.is_dir():
        return 0
    total = 0
    for entry in path.rglob("*"):
        try:
            if entry.is_file() and not entry.is_symlink():
                total += entry.stat().st_size
        except OSError:
            continue
    return total


def build_voice_input_service(config: 'VoiceConfig'):  # type: ignore[name-defined]
    """Construct the input service for the engine *config* selects.

    The two engines are different classes with different runtimes, so
    switching engine means building a new service rather than reconfiguring
    the existing one. Imports are function-local because the engine modules
    import this one for their model paths.

    Returns:
        A :class:`~servonaut.services.interfaces.VoiceInputServiceInterface`
        implementation.
    """
    if engine_spec(getattr(config, "engine", DEFAULT_ENGINE)).streaming:
        from servonaut.services.voice_streaming_service import (
            StreamingVoiceInputService,
        )
        return StreamingVoiceInputService(config)
    from servonaut.services.voice_input_service import VoiceInputService
    return VoiceInputService(config)


def human_bytes(size: Optional[int]) -> str:
    """Render a byte count as a short human-readable string."""
    if not size:
        return "0 MB"
    value = float(size)
    for unit in ("B", "KB", "MB"):
        if value < 1024:
            return f"{value:.0f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"
