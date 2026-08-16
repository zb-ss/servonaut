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

# ---------------------------------------------------------------------------
# Text-to-speech (spoken replies)
# ---------------------------------------------------------------------------
#
# One TTS model rather than a per-engine choice: Kokoro (v1.0, int8) is the
# best speech quality per megabyte currently published in sherpa-onnx
# format, runs faster than real time on a laptop CPU, and its runtime is a
# package the streaming STT engine already uses — so speaking replies adds
# one model download and no new native stack.
#
# The int8 multilingual v1.0 export specifically: it carries the full v1.0
# English voice roster (28 voices). The newer v1.1 export is a trap for an
# English-first product — it ships only three English voices — and the old
# v0.19 export has no int8 build and a different, smaller voice set.

KOKORO_MODEL_ID = "kokoro-int8-multi-lang-v1_0"

# Single-tarball release asset. One streamed download beats fetching the
# repository's files individually: the model directory holds hundreds of
# small espeak data files, and bz2 compresses the int8 weights well enough
# that the archive is smaller than the raw English-runtime subset.
KOKORO_ARCHIVE_URL = (
    "https://github.com/k2-fsa/sherpa-onnx/releases/download/tts-models/"
    "kokoro-int8-multi-lang-v1_0.tar.bz2"
)

# Measured sizes for the confirmation copy: the archive as served, and the
# extracted tree on disk.
KOKORO_ARCHIVE_BYTES = 131_839_838
KOKORO_DISK_BYTES = 189_455_587

# Files the synthesiser is pointed at (relative to the model directory).
KOKORO_MODEL_FILE = "model.int8.onnx"
KOKORO_VOICES_FILE = "voices.bin"
KOKORO_TOKENS_FILE = "tokens.txt"
KOKORO_LEXICON_FILES: Tuple[str, ...] = ("lexicon-us-en.txt", "lexicon-gb-en.txt")
KOKORO_ESPEAK_DIR = "espeak-ng-data"

# Presence check: every file the engine validates at load time, including
# the espeak sentinels it looks for inside the data directory. Checking all
# of them means an interrupted extraction can never read as a complete
# install.
KOKORO_REQUIRED_FILES: Tuple[str, ...] = (
    KOKORO_MODEL_FILE,
    KOKORO_VOICES_FILE,
    KOKORO_TOKENS_FILE,
    *KOKORO_LEXICON_FILES,
    f"{KOKORO_ESPEAK_DIR}/phontab",
    f"{KOKORO_ESPEAK_DIR}/phonindex",
    f"{KOKORO_ESPEAK_DIR}/phondata",
    f"{KOKORO_ESPEAK_DIR}/intonations",
)

# pip requirements for speaking replies. The synthesis runtime is the same
# package the streaming STT engine uses, so a user already on that engine
# needs no further install.
TTS_PACKAGES: Tuple[str, ...] = ("sherpa-onnx>=1.13.3", *_AUDIO_PACKAGES)

# Voice name → speaker id for the model above. Ids are fixed properties of
# the voices file, so they live here with the rest of the model identity.
# English voices only — the ids above 27 are other languages, which the
# English lexicons would mispronounce.
KOKORO_VOICES: Dict[str, int] = {
    "af_alloy": 0, "af_aoede": 1, "af_bella": 2, "af_heart": 3,
    "af_jessica": 4, "af_kore": 5, "af_nicole": 6, "af_nova": 7,
    "af_river": 8, "af_sarah": 9, "af_sky": 10,
    "am_adam": 11, "am_echo": 12, "am_eric": 13, "am_fenrir": 14,
    "am_liam": 15, "am_michael": 16, "am_onyx": 17, "am_puck": 18,
    "am_santa": 19,
    "bf_alice": 20, "bf_emma": 21, "bf_isabella": 22, "bf_lily": 23,
    "bm_daniel": 24, "bm_fable": 25, "bm_george": 26, "bm_lewis": 27,
}

DEFAULT_TTS_VOICE = "af_heart"

# ---------------------------------------------------------------------------
# Voice activity detection (conversation mode)
# ---------------------------------------------------------------------------
#
# The hands-free conversation loop needs to know when the user has stopped
# talking. Both capture engines get that from the same tiny Silero VAD
# model rather than from the streaming recognizer's endpoint rules: the
# batch engine has no endpointing at all, and one detector serving both
# engines keeps turn-taking behaviour — and its tuning knobs — identical
# regardless of which speech-to-text engine is configured.
#
# The 16 kHz-only v4 export specifically: it is the artifact the runtime's
# own examples pin, it is the smallest published variant by a wide margin,
# and the branch it drops (8 kHz) is one this application can never feed —
# capture is fixed at 16 kHz.

SILERO_VAD_MODEL_ID = "silero-vad-v4-16k"

# Single-file release asset — no archive, no extraction step.
SILERO_VAD_URL = (
    "https://github.com/k2-fsa/sherpa-onnx/releases/download/asr-models/"
    "silero_vad.onnx"
)

# Measured size of the asset as served, for the confirmation copy.
SILERO_VAD_BYTES = 643_854

SILERO_VAD_FILE = "silero_vad.onnx"


def silero_vad_model_dir() -> Path:
    """Local directory the voice-activity model lives in."""
    return VOICE_MODEL_ROOT / SILERO_VAD_MODEL_ID


def silero_vad_model_path() -> Path:
    """Full path of the voice-activity model file."""
    return silero_vad_model_dir() / SILERO_VAD_FILE


def is_silero_vad_model_present() -> bool:
    """Whether a usable voice-activity model is on disk.

    Checks for a non-empty file, not mere existence: a download that was
    interrupted before the first byte leaves an empty file behind, and
    treating that as installed pushes the failure to the first
    conversation instead of surfacing it in the settings panel.
    """
    path = silero_vad_model_path()
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


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


def kokoro_model_dir() -> Path:
    """Local directory the speech-synthesis model lives in."""
    return VOICE_MODEL_ROOT / KOKORO_MODEL_ID


def is_kokoro_model_present() -> bool:
    """Whether a complete set of speech-synthesis files is on disk.

    Every required file is checked, not just the directory: an interrupted
    download or extraction must not read as an installed model.
    """
    model_dir = kokoro_model_dir()
    if not model_dir.is_dir():
        return False
    return all((model_dir / name).is_file() for name in KOKORO_REQUIRED_FILES)


def kokoro_voice_sid(voice_name: str) -> int:
    """Resolve a voice name to its speaker id, defaulting on unknown names.

    Falls back rather than raising for the same reason :func:`engine_spec`
    does: a hand-edited or newer-release config should degrade to a working
    voice, not take spoken replies down.
    """
    if voice_name in KOKORO_VOICES:
        return KOKORO_VOICES[voice_name]
    return KOKORO_VOICES[DEFAULT_TTS_VOICE]


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


def build_voice_output_service(config: 'VoiceConfig'):  # type: ignore[name-defined]
    """Construct the spoken-reply (text-to-speech) service.

    Mirrors :func:`build_voice_input_service`: the import is function-local
    because the output module imports this one for its model paths, and the
    factory is the single construction point call sites go through.

    Returns:
        A :class:`~servonaut.services.interfaces.VoiceOutputServiceInterface`
        implementation.
    """
    from servonaut.services.voice_output_service import VoiceOutputService
    return VoiceOutputService(config)


def build_voice_conversation_service(
    config: 'VoiceConfig',  # type: ignore[name-defined]
    *,
    input_service,
    output_service,
):
    """Construct the hands-free conversation-loop controller.

    Mirrors the other ``build_*`` factories: function-local import because
    the service module imports this one for the model registry, and one
    construction point for every call site.

    Args:
        config: The voice configuration the loop reads its knobs from.
        input_service: Zero-argument callable resolving the CURRENT
            capture service. A callable rather than the instance on
            purpose — a settings save rebuilds the capture service, and a
            loop holding a direct reference would keep driving the retired
            one.
        output_service: Zero-argument callable resolving the CURRENT
            speech-output service, for the same reason.

    Returns:
        A :class:`~servonaut.services.interfaces.VoiceConversationServiceInterface`
        implementation.
    """
    from servonaut.services.voice_conversation_service import (
        VoiceConversationService,
    )
    return VoiceConversationService(
        config,
        input_service=input_service,
        output_service=output_service,
    )


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
