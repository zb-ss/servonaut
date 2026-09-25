"""Managed voice worker protocol and data models for Servonaut Desktop.

This package defines the standard I/O protocol, message models, framing codec,
and error taxonomy for the out-of-process voice companion runtime.
Zero native audio dependencies.

Every public name resolves lazily (PEP 562). The voice worker runs from this
package inside the managed voice runtime, which carries only the speech
dependencies: importing it must not pull in the parent-side modules (the
connection, the setup services, the runtime manager) or what they import.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any, Dict, Tuple

# Submodule -> the public names it defines.
_EXPORTS_BY_MODULE: Dict[str, Tuple[str, ...]] = {
    ".protocol": (
        "MAX_FRAME_BYTES",
        "VOICE_PROTOCOL_VERSION",
        "ConfigureRequest",
        "ConversationErrorEvent",
        "ConversationInterruptRequest",
        "ConversationSignalRequest",
        "ConversationStartRequest",
        "ConversationStateEvent",
        "ConversationStopRequest",
        "ConversationStoppedEvent",
        "ConversationTranscriptEvent",
        "HandshakeRequest",
        "HandshakeResponsePayload",
        "InputCancelRequest",
        "InputCapHitEvent",
        "InputEndpointEvent",
        "InputPartialEvent",
        "InputResetBudgetRequest",
        "InputStartRequest",
        "InputStopRequest",
        "InputStopResponsePayload",
        "OutputCloseRequest",
        "OutputEnqueueRequest",
        "OutputSpeakRequest",
        "OutputSpeakResponsePayload",
        "OutputStateEvent",
        "OutputStopRequest",
        "OutputUtteranceBeginRequest",
        "OutputUtteranceEndRequest",
        "OutputUtteranceEnqueueRequest",
        "PingRequest",
        "ProbeRequest",
        "ProbeResponsePayload",
        "ShutdownRequest",
        "UtteranceCompletedEvent",
        "VoiceErrorCode",
        "VoiceErrorPayload",
        "VoiceEvent",
        "VoiceFrameReader",
        "VoiceMessage",
        "VoiceProtocolEofError",
        "VoiceProtocolError",
        "VoiceProtocolVersionError",
        "VoiceRequest",
        "VoiceResponse",
        "VoiceWorkerConfig",
        "WorkerErrorEvent",
        "decode_voice_message",
        "encode_voice_message",
        "read_voice_frame",
        "write_voice_frame",
    ),
    ".connection": (
        "VoiceConnection",
        "VoiceConnectionClosedError",
        "VoiceConnectionError",
        "VoiceConnectionPolicy",
        "VoiceConnectionTimeoutError",
        "VoiceRemoteError",
    ),
    ".packaged_manifest": (
        "PackagedVoiceManifest",
        "PackagedVoiceManifestError",
        "load_packaged_manifest",
    ),
    ".models": (
        "DEFAULT_MODELS_ROOT",
        "KOKORO_TTS_SPEC",
        "MODEL_REGISTRY",
        "NEMOTRON_ASR_SPEC",
        "SILERO_VAD_SPEC",
        "VoiceModelAsset",
        "VoiceModelCache",
        "VoiceModelCacheState",
        "VoiceModelError",
        "VoiceModelExtractionError",
        "VoiceModelIntegrityError",
        "VoiceModelSpec",
        "VoiceModelStatus",
        "compute_file_sha256",
        "nemotron_model_id",
        "nemotron_spec",
        "safe_extract_tar",
    ),
    ".runtime": (
        "VoiceRuntimeCancelledError",
        "VoiceRuntimeCommandError",
        "VoiceRuntimeError",
        "VoiceRuntimeIntegrityError",
        "VoiceRuntimeLock",
        "VoiceRuntimeLockError",
        "VoiceRuntimeManager",
        "VoiceRuntimeManifest",
        "VoiceRuntimeNotReadyError",
        "VoiceRuntimeSmokeError",
        "VoiceRuntimeState",
        "VoiceRuntimeStatus",
        "VoiceRuntimeStepError",
        "VoiceRuntimeTimeoutError",
        "VoiceRuntimeUnavailableError",
    ),
    ".service": (
        "DesktopUtteranceSession",
        "DesktopVoiceConversationService",
        "DesktopVoiceInputService",
        "DesktopVoiceOutputService",
        "build_desktop_voice_services",
    ),
    ".setup_service": (
        "DesktopVoiceSetupService",
    ),
    ".worker": (
        "EngineServiceFactory",
        "VoiceServiceFactory",
        "VoiceWorker",
        "run_worker",
    ),
}

_LAZY_EXPORTS: Dict[str, str] = {
    name: module for module, names in _EXPORTS_BY_MODULE.items() for name in names
}

__all__ = sorted(_LAZY_EXPORTS)


def __getattr__(name: str) -> Any:
    """Import the submodule that defines *name* on first access.

    Unknown names raise ``AttributeError`` so submodule imports
    (``from servonaut.desktop.voice import worker``) keep working.
    """
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name, __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
