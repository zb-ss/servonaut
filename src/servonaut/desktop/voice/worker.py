"""Standalone companion voice worker process for Servonaut Desktop.

Executes local microphone capture, streaming speech-to-text (STT),
voice-activity detection (VAD), hands-free conversation loop, and speech
synthesis/playback (TTS) in an isolated process over standard I/O JSON Lines.
Raw PCM audio buffers never traverse the IPC boundary.
"""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
import platform
import signal
import sys
import threading
from typing import Any, BinaryIO, Callable, Dict, Final, List, Optional, TextIO, Tuple, Union
import uuid

from servonaut.config.schema import VoiceConfig
from servonaut.desktop.voice.protocol import (
    MAX_FRAME_BYTES,
    VOICE_PROTOCOL_VERSION,
    ConversationErrorEvent,
    ConversationInterruptRequest,
    ConversationSignalRequest,
    ConversationStartRequest,
    ConversationStateEvent,
    ConversationStopRequest,
    ConversationStoppedEvent,
    ConversationTranscriptEvent,
    HandshakeRequest,
    HandshakeResponsePayload,
    InputCapHitEvent,
    InputCancelRequest,
    InputEndpointEvent,
    InputPartialEvent,
    InputResetBudgetRequest,
    InputStartRequest,
    InputStopRequest,
    InputStopResponsePayload,
    OutputCloseRequest,
    OutputEnqueueRequest,
    OutputSpeakRequest,
    OutputSpeakResponsePayload,
    OutputStateEvent,
    OutputStopRequest,
    OutputUtteranceBeginRequest,
    OutputUtteranceEndRequest,
    OutputUtteranceEnqueueRequest,
    PingRequest,
    ProbeRequest,
    ProbeResponsePayload,
    ShutdownRequest,
    UtteranceCompletedEvent,
    VoiceErrorCode,
    VoiceErrorPayload,
    VoiceEvent,
    VoiceMessage,
    VoiceProtocolEofError,
    VoiceProtocolError,
    VoiceRequest,
    VoiceResponse,
    WorkerErrorEvent,
    decode_voice_message,
    encode_voice_message,
    read_voice_frame,
    write_voice_frame,
)
from servonaut.services.interfaces import (
    VoiceConversationServiceInterface,
    VoiceInputServiceInterface,
    VoiceOutputServiceInterface,
)

logger = logging.getLogger("servonaut.voice.worker")

DEFAULT_CAPABILITIES: Final[Tuple[str, ...]] = (
    "stt_batch",
    "stt_streaming",
    "tts",
    "vad",
    "conversation",
)


class VoiceWorker:
    """Manages voice capture, synthesis, and conversation in a companion process."""

    def __init__(
        self,
        stdin: BinaryIO,
        stdout: BinaryIO,
        stderr: Optional[TextIO] = None,
        *,
        manifest_id: str = "managed-runtime-v1",
        models_root: Optional[Path] = None,
        config: Optional[VoiceConfig] = None,
        input_service: Optional[VoiceInputServiceInterface] = None,
        streaming_input_service: Optional[VoiceInputServiceInterface] = None,
        output_service: Optional[VoiceOutputServiceInterface] = None,
        conversation_service: Optional[VoiceConversationServiceInterface] = None,
    ) -> None:
        self._stdin = stdin
        self._stdout = stdout
        self._stderr = stderr or sys.stderr
        self._manifest_id = manifest_id
        self._models_root = (
            models_root or Path("~/.servonaut/voice_models").expanduser()
        )
        self._config = config or VoiceConfig()

        # Injected or lazily constructed services
        self._input_service = input_service
        self._streaming_input_service = streaming_input_service
        self._output_service = output_service
        self._conversation_service = conversation_service

        # Lifecycle & concurrency
        self._handshaken = False
        self._shutdown = False
        self._write_lock = threading.Lock()
        self._active_utterance_sessions: Dict[str, Any] = {}
        self._active_input_is_streaming = False
        self._last_conv_state = "idle"

    # ------------------------------------------------------------------
    # Message Dispatching
    # ------------------------------------------------------------------

    def run(self) -> int:
        """Run the main event loop reading from stdin and dispatching messages."""
        logger.info("VoiceWorker starting main dispatch loop")
        while not self._shutdown:
            try:
                msg = read_voice_frame(self._stdin)
                if msg is None:
                    # Clean EOF at line boundary
                    logger.info("VoiceWorker received EOF on stdin, terminating")
                    break
                self._dispatch(msg)
            except VoiceProtocolEofError:
                logger.info("VoiceWorker received mid-frame EOF, terminating")
                break
            except VoiceProtocolError as e:
                logger.warning("Voice protocol error: %s", e)
                # Send worker error event
                self._send_event(
                    WorkerErrorEvent(
                        id=str(uuid.uuid4()),
                        code=e.code,
                        message=e.message,
                        fatal=False,
                    )
                )
            except Exception as e:
                logger.exception("Unexpected error in VoiceWorker loop: %s", e)
                self._send_event(
                    WorkerErrorEvent(
                        id=str(uuid.uuid4()),
                        code=VoiceErrorCode.PROTOCOL_VIOLATION,
                        message=f"Internal worker exception: {type(e).__name__}",
                        fatal=False,
                    )
                )

        self.teardown()
        return 0

    def _dispatch(self, msg: VoiceMessage) -> None:
        """Dispatch a single decoded message."""
        if not isinstance(msg, VoiceRequest.__args__):  # type: ignore[attr-defined]
            # Worker only handles requests from parent
            logger.warning("Worker received unexpected message type: %s", type(msg).__name__)
            return

        req: VoiceRequest = msg
        req_id = req.id

        # Handshake gate: only handshake, ping, or shutdown are allowed before handshake
        if not self._handshaken and req.name not in ("handshake", "ping", "shutdown"):
            self._send_response(
                VoiceResponse(
                    id=str(uuid.uuid4()),
                    ref_id=req_id,
                    ok=False,
                    error=VoiceErrorPayload(
                        code=VoiceErrorCode.NOT_HANDSHAKEN,
                        message="Handshake required before operation",
                    ),
                )
            )
            return

        try:
            if isinstance(req, HandshakeRequest):
                self._handle_handshake(req)
            elif isinstance(req, ProbeRequest):
                self._handle_probe(req)
            elif isinstance(req, InputStartRequest):
                self._handle_input_start(req)
            elif isinstance(req, InputStopRequest):
                self._handle_input_stop(req)
            elif isinstance(req, InputCancelRequest):
                self._handle_input_cancel(req)
            elif isinstance(req, InputResetBudgetRequest):
                self._handle_input_reset_budget(req)
            elif isinstance(req, OutputSpeakRequest):
                self._handle_output_speak(req)
            elif isinstance(req, OutputEnqueueRequest):
                self._handle_output_enqueue(req)
            elif isinstance(req, OutputUtteranceBeginRequest):
                self._handle_output_utterance_begin(req)
            elif isinstance(req, OutputUtteranceEnqueueRequest):
                self._handle_output_utterance_enqueue(req)
            elif isinstance(req, OutputUtteranceEndRequest):
                self._handle_output_utterance_end(req)
            elif isinstance(req, OutputStopRequest):
                self._handle_output_stop(req)
            elif isinstance(req, OutputCloseRequest):
                self._handle_output_close(req)
            elif isinstance(req, ConversationStartRequest):
                self._handle_conversation_start(req)
            elif isinstance(req, ConversationStopRequest):
                self._handle_conversation_stop(req)
            elif isinstance(req, ConversationInterruptRequest):
                self._handle_conversation_interrupt(req)
            elif isinstance(req, ConversationSignalRequest):
                self._handle_conversation_signal(req)
            elif isinstance(req, PingRequest):
                self._handle_ping(req)
            elif isinstance(req, ShutdownRequest):
                self._handle_shutdown(req)
        except Exception as e:
            logger.exception("Error handling request %s: %s", req.name, e)
            self._send_response(
                VoiceResponse(
                    id=str(uuid.uuid4()),
                    ref_id=req_id,
                    ok=False,
                    error=VoiceErrorPayload(
                        code=VoiceErrorCode.INVALID_STATE,
                        message=f"{type(e).__name__}: {e}",
                    ),
                )
            )

    # ------------------------------------------------------------------
    # Request Handlers
    # ------------------------------------------------------------------

    def _handle_handshake(self, req: HandshakeRequest) -> None:
        if req.protocol_version != VOICE_PROTOCOL_VERSION:
            self._send_response(
                VoiceResponse(
                    id=str(uuid.uuid4()),
                    ref_id=req.id,
                    ok=False,
                    error=VoiceErrorPayload(
                        code=VoiceErrorCode.UNSUPPORTED_VERSION,
                        message=(
                            f"Protocol version mismatch: client requested {req.protocol_version}, "
                            f"worker supports {VOICE_PROTOCOL_VERSION}"
                        ),
                    ),
                )
            )
            return

        self._handshaken = True
        models_status = self._inspect_models_status()
        audio_devices = self._inspect_audio_devices()

        payload = HandshakeResponsePayload(
            worker_version="2.26.3",
            protocol_version=VOICE_PROTOCOL_VERSION,
            manifest_id=self._manifest_id,
            python_version=platform.python_version(),
            platform=sys.platform,
            architecture=platform.machine(),
            capabilities=DEFAULT_CAPABILITIES,
            models_status=models_status,
            audio_devices=audio_devices,
        )
        self._send_response(
            VoiceResponse(
                id=str(uuid.uuid4()),
                ref_id=req.id,
                ok=True,
                payload=payload.to_dict(),
            )
        )

    def _handle_probe(self, req: ProbeRequest) -> None:
        in_svc = self._get_input_service(streaming=False)
        out_svc = self._get_output_service()

        in_avail = in_svc.is_available() if in_svc is not None else False
        in_reason = in_svc.unavailable_reason() if in_svc is not None else "Input unavailable"

        out_avail = out_svc.is_available() if out_svc is not None else False
        out_reason = out_svc.unavailable_reason() if out_svc is not None else "Output unavailable"

        devices = self._inspect_audio_devices()

        payload = ProbeResponsePayload(
            input_available=in_avail,
            input_unavailable_reason=in_reason,
            output_available=out_avail,
            output_unavailable_reason=out_reason,
            devices=devices,
        )
        self._send_response(
            VoiceResponse(
                id=str(uuid.uuid4()),
                ref_id=req.id,
                ok=True,
                payload=payload.to_dict(),
            )
        )

    def _handle_input_start(self, req: InputStartRequest) -> None:
        self._active_input_is_streaming = req.streaming
        svc = self._get_input_service(streaming=req.streaming)

        if not svc.is_available():
            self._send_response(
                VoiceResponse(
                    id=str(uuid.uuid4()),
                    ref_id=req.id,
                    ok=False,
                    error=VoiceErrorPayload(
                        code=VoiceErrorCode.AUDIO_DEVICE_ERROR,
                        message=svc.unavailable_reason() or "Voice input device unavailable",
                    ),
                )
            )
            return

        if svc.is_recording:
            self._send_response(
                VoiceResponse(
                    id=str(uuid.uuid4()),
                    ref_id=req.id,
                    ok=False,
                    error=VoiceErrorPayload(
                        code=VoiceErrorCode.INVALID_STATE,
                        message="Voice input recording already in progress",
                    ),
                )
            )
            return

        # Setup streaming callbacks if available
        if req.streaming and hasattr(svc, "set_partial_callback"):
            def _on_partial(text: str) -> None:
                self._send_event(InputPartialEvent(id=str(uuid.uuid4()), text=text))

            def _on_endpoint() -> None:
                self._send_event(InputEndpointEvent(id=str(uuid.uuid4())))

            svc.set_partial_callback(_on_partial)
            if hasattr(svc, "set_endpoint_callback"):
                svc.set_endpoint_callback(_on_endpoint)

        svc.start_recording()
        self._send_response(VoiceResponse(id=str(uuid.uuid4()), ref_id=req.id, ok=True))

    def _handle_input_stop(self, req: InputStopRequest) -> None:
        svc = self._get_input_service(streaming=self._active_input_is_streaming)

        # Execute transcription in a thread to keep stdin responsive
        def _transcribe() -> None:
            try:
                text = svc.stop_and_transcribe(initial_prompt=req.initial_prompt)
                hit_cap = getattr(svc, "hit_recording_cap", False)
                if hit_cap:
                    self._send_event(InputCapHitEvent(id=str(uuid.uuid4())))

                payload = InputStopResponsePayload(text=text, hit_cap=hit_cap)
                self._send_response(
                    VoiceResponse(
                        id=str(uuid.uuid4()),
                        ref_id=req.id,
                        ok=True,
                        payload=payload.to_dict(),
                    )
                )
            except Exception as e:
                logger.exception("Error during transcription: %s", e)
                self._send_response(
                    VoiceResponse(
                        id=str(uuid.uuid4()),
                        ref_id=req.id,
                        ok=False,
                        error=VoiceErrorPayload(
                            code=VoiceErrorCode.TRANSCRIPTION_ERROR,
                            message=str(e),
                        ),
                    )
                )

        threading.Thread(target=_transcribe, daemon=True).start()

    def _handle_input_cancel(self, req: InputCancelRequest) -> None:
        svc = self._get_input_service(streaming=self._active_input_is_streaming)
        svc.cancel_recording()
        self._send_response(VoiceResponse(id=str(uuid.uuid4()), ref_id=req.id, ok=True))

    def _handle_input_reset_budget(self, req: InputResetBudgetRequest) -> None:
        svc = self._get_input_service(streaming=self._active_input_is_streaming)
        if hasattr(svc, "reset_recording_budget"):
            svc.reset_recording_budget()
        self._send_response(VoiceResponse(id=str(uuid.uuid4()), ref_id=req.id, ok=True))

    def _handle_output_speak(self, req: OutputSpeakRequest) -> None:
        out_svc = self._get_output_service()

        def _speak_work() -> None:
            try:
                epoch_val = req.epoch if req.epoch is not None else out_svc.current_epoch()
                self._send_event(
                    OutputStateEvent(
                        id=str(uuid.uuid4()),
                        is_speaking=True,
                        current_epoch=epoch_val,
                    )
                )
                out_svc.speak(req.text, epoch=req.epoch)
                end_epoch = out_svc.current_epoch()
                self._send_event(
                    OutputStateEvent(
                        id=str(uuid.uuid4()),
                        is_speaking=False,
                        current_epoch=end_epoch,
                    )
                )
                payload = OutputSpeakResponsePayload(completed=True, epoch=end_epoch)
                self._send_response(
                    VoiceResponse(
                        id=str(uuid.uuid4()),
                        ref_id=req.id,
                        ok=True,
                        payload=payload.to_dict(),
                    )
                )
            except Exception as e:
                logger.exception("Error during speech synthesis: %s", e)
                end_epoch = out_svc.current_epoch() if out_svc else 0
                self._send_event(
                    OutputStateEvent(
                        id=str(uuid.uuid4()),
                        is_speaking=False,
                        current_epoch=end_epoch,
                    )
                )
                self._send_response(
                    VoiceResponse(
                        id=str(uuid.uuid4()),
                        ref_id=req.id,
                        ok=False,
                        error=VoiceErrorPayload(
                            code=VoiceErrorCode.SYNTHESIS_ERROR,
                            message=str(e),
                        ),
                    )
                )

        threading.Thread(target=_speak_work, daemon=True).start()

    def _handle_output_enqueue(self, req: OutputEnqueueRequest) -> None:
        out_svc = self._get_output_service()
        out_svc.enqueue(req.text, epoch=req.epoch)
        self._send_response(VoiceResponse(id=str(uuid.uuid4()), ref_id=req.id, ok=True))

    def _handle_output_utterance_begin(self, req: OutputUtteranceBeginRequest) -> None:
        out_svc = self._get_output_service()
        session_id = req.session_id

        def _on_complete(played_to_end: bool) -> None:
            self._active_utterance_sessions.pop(session_id, None)
            self._send_event(
                UtteranceCompletedEvent(
                    id=str(uuid.uuid4()),
                    session_id=session_id,
                    played_to_end=played_to_end,
                )
            )

        session = out_svc.begin_utterance(on_complete=_on_complete, epoch=req.epoch)
        self._active_utterance_sessions[session_id] = session
        self._send_response(VoiceResponse(id=str(uuid.uuid4()), ref_id=req.id, ok=True))

    def _handle_output_utterance_enqueue(self, req: OutputUtteranceEnqueueRequest) -> None:
        session = self._active_utterance_sessions.get(req.session_id)
        if session is not None and hasattr(session, "enqueue"):
            session.enqueue(req.text)
            self._send_response(VoiceResponse(id=str(uuid.uuid4()), ref_id=req.id, ok=True))
        else:
            self._send_response(
                VoiceResponse(
                    id=str(uuid.uuid4()),
                    ref_id=req.id,
                    ok=False,
                    error=VoiceErrorPayload(
                        code=VoiceErrorCode.INVALID_STATE,
                        message=f"No active utterance session with id {req.session_id}",
                    ),
                )
            )

    def _handle_output_utterance_end(self, req: OutputUtteranceEndRequest) -> None:
        session = self._active_utterance_sessions.get(req.session_id)
        if session is not None and hasattr(session, "end"):
            session.end()
            self._send_response(VoiceResponse(id=str(uuid.uuid4()), ref_id=req.id, ok=True))
        else:
            self._send_response(
                VoiceResponse(
                    id=str(uuid.uuid4()),
                    ref_id=req.id,
                    ok=False,
                    error=VoiceErrorPayload(
                        code=VoiceErrorCode.INVALID_STATE,
                        message=f"No active utterance session with id {req.session_id}",
                    ),
                )
            )

    def _handle_output_stop(self, req: OutputStopRequest) -> None:
        out_svc = self._get_output_service()
        out_svc.stop()
        self._send_response(VoiceResponse(id=str(uuid.uuid4()), ref_id=req.id, ok=True))

    def _handle_output_close(self, req: OutputCloseRequest) -> None:
        out_svc = self._get_output_service()
        out_svc.close()
        self._send_response(VoiceResponse(id=str(uuid.uuid4()), ref_id=req.id, ok=True))

    def _handle_conversation_start(self, req: ConversationStartRequest) -> None:
        conv_svc = self._get_conversation_service()

        def _on_state_change(new_state: Any) -> None:
            new_state_str = str(getattr(new_state, "value", new_state)).lower()
            old_state_str = self._last_conv_state
            self._last_conv_state = new_state_str
            self._send_event(
                ConversationStateEvent(
                    id=str(uuid.uuid4()),
                    old_state=old_state_str,
                    new_state=new_state_str,
                )
            )

        def _on_transcript(text: str) -> None:
            self._send_event(
                ConversationTranscriptEvent(
                    id=str(uuid.uuid4()),
                    text=text,
                )
            )

        def _on_error(message: str) -> None:
            self._send_event(
                ConversationErrorEvent(
                    id=str(uuid.uuid4()),
                    message=message,
                    code=VoiceErrorCode.CONVERSATION_ERROR,
                )
            )

        def _on_stopped(reason: str) -> None:
            self._send_event(
                ConversationStoppedEvent(
                    id=str(uuid.uuid4()),
                    reason=reason,
                )
            )

        conv_svc.set_state_callback(_on_state_change)
        conv_svc.set_transcript_callback(_on_transcript)
        conv_svc.set_error_callback(_on_error)
        conv_svc.set_stopped_callback(_on_stopped)

        conv_svc.start()
        self._send_response(VoiceResponse(id=str(uuid.uuid4()), ref_id=req.id, ok=True))

    def _handle_conversation_stop(self, req: ConversationStopRequest) -> None:
        conv_svc = self._get_conversation_service()
        conv_svc.stop()
        self._send_response(VoiceResponse(id=str(uuid.uuid4()), ref_id=req.id, ok=True))

    def _handle_conversation_interrupt(self, req: ConversationInterruptRequest) -> None:
        conv_svc = self._get_conversation_service()
        conv_svc.interrupt()
        self._send_response(VoiceResponse(id=str(uuid.uuid4()), ref_id=req.id, ok=True))

    def _handle_conversation_signal(self, req: ConversationSignalRequest) -> None:
        conv_svc = self._get_conversation_service()
        signal_name = req.signal
        if signal_name == "reply_started" and hasattr(conv_svc, "reply_started"):
            conv_svc.reply_started()
        elif signal_name == "reply_finished" and hasattr(conv_svc, "reply_finished"):
            conv_svc.reply_finished()
        elif signal_name == "speaking_started" and hasattr(conv_svc, "speaking_started"):
            conv_svc.speaking_started()
        elif signal_name == "speaking_finished" and hasattr(conv_svc, "speaking_finished"):
            conv_svc.speaking_finished()
        else:
            logger.debug("Unknown or unhandled conversation signal: %s", signal_name)

        self._send_response(VoiceResponse(id=str(uuid.uuid4()), ref_id=req.id, ok=True))

    def _handle_ping(self, req: PingRequest) -> None:
        self._send_response(
            VoiceResponse(
                id=str(uuid.uuid4()),
                ref_id=req.id,
                ok=True,
                payload={"pong": True, "status": "ready" if self._handshaken else "pending"},
            )
        )

    def _handle_shutdown(self, req: ShutdownRequest) -> None:
        self._shutdown = True
        self._send_response(VoiceResponse(id=str(uuid.uuid4()), ref_id=req.id, ok=True, payload={"ack": True}))

    # ------------------------------------------------------------------
    # Frame Sending Helpers
    # ------------------------------------------------------------------

    def _send_response(self, resp: VoiceResponse) -> None:
        with self._write_lock:
            write_voice_frame(self._stdout, resp)

    def _send_event(self, event: VoiceEvent) -> None:
        with self._write_lock:
            write_voice_frame(self._stdout, event)

    # ------------------------------------------------------------------
    # Engine / Hardware Queries
    # ------------------------------------------------------------------

    def _inspect_models_status(self) -> Dict[str, bool]:
        """Detect presence of model files on disk under models_root."""
        status = {
            "whisper": False,
            "nemotron": False,
            "kokoro": False,
            "silero": False,
        }
        # Check streaming nemotron
        nemotron_dir = self._models_root / "nemotron"
        if nemotron_dir.is_dir() and (nemotron_dir / "tokens.txt").is_file():
            status["nemotron"] = True

        # Check kokoro TTS
        kokoro_dir = self._models_root / "kokoro-int8-multi-lang-v1_0"
        if kokoro_dir.is_dir() and (kokoro_dir / "model.int8.onnx").is_file():
            status["kokoro"] = True

        # Check silero VAD
        silero_file = self._models_root / "silero_vad.onnx"
        if silero_file.is_file():
            status["silero"] = True

        # Whisper default check
        status["whisper"] = True  # Whisper weights are cached in HF root
        return status

    def _inspect_audio_devices(self) -> Dict[str, Any]:
        """Sanitized enumeration of audio input/output devices without machine secrets."""
        info: Dict[str, Any] = {
            "has_sounddevice": False,
            "input_count": 0,
            "output_count": 0,
            "default_input": None,
            "default_output": None,
        }
        try:
            import sounddevice as sd  # type: ignore[import-untyped]
            info["has_sounddevice"] = True
            devices = sd.query_devices()
            if isinstance(devices, list):
                info["input_count"] = sum(
                    1 for d in devices if d.get("max_input_channels", 0) > 0
                )
                info["output_count"] = sum(
                    1 for d in devices if d.get("max_output_channels", 0) > 0
                )
            default = sd.default.device
            if isinstance(default, (list, tuple)) and len(default) >= 2:
                info["default_input"] = default[0]
                info["default_output"] = default[1]
        except Exception as e:
            logger.debug("Audio device probe failed: %s", e)
        return info

    # ------------------------------------------------------------------
    # Service Lazy Construction
    # ------------------------------------------------------------------

    def _get_input_service(self, *, streaming: bool) -> VoiceInputServiceInterface:
        if streaming:
            if self._streaming_input_service is None:
                from servonaut.services.voice_streaming_service import (
                    StreamingVoiceInputService,
                )
                self._streaming_input_service = StreamingVoiceInputService(self._config)
            return self._streaming_input_service
        else:
            if self._input_service is None:
                from servonaut.services.voice_input_service import (
                    VoiceInputService,
                )
                self._input_service = VoiceInputService(self._config)
            return self._input_service

    def _get_output_service(self) -> VoiceOutputServiceInterface:
        if self._output_service is None:
            from servonaut.services.voice_output_service import VoiceOutputService
            self._output_service = VoiceOutputService(self._config)
        return self._output_service

    def _get_conversation_service(self) -> VoiceConversationServiceInterface:
        if self._conversation_service is None:
            from servonaut.services.voice_conversation_service import (
                VoiceConversationService,
            )
            in_svc = self._get_input_service(streaming=False)
            out_svc = self._get_output_service()
            self._conversation_service = VoiceConversationService(
                in_svc, out_svc, self._config
            )
        return self._conversation_service

    def teardown(self) -> None:
        """Release audio devices and cancel active streams on worker exit."""
        logger.info("VoiceWorker tearing down active services")
        if self._conversation_service is not None:
            try:
                self._conversation_service.stop(join=False)
            except Exception:
                pass
        if self._input_service is not None:
            try:
                self._input_service.cancel_recording()
            except Exception:
                pass
        if self._streaming_input_service is not None:
            try:
                self._streaming_input_service.cancel_recording()
            except Exception:
                pass
        if self._output_service is not None:
            try:
                self._output_service.stop()
                self._output_service.close()
            except Exception:
                pass
        self._active_utterance_sessions.clear()


def run_worker(
    stdin: Optional[BinaryIO] = None,
    stdout: Optional[BinaryIO] = None,
    stderr: Optional[TextIO] = None,
    *,
    manifest_id: str = "managed-runtime-v1",
    models_root: Optional[Path] = None,
) -> int:
    """Run the voice worker daemon on stdio."""
    in_stream = stdin or sys.stdin.buffer
    out_stream = stdout or sys.stdout.buffer
    err_stream = stderr or sys.stderr

    worker = VoiceWorker(
        stdin=in_stream,
        stdout=out_stream,
        stderr=err_stream,
        manifest_id=manifest_id,
        models_root=models_root,
    )

    def _on_signal(signum: int, frame: Any) -> None:
        logger.info("VoiceWorker received signal %s, initiating shutdown", signum)
        worker._shutdown = True

    try:
        signal.signal(signal.SIGINT, _on_signal)
        signal.signal(signal.SIGTERM, _on_signal)
    except (ValueError, AttributeError):
        # Non-main thread or unsupported platform signal
        pass

    return worker.run()


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point for launching the companion voice worker process."""
    parser = argparse.ArgumentParser(description="Servonaut Managed Voice Companion Worker")
    parser.add_argument(
        "--manifest-id",
        default=os.environ.get("SERVONAUT_VOICE_MANIFEST_ID", "managed-runtime-v1"),
        help="Managed runtime release identifier",
    )
    parser.add_argument(
        "--models-root",
        default=os.environ.get("SERVONAUT_VOICE_MODELS_DIR"),
        help="Directory containing voice model weights",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] [voice-worker] %(message)s",
    )

    models_path = Path(args.models_root).expanduser() if args.models_root else None
    return run_worker(manifest_id=args.manifest_id, models_root=models_path)


if __name__ == "__main__":
    sys.exit(main())
