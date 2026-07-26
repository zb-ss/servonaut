"""Readiness detection and guided setup for local voice input.

Voice input is opt-in because it costs a few hundred megabytes across two
separate downloads — the Python packages and the speech model weights —
and one of its requirements (the PortAudio system library) cannot be
installed by pip at all. Rather than hide that behind a single button
that silently half-succeeds, this service reports each requirement
independently so the settings panel can name the one thing standing in
the way and offer the matching action.

Both engines are handled here. What differs between them — which packages,
which weights, where they land, how big they are — comes from
:mod:`servonaut.services.voice_engines`, so this module stays free of
per-engine branching beyond the two places it genuinely matters: probing
imports and fetching weights.

The service also keeps an inventory of every model on disk across both
engines. Switching engine or model size otherwise silently strands
hundreds of megabytes, which the settings panel uses to offer a cleanup.

Split from :mod:`servonaut.services.voice_input_service` on purpose: the
recording hot path has no business carrying subprocess and download
logic, and setup has no business holding an audio buffer.
"""

from __future__ import annotations

import asyncio
import glob
import logging
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple, TYPE_CHECKING

from servonaut.utils.platform_utils import command_exists, get_os
from servonaut.services.voice_engines import (
    NEMOTRON_DOWNLOAD_BYTES,
    NEMOTRON_FILES,
    VOICE_MODEL_ROOT,
    directory_bytes,
    engine_spec,
    human_bytes,
    model_label,
    nemotron_model_dir,
    nemotron_repo,
)

if TYPE_CHECKING:
    from servonaut.config.schema import VoiceConfig

logger = logging.getLogger(__name__)

# Kept for callers that predate per-engine package lists; the batch
# engine's requirements. New code should ask :meth:`VoiceSetupService.packages`.
VOICE_PACKAGES: Tuple[str, ...] = (
    "faster-whisper>=1.0",
    "sounddevice>=0.4",
    "numpy>=1.24",
)

# Rough download footprint per Whisper model size, for the confirmation
# copy. These are the int8 CTranslate2 conversions the batch engine pulls,
# not the original checkpoints.
MODEL_DOWNLOAD_SIZES: dict = {
    "tiny": "~75 MB",
    "tiny.en": "~75 MB",
    "base": "~145 MB",
    "base.en": "~145 MB",
    "small": "~490 MB",
    "small.en": "~490 MB",
    "medium": "~1.5 GB",
    "medium.en": "~1.5 GB",
    "large-v2": "~3 GB",
    "large-v3": "~3 GB",
    "distil-small.en": "~340 MB",
    "distil-medium.en": "~790 MB",
    "distil-large-v3": "~1.5 GB",
}

# Install hint for the PortAudio shared library, keyed by the package
# manager we can actually find on the box. pip cannot provide this — it is
# a system library — so every path here is a command for the user to run.
_PORTAUDIO_COMMANDS: Tuple[Tuple[str, str], ...] = (
    ("apt-get", "sudo apt install libportaudio2"),
    ("dnf", "sudo dnf install portaudio"),
    ("pacman", "sudo pacman -S portaudio"),
    ("zypper", "sudo zypper install portaudio"),
    ("apk", "sudo apk add portaudio"),
)

_PORTAUDIO_MACOS = "brew install portaudio"

# Ceiling for the package install subprocess. A cold install pulls a
# multi-hundred-megabyte runtime, which is slow on a thin connection but
# should never take a quarter of an hour.
_INSTALL_TIMEOUT_SECONDS = 900

# Ceiling for the model download. Generous because the larger models are
# multi-gigabyte and the host throttles.
_DOWNLOAD_TIMEOUT_SECONDS = 1800

# Streamed download chunk size. Large enough to keep syscall overhead off
# the profile, small enough that progress updates feel live.
_DOWNLOAD_CHUNK_BYTES = 1 << 20


@dataclass(frozen=True)
class InstalledModel:
    """One set of model weights present on disk.

    Attributes:
        engine: Engine the weights belong to.
        label: Human-readable name, e.g. "Whisper small".
        key: Identifier the removal call takes back — a Whisper model size
            or a streaming latency, depending on the engine.
        path: Directory holding the weights.
        size_bytes: Total on-disk size.
        in_use: Whether the current configuration points at these weights.
    """

    engine: str
    label: str
    key: str
    path: Path
    size_bytes: int
    in_use: bool

    @property
    def human_size(self) -> str:
        """On-disk size as a short string."""
        return human_bytes(self.size_bytes)


@dataclass(frozen=True)
class VoiceReadiness:
    """Which of the voice-input requirements are currently satisfied.

    Attributes:
        packages_ok: The engine's Python packages are importable.
        portaudio_ok: ``sounddevice`` imports, meaning the PortAudio shared
            library resolved. False specifically when the Python package is
            present but the system library is not — the one failure pip
            cannot fix.
        device_ok: At least one capture device is present. False on a
            headless host or over SSH.
        model_ok: Weights for the configured model are already on disk, so
            the first dictation will not stall on a download.
        model_size: The Whisper size these verdicts were resolved against.
        detail: Optional human-readable note about the first unmet
            requirement (an import error message, for instance).
        engine: The engine these verdicts were resolved against.
    """

    packages_ok: bool
    portaudio_ok: bool
    device_ok: bool
    model_ok: bool
    model_size: str
    detail: str = ""
    engine: str = "whisper"

    @property
    def is_ready(self) -> bool:
        """Whether a dictation started right now would work end to end."""
        return (
            self.packages_ok
            and self.portaudio_ok
            and self.device_ok
            and self.model_ok
        )

    @property
    def next_step(self) -> str:
        """The first unmet requirement, as a stable identifier.

        Ordered by dependency: there is no point reporting a missing model
        to someone who has not installed the packages yet.

        Returns:
            One of ``packages``, ``portaudio``, ``device``, ``model``, or
            an empty string when everything is satisfied.
        """
        if not self.packages_ok:
            return "packages"
        if not self.portaudio_ok:
            return "portaudio"
        if not self.device_ok:
            return "device"
        if not self.model_ok:
            return "model"
        return ""


class VoiceSetupService:
    """Detects what voice input still needs, and installs it on request."""

    def __init__(self, config: 'VoiceConfig') -> None:
        self._config = config
        self._cached: Optional[VoiceReadiness] = None

    # ------------------------------------------------------------------
    # Engine
    # ------------------------------------------------------------------

    @property
    def engine_id(self) -> str:
        """Configured engine id, normalised to one this release knows."""
        return self._engine().id

    def _engine(self):
        """Spec for the currently configured engine."""
        return engine_spec(getattr(self._config, "engine", "whisper"))

    def _latency_ms(self) -> int:
        """Configured streaming chunk size."""
        return int(getattr(self._config, "nemotron_latency_ms", 320) or 320)

    def packages(self) -> Tuple[str, ...]:
        """pip requirements for the configured engine."""
        return self._engine().packages

    def current_model_label(self) -> str:
        """Human-readable name of the model the configuration points at."""
        return model_label(
            self.engine_id,
            model_size=self._config.model_size,
            latency_ms=self._latency_ms(),
        )

    # ------------------------------------------------------------------
    # Readiness
    # ------------------------------------------------------------------

    def probe(self, *, force: bool = False) -> VoiceReadiness:
        """Resolve which requirements are met.

        Importing the audio stack and enumerating devices both cost real
        time, so the verdict is cached until something might have changed.

        Args:
            force: Re-run every check instead of returning the cached
                verdict. Pass this after an install or a download.

        Returns:
            The current :class:`VoiceReadiness`.
        """
        if self._cached is not None and not force:
            return self._cached

        packages_ok, portaudio_ok, device_ok, detail = self._probe_runtime()
        # Only meaningful once the packages are in place: reporting "no
        # model" to someone who has installed nothing buries the real
        # next step.
        model_ok = self.is_model_present() if packages_ok else False

        self._cached = VoiceReadiness(
            packages_ok=packages_ok,
            portaudio_ok=portaudio_ok,
            device_ok=device_ok,
            model_ok=model_ok,
            model_size=self._config.model_size,
            detail=detail,
            engine=self.engine_id,
        )
        return self._cached

    def _probe_runtime(self) -> Tuple[bool, bool, bool, str]:
        """Check the engine's imports and the capture devices.

        ``sounddevice`` is imported separately from the rest because its
        failure mode is the interesting one: an :exc:`OSError` naming
        PortAudio means the pip package installed fine and the system
        library is what is missing.

        Returns:
            Tuple of (packages_ok, portaudio_ok, device_ok, detail).
        """
        import importlib

        importlib.invalidate_caches()
        for module in self._engine().import_names:
            try:
                importlib.import_module(module)
            except Exception as e:  # noqa: BLE001 — a broken build raises OSError
                logger.debug("Voice package %s unavailable: %s", module, e)
                return False, False, False, str(e)

        try:
            import sounddevice as sd
        except OSError as e:
            # sounddevice raises OSError, not ImportError, when the shared
            # library is absent — that is the signal we branch on.
            logger.debug("PortAudio unavailable: %s", e)
            return True, False, False, str(e)
        except Exception as e:  # noqa: BLE001 — the package itself is broken
            logger.debug("sounddevice unavailable: %s", e)
            return False, False, False, str(e)

        detail = ""
        try:
            devices = sd.query_devices()
            device_ok = any(
                int(device.get('max_input_channels', 0)) > 0 for device in devices
            )
            if not device_ok:
                detail = "No capture device reported by the audio system"
        except Exception as e:  # noqa: BLE001 — headless hosts raise from PortAudio
            logger.debug("Device enumeration failed: %s", e)
            device_ok = False
            detail = str(e)

        return True, True, device_ok, detail

    # ------------------------------------------------------------------
    # Model presence
    # ------------------------------------------------------------------

    def is_model_present(self) -> bool:
        """Whether usable weights for the configured engine are on disk."""
        return self.is_model_present_for(
            self.engine_id,
            model_size=self._config.model_size,
            latency_ms=self._latency_ms(),
        )

    def is_model_present_for(
        self, engine_id: str, *, model_size: str, latency_ms: int
    ) -> bool:
        """Whether weights for an arbitrary engine/model choice are on disk.

        Takes the choice explicitly so the settings panel can describe what
        the user is about to save rather than what is currently saved —
        showing the old model's status next to a newly picked engine is how
        a readiness card starts lying.
        """
        if engine_spec(engine_id).streaming:
            return self.is_streaming_model_present(latency_ms)
        return self.is_model_cached(model_size)

    def model_bytes_for(
        self, engine_id: str, *, model_size: str, latency_ms: int
    ) -> int:
        """On-disk size of the weights for an arbitrary engine/model choice."""
        if engine_spec(engine_id).streaming:
            return directory_bytes(nemotron_model_dir(latency_ms))
        return self.model_cache_bytes(model_size)

    def download_size_hint_for(self, engine_id: str, *, model_size: str) -> str:
        """Approximate download size for an arbitrary engine/model choice."""
        if engine_spec(engine_id).streaming:
            return f"~{human_bytes(NEMOTRON_DOWNLOAD_BYTES)}"
        return MODEL_DOWNLOAD_SIZES.get(model_size, "size unknown")

    def packages_size_hint(self, engine_id: Optional[str] = None) -> str:
        """Rough install footprint for an engine's packages.

        Both runtimes are dominated by their inference library, so this is
        a coarse figure rather than a resolved dependency total.
        """
        return "~90 MB" if engine_spec(engine_id or self.engine_id).streaming else "~200 MB"

    def is_streaming_model_present(self, latency_ms: int) -> bool:
        """Whether the streaming weights for *latency_ms* are complete.

        Every file is checked, not just the directory: an interrupted
        download leaves a partial set behind, and treating that as done
        pushes the failure to the first dictation.
        """
        model_dir = nemotron_model_dir(latency_ms)
        if not model_dir.is_dir():
            return False
        return all((model_dir / name).is_file() for name in NEMOTRON_FILES.values())

    def _model_cache_root(self) -> Path:
        """Locate the Hugging Face hub cache the batch weights land in.

        Honours the same environment overrides the hub library does so a
        user who redirected their cache is not told the model is missing.
        """
        for env_var in ("HF_HUB_CACHE", "HUGGINGFACE_HUB_CACHE"):
            value = os.environ.get(env_var)
            if value:
                return Path(value).expanduser()
        hf_home = os.environ.get("HF_HOME")
        if hf_home:
            return Path(hf_home).expanduser() / "hub"
        return Path.home() / ".cache" / "huggingface" / "hub"

    def _model_cache_dirs(self, model_size: str) -> List[Path]:
        """Find cache directories that look like the requested Whisper model.

        Matched by glob rather than by an exact repository id because the
        publishing org has moved before, and a hard-coded id would report
        a present model as missing after the next move.
        """
        root = self._model_cache_root()
        if not root.is_dir():
            return []
        pattern = str(root / f"models--*whisper*{model_size}")
        return [Path(p) for p in glob.glob(pattern) if Path(p).is_dir()]

    def is_model_cached(self, model_size: str) -> bool:
        """Whether usable Whisper weights for *model_size* are downloaded.

        Checks for the weights file rather than just the directory: an
        interrupted download leaves the folder and its refs behind, and
        treating that as "done" would push the failure to the first
        dictation instead of surfacing it here.
        """
        for cache_dir in self._model_cache_dirs(model_size):
            snapshots = cache_dir / "snapshots"
            if not snapshots.is_dir():
                continue
            for weights in snapshots.glob("*/model.bin"):
                # A blob symlink that outlived its target reads as missing.
                if weights.exists():
                    return True
        return False

    def model_cache_bytes(self, model_size: str) -> int:
        """Total on-disk size of the cached Whisper weights, or 0 if absent."""
        return sum(directory_bytes(d) for d in self._model_cache_dirs(model_size))

    def download_size_hint(self, model_size: Optional[str] = None) -> str:
        """Approximate download size for the configured model."""
        if self._engine().streaming:
            return f"~{human_bytes(NEMOTRON_DOWNLOAD_BYTES)}"
        size = model_size or self._config.model_size
        return MODEL_DOWNLOAD_SIZES.get(size, "size unknown")

    # ------------------------------------------------------------------
    # Model inventory + removal
    # ------------------------------------------------------------------

    def installed_models(
        self,
        *,
        active_engine: Optional[str] = None,
        active_model_size: Optional[str] = None,
        active_latency_ms: Optional[int] = None,
    ) -> List[InstalledModel]:
        """Every set of weights on disk, across both engines.

        Switching engine or model size strands the previous download, which
        is hundreds of megabytes; this is what lets the settings panel show
        what is taking up space and offer to reclaim it.
        """
        found: List[InstalledModel] = []
        engine_id = engine_spec(active_engine or self.engine_id).id
        active_size = active_model_size or self._config.model_size
        active_latency = active_latency_ms or self._latency_ms()
        streaming_active = engine_spec(engine_id).streaming

        for size in MODEL_DOWNLOAD_SIZES:
            if not self.is_model_cached(size):
                continue
            found.append(InstalledModel(
                engine="whisper",
                label=f"Whisper {size}",
                key=size,
                path=self._model_cache_dirs(size)[0],
                size_bytes=self.model_cache_bytes(size),
                in_use=(engine_id == "whisper" and size == active_size),
            ))

        if VOICE_MODEL_ROOT.is_dir():
            for entry in sorted(VOICE_MODEL_ROOT.iterdir()):
                if not entry.is_dir() or not entry.name.startswith("nemotron"):
                    continue
                latency = self._latency_from_dirname(entry.name)
                found.append(InstalledModel(
                    engine="nemotron",
                    label=f"Nemotron streaming {latency}ms" if latency else entry.name,
                    key=str(latency or ""),
                    path=entry,
                    size_bytes=directory_bytes(entry),
                    in_use=streaming_active and latency == active_latency,
                ))

        return found

    @staticmethod
    def _latency_from_dirname(name: str) -> Optional[int]:
        """Recover the chunk size from a streaming model directory name."""
        for part in name.split("-"):
            if part.endswith("ms") and part[:-2].isdigit():
                return int(part[:-2])
        return None

    def stale_models(self, **active) -> List[InstalledModel]:
        """Weights on disk that the given (or current) choice does not use."""
        return [
            model for model in self.installed_models(**active) if not model.in_use
        ]

    def remove_installed(self, model: InstalledModel) -> Tuple[bool, str]:
        """Delete the weights *model* describes.

        Returns:
            Tuple of (success, message).
        """
        try:
            shutil.rmtree(model.path)
        except FileNotFoundError:
            return True, f"{model.label} was already gone"
        except OSError as e:
            logger.error("Could not remove %s: %s", model.path, e)
            return False, f"Could not remove {model.label}: {e}"
        self._cached = None
        return True, f"Removed {model.label}, reclaiming {model.human_size}"

    def remove_model(self, model_size: str) -> Tuple[bool, str]:
        """Delete the cached Whisper weights for *model_size*.

        Removing an absent model is reported as success — the requested end
        state already holds.
        """
        cache_dirs = self._model_cache_dirs(model_size)
        if not cache_dirs:
            return True, f"No cached weights for {model_size}"

        for cache_dir in cache_dirs:
            try:
                shutil.rmtree(cache_dir)
            except OSError as e:
                logger.error("Could not remove %s: %s", cache_dir, e)
                return False, f"Could not remove the cached model: {e}"

        self._cached = None
        return True, f"Removed the cached {model_size} model"

    # ------------------------------------------------------------------
    # Package install
    # ------------------------------------------------------------------

    def install_method(self) -> str:
        """How Servonaut itself was installed.

        Delegates to :class:`~servonaut.services.update_service.UpdateService`
        so the extras install targets the same environment the in-app
        upgrade does, instead of guessing separately.

        Returns:
            One of ``pipx``, ``pip``, ``source``, ``unknown``.
        """
        try:
            from servonaut.services.update_service import UpdateService
            return UpdateService().detect_install_method()
        except Exception as e:  # noqa: BLE001 — detection must never block setup
            logger.debug("Install-method detection failed: %s", e)
            return "unknown"

    def install_command(self) -> Optional[List[str]]:
        """Build the argv that installs the packages, when it is safe to run.

        A source or editable checkout is deliberately excluded: its
        dependencies are owned by whoever manages that environment, and
        quietly pip-installing into it is not ours to do.

        Returns:
            The argv list, or None when the install should be left to the
            user (:meth:`manual_install_command` has the copy for them).
        """
        method = self.install_method()
        packages = list(self.packages())
        if method == "pipx":
            pipx = shutil.which("pipx")
            if not pipx:
                return None
            return [pipx, "inject", "servonaut", *packages]
        if method == "pip":
            return [sys.executable, "-m", "pip", "install", *packages]
        return None

    def manual_install_command(self) -> str:
        """The install command as a single copy-pasteable string.

        Always available, including for the source installs
        :meth:`install_command` refuses to run itself.
        """
        argv = self.install_command()
        if argv:
            return " ".join(argv)
        extra = "voice-streaming" if self._engine().streaming else "voice"
        if self.install_method() == "source":
            # An editable checkout installs extras through the project, so
            # point at the extra rather than the loose package list.
            return f"pip install -e '.[{extra}]'"
        return f"pip install {' '.join(self.packages())}"

    def portaudio_command(self) -> str:
        """The command that installs the PortAudio system library.

        Resolved against the package manager actually present so the
        instruction is runnable rather than a list of maybes.
        """
        if get_os() == "macos":
            return _PORTAUDIO_MACOS
        for binary, command in _PORTAUDIO_COMMANDS:
            if command_exists(binary):
                return command
        return "install the PortAudio library for your distribution"

    async def install_packages(self) -> Tuple[bool, str]:
        """Install the engine's packages into Servonaut's own environment.

        Runs the package manager as a subprocess and, on success, asks the
        input service to re-import so the feature works without a restart.

        Returns:
            Tuple of (success, message) fit for display.
        """
        argv = self.install_command()
        if argv is None:
            return False, (
                "This looks like a source checkout — install the extra "
                f"yourself with: {self.manual_install_command()}"
            )

        logger.info("Installing voice packages via %s", argv[0])
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except OSError as e:
            logger.error("Could not start the installer: %s", e)
            return False, f"Could not start the installer: {e}"

        try:
            stdout, _ = await asyncio.wait_for(
                process.communicate(), timeout=_INSTALL_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return False, "The install timed out. Try running it in a terminal."

        output = (stdout or b"").decode(errors="replace")
        if process.returncode != 0:
            logger.error("Voice package install failed (rc=%s)", process.returncode)
            return False, self._installer_failure_message(output)

        self._cached = None
        if not self._engine().streaming:
            # Only the batch engine caches its imports in module globals;
            # the streaming service re-imports on every probe, so it picks
            # a fresh install up without help.
            from servonaut.services.voice_input_service import reload_voice_deps
            reload_voice_deps()

        readiness = self.probe(force=True)
        if not readiness.portaudio_ok:
            return True, (
                "Packages installed. PortAudio is still missing — run: "
                f"{self.portaudio_command()}"
            )
        if not readiness.packages_ok:
            return True, "Packages installed. Restart Servonaut to finish enabling voice input."
        return True, "Voice packages installed."

    def _installer_failure_message(self, output: str) -> str:
        """Turn installer output into one actionable line.

        The tail of a pip failure is usually the useful part, but it can
        run to hundreds of lines of resolver noise, so it is trimmed to
        something a notification can hold.
        """
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        tail = lines[-1] if lines else "no output"
        return f"Install failed: {tail[:200]}"

    # ------------------------------------------------------------------
    # Model download
    # ------------------------------------------------------------------

    async def download_model(
        self,
        model_size: Optional[str] = None,
        *,
        progress: Optional[Callable[[str, int, int], None]] = None,
    ) -> Tuple[bool, str]:
        """Fetch the model weights ahead of the first dictation.

        The engines would fetch these lazily anyway; doing it here means
        the cost is paid against a button the user pressed knowingly, with
        the size shown, instead of stalling their first recording.

        Args:
            model_size: Whisper size to fetch. Ignored by the streaming
                engine, whose model is selected by latency instead.
            progress: Optional callback invoked as
                ``(label, downloaded_bytes, total_bytes)``. ``total_bytes``
                is 0 when the server sends no length. Only the streaming
                download reports progress — the batch engine's downloader
                exposes no hook, so its caller should show an indeterminate
                indicator instead of a percentage.

        Returns:
            Tuple of (success, message).
        """
        readiness = self.probe()
        if not readiness.packages_ok:
            return False, "Install the voice packages first."

        if self._engine().streaming:
            return await self._download_streaming_model(progress)

        size = model_size or self._config.model_size
        try:
            success, message = await asyncio.wait_for(
                asyncio.to_thread(self._download_whisper_blocking, size),
                timeout=_DOWNLOAD_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            return False, "The model download timed out."

        self._cached = None
        return success, message

    def _download_whisper_blocking(self, model_size: str) -> Tuple[bool, str]:
        """Construct the batch model, which pulls its weights into the cache.

        Runs on a worker thread — it blocks for the whole download.
        """
        try:
            from faster_whisper import WhisperModel
            WhisperModel(model_size, device="cpu", compute_type="int8")
        except Exception as e:  # noqa: BLE001 — hub errors, disk-full, bad size
            logger.error("Model download failed for %s: %s", model_size, e)
            return False, f"Download failed: {e}"

        if not self.is_model_cached(model_size):
            # Loaded from somewhere we do not recognise as the cache (a
            # local conversion path, say). Not a failure, but the panel
            # should not promise it is cached.
            return True, f"Loaded {model_size}, but it is not in the expected cache location."
        return True, f"Downloaded the {model_size} model."

    async def _download_streaming_model(
        self, progress: Optional[Callable[[str, int, int], None]]
    ) -> Tuple[bool, str]:
        """Fetch the four streaming model files.

        Downloaded with the HTTP client already in Servonaut's core
        dependencies rather than pulling in a hub library the streaming
        engine does not otherwise need — and it gives us real progress,
        which matters for a download this size.
        """
        latency = self._latency_ms()
        model_dir = nemotron_model_dir(latency)
        repo = nemotron_repo(latency)

        try:
            import httpx
        except ImportError:  # pragma: no cover — httpx is a core dependency
            return False, "The HTTP client is unavailable; cannot download the model."

        # Staged in a sibling directory so an interrupted download can never
        # be mistaken for a complete one by the presence check.
        staging = model_dir.with_name(model_dir.name + ".partial")
        try:
            if staging.exists():
                shutil.rmtree(staging)
            staging.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return False, f"Could not prepare the download directory: {e}"

        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
                for index, (remote, local) in enumerate(NEMOTRON_FILES.items(), start=1):
                    url = f"https://huggingface.co/{repo}/resolve/main/{remote}"
                    if progress is not None:
                        progress(f"{local} ({index}/{len(NEMOTRON_FILES)})", 0, 0)
                    ok, error = await self._download_file(
                        client, url, staging / local, local, progress
                    )
                    if not ok:
                        shutil.rmtree(staging, ignore_errors=True)
                        return False, error
        except asyncio.TimeoutError:
            shutil.rmtree(staging, ignore_errors=True)
            return False, "The model download timed out."
        except Exception as e:  # noqa: BLE001 — network failures vary widely
            shutil.rmtree(staging, ignore_errors=True)
            logger.error("Streaming model download failed: %s", e)
            return False, f"Download failed: {e}"

        try:
            if model_dir.exists():
                shutil.rmtree(model_dir)
            staging.rename(model_dir)
        except OSError as e:
            shutil.rmtree(staging, ignore_errors=True)
            return False, f"Could not finalise the download: {e}"

        self._cached = None
        return True, f"Downloaded the streaming model ({latency}ms)."

    async def _download_file(
        self,
        client,
        url: str,
        destination: Path,
        label: str,
        progress: Optional[Callable[[str, int, int], None]],
    ) -> Tuple[bool, str]:
        """Stream one file to disk, reporting progress as it goes."""
        try:
            async with client.stream("GET", url) as response:
                if response.status_code != 200:
                    return False, f"Download failed for {label}: HTTP {response.status_code}"
                total = int(response.headers.get("content-length") or 0)
                written = 0
                last_reported = 0
                with destination.open("wb") as handle:
                    async for chunk in response.aiter_bytes(_DOWNLOAD_CHUNK_BYTES):
                        handle.write(chunk)
                        written += len(chunk)
                        # Throttled to every 4 MB: a 660 MB file would
                        # otherwise repaint the bar hundreds of times a second.
                        if progress is not None and written - last_reported >= 4 << 20:
                            last_reported = written
                            progress(label, written, total)
        except Exception as e:  # noqa: BLE001 — network/disk failures vary
            logger.error("Failed downloading %s: %s", url, e)
            return False, f"Download failed for {label}: {e}"
        return True, ""


def build_voice_setup_service(config: 'VoiceConfig') -> VoiceSetupService:
    """Construct the setup service.

    A factory for symmetry with the other optional-service builders, and so
    call sites do not import the class directly.
    """
    return VoiceSetupService(config)
